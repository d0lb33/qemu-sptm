/*
 * Apple SMP startup and fast IPIs.
 *
 * Evidence: AsahiLinux/m1n1 src/smp.c, smp_start_cpu() programs RVBAR at
 * cpu-impl-reg+0 and starts a core at PMGR+CPU_START_OFF+8+4*cluster.
 * Its T8140 case selects offset 0x34000. RVBAR bits [47:12] are the address,
 * bit 0 locks it. cpu-impl-reg+0x100 low byte is nonzero on a live core.
 *
 * XNU osfmk/arm64/machine_routines.c:ml_cpu_signal_type() encodes local IPIs
 * as the core number and global IPIs as cluster<<16 | core. apple_arm64_regs.h
 * defines type [29:28]. sleh.c:sleh_fiq() reads IPI_SR bit 0 and acknowledges
 * it with a write-one-to-clear before calling cpu_signal_handler(). Timer
 * and IPI FIQ levels are combined, so acknowledging one cannot lose the other.
 *
 * Experimental immediate-IPI model: deferred requests currently use the
 * immediate path, and retraction/no-wake requests are not implemented.
 * Power gating and CPU hotplug are not implemented. See docs/re/multicpu.md
 * in the parent project for the opt-in virtual platform adapter and test evidence.
 */
#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "hw/core/irq.h"
#include "qapi/error.h"
#include "qemu/main-loop.h"
#include "qemu/log.h"
#include "qemu/cutils.h"
#include "system/address-spaces.h"
#include "hw/core/or-irq.h"
#include "hw/core/qdev-properties.h"
#include "migration/vmstate.h"
#include "cpregs.h"
#include "target/arm/arm-powerctl.h"
#include "target/arm/internals.h"
#include "target/arm/multiprocessing.h"
#include "xnu/darwin_smp.h"
#include "xnu/apple_regs.h"

typedef struct {
    ARMCPU *cpu;
    MemoryRegion impl;
    MemoryRegion rvbar_region;
    MemoryRegion state_region;
    MemoryRegion cpm;
    uint64_t cpm_base;
    uint64_t rvbar;
    uint64_t ipi_pending;
    qemu_irq ipi;
} DarwinSMPCPU;

typedef struct {
    DarwinSMPCPU cpus[DARWIN_MAX_CPUS];
    unsigned count;
    MemoryRegion start_region;
    uint64_t boot_x0;
    uint64_t reset_pc;
    bool debug;
} DarwinSMP;

static DarwinSMP smp;

static void start_write(void *opaque, hwaddr offset, uint64_t val, unsigned size);

/* Experimental virtual platform ABI, paired with tools/re/smp_pv_patch.py.
 * This is not an Apple hardware register. XNU's PE_cpu_start_internal passes
 * a logical CPU ID; the bridge releases that CPU through the same reset path
 * as the PMGR bitmap. The real SPTM and XNU secondary entries still execute.
 */
static void pv_cpu_start(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t id)
{
    BQL_LOCK_GUARD();
    if (!id || id >= smp.count) {
        error_report("darwin-smp: invalid virtual CPU start %" PRIu64, id);
        abort();
    }
    if (smp.cpus[id].cpu->power_state != PSCI_OFF) {
        return;
    }
    apple_regs_pv_cpu_handoff(&smp.cpus[id].cpu->env, env);
    uint64_t affinity = arm_cpu_mp_affinity(smp.cpus[id].cpu);
    start_write(NULL, 8 + 4 * ((affinity >> 8) & 0xff),
                1u << (affinity & 0xff), 4);
}

static const ARMCPRegInfo pv_regs[] = {
    { .name = "DVM_PV_CPU_START", .state = ARM_CP_STATE_AA64,
      .access = PL1_W, .type = ARM_CP_OVERRIDE | ARM_CP_NO_RAW | ARM_CP_IO,
      .opc0 = 3, .opc1 = 0, .crn = 15, .crm = 15, .opc2 = 7,
      .writefn = pv_cpu_start },
};

static DarwinSMPCPU *smp_cpu(CPUARMState *env)
{
    unsigned idx = env_cpu(env)->cpu_index;
    assert(idx < smp.count);
    return &smp.cpus[idx];
}

static uint64_t ipi_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    BQL_LOCK_GUARD();
    return smp_cpu(env)->ipi_pending;
}

static void ipi_ack(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t value)
{
    BQL_LOCK_GUARD();
    DarwinSMPCPU *c = smp_cpu(env);
    c->ipi_pending &= ~(value & 1);
    qemu_set_irq(c->ipi, !!c->ipi_pending);
}

static void ipi_send(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t value)
{
    BQL_LOCK_GUARD();
    uint64_t affinity = value & 0xff;
    unsigned type = (value >> 28) & 3;

    if (type == 1) {
        return; /* Already delivered deferred IPIs cannot be retracted. */
    }
    if (type == 3) {
        qemu_log_mask(LOG_UNIMP, "darwin-smp: no-wake IPI not implemented\n");
        return;
    }
    affinity |= ri->opc2 ? ((value >> 8) & 0xff00) :
                         (arm_cpu_mp_affinity(env_archcpu(env)) & 0xffff00);
    for (unsigned i = 0; i < smp.count; i++) {
        DarwinSMPCPU *c = &smp.cpus[i];
        if (arm_cpu_mp_affinity(c->cpu) != affinity) {
            continue;
        }
        c->ipi_pending = 1;
        qemu_set_irq(c->ipi, 1);
        if (smp.debug) {
            fprintf(stderr, "darwin-smp: IPI %d -> %u type=%u\n",
                    env_cpu(env)->cpu_index, i, type);
        }
        return;
    }
    qemu_log_mask(LOG_GUEST_ERROR, "darwin-smp: IPI to absent affinity 0x%" PRIx64 "\n", affinity);
}

static const ARMCPRegInfo ipi_regs[] = {
    { .name = "IPI_RR_LOCAL_EL1", .state = ARM_CP_STATE_AA64,
      .access = PL1_W, .type = ARM_CP_OVERRIDE | ARM_CP_NO_RAW | ARM_CP_IO,
      .opc0 = 3, .opc1 = 5, .crn = 15, .crm = 0, .opc2 = 0,
      .writefn = ipi_send },
    { .name = "IPI_RR_GLOBAL_EL1", .state = ARM_CP_STATE_AA64,
      .access = PL1_W, .type = ARM_CP_OVERRIDE | ARM_CP_NO_RAW | ARM_CP_IO,
      .opc0 = 3, .opc1 = 5, .crn = 15, .crm = 0, .opc2 = 1,
      .writefn = ipi_send },
    { .name = "IPI_SR", .state = ARM_CP_STATE_AA64,
      .access = PL1_RW, .type = ARM_CP_OVERRIDE | ARM_CP_NO_RAW | ARM_CP_IO,
      .opc0 = 3, .opc1 = 5, .crn = 15, .crm = 1, .opc2 = 1,
      .readfn = ipi_read, .writefn = ipi_ack },
    { .name = "IPI_CR", .state = ARM_CP_STATE_AA64,
      .access = PL1_RW, .type = ARM_CP_OVERRIDE | ARM_CP_CONST,
      .opc0 = 3, .opc1 = 5, .crn = 15, .crm = 3, .opc2 = 1,
      .resetvalue = 0 },
};

void darwin_smp_register_cpu(ARMCPU *cpu)
{
    define_arm_cp_regs(cpu, ipi_regs);
    if (getenv("DARWIN_SMP_PV")) {
        define_arm_cp_regs(cpu, pv_regs);
    }
}

void darwin_smp_connect_cpu(ARMCPU *cpu)
{
    DeviceState *merge = qdev_new(TYPE_OR_IRQ);
    qdev_prop_set_uint16(merge, "num-lines", 2);
    qdev_realize_and_unref(merge, NULL, &error_fatal);
    qdev_connect_gpio_out(merge, 0,
                         qdev_get_gpio_in(DEVICE(cpu), ARM_CPU_FIQ));
    qdev_connect_gpio_out(DEVICE(cpu), GTIMER_HYPVIRT,
                         qdev_get_gpio_in(merge, 0));
    smp.cpus[CPU(cpu)->cpu_index].ipi = qdev_get_gpio_in(merge, 1);
}

static uint64_t rvbar_read(void *opaque, hwaddr offset, unsigned size)
{
    DarwinSMPCPU *c = opaque;
    return c->rvbar >> (offset * 8);
}

static void rvbar_write(void *opaque, hwaddr offset, uint64_t val, unsigned size)
{
    DarwinSMPCPU *c = opaque;
    if (!(c->rvbar & 1)) {
        uint64_t mask = MAKE_64BIT_MASK(offset * 8, size * 8);
        c->rvbar = (c->rvbar & ~mask) | ((val << (offset * 8)) & mask);
    }
}

static uint64_t state_read(void *opaque, hwaddr offset, unsigned size)
{
    DarwinSMPCPU *c = opaque;
    return offset == 0 && c->cpu->power_state == PSCI_ON ? 1 : 0;
}

static void state_write(void *opaque, hwaddr offset, uint64_t val, unsigned size)
{
    qemu_log_mask(LOG_UNIMP, "darwin-smp: CPU state write ignored\n");
}

static uint64_t start_read(void *opaque, hwaddr offset, unsigned size)
{
    return 0;
}

static void secondary_boot_state(CPUState *cs, run_on_cpu_data unused)
{
    CPUARMState *env = &ARM_CPU(cs)->env;
    /* Same firmware handoff as do_darwin_reset(). SPTM's secondary path
     * uses LDR Q0 at 24A5430a SPTM+0xd72a0 before enabling FP itself.
     * Queue after arm_set_cpu_on's reset, before the vCPU executes.
     */
    env->cp15.cpacr_el1 |= BIT(20) | BIT(21);
    env->cp15.cptr_el[2] |= BIT(20) | BIT(21);
    arm_rebuild_hflags(env);
}

static void start_write(void *opaque, hwaddr offset, uint64_t val, unsigned size)
{
    if (smp.debug) {
        fprintf(stderr, "darwin-smp: CPU_START +0x%" HWADDR_PRIx " = 0x%" PRIx64 "\n", offset, val);
    }
    if (offset < 8) {
        return;
    }
    unsigned cluster = (offset - 8) / 4;
    for (unsigned i = 1; i < smp.count; i++) {
        DarwinSMPCPU *c = &smp.cpus[i];
        uint64_t mpidr = arm_cpu_mp_affinity(c->cpu);
        if (((mpidr >> 8) & 0xff) == cluster &&
            (mpidr & 0xff) < 32 && (val & (1u << (mpidr & 0xff)))) {
            uint64_t entry = c->rvbar & MAKE_64BIT_MASK(12, 36);
            int result = arm_set_cpu_on(mpidr, entry, smp.boot_x0, 2, true);
            if (result == QEMU_ARM_POWERCTL_RET_SUCCESS) {
                arm_set_cpu_power_state(c->cpu, PSCI_ON_PENDING);
                async_run_on_cpu(CPU(c->cpu), secondary_boot_state,
                                 RUN_ON_CPU_NULL);
            }
            fprintf(stderr, "darwin-smp: start CPU %u affinity=0x%" PRIx64
                    " entry=0x%" PRIx64 " result=%d\n", i, mpidr, entry, result);
        }
    }
}

static const MemoryRegionOps rvbar_ops = {
    .read = rvbar_read, .write = rvbar_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 4, .valid.max_access_size = 8,
    .impl.min_access_size = 4, .impl.max_access_size = 8,
};
static const MemoryRegionOps state_ops = {
    .read = state_read, .write = state_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 4, .valid.max_access_size = 8,
    .impl.min_access_size = 4, .impl.max_access_size = 8,
};
static const MemoryRegionOps start_ops = {
    .read = start_read, .write = start_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 4, .valid.max_access_size = 4,
};

static int smp_cpu_post_load(void *opaque, int version)
{
    DarwinSMPCPU *c = opaque;
    qemu_set_irq(c->ipi, !!c->ipi_pending);
    return 0;
}

static const VMStateDescription vmstate_smp_cpu = {
    .name = "darwin-smp/cpu", .version_id = 1, .minimum_version_id = 1,
    .post_load = smp_cpu_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT64(rvbar, DarwinSMPCPU),
        VMSTATE_UINT64(ipi_pending, DarwinSMPCPU),
        VMSTATE_END_OF_LIST()
    },
};

void darwin_smp_reset(void)
{
    for (unsigned i = 0; i < smp.count; i++) {
        DarwinSMPCPU *c = &smp.cpus[i];
        c->rvbar = smp.reset_pc & ~0xfffull;
        c->ipi_pending = 0;
        qemu_set_irq(c->ipi, 0);
    }
}

void darwin_smp_init(ARMCPU **cpus, unsigned count,
                     struct dtree_node *dt, struct xnu_boot_info *info)
{
    struct dtree_node *nodes = adt_find_node(dt, "cpus");
    struct dtree_node *pmgr = adt_find_node(dt, "arm-io/pmgr");
    struct dtree_node *armio = adt_find_node(dt, "arm-io");
    uint64_t *ranges = armio ? adt_get_prop_val(armio, "ranges") : NULL;
    struct adt_io_reg *pmgr_reg = pmgr ? adt_get_prop_val(pmgr, "reg") : NULL;
    uint32_t *chip = adt_get_prop_val(adt_find_node(dt, "chosen"), "chip-id");
    const char *platform = adt_get_prop_val(dt, "platform-name");
    unsigned chip_id = chip ? *chip : 0;
    uint64_t start_off;

    /* IPSW trees leave chip-id zero; dt_fixup retains the SoC name. */
    if (!chip_id && platform && platform[0] == 't') {
        if (qemu_strtoui(platform + 1, NULL, 16, &chip_id)) {
            chip_id = 0;
        }
    }
    if (!chip_id || !pmgr_reg || !ranges) {
        error_report("darwin-smp: missing chip-id or PMGR registers");
        exit(1);
    }
    switch (chip_id) {
    case 0x8140:
        start_off = 0x34000; break;
    default:
        error_report("darwin-smp: experimental SMP currently supports T8140 only (got 0x%x)", chip_id);
        exit(1);
    }
    smp.count = count;
    smp.boot_x0 = info->init_x0;
    smp.reset_pc = info->init_pc;
    smp.debug = getenv("DARWIN_SMP_DEBUG") != NULL;
    unsigned i = 0;
    for (struct dtree_node *n = adt_first_child(nodes); n && i < count;
         n = adt_next_sibling(nodes, n), i++) {
        DarwinSMPCPU *c = &smp.cpus[i];
        struct adt_io_reg *r = adt_get_prop_val(n, "cpu-impl-reg");
        struct adt_io_reg *cpm = adt_get_prop_val(n, "cpm-impl-reg");
        uint32_t *die = adt_get_prop_val(n, "die-id");
        uint64_t affinity = arm_cpu_mp_affinity(cpus[i]);
        if (!r || r->len < 0x108 || !cpm || (die && *die) ||
            affinity > 0x101) {
            error_report("darwin-smp: unsupported CPU %u device-tree layout", i);
            exit(1);
        }
        for (unsigned j = 0; j < i; j++) {
            if (arm_cpu_mp_affinity(cpus[j]) == affinity) {
                error_report("darwin-smp: duplicate CPU affinity");
                exit(1);
            }
        }
        g_autofree char *name = g_strdup_printf("darwin-cpu%u-impl", i);
        c->cpu = cpus[i];
        c->rvbar = info->init_pc & ~0xfffull;
        memory_region_init_ram(&c->impl, OBJECT(cpus[i]), name, r->len, &error_fatal);
        memory_region_add_subregion_overlap(get_system_memory(), r->base, &c->impl, 1);
        memory_region_init_io(&c->rvbar_region, OBJECT(cpus[i]), &rvbar_ops, c, "rvbar", 8);
        memory_region_add_subregion_overlap(&c->impl, 0, &c->rvbar_region, 1);
        memory_region_init_io(&c->state_region, OBJECT(cpus[i]), &state_ops, c, "cpu-state", 8);
        memory_region_add_subregion_overlap(&c->impl, 0x100, &c->state_region, 1);
        vmstate_register(NULL, i, &vmstate_smp_cpu, c);
        bool mapped = false;
        for (unsigned j = 0; j < i; j++) {
            mapped |= smp.cpus[j].cpm_base == cpm->base;
        }
        c->cpm_base = cpm->base;
        if (!mapped) {
            g_autofree char *cpm_name = g_strdup_printf("darwin-cpm%u", i);
            memory_region_init_ram(&c->cpm, OBJECT(cpus[i]), cpm_name,
                                   cpm->len, &error_fatal);
            memory_region_add_subregion_overlap(get_system_memory(), cpm->base,
                                               &c->cpm, 1);
        }
    }
    memory_region_init_io(&smp.start_region, NULL, &start_ops, &smp, "darwin-cpu-start", 0x28);
    memory_region_add_subregion_overlap(get_system_memory(), ranges[1] + pmgr_reg->base + start_off,
                                       &smp.start_region, 1);
}
