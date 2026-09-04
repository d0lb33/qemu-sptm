#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qom/object.h"
#include "system/address-spaces.h"
#include "system/reset.h"
#include "exec/memattrs.h"
#include "qemu/module.h"
#include "qemu/option.h"
#include "qemu/config-file.h"
#include "cpregs.h"
#include "system/system.h"
#include "xnu/apple_regs.h"
#include "hw/arm/apple_amcc.h"

typedef uint64_t usize;
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t  u8;

void log_read(const char *, CPUARMState *, const ARMCPRegInfo *);
void log_write(const char *, CPUARMState *, const ARMCPRegInfo *, u64 val);

#define APPLE_STATE(env) ((apple_state_t*)env->apple_state)

#define TAG_OFFSET_EL2_LOCK            BIT(63)

/* gxfstat: measurement counters, see include/xnu/gxfstat.h. The generated
 * accessors below reference gxfstat_sysreg_{rd,wr}. */
#include "xnu/gxfstat.h"

#include "apple_regs_autogen.h"

static uint64_t pmc0_read(CPUARMState *env, const ARMCPRegInfo *ri) {
    if (0 == env->pc) return 0;
    APPLE_STATE(env)->pmc0_internal_count += rand() % 10000;
    return APPLE_STATE(env)->pmc0_internal_count;
}

static void pmc0_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t val) {
}

static uint64_t pmc1_read(CPUARMState *env, const ARMCPRegInfo *ri) {
    if (0 == env->pc) return 0;
    APPLE_STATE(env)->pmc1_internal_count += rand() % 1000;
    return APPLE_STATE(env)->pmc1_internal_count;
}

static void pmc1_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t val) {
}

/*
 * Migration must not use the guest-visible PMC accessors above: reads advance
 * the synthetic counters and writes are intentionally ignored.  Raw access
 * stores and restores the backing values without side effects, which also
 * makes ARM's post-load write/read-back validation deterministic.
 */
static uint64_t pmc0_raw_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    return APPLE_STATE(env)->pmc0_internal_count;
}

static void pmc0_raw_write(CPUARMState *env, const ARMCPRegInfo *ri,
                           uint64_t val)
{
    APPLE_STATE(env)->pmc0_internal_count = val;
}

static uint64_t pmc1_raw_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    return APPLE_STATE(env)->pmc1_internal_count;
}

static void pmc1_raw_write(CPUARMState *env, const ARMCPRegInfo *ri,
                           uint64_t val)
{
    APPLE_STATE(env)->pmc1_internal_count = val;
}

typedef struct {
    uint64_t   pmc0;
    uint64_t   pmc1;
} apple_pmc_t;

static const ARMCPRegInfo apple_pmcregs[] = {
    {
        .name = "PMC0", .state = ARM_CP_STATE_AA64, .access = PL1_RW,
        .opc0 = 3, .opc1 = 2, .crn = 15, .crm = 0, .opc2 = 0,
        .readfn = pmc0_read, .writefn = pmc0_write,
        .raw_readfn = pmc0_raw_read, .raw_writefn = pmc0_raw_write,
    },
    {
        .name = "PMC1", .state = ARM_CP_STATE_AA64, .access = PL1_RW,
        .opc0 = 3, .opc1 = 2, .crn = 15, .crm = 1, .opc2 = 0,
        .readfn = pmc1_read, .writefn = pmc1_write,
        .raw_readfn = pmc1_raw_read, .raw_writefn = pmc1_raw_write,
    },
};

static bool apple_cpu_state_needed(void *opaque)
{
    ARMCPU *cpu = opaque;

    return cpu->env.apple_state != NULL;
}

const VMStateDescription vmstate_apple_cpu = {
    .name = "cpu/apple-darwin",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = apple_cpu_state_needed,
    .fields = (const VMStateField[]) {
        /*
         * apple_state_t is generated from the complete IMP-DEF register list.
         * It contains values only; its address is destination-local.
         */
        VMSTATE_BUFFER_POINTER_UNSAFE(env.apple_state, ARMCPU, 1,
                                      sizeof(apple_state_t)),
        VMSTATE_UINT64_ARRAY(env.sprr_config_el, ARMCPU, 4),
        VMSTATE_UINT64_ARRAY(env.sprr_pperm_el, ARMCPU, 4),
        VMSTATE_UINT64(env.sprr_uperm_el0, ARMCPU),
        VMSTATE_UINT64_ARRAY(env.gxf_config_el, ARMCPU, 4),
        VMSTATE_UINT64_ARRAY(env.gxf_entry_el, ARMCPU, 4),
        VMSTATE_UINT64_ARRAY(env.gxf_pabentry_el, ARMCPU, 4),
        VMSTATE_UINT64_ARRAY(env.sp_gl, ARMCPU, 4),
        VMSTATE_UINT64_ARRAY(env.tpidr_gl, ARMCPU, 4),
        VMSTATE_UINT64_ARRAY(env.aspsr_gl, ARMCPU, 4),
        VMSTATE_UINT64_ARRAY(env.vbar_gl, ARMCPU, 4),
        VMSTATE_UINT64_ARRAY(env.far_gl, ARMCPU, 4),
        VMSTATE_UINT64_ARRAY(env.esr_gl, ARMCPU, 4),
        VMSTATE_UINT64_ARRAY(env.elr_gl, ARMCPU, 4),
        VMSTATE_UINT64_ARRAY(env.spsr_gl, ARMCPU, 4),
        VMSTATE_UINT64_ARRAY(env.pmcr1_gl, ARMCPU, 4),
        VMSTATE_UINT64_ARRAY(env.afsr1_gl, ARMCPU, 4),
        VMSTATE_UINT64(env.currentg, ARMCPU),
        VMSTATE_END_OF_LIST()
    },
};

static u64 *_adt_find_region(struct dtree_node *dt_root, const char *name) {
    struct dtree_node *mem_map = adt_find_node(dt_root, "chosen/memory-map");
    assert(mem_map);
    u64 *map_val = adt_get_prop_val(mem_map, name);
    assert(map_val);
    return map_val;
}

static hwaddr adt_find_region_first_page(struct dtree_node *dt_root, const char *name) {
    return _adt_find_region(dt_root, name)[0];
}

static hwaddr adt_find_region_last_page(struct dtree_node *dt_root, const char *name) {
    // This needs to be the start of the last 4K (NOT 16K) page in the region
    u64 *m = _adt_find_region(dt_root, name);
    return m[0] + m[1] - 0x1000;
}

void apple_regs_init(ARMCPU *cpu, AMCCState *amcc, struct dtree_node *dt_root, struct xnu_boot_info *info) {
    CPUARMState *env = &cpu->env;
    env->currentg = 0;
    env->apple_state = malloc(sizeof(apple_state_t));
    memset(env->apple_state, '\x00', sizeof(apple_state_t));

    // Magic numbers to make SPTM/ XNU happy
    APPLE_STATE(env)->apctl_el1 = 0xFF;
    APPLE_STATE(env)->apsts_el1 = 0xFF;
    APPLE_STATE(env)->apsts_el2 = 0xFF;
    APPLE_STATE(env)->amxidr_el1 = 0x10003;
    APPLE_STATE(env)->ctrr_a_ctl_el2     = 0x8000000000000001;
    APPLE_STATE(env)->ctrr_b_ctl_el2     = 0x8000000000000001;
    APPLE_STATE(env)->acc_ctrr_a_ctl_el2 = 0x8000000000000001;
    APPLE_STATE(env)->acc_ctrr_b_ctl_el2 = 0x8000000000000001;
    APPLE_STATE(env)->acc_ctrr_c_ctl_el2 = 0x8000000000000001;
    APPLE_STATE(env)->acc_ctxr_a_ctl_el2 = 0xc000000000aa019a;
    APPLE_STATE(env)->acc_ctxr_b_ctl_el2 = 0xc0000000009a02aa;
    APPLE_STATE(env)->acc_ctxr_c_ctl_el2 = 0xc000000000aa026a;
    APPLE_STATE(env)->acc_ctxr_d_ctl_el2 = 0xc000000000aa02a9;

#define REGION_START(s) adt_find_region_first_page(dt_root, s)
#define REGION_END(s)   adt_find_region_last_page(dt_root, s)

    // iPhone 13 and 14 rorgn_start and rorgn_end come from ctrr A
    // If these are not correct, you'll get the following:
    // panic(cpu 0 caller ...): zalloc_ro_mut failed: source (...) not from RO zone map (...), current stack (...) or const memory (phys 0 - 0xfff) @zalloc.c:6733
    // the giveaway here is "cosnt memory" being from 0 to 0xfff- this is what happens when a CTRR region is from [0,0].
    APPLE_STATE(env)->ctrr_a_lwr_el2 = REGION_START("BootKC-rx");
    APPLE_STATE(env)->ctrr_a_upr_el2 = REGION_END("BootKC-rs");

    // CTRR region C: [DeviceTree, SPTM-rx]
    APPLE_STATE(env)->acc_ctrr_c_lwr_el2 = REGION_START("DeviceTree");
    APPLE_STATE(env)->acc_ctrr_c_upr_el2 = REGION_END("SPTM-rx");
    if (amcc) {
        amcc->ctrr_lwr[AMCC_BANK_C] = APPLE_STATE(env)->acc_ctrr_c_lwr_el2;
        amcc->ctrr_upr[AMCC_BANK_C] = APPLE_STATE(env)->acc_ctrr_c_upr_el2;
    }

    // CTXR region A: [SPTM-rx, SPTM-rw]
    APPLE_STATE(env)->acc_ctxr_a_lwr_el2 = REGION_START("SPTM-rx");
    APPLE_STATE(env)->acc_ctxr_a_upr_el2 = REGION_END("SPTM-rx");

    // CTXR region B: [CL4-dummypage]
    APPLE_STATE(env)->acc_ctxr_b_lwr_el2 = REGION_START("CL4-dummypage");
    APPLE_STATE(env)->acc_ctxr_b_upr_el2 = REGION_END("CL4-dummypage");

    // CTXR region C: [TXM-rx, TXM-bx]
    APPLE_STATE(env)->acc_ctxr_c_lwr_el2 = REGION_START("TXM-rx");
    APPLE_STATE(env)->acc_ctxr_c_upr_el2 = REGION_END("TXM-bx");

    // CTXR region D: [BootKC-rx, BootKC-bx]
    APPLE_STATE(env)->acc_ctxr_d_lwr_el2 = REGION_START("BootKC-rx");
    APPLE_STATE(env)->acc_ctxr_d_upr_el2 = REGION_END("BootKC-bx");

#undef REGION_START
#undef REGION_END

    // TagOffset_EL2 needs to be the last 1/32nd of physical memory
    //
    // When boot args memsize is 31/32 of dram size, we need to move the tag
    // offset forward another 1/32nd, so we subtract 2 * (1/32) of dram size.
    APPLE_STATE(env)->tag_offset_el2 = TAG_OFFSET_EL2_LOCK |
        (info->dram_base + info->dram_size - ((2 * info->dram_size) / 32));

    define_arm_cp_regs(cpu, apple_sysregs);
    define_arm_cp_regs(cpu, apple_pmcregs);
    gxfstat_start();
}
