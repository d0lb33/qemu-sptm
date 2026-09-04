#include "qemu/osdep.h"
#include "qemu/error-report.h"
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

#define LLC_RAM_CONFIG_ACTIVE          BIT(63)
#define LLC_RAM_CONFIG_REQUEST_MASK    MAKE_64BIT_MASK(0, 6)
#define LLC_RAM_CONFIG_UNIT_SHIFT_MASK MAKE_64BIT_MASK(8, 6)
#define LLC_RAM_CONFIG_MAX_COUNT_MASK  MAKE_64BIT_MASK(16, 6)
#define LLC_RAM_CONFIG_GEOMETRY_MASK \
    (LLC_RAM_CONFIG_UNIT_SHIFT_MASK | LLC_RAM_CONFIG_MAX_COUNT_MASK)

/* gxfstat: measurement counters, see include/xnu/gxfstat.h. The generated
 * accessors below reference gxfstat_sysreg_{rd,wr}. */
#include "xnu/gxfstat.h"

#include "apple_regs_autogen.h"

static uint64_t pmc0_read(CPUARMState *env, const ARMCPRegInfo *ri) {
    if (0 == env->pc) return 0;
    static uint64_t internal_count = 0;
    internal_count += rand() % 10000;
    return internal_count;
}

static void pmc0_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t val) {
}

static uint64_t pmc1_read(CPUARMState *env, const ARMCPRegInfo *ri) {
    if (0 == env->pc) return 0;
    static uint64_t internal_count = 0;
    internal_count += rand() % 1000;
    return internal_count;
}

static void pmc1_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t val) {
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
    },
    {
        .name = "PMC1", .state = ARM_CP_STATE_AA64, .access = PL1_RW,
        .opc0 = 3, .opc1 = 2, .crn = 15, .crm = 1, .opc2 = 0,
        .readfn = pmc1_read, .writefn = pmc1_write,
    },
};

static uint64_t apple_apiakey_el2_read(CPUARMState *env,
                                       const ARMCPRegInfo *ri)
{
    uint64_t value = raw_read(env, ri);

    fprintf(stderr, "iBoot experiment: %s read pc=0x%" PRIx64
            " value=0x%" PRIx64 "\n", ri->name, env->pc, value);
    return value;
}

static void apple_apiakey_el2_write(CPUARMState *env,
                                    const ARMCPRegInfo *ri, uint64_t value)
{
    raw_write(env, ri, value);
    fprintf(stderr, "iBoot experiment: %s write pc=0x%" PRIx64
            " value=0x%" PRIx64 "\n", ri->name, env->pc, value);
}

/*
 * Apple exposes the instruction-address pointer-authentication key at EL2
 * through S3_6_c15_c13_{0,1}.  iBoot writes two independently generated
 * 64-bit values here before it enables later authenticated control flow.
 * Alias QEMU's architected APIA state so the existing TCG pauth helpers see
 * the guest's keys; do not accept and discard these writes.
 */
static const ARMCPRegInfo apple_apiakey_el2_regs[] = {
    {
        .name = "APIAKEYLO_EL2", .state = ARM_CP_STATE_AA64,
        .access = PL2_RW, .type = ARM_CP_ALIAS,
        .opc0 = 3, .opc1 = 6, .crn = 15, .crm = 13, .opc2 = 0,
        .fieldoffset = offsetof(CPUARMState, keys.apia.lo),
        .readfn = apple_apiakey_el2_read,
        .writefn = apple_apiakey_el2_write,
    },
    {
        .name = "APIAKEYHI_EL2", .state = ARM_CP_STATE_AA64,
        .access = PL2_RW, .type = ARM_CP_ALIAS,
        .opc0 = 3, .opc1 = 6, .crn = 15, .crm = 13, .opc2 = 1,
        .fieldoffset = offsetof(CPUARMState, keys.apia.hi),
        .readfn = apple_apiakey_el2_read,
        .writefn = apple_apiakey_el2_write,
    },
};

static uint64_t llc_ram_config_read(CPUARMState *env,
                                    const ARMCPRegInfo *ri)
{
    uint64_t value = APPLE_STATE(env)->llc_ram_config;

    fprintf(stderr, "iBoot experiment: LLC_RAM_CONFIG read pc=0x%" PRIx64
            " value=0x%" PRIx64 "\n", env->pc, value);
    return value;
}

static void llc_ram_config_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                 uint64_t value)
{
    uint64_t old = APPLE_STATE(env)->llc_ram_config;
    uint64_t geometry = old & LLC_RAM_CONFIG_GEOMETRY_MASK;
    uint64_t request = value & LLC_RAM_CONFIG_REQUEST_MASK;
    uint64_t writable = LLC_RAM_CONFIG_ACTIVE | LLC_RAM_CONFIG_REQUEST_MASK;

    if ((value & ~writable) != geometry) {
        error_report("iBoot experiment: LLC_RAM_CONFIG write at pc=0x%"
                     PRIx64 " changed inferred read-only geometry: old=0x%"
                     PRIx64 " value=0x%" PRIx64, env->pc, old, value);
        exit(EXIT_FAILURE);
    }

    APPLE_STATE(env)->llc_ram_config = geometry | request |
        (request ? LLC_RAM_CONFIG_ACTIVE : 0);
    fprintf(stderr, "iBoot experiment: LLC_RAM_CONFIG write pc=0x%" PRIx64
            " request=%" PRIu64 " result=0x%" PRIx64 "\n", env->pc,
            request, APPLE_STATE(env)->llc_ram_config);
}

static const ARMCPRegInfo apple_llc_ram_config_reg[] = {
    {
        .name = "LLC_RAM_CONFIG", .state = ARM_CP_STATE_AA64,
        .access = PL1_RW,
        .opc0 = 3, .opc1 = 3, .crn = 15, .crm = 7, .opc2 = 0,
        .readfn = llc_ram_config_read, .writefn = llc_ram_config_write,
    },
};

static void apple_llc_ram_config_init(ARMCPU *cpu,
                                      struct dtree_node *dt_root)
{
    CPUARMState *env = &cpu->env;
    const char *ways = getenv("DARWIN_IBOOT_LLC_WAYS");
    struct dtree_node *cpu0;
    uint32_t *l2_size_prop;
    uint64_t unit;
    unsigned shift;

    if (!ways) {
        return;
    }
    if (strcmp(ways, "16") != 0) {
        error_report("DARWIN_IBOOT_LLC_WAYS is an experimental hypothesis;"
                     " this bounded probe supports only the 16-unit model");
        exit(EXIT_FAILURE);
    }

    cpu0 = adt_find_node(dt_root, "cpus/cpu0");
    l2_size_prop = cpu0 ? adt_get_prop_val(cpu0, "l2-cache-size") : NULL;
    if (!l2_size_prop ||
        adt_get_prop_len(cpu0, "l2-cache-size") != sizeof(*l2_size_prop) ||
        *l2_size_prop == 0 || (*l2_size_prop % 16) != 0) {
        error_report("DARWIN_IBOOT_LLC_WAYS=16 requires a valid cpu0"
                     " l2-cache-size device-tree property");
        exit(EXIT_FAILURE);
    }

    unit = *l2_size_prop / 16;
    if (!is_power_of_2(unit)) {
        error_report("cpu0 l2-cache-size/16 is not a power of two");
        exit(EXIT_FAILURE);
    }
    shift = ctz64(unit);
    if (shift > 63) {
        error_report("cpu0 LLC allocation-unit shift does not fit its field");
        exit(EXIT_FAILURE);
    }

    APPLE_STATE(env)->llc_ram_config =
        deposit64(0, 8, 6, shift) | deposit64(0, 16, 6, 16);
    define_arm_cp_regs(cpu, apple_llc_ram_config_reg);
    fprintf(stderr, "iBoot experiment: enabled inferred LLC_RAM_CONFIG:"
            " l2-size=0x%x ways=16 unit=0x%" PRIx64
            " reset=0x%" PRIx64 "\n", *l2_size_prop, unit,
            APPLE_STATE(env)->llc_ram_config);
}

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

    if (!info->iboot) {
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
    }

    /* The direct loader populates chosen/memory-map and establishes the
     * protected ranges above.  iBoot mode deliberately loads none of those
     * artifacts, so leave their reset-zero bounds for iBoot to program rather
     * than manufacturing security state from sentinel device-tree entries. */

    define_arm_cp_regs(cpu, apple_sysregs);
    define_arm_cp_regs(cpu, apple_pmcregs);
    if (info->iboot) {
        define_arm_cp_regs(cpu, apple_apiakey_el2_regs);
        apple_llc_ram_config_init(cpu, dt_root);
    }
    gxfstat_start();
}
