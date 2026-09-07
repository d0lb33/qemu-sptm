/*
 * Apple AMX (Apple Matrix eXtensions) for the darwin-vm machine.
 *
 * Why: on the iOS 27 guest, MercuryPosterExt, iconservicesagent, audiomxd
 * and mediaanalysisd die with SIGILL on their first AMX instruction
 * (`set`, 0x00201220) because nothing implemented the space
 * (docs/re/tcg-idle-profile.md, crash census).  The kernel itself enables
 * AMX per CPU and per thread; without the unit, userspace never gets past
 * the first instruction.
 *
 * Instruction semantics come from corsix/amx (tcg/amx/, MIT), the same
 * reference the guest's libraries were written against by observation.  The
 * control contract is read out of the 24A5430a kernelcache
 * (docs/re/native-amx.md):
 *
 *   AMX_CONFIG_EL1 (S3_4_C15_C1_4)  bit 8: CPU enable, written 0x100 at
 *                                   CPU init (kernel+0xc6da0c); bit 63:
 *                                   thread enable, ORed in at
 *                                   kernel+0xc701dc, read back at +0xc70038.
 *   AMX_STATE_T_EL1 (S3_4_C15_C1_3) non-zero while the unit holds live
 *                                   state (after `set`); the switch path
 *                                   tests it at kernel+0xc70054 to decide
 *                                   whether to save.
 *   AMXIDR_EL1 (S3_6_C15_C2_7)      bit (version-1) advertises the AMX
 *                                   version; the kernel maps bits 0..5 to
 *                                   versions 1..6 (kernel+0xb359e6c).
 *   AMX_CONTEXT_EL1 (S3_4_C15_C5_0) written with the CPU id for versions
 *                                   2 and 3 (kernel+0xc6da1c); opaque here.
 *
 * An AMX instruction while the thread bit is clear raises the synchronous
 * exception the kernel's handler classifies as AMX: EC 0x3f with ISS
 * (esr & 0x1fffff8) == 0x18 (kernel+0xc65624, +0xc65f88).  The kernel then
 * allocates the thread's save area, sets bit 63 and returns to retry.
 *
 * Loads and stores go through the guest MMU with the current mmu index, so
 * the kernel's save/restore at EL2 and userspace at EL0 both work and
 * faults on the operand address are ordinary data aborts at this PC.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "internals.h"
#include "cpregs.h"
#include "syndrome.h"
#include "helper-amx.h"
#include "accel/tcg/cpu-ldst.h"
#include "amx.h"
#include "amx/amx_emulate.h"

#define HELPER_H "tcg/helper-amx-defs.h"
#include "exec/helper-info.c.inc"

/* Generation for the corsix semantics; set from the advertised version. */
uint32_t AMX_VER = AMX_VER_M3;

#define LDST_MULTIPLE            (1ull << 62)
#define LDST_NON_CONSECUTIVE     (1ull << 61)
#define LDST_MULTIPLE_MEANS_FOUR (1ull << 60)

static inline amx_state *amx_regs(CPUARMState *env)
{
    return (amx_state *)env->amx.regs;
}

static inline uint64_t amx_addr(uint64_t operand)
{
    return (operand << 8) >> 8;   /* 56-bit address, register number above */
}

static void amx_load_row(CPUARMState *env, amx_reg *reg, uint64_t addr, uintptr_t ra)
{
    for (int i = 0; i < 8; i++) {
        uint64_t v = cpu_ldq_le_data_ra(env, addr + 8 * i, ra);
        memcpy(reg->u8 + 8 * i, &v, sizeof(v));
    }
}

static void amx_store_row(CPUARMState *env, const amx_reg *reg, uint64_t addr, uintptr_t ra)
{
    for (int i = 0; i < 8; i++) {
        uint64_t v;
        memcpy(&v, reg->u8 + 8 * i, sizeof(v));
        cpu_stq_le_data_ra(env, addr + 8 * i, v, ra);
    }
}

/* corsix ldst.c ld_common, with guest memory instead of host pointers. */
static void amx_ld_common(CPUARMState *env, amx_reg *regs, uint64_t operand,
                          uint32_t regmask, uintptr_t ra)
{
    uint32_t rn = (operand >> 56) & regmask;
    uint64_t src = amx_addr(operand);

    amx_load_row(env, regs + rn, src, ra);
    if (operand & LDST_MULTIPLE) {
        uint32_t rs = 1;
        if (AMX_VER >= AMX_VER_M3 && (operand & LDST_NON_CONSECUTIVE) && regmask <= 15) {
            rs = (operand & LDST_MULTIPLE_MEANS_FOUR) ? 2 : 4;
        }
        amx_load_row(env, regs + ((rn + rs) & regmask), src + 64, ra);
        if (AMX_VER >= AMX_VER_M2 && (operand & LDST_MULTIPLE_MEANS_FOUR) && regmask <= 15) {
            amx_load_row(env, regs + ((rn + rs * 2) & regmask), src + 128, ra);
            amx_load_row(env, regs + ((rn + rs * 3) & regmask), src + 192, ra);
        }
    }
}

static void amx_st_common(CPUARMState *env, const amx_reg *regs, uint64_t operand,
                          uint32_t regmask, uintptr_t ra)
{
    uint32_t rn = (operand >> 56) & regmask;
    uint64_t dst = amx_addr(operand);

    amx_store_row(env, regs + rn, dst, ra);
    if (operand & LDST_MULTIPLE) {
        amx_store_row(env, regs + ((rn + 1) & regmask), dst + 64, ra);
    }
}

static void amx_ldzi(CPUARMState *env, amx_state *st, uint64_t operand, uintptr_t ra)
{
    uint32_t rn = (operand >> 56) & 63;
    uint32_t half = (rn & 1) << 3;
    uint64_t src = amx_addr(operand);

    for (uint32_t i = 0; i < 16; i++) {
        uint32_t v = cpu_ldl_le_data_ra(env, src + 4 * i, ra);
        st->z[bit_select(rn, i, 1)].u32[half + (i >> 1)] = v;
    }
}

static void amx_stzi(CPUARMState *env, const amx_state *st, uint64_t operand, uintptr_t ra)
{
    uint32_t rn = (operand >> 56) & 63;
    uint32_t half = (rn & 1) << 3;
    uint64_t dst = amx_addr(operand);

    for (uint32_t i = 0; i < 16; i++) {
        cpu_stl_le_data_ra(env, dst + 4 * i,
                           st->z[bit_select(rn, i, 1)].u32[half + (i >> 1)], ra);
    }
}

static int amx_debug = -1;

static void amx_log(CPUARMState *env, const char *what, uint32_t op, uint64_t operand)
{
    static unsigned printed;

    if (amx_debug < 0) {
        amx_debug = getenv("DARWIN_AMX_DEBUG") != NULL;
    }
    if (amx_debug && printed < 200) {
        printed++;
        fprintf(stderr, "amx: %s op=%u operand=0x%" PRIx64 " pc=0x%" PRIx64
                " el=%d config=0x%" PRIx64 " active=%u\n", what, op, operand,
                env->pc, arm_current_el(env), env->amx.config, env->amx.active);
    }
}

static G_NORETURN void amx_trap(CPUARMState *env, uint32_t op, uint64_t operand,
                                uintptr_t ra)
{
    amx_log(env, "trap (thread/cpu disabled)", op, operand);
    raise_exception_ra(env, EXCP_UDEF, AMX_TRAP_SYNDROME,
                       exception_target_el(env), ra);
}

void HELPER(amx)(CPUARMState *env, uint32_t op, uint64_t operand)
{
    uintptr_t ra = GETPC();
    amx_state *st = amx_regs(env);

    if (!env->amx.version) {
        raise_exception_ra(env, EXCP_UDEF, syn_uncategorized(),
                           exception_target_el(env), ra);
    }
    if (!(env->amx.config & AMX_CONFIG_CPU_ENABLE) ||
        !(env->amx.config & AMX_CONFIG_THREAD_ENABLE)) {
        amx_trap(env, op, operand, ra);
    }

    switch (op) {
    case 0:  amx_ld_common(env, st->x, operand, 7, ra); break;
    case 1:  amx_ld_common(env, st->y, operand, 7, ra); break;
    case 2:  amx_st_common(env, st->x, operand, 7, ra); break;
    case 3:  amx_st_common(env, st->y, operand, 7, ra); break;
    case 4:  amx_ld_common(env, st->z, operand, 63, ra); break;
    case 5:  amx_st_common(env, st->z, operand, 63, ra); break;
    case 6:  amx_ldzi(env, st, operand, ra); break;
    case 7:  amx_stzi(env, st, operand, ra); break;
    case 8:  emulate_AMX_EXTRX(st, operand); break;
    case 9:  emulate_AMX_EXTRY(st, operand); break;
    case 10: emulate_AMX_FMA64(st, operand); break;
    case 11: emulate_AMX_FMS64(st, operand); break;
    case 12: emulate_AMX_FMA32(st, operand); break;
    case 13: emulate_AMX_FMS32(st, operand); break;
    case 14: emulate_AMX_MAC16(st, operand); break;
    case 15: emulate_AMX_FMA16(st, operand); break;
    case 16: emulate_AMX_FMS16(st, operand); break;
    case 17:
        if (operand & 1) {          /* clr */
            env->amx.active = 0;
        } else {                    /* set: zero everything, become live */
            /*
             * corsix setclr.md says hardware raises an invalid-instruction
             * exception when the unit is already set up. Raising UNDEF here
             * reproduced the SIGILL this device exists to remove
             * (SYS_AMX3: 9 crashes on `set` after the kernel switched
             * threads without `clr`), so a repeated `set` re-initialises.
             */
            if (env->amx.active) {
                amx_log(env, "set while live (re-initialising)", op, operand);
            }
            memset(st, 0, sizeof(*st));
            env->amx.active = 1;
        }
        break;
    case 18: emulate_AMX_VECINT(st, operand); break;
    case 19: emulate_AMX_VECFP(st, operand); break;
    case 20: emulate_AMX_MATINT(st, operand); break;
    case 21: emulate_AMX_MATFP(st, operand); break;
    case 22: emulate_AMX_GENLUT(st, operand); break;
    default:
        amx_log(env, "unknown op (UNDEF)", op, operand);
        raise_exception_ra(env, EXCP_UDEF, syn_uncategorized(),
                           exception_target_el(env), ra);
    }
}

/* ---- control registers ---- */

static uint64_t amxidr_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    return env->amx.version ? 1ull << (env->amx.version - 1) : 0;
}

static uint64_t amx_state_t_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    return env->amx.active;
}

static void amx_state_t_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t val)
{
    env->amx.active = val != 0;
}

static uint64_t amx_config_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    return env->amx.config;
}

static void amx_config_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t val)
{
    env->amx.config = val;
}

static uint64_t amx_context_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    return env->amx.context;
}

static void amx_context_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t val)
{
    env->amx.context = val;
}

/* These replace the generated opaque accessors (ARM_CP_OVERRIDE). */
static const ARMCPRegInfo amx_cp_regs[] = {
    { .name = "AMXIDR_EL1", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 6, .crn = 15, .crm = 2, .opc2 = 7,
      .access = PL1_R, .type = ARM_CP_OVERRIDE | ARM_CP_NO_RAW,
      .readfn = amxidr_read },
    { .name = "AMX_STATE_T_EL1", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 4, .crn = 15, .crm = 1, .opc2 = 3,
      .access = PL1_RW, .type = ARM_CP_OVERRIDE | ARM_CP_NO_RAW,
      .readfn = amx_state_t_read, .writefn = amx_state_t_write },
    { .name = "AMX_CONFIG_EL1", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 4, .crn = 15, .crm = 1, .opc2 = 4,
      .access = PL1_RW, .type = ARM_CP_OVERRIDE | ARM_CP_NO_RAW,
      .readfn = amx_config_read, .writefn = amx_config_write },
    { .name = "AMX_CONTEXT_EL1", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 4, .crn = 15, .crm = 5, .opc2 = 0,
      .access = PL1_RW, .type = ARM_CP_OVERRIDE | ARM_CP_NO_RAW,
      .readfn = amx_context_read, .writefn = amx_context_write },
};

void arm_amx_init(ARMCPU *cpu, uint32_t version)
{
    CPUARMState *env = &cpu->env;

    memset(&env->amx, 0, sizeof(env->amx));
    env->amx.version = version;
    if (!version) {
        return;
    }
    AMX_VER = version;
    define_arm_cp_regs(cpu, amx_cp_regs);
}
