/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Observed VMSA lock bootstrap: SPTM 0xfffffff0270b4558 writes
 * 0x8000000000000010/11. M5 VMSA_LOCK_EL2 field definitions identify bit 63
 * as SCTLR.M and bits 4..0 as TTBR1, TTBR0, TCR, SCTLR, VBAR locks.
 * Forbidden writes stop before mutation; their hardware exception/ignored
 * behavior is not inferred here. No reset or lower-EL lock bank yet.
 */
static int hvf_virtual_vmsa_write(CPUState *cpu, const ARMCPRegInfo *ri,
                                 uint64_t value)
{
    CPUARMState *env = cpu_env(cpu);
    const ARMCPRegInfo *control = get_arm_cp_reginfo(ARM_CPU(cpu)->cp_regs,
                                      ENCODE_AA64_CP_REG(3, 4, 15, 1, 5));
    uint64_t lock, bits = 0;

    if (!control || !control->readfn) {
        return -1;
    }
    lock = control->readfn(env, control);
    if (!strcmp(ri->name, "VMSA_LOCK_EL2")) {
        if (!hvf_vsh.active || !arm_apple_is_gl(env) || !ri->writefn ||
            (value != UINT64_C(0x8000000000000010) &&
             value != UINT64_C(0x8000000000000011)) || (lock & ~value)) {
            goto denied;
        }
        return 1;
    }
    if (!strcmp(ri->name, "TTBR1_EL2")) {
        bits = lock & BIT_ULL(4);
    } else if (!strcmp(ri->name, "TTBR0_EL2")) {
        bits = lock & BIT_ULL(3);
    } else if (!strcmp(ri->name, "TCR_EL2")) {
        bits = lock & BIT_ULL(2);
    } else if (!strcmp(ri->name, "VBAR_EL2")) {
        bits = lock & BIT_ULL(0);
    } else if (!strcmp(ri->name, "SCTLR_EL2")) {
        bits = lock & BIT_ULL(1);
        if ((lock & BIT_ULL(63)) &&
            ((value ^ env->cp15.sctlr_el[2]) & SCTLR_M)) {
            goto denied;
        }
    }
    if (bits && value != read_raw_cp_reg(env, ri)) {
        goto denied;
    }
    return 0;

denied:
    error_report("Virtual VMSA lock denied %s=0x%" PRIx64
                 " lock=0x%" PRIx64 " at 0x%" PRIx64,
                 ri->name, value, lock, env->pc);
    return -1;
}
