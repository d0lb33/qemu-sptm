/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * CTRR/CTXR range programming and the observed activation sequence.
 * SPTM 0xfffffff0270bba90..bbae8 supplies inclusive byte upper bounds; its
 * checker at 0xfffffff0270b42d0 and 0xfffffff0270b4334 expects 4 KiB masking.
 * The M5 register field dump specifies address bits [41:12]. The bounds are
 * stored exactly as written (the TCG model in hw/arm/apple_regs.c does the
 * same and masks at its comparison sites), so guest readbacks match TCG.
 *
 * Control registers follow the sequence captured in
 * docs/re/hvf-sptm-bootstrap.md from SPTM 0xfffffff0270bbcec..bbd98
 * (CTXR A-D) and 0xfffffff0270bbefc/bbf14 (CTRR C):
 *
 *   CTXR_x_CTL:  0 -> 0x4000000000000000 -> 0x40000000_00xxxxxx -> bit 63 set
 *   CTRR_C_CTL:  0 -> 1 (WRPROTECT)      -> 0x8000000000000001 (LOCK)
 *
 * Bit 63 is LOCK and CTRR bit 0 is WRPROTECT in the M5 field dump; the CTXR
 * low configuration fields and bit 62 have no documented semantics and are
 * stored without enforcement, exactly as the TCG model stores them (its
 * reset values in apple_regs.c are these same words). Enforcement available
 * to the shadow is limited to hvf_vsh_ctrr_write_allowed(). Once LOCK is
 * set, every further change stops rather than guessing the hardware's
 * rejected-write behaviour.
 */
static int hvf_virtual_control_write(CPUState *cpu, const ARMCPRegInfo *ri,
                                     uint64_t value)
{
    CPUARMState *env = cpu_env(cpu);
    static const char *const names[] = {
        "CTXR_A_CTL_EL2", "CTXR_B_CTL_EL2", "CTXR_C_CTL_EL2", "CTXR_D_CTL_EL2",
        "CTRR_C_CTL_EL2", "CTRR_D_CTL_EL2",
    };
    const uint64_t lock = BIT_ULL(63), enable = BIT_ULL(62);
    uint64_t current;
    bool ctxr, ok;
    unsigned i;

    for (i = 0; i < ARRAY_SIZE(names); i++) {
        if (!strcmp(ri->name, names[i])) {
            break;
        }
    }
    if (i == ARRAY_SIZE(names)) {
        return 0;
    }
    ctxr = i < 4;
    if (!ri->readfn || !ri->writefn) {
        return -1;
    }
    current = ri->readfn(env, ri);
    if (value == current) {
        return 1;
    }
    if (!hvf_vsh.active || !arm_apple_is_gl(env) || (current & lock)) {
        ok = false;
    } else if (ctxr) {
        ok = (current == 0 && value == enable) ||
             (current == enable && (value & (lock | enable)) == enable &&
              !(value & ~UINT64_C(0x4000000000ffffff))) ||
             ((current & enable) && !(current & lock) &&
              value == (current | lock));
    } else {
        ok = (current == 0 && value == 1) ||
             (current == 1 && value == (lock | 1));
    }
    if (!ok) {
        error_report("Virtual protection control denied: %s current=0x%"
                     PRIx64 " value=0x%" PRIx64 " at 0x%" PRIx64,
                     ri->name, current, value, env->pc);
        return -1;
    }
    return 1;
}

static int hvf_virtual_range_write(CPUState *cpu, const ARMCPRegInfo *ri,
                                   uint64_t *value)
{
    int control = hvf_virtual_control_write(cpu, ri, *value);

    if (control) {
        return control;
    }
    static const struct {
        const char *prefix;
        uint32_t control;
    } banks[] = {
        { "CTRR_C_", ENCODE_AA64_CP_REG(3, 0, 11, 2, 0) },
        { "CTRR_D_", ENCODE_AA64_CP_REG(3, 0, 11, 2, 1) },
        { "CTXR_A_", ENCODE_AA64_CP_REG(3, 0, 11, 6, 2) },
        { "CTXR_B_", ENCODE_AA64_CP_REG(3, 0, 11, 6, 3) },
        { "CTXR_C_", ENCODE_AA64_CP_REG(3, 0, 11, 6, 4) },
        { "CTXR_D_", ENCODE_AA64_CP_REG(3, 0, 11, 6, 5) },
    };

    for (unsigned i = 0; i < ARRAY_SIZE(banks); i++) {
        if (strncmp(ri->name, banks[i].prefix, 7) ||
            (strcmp(ri->name + 7, "LWR_EL2") &&
             strcmp(ri->name + 7, "UPR_EL2"))) {
            continue;
        }
        const ARMCPRegInfo *ctl = get_arm_cp_reginfo(ARM_CPU(cpu)->cp_regs,
                                                     banks[i].control);
        uint64_t control;
        if (!ctl || !ctl->readfn) {
            return -1;
        }
        control = ctl->readfn(cpu_env(cpu), ctl);
        /*
         * Permit only the initial all-zero control state. Changing an active
         * range needs permission revocation; changing a locked range must
         * not overwrite the model's backing through its plain accessor.
         */
        if (control || (*value >> 42)) {
            error_report("Virtual protection range denied: %s control=0x%"
                         PRIx64 " value=0x%" PRIx64,
                         ri->name, control, *value);
            return -1;
        }
        return 1;
    }
    return 0;
}
