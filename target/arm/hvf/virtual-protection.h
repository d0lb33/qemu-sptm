/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Initial inactive CTRR/CTXR range programming. This is deliberately separate
 * from activation: accepting a stored control value does not enforce it.
 * SPTM 0xfffffff0270bba90..bbae8 supplies inclusive byte upper bounds; its
 * checker at 0xfffffff0270b42d0 and 0xfffffff0270b4334 expects 4 KiB masking.
 * The M5 register field dump specifies address bits [41:12]. See the parent
 * docs/re/hvf-integrated-shadow.md for sources and remaining protection work.
 */
static int hvf_virtual_range_write(CPUState *cpu, const ARMCPRegInfo *ri,
                                   uint64_t *value)
{
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
        *value &= ~UINT64_C(0xfff);
        return 1;
    }
    return 0;
}
