/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Initial SPRR enable/permission bank for virtual EL2. The ordinary walker
 * implements the AP/UXN/PXN nibble table documented at
 * https://asahilinux.org/docs/hw/cpu/sprr-gxf/ . Every accepted write must
 * discard native aliases before execution with the new permission bank.
 * The observed locked configuration and guarded bootstrap transitions are
 * supported below. Other configurations and AMRANGE still stop.
 */
static bool hvf_virtual_sprr_raw(CPUState *cpu, uint32_t key, uint64_t *value)
{
    const ARMCPRegInfo *ri = get_arm_cp_reginfo(ARM_CPU(cpu)->cp_regs, key);

    if (!ri) {
        return false;
    }
    *value = read_raw_cp_reg(cpu_env(cpu), ri);
    return true;
}

static int hvf_virtual_sprr_write(CPUState *cpu, const ARMCPRegInfo *ri,
                                  uint64_t value)
{
    CPUARMState *env = cpu_env(cpu);
    bool config = !strcmp(ri->name, "SPRR_CONFIG_EL2");
    bool pmprr = !strcmp(ri->name, "SPRR_PMPRR_EL2");
    bool pperm = !strcmp(ri->name, "SPRR_PPERM_EL2");
    uint64_t mask, user_mask, range;
    uint64_t old_config = env->sprr_config_el[2];

    if (!config && !pmprr && !pperm &&
        strcmp(ri->name, "SPRR_UPERM_EL0")) {
        return 0;
    }
    /*
     * No native SPRR registers are borrowed from the host. Reject unknown
     * pre-existing restriction state and unsupported GXF configurations.
     */
    if (!ri->writefn || env->sprr_config_el[1] ||
        (old_config != 0 && old_config != 1 &&
         old_config != 0xfb && old_config != 0xff) ||
        env->gxf_config_el[2] > 1 ||
        (arm_apple_is_gl(env) && env->gxf_config_el[2] != 1)) {
        error_report("Virtual SPRR unsupported configuration for %s "
                     "at 0x%" PRIx64, ri->name, env->pc);
        return -1;
    }
    if (!hvf_virtual_sprr_raw(cpu, ENCODE_AA64_CP_REG(3, 6, 15, 3, 2),
                              &mask) ||
        !hvf_virtual_sprr_raw(cpu, ENCODE_AA64_CP_REG(3, 6, 15, 3, 0),
                              &user_mask) ||
        !hvf_virtual_sprr_raw(cpu, ENCODE_AA64_CP_REG(3, 6, 15, 14, 3),
                              &range) || user_mask || range ||
        (mask && (mask != 0x40010 || !old_config))) {
        goto unsupported;
    }
    if (arm_apple_is_gl(env) && old_config == 0xfb && mask == 0x40010) {
        /*
         * Observed GL bootstrap: SPTM ...a3880/...a3898 changes PPERM,
         * then ...a38ac or ...b16f8 seals CONFIG with 0xff. Do not infer
         * arbitrary guarded writes from the otherwise undocumented locks.
         */
        uint64_t old = env->sprr_pperm_el[2];
        bool initial = old == UINT64_C(0x2020a52a302abaf5) ||
                       old == UINT64_C(0x2020a52a302acae6) ||
                       old == UINT64_C(0x2020a52a302abae6);
        if (pperm && initial &&
            (value == UINT64_C(0x2020a52a302acae6) ||
             value == UINT64_C(0x2020a52a302abae6))) {
            return 1;
        }
        if (config && value == 0xff &&
            old == UINT64_C(0x2020a52a302abae6)) {
            return 1;
        }
    }
    if (old_config == 0xfb || old_config == 0xff) {
        /*
         * SPTM 0xfffffff0270a382c/3840 sets PMPRR=0x40010, CONFIG=0xfb.
         * The kernel subsequently toggles PPERM entry 2 A/B at unslid
         * 0xfffffff00ac56fe8/57024 and entry 9 2/3 at ...ac608ac/608f8.
         * These are the low bits selected by the two-bit PMPRR fields.
         * Preserve every other bit, including each guarded permission pair.
         * See docs/re/hvf-pmprr-locks.md in the parent repository.
         *
         * Forbidden writes stop rather than guessing hardware's ignored-write
         * versus exception behavior. Other bank/range/shadow writes are still
         * rejected by the dispatcher. Guarded bootstrap exceptions are above.
         */
        if (mask != 0x40010) {
            goto unsupported;
        }
        if (pperm && !((value ^ env->sprr_pperm_el[2]) &
                       ~UINT64_C(0x1000000100))) {
            return 1;
        }
        if (!pperm && value == read_raw_cp_reg(env, ri)) {
            return 1;
        }
        goto unsupported;
    }
    if (pmprr) {
        if (old_config != 1 || mask || value != 0x40010) {
            goto unsupported;
        }
    } else if (config) {
        if (mask ? (old_config != 1 || value != 0xfb) : (value & ~1ULL)) {
            goto unsupported;
        }
    } else if (mask) {
        /* Unlocked writes after mask programming need independent evidence. */
        goto unsupported;
    }
    return 1;

unsupported:
    error_report("Virtual SPRR unsupported mask/locked write %s=0x%" PRIx64
                 " at 0x%" PRIx64, ri->name, value, env->pc);
    return -1;
}
