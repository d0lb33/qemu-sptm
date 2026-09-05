/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Virtual guarded EL2 on native EL1. Permission banks remain in common QEMU
 * state and every lateral transition discards native translations.
 * Entry/return and separate saved state: Asahi m1n1 src/gxf_asm.S;
 * https://blog.svenpeter.dev/posts/m1_sprr_gxf/ . Initial firmware setup is
 * SPTM 0xfffffff0270a38e8..390c. Other GXF configuration bits still stop.
 */
static bool hvf_virtual_gxf_context(CPUState *cpu)
{
    CPUARMState *env = cpu_env(cpu);

    return hvf_vsh.active && arm_current_el(env) == 2 &&
           !env->gxf_config_el[1] && !env->sprr_config_el[1] &&
           (env->sprr_config_el[2] == 0xfb ||
            env->sprr_config_el[2] == 0xff);
}

static int hvf_virtual_gxf_write(CPUState *cpu, const ARMCPRegInfo *ri,
                                uint64_t value)
{
    CPUARMState *env = cpu_env(cpu);
    bool config = !strcmp(ri->name, "GXF_CONFIG_EL2");
    bool entry = !strcmp(ri->name, "GXF_ENTRY_EL2") ||
                 !strcmp(ri->name, "GXF_PABENTRY_EL2");
    bool tpidr = !strcmp(ri->name, "TPIDR_GL2");
    bool vbar = !strcmp(ri->name, "VBAR_GL2");
    bool lower = !strcmp(ri->name, "GXF_CONFIG_EL1") ||
                 !strcmp(ri->name, "GXF_ENTRY_EL1") ||
                 !strcmp(ri->name, "GXF_PABENTRY_EL1");

    if (!config && !entry && !tpidr && !vbar && !lower) {
        return 0;
    }
    if (!hvf_virtual_gxf_context(cpu) || !ri->writefn ||
        env->gxf_config_el[2] > 1) {
        goto unsupported;
    }
    if (lower) {
        /*
         * SPTM ...a3968..3970 explicitly clears its unused lower-EL banks.
         * Accept only the already-zero, disabled state from guarded EL2;
         * this does not enable or tear down a lower guarded context.
         */
        if (!arm_apple_is_gl(env) || value || env->gxf_entry_el[1] ||
            env->gxf_pabentry_el[1]) {
            goto unsupported;
        }
        return 1;
    }
    if (config) {
        if (value != 1 || arm_apple_is_gl(env)) {
            goto unsupported;
        }
    } else if (env->gxf_config_el[2] != 1) {
        goto unsupported;
    } else if (entry) {
        /* Initial non-guarded setup; later changes require guarded context. */
        if ((!arm_apple_is_gl(env) && read_raw_cp_reg(env, ri)) ||
            !value || (value & 3)) {
            goto unsupported;
        }
    } else if (!arm_apple_is_gl(env) || (vbar && (value & 0x7ff))) {
        goto unsupported;
    }
    return 1;

unsupported:
    error_report("Virtual GXF unsupported register write %s=0x%" PRIx64
                 " at 0x%" PRIx64, ri->name, value, env->pc);
    return -1;
}

static bool hvf_virtual_gxf_transition(CPUState *cpu, bool enter, unsigned imm)
{
    CPUARMState *env = cpu_env(cpu);
    uint64_t old_pc = env->pc;

    if (!hvf_virtual_gxf_context(cpu) || env->gxf_config_el[2] != 1 ||
        env->currentg != !enter) {
        goto unsupported;
    }
    if (enter) {
        uint64_t guarded_sp = env->sp_gl[2];

        if (!env->gxf_entry_el[2] || (env->gxf_entry_el[2] & 3)) {
            goto unsupported;
        }
        /*
         * Preserve the pre-entry stack bank. The existing interrupt helper
         * selects CURRENTG before saving SP, so explicitly preserve both
         * banks around that ordering for an SP_EL2 caller.
         */
        aarch64_save_sp(env, 2);
        env->pc += 4;
        cpu->exception_index = EXCP_GENTER;
        env->exception.target_el = 2;
        /*
         * Asahi m1n1 hv-sprr, 1c98fd09817cede0043d25c95fb540dbd683ef18,
         * src/hv_sprr.h: HV_GXF_ESR_GENTER, and hv_gxf_genter(). This is
         * the reference emulation's EC/IL/ISS plus its four-bit immediate;
         * public HVF does not expose native GENTER for direct measurement.
         */
        env->exception.syndrome = 0xfe010000 | imm;
        arm_cpu_do_interrupt(cpu);
        env->sp_gl[2] = guarded_sp;
        aarch64_restore_sp(env, 2);
    } else {
        uint64_t spsr = env->spsr_gl[2];

        /* Only same-EL AArch64 returns to non-guarded state are integrated. */
        if (env->aspsr_gl[2] || (spsr & 0x1c) != 8 ||
            (env->elr_gl[2] & 3)) {
            goto unsupported;
        }
        aarch64_save_sp(env, 2);
        env->currentg = 0;
        env->pc = env->elr_gl[2];
        pstate_write(env, spsr);
        aarch64_restore_sp(env, 2);
    }
    /* Target fetch is rewalked in the new context; no old alias survives. */
    hvf_vsh_invalidate(cpu);
    error_report("Virtual GXF %s pc=0x%" PRIx64 " target=0x%" PRIx64
                 " pstate=0x%" PRIx64 " sp=0x%" PRIx64,
                 enter ? "GENTER" : "GEXIT", old_pc, env->pc,
                 pstate_read(env), env->xregs[31]);
    return true;

unsupported:
    error_report("Virtual GXF denied %s at 0x%" PRIx64,
                 enter ? "GENTER" : "GEXIT", old_pc);
    return false;
}
