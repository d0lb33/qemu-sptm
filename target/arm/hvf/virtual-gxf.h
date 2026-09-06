/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Virtual guarded EL2 on native EL1. Permission banks remain in common QEMU
 * state and every lateral transition discards native translations.
 * Entry/return and separate saved state: Asahi m1n1 src/gxf_asm.S;
 * https://blog.svenpeter.dev/posts/m1_sprr_gxf/ . Initial firmware setup is
 * SPTM 0xfffffff0270a38e8..390c.
 *
 * GXF_CONFIG_EL2 has two accepted states. The bootstrap value 1 (ENAB) and
 * the sealed value 0x6f written from guarded EL2 at SPTM 0xfffffff0270a3978.
 * The M5 field dump names bits 0..6 ENAB, PEX2, PEX0, LOCK, ALLW, NACC, HVAC;
 * docs/re/hvf-gxf-policy.md ties HVAC (bit 6) to the firmware's
 * internal-ISA-VM policy. Only ENAB and LOCK are modelled here: ENAB gates
 * every transition, LOCK makes the register immutable. PEX2/PEX0/NACC/HVAC
 * are stored without semantics, matching the TCG model in
 * hw/arm/apple_regs.c, which treats the whole register as storage and boots
 * to a home screen. No hardware oracle is available on this host to refine
 * them; see docs/re/hvf-sptm-bootstrap.md.
 */
#define GXF_CONFIG_ENAB  BIT_ULL(0)
#define GXF_CONFIG_LOCK  BIT_ULL(3)
#define GXF_CONFIG_SEALED UINT64_C(0x6f)

static bool hvf_virtual_gxf_config_ok(CPUARMState *env)
{
    return env->gxf_config_el[2] == GXF_CONFIG_ENAB ||
           env->gxf_config_el[2] == GXF_CONFIG_SEALED;
}

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
    bool lower_saved = !strcmp(ri->name, "ELR_GL1") ||
                       !strcmp(ri->name, "SPSR_GL1") ||
                       !strcmp(ri->name, "ESR_GL1") ||
                       !strcmp(ri->name, "ASPSR_GL1") ||
                       !strcmp(ri->name, "ELR_GL2") ||
                       !strcmp(ri->name, "SPSR_GL2") ||
                       !strcmp(ri->name, "ESR_GL2") ||
                       !strcmp(ri->name, "ASPSR_GL2");

    if (!config && !entry && !tpidr && !vbar && !lower && !lower_saved) {
        return 0;
    }
    if (!hvf_virtual_gxf_context(cpu) || !ri->writefn ||
        (env->gxf_config_el[2] && !hvf_virtual_gxf_config_ok(env))) {
        goto unsupported;
    }
    if (lower_saved) {
        /*
         * Saved-state banks are written from guarded EL2 only: SPTM
         * 0xfffffff02709aabc/aad0 seeds ELR/SPSR before its ERET into TXM,
         * its SVC handler (0xfffffff02709ac18..ac28) rewrites them before
         * returning, and 0xfffffff02709afd8..b000 sets ELR/SPSR/ASPSR before
         * the GEXIT that launches the kernel. Storing them changes no
         * execution state until the matching ERET/GEXIT consumes them.
         */
        if (!arm_apple_is_gl(env)) {
            goto unsupported;
        }
        return 1;
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
        /*
         * Ordinary EL2 enables with exactly ENAB; guarded EL2 later seals the
         * enabled register with the sealed value. Once LOCK is set nothing
         * is accepted: the hardware's rejected-write behaviour is not known,
         * so the bridge stops rather than guessing.
         */
        if (env->gxf_config_el[2] & GXF_CONFIG_LOCK) {
            goto unsupported;
        }
        if (!(value == GXF_CONFIG_ENAB && !arm_apple_is_gl(env)) &&
            !(value == GXF_CONFIG_SEALED && arm_apple_is_gl(env) &&
              env->gxf_config_el[2] == GXF_CONFIG_ENAB)) {
            goto unsupported;
        }
    } else if (!hvf_virtual_gxf_config_ok(env)) {
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

    if (!hvf_virtual_gxf_context(cpu) || !hvf_virtual_gxf_config_ok(env) ||
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

/*
 * ERET from virtual EL2/GL2. Mirrors HELPER(exception_return) in
 * target/arm/tcg/helper-a64.c: a guarded caller returns through its GL bank
 * and CURRENTG is unchanged (only GEXIT clears it). SPTM's bootstrap ERET at
 * 0xfffffff02709ab80 returns to EL0t with CURRENTG=1 (TXM at guarded EL0),
 * and its SVC handler returns the same way at 0xfffffff02709ac2c.
 * AArch32, illegal-state and PAC-authenticated returns are not supported.
 */
static bool hvf_virtual_eret(CPUState *cpu)
{
    ARMCPU *armcpu = ARM_CPU(cpu);
    CPUARMState *env = &armcpu->env;
    uint64_t old_pc = env->pc, spsr, new_pc;
    unsigned new_el;

    if (arm_current_el(env) != 2 || !hvf_vsh.active) {
        goto unsupported;
    }
    if (arm_apple_is_gl(env)) {
        spsr = env->spsr_gl[2];
        new_pc = env->elr_gl[2];
    } else {
        spsr = env->banked_spsr[aarch64_banked_spsr_index(2)];
        new_pc = env->elr_el[2];
    }
    if ((spsr & (PSTATE_nRW | PSTATE_IL)) || (spsr & 2) ||
        ((spsr & 0xc) == 0 && (spsr & 1))) {
        goto unsupported;
    }
    new_el = (spsr >> 2) & 3;
    if (new_el != 0 && new_el != 2) {
        goto unsupported;
    }
    aarch64_save_sp(env, 2);
    arm_clear_exclusive(env);
    spsr &= aarch64_pstate_valid_mask(&armcpu->isar);
    pstate_write(env, spsr);
    env->pstate &= ~PSTATE_SS;
    aarch64_restore_sp(env, new_el);
    /* E2H regimes always have two VA ranges: TBI sign-extends bit 55. */
    if (aa64_va_parameters(env, new_pc, arm_mmu_idx(env), true, false).tbi) {
        new_pc = sextract64(new_pc, 0, 56);
    }
    env->pc = new_pc;
    /* The target regime's permissions are rewalked; no old alias survives. */
    hvf_vsh_invalidate(cpu);
    error_report("Virtual EL2 ERET pc=0x%" PRIx64 " target=0x%" PRIx64
                 " el=%u pstate=0x%" PRIx64 " currentg=%" PRIu64
                 " sp=0x%" PRIx64, old_pc, env->pc, new_el,
                 pstate_read(env), env->currentg, env->xregs[31]);
    return true;

unsupported:
    error_report("Virtual EL2 unsupported ERET at 0x%" PRIx64, old_pc);
    return false;
}
