/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Virtual EL2 state on physical HVF EL1. Initial integration is restricted
 * to one EL2 CPU. An opt-in shadow context owns translated runs; unsupported
 * transitions stop before changing the guest contract.
 */
#include "exec/cputlb.h"
#include "migration/blocker.h"
#include "virtual-shadow.h"
#include "virtual-counter.h"
#include "virtual-protection.h"
#include "virtual-sprr.h"
#include "virtual-gxf.h"
#include "virtual-pmu.h"
#include "virtual-vmsa.h"

static bool hvf_virtual_el2;
static uint32_t hvf_virtual_words[4096];
static unsigned hvf_virtual_word_count;
static Error *hvf_virtual_migration_blocker;

static int hvf_virtual_init(void)
{
    g_autofree char *data = NULL;
    gsize length;
    const char *path;

    hvf_virtual_el2 = g_strcmp0(getenv("QEMU_HVF_VIRTUAL_EL2"), "1") == 0;
    if (!hvf_virtual_el2) {
        return 0;
    }
    path = getenv("QEMU_HVF_VIRTUAL_LEDGER");
    if (hvf_nested_virt_enabled() || hvf_irqchip_in_kernel() || !path ||
        !g_file_get_contents(path, &data, &length, NULL) || length < 8 ||
        memcmp(data, "DVEL", 4)) {
        error_report("Virtual EL2 requires nested-virt=off, kernel-irqchip=off "
                     "and a valid QEMU_HVF_VIRTUAL_LEDGER");
        return -EINVAL;
    }
    hvf_virtual_word_count = ldl_le_p(data + 4);
    if (!hvf_virtual_word_count || hvf_virtual_word_count > 4096 ||
        length != 8 + hvf_virtual_word_count * 4) {
        return -EINVAL;
    }
    for (unsigned i = 0; i < hvf_virtual_word_count; i++) {
        hvf_virtual_words[i] = ldl_le_p(data + 8 + i * 4);
    }
    error_setg(&hvf_virtual_migration_blocker,
               "Experimental virtual EL2 has no snapshot/migration state yet");
    return migrate_add_blocker(&hvf_virtual_migration_blocker, &error_fatal);
}

static bool hvf_virtual_instruction(CPUState *cpu, uint32_t word, bool *advance)
{
    ARMCPU *armcpu = ARM_CPU(cpu);
    CPUARMState *env = &armcpu->env;
    const ARMCPRegInfo *ri;
    bool read = word & (1 << 21);
    unsigned rt = word & 31;
    uint64_t value;
    uint32_t key;

    cpu_synchronize_state(cpu);
    *advance = true;
    if ((word & 0xfffffff0) == 0x00201420 || word == 0x00201400) {
        *advance = false;
        return hvf_virtual_gxf_transition(cpu, word != 0x00201400, word & 15);
    }
    if (word == 0xd508751f && arm_current_el(env) == 2 && hvf_vsh.active) {
        hvf_vsh_icache(cpu);
        return true;
    }
    if (word == 0xd500409f && arm_current_el(env) == 2 && hvf_vsh.active) {
        /*
         * SPTM ...a38d8 explicitly clears PAN after installing VBAR_GL2.
         * Rewalk all mappings after the PSTATE change. PAN-setting and
         * lower-EL user mappings still need their own protection model.
         */
        pstate_write(env, pstate_read(env) & ~PSTATE_PAN);
        hvf_vsh_invalidate(cpu);
        return true;
    }
    if (arm_current_el(env) == 2 &&
        (word & 0xfffff0ff) == 0xd50340df) {
        /* DAIFSet, matching a64.decode and the architectural DAIF mask. */
        pstate_write(env, pstate_read(env) | (((word >> 8) & 15) << 6));
        return true;
    }
    if (word == 0xd508871f && arm_current_el(env) == 2 &&
        !(env->cp15.sctlr_el[1] & SCTLR_M) &&
        !(env->cp15.sctlr_el[2] & SCTLR_M)) {
        /*
         * VMALLE1 has no translations to invalidate in this initial mode.
         * Native shadows are not installed until the guarded MMU handoff.
         * Keep the software TLB empty for architectural register callbacks.
         */
        tlb_flush(cpu);
        error_report("Virtual EL2 TLBI VMALLE1, empty context pc=0x%" PRIx64,
                     env->pc);
        return true;
    }
    if ((word == 0xd508871f || word == 0xd508971f ||
         (word & ~31U) == 0xd50887e0 || /* VAALE1 */
         (word & ~31U) == 0xd50897e0 || /* VAALE1NXS */
         (word & ~31U) == 0xd50886e0 || /* RVAALE1 */
         (word & ~31U) == 0xd50896e0) && /* RVAALE1NXS */
        arm_current_el(env) == 2 && hvf_vsh.active) {
        /*
         * The helper performs a stronger full invalidation for these TLBIs.
         * Protection changes still stop. Accepted TCR/TTBR writes and
         * emulated table stores discard every alias separately, so the
         * remaining checked leaves stay valid.
         */
        hvf_vsh.generation++;
        error_report("Virtual EL2 TLBI full native context pc=0x%" PRIx64,
                     env->pc);
        return true;
    }
    if (arm_current_el(env) != 2 ||
        (word & 0xffc00000) != 0xd5000000 || !((word >> 19) & 3)) {
        error_report("Virtual EL2 unsupported instruction 0x%08x at 0x%" PRIx64,
                     word, env->pc);
        return false;
    }
    key = ENCODE_AA64_CP_REG((word >> 19) & 3, (word >> 16) & 7,
                             (word >> 12) & 15, (word >> 8) & 15,
                             (word >> 5) & 7);
    ri = get_arm_cp_reginfo(armcpu->cp_regs,
                           hvf_virtual_counter_key(key, read));
    if (!ri || !cp_access_ok(2, ri, read)) {
        error_report("Virtual EL2 unknown/denied sysreg 0x%08x at 0x%" PRIx64,
                     word, env->pc);
        return false;
    }
    /* Match the architectural VHE redirect order in translate-a64.c. */
    if (ri->vhe_redir_to_el2 && (env->cp15.hcr_el2 & HCR_E2H)) {
        ri = get_arm_cp_reginfo(armcpu->cp_regs, ri->vhe_redir_to_el2);
    } else if (ri->vhe_redir_to_el01) {
        if (!(env->cp15.hcr_el2 & HCR_E2H)) {
            return false;
        }
        ri = get_arm_cp_reginfo(armcpu->cp_regs, ri->vhe_redir_to_el01);
    }
    if (!ri || !cp_access_ok(2, ri, read) ||
        (ri->accessfn && ri->accessfn(env, ri, read) != CP_ACCESS_OK) ||
        (ri->type & ARM_CP_RAISES_EXC)) {
        error_report("Virtual EL2 sysreg access needs exception handling "
                     "at 0x%" PRIx64, env->pc);
        return false;
    }
    /*
     * The generated register table has PL2 permissions but no GL accessfn.
     * Same-EL guarded banks require guarded execution (m1n1 gxf_asm.S).
     * Lower-GL access from higher EL is not integrated into this bridge.
     */
    if (strstr(ri->name, "_GL") && !arm_apple_is_gl(env)) {
        error_report("Virtual EL2 guarded register denied: %s at 0x%" PRIx64,
                     ri->name, env->pc);
        return false;
    }
    value = rt == 31 ? 0 : env->xregs[rt];
    int vmsa_write = read ? 0 : hvf_virtual_vmsa_write(cpu, ri, value);
    if (vmsa_write < 0) {
        return false;
    }
    int range_write = read ? 0 : hvf_virtual_range_write(cpu, ri, &value);
    int sprr_write = !read && hvf_vsh.active ?
                    hvf_virtual_sprr_write(cpu, ri, value) : 0;
    int gxf_write = read ? 0 : hvf_virtual_gxf_write(cpu, ri, value);
    int pmu_write = read ? 0 : hvf_virtual_pmu_write(cpu, ri, value);
    bool pmu_read = read && hvf_virtual_pmu_counter(ri);
    if (range_write < 0 || sprr_write < 0 || gxf_write < 0 || pmu_write < 0 ||
        (pmu_read && !hvf_virtual_pmu_disabled(cpu))) {
        return false;
    }
    if ((ri->type & ARM_CP_SPECIAL_MASK) == ARM_CP_DC_ZVA) {
        bool ok;
        WITH_RCU_READ_LOCK_GUARD() {
            ok = hvf_vsh_zero(cpu, value);
        }
        if (!ok) {
            error_report("Virtual EL2 DC ZVA requires writable normal RAM "
                         "at 0x%" PRIx64 " address=0x%" PRIx64,
                         env->pc, value);
        }
        return ok;
    }
    bool counter_read = read && hvf_virtual_counter_read(ri);
    bool counter_route = !read && (!strcmp(ri->name, "AGTCNTRDIR_EL2") ||
                                   !strcmp(ri->name, "AGTCNTRDIR_EL1"));
    if ((counter_read || counter_route) &&
        (!hvf_virtual_counter_common(cpu) ||
         (counter_route && value != 0 && value != 3))) {
        error_report("Virtual counter requires common 24 MHz zero-offset "
                     "disabled-timer context: %s at 0x%" PRIx64,
                     ri->name, env->pc);
        return false;
    }
    /*
     * Initial post-MMU boot setup (SPTM 0xfffffff0270a376c..3798).
     * VBAR/TPIDR are virtual banks. APL_INTENABLE=0 keeps all timer routes
     * disabled; enabling a timer is still rejected. ACFG=0x18 is the
     * observed cache-control profile. Cache operations are intercepted;
     * only checked DC ZVA and the IC IALLU path above are integrated.
     * MDSCR.TDCC restricts EL0 DCC accesses; lower-EL entry is still rejected.
     * No debug enable, cache enable, or translation change is accepted here.
     * Field sources and the scope of these restrictions are in
     * docs/re/hvf-integrated-shadow.md in the parent repository.
     */
    bool translation_write = !read && hvf_vsh.active &&
                             (!strcmp(ri->name, "TCR_EL2") ||
                              !strcmp(ri->name, "TTBR0_EL2") ||
                              !strcmp(ri->name, "TTBR1_EL2"));
    if (translation_write &&
        (!ri->writefn || env->sprr_config_el[2] || env->gxf_config_el[2] ||
         !hvf_vsh_tcr_valid(!strcmp(ri->name, "TCR_EL2") ? value :
                           env->cp15.tcr_el[2]))) {
        error_report("Virtual shadow unsupported translation context: %s "
                     "at 0x%" PRIx64, ri->name, env->pc);
        return false;
    }
    bool bank_write = translation_write || sprr_write > 0 || range_write > 0 ||
                      gxf_write > 0 || pmu_write > 0 || vmsa_write > 0 ||
                      counter_route ||
                      !strcmp(ri->name, "VBAR_EL2") ||
                      !strcmp(ri->name, "TPIDR_EL2") ||
                      (!strcmp(ri->name, "APL_INTENABLE_EL2") && value == 0) ||
                      (!strcmp(ri->name, "ACFG_EL1") && value == 0x18) ||
                      (!strcmp(ri->name, "MDSCR_EL1") && value == 0x1000);
    if (!read && hvf_vsh.active && !bank_write) {
        error_report("Virtual shadow context change requires invalidation: "
                     "%s at 0x%" PRIx64, ri->name, env->pc);
        return false;
    }
    /* No native translation may run until the shadow context is installed. */
    if (!read && (strcmp(ri->name, "SCTLR_EL1") == 0 ||
                  strcmp(ri->name, "SCTLR_EL2") == 0) && (value & SCTLR_M)) {
        if (!hvf_vsh_start(cpu, ri, value)) {
            error_report("Virtual EL2 MMU handoff at 0x%" PRIx64
                         " %s=0x%" PRIx64 " requires shadow context",
                         env->pc, ri->name, value);
            return false;
        }
    }
    switch (ri->type & ARM_CP_SPECIAL_MASK) {
    case ARM_CP_CURRENTEL:
        value = 8;
        break;
    case ARM_CP_NZCV:
        if (read) {
            value = pstate_read(env) & 0xf0000000;
        } else {
            pstate_write(env, (pstate_read(env) & ~0xf0000000) |
                              (value & 0xf0000000));
        }
        break;
    case 0:
        if (ri->type & ARM_CP_CONST) {
            value = ri->resetvalue;
        } else if (read) {
            if (counter_read) {
                value = hvf_virtual_counter_value(cpu);
            } else if (pmu_read) {
                /* Disabled counts stay frozen; avoid synthetic random reads. */
                value = read_raw_cp_reg(env, ri);
            } else if (ri->readfn) {
                value = ri->readfn(env, ri);
            } else if (ri->fieldoffset) {
                value = raw_read(env, ri);
            } else {
                return false;
            }
        } else {
            if (ri->writefn) {
                ri->writefn(env, ri, value);
            } else if (ri->fieldoffset) {
                raw_write(env, ri, value);
            } else {
                return false;
            }
        }
        break;
    default:
        error_report("Virtual EL2 unsupported special sysreg %s at 0x%" PRIx64,
                     ri->name, env->pc);
        return false;
    }
    if (translation_write || sprr_write > 0 || gxf_write > 0) {
        hvf_vsh_invalidate(cpu);
    }
    if (read && rt != 31) {
        env->xregs[rt] = value;
    }
    if (!read && ri->fieldoffset) {
        error_report("Virtual EL2 write %s requested=0x%" PRIx64
                     " stored=0x%" PRIx64 " pc=0x%" PRIx64,
                     ri->name, value, raw_read(env, ri), env->pc);
    } else {
        error_report("Virtual EL2 %s %s=0x%" PRIx64 " pc=0x%" PRIx64,
                     read ? "read" : "write-request", ri->name, value, env->pc);
    }
    return true;
}
