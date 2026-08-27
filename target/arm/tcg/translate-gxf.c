#include "qemu/osdep.h"
#include "cpu.h"
#include "helper-gxf.h"
#include "translate.h"
#include "translate-a64.h"
#include "qemu/log.h"
#include <assert.h>

#include "decode-apple-gxf.c.inc"

#define HELPER_H "tcg/helper-gxf-defs.h"
#include "exec/helper-info.c.inc"

void HELPER(genter)(CPUARMState *env, uint32_t imm) {
    assert(false);
}

void HELPER(gexit)(CPUARMState *env) {
    int cur_el = arm_current_el(env);
    uint64_t spsr = env->spsr_gl[cur_el];
    uint64_t old_pc;
    assert(1 == env->currentg);
    assert(env->aarch64);

    // Most of this is copied from HELPER(exception_return)
    aarch64_save_sp(env, cur_el);

    old_pc = env->pc;
    env->currentg = env->aspsr_gl[cur_el];
    env->pc = env->elr_gl[cur_el];

    pstate_write(env, spsr);
    aarch64_restore_sp(env, cur_el);
    arm_rebuild_hflags(env);
    qemu_log_mask(CPU_LOG_INT, "gexit 0x%" PRIx64 " -> 0x%" PRIx64 "\n", old_pc, env->pc);
}

__attribute__((unused))
static bool trans_GENTER(DisasContext *s, arg_GENTER *a) {
    // Originally genter was also a separate helper rather than proper
    // exception, but since we have to heavily modify exceptions to support GL
    // anyways, and Qemu takes care of lots of random pstate stuff (eg. PAN) in
    // the exception path, it was easier to just turn genter into an exception
    // and keep gexit its own helper.
    gen_ss_advance(s);
    gen_exception_insn(s, 4, EXCP_GENTER, a->imm);
    return true;
}

__attribute__((unused))
static bool trans_GEXIT(DisasContext *s, arg_GEXIT *a) {
    gen_helper_gexit(tcg_env);
    s->base.is_jmp = DISAS_EXIT;
    return true;
}

#if 0

// Old approach: genter is its own helper
// Moved genter -> to be a real exception to reuse Qemu's pstate handling logic for things like PAN
// Keeping gexit as its own helper to disambiguate what to do with aspsr_gl
// (on eret, ignore aspsr_gl; on gexit, restore it -> easier to keep aspsr_gl handling separate from exception_return helper)

void HELPER(genter)(CPUARMState *env, uint32_t imm) {
    int cur_el = arm_current_el(env);
    assert(0 == env->currentg);
    assert(env->aarch64);

    aarch64_save_sp(env, cur_el);

    env->aspsr_gl[cur_el] = env->currentg;
    env->currentg = 1;

    env->spsr_gl[cur_el] = pstate_read(env);
    env->esr_gl[cur_el] = imm;
    env->elr_gl[cur_el] = env->pc + 4;

    // According to ARM docs, exceptions always switch to SP_ELx
    // This seems to also be the case for GL
    // aarch64_pstate_mode gives us a fresh pstate with SP_ELx already selected
    pstate_write(env, aarch64_pstate_mode(cur_el, true) | PSTATE_DAIF);

#error "TODO: Handle setting PAN + whatever else here in new pstate (easier to" \
    "just turn genter into an exception and reuse Qemu's logic)"

    aarch64_restore_sp(env, cur_el);

    arm_rebuild_hflags(env);
    env->pc = env->gxf_entry_el1;
    qemu_log_mask(CPU_LOG_INT, "genter ELR_GL1 0x%" PRIx64 "\n", env->elr_gl[cur_el]);
}

__attribute__((unused))
static bool trans_GENTER(DisasContext *s, arg_GENTER *a) {
    gen_helper_genter(tcg_env, tcg_constant_i32(a->imm));
    s->base.is_jmp = DISAS_EXIT;
    return true;
}

#endif // 0
