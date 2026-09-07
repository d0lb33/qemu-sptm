/*
 * Apple AMX instruction decode (darwin-vm).
 *
 * Every AMX instruction becomes one helper call carrying the 5-bit op and the
 * 64-bit operand (a GPR value, or the set/clr immediate for op 17).  The PC is
 * synchronised first because the helper raises the AMX-disabled trap and
 * ordinary data aborts on the operand address, both of which must report this
 * instruction.  Without AMX in the machine the space stays unallocated, which
 * is what the guest saw before this file existed (SIGILL on `set`,
 * docs/re/tcg-idle-profile.md).
 */
#include "qemu/osdep.h"
#include "cpu.h"
#include "helper-amx.h"
#include "translate.h"
#include "translate-a64.h"

#include "decode-apple-amx.c.inc"

__attribute__((unused))
static bool trans_AMX(DisasContext *s, arg_AMX *a)
{
    TCGv_i64 operand;

    if (!s->amx_enabled) {
        return false;
    }
    if (a->op == 17) {
        operand = tcg_constant_i64(a->rn);   /* 0 = set, 1 = clr */
    } else {
        operand = cpu_reg(s, a->rn);
    }
    gen_a64_update_pc(s, 0);
    gen_helper_amx(tcg_env, tcg_constant_i32(a->op), operand);
    return true;
}
