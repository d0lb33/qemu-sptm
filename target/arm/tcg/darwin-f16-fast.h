/*
 * Exact common-case binary16/binary32 conversions for darwin-vm.
 *
 * These helpers only accept conversions that need no rounding and raise no
 * floating-point exception.  ARM's full SoftFloat path remains authoritative
 * for subnormals, infinities, NaNs, alternate-half exponent 31, and inexact
 * narrowing.  Keeping the predicate beside the bit transform makes it
 * possible to exhaustively test the optimized domain without constructing an
 * ARMCPU or duplicating float_status setup.
 */
#ifndef TARGET_ARM_TCG_DARWIN_F16_FAST_H
#define TARGET_ARM_TCG_DARWIN_F16_FAST_H

#include <stdbool.h>
#include <stdint.h>

static inline bool dvm_f16_to_f32_exact(uint32_t input, uint32_t *output)
{
    uint32_t exponent = (input >> 10) & 0x1f;
    uint32_t fraction = input & 0x3ff;

    if (exponent == 0) {
        if (fraction != 0) {
            return false;
        }
        *output = (input & 0x8000) << 16;
        return true;
    }
    if (exponent == 0x1f) {
        return false;
    }
    *output = ((input & 0x8000) << 16) |
              ((exponent + 112) << 23) | (fraction << 13);
    return true;
}

static inline bool dvm_f32_to_f16_exact(uint32_t input, uint32_t *output)
{
    uint32_t exponent = (input >> 23) & 0xff;
    uint32_t fraction = input & 0x7fffff;

    if (exponent == 0) {
        if (fraction != 0) {
            return false;
        }
        *output = (input >> 16) & 0x8000;
        return true;
    }
    if (exponent < 113 || exponent > 142 || (fraction & 0x1fff) != 0) {
        return false;
    }
    *output = ((input >> 16) & 0x8000) |
              ((exponent - 112) << 10) | (fraction >> 13);
    return true;
}

#endif
