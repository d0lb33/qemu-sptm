/* Compare both result bits and sticky exceptions with the canonical oracle. */
#include "../../fpu/softfloat.c"
static void check(uint32_t a, uint32_t b, unsigned mode)
{
    float_status got = { 0 }, expected;
    set_float_2nan_prop_rule(float_2nan_prop_s_ab, &got);
    set_float_default_nan_pattern(0x40, &got);
    set_float_rounding_mode(mode % 8, &got);
    set_flush_to_zero(!!(mode & 8), &got);
    set_flush_inputs_to_zero(!!(mode & 16), &got);
    set_default_nan_mode(!!(mode & 32), &got);
    set_float_exception_flags(mode & 64 ? float_flag_inexact : 0, &got);
    expected = got;
    uint32_t want = soft_f32_mul(a, b, &expected);
    uint32_t result = float32_mul(a, b, &got);
    if (result != want || got.float_exception_flags != expected.float_exception_flags) {
        fprintf(stderr, "%08x * %08x mode=%u result=%08x/%08x flags=%x/%x\n",
                a, b, mode, result, want, got.float_exception_flags,
                expected.float_exception_flags);
        abort();
    }
}
static void differential(void)
{
    const uint32_t edge[] = {0,1,0x7fffff,0x800000,0x800001,0x3f800000,
                            0x7f7fffff,0x7f800000,0x7f800001,0x7fc00000};
    for (unsigned m = 0; m < 128; m++) {
        for (unsigned a = 0; a < G_N_ELEMENTS(edge) * 2; a++) {
            for (unsigned b = 0; b < G_N_ELEMENTS(edge) * 2; b++) {
                check(edge[a / 2] | ((a & 1) << 31),
                      edge[b / 2] | ((b & 1) << 31), m);
            }
        }
    }
    GRand *rng = g_rand_new_with_seed(0x85a308d3);
    for (unsigned i = 0; i < 1000000; i++) {
        uint32_t a = g_rand_int(rng), b = g_rand_int(rng);
        check(a, b, i & 127);
        check(a, 0, i & 127);
        check(a, 0x80000000u, i & 127);
        check(0, a, i & 127);
        check(0x80000000u, a, i & 127);
    }
    g_rand_free(rng);
}
int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/softfloat/zero-mul/differential", differential);
    return g_test_run();
}
