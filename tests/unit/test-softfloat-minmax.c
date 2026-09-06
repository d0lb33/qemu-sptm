/* Differential oracle: the original canonical implementation, including all
 * exception flags, versus the normal-operand fast path. Include the source to
 * access its internal canonical helpers without exporting a test-only API.
 */
#include "../../fpu/softfloat.c"

static void check_pair(uint32_t a, uint32_t b, unsigned mode, unsigned flags)
{
    float_status actual = { 0 }, expected;
    set_float_2nan_prop_rule(float_2nan_prop_s_ab, &actual);
    set_float_default_nan_pattern(0x40, &actual);
    set_float_rounding_mode(mode % 6, &actual);
    set_flush_to_zero(!!(mode & 8), &actual);
    set_flush_inputs_to_zero(!!(mode & 16), &actual);
    set_default_nan_mode(!!(mode & 32), &actual);
    set_float_exception_flags(mode & 64 ? float_flag_inexact : 0, &actual);
    expected = actual;
    FloatParts64 pa = float32_unpack_canonical(a, &expected);
    FloatParts64 pb = float32_unpack_canonical(b, &expected);
    FloatParts64 *pr = parts64_minmax(&pa, &pb, &expected, flags);
    uint32_t want = float32_round_pack_canonical(pr, &expected);
    uint32_t got = float32_minmax(a, b, &actual, flags);
    if (got != want || get_float_exception_flags(&actual) !=
                       get_float_exception_flags(&expected)) {
        fprintf(stderr, "a=%08x b=%08x mode=%u flags=%u got=%08x expected=%08x exceptions=%x/%x\n",
                a, b, mode, flags, got, want,
                get_float_exception_flags(&actual), get_float_exception_flags(&expected));
        abort();
    }
}

static void differential(void)
{
    static const uint32_t edge[] = {
        0, 1, 0x007fffff, 0x00800000, 0x00800001, 0x3f7fffff,
        0x3f800000, 0x3f800001, 0x7f7fffff, 0x7f800000,
        0x7f800001, 0x7fc00000, 0x7fffffff,
    };
    static const unsigned flags[] = {0, 1, 2, 3, 6, 7, 8, 9};
    for (unsigned mode = 0; mode < 128; mode++) {
        for (unsigned i = 0; i < G_N_ELEMENTS(edge) * 2; i++) {
            uint32_t a = edge[i / 2] | (i & 1 ? 0x80000000u : 0);
            for (unsigned j = 0; j < G_N_ELEMENTS(edge) * 2; j++) {
                uint32_t b = edge[j / 2] | (j & 1 ? 0x80000000u : 0);
                for (unsigned f = 0; f < G_N_ELEMENTS(flags); f++) {
                    check_pair(a, b, mode, flags[f]);
                }
            }
        }
    }
    GRand *rng = g_rand_new_with_seed(0x243f6a88);
    for (unsigned i = 0; i < 200000; i++) {
        uint32_t a = g_rand_int(rng), b = g_rand_int(rng);
        unsigned mode = i & 127;
        for (unsigned f = 0; f < G_N_ELEMENTS(flags); f++) {
            check_pair(a, b, mode, flags[f]);
            check_pair(a, a, mode, flags[f]);
            check_pair(a, a ^ 0x80000000u, mode, flags[f]);
        }
    }
    g_rand_free(rng);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/softfloat/minmax-differential", differential);
    return g_test_run();
}
