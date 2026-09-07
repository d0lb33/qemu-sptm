#include "qemu/osdep.h"
#include "qemu/bswap.h"
#include "hw/arm/darwin_iomfb_swap.h"

static void native_contract(void)
{
    uint8_t input[DARWIN_IOMFB_SWAP_INPUT_SIZE] = { 0 };
    uint8_t output[DARWIN_IOMFB_SWAP_COMPLETION_SIZE + 8];
    uint32_t id;
    /* A nonzero identifier catches accidentally hardcoded first-frame IDs. */
    stl_le_p(input + 0x98, 0xfedcba98);
    g_assert_true(darwin_iomfb_swap_id(input, sizeof(input), 12, &id));
    g_assert_cmphex(id, ==, 0xfedcba98);
    memset(output, 0xa5, sizeof(output));
    darwin_iomfb_swap_completion(output, id);
    g_assert_cmphex((uint32_t)ldl_le_p(output), ==, id);
    for (size_t i = 4; i < DARWIN_IOMFB_SWAP_COMPLETION_SIZE; i++) {
        g_assert_cmpuint(output[i], ==, i == 0x72c ? 1 : 0);
    }
    for (size_t i = DARWIN_IOMFB_SWAP_COMPLETION_SIZE; i < sizeof(output); i++) {
        g_assert_cmpuint(output[i], ==, 0xa5);
    }
}

static void reject_unsupported(void)
{
    uint8_t input[DARWIN_IOMFB_SWAP_INPUT_SIZE + 1] = { 0 };
    uint32_t id = 0xabcdef;
    for (size_t n = 0; n <= sizeof(input); n++) {
        if (n != DARWIN_IOMFB_SWAP_INPUT_SIZE) {
            g_assert_false(darwin_iomfb_swap_id(input, n, 12, &id));
        }
    }
    input[0xfea] = 1;
    g_assert_false(darwin_iomfb_swap_id(input, DARWIN_IOMFB_SWAP_INPUT_SIZE, 12, &id));
    input[0xfea] = 0;
    g_assert_false(darwin_iomfb_swap_id(input, DARWIN_IOMFB_SWAP_INPUT_SIZE, 0, &id));
    g_assert_false(darwin_iomfb_swap_id(NULL, DARWIN_IOMFB_SWAP_INPUT_SIZE, 12, &id));
    g_assert_false(darwin_iomfb_swap_id(input, DARWIN_IOMFB_SWAP_INPUT_SIZE, 12, NULL));
    g_assert_cmphex(id, ==, 0xabcdef);
}

static void scanout_contract(void)
{
    uint8_t input[DARWIN_IOMFB_SWAP_INPUT_SIZE] = { 0 };
    DarwinIOMFBSurface v;
    uint8_t *d = input + 0x6e0;
    input[0xfec] = input[0xfed] = input[0xfee] = 1;
    stl_le_p(d + 0xb, 0x42475241);
    stl_le_p(d + 0x15, 4864);
    stl_le_p(d + 0x21, 1179);
    stl_le_p(d + 0x25, 2556);
    stl_le_p(d + 0x29, 12435456);
    stq_le_p(input + 0xf90, 0x10000000000ULL);
    g_assert_true(darwin_iomfb_swap_surface(input, sizeof(input), &v));
    g_assert_cmpuint(v.size, ==, 12432384);
    g_assert_cmpuint(v.width, ==, 1179);
    g_assert_cmphex(v.dva, ==, 0x10000000000ULL);
    /* A padded descriptor must still recognize the existing scanout bytes. */
    uint8_t marker[16];
    uint32_t frame;
    stl_le_p(marker, 0xff44564d);
    stl_le_p(marker + 4, 0xff505253);
    stl_le_p(marker + 8, 0xff424c52);
    stl_le_p(marker + 12, 0xff000021);
    g_assert_true(darwin_iomfb_marked_frame(&v, marker, &frame));
    g_assert_cmpuint(frame, ==, 33);
    stl_le_p(marker + 12, 0xff001c21); /* 7201: must retain more than 8 bits. */
    g_assert_true(darwin_iomfb_marked_frame(&v, marker, &frame));
    g_assert_cmpuint(frame, ==, 7201);
    stl_le_p(marker + 12, 0xff002001);
    g_assert_false(darwin_iomfb_marked_frame(&v, marker, &frame));
    stl_le_p(marker + 12, 0xff000000);
    g_assert_false(darwin_iomfb_marked_frame(&v, marker, &frame));
    stl_le_p(marker + 12, 0xff000021);
    marker[0] ^= 1;
    g_assert_false(darwin_iomfb_marked_frame(&v, marker, &frame));
    g_assert_false(darwin_iomfb_swap_surface(input, sizeof(input) - 1, &v));
    input[0xfec] = 0;
    g_assert_false(darwin_iomfb_swap_surface(input, sizeof(input), &v));
    input[0xfec] = 1;
    stl_le_p(d + 0xb, 0x41524742);
    g_assert_false(darwin_iomfb_swap_surface(input, sizeof(input), &v));
    stl_le_p(d + 0xb, 0x42475241);
    stl_le_p(d + 0x29, 1);
    g_assert_false(darwin_iomfb_swap_surface(input, sizeof(input), &v));
    stl_le_p(d + 0x29, UINT32_MAX);
    stl_le_p(d + 0x15, UINT32_MAX - 3);
    g_assert_false(darwin_iomfb_swap_surface(input, sizeof(input), &v));
    stl_le_p(d + 0x15, 4864);
    stq_le_p(input + 0xf90, UINT64_MAX - 16);
    g_assert_false(darwin_iomfb_swap_surface(input, sizeof(input), &v));
}

static void empty_contract(void)
{
    uint8_t input[DARWIN_IOMFB_SWAP_INPUT_SIZE];
    DarwinIOMFBSurface surface;
    uint32_t id;
    /* Captured absent descriptors contain poison, not a BGRA surface. */
    memset(input, 0xaa, sizeof(input));
    input[0xfea] = 0;
    memset(input + 0xfeb, 1, 4);
    stl_le_p(input + 0x98, 0);
    g_assert_true(darwin_iomfb_swap_empty(input, sizeof(input)));
    g_assert_true(darwin_iomfb_swap_id(input, sizeof(input), 12, &id));
    g_assert_cmpuint(id, ==, 0);
    g_assert_false(darwin_iomfb_swap_surface(input, sizeof(input), &surface));
    g_assert_false(darwin_iomfb_swap_empty(NULL, sizeof(input)));
    g_assert_false(darwin_iomfb_swap_empty(input, sizeof(input) - 1));
    for (size_t i = 0xfea; i <= 0xfee; i++) {
        uint8_t saved = input[i];
        input[i] = saved ^ 1;
        g_assert_false(darwin_iomfb_swap_empty(input, sizeof(input)));
        input[i] = 2;
        g_assert_false(darwin_iomfb_swap_empty(input, sizeof(input)));
        input[i] = saved;
    }
}

static void rgha_contract(void)
{
    uint8_t input[DARWIN_IOMFB_SWAP_INPUT_SIZE] = { 0 };
    uint8_t *d = input + 0x6e0;
    DarwinIOMFBSurface s;
    input[0xfec] = input[0xfed] = input[0xfee] = 1;
    stl_le_p(d + 0xb, 0x52476841); d[0x13] = 13; d[0x14] = 1;
    stw_le_p(d + 0x19, 8); d[0x1b] = d[0x1c] = 1;
    stl_le_p(d + 0x15, 9472); stl_le_p(d + 0x21, 1179);
    stl_le_p(d + 0x25, 2556); stl_le_p(d + 0x29, 24211456);
    stq_le_p(input + 0xf90, 0x10000000000ULL);
    g_assert_true(darwin_iomfb_swap_surface(input, sizeof(input), &s));
    g_assert_cmpuint(s.size, ==, 9472 * 2556);
    for (unsigned i = 0; i < 256; i++) {
        d[0x13] = i;
        g_assert_cmpint(darwin_iomfb_swap_surface(input, sizeof(input), &s), ==, i == 13);
    }
    d[0x13] = 13; input[0x54c] = 1;
    g_assert_false(darwin_iomfb_swap_surface(input, sizeof(input), &s));
    input[0x54c] = 0; d[0] = 1;
    g_assert_false(darwin_iomfb_swap_surface(input, sizeof(input), &s));
    d[0] = 0; stl_le_p(d + 0x15, 1179 * 4);
    g_assert_false(darwin_iomfb_swap_surface(input, sizeof(input), &s));

    uint8_t source[64], output[24 + 8];
    memset(source, 0xa5, sizeof(source)); memset(output, 0xa5, sizeof(output));
    s = (DarwinIOMFBSurface){ .width = 3, .height = 2, .stride = 32,
        .format = 0x52476841, .transfer = 13, .colorspace = 1 };
    for (unsigned y = 0; y < 2; y++) for (unsigned x = 0; x < 3; x++) {
        uint8_t *p = source + y * 32 + x * 8;
        stw_le_p(p, 0x3800); stw_le_p(p + 2, 0x3400);
        stw_le_p(p + 4, 0x3a00); stw_le_p(p + 6, 0x3c00);
    }
    g_assert_true(darwin_iomfb_rgha_to_bgra(&s, source, sizeof(source), output, 24));
    for (unsigned x = 0; x < 6; x++) {
        g_assert_cmphex((uint32_t)ldl_le_p(output + x * 4), ==, 0xff8040bf);
    }
    for (unsigned x = 24; x < sizeof(output); x++) g_assert_cmpuint(output[x], ==, 0xa5);
    g_assert_false(darwin_iomfb_rgha_to_bgra(&s, source, 63, output, 24));
    g_assert_false(darwin_iomfb_rgha_to_bgra(&s, source, 64, output, 23));
    stw_le_p(source, 0x7c00);
    g_assert_false(darwin_iomfb_rgha_to_bgra(&s, source, 64, output, 24));
    stw_le_p(source, 0xfc00);
    g_assert_false(darwin_iomfb_rgha_to_bgra(&s, source, 64, output, 24));
    stw_le_p(source, 0x7e00);
    g_assert_false(darwin_iomfb_rgha_to_bgra(&s, source, 64, output, 24));
}

static void rgha_native_oracle(void)
{
    const char *directory = getenv("DVM_RGBA_ORACLE");
    if (!directory) { g_test_skip("native CoreGraphics artifact not supplied"); return; }
    g_autofree char *src_path = g_build_filename(directory, "source.rgha", NULL);
    g_autofree char *dst_path = g_build_filename(directory, "expected.bgra", NULL);
    g_autofree char *source = NULL, *expected = NULL;
    gsize source_size, expected_size;
    g_assert_true(g_file_get_contents(src_path, &source, &source_size, NULL));
    g_assert_true(g_file_get_contents(dst_path, &expected, &expected_size, NULL));
    g_assert_cmpuint(source_size, ==, 2112 * 256);
    g_assert_cmpuint(expected_size, ==, 256 * 256 * 4);
    g_autofree uint8_t *output = g_malloc(expected_size);
    DarwinIOMFBSurface s = { .width = 256, .height = 256, .stride = 2112,
        .format = 0x52476841, .transfer = 13, .colorspace = 1 };
    g_assert_true(darwin_iomfb_rgha_to_bgra(&s, (uint8_t *)source, source_size, output, expected_size));
    unsigned different = 0, maximum = 0;
    for (size_t i = 0; i < expected_size; i++) {
        unsigned delta = abs((int)output[i] - (uint8_t)expected[i]);
        different += delta != 0; maximum = MAX(maximum, delta);
    }
    g_test_message("native CoreGraphics: differing channels=%u maximum error=%u", different, maximum);
    g_assert_cmpuint(maximum, <=, 1);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/darwin-iomfb/swap/native-contract", native_contract);
    g_test_add_func("/darwin-iomfb/swap/reject-unsupported", reject_unsupported);
    g_test_add_func("/darwin-iomfb/swap/scanout-contract", scanout_contract);
    g_test_add_func("/darwin-iomfb/swap/empty-contract", empty_contract);
    g_test_add_func("/darwin-iomfb/swap/rgha-contract", rgha_contract);
    g_test_add_func("/darwin-iomfb/swap/rgha-native-oracle", rgha_native_oracle);
    return g_test_run();
}
