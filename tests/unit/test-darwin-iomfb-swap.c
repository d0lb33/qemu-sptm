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

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/darwin-iomfb/swap/native-contract", native_contract);
    g_test_add_func("/darwin-iomfb/swap/reject-unsupported", reject_unsupported);
    g_test_add_func("/darwin-iomfb/swap/scanout-contract", scanout_contract);
    return g_test_run();
}
