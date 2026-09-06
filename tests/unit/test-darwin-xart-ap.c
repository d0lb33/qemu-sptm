#include "qemu/osdep.h"
#include "hw/arm/darwin_xart_ap.h"

static void test_boot(void)
{
    uint8_t nonce[8] = { 1,2,3,4,5,6,7,8 }, manifest[48], zero[56] = { 0 };
    DarwinXARTAP s;
    memset(manifest, 0xa5, sizeof(manifest));
    darwin_xart_ap_init(&s, nonce, manifest);
    g_assert_cmpmem(s.payload[0], 8, nonce, 8);
    g_assert_cmpmem(s.payload[0] + 8, 48, manifest, 48);
    g_assert_cmpuint(s.state[0], ==, 3);
    g_assert_cmpuint(s.state[1], ==, 0);
    g_assert_cmpmem(s.payload[1], 56, zero, 56);
    DarwinXARTAP saved = s;
    g_assert_false(darwin_xart_ap_change(&s, 0x15, 0, nonce));
    g_assert_cmpmem(&s, sizeof(s), &saved, sizeof(saved));
    g_assert_true(darwin_xart_ap_change(&s, 0x15, 1, nonce));
    g_assert_cmpuint(s.state[1], ==, 1);
    g_assert_cmpmem(s.payload[1], 8, nonce, 8);
    g_assert_cmpmem(s.payload[1] + 8, 48, zero, 48);
    g_assert_false(darwin_xart_ap_change(&s, 0x1a, 1, NULL));
    g_assert_true(darwin_xart_ap_change(&s, 0x19, 1, NULL));
    g_assert_cmpmem(&s, sizeof(s), &saved, sizeof(saved));
    s.state[1] = 2;
    g_assert_true(darwin_xart_ap_change(&s, 0x1a, 1, NULL));
    g_assert_cmpuint(s.state[1], ==, 3);
}

static void test_frame(void)
{
    uint8_t op, slot;
    const uint64_t native = UINT64_C(0x0000000000180710);
    g_assert_true(darwin_xart_ap_request(native, &op, &slot));
    g_assert_cmpuint(op, ==, 0x18);
    g_assert_cmpuint(slot, ==, 0);
    g_assert_true(darwin_xart_ap_request(native | (UINT64_C(1) << 48), &op, &slot));
    g_assert_cmpuint(slot, ==, 1);
    for (unsigned bit = 0; bit < 64; bit++) {
        if ((bit >= 8 && bit < 16) || bit == 48) {
            continue;
        }
        uint64_t value = native ^ (UINT64_C(1) << bit);
        if ((value >> 16 & 255) == 0x19 || (value >> 16 & 255) == 0x1a) {
            continue;
        }
        g_assert_false(darwin_xart_ap_request(value, &op, &slot));
    }
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/darwin-xart-ap/boot-lifecycle", test_boot);
    g_test_add_func("/darwin-xart-ap/frame", test_frame);
    return g_test_run();
}
