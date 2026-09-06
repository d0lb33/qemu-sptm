#include "qemu/osdep.h"
#include "qemu/bswap.h"
#include "hw/arm/darwin_scrd.h"
static const uint8_t capture[40] = {
  1,0,28,0,10,0,0,0,0,0,0,0,245,1,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,68,82,67,83,36,0,0,2,245,1,0,0
};
static void test_capture(void)
{
    uint32_t owner = 0;
    g_assert_true(darwin_scrd_parse_create(capture, sizeof(capture), &owner));
    g_assert_cmpuint(owner, ==, 501);
    for (size_t n = 0; n < sizeof(capture); n++) {
        g_assert_false(darwin_scrd_parse_create(capture, n, &owner));
    }
}
static void test_reject_mutations(void)
{
    uint32_t owner;
    uint8_t r[41];
    for (size_t i = 0; i < 40; i++) {
        if (i >= 4 && i < 8) { /* request sequence is deliberately variable */
            continue;
        }
        memcpy(r, capture, 40);
        r[i] ^= 1;
        g_assert_false(darwin_scrd_parse_create(r, 40, &owner));
    }
    memcpy(r, capture, 40);
    g_assert_false(darwin_scrd_parse_create(r, 41, &owner));
    stl_le_p(r + 4, 123);
    stl_le_p(r + 12, 502);
    stl_le_p(r + 36, 502);
    g_assert_true(darwin_scrd_parse_create(r, 40, &owner));
    g_assert_cmpuint(owner, ==, 502);
}
static void test_handle(void)
{
    uint8_t r[52] = { 0 };
    const uint8_t *handle;
    uint32_t owner;
    memcpy(r, capture, 36);
    r[32] = 0x13;
    memset(r + 36, 0xa5, 16);
    g_assert_true(darwin_scrd_parse_handle(r, 52, 0x13, &owner, &handle));
    g_assert_cmpuint(owner, ==, 501);
    g_assert_cmpmem(handle, 16, r + 36, 16);
    g_assert_false(darwin_scrd_parse_handle(r, 51, 0x13, &owner, &handle));
    g_assert_false(darwin_scrd_parse_handle(r, 52, 0x12, &owner, &handle));
    r[32] = 0x02;
    g_assert_true(darwin_scrd_parse_handle(r, 52, 0x02, &owner, &handle));
    r[32] = 0x13;
    r[35] ^= 1;
    g_assert_false(darwin_scrd_parse_handle(r, 52, 0x13, &owner, &handle));
}
static void test_empty_data(void)
{
    uint8_t r[74] = { 0 }, original[73];
    uint32_t owner;
    const uint8_t *handle;
    memcpy(r, capture, 36);
    r[32] = 0x28;
    memset(r + 36, 0xa5, 16);
    stl_le_p(r + 52, 5);
    stl_le_p(r + 60, 1);
    stl_le_p(r + 64, 14);
    stl_le_p(r + 68, 1);
    memcpy(original, r, 73);
    g_assert_true(darwin_scrd_parse_empty_data(r, 73, &owner, &handle));
    g_assert_cmpuint(owner, ==, 501);
    g_assert_cmpmem(handle, 16, r + 36, 16);
    for (size_t n = 0; n < 73; n++) {
        g_assert_false(darwin_scrd_parse_empty_data(r, n, &owner, &handle));
    }
    g_assert_false(darwin_scrd_parse_empty_data(r, 74, &owner, &handle));
    for (size_t i = 0; i < 73; i++) {
        if ((i >= 4 && i < 8) || (i >= 12 && i < 16) ||
            (i >= 36 && i < 52)) {
            continue; /* sequence, owner and token checked by device state */
        }
        memcpy(r, original, 73);
        r[i] ^= 1;
        g_assert_false(darwin_scrd_parse_empty_data(r, 73, &owner, &handle));
    }
}
static void test_unsupported_queries(void)
{
    uint8_t r[73] = { 0 }, good[73];
    memcpy(r, capture, 36);
    r[32] = 0x29;
    memset(r + 36, 0xa5, 16);
    stl_le_p(r + 52, 13);
    r[56] = 1;
    g_assert_true(darwin_scrd_can_report_unsupported(r, 61));
    memcpy(good, r, sizeof(r));
    for (size_t i = 0; i < 61; i++) {
        if ((i >= 4 && i < 8) || (i >= 12 && i < 16) ||
            (i >= 36 && i < 52)) {
            continue; /* variable sequence, caller and handle; always denial */
        }
        memcpy(r, good, sizeof(r));
        r[i] ^= 1;
        g_assert_false(darwin_scrd_can_report_unsupported(r, 61));
    }
    memcpy(r, capture, 36);
    memset(r + 36, 0, sizeof(r) - 36);
    r[32] = 0x33;
    stl_le_p(r + 56, 12);
    stl_le_p(r + 60, 1);
    stl_le_p(r + 64, 2);
    g_assert_true(darwin_scrd_can_report_unsupported(r, 72));
    memcpy(good, r, sizeof(r));
    for (size_t i = 0; i < 72; i++) {
        if ((i >= 4 && i < 8) || (i >= 12 && i < 16)) {
            continue;
        }
        memcpy(r, good, sizeof(r));
        r[i] ^= 1;
        g_assert_false(darwin_scrd_can_report_unsupported(r, 72));
    }
    for (size_t n = 0; n < 73; n++) {
        if (n != 72) {
            g_assert_false(darwin_scrd_can_report_unsupported(good, n));
        }
    }
}
int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/darwin-scrd/create/capture", test_capture);
    g_test_add_func("/darwin-scrd/create/reject", test_reject_mutations);
    g_test_add_func("/darwin-scrd/handle/framing", test_handle);
    g_test_add_func("/darwin-scrd/data/empty-reset", test_empty_data);
    g_test_add_func("/darwin-scrd/error/strict-queries", test_unsupported_queries);
    return g_test_run();
}
