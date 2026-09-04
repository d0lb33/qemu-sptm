#include "qemu/osdep.h"
#include "hw/arm/darwin_sks.h"

/* Exact 164-byte Data-volume request captured at
 * ROOT_SKS_OP0F_DATA_POS1.stderr.log:4117924-4117936. */
static const uint8_t captured_data_request[] = {
    0x48, 0x00, 0x00, 0x00, 0xcb, 0xce, 0xc5, 0xf2,
    0xd8, 0x65, 0x44, 0x37, 0x6c, 0x7f, 0x5c, 0x40,
    0x44, 0xe6, 0x37, 0xba, 0x01, 0x00, 0x00, 0x00,
    0xb3, 0x0b, 0x3d, 0x94, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x9c, 0x83, 0x46, 0x1a, 0x84, 0xf2, 0x6a, 0xb7,
    0xd8, 0x67, 0xa8, 0x74, 0xef, 0xaf, 0xa9, 0xf5,
    0x37, 0xc0, 0xee, 0xc1, 0x03, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00,
    0x0c, 0xbc, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x61, 0x70, 0x66, 0x73, 0x75, 0x75,
    0x69, 0x64, 0x00, 0x00, 0x76, 0x6f, 0x6c, 0x75,
    0x6d, 0x01, 0x00, 0x00,
};

static void parse_captured_data(void)
{
    g_autofree char *digest = g_compute_checksum_for_data(
        G_CHECKSUM_SHA256, captured_data_request,
        sizeof(captured_data_request));
    DarwinSKSMigrateRequest parsed;

    g_test_message("captured request sha256=%s", digest);
    g_assert_cmpstr(digest, ==,
                    "405926d6f771cb768e3ceddcb0f147489a815f0c6d55ff3dac016086d0df8f0c");
    g_assert_true(darwin_sks_parse_migrate_request(
        captured_data_request, sizeof(captured_data_request), &parsed));
    g_assert_cmpint(parsed.shape, ==, DARWIN_SKS_MIGRATE_TAGGED_DATA);
    g_assert_cmpuint(parsed.variant, ==, 3);
    g_assert_cmpuint(parsed.record_kind, ==, 4);
    g_assert_cmpuint(parsed.target_class, ==, 3);
    g_assert_cmpuint(parsed.record_len, ==, 28);
}

static void reject_old_kind_three_bug(void)
{
    uint8_t request[sizeof(captured_data_request)];
    DarwinSKSMigrateRequest parsed;

    memcpy(request, captured_data_request, sizeof(request));
    request[0x68] = 3;
    g_assert_false(darwin_sks_parse_migrate_request(
        request, sizeof(request), &parsed));
}

static void reject_wrong_class_volume_pair(void)
{
    uint8_t request[sizeof(captured_data_request)];
    DarwinSKSMigrateRequest parsed;

    memcpy(request, captured_data_request, sizeof(request));
    request[0x6c] = 4;
    g_assert_false(darwin_sks_parse_migrate_request(
        request, sizeof(request), &parsed));
}

static void reject_corrupt_fixed_fields(void)
{
    static const size_t offsets[] = { 0x00, 0x14, 0x4c, 0x50, 0x70,
                                      0x84, 0x90, 0xa1 };

    for (size_t i = 0; i < G_N_ELEMENTS(offsets); i++) {
        uint8_t request[sizeof(captured_data_request)];
        DarwinSKSMigrateRequest parsed;

        memcpy(request, captured_data_request, sizeof(request));
        request[offsets[i]] ^= 1;
        g_assert_false(darwin_sks_parse_migrate_request(
            request, sizeof(request), &parsed));
    }
}

static void reject_truncation(void)
{
    DarwinSKSMigrateRequest parsed;

    g_assert_false(darwin_sks_parse_migrate_request(
        captured_data_request, sizeof(captured_data_request) - 1, &parsed));
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/darwin-sks/migrate/captured-data", parse_captured_data);
    g_test_add_func("/darwin-sks/migrate/reject-old-kind3",
                    reject_old_kind_three_bug);
    g_test_add_func("/darwin-sks/migrate/reject-class-pair",
                    reject_wrong_class_volume_pair);
    g_test_add_func("/darwin-sks/migrate/reject-fixed-fields",
                    reject_corrupt_fixed_fields);
    g_test_add_func("/darwin-sks/migrate/reject-truncation",
                    reject_truncation);
    return g_test_run();
}
