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

/* Exact 148-byte wrapped-record op09 request recovered from the preserved
 * ROOT_SKS_LATE_HOST2 endpoint-18 OOL page.  The DART walk translates DVA
 * 0x1000004c000 to PA 0x1001a478000. */
static const uint8_t captured_unwrap_request[] = {
    0x48, 0x00, 0x00, 0x00, 0x87, 0x92, 0xb8, 0xcc,
    0xa5, 0x8d, 0xc6, 0xcc, 0x5c, 0x81, 0x55, 0xb6,
    0xf2, 0x33, 0xdd, 0xbb, 0x01, 0x00, 0x00, 0x00,
    0xf7, 0xc7, 0x6d, 0x3b, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x45, 0x9d, 0x72, 0x92, 0x88, 0xef, 0x08, 0x70,
    0xaa, 0x6c, 0x13, 0x8e, 0x8d, 0x8a, 0x0d, 0x7d,
    0xda, 0x59, 0xe2, 0xca, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00,
    0x44, 0x56, 0x4d, 0x2d, 0x53, 0x4b, 0x53, 0x2d,
    0x57, 0x52, 0x41, 0x50, 0x50, 0x45, 0x44, 0x2d,
    0x4b, 0x45, 0x59, 0x2d, 0x30, 0x31, 0x00, 0x01,
    0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
    0x02, 0x00, 0x00, 0x00,
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

static void parse_captured_unwrap(void)
{
    g_autofree char *digest = g_compute_checksum_for_data(
        G_CHECKSUM_SHA256, captured_unwrap_request,
        sizeof(captured_unwrap_request));
    DarwinSKSUnwrapFileKeyRequest parsed;

    g_test_message("captured request sha256=%s", digest);
    g_assert_cmpstr(digest, ==,
                    "e400aae31fd6fff8b662d28c262ca2e0c345e23eb97b99664eae1e2e7f77ee0e");
    g_assert_true(darwin_sks_parse_unwrap_file_key_request(
        captured_unwrap_request, sizeof(captured_unwrap_request), &parsed));
    g_assert_cmpint(parsed.shape, ==,
                    DARWIN_SKS_UNWRAP_FILE_KEY_WRAPPED_RECORD);
    g_assert_cmpuint(parsed.variant, ==, 1);
    g_assert_cmpuint(parsed.protection_class, ==, 4);
    g_assert_cmpuint(parsed.record_len, ==, 40);
    g_assert_cmpuint(parsed.output_selector, ==, 2);
}

static void reject_corrupt_unwrap_fields(void)
{
    static const size_t offsets[] = { 0x00, 0x14, 0x4c, 0x50, 0x58,
                                      0x60, 0x64, 0x90 };

    for (size_t i = 0; i < G_N_ELEMENTS(offsets); i++) {
        uint8_t request[sizeof(captured_unwrap_request)];
        DarwinSKSUnwrapFileKeyRequest parsed;

        memcpy(request, captured_unwrap_request, sizeof(request));
        request[offsets[i]] ^= 1;
        g_assert_false(darwin_sks_parse_unwrap_file_key_request(
            request, sizeof(request), &parsed));
    }
}

static void reject_unwrap_truncation(void)
{
    DarwinSKSUnwrapFileKeyRequest parsed;

    g_assert_false(darwin_sks_parse_unwrap_file_key_request(
        captured_unwrap_request, sizeof(captured_unwrap_request) - 1,
        &parsed));
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
    g_test_add_func("/darwin-sks/unwrap/captured-wrapped-record",
                    parse_captured_unwrap);
    g_test_add_func("/darwin-sks/unwrap/reject-fixed-fields",
                    reject_corrupt_unwrap_fields);
    g_test_add_func("/darwin-sks/unwrap/reject-truncation",
                    reject_unwrap_truncation);
    return g_test_run();
}
