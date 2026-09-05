/*
 * AppleSEPKeyStore request-shape parsing shared by the device model and its
 * capture-replay tests.  This deliberately validates framing and observed
 * union shapes, not the opaque cryptographic record bytes.
 */

#include "qemu/osdep.h"
#include "hw/arm/darwin_sks.h"

/*
 * IPC selector 0, length 20, then DER SET OF SEQUENCE { UTF8 key, INTEGER }.
 * The native decoder at 0xfffffff009581144 writes "ss" to record+0 and
 * "bh" to record+0x2a. Public selector 7 returns record+0; MobileKeyBag's
 * MKBDeviceUnlockedSinceBoot tests its bit 2. This models the existing
 * deterministic, unlocked fake-key environment, not SEP keybag security.
 *
 * The old SET { UTF8 "bh", INTEGER -6 } silently decoded as an empty record:
 * ccder's sequence iterator at 0xfffffff00a9d08e8 requires the nested 0x30.
 * DISPLAY_UNLOCK_R1 proves these exact bytes decode to ss=4 and bh=-6.
 */
size_t darwin_sks_build_unlocked_device_state(uint8_t *payload, size_t capacity)
{
    static const uint8_t reply[DARWIN_SKS_DEVICE_STATE_PAYLOAD_SIZE] = {
        0, 0, 0, 0, 20, 0, 0, 0,
        0x31, 0x12,
        0x30, 0x07, 0x0c, 0x02, 'b', 'h', 0x02, 0x01, 0xfa,
        0x30, 0x07, 0x0c, 0x02, 's', 's', 0x02, 0x01, 0x04,
    };

    if (!payload || capacity < sizeof(reply)) {
        return 0;
    }
    memcpy(payload, reply, sizeof(reply));
    return sizeof(reply);
}

#define SKS_IPC_V1_HEADER_BODY_SIZE          0x48
#define SKS_IPC_V1_HEADER_SIZE               0x4c
#define SKS_IPC_VERSION_OFF                  0x14
#define SKS_IPC_VERSION_1                    1

#define SKS_MIGRATE_REQUEST_SIZE             0xb0
#define SKS_MIGRATE_VARIANT_OFF              0x4c
#define SKS_MIGRATE_FIXED_ONE_OFF            0x50
#define SKS_MIGRATE_FIXED_ZERO0_OFF          0x54
#define SKS_MIGRATE_FIXED_ZERO1_OFF          0x58
#define SKS_MIGRATE_FIXED_ZERO2_OFF          0x5c
#define SKS_MIGRATE_FIXED_U64_OFF            0x60
#define SKS_MIGRATE_FIXED_ZERO3_OFF          0x68
#define SKS_MIGRATE_TARGET_CLASS_OFF         0x6c
#define SKS_MIGRATE_FIXED_ZERO4_OFF          0x70
#define SKS_MIGRATE_FIXED_ZERO5_OFF          0x74
#define SKS_MIGRATE_RECORD_LEN_OFF           0x78
#define SKS_MIGRATE_RECORD_OFF               0x7c
#define SKS_MIGRATE_OUTPUT_CAP_OFF           0xa4
#define SKS_MIGRATE_OUTPUT_AUX_OFF           0xa8
#define SKS_MIGRATE_OUTPUT_SCALAR_OFF        0xac
#define SKS_MIGRATE_REQUEST_VARIANT          3
#define SKS_MIGRATE_TARGET_CLASS             0x0e
#define SKS_MIGRATE_REQUEST_SCALAR           0
#define SKS_WRAPPED_KEY_SIZE                 40
#define SKS_MEDIA_KEY_SIZE                   64

#define SKS_UNWRAP_SHORT_REQUEST_SIZE        0x6c
#define SKS_UNWRAP_LONG_REQUEST_SIZE         0x94
#define SKS_UNWRAP_VARIANT_OFF               0x4c
#define SKS_UNWRAP_FIXED_ONE_OFF             0x50
#define SKS_UNWRAP_FIXED_ZERO0_OFF           0x54
#define SKS_UNWRAP_FIXED_MAX_OFF             0x58
#define SKS_UNWRAP_FIXED_ZERO1_OFF           0x5c
#define SKS_UNWRAP_CLASS_OFF                 0x60
#define SKS_UNWRAP_RECORD_LEN_OFF            0x64
#define SKS_UNWRAP_RECORD_OFF                0x68
#define SKS_UNWRAP_SHORT_OUTPUT_SELECTOR_OFF 0x68
#define SKS_UNWRAP_LONG_OUTPUT_SELECTOR_OFF  0x90
#define SKS_UNWRAP_VARIANT                   1
#define SKS_UNWRAP_OUTPUT_SELECTOR           2

#define SKS_MIGRATE_TAGGED_REQUEST_SIZE      0xa4
#define SKS_MIGRATE_TAGGED_RECORD_KIND_OFF   0x68
#define SKS_MIGRATE_TAGGED_DATA_RECORD_KIND  4
#define SKS_MIGRATE_TAGGED_DATA_CLASS_B      2
#define SKS_MIGRATE_TAGGED_USER_RECORD_KIND  3
#define SKS_MIGRATE_TAGGED_TARGET_CLASS_C    3
#define SKS_MIGRATE_TAGGED_TARGET_CLASS_D    4
#define SKS_MIGRATE_TAGGED_TARGET_CLASS_A    1
#define SKS_MIGRATE_TAGGED_ZERO_TAIL_OFF     0x70
#define SKS_MIGRATE_TAGGED_ZERO_TAIL_SIZE    20
#define SKS_MIGRATE_TAGGED_RECORD_LEN_OFF    0x84
#define SKS_MIGRATE_TAGGED_RECORD_OFF        0x88
#define SKS_MIGRATE_TAGGED_RECORD_SIZE       28
#define SKS_MIGRATE_TAGGED_RECORD_FIXED_OFF  0x90

static const uint8_t sks_migrate_tagged_data_record_fixed[] = {
    0x01, 0x00, 'a', 'p', 'f', 's', 'u', 'u', 'i', 'd', 0x00, 0x00,
    'v', 'o', 'l', 'u', 'm', 0x01, 0x00, 0x00,
};

static const uint8_t sks_migrate_tagged_user_record_fixed[] = {
    0x01, 0x00, 'a', 'p', 'f', 's', 'u', 'u', 'i', 'd', 0x00, 0x02,
    'v', 'o', 'l', 'u', 'm', 0x04, 0x00, 0x00,
};

static uint32_t sks_ldl_le(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint64_t sks_ldq_le(const uint8_t *p)
{
    return (uint64_t)sks_ldl_le(p) | (uint64_t)sks_ldl_le(p + 4) << 32;
}

static bool sks_bytes_are_zero(const uint8_t *p, size_t size)
{
    while (size--) {
        if (*p++) {
            return false;
        }
    }
    return true;
}

bool darwin_sks_parse_migrate_request(const uint8_t *request,
                                      size_t request_size,
                                      DarwinSKSMigrateRequest *parsed)
{
    DarwinSKSMigrateRequest result = { 0 };
    bool common;
    bool tagged_data;
    bool tagged_user;

    if (!request || !parsed) {
        return false;
    }
    if (request_size >= SKS_IPC_V1_HEADER_SIZE) {
        result.header_body_size = sks_ldl_le(request);
        result.ipc_version = sks_ldl_le(request + SKS_IPC_VERSION_OFF);
    }
    if (request_size >= SKS_MIGRATE_TARGET_CLASS_OFF + sizeof(uint32_t)) {
        result.variant = sks_ldl_le(request + SKS_MIGRATE_VARIANT_OFF);
        result.record_kind =
            sks_ldl_le(request + SKS_MIGRATE_TAGGED_RECORD_KIND_OFF);
        result.target_class =
            sks_ldl_le(request + SKS_MIGRATE_TARGET_CLASS_OFF);
    }
    if (request_size >= SKS_MIGRATE_OUTPUT_SCALAR_OFF + sizeof(uint32_t)) {
        result.record_len = sks_ldl_le(request + SKS_MIGRATE_RECORD_LEN_OFF);
        result.output_cap = sks_ldl_le(request + SKS_MIGRATE_OUTPUT_CAP_OFF);
        result.output_scalar =
            sks_ldl_le(request + SKS_MIGRATE_OUTPUT_SCALAR_OFF);
    }

    common = request_size >= SKS_MIGRATE_TARGET_CLASS_OFF + 4 &&
        result.header_body_size == SKS_IPC_V1_HEADER_BODY_SIZE &&
        result.ipc_version == SKS_IPC_VERSION_1 &&
        result.variant == SKS_MIGRATE_REQUEST_VARIANT &&
        sks_ldl_le(request + SKS_MIGRATE_FIXED_ONE_OFF) == 1 &&
        sks_ldl_le(request + SKS_MIGRATE_FIXED_ZERO0_OFF) == 0 &&
        sks_ldl_le(request + SKS_MIGRATE_FIXED_ZERO1_OFF) == 0 &&
        sks_ldl_le(request + SKS_MIGRATE_FIXED_ZERO2_OFF) == 0 &&
        sks_ldq_le(request + SKS_MIGRATE_FIXED_U64_OFF) == UINT64_MAX;

    if (common && request_size == SKS_MIGRATE_REQUEST_SIZE &&
        result.target_class == SKS_MIGRATE_TARGET_CLASS &&
        result.record_len == SKS_WRAPPED_KEY_SIZE &&
        result.output_cap == SKS_MEDIA_KEY_SIZE &&
        sks_ldl_le(request + SKS_MIGRATE_FIXED_ZERO3_OFF) == 0 &&
        sks_ldl_le(request + SKS_MIGRATE_FIXED_ZERO4_OFF) == 0 &&
        sks_ldl_le(request + SKS_MIGRATE_FIXED_ZERO5_OFF) == 0 &&
        sks_ldl_le(request + SKS_MIGRATE_OUTPUT_AUX_OFF) == 0 &&
        result.output_scalar == SKS_MIGRATE_REQUEST_SCALAR &&
        SKS_MIGRATE_RECORD_OFF + result.record_len ==
            SKS_MIGRATE_OUTPUT_CAP_OFF) {
        result.shape = DARWIN_SKS_MIGRATE_WRAPPED_KEY;
        *parsed = result;
        return true;
    }

    tagged_data = request_size == SKS_MIGRATE_TAGGED_REQUEST_SIZE &&
        result.target_class == SKS_MIGRATE_TAGGED_TARGET_CLASS_C &&
        /* SMP_SKS_CAPTURE6 captures Data 2 -> 3 during a warm-disk cold
         * boot (request SHA256 014e378d1667d4ae...). Like the existing
         * Data 4 -> 3 record, +0x68 is the source class, not a fixed volume
         * kind. Keep the exact Data tag, framing and destination checks. */
        (result.record_kind == SKS_MIGRATE_TAGGED_DATA_RECORD_KIND ||
         result.record_kind == SKS_MIGRATE_TAGGED_DATA_CLASS_B) &&
        !memcmp(request + SKS_MIGRATE_TAGGED_RECORD_FIXED_OFF,
                sks_migrate_tagged_data_record_fixed,
                sizeof(sks_migrate_tagged_data_record_fixed));
    tagged_user = request_size == SKS_MIGRATE_TAGGED_REQUEST_SIZE &&
        /* DISPLAY_NATIVE_R2's protected temporary-file creation also sends
         * the exact User-volume record with target class 1. Dropping it
         * exhausts the one-request buffer and ends in an SKS timeout.
         * Preserve the class in the existing variant-3 reply; do not infer
         * support for other classes or relax the record/framing checks. */
        (((result.target_class == SKS_MIGRATE_TAGGED_TARGET_CLASS_D ||
           result.target_class == SKS_MIGRATE_TAGGED_TARGET_CLASS_A) &&
          result.record_kind == SKS_MIGRATE_TAGGED_USER_RECORD_KIND) ||
         /* DISPLAY_NATIVE_R4 then captures the reverse 1 -> 3 transfer
          * with the same User-volume tagged record. The historical field
          * name "record_kind" must not imply a fixed volume identity.
          * DISPLAY_NATIVE_R8 also captures User 4 -> 3 (SHA256
          * b888d00d543ad02a...), the reverse of the earlier 3 -> 4. */
         (result.target_class == SKS_MIGRATE_TAGGED_TARGET_CLASS_C &&
          (result.record_kind == SKS_MIGRATE_TAGGED_TARGET_CLASS_A ||
           result.record_kind == SKS_MIGRATE_TAGGED_TARGET_CLASS_D))) &&
        !memcmp(request + SKS_MIGRATE_TAGGED_RECORD_FIXED_OFF,
                sks_migrate_tagged_user_record_fixed,
                sizeof(sks_migrate_tagged_user_record_fixed));

    if (common && request_size == SKS_MIGRATE_TAGGED_REQUEST_SIZE &&
        (tagged_data || tagged_user) &&
        sks_bytes_are_zero(request + SKS_MIGRATE_TAGGED_ZERO_TAIL_OFF,
                           SKS_MIGRATE_TAGGED_ZERO_TAIL_SIZE) &&
        sks_ldl_le(request + SKS_MIGRATE_TAGGED_RECORD_LEN_OFF) ==
            SKS_MIGRATE_TAGGED_RECORD_SIZE &&
        SKS_MIGRATE_TAGGED_RECORD_OFF + SKS_MIGRATE_TAGGED_RECORD_SIZE ==
            request_size) {
        result.record_len = SKS_MIGRATE_TAGGED_RECORD_SIZE;
        result.shape = tagged_data ? DARWIN_SKS_MIGRATE_TAGGED_DATA :
                                     DARWIN_SKS_MIGRATE_TAGGED_USER;
        *parsed = result;
        return true;
    }

    *parsed = result;
    return false;
}

bool darwin_sks_parse_unwrap_file_key_request(
    const uint8_t *request, size_t request_size,
    DarwinSKSUnwrapFileKeyRequest *parsed)
{
    DarwinSKSUnwrapFileKeyRequest result = { 0 };
    bool common;

    if (!request || !parsed) {
        return false;
    }
    if (request_size >= SKS_IPC_V1_HEADER_SIZE) {
        result.header_body_size = sks_ldl_le(request);
        result.ipc_version = sks_ldl_le(request + SKS_IPC_VERSION_OFF);
    }
    if (request_size >= SKS_UNWRAP_CLASS_OFF + sizeof(uint32_t)) {
        result.variant = sks_ldl_le(request + SKS_UNWRAP_VARIANT_OFF);
        result.protection_class = sks_ldl_le(request + SKS_UNWRAP_CLASS_OFF);
    }

    /* Decode selectors even on rejection, so diagnostics report the wire
     * value rather than an uninitialized zero. Both offsets require an exact
     * known size before being read. */
    if (request_size == SKS_UNWRAP_SHORT_REQUEST_SIZE) {
        result.output_selector = sks_ldl_le(
            request + SKS_UNWRAP_SHORT_OUTPUT_SELECTOR_OFF);
    } else if (request_size == SKS_UNWRAP_LONG_REQUEST_SIZE) {
        result.output_selector = sks_ldl_le(
            request + SKS_UNWRAP_LONG_OUTPUT_SELECTOR_OFF);
    }

    common = request_size >= SKS_UNWRAP_CLASS_OFF + sizeof(uint32_t) &&
        result.header_body_size == SKS_IPC_V1_HEADER_BODY_SIZE &&
        result.ipc_version == SKS_IPC_VERSION_1 &&
        result.variant == SKS_UNWRAP_VARIANT &&
        sks_ldl_le(request + SKS_UNWRAP_FIXED_ONE_OFF) == 1 &&
        sks_ldl_le(request + SKS_UNWRAP_FIXED_ZERO0_OFF) == 0 &&
        sks_ldl_le(request + SKS_UNWRAP_FIXED_MAX_OFF) == UINT32_MAX &&
        sks_ldl_le(request + SKS_UNWRAP_FIXED_ZERO1_OFF) == 0 &&
        (result.protection_class == 1 || result.protection_class == 2 ||
         result.protection_class == 3 || result.protection_class == 4 ||
         result.protection_class == 17 ||
         /* DISPLAY_SMP6_WARM2: endpoint-18 DVA 0x1000000c000,
          * PA 0x1001a3d8000, class 13 at +0x60; only the empty-record
          * 108-byte form has been captured for this class. */
         (result.protection_class == 13 &&
          request_size == SKS_UNWRAP_SHORT_REQUEST_SIZE));

    if (common && request_size == SKS_UNWRAP_SHORT_REQUEST_SIZE &&
        sks_ldl_le(request + SKS_UNWRAP_RECORD_LEN_OFF) == 0) {
        result.output_selector = sks_ldl_le(
            request + SKS_UNWRAP_SHORT_OUTPUT_SELECTOR_OFF);
        if (result.output_selector == SKS_UNWRAP_OUTPUT_SELECTOR) {
            result.shape = DARWIN_SKS_UNWRAP_FILE_KEY_EMPTY_RECORD;
            *parsed = result;
            return true;
        }
    }

    if (common && request_size == SKS_UNWRAP_LONG_REQUEST_SIZE) {
        result.record_len = sks_ldl_le(request + SKS_UNWRAP_RECORD_LEN_OFF);
        result.output_selector = sks_ldl_le(
            request + SKS_UNWRAP_LONG_OUTPUT_SELECTOR_OFF);
        if (result.record_len == SKS_WRAPPED_KEY_SIZE &&
            SKS_UNWRAP_RECORD_OFF + result.record_len ==
                SKS_UNWRAP_LONG_OUTPUT_SELECTOR_OFF &&
            result.output_selector == SKS_UNWRAP_OUTPUT_SELECTOR) {
            result.shape = DARWIN_SKS_UNWRAP_FILE_KEY_WRAPPED_RECORD;
            *parsed = result;
            return true;
        }
    }

    *parsed = result;
    return false;
}

/* fs_check_class emits two live-captured selector-2 request shapes.  The
 * 0x70-byte class-1 query was already accepted on remount
 * (/tmp/dvm/probe/SKS_REMOUNT_V10.stderr.log:1912-1919).  The 0x8c-byte form
 * carries the requested protection class at wire +0x60 and is the form APFS
 * uses while creating protected named streams
 * (/tmp/dvm/probe/DATA_SEED_VISIBLE.stderr.log:1573-1585). */
#define SKS_CHECK_CLASS_SHORT_REQUEST_SIZE 0x70
#define SKS_CHECK_CLASS_REQUEST_SIZE       0x8c
#define SKS_CHECK_CLASS_VARIANT_OFF        0x4c
#define SKS_CHECK_CLASS_FIXED_ONE_OFF      0x50
#define SKS_CHECK_CLASS_FIXED_ZERO0_OFF    0x54
#define SKS_CHECK_CLASS_FIXED_MAX_OFF      0x58
#define SKS_CHECK_CLASS_FIXED_ZERO1_OFF    0x5c
#define SKS_CHECK_CLASS_REQUEST_CLASS_OFF  0x60
#define SKS_CHECK_CLASS_LONG_TAG_OFF       0x64
#define SKS_CHECK_CLASS_LONG_SIZE_OFF      0x68
#define SKS_CHECK_CLASS_LONG_ZERO_OFF      0x70
#define SKS_CHECK_CLASS_LONG_UUID_VALID_OFF 0x74
#define SKS_CHECK_CLASS_LONG_UUID_OFF      0x76
#define SKS_CHECK_CLASS_LONG_UUID_SIZE     16
#define SKS_CHECK_CLASS_LONG_ZERO_TAIL_OFF 0x86
#define SKS_CHECK_CLASS_LONG_ZERO_TAIL_SIZE 6
#define SKS_CHECK_CLASS_REQUEST_VARIANT    2
#define SKS_CHECK_CLASS_SHORT_CLASS        1
#define SKS_CHECK_CLASS_SPECIAL_CLASS      17
#define SKS_CHECK_CLASS_LONG_TAG           2
#define SKS_CHECK_CLASS_LONG_SIZE          0x1c

static const uint8_t sks_check_class_long_zero_tail[
    SKS_CHECK_CLASS_LONG_ZERO_TAIL_SIZE] = { 0 };
static const uint8_t sks_check_class_zero_uuid[
    SKS_CHECK_CLASS_LONG_UUID_SIZE] = { 0 };

bool darwin_sks_parse_check_class_request(const uint8_t *request,
                                         size_t request_size,
                                         DarwinSKSCheckClassRequest *parsed)
{
    uint32_t header_body_size = 0;
    uint32_t ipc_version = 0;
    uint32_t variant = 0;
    uint32_t protection_class = 0;
    bool common_shape;
    bool short_shape;
    bool long_shape;

    if (!request || !parsed) {
        return false;
    }
    if (request_size >= SKS_IPC_V1_HEADER_SIZE) {
        header_body_size = sks_ldl_le(request);
        ipc_version = sks_ldl_le(request + SKS_IPC_VERSION_OFF);
    }
    if (request_size >=
        SKS_CHECK_CLASS_REQUEST_CLASS_OFF + sizeof(uint32_t)) {
        variant = sks_ldl_le(request + SKS_CHECK_CLASS_VARIANT_OFF);
        protection_class =
            sks_ldl_le(request + SKS_CHECK_CLASS_REQUEST_CLASS_OFF);
    }

    common_shape = request_size >=
            SKS_CHECK_CLASS_REQUEST_CLASS_OFF + sizeof(uint32_t) &&
        header_body_size == SKS_IPC_V1_HEADER_BODY_SIZE &&
        ipc_version == SKS_IPC_VERSION_1 &&
        variant == SKS_CHECK_CLASS_REQUEST_VARIANT &&
        sks_ldl_le(request + SKS_CHECK_CLASS_FIXED_ONE_OFF) == 1 &&
        sks_ldl_le(request + SKS_CHECK_CLASS_FIXED_ZERO0_OFF) == 0 &&
        sks_ldl_le(request + SKS_CHECK_CLASS_FIXED_MAX_OFF) == UINT32_MAX &&
        sks_ldl_le(request + SKS_CHECK_CLASS_FIXED_ZERO1_OFF) == 0;
    short_shape = request_size == SKS_CHECK_CLASS_SHORT_REQUEST_SIZE &&
        protection_class == SKS_CHECK_CLASS_SHORT_CLASS &&
        sks_ldl_le(request + SKS_CHECK_CLASS_LONG_TAG_OFF) == 0 &&
        sks_ldl_le(request + SKS_CHECK_CLASS_LONG_SIZE_OFF) == 0 &&
        sks_ldl_le(request + SKS_CHECK_CLASS_LONG_SIZE_OFF + 4) == 0;
    /* The persistent-Data normal boot adds class 2 to the same long-form
     * request already proven for classes 3 and 4.  It is the final request
     * before the SKS timeout at /tmp/dvm/probe/
     * PERSIST_NVME_ROLES_PREINIT_TZ1_BOOT1.stderr.log:1480.  A later
     * 600-second positive control crosses that boundary repeatedly, then
     * reaches the same 140-byte variant-2 request with class 17 at
     * ROOT_SKS_CLASS2_POS1.stderr.log:15157; its rejection alone begins the
     * timeout sequence at serial lines 912-917.  The next boot reaches the
     * same long form with class 1 at ROOT_SKS_CLASS17_POS1.stderr.log:74829,
     * distinct from the already accepted class-1 short availability query;
     * it alone starts the serial timeout at lines 892-894.  Keep every
     * remaining shape check intact so none of these observations broadens
     * selector, object, or UUID semantics.
     * DISPLAY_NATIVE_R5.request.bin (SHA256 a5b8ab23539ecd02...) adds
     * the same long form for class 13 on User. The pre-timeout guard froze
     * the rejected request; all framing and tagged-object checks match. */
    long_shape = request_size == SKS_CHECK_CLASS_REQUEST_SIZE &&
        (protection_class == SKS_CHECK_CLASS_SHORT_CLASS ||
         protection_class == 2 || protection_class == 3 ||
         protection_class == 4 || protection_class == 13 ||
         protection_class == SKS_CHECK_CLASS_SPECIAL_CLASS) &&
        sks_ldl_le(request + SKS_CHECK_CLASS_LONG_TAG_OFF) ==
            SKS_CHECK_CLASS_LONG_TAG &&
        sks_ldl_le(request + SKS_CHECK_CLASS_LONG_SIZE_OFF) ==
            SKS_CHECK_CLASS_LONG_SIZE &&
        sks_ldl_le(request + SKS_CHECK_CLASS_LONG_ZERO_OFF) == 0 &&
        request[SKS_CHECK_CLASS_LONG_UUID_VALID_OFF] == 1 &&
        request[SKS_CHECK_CLASS_LONG_UUID_VALID_OFF + 1] == 0 &&
        memcmp(request + SKS_CHECK_CLASS_LONG_UUID_OFF,
               sks_check_class_zero_uuid,
               sizeof(sks_check_class_zero_uuid)) != 0 &&
        !memcmp(request + SKS_CHECK_CLASS_LONG_ZERO_TAIL_OFF,
                sks_check_class_long_zero_tail,
                sizeof(sks_check_class_long_zero_tail));

    *parsed = (DarwinSKSCheckClassRequest) {
        .header_body_size = header_body_size, .ipc_version = ipc_version,
        .variant = variant, .protection_class = protection_class,
        .echo_class = common_shape && long_shape,
    };
    return common_shape && (short_shape || long_shape);
}
