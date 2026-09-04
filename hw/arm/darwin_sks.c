/*
 * AppleSEPKeyStore request-shape parsing shared by the device model and its
 * capture-replay tests.  This deliberately validates framing and observed
 * union shapes, not the opaque cryptographic record bytes.
 */

#include "qemu/osdep.h"
#include "hw/arm/darwin_sks.h"

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

#define SKS_MIGRATE_TAGGED_REQUEST_SIZE      0xa4
#define SKS_MIGRATE_TAGGED_RECORD_KIND_OFF   0x68
#define SKS_MIGRATE_TAGGED_DATA_RECORD_KIND  4
#define SKS_MIGRATE_TAGGED_USER_RECORD_KIND  3
#define SKS_MIGRATE_TAGGED_TARGET_CLASS_C    3
#define SKS_MIGRATE_TAGGED_TARGET_CLASS_D    4
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
        result.record_kind == SKS_MIGRATE_TAGGED_DATA_RECORD_KIND &&
        !memcmp(request + SKS_MIGRATE_TAGGED_RECORD_FIXED_OFF,
                sks_migrate_tagged_data_record_fixed,
                sizeof(sks_migrate_tagged_data_record_fixed));
    tagged_user = request_size == SKS_MIGRATE_TAGGED_REQUEST_SIZE &&
        result.target_class == SKS_MIGRATE_TAGGED_TARGET_CLASS_D &&
        result.record_kind == SKS_MIGRATE_TAGGED_USER_RECORD_KIND &&
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
