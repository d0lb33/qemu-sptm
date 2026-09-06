/*
 * Pure parsers for AP-visible AppleSEPKeyStore request shapes.
 *
 * Keep these helpers independent of QOM and DarwinSEPState so captured wire
 * requests can be replayed by unit tests without booting an iOS guest.
 */
#ifndef HW_ARM_DARWIN_SKS_H
#define HW_ARM_DARWIN_SKS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* IPC header (8) + 30-byte DER SET, rounded up to four-byte framing. */
#define DARWIN_SKS_DEVICE_STATE_PAYLOAD_SIZE 40

size_t darwin_sks_build_unlocked_device_state(uint8_t *payload,
                                              size_t capacity);

typedef enum DarwinSKSMigrateShape {
    DARWIN_SKS_MIGRATE_INVALID = 0,
    DARWIN_SKS_MIGRATE_WRAPPED_KEY,
    DARWIN_SKS_MIGRATE_TAGGED_DATA,
    DARWIN_SKS_MIGRATE_TAGGED_USER,
} DarwinSKSMigrateShape;

typedef struct DarwinSKSMigrateRequest {
    DarwinSKSMigrateShape shape;
    uint32_t header_body_size;
    uint32_t ipc_version;
    uint32_t variant;
    uint32_t target_class;
    uint32_t record_kind;
    uint32_t record_len;
    uint32_t output_cap;
    uint32_t output_scalar;
} DarwinSKSMigrateRequest;

typedef enum DarwinSKSUnwrapFileKeyShape {
    DARWIN_SKS_UNWRAP_FILE_KEY_INVALID = 0,
    DARWIN_SKS_UNWRAP_FILE_KEY_EMPTY_RECORD,
    DARWIN_SKS_UNWRAP_FILE_KEY_WRAPPED_RECORD,
} DarwinSKSUnwrapFileKeyShape;

typedef struct DarwinSKSUnwrapFileKeyRequest {
    DarwinSKSUnwrapFileKeyShape shape;
    uint32_t header_body_size;
    uint32_t ipc_version;
    uint32_t variant;
    uint32_t protection_class;
    uint32_t record_len;
    uint32_t output_selector;
} DarwinSKSUnwrapFileKeyRequest;

bool darwin_sks_parse_migrate_request(const uint8_t *request,
                                      size_t request_size,
                                      DarwinSKSMigrateRequest *parsed);

bool darwin_sks_parse_unwrap_file_key_request(
    const uint8_t *request, size_t request_size,
    DarwinSKSUnwrapFileKeyRequest *parsed);

typedef struct DarwinSKSCheckClassRequest {
    uint32_t header_body_size;
    uint32_t ipc_version;
    uint32_t variant;
    uint32_t protection_class;
    bool echo_class;
} DarwinSKSCheckClassRequest;

bool darwin_sks_parse_check_class_request(const uint8_t *request,
                                         size_t request_size,
                                         DarwinSKSCheckClassRequest *parsed);

#endif
