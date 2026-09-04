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

bool darwin_sks_parse_migrate_request(const uint8_t *request,
                                      size_t request_size,
                                      DarwinSKSMigrateRequest *parsed);

#endif
