#ifndef HW_ARM_DARWIN_SCRD_H
#define HW_ARM_DARWIN_SCRD_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
/* Exact observed tracked-context creation request. No credential is granted. */
bool darwin_scrd_parse_create(const uint8_t *request, size_t size,
                             uint32_t *owner);
bool darwin_scrd_parse_handle(const uint8_t *request, size_t size,
                             uint8_t command, uint32_t *owner,
                             const uint8_t **handle);
bool darwin_scrd_parse_empty_data(const uint8_t *request, size_t size,
                                 uint32_t *owner, const uint8_t **handle);
/* Only the captured encoding-seed length query and initial ratchet query. */
bool darwin_scrd_can_report_unsupported(const uint8_t *request, size_t size);
#endif
