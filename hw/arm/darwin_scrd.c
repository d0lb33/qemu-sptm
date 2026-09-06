/* SCRD framing shared with capture-replay tests.
 * APP_SCAN_COCOA_BASE1/scrd24-request.bin (40 bytes): header v1/0x1c,
 * command word 0x02000024, SUID at +12, repeated at +36.
 * Command selection and 21-byte response: AppleSEPCredentialManager
 * 0xfffffff00952d270..0xfffffff00952d2ac (24A5430a).
 * This parser deliberately accepts only the captured request family.
 */
#include "qemu/osdep.h"
#include "qemu/bswap.h"
#include "hw/arm/darwin_scrd.h"

bool darwin_scrd_parse_create(const uint8_t *r, size_t size, uint32_t *owner)
{
    if (size != 40 || lduw_le_p(r) != 1 || lduw_le_p(r + 2) != 28 ||
        ldl_le_p(r + 8) || ldq_le_p(r + 16) || ldl_le_p(r + 24) ||
        memcmp(r + 28, "DRCS", 4) || ldl_le_p(r + 32) != 0x02000024 ||
        ldl_le_p(r + 12) != ldl_le_p(r + 36)) {
        return false;
    }
    *owner = ldl_le_p(r + 12);
    return true;
}

/* Captured command 0x13 body is header + command word + 16-byte token.
 * LocalAuthenticationCore 0x206394720..0x206394758 sends this token with
 * no output and, on success, passes the same 16 bytes to its export block.
 */
bool darwin_scrd_parse_handle(const uint8_t *r, size_t size, uint8_t command,
                             uint32_t *owner, const uint8_t **handle)
{
    if ((command != 0x13 && command != 0x02) || size != 52 || lduw_le_p(r) != 1 ||
        lduw_le_p(r + 2) != 28 || ldl_le_p(r + 8) ||
        ldq_le_p(r + 16) || ldl_le_p(r + 24) ||
        memcmp(r + 28, "DRCS", 4) ||
        ldl_le_p(r + 32) != (0x02000000u | command)) {
        return false;
    }
    *owner = ldl_le_p(r + 12);
    *handle = r + 36;
    return true;
}

/* Empty data-type 5 reset from APP_SPLASH_TRACE1/scrd28.bin. ModuleACM
 * 24A5430a UUID 4DB51F53-FDEA-31A7-8958-C9A00E9F4C59 at 0xdd30..0xdd40,
 * 0xe0a8..0xe0d8 passes nil to setData:type:encoded:error:. Serializer
 * AppleSEPCredentialManager 0x95092ac..0x95092e0 writes token, type, length,
 * then parameters. Accept neither nonempty data nor other parameter values.
 */
bool darwin_scrd_parse_empty_data(const uint8_t *r, size_t size,
                                 uint32_t *owner, const uint8_t **handle)
{
    if (size != 73 || lduw_le_p(r) != 1 || lduw_le_p(r + 2) != 28 ||
        ldl_le_p(r + 8) || ldq_le_p(r + 16) || ldl_le_p(r + 24) ||
        memcmp(r + 28, "DRCS", 4) || ldl_le_p(r + 32) != 0x02000028 ||
        ldl_le_p(r + 52) != 5 || ldl_le_p(r + 56) != 0 ||
        ldl_le_p(r + 60) != 1 || ldl_le_p(r + 64) != 14 ||
        ldl_le_p(r + 68) != 1 || r[72] != 0) {
        return false;
    }
    *owner = ldl_le_p(r + 12);
    *handle = r + 36;
    return true;
}

/* Diagnostic error replies must not turn arbitrary requests into successes.
 * Seed query: serializer 0x950976c..0x9509794, LAC 0x2063a7cf4/cf8 checks
 * status before reading the returned length. Ratchet query: LAC
 * 0x20628a9ac..a9b8 constructs {1,2,0}; aa50..aaac handles errors.
 * Both captured requests use header v1/28 with no request flags/parameters.
 */
bool darwin_scrd_can_report_unsupported(const uint8_t *r, size_t size)
{
    if ((size != 61 && size != 72) || lduw_le_p(r) != 1 ||
        lduw_le_p(r + 2) != 28 || ldl_le_p(r + 8) ||
        ldq_le_p(r + 16) || ldl_le_p(r + 24) ||
        memcmp(r + 28, "DRCS", 4)) {
        return false;
    }
    if (size == 61) {
        return ldl_le_p(r + 32) == 0x02000029 &&
               ldl_le_p(r + 52) == 13 && r[56] == 1 &&
               ldl_le_p(r + 57) == 0;
    }
    return ldl_le_p(r + 32) == 0x02000033 &&
           ldq_le_p(r + 36) == 0 && ldq_le_p(r + 44) == 0 &&
           ldl_le_p(r + 52) == 0 && ldl_le_p(r + 56) == 12 &&
           ldl_le_p(r + 60) == 1 && ldl_le_p(r + 64) == 2 &&
           ldl_le_p(r + 68) == 0;
}
