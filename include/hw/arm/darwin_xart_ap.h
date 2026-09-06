#ifndef HW_ARM_DARWIN_XART_AP_H
#define HW_ARM_DARWIN_XART_AP_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* T8140 AppleMobileApNonce enumerates slots 0 and 1. State 0 is empty,
 * state 1 proposed, state 2 RL, state 3 L. See 9176f50,9176d04/9176d08.
 * The booted slot is selected by comparing its 48-byte commit hash with
 * /chosen/sidp-rom-manifest-hash at9176fbc, not by hashing the nonce.
 */
typedef struct DarwinXARTAP {
    uint8_t payload[2][56];
    uint8_t state[2];
} DarwinXARTAP;

void darwin_xart_ap_init(DarwinXARTAP *s, const uint8_t nonce[8],
                          const uint8_t manifest[48]);
/* Strict native endpoint16 request frame; byte1 tag varies, byte6 is slot. */
bool darwin_xart_ap_request(uint64_t message, uint8_t *op, uint8_t *slot);
/* No changes unless the requested lifecycle transition is supported.
 * 15 generates a proposed nonce; 19 deletes; 1a promotes an RL slot.
 * The random nonce is supplied by the device's RNG for opcode15 only.
 * The firmware commit-to-RL transition is not implemented here.
 */
bool darwin_xart_ap_change(DarwinXARTAP *s, uint8_t op, uint8_t slot,
                            const uint8_t nonce[8]);
#endif
