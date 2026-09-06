#include "qemu/osdep.h"
#include "hw/arm/darwin_xart_ap.h"

void darwin_xart_ap_init(DarwinXARTAP *s, const uint8_t nonce[8],
                          const uint8_t manifest[48])
{
    memset(s, 0, sizeof(*s));
    memcpy(s->payload[0], nonce, 8);
    memcpy(s->payload[0] + 8, manifest, 48);
    /* Model the already booted image as the promoted slot. Slot assignment
     * is virtual; the identifying nonce/hash are the supplied boot values.
     * No Apple authentication or new commit hash is synthesized. */
    s->state[0] = 3;
}

bool darwin_xart_ap_request(uint64_t m, uint8_t *op, uint8_t *slot)
{
    if ((m & UINT64_C(0xff00ffffff0000ff)) != 16 || (m >> 48 & 255) > 1) {
        return false;
    }
    uint8_t code = m >> 16;
    if (code != 0x15 && code != 0x18 && code != 0x19 && code != 0x1a) {
        return false;
    }
    *op = code;
    *slot = m >> 48;
    return true;
}

bool darwin_xart_ap_change(DarwinXARTAP *s, uint8_t op, uint8_t slot,
                            const uint8_t nonce[8])
{
    if (slot > 1) {
        return false;
    }
    switch (op) {
    case 0x15:
        if (s->state[slot] || !nonce) {
            return false;
        }
        memset(s->payload[slot], 0, 56);
        memcpy(s->payload[slot], nonce, 8);
        s->state[slot] = 1;
        return true;
    case 0x19:
        memset(s->payload[slot], 0, 56);
        s->state[slot] = 0;
        return true;
    case 0x1a:
        if (s->state[slot] != 2) {
            return false;
        }
        s->state[slot] = 3;
        return true;
    default:
        return false;
    }
}
