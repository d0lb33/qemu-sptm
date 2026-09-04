/* AFK StateTask messages, separate from the longer EPIC service frames. */
#pragma once

#include "qemu/bswap.h"

#define DARWIN_AFK_STATE_SIZE 12

/*
 * iOS 27 b8 StateTask receiver: 0xfffffff008b9267c..0xfffffff008b92804.
 * 2/4 are peer open/close requests; 3/5 acknowledge those requests. Echoing
 * 2 installs a peer open claim and blocks a later local close. Preserve the
 * request's sequence and framing; never originate a peer state transition.
 * See docs/re/dcp-state-acknowledgements.md in the parent project.
 */
static inline bool darwin_afk_build_state_ack(uint32_t channel, uint32_t type,
                                            const uint8_t *data, uint32_t len,
                                            uint8_t reply[DARWIN_AFK_STATE_SIZE])
{
    uint32_t state;

    if (channel != 0 || type != 0 || len != DARWIN_AFK_STATE_SIZE ||
        lduw_le_p(data + 2) != 0 || ldl_le_p(data + 4) != 4) {
        return false;
    }
    state = ldl_le_p(data + 8);
    if (state != 2 && state != 4) {
        return false;
    }
    memcpy(reply, data, DARWIN_AFK_STATE_SIZE);
    stl_le_p(reply + 8, state + 1);
    return true;
}
