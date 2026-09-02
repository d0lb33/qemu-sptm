#pragma once

#include "qemu/osdep.h"
#include "hw/core/sysbus.h"
#include "xnu/apple_dtree.h"

#define TYPE_DARWIN_ASC "darwin-asc"

// Personality hooks for a coprocessor emulated on top of the generic
// ASC mailbox + RTKit model (DCP, ANS, SMC, ...).
typedef struct DarwinASCOps {
    // IOP finished the RTKit boot handshake
    void (*started)(void *opaque);
    // AP started (flag=2) / stopped (flag=1) an endpoint
    void (*ep_start)(void *opaque, uint8_t ep, uint32_t flag);
    // Message from the AP on a non-management endpoint. Return true if handled.
    bool (*handle)(void *opaque, uint8_t ep, uint64_t msg);
} DarwinASCOps;

// Create an ASC wrapper + mailbox + RTKit coprocessor for a device tree node
// (eg. /arm-io/dcp). reg[0] is mapped at iobase; the node's 4 "interrupts"
// (a2i empty, a2i not-empty, i2a empty, i2a not-empty) are wired to the AIC.
// eps lists the endpoints (beyond the standard system ones) the firmware
// advertises during the endpoint map handshake.
DeviceState *darwin_asc_create(struct dtree_node *node, uint64_t iobase, DeviceState *aic,
                               const uint8_t *eps, int n_eps,
                               const DarwinASCOps *ops, void *opaque);

// Send a message from the IOP to the AP on an endpoint.
void darwin_asc_send(DeviceState *dev, uint8_t ep, uint64_t msg);

// Instantiate a bare ASC + RTKit coprocessor for every /arm-io node that is
// still marked compatible "iop,ascwrap-v*" and has not already been claimed by
// a personality (pass those names in `claimed`). Coprocessors created this way
// speak the RTKit management protocol and log everything above it, which is
// enough for XNU's RTBuddy to attach and start them.
void darwin_ascs_create(struct dtree_node *dt_root, uint64_t iobase, DeviceState *aic,
                        const char *const *claimed, int n_claimed);

const char *darwin_asc_role(DeviceState *dev);
