/*
 * darwin-dcp: Display Coprocessor personality on top of darwin-asc
 *
 * On A14+/M1+ the display is driven entirely by the DCP firmware; the AP's
 * AppleDCP / AppleMobileDisp / IOMobileGraphicsFamily-DCP stack talks to it
 * over RTKit endpoints 0x20-0x2a ("iomfb", "dcpexpert", "dptx", "dcpav", ...)
 * using the "EPIC" RPC framing.
 *
 * This first stage brings the coprocessor up to the point where XNU's
 * RTBuddy has completed the RTKit handshake and started endpoints, and logs
 * every endpoint message so the protocol the iOS release actually speaks can
 * be captured and implemented incrementally.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "xnu/darwin_asc.h"
#include "xnu/darwin_dcp.h"

typedef struct DarwinDCP {
    DeviceState *asc;
    uint64_t msgs;
} DarwinDCP;

// Endpoints advertised by DCP firmware (m1n1 fw/dcp): iomfb 0x20, dcpexpert 0x21,
// disp0/dptx 0x22, dcpav 0x23/0x24, dcpav-controller 0x25, dcpdp 0x26, av-controller 0x27,
// av-power 0x28, hdcp 0x29, dcpextlink 0x2a
static const uint8_t dcp_eps[] = { 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a };

static void dcp_started(void *opaque) {
    fprintf(stderr, "dcp: coprocessor booted\n");
}

static void dcp_ep_start(void *opaque, uint8_t ep, uint32_t flag) {
}

static bool dcp_handle(void *opaque, uint8_t ep, uint64_t msg) {
    DarwinDCP *d = opaque;
    d->msgs++;
    // Every DCP endpoint message is 64 bits: type in the top byte(s) with
    // shared-memory context. Log the raw message for now.
    fprintf(stderr, "dcp: AP -> ep 0x%02x msg 0x%016" PRIx64 " (type 0x%02x)\n", ep, msg, (unsigned)(msg >> 48));
    return true;
}

static const DarwinASCOps dcp_ops = {
    .started = dcp_started,
    .ep_start = dcp_ep_start,
    .handle = dcp_handle,
};

DeviceState *darwin_dcp_create(struct dtree_node *dt_root, uint64_t iobase, DeviceState *aic) {
    struct dtree_node *dcp = adt_find_node(dt_root, "arm-io/dcp");
    if (!dcp || !adt_get_prop_val(dcp, "compatible")) {
        return NULL;
    }
    DarwinDCP *d = g_new0(DarwinDCP, 1);
    d->asc = darwin_asc_create(dcp, iobase, aic, dcp_eps, ARRAY_SIZE(dcp_eps), &dcp_ops, d);
    return d->asc;
}
