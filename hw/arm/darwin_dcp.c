/*
 * darwin-dcp: Display Coprocessor personality on top of darwin-asc
 *
 * On A14+/M1+ the display is driven entirely by the DCP firmware; the AP's
 * AppleDCP / IOMobileFramebuffer / AppleCLCD2 stack talks to it over RTKit
 * endpoints. This file is the DCP-shaped glue: it decides which endpoints
 * exist and which protocol runs on each, and owns nothing else.
 *
 * Endpoint map (docs/re/dcp-bringup.md, from the iOS 27 kernelcache's
 * IOKitPersonalities; confirmed live by the RTKit endpoint-start trace):
 *
 *   0x20 .. 0x2a   DCPEndpoint1..11   AppleDCPEndpointV2 -- AFK ring
 *                                     transport with EPIC framing on top.
 *                                     Handled here by darwin_afk.c.
 *   0x37           DCPEndpoint24      AppleDCPLinkServiceSoC -- IOMFB, a
 *                                     different RPC framing that rides
 *                                     directly on RTKit, *not* AFK. Not
 *                                     advertised yet, so XNU never starts it.
 *
 * What works today: the RTKit handshake (darwin_asc.c) and the AFK transport
 * handshake for every 0x20..0x2a endpoint, up to and including START_ACK,
 * with both rings live in guest memory reached through dart-dcp's stream 23.
 * What does not: the EPIC framing inside the ring entries, and therefore the
 * service announces (`dcpav-*`, `dcpdptx-*`) XNU's sub-drivers match on. Any
 * ring entry the AP sends us is logged with its EPIC header decoded, and
 * nothing else -- see dcp_afk_recv().
 *
 * Tracing: DARWIN_ASC_DEBUG=1 for the mailbox, DARWIN_AFK_DEBUG=1 for the
 * ring transport, DARWIN_DART_DEBUG=1 for the IOMMU underneath it.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "xnu/darwin_asc.h"
#include "xnu/darwin_afk.h"
#include "xnu/darwin_dart.h"
#include "xnu/darwin_dcp.h"

typedef struct DarwinDCP {
    DeviceState *asc;
    DarwinAFK *afk;
    uint64_t msgs;
} DarwinDCP;

/*
 * Endpoints the firmware advertises in the RTKit endpoint map. 0x20..0x2a is
 * what the iOS 27 kernelcache calls DCPEndpoint1..11; XNU issues a START_EP
 * for every one of them and then an AFK INIT on each, which is exactly what
 * the trace shows. 0x37 (IOMFB) is deliberately absent: nothing models that
 * protocol yet, and advertising an endpoint we cannot answer only moves the
 * stall somewhere harder to read.
 */
static const uint8_t dcp_eps[] = {
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a
};

static void dcp_started(void *opaque) {
    fprintf(stderr, "dcp: coprocessor booted\n");
}

static void dcp_ep_start(void *opaque, uint8_t ep, uint32_t flag) {
    DarwinDCP *d = opaque;
    // darwin_asc_create() runs before darwin_afk_new(), so tolerate a
    // callback arriving during ASC realize.
    if (d->afk) darwin_afk_ep_start(d->afk, ep, flag);
}

static bool dcp_handle(void *opaque, uint8_t ep, uint64_t msg) {
    DarwinDCP *d = opaque;
    d->msgs++;
    if (d->afk && darwin_afk_owns_endpoint(d->afk, ep)) {
        return darwin_afk_handle(d->afk, ep, msg);
    }
    // Endpoints we advertise but do not speak (and the RTKit system
    // endpoints darwin_asc.c does not consume). Log, never fault.
    fprintf(stderr, "dcp: AP -> ep 0x%02x msg 0x%016" PRIx64 " (type 0x%02x, no protocol modelled)\n",
            ep, msg, (unsigned)(msg >> 48));
    return true;
}

static void dcp_afk_started(void *opaque, uint8_t ep) {
    /*
     * The AFK transport for this endpoint is live. Real firmware would now
     * announce its services here with EPIC REPORT/ANNOUNCE frames
     * (docs/re/afk-epic-references.md §3 step 11, service names in
     * docs/re/dcp-firmware-services.md). That is the next task; we
     * deliberately announce nothing rather than guess at a payload.
     */
    fprintf(stderr, "dcp: AFK endpoint 0x%02x is up; no EPIC services announced "
            "(EPIC layer not implemented)\n", ep);
}

/*
 * Diagnostic decode only. The two EPIC headers are documented at
 * linux-asahi drivers/gpu/drm/apple/afk.h:93-110:
 *   epic_hdr      (16 bytes) version:u8, seq:u16, pad:u8, unk:u32, ts:u64
 *   epic_sub_hdr  (24 bytes) length:u32, version:u8, category:u8, type:u16,
 *                            ts:u64, tag:u16, unk:u16, inline_len:u32
 * We print them so the next person can see what the guest sent; we do not
 * act on them, and we do not reply.
 */
static void dcp_afk_recv(void *opaque, uint8_t ep, uint32_t channel, uint32_t type,
                         const uint8_t *data, uint32_t len) {
    if (len >= 40) {
        const uint8_t *sh = data + 16;
        uint8_t ehdr_ver = data[0];
        uint16_t seq = data[1] | (data[2] << 8);
        uint32_t slen = sh[0] | (sh[1] << 8) | (sh[2] << 16) | ((uint32_t)sh[3] << 24);
        uint8_t sver = sh[4], scat = sh[5];
        uint16_t stype = sh[6] | (sh[7] << 8);
        uint16_t tag = sh[16] | (sh[17] << 8);
        fprintf(stderr, "dcp: UNHANDLED EPIC frame ep 0x%02x chan %u type %u len 0x%x "
                "[epic v%u seq %u | sub v%u cat 0x%02x subtype 0x%04x tag 0x%04x plen 0x%x]\n",
                ep, channel, type, len, ehdr_ver, seq, sver, scat, stype, tag, slen);
    } else {
        fprintf(stderr, "dcp: UNHANDLED EPIC frame ep 0x%02x chan %u type %u len 0x%x "
                "(too short for the two EPIC headers)\n", ep, channel, type, len);
    }
}

static const DarwinASCOps dcp_asc_ops = {
    .started = dcp_started,
    .ep_start = dcp_ep_start,
    .handle = dcp_handle,
};

static const DarwinAFKOps dcp_afk_ops = {
    .ep_started = dcp_afk_started,
    .recv = dcp_afk_recv,
};

DeviceState *darwin_dcp_create(struct dtree_node *dt_root, uint64_t iobase, DeviceState *aic) {
    struct dtree_node *dcp = adt_find_node(dt_root, "arm-io/dcp");
    if (!dcp || !adt_get_prop_val(dcp, "compatible")) {
        return NULL;
    }
    DarwinDCP *d = g_new0(DarwinDCP, 1);
    d->asc = darwin_asc_create(dcp, iobase, aic, dcp_eps, ARRAY_SIZE(dcp_eps), &dcp_asc_ops, d);

    /*
     * The AFK rings live in guest memory the DCP reaches through its own
     * DART. Which DART and which stream id is in the tree, not in this file:
     * /arm-io/dcp's "iommu-parent" phandle points at an iommu-mapper node
     * (/arm-io/dart-dcp/mapper-dcp on t8140) whose "reg" is the stream id.
     * Resolving it that way keeps this working if a future SoC renumbers.
     */
    struct dtree_node *dart_node = NULL;
    DeviceState *dart = NULL;
    unsigned sid = 0;
    if (darwin_afk_find_iommu(dt_root, dcp, &dart_node, &sid)) {
        const char *dart_name = adt_get_prop_val(dart_node, "name");
        dart = darwin_dart_find(dart_name);
        if (!dart) {
            fprintf(stderr, "dcp: device tree points at DART \"%s\" sid %u but no such "
                    "darwin-dart was created; AFK rings will be unreachable\n",
                    dart_name ? dart_name : "?", sid);
        } else {
            fprintf(stderr, "dcp: DMA through %s sid %u\n", dart_name, sid);
        }
    } else {
        fprintf(stderr, "dcp: no iommu-parent -> iommu-mapper chain in the device tree; "
                "AFK rings will be unreachable\n");
    }

    d->afk = darwin_afk_new(d->asc, adt_get_prop_val(dcp, "role"), dart, sid,
                            NULL, &dcp_afk_ops, d);
    for (size_t i = 0; i < ARRAY_SIZE(dcp_eps); i++) {
        darwin_afk_add_endpoint(d->afk, dcp_eps[i]);
    }
    return d->asc;
}
