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
 * What works today: the RTKit handshake (darwin_asc.c), the AFK transport
 * handshake for every 0x20..0x2a endpoint (darwin_afk.c), and one EPIC
 * REPORT/PUBLISH per endpoint announcing a service by name (darwin_epic.c),
 * which is what XNU's sub-driver personalities match on -- every one of them
 * is `IOProviderClass = AFKEndpointInterface` plus
 * `IOPropertyMatch = { EPICName: ... }` in the kernelcache's
 * __PRELINK_INFO. What does not: any command/response traffic *after* a
 * driver binds. Commands the AP sends us are decoded and logged, and
 * deliberately not answered -- see dcp_afk_recv().
 *
 * WHAT TO ANNOUNCE is policy, and it lives here rather than in darwin_epic.c.
 * The service list below is the "confirmed both sides" table from
 * docs/re/dcp-firmware-services.md: each name appears both as an `-epic`
 * string in the real t8140 DCP firmware and as an `EPICName` IOPropertyMatch
 * in this kernelcache, so XNU really will try to bind the named class.
 *
 * Which endpoint carries which service is *not* known for t8140 -- the
 * endpoint-to-service correlation in docs/re/afk-epic-references.md sec. 4 is
 * M1-era and explicitly unconfirmed. It should not matter: matching keys on
 * the announced properties, not on the endpoint number. The default is
 * therefore one service on one endpoint, overridable without a rebuild:
 *
 *   DARWIN_DCP_EPIC=off                   announce nothing (pre-EPIC behaviour)
 *   DARWIN_DCP_EPIC=all                   announce every service in dcp_services[]
 *   DARWIN_DCP_EPIC=dcpav-device-epic     announce just that one
 *   DARWIN_DCP_EPIC_EP=0x22               ...on this endpoint (default 0x20)
 *   DARWIN_DCP_EPIC_OPTIONS=0             packet header options byte
 *
 * Tracing: DARWIN_ASC_DEBUG=1 for the mailbox, DARWIN_AFK_DEBUG=1 for the
 * ring transport, DARWIN_DART_DEBUG=1 for the IOMMU underneath it. The
 * announce itself always logs one line per service (prefix "dcp:", which is
 * what tools/probe.sh filters device-model traces on).
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "xnu/darwin_asc.h"
#include "xnu/darwin_afk.h"
#include "xnu/darwin_dart.h"
#include "xnu/darwin_dcp.h"
#include "xnu/darwin_epic.h"

/*
 * One announceable EPIC service. `epic_name` is the match key; `provider` is
 * the IOClass the kernelcache pairs it with -- we publish it as
 * `EPICProviderClass` because the real firmware's string table keeps
 * EPICName/EPICProviderClass/EPICUnit adjacent (dcpfw+0x3f6ef6..0x3f6f15) even
 * though this kernelcache never matches on it.
 */
typedef struct {
    const char *epic_name;
    const char *provider;
} DCPService;

/* docs/re/dcp-firmware-services.md, "Confirmed both sides" table. */
static const DCPService dcp_services[] = {
    { "dcpav-controller-epic",       "DCPAVControllerProxy" },
    { "dcpav-device-epic",           "DCPAVDeviceProxy" },
    { "dcpav-service-epic",          "DCPAVServiceProxy" },
    { "dcpav-video-interface-epic",  "DCPAVVideoInterfaceProxy" },
    { "dcpav-power-epic",            "DCPAVPowerControllerProxy" },
    { "dcpav-audio-interface-epic",  "DCPAVAudioInterfaceProxy" },
    { "dcpav-cec-interface-epic",    "DCPAVCECInterfaceProxy" },
    { "dcpav-sac-epic",              "DCPAVRemoteSACControllerProxy" },
    { "dcpdp-controller-epic",       "DCPDPControllerProxy" },
    { "dcpdp-device-epic",           "DCPDPDeviceProxy" },
    { "dcpdp-service-epic",          "DCPDPServiceProxy" },
    { "dcpdptx-port-epic",           "AppleDCPDPTXRemotePortProxy" },
    { "dcp-lpdptx-port-epic",        "AppleDCPLPDPTXPortProxy" },
    { "dcpdptx-hdcp-interface",      "AppleDCPDPTXRemoteHDCPInterfaceProxy" },
    { "dcpdptx-hdcp-auth-session",   "AppleDCPDPTXRemoteHDCPAuthSessionProxy" },
    { "dcpmipi-controller-epic",     "DCPMIPIControllerProxy" },
};

typedef struct DarwinDCP {
    DeviceState *asc;
    DarwinAFK *afk;
    uint64_t msgs;

    /* announce policy, resolved once at create time */
    bool announce;          /* DARWIN_DCP_EPIC != "off" */
    bool announce_all;      /* DARWIN_DCP_EPIC == "all" */
    const char *only;       /* a single EPICName, or NULL */
    uint8_t announce_ep;    /* which endpoint to announce on */
    uint8_t options;        /* EPIC packet header options byte */
    uint16_t next_iface;    /* firmware-chosen interface ids, 1-based */
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

/*
 * Announce one service on `ep` as an EPIC REPORT/PUBLISH.
 *
 * The property dictionary is what XNU turns into the nub's property table
 * (0xfffffff008b7bd5c onwards), so it has to carry everything anyone matches
 * on or reads:
 *
 *   EPICName           the IOPropertyMatch key of every DCP sub-driver
 *                      personality in this kernelcache
 *   EPICProviderClass  the class the firmware pairs with that name
 *   EPICUnit           instance index; 0 for the single-instance services
 *   name               read back explicitly at 0xfffffff008b7bdf0
 *   interface-name     read back at 0xfffffff008b7be3c and used to setName()
 *                      the nub, so it is also what an IONameMatch personality
 *                      would see
 *
 * The AP adds "interface-id" itself from the message header, so we must not.
 */
static bool dcp_announce(DarwinDCP *d, uint8_t ep, const DCPService *svc) {
    const DarwinEpicProp props[] = {
        { .key = "EPICName",          .str = svc->epic_name },
        { .key = "EPICProviderClass", .str = svc->provider },
        { .key = "EPICUnit",          .num = 0, .bits = 64 },
        /*
         * Required, and its absence is what kept every DCPAV*Proxy from
         * starting. They all share DCPAVProxy::start (0xfffffff009b03e40),
         * which checks, in order: OSDynamicCast(AFKEndpointInterface,
         * provider), getWorkLoop(), IOService::start, then
         *
         *   provider->getProperty("EPICLocation") must be an OSString
         *   (0xfffffff009b04088-0xfffffff009b040ac)
         *
         * before EPICUnit. Without it the proxy fails out with
         * "DCPAVRemoteSACControllerProxy failed to start".
         *
         * The value is compared against "External"; IOAVFamily
         * (0xfffffff009db7868) maps it to an "External"/"Embedded" Location
         * property, and the DCP firmware's own string table carries exactly
         * those two next to the EPIC* keys (dcpfw+0x3f65d5, +0x3f65de).
         * "Embedded" is the built-in panel, which is what we are.
         */
        { .key = "EPICLocation",      .str = "Embedded" },
        { .key = "name",              .str = svc->epic_name },
        { .key = "interface-name",    .str = svc->epic_name },
    };
    size_t plen = 0;
    g_autofree uint8_t *blob = darwin_epic_serialize_props(props, ARRAY_SIZE(props), &plen);

    uint16_t iface = d->next_iface++;
    size_t flen = 0;
    g_autofree uint8_t *frame =
        darwin_epic_build_publish(iface, svc->epic_name, blob, plen, d->options, &flen);

    /*
     * afk_qe.channel and afk_qe.type are 0: iOS 27's AP writes 0 in both and
     * its ring drain never reads either back (it reads only magic and size,
     * 0xfffffff008b94a7c / 0xfffffff008b9492c). The EPIC message header inside
     * the payload is what carries the multiplexing.
     */
    bool ok = darwin_afk_send_qe(d->afk, ep, 0, 0, frame, (uint32_t)flen, false);
    fprintf(stderr, "dcp: ep 0x%02x announce EPICName=%s provider=%s iface-id %u "
            "frame 0x%zx bytes (props 0x%zx) -> %s\n",
            ep, svc->epic_name, svc->provider, iface, flen, plen,
            ok ? "queued" : "FAILED (ring full, or DMA unreachable)");

    // The exact bytes matter and are awkward to reconstruct from a panic, so
    // dump them when the transport is already being traced.
    if (getenv("DARWIN_AFK_DEBUG")) {
        g_autoptr(GString) s = g_string_new(NULL);
        for (size_t i = 0; i < flen; i++) {
            g_string_append_printf(s, "%s%02x", (i && !(i & 15)) ? "\n dcp:   " : " ", frame[i]);
        }
        fprintf(stderr, "dcp:   %s\n", s->str);
    }
    return ok;
}

static void dcp_afk_started(void *opaque, uint8_t ep) {
    DarwinDCP *d = opaque;

    if (!d->announce) {
        fprintf(stderr, "dcp: AFK endpoint 0x%02x is up; announcing nothing "
                "(DARWIN_DCP_EPIC=off)\n", ep);
        return;
    }
    if (ep != d->announce_ep) {
        return;
    }
    bool any = false;
    for (size_t i = 0; i < ARRAY_SIZE(dcp_services); i++) {
        if (d->only && strcmp(d->only, dcp_services[i].epic_name)) {
            continue;
        }
        if (!dcp_announce(d, ep, &dcp_services[i])) {
            return;
        }
        any = true;
        if (!d->announce_all && !d->only) {
            break;      /* default: the first service only */
        }
    }
    /*
     * A name that is not in the confirmed table is announced verbatim. This is
     * how you aim at a driver that matches on something other than EPICName --
     * notably AppleFirmwareKit's own AFKEchoTestEPIC, whose personality is
     * `IONameMatch = ["ap_echo-test"]` on AFKEndpointInterface, and which sends
     * traffic of its own accord, so it is the cheapest way to prove that a
     * driver really bound rather than merely that a nub appeared.
     */
    if (!any && d->only) {
        DCPService synth = { d->only, d->only };
        any = dcp_announce(d, ep, &synth);
    }
    /*
     * One RBEP_RECV for the whole burst. RECV carries the new wptr and the AP
     * drains until rptr == wptr, so a single notify covers every entry -- and
     * one notify per entry overruns darwin_asc.c's inbound FIFO (16 announces
     * produced "asc(DCP): i2a fifo overflow, dropping ep 32", the dropped
     * message being the last and therefore the one that mattered; the guest
     * then stalled with the whole burst unread).
     */
    if (any) {
        darwin_afk_notify(d->afk, ep);
    }
}

/*
 * Diagnostic decode only: darwin_epic_describe() knows the iOS 27 header
 * shapes (8-byte message header + 16-byte packet header, see darwin_epic.c).
 * We print what the guest sent and do not reply -- answering a command
 * without knowing its group/command numbers would be a guess, and a wrong
 * reply is harder to debug than no reply. A driver that binds and then waits
 * here is the expected next stall, and this line is where you see it.
 */
static void dcp_afk_recv(void *opaque, uint8_t ep, uint32_t channel, uint32_t type,
                         const uint8_t *data, uint32_t len) {
    g_autofree char *desc = darwin_epic_describe(data, len);
    fprintf(stderr, "dcp: UNANSWERED EPIC frame ep 0x%02x qe(chan %u type %u len 0x%x): %s\n",
            ep, channel, type, len, desc);
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

    /*
     * Announce policy. Defaults: one service, the first of the confirmed
     * list, on endpoint 0x20 -- the smallest thing that can prove the framing
     * end to end. options=1 because that is the value the AP itself puts in
     * every report it sends (0xfffffff008b8fcbc, 0xfffffff008b8fe58); no
     * report path we traced reads it back, so it is the least-surprising
     * choice rather than a modelled behaviour.
     */
    const char *env = getenv("DARWIN_DCP_EPIC");
    d->announce = !(env && !strcmp(env, "off"));
    d->announce_all = env && !strcmp(env, "all");
    if (env && strcmp(env, "off") && strcmp(env, "all")) {
        d->only = env;
    }
    d->announce_ep = 0x20;
    if ((env = getenv("DARWIN_DCP_EPIC_EP"))) {
        d->announce_ep = (uint8_t)strtoul(env, NULL, 0);
    }
    d->options = 1;
    if ((env = getenv("DARWIN_DCP_EPIC_OPTIONS"))) {
        d->options = (uint8_t)strtoul(env, NULL, 0);
    }
    d->next_iface = 1;

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

    if (!d->announce) {
        fprintf(stderr, "dcp: EPIC announces disabled (DARWIN_DCP_EPIC=off)\n");
    } else {
        fprintf(stderr, "dcp: will announce %s on ep 0x%02x (options 0x%02x)\n",
                d->announce_all ? "every confirmed service" :
                d->only ? d->only : dcp_services[0].epic_name,
                d->announce_ep, d->options);
    }
    return d->asc;
}
