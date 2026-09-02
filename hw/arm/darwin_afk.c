/*
 * darwin-afk: Apple "AFK" ring-buffer transport, firmware (IOP) side.
 *
 * AFK is the shared library Apple's coprocessors use to turn one RTKit
 * endpoint into a pair of DMA ring buffers, on top of which the EPIC message
 * framing (and then the actual services) live. The DCP brings up one AFK
 * instance per display endpoint (0x20..0x2a on t8140, "DCPEndpoint1".."11");
 * nothing above the mailbox works until this handshake completes.
 *
 * We play the *firmware* side: XNU's AppleDCPEndpointV2 is the real AP-side
 * driver on the other end.
 *
 *
 * PROTOCOL MAP -- one 64-bit RTKit message per operation, opcode in bits
 * [63:48] (`RBEP_TYPE`, linux-asahi drivers/gpu/drm/apple/afk.c:22).
 * BLOCK_SHIFT = 6 (afk.c:39): every size/offset below the low 16 bits is a
 * count of 0x40-byte blocks, not bytes.
 *
 *   op    name            dir      fields (bit ranges)      source
 *   0x80  INIT            AP->FW   -                        afk.c:25, sent at afk.c:107-108
 *   0xa0  INIT_ACK        FW->AP   -                        afk.c:26, consumed at afk.c:690
 *   0x89  GETBUF          FW->AP   SIZE 31:16, TAG 15:0     afk.c:27,41-42, handled afk.c:117-145
 *   0xa1  GETBUF_ACK      AP->FW   DVA 47:0                 afk.c:28,43, sent afk.c:142-144
 *   0x8a  INIT_TX         FW->AP   OFF 47:32, SIZE 31:16,   afk.c:29,45-47, handled afk.c:147-196
 *                                  TAG 15:0                 (designates the ring the AP writes)
 *   0x8b  INIT_RX         FW->AP   same                     afk.c:30 (the ring the AP reads)
 *   0xa3  START           AP->FW   -                        afk.c:31, sent afk.c:195-196
 *                                  (confirmed on iOS 27: the AP checks both ring
 *                                   flags at bootkc 0xfffffff008b94d90 and, if both
 *                                   are set, sends 0xa3 at 0xfffffff008b94cf0)
 *   0x86  START_ACK       FW->AP   -                        afk.c:32, completes afk_start() at afk.c:693
 *   0xa2  SEND            AP->FW   WPTR 31:0                afk.c:33,49, sent afk.c:878-879
 *   0x85  RECV            FW->AP   WPTR 31:0                afk.c:34, drained afk.c:713-716
 *   0xc0  SHUTDOWN        AP->FW   -                        afk.c:35, sent afk.c:89-91
 *   0xc1  SHUTDOWN_ACK    FW->AP   -                        afk.c:36, consumed afk.c:697
 *
 * The AP considers the endpoint live on START_ACK, not INIT_ACK
 * (afk_start()'s wait_for_completion is completed only by START_ACK,
 * afk.c:110-114 + 693-694). Direction is unambiguous because afk.c's
 * receive worker (afk.c:681-724) only ever sees FW->AP messages while
 * afk_send() (afk.c:51-54) only ever emits AP->FW ones.
 *
 * A caveat worth knowing: AppleFirmwareKit's messenger is *symmetric*. The
 * same kext contains a path (0xfffffff008b94048) where the AP allocates the
 * buffer itself and sends INIT_TX/INIT_RX, and the receive path we exercise
 * (0xfffffff008b94d20) where the firmware does. Which role an endpoint plays
 * is a construction-time choice, and for the DCP it is the receiving one --
 * i.e. the table above holds. Do not conclude from a stray `mov w1, #0x8a`
 * in that kext that the directions are reversed.
 *
 *
 * RING LAYOUT -- one `afk_ringbuffer_header` at the base of each ring
 * (linux-asahi afk.h:74-82), then `bufsz` bytes of payload:
 *
 *   +0*block  bufsz   payload bytes, excluding this header
 *   +1*block  rptr    reader's cursor, byte offset into the payload
 *   +2*block  wptr    writer's cursor, byte offset into the payload
 *   +3*block  payload
 *
 * The three fields are each in their own `block`-sized slot and the header is
 * three blocks. **The block size is 0x80 on iOS 27's DCP, not the 0x40 that
 * Linux hardcodes** (afk.h:74-82 asserts `bufsz + 0xc0 == size`). Evidence,
 * all from this build's kernelcache (`firmware/bootkc`, unslid addresses;
 * the boot that produced them had slide 0x20000000):
 *
 *  - AppleFirmwareKit's ring-init helper at 0xfffffff008b94120 takes the
 *    ring VA, the SIZE from the INIT_TX/INIT_RX message and a 3-byte
 *    "profile" whose first byte is the block size (stored to `this+0x28`,
 *    0xfffffff008b94154-0xfffffff008b94168).
 *  - At 0xfffffff008b941a0-0xfffffff008b941c4 it computes, in the compiler's
 *    roundabout way, `expected_bufsz = SIZE - 3 * block`.
 *  - At 0xfffffff008b94220-0xfffffff008b9424c it loads the u32 the firmware
 *    wrote at the ring base and, if it differs, calls an error handler that
 *    is the assert thunk at 0xfffffff008ba87a8:
 *        panic("false" @afk_messenger_common.c:126)
 *    We hit exactly that panic with a 0x40 block and stopped hitting it with
 *    0x80, which is also what makes the AP go on to send START.
 *  - The profile table lives in __TEXT.__const at 0xfffffff00740756f, right
 *    after the string "afklib": `40 40 00`, `80 80 00`, `40 40 00`. 0x40 is
 *    only the default used when the caller passes no profile
 *    (0xfffffff008b9414c-0xfffffff008b94158); the DCP's messenger is
 *    constructed with the 0x80 one. m1n1 saw the same thing on macOS-era
 *    firmware -- its worked example has bufsize 0x7e80 in a 0x8000 region,
 *    i.e. a 0x180 header (rbep.py:57-78) -- and derives the block size as
 *    (size - bufsz)/3 (rbep.py:85-98) rather than assuming it.
 *
 * DARWIN_AFK_BLOCK overrides it, which is how the 0x40-vs-0x80 question was
 * settled without a rebuild; keep that escape hatch for the next iOS.
 *
 * Note that this is *only* the ring's internal granule. The SIZE/OFFSET
 * fields of GETBUF/INIT_TX/INIT_RX are always in units of 0x40 regardless
 * (the AP does `>> 6` / `<< 6` on them: SIZE = (msg >> 10) & 0x3fffc0 and
 * OFFSET = (msg >> 26) & 0x3fffc0 at 0xfffffff008b94d3c-0xfffffff008b94d74),
 * so AFK_BLOCK_SHIFT and `block` are deliberately separate constants here.
 *
 * Queue entry, written at the writer's wptr (linux-asahi afk.h:84-91):
 *
 *   +0x00  magic    "IOP " == 0x20504f49 (per-coprocessor; AOP uses "AOP ")
 *   +0x04  size     bytes of payload following this 16-byte header
 *   +0x08  channel  EPIC channel number
 *   +0x0c  type     EPIC type (NOTIFY/COMMAND/REPLY/NOTIFY_ACK)
 *   +0x10  data[size]
 *
 * wptr/rptr always advance to a `block` boundary and wrap to 0 exactly at
 * bufsz (afk.c:658, 872-874). If an entry would not fit before the end of
 * the ring the writer leaves a bare 16-byte header at wptr and writes the
 * real entry at offset 0; the reader detects that with
 * `rptr + size + 16 > bufsz` (afk.c:626-645, mirrored at afk.c:795-829).
 *
 *
 * WHAT THIS FILE DOES NOT DO: the EPIC framing inside afk_qe.data, and the
 * DCP services above it. Received entries are handed to the personality's
 * `recv` callback and logged; nothing is generated on our own initiative.
 *
 * Tracing: DARWIN_AFK_DEBUG=1.
 * Full write-up with citations: docs/re/afk-epic-references.md -- but note
 * that its section 1.2 states the ring header is 0xc0 bytes, which is true of
 * Linux's driver and false of iOS 27's DCP (see the block-size discussion
 * above). Everything else in that document held up against the live guest.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "system/memory.h"
#include "system/address-spaces.h"
#include "exec/memattrs.h"
#include "xnu/apple_dtree.h"
#include "xnu/darwin_asc.h"
#include "xnu/darwin_dart.h"
#include "xnu/darwin_afk.h"

/* ---------------- protocol constants ---------------- */

#define AFK_TYPE_SHIFT      48
#define AFK_TYPE(m)         (((m) >> AFK_TYPE_SHIFT) & 0xffff)
#define AFK_MSG(t)          ((uint64_t)(t) << AFK_TYPE_SHIFT)

#define RBEP_INIT           0x80
#define RBEP_INIT_ACK       0xa0
#define RBEP_GETBUF         0x89
#define RBEP_GETBUF_ACK     0xa1
#define RBEP_INIT_TX        0x8a
#define RBEP_INIT_RX        0x8b
#define RBEP_START          0xa3
#define RBEP_START_ACK      0x86
#define RBEP_SEND           0xa2
#define RBEP_RECV           0x85
#define RBEP_SHUTDOWN       0xc0
#define RBEP_SHUTDOWN_ACK   0xc1

#define AFK_BLOCK_SHIFT     6

#define GETBUF_SIZE(v)      (((uint64_t)(v) & 0xffff) << 16)
#define GETBUF_TAG(v)       ((uint64_t)(v) & 0xffff)
#define GETBUF_ACK_DVA(m)   ((m) & 0xffffffffffffULL)
#define INITRB_OFFSET(v)    (((uint64_t)(v) & 0xffff) << 32)
#define INITRB_SIZE(v)      (((uint64_t)(v) & 0xffff) << 16)
#define INITRB_TAG(v)       ((uint64_t)(v) & 0xffff)
#define SEND_WPTR(m)        ((uint32_t)((m) & 0xffffffff))

#define AFK_QE_MAGIC        0x20504f49u     // "IOP "
#define AFK_QE_HDR_SIZE     16

// Ring header field offsets, in units of the ring's block size.
#define AFK_HDR_BUFSZ_BLOCK 0
#define AFK_HDR_RPTR_BLOCK  1
#define AFK_HDR_WPTR_BLOCK  2

// Defaults. 0x80 is the ring granule iOS 27's DCP messenger is built with;
// see the header comment for the kernelcache evidence and for why getting it
// wrong panics the guest rather than merely failing. The per-ring size is a
// *choice*: we are the allocator's peer, we ask for the buffer and we carve
// it up. 0x2000 per ring keeps the total GETBUF request at 0x100 blocks,
// which is also the value XNU puts in the low bits of its INIT message (see
// afk_handle_init) -- if that field ever turns out to be a cap we are
// already inside it.
#define AFK_DEF_BLOCK       0x80
#define AFK_DEF_HDR_BLOCKS  3
#define AFK_DEF_RING_SIZE   0x2000

#define AFK_MAX_EPS         256

/* ---------------- state ---------------- */

enum {
    AFK_EP_OFF = 0,     // no RTKit START_EP seen (or it was stopped)
    AFK_EP_IDLE,        // started by RTKit, waiting for the AP's INIT
    AFK_EP_GETBUF,      // GETBUF sent, waiting for GETBUF_ACK
    AFK_EP_INITRB,      // INIT_TX/INIT_RX sent, waiting for START
    AFK_EP_STARTED,     // START_ACK sent; rings live
};

typedef struct {
    uint32_t off;       // byte offset of this ring inside the shared buffer
    uint32_t size;      // total bytes, header included
    uint32_t bufsz;     // payload bytes (size - header)
} AFKRing;

typedef struct {
    uint8_t state;
    bool is_afk;        // declared with darwin_afk_add_endpoint()
    uint16_t tag;       // GETBUF correlation id, echoed in INIT_TX/INIT_RX
    uint64_t dva;       // buffer address the AP gave us, IOP-visible
    uint32_t buf_size;  // total bytes of that buffer
    AFKRing tx;         // the AP writes here, we read
    AFKRing rx;         // we write here, the AP reads
    uint32_t tx_rptr;   // our cursor into the AP's TX ring
    uint32_t rx_wptr;   // our cursor into the AP's RX ring
    uint64_t n_recv, n_sent;
    bool dma_warned;    // rate-limit the "translation failed" log
} AFKEndpoint;

struct DarwinAFK {
    DeviceState *asc;
    char *role;
    DeviceState *dart;
    unsigned sid;
    uint32_t block;
    uint32_t hdr_size;
    uint32_t ring_size;
    bool debug;
    const DarwinAFKOps *ops;
    void *opaque;
    AFKEndpoint eps[AFK_MAX_EPS];
};

static const char *afk_type_name(unsigned t) {
    switch (t) {
    case RBEP_INIT: return "INIT";
    case RBEP_INIT_ACK: return "INIT_ACK";
    case RBEP_GETBUF: return "GETBUF";
    case RBEP_GETBUF_ACK: return "GETBUF_ACK";
    case RBEP_INIT_TX: return "INIT_TX";
    case RBEP_INIT_RX: return "INIT_RX";
    case RBEP_START: return "START";
    case RBEP_START_ACK: return "START_ACK";
    case RBEP_SEND: return "SEND";
    case RBEP_RECV: return "RECV";
    case RBEP_SHUTDOWN: return "SHUTDOWN";
    case RBEP_SHUTDOWN_ACK: return "SHUTDOWN_ACK";
    default: return "?";
    }
}

static void afk_send(DarwinAFK *a, uint8_t ep, uint64_t msg) {
    if (a->debug) {
        fprintf(stderr, "afk(%s): ep 0x%02x FW -> AP %-12s 0x%016" PRIx64 "\n",
                a->role, ep, afk_type_name(AFK_TYPE(msg)), msg);
    }
    darwin_asc_send(a->asc, ep, msg);
}

/* ---------------- DMA through the IOP's DART ---------------- */

/*
 * Every ring access goes through the coprocessor's DART, exactly as the real
 * IOP's DMA would. We re-translate on every 4K boundary rather than assume
 * the DART's page size: darwin_dart_translate() maps a single address, and
 * 4K is a divisor of every Apple DART granule, so this is correct whatever
 * page-size the tree declares.
 *
 * A failure here is reported, never papered over: a wrong physical address
 * would silently corrupt guest memory, which is far worse than an endpoint
 * that does not come up.
 */
static bool afk_dma(DarwinAFK *a, AFKEndpoint *e, uint8_t ep, uint64_t dva,
                    void *buf, uint32_t len, bool is_write) {
    uint8_t *p = buf;

    if (!a->dart) {
        if (!e->dma_warned) {
            e->dma_warned = true;
            fprintf(stderr, "afk(%s): ep 0x%02x has no DART; cannot reach the ring at "
                    "dva 0x%" PRIx64 ". The endpoint will not start.\n", a->role, ep, dva);
        }
        return false;
    }

    while (len) {
        uint64_t pa;
        if (!darwin_dart_translate(a->dart, a->sid, dva, &pa)) {
            if (!e->dma_warned) {
                e->dma_warned = true;
                fprintf(stderr, "afk(%s): ep 0x%02x DART sid %u has no mapping for dva "
                        "0x%" PRIx64 " (%s). The endpoint will not start.\n",
                        a->role, ep, a->sid, dva, is_write ? "write" : "read");
                darwin_dart_dump_sid(a->dart, a->sid);
            }
            return false;
        }
        uint32_t chunk = 0x1000 - (uint32_t)(dva & 0xfff);
        if (chunk > len) chunk = len;
        if (address_space_rw(&address_space_memory, pa, MEMTXATTRS_UNSPECIFIED,
                             p, chunk, is_write) != MEMTX_OK) {
            fprintf(stderr, "afk(%s): ep 0x%02x guest memory access failed at pa 0x%" PRIx64 "\n",
                    a->role, ep, pa);
            return false;
        }
        dva += chunk;
        p += chunk;
        len -= chunk;
    }
    return true;
}

static bool afk_ring_read32(DarwinAFK *a, AFKEndpoint *e, uint8_t ep,
                            const AFKRing *r, unsigned block, uint32_t *out) {
    uint32_t v = 0;
    if (!afk_dma(a, e, ep, e->dva + r->off + (uint64_t)block * a->block, &v, 4, false)) {
        return false;
    }
    *out = le32_to_cpu(v);
    return true;
}

static bool afk_ring_write32(DarwinAFK *a, AFKEndpoint *e, uint8_t ep,
                             const AFKRing *r, unsigned block, uint32_t val) {
    uint32_t v = cpu_to_le32(val);
    return afk_dma(a, e, ep, e->dva + r->off + (uint64_t)block * a->block, &v, 4, true);
}

// Read/write inside a ring's payload area, wrapping at bufsz.
static bool afk_ring_payload(DarwinAFK *a, AFKEndpoint *e, uint8_t ep,
                             const AFKRing *r, uint32_t off, void *buf,
                             uint32_t len, bool is_write) {
    uint8_t *p = buf;
    while (len) {
        while (off >= r->bufsz) off -= r->bufsz;
        uint32_t chunk = r->bufsz - off;
        if (chunk > len) chunk = len;
        if (!afk_dma(a, e, ep, e->dva + r->off + a->hdr_size + off, p, chunk, is_write)) {
            return false;
        }
        off += chunk;
        p += chunk;
        len -= chunk;
    }
    return true;
}

/* ---------------- handshake ---------------- */

static void afk_ep_reset(DarwinAFK *a, AFKEndpoint *e) {
    bool is_afk = e->is_afk;
    memset(e, 0, sizeof(*e));
    e->is_afk = is_afk;
}

/*
 * Step 2-4 of the ordered handshake (docs/re/afk-epic-references.md §3):
 * ack the AP's INIT and immediately ask it for the DMA buffer that will hold
 * both rings.
 */
static void afk_handle_init(DarwinAFK *a, uint8_t ep, AFKEndpoint *e, uint64_t msg) {
    /*
     * Neither reference puts any field in INIT: Linux sends a bare
     * FIELD_PREP(RBEP_TYPE, RBEP_INIT) (afk.c:108) and m1n1 a bare
     * AFKEP_Init() (rbep.py:186-187). iOS 27's DCPEndpointV2 sends
     * 0x0080000000000100, i.e. 0x100 in the low bits. We do not know what
     * that field means, so we do not pretend to: it is logged and ignored,
     * and INIT_ACK goes back with no fields, matching both references. If a
     * future trace shows the AP checking an echoed value, this is the place.
     */
    uint64_t unknown = msg & 0xffffffffffffULL;
    if (unknown) {
        fprintf(stderr, "afk(%s): ep 0x%02x INIT carries unmodelled payload 0x%012" PRIx64
                " (ignored; both AP-side references send none)\n", a->role, ep, unknown);
    }

    afk_ep_reset(a, e);
    e->state = AFK_EP_GETBUF;
    // Any value: the AP echoes it back to us in INIT_TX/INIT_RX and checks
    // nothing else (afk.c:157-161). Make it recognisable in traces.
    e->tag = 0x1000 | ep;
    e->buf_size = a->ring_size * 2;

    afk_send(a, ep, AFK_MSG(RBEP_INIT_ACK));
    afk_send(a, ep, AFK_MSG(RBEP_GETBUF) |
                    GETBUF_SIZE(e->buf_size >> AFK_BLOCK_SHIFT) |
                    GETBUF_TAG(e->tag));
}

/*
 * Step 5-8: the AP allocated the buffer and told us its IOP-visible address.
 * Carve it into the AP's TX ring (low half) and RX ring (high half), write
 * each ring's header through the DART, then hand both to the AP. The AP
 * validates `bufsz + header == SIZE` against what we wrote
 * (afk.c:182-189), so the header writes have to land before the messages.
 */
static void afk_handle_getbuf_ack(DarwinAFK *a, uint8_t ep, AFKEndpoint *e, uint64_t msg) {
    if (e->state != AFK_EP_GETBUF) {
        fprintf(stderr, "afk(%s): ep 0x%02x unexpected GETBUF_ACK in state %u\n",
                a->role, ep, e->state);
        return;
    }
    e->dva = GETBUF_ACK_DVA(msg);

    e->tx.off = 0;
    e->tx.size = a->ring_size;
    e->tx.bufsz = a->ring_size - a->hdr_size;
    e->rx.off = a->ring_size;
    e->rx.size = a->ring_size;
    e->rx.bufsz = a->ring_size - a->hdr_size;

    if (a->debug) {
        fprintf(stderr, "afk(%s): ep 0x%02x buffer dva 0x%" PRIx64 " size 0x%x; "
                "tx +0x%x/0x%x rx +0x%x/0x%x (bufsz 0x%x each)\n", a->role, ep,
                e->dva, e->buf_size, e->tx.off, e->tx.size, e->rx.off, e->rx.size, e->tx.bufsz);
    }

    bool ok = true;
    const AFKRing *rings[2] = { &e->tx, &e->rx };
    for (int i = 0; i < 2 && ok; i++) {
        ok = afk_ring_write32(a, e, ep, rings[i], AFK_HDR_BUFSZ_BLOCK, rings[i]->bufsz) &&
             afk_ring_write32(a, e, ep, rings[i], AFK_HDR_RPTR_BLOCK, 0) &&
             afk_ring_write32(a, e, ep, rings[i], AFK_HDR_WPTR_BLOCK, 0);
    }
    if (!ok) {
        // afk_dma() already explained why. Do not send INIT_TX/INIT_RX: the
        // AP would read a garbage bufsz and log a misleading size mismatch.
        fprintf(stderr, "afk(%s): ep 0x%02x could not publish the ring headers; "
                "stopping the handshake here rather than lying to the AP\n", a->role, ep);
        e->state = AFK_EP_IDLE;
        return;
    }

    e->state = AFK_EP_INITRB;
    afk_send(a, ep, AFK_MSG(RBEP_INIT_TX) |
                    INITRB_OFFSET(e->tx.off >> AFK_BLOCK_SHIFT) |
                    INITRB_SIZE(e->tx.size >> AFK_BLOCK_SHIFT) |
                    INITRB_TAG(e->tag));
    afk_send(a, ep, AFK_MSG(RBEP_INIT_RX) |
                    INITRB_OFFSET(e->rx.off >> AFK_BLOCK_SHIFT) |
                    INITRB_SIZE(e->rx.size >> AFK_BLOCK_SHIFT) |
                    INITRB_TAG(e->tag));
}

/*
 * Drain the AP's TX ring up to the wptr it just told us about. Mirrors
 * afk_recv() (afk.c:586-679) with the roles swapped.
 */
static void afk_drain_tx(DarwinAFK *a, uint8_t ep, AFKEndpoint *e, uint32_t wptr) {
    if (wptr >= e->tx.bufsz) {
        fprintf(stderr, "afk(%s): ep 0x%02x SEND wptr 0x%x out of range (bufsz 0x%x)\n",
                a->role, ep, wptr, e->tx.bufsz);
        return;
    }

    // Bound the loop: one pass can never legitimately consume more entries
    // than the ring can hold.
    unsigned guard = e->tx.bufsz / AFK_QE_HDR_SIZE + 1;
    while (e->tx_rptr != wptr && guard--) {
        uint32_t hdr[4];
        if (!afk_ring_payload(a, e, ep, &e->tx, e->tx_rptr, hdr, sizeof(hdr), false)) return;
        uint32_t magic = le32_to_cpu(hdr[0]);
        uint32_t size = le32_to_cpu(hdr[1]);
        uint32_t channel = le32_to_cpu(hdr[2]);
        uint32_t type = le32_to_cpu(hdr[3]);

        // Wrap marker: a bare header whose payload does not fit before the
        // end of the ring means the real entry starts at offset 0.
        if (magic == AFK_QE_MAGIC && e->tx_rptr + size + AFK_QE_HDR_SIZE > e->tx.bufsz) {
            e->tx_rptr = 0;
            if (!afk_ring_payload(a, e, ep, &e->tx, 0, hdr, sizeof(hdr), false)) return;
            magic = le32_to_cpu(hdr[0]);
            size = le32_to_cpu(hdr[1]);
            channel = le32_to_cpu(hdr[2]);
            type = le32_to_cpu(hdr[3]);
        }
        if (magic != AFK_QE_MAGIC) {
            fprintf(stderr, "afk(%s): ep 0x%02x bad queue entry magic 0x%08x at rptr 0x%x "
                    "(expected \"IOP \"); dropping the rest of this ring\n",
                    a->role, ep, magic, e->tx_rptr);
            e->tx_rptr = wptr;
            break;
        }
        if (size > e->tx.bufsz || e->tx_rptr + size + AFK_QE_HDR_SIZE > e->tx.bufsz) {
            fprintf(stderr, "afk(%s): ep 0x%02x queue entry size 0x%x at rptr 0x%x runs past "
                    "the ring (bufsz 0x%x)\n", a->role, ep, size, e->tx_rptr, e->tx.bufsz);
            e->tx_rptr = wptr;
            break;
        }

        g_autofree uint8_t *data = g_malloc0(size ? size : 1);
        if (size && !afk_ring_payload(a, e, ep, &e->tx, e->tx_rptr + AFK_QE_HDR_SIZE,
                                      data, size, false)) {
            return;
        }

        e->n_recv++;
        uint32_t next = e->tx_rptr + AFK_QE_HDR_SIZE + size;
        next = (next + a->block - 1) & ~(a->block - 1);
        if (next >= e->tx.bufsz) next = 0;
        e->tx_rptr = next;

        // Publish our read cursor before handing the entry up, matching
        // afk.c:664-666.
        afk_ring_write32(a, e, ep, &e->tx, AFK_HDR_RPTR_BLOCK, e->tx_rptr);

        if (a->debug) {
            fprintf(stderr, "afk(%s): ep 0x%02x AP -> FW qe chan %u type %u len 0x%x\n",
                    a->role, ep, channel, type, size);
        }
        if (a->ops && a->ops->recv) {
            a->ops->recv(a->opaque, ep, channel, type, data, size);
        } else {
            fprintf(stderr, "afk(%s): ep 0x%02x unhandled queue entry chan %u type %u len 0x%x\n",
                    a->role, ep, channel, type, size);
        }
    }
}

/* ---------------- public API ---------------- */

void darwin_afk_add_endpoint(DarwinAFK *a, uint8_t ep) {
    a->eps[ep].is_afk = true;
}

bool darwin_afk_owns_endpoint(DarwinAFK *a, uint8_t ep) {
    return a->eps[ep].is_afk;
}

bool darwin_afk_ep_started(DarwinAFK *a, uint8_t ep) {
    return a->eps[ep].state == AFK_EP_STARTED;
}

void darwin_afk_reset(DarwinAFK *a) {
    for (int i = 0; i < AFK_MAX_EPS; i++) afk_ep_reset(a, &a->eps[i]);
}

void darwin_afk_ep_start(DarwinAFK *a, uint8_t ep, uint32_t flag) {
    AFKEndpoint *e = &a->eps[ep];
    if (!e->is_afk) return;
    afk_ep_reset(a, e);
    // flag 2 = start, 1 = stop (darwin_asc.c MGMT_STARTEP_FLAG). The AFK
    // sequence itself only begins when the AP's INIT arrives.
    e->state = (flag == 2) ? AFK_EP_IDLE : AFK_EP_OFF;
}

bool darwin_afk_handle(DarwinAFK *a, uint8_t ep, uint64_t msg) {
    AFKEndpoint *e = &a->eps[ep];
    if (!e->is_afk) return false;

    unsigned type = AFK_TYPE(msg);
    if (a->debug) {
        fprintf(stderr, "afk(%s): ep 0x%02x AP -> FW %-12s 0x%016" PRIx64 "\n",
                a->role, ep, afk_type_name(type), msg);
    }

    switch (type) {
    case RBEP_INIT:
        afk_handle_init(a, ep, e, msg);
        return true;

    case RBEP_GETBUF_ACK:
        afk_handle_getbuf_ack(a, ep, e, msg);
        return true;

    case RBEP_START:
        if (e->state != AFK_EP_INITRB) {
            fprintf(stderr, "afk(%s): ep 0x%02x unexpected START in state %u\n",
                    a->role, ep, e->state);
        }
        e->state = AFK_EP_STARTED;
        afk_send(a, ep, AFK_MSG(RBEP_START_ACK));
        fprintf(stderr, "afk(%s): ep 0x%02x started (rings at dva 0x%" PRIx64 ")\n",
                a->role, ep, e->dva);
        if (a->ops && a->ops->ep_started) a->ops->ep_started(a->opaque, ep);
        return true;

    case RBEP_SEND:
        if (e->state != AFK_EP_STARTED) {
            fprintf(stderr, "afk(%s): ep 0x%02x SEND before START_ACK (state %u), ignoring\n",
                    a->role, ep, e->state);
            return true;
        }
        afk_drain_tx(a, ep, e, SEND_WPTR(msg));
        return true;

    case RBEP_SHUTDOWN:
        afk_send(a, ep, AFK_MSG(RBEP_SHUTDOWN_ACK));
        afk_ep_reset(a, e);
        return true;

    default:
        // Never fault, never guess: log what the AP asked for so the next
        // person can see exactly which opcode is missing.
        fprintf(stderr, "afk(%s): ep 0x%02x UNHANDLED AFK opcode 0x%02x msg 0x%016" PRIx64
                " (state %u)\n", a->role, ep, type, msg, e->state);
        return true;
    }
}

/*
 * Write one queue entry into the AP's RX ring and notify it. This is the
 * FW->AP data path; it is the mirror of afk_send_epic() (afk.c:744-880).
 *
 * NOTE: nothing calls this yet. The EPIC layer that will (service announces
 * and replies) is the next task; this exists so that layer has a transport
 * to sit on and so the ring-full / wrap logic lives next to its read-side
 * counterpart.
 */
bool darwin_afk_send_qe(DarwinAFK *a, uint8_t ep, uint32_t channel,
                        uint32_t type, const void *data, uint32_t len) {
    AFKEndpoint *e = &a->eps[ep];
    if (e->state != AFK_EP_STARTED) return false;

    uint32_t rptr;
    if (!afk_ring_read32(a, e, ep, &e->rx, AFK_HDR_RPTR_BLOCK, &rptr)) return false;
    if (rptr >= e->rx.bufsz) {
        fprintf(stderr, "afk(%s): ep 0x%02x AP rptr 0x%x out of range\n", a->role, ep, rptr);
        return false;
    }

    uint32_t wptr = e->rx_wptr;
    uint32_t total = AFK_QE_HDR_SIZE + len;
    uint32_t hdr[4] = {
        cpu_to_le32(AFK_QE_MAGIC), cpu_to_le32(len),
        cpu_to_le32(channel), cpu_to_le32(type),
    };
    bool wrap = false;

    if (wptr < rptr) {
        if (wptr + total > rptr) return false;                  // afk.c:787-795
    } else {
        if (wptr + AFK_QE_HDR_SIZE > e->rx.bufsz) return false;  // afk.c:797-801
        if (wptr + total > e->rx.bufsz) {
            // Leave a bare header at wptr, restart the entry at offset 0.
            if (AFK_QE_HDR_SIZE > rptr) return false;           // afk.c:809-813
            if (AFK_QE_HDR_SIZE + len > rptr) return false;     // afk.c:823-827
            wrap = true;
        }
    }

    if (!afk_ring_payload(a, e, ep, &e->rx, wptr, hdr, sizeof(hdr), true)) return false;
    if (wrap) {
        if (!afk_ring_payload(a, e, ep, &e->rx, 0, hdr, sizeof(hdr), true)) return false;
        wptr = 0;
    }
    if (len && !afk_ring_payload(a, e, ep, &e->rx, wptr + AFK_QE_HDR_SIZE,
                                 (void *)data, len, true)) {
        return false;
    }

    wptr += total;
    wptr = (wptr + a->block - 1) & ~(a->block - 1);
    if (wptr >= e->rx.bufsz) wptr = 0;
    e->rx_wptr = wptr;
    e->n_sent++;

    // Payload, then queue entry, then wptr, then the notify -- the order
    // afk_send_epic() uses (afk.c:838-878).
    if (!afk_ring_write32(a, e, ep, &e->rx, AFK_HDR_WPTR_BLOCK, wptr)) return false;
    afk_send(a, ep, AFK_MSG(RBEP_RECV) | wptr);
    return true;
}

DarwinAFK *darwin_afk_new(DeviceState *asc, const char *role,
                          DeviceState *dart, unsigned sid,
                          const DarwinAFKConfig *cfg,
                          const DarwinAFKOps *ops, void *opaque) {
    DarwinAFK *a = g_new0(DarwinAFK, 1);
    a->asc = asc;
    a->role = g_strdup(role ? role : "afk");
    a->dart = dart;
    a->sid = sid;
    a->ops = ops;
    a->opaque = opaque;
    a->debug = getenv("DARWIN_AFK_DEBUG") != NULL;

    a->block = (cfg && cfg->block) ? cfg->block : AFK_DEF_BLOCK;
    uint32_t hdr_blocks = (cfg && cfg->hdr_blocks) ? cfg->hdr_blocks : AFK_DEF_HDR_BLOCKS;
    a->ring_size = (cfg && cfg->ring_size) ? cfg->ring_size : AFK_DEF_RING_SIZE;

    // Escape hatches for trying a different geometry against a new iOS
    // without a rebuild; see the header comment on why the defaults are what
    // they are.
    const char *env;
    if ((env = getenv("DARWIN_AFK_BLOCK"))) a->block = strtoul(env, NULL, 0);
    if ((env = getenv("DARWIN_AFK_RING_SIZE"))) a->ring_size = strtoul(env, NULL, 0);
    a->hdr_size = a->block * hdr_blocks;

    fprintf(stderr, "darwin-afk: %s transport, dart %s sid %u, rings 2 x 0x%x "
            "(header 0x%x, block 0x%x)\n", a->role,
            dart ? "ok" : "MISSING", sid, a->ring_size, a->hdr_size, a->block);
    return a;
}

/* ---------------- device tree glue ---------------- */

// Find the "iommu-mapper" child of any /arm-io dart node whose AAPL,phandle
// matches `phandle`. Returns the dart node and fills *sid from the mapper's
// "reg", which is the stream id.
static struct dtree_node *afk_find_mapper(struct dtree_node *arm_io,
                                          uint32_t phandle, unsigned *sid) {
    for (struct dtree_node *dart = adt_first_child(arm_io); dart;
         dart = adt_next_sibling(arm_io, dart)) {
        const char *dtype = adt_get_prop_val(dart, "device_type");
        if (!dtype || strcmp(dtype, "dart")) continue;
        for (struct dtree_node *m = adt_first_child(dart); m;
             m = adt_next_sibling(dart, m)) {
            uint32_t *ph = adt_get_prop_val(m, "AAPL,phandle");
            uint32_t *reg = adt_get_prop_val(m, "reg");
            if (!ph || !reg || *ph != phandle) continue;
            *sid = *reg;
            return dart;
        }
    }
    return NULL;
}

bool darwin_afk_find_iommu(struct dtree_node *dt_root, struct dtree_node *node,
                           struct dtree_node **dart_node, unsigned *sid) {
    struct dtree_node *arm_io = adt_find_node(dt_root, "arm-io");
    if (!arm_io) return false;

    // "iommu-parent" is one or more 32-bit phandles pointing at iommu-mapper
    // nodes (dcp: <&mapper-dcp>; disp0 carries two). The first is the
    // device's own mapper.
    uint32_t *parent = adt_get_prop_val(node, "iommu-parent");
    if (!parent || adt_get_prop_len(node, "iommu-parent") < 4) return false;

    struct dtree_node *dart = afk_find_mapper(arm_io, parent[0], sid);
    if (!dart) return false;
    *dart_node = dart;
    return true;
}
