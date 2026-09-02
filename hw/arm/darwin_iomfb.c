/*
 * darwin-iomfb: the DCP "link" protocol on endpoint 0x37, firmware side.
 *
 * Endpoint 0x37 is DCPEndpoint24 / AppleDCPLinkServiceSoC, the endpoint the
 * *framebuffer* rides on. It is NOT AFK and NOT EPIC: the 64-bit RTKit
 * mailbox word is itself the message, with a structured 16-bit header in the
 * low bits and a class-dependent payload above it.
 *
 * SOURCE for everything below: iOS 27.0 beta (24A5430a), iPhone17,3
 * (t8140/H17P), kernelcache firmware/bootkc, fileset entry
 * com.apple.iokit.IOMobileGraphicsFamily-DCP. The kext is stripped (nsyms=0),
 * so functions are named by string cross-reference. Unslid VAs; the panic
 * addresses the guest prints are these + 0x20000000. The long-form write-up
 * with the reasoning is docs/re/iomfb-link.md.
 *
 *   link_send_message      fcn.fffffff00a0cecd0
 *   link_handle_message    fcn.fffffff00a0cfac0   (the AP's receive dispatcher)
 *   link_init_ack step     fcn.fffffff00a0ce0f0
 *   rpc_caller_gated       fcn.fffffff00a0ce46c   (aka link_shared_alloc)
 *   the heap announce      fcn.fffffff00a0cdfe0
 *
 * ---------------------------------------------------------------- header --
 *
 * link_send_message builds, and link_handle_message dispatches on, exactly
 * these fields. The 48-bit boundary is the literal operand of
 * `and x8, x2, 0xffffffffffff0000` at 0xa0ced14 -- not an inference.
 *
 *   [1:0]    class    `and w26, w28, 3`      @ 0xa0cfb04
 *   [5:2]    unused   (zero in every message seen, read by nobody)
 *   [7:6]    subkind  `ubfx w0, w28, 6, 2`   @ 0xa0cfb14
 *   [8]      ack bit  `bfi ..., 8, 1`        @ 0xa0ced10, keyed on @ 0xa0cfc48
 *   [9]      flag     passed through by the sender (`x2 & 0x2ff` keeps it)
 *   [15:10]  6-bit tag `(*ctx & 0x3f) << 10` @ 0xa0ced00, extracted @ 0xa0cfc4c
 *   [63:16]  payload, meaning depends on class
 *
 * ------------------------------------------------------------- the flow --
 *
 * 1. AP -> IOP, class 0 / subkind 1: "here is my shared heap".
 *    Built at 0xa0ce074 as `0x40 | (dva << 16)`; observed
 *    0x0100000000000040, i.e. DVA 0x10000000000. It is SEND-ONLY: echoing it
 *    back makes the AP take link_handle_message's own class-0/subkind-1
 *    branch (0xa0d0008), which unconditionally logs
 *    "link_init_ack_callback failed with 0x6" and returns kIOReturnNoMemory,
 *    panicking at AppleDCPLinkService.cpp:882. Verified live.
 *
 * 2. IOP -> AP, class 1: the init ack. link_handle_message's class-1 branch
 *    (0xa0cfb5c) computes
 *      local  = crc32(0, (uint8_t*)0xfffffff00b880c70, 4)   @ 0xa0cfb60-b6c
 *    and compares it 32-bit against
 *      remote = (msg >> 16) & 0xffffffff                    @ 0xa0cfb9c-ba0
 *    Those four bytes of the kext's own __DATA are `d3 00 00 00` (bootkc file
 *    offset 0x487cc70), and zlib.crc32(b"\xd3\0\0\0") == 0x15a5c96b, which is
 *    exactly the `local=` the guest printed when we got this wrong. So the
 *    constant is reproduced from first principles rather than copied out of a
 *    panic -- but it is specific to THIS kernelcache; recompute it from those
 *    bytes for a different build. Bits[63:48] are a phase/count the AP stores
 *    as max(phase, 4) at chan+0x48 (0xa0cfbe4-0xa0cfc00), so 0 is safe.
 *
 * 3. AP -> IOP, class 2 / subkind 0: "there is an RPC request in the heap".
 *    Built by rpc_caller_gated at 0xa0ce65c-0xa0ce688:
 *        x24 = offset; bfi w24, w25, 16, 16     ; w25 = total size
 *        x25 = 2; bfi x25, x23, 9, 1            ; class 2, bit 9 = a caller flag
 *        x2  = x25 | (x24 << 16)
 *    i.e. bits[31:16] = byte offset into the heap, bits[47:32] = total size.
 *    The request itself is written into the heap at that offset by
 *    0xa0ce608-0xa0ce654:
 *        +0x00  u32  name    a FourCC, printed big-endian at 0xa0ce4a8-4c4
 *        +0x04  u32  in_len
 *        +0x08  u32  out_len
 *        +0x0c  u8   in[in_len]
 *        +0x0c+in_len  u8 out[out_len]   <- the IOP fills this in
 *    and total size == 0xc + in_len + out_len (`add w11,w26,0xc;
 *    adds w25,w22,w11` @ 0xa0ce4d8-4dc). The caller then blocks in
 *    link_cond_wait_priv.
 *
 * 4. IOP -> AP, class 2 / subkind 1: the completion. The waiter checks
 *        (reply_header & 0xc3) == 0x42                      @ 0xa0ce750-75c
 *    -- 0xc3 masks class and subkind, 0x42 is class 2 + subkind 1 -- and then
 *        status = (u32)(reply >> 16); if (status) fail       @ 0xa0ce78c-790
 *        memcpy(caller_out, heap + offset + 0xc + in_len, out_len)  @ 0xa0ce7c8-7dc
 *    The reply is routed back to the right caller by a lookup keyed on
 *    (ack_bit << 32) | tag (0xa0cfc44-4c), so the reply must carry the
 *    request's own tag and ack bit. Class 2 + subkind 1 is also the one
 *    combination link_send_message REQUIREs you not to send directly
 *    (0xa0ced2c-38) -- it is reply-only, which is a second confirmation that
 *    this is the completion shape.
 *
 * ------------------------------------------------------- what is stubbed --
 *
 * The RPC methods themselves. We log every FourCC and hexdump its input, and
 * answer with status 0 and a zeroed output buffer. That is a deliberate,
 * documented hole: no method's semantics have been derived from this
 * firmware, so returning "success, all zeroes" is the only answer that does
 * not invent behaviour. Where it is wrong the AP will say so by name, which
 * is how the next method gets modelled.
 *
 * Class 3 is never sent by either side here and is not modelled. Class 2 /
 * subkind 0 messages with a heap we have not been told about are logged and
 * dropped rather than guessed at.
 *
 * Tracing and knobs: DARWIN_DCP_IOMFB selects the level (see
 * darwin_iomfb.h); DARWIN_DCP_IOMFB_DEBUG=1 adds a hexdump of every RPC
 * request and reply body; DARWIN_DCP_IOMFB_OUT='A401=01,...' substitutes
 * canned output bytes for one FourCC so a probe can test a hypothesis
 * without a rebuild. Level 4 is that same mechanism with the answers a
 * measurement has already justified (see iomfb_level4[]). Every line is
 * prefixed "iomfb:", which tools/probe.sh filters on.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "system/memory.h"
#include "system/address-spaces.h"
#include "exec/memattrs.h"
#include "xnu/darwin_asc.h"
#include "xnu/darwin_dart.h"
#include "xnu/darwin_iomfb.h"

/* Header field accessors -- see the table above. */
#define IOMFB_CLASS(m)    ((unsigned)((m) & 0x3))
#define IOMFB_SUBKIND(m)  ((unsigned)(((m) >> 6) & 0x3))
#define IOMFB_ACK(m)      ((unsigned)(((m) >> 8) & 0x1))
#define IOMFB_FLAG9(m)    ((unsigned)(((m) >> 9) & 0x1))
#define IOMFB_TAG(m)      ((unsigned)(((m) >> 10) & 0x3f))
#define IOMFB_HDR(m)      ((uint16_t)(m))

/* class-2 payload split (0xa0ce65c-0xa0ce688) */
#define IOMFB_RPC_OFF(m)  ((uint32_t)(((m) >> 16) & 0xffff))
#define IOMFB_RPC_SIZE(m) ((uint32_t)(((m) >> 32) & 0xffff))

/*
 * crc32(0, {0xd3,0,0,0}, 4). See step 2 above: the AP recomputes this from
 * its own __DATA on every class-1 message and compares it 32-bit, so it is a
 * build constant, not a secret. It is *this* kernelcache's value.
 */
#define IOMFB_FW_HASH 0x15A5C96BU

/* Request header in the shared heap (0xa0ce608-0xa0ce614). */
typedef struct QEMU_PACKED {
    uint32_t name;      /* FourCC, stored little-endian, printed big-endian */
    uint32_t in_len;
    uint32_t out_len;
} IOMFBRpcHdr;

struct DarwinIOMFB {
    DeviceState *asc;
    DeviceState *dart;
    unsigned sid;
    unsigned level;
    bool debug;

    /* The AP's shared heap, from the class-0/subkind-1 announce. */
    bool heap_known;
    uint64_t heap_dva;

    bool dma_warned;    /* one DART complaint per boot, not one per message */
    uint64_t rpcs;

    /*
     * Experiment harness, DARWIN_DCP_IOMFB_OUT. The default answer to every
     * RPC is "status 0, output all zeroes" (see the header comment): honest,
     * but often not what the driver wants to hear. This lets a probe try a
     * different canned answer without a rebuild, so the boot log can say
     * which one moves the guest forward, eg.
     *
     *   DARWIN_DCP_IOMFB_OUT='A401=01,A410=0100'
     *
     * Bytes are hex, little-endian on the wire (they are copied verbatim
     * into the output region), truncated or zero-padded to out_len. Nothing
     * here is derived from firmware; every entry is a hypothesis under test
     * and none of them is a default.
     */
    GHashTable *out_override;   /* char* FourCC -> GByteArray* */
};

/* ------------------------------------------------------------------ DMA -- */

/*
 * Read/write guest memory the way the real DCP would: through its DART, with
 * the stream id the device tree gives /arm-io/dcp. Re-translates on every 4K
 * boundary because darwin_dart_translate() maps a single address and 4K
 * divides every Apple DART granule. Identical in shape to afk_dma() in
 * darwin_afk.c; kept separate only because this file has no ring state.
 *
 * A failure is reported and propagated, never papered over -- writing to a
 * wrong physical address would corrupt the guest silently.
 */
static bool iomfb_dma(DarwinIOMFB *m, uint64_t dva, void *buf, uint32_t len,
                      bool is_write) {
    uint8_t *p = buf;

    if (!m->dart) {
        if (!m->dma_warned) {
            m->dma_warned = true;
            fprintf(stderr, "iomfb: no DART; cannot reach the RPC heap at dva 0x%" PRIx64 "\n",
                    dva);
        }
        return false;
    }
    while (len) {
        uint64_t pa;
        if (!darwin_dart_translate(m->dart, m->sid, dva, &pa)) {
            if (!m->dma_warned) {
                m->dma_warned = true;
                fprintf(stderr, "iomfb: DART sid %u has no mapping for dva 0x%" PRIx64
                        " (%s)\n", m->sid, dva, is_write ? "write" : "read");
                darwin_dart_dump_sid(m->dart, m->sid);
            }
            return false;
        }
        uint32_t chunk = 0x1000 - (uint32_t)(dva & 0xfff);
        if (chunk > len) chunk = len;
        if (address_space_rw(&address_space_memory, pa, MEMTXATTRS_UNSPECIFIED,
                             p, chunk, is_write) != MEMTX_OK) {
            fprintf(stderr, "iomfb: guest memory access failed at pa 0x%" PRIx64 "\n", pa);
            return false;
        }
        dva += chunk;
        p += chunk;
        len -= chunk;
    }
    return true;
}

static void iomfb_hexdump(const char *what, const uint8_t *p, uint32_t len) {
    if (!len) {
        fprintf(stderr, "iomfb:   %s: (empty)\n", what);
        return;
    }
    for (uint32_t i = 0; i < len; i += 16) {
        char line[3 * 16 + 1];
        int n = 0;
        for (uint32_t j = i; j < len && j < i + 16; j++) {
            n += snprintf(line + n, sizeof(line) - n, "%02x ", p[j]);
        }
        fprintf(stderr, "iomfb:   %s +%04x: %s\n", what, i, line);
    }
}

/*
 * Level 4: the canned RPC answers that a *measurement* showed advance the
 * guest. Each entry names the call site that reads the value and what the
 * boot log did with and without it. Nothing here is a semantic model of the
 * method -- it is a hypothesis that survived a boot, which is why it is a
 * separate level rather than the level-3 default.
 *
 * A401  IOMobileFramebufferAP::start() calls it through vtable slot +0x970
 *       at 0xfffffff00a0b5fe4 -- the very next thing after the log line our
 *       boot ends on, "%s: fRackDebugSwapWaitTimeoutSec = %d"
 *       (0xfffffff00798f021) -- and branches on bit 0 of the result at
 *       0xa0b5fec (`tbz w0, 0, 0xa0b6154`). True publishes an
 *       "IOMFB Debug Info" (0xfffffff00798f047) property; false stores 0 at
 *       this+0x260 and skips it (0xa0b6154). The stub itself is at
 *       0xfffffff00a0c8a80: in_len 0, out_len 4, and it returns
 *       `out[0] & 1`, so it is a bool.
 *
 *       Measured, io=0x1f, otherwise identical boots:
 *         out=00 -> "AppleCLCD2[...]::start took 596 ms" and nothing else;
 *                   the driver then runs IOMFB_POWER_DART set_power_state
 *                   powerState=0 and no AppleCLCD2 service is registered.
 *         out=01 -> "Registering: ../disp0@0/AppleCLCD2" followed by
 *                   "AppleCLCD2[...]::start took 657 ms", and two further
 *                   RPCs flow (A465 with in {0x800,0x20}, A353 out 8).
 */
typedef struct { const char *name; const char *hex; } IOMFBCannedOut;
static const IOMFBCannedOut iomfb_level4[] = {
    { "A401", "01" },
};

static void iomfb_free_bytes(gpointer p) {
    g_byte_array_unref((GByteArray *)p);
}

/*
 * Parse DARWIN_DCP_IOMFB_OUT into m->out_override. Format is a comma or
 * space separated list of NAME=HEXBYTES, eg. "A401=01,A500=".  Malformed
 * entries are reported and skipped rather than silently ignored.
 */
static void iomfb_parse_overrides(DarwinIOMFB *m, const char *spec) {
    g_auto(GStrv) items = g_strsplit_set(spec, ", ", -1);

    for (char **it = items; it && *it; it++) {
        if (!**it) continue;
        char *eq = strchr(*it, '=');
        if (!eq || eq - *it != 4) {
            fprintf(stderr, "iomfb: DARWIN_DCP_IOMFB_OUT: cannot parse \"%s\" "
                    "(want NAME=HEXBYTES, NAME exactly 4 chars); skipped\n", *it);
            continue;
        }
        *eq = 0;
        const char *hex = eq + 1;
        if (strlen(hex) & 1) {
            fprintf(stderr, "iomfb: DARWIN_DCP_IOMFB_OUT: odd hex digit count for %s; "
                    "skipped\n", *it);
            continue;
        }
        GByteArray *bytes = g_byte_array_new();
        bool ok = true;
        for (const char *q = hex; *q; q += 2) {
            char pair[3] = { q[0], q[1], 0 };
            char *end = NULL;
            unsigned long v = strtoul(pair, &end, 16);
            if (end != pair + 2) { ok = false; break; }
            uint8_t b = (uint8_t)v;
            g_byte_array_append(bytes, &b, 1);
        }
        if (!ok) {
            fprintf(stderr, "iomfb: DARWIN_DCP_IOMFB_OUT: bad hex for %s; skipped\n", *it);
            g_byte_array_unref(bytes);
            continue;
        }
        if (!m->out_override) {
            m->out_override = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
                                                    iomfb_free_bytes);
        }
        g_hash_table_insert(m->out_override, g_strdup(*it), bytes);
        fprintf(stderr, "iomfb: PROBE override: %s returns %u byte(s) 0x%s\n",
                *it, bytes->len, hex);
    }
}

/* -------------------------------------------------------------- sending -- */

static void iomfb_send(DarwinIOMFB *m, uint8_t ep, uint64_t msg, const char *what) {
    fprintf(stderr, "iomfb: IOP -> AP ep 0x%02x 0x%016" PRIx64 "  (%s)\n", ep, msg, what);
    darwin_asc_send(m->asc, ep, msg);
}

/* --------------------------------------------------------------- class 0 -- */

/*
 * The AP announcing its shared heap. Reply with the class-1 init ack; see
 * step 2 in the header comment for why the hash goes in bits[47:16].
 */
static void iomfb_class0(DarwinIOMFB *m, uint8_t ep, uint64_t msg) {
    unsigned subkind = IOMFB_SUBKIND(msg);

    if (subkind != 1) {
        /*
         * Class 0 / subkind 0 exists (link_handle_message 0xa0cfb1c-0xa0cfb58
         * handles it, comparing (msg>>16) against the raw word at
         * 0xfffffff00b880c70 rather than its crc32, and resending the heap
         * announce). The AP has never sent us one, so there is nothing to
         * model from observation. Logged no-op, deliberately.
         */
        fprintf(stderr, "iomfb: ep 0x%02x class 0 subkind %u -- not modelled "
                "(no such message observed from this AP), ignored\n", ep, subkind);
        return;
    }

    m->heap_dva = msg >> 16;
    m->heap_known = true;
    fprintf(stderr, "iomfb: ep 0x%02x AP heap announce: dva 0x%" PRIx64 "\n",
            ep, m->heap_dva);

    if (m->level < 2) return;

    /*
     * class 1, subkind 0, tag 0, ack 0, hash in [47:16], phase left 0 (the AP
     * clamps it to at least 4 itself at 0xa0cfbf8).
     */
    uint64_t ack = ((uint64_t)IOMFB_FW_HASH << 16) | 0x0001ULL;
    iomfb_send(m, ep, ack, "class-1 init ack, firmware hash");
}

/* --------------------------------------------------------------- class 2 -- */

/*
 * An RPC request sits in the AP's shared heap. Read it, log it, and (level 3)
 * complete it.
 *
 * Everything about the reply's shape is sourced in step 4 of the header
 * comment. What we cannot source is any *method*: the FourCC namespace of
 * this firmware has not been derived, so we answer status 0 with a zeroed
 * output buffer and say so in the log. That is a stub, not a model.
 */
static void iomfb_class2(DarwinIOMFB *m, uint8_t ep, uint64_t msg) {
    unsigned subkind = IOMFB_SUBKIND(msg);
    uint32_t off = IOMFB_RPC_OFF(msg), size = IOMFB_RPC_SIZE(msg);

    if (subkind != 0) {
        /*
         * Subkind 1 is the completion *we* send; the AP does not send it to
         * us. Anything else here is unexplored.
         */
        fprintf(stderr, "iomfb: ep 0x%02x class 2 subkind %u from the AP -- not modelled, "
                "ignored\n", ep, subkind);
        return;
    }
    if (!m->heap_known) {
        fprintf(stderr, "iomfb: ep 0x%02x RPC at offset 0x%x size 0x%x, but the AP never "
                "announced a heap; cannot read it\n", ep, off, size);
        return;
    }
    if (size < sizeof(IOMFBRpcHdr)) {
        fprintf(stderr, "iomfb: ep 0x%02x RPC size 0x%x is smaller than the 0xc-byte "
                "header; ignored\n", ep, size);
        return;
    }

    g_autofree uint8_t *buf = g_malloc0(size);
    if (!iomfb_dma(m, m->heap_dva + off, buf, size, false)) {
        fprintf(stderr, "iomfb: ep 0x%02x could not read the RPC at dva 0x%" PRIx64
                "+0x%x\n", ep, m->heap_dva, off);
        return;
    }

    IOMFBRpcHdr h;
    memcpy(&h, buf, sizeof(h));
    /* The AP prints this FourCC big-endian (0xa0ce4a8-0xa0ce4c4); match it. */
    char name[5] = {
        (char)(h.name >> 24), (char)(h.name >> 16), (char)(h.name >> 8), (char)h.name, 0
    };
    for (int i = 0; i < 4; i++) {
        if (name[i] < 0x20 || name[i] > 0x7e) name[i] = '.';
    }

    m->rpcs++;
    fprintf(stderr, "iomfb: ep 0x%02x RPC #%" PRIu64 " '%s' (0x%08x) in %u out %u "
            "at heap+0x%x size 0x%x tag %u ack %u flag9 %u\n",
            ep, m->rpcs, name, h.name, h.in_len, h.out_len, off, size,
            IOMFB_TAG(msg), IOMFB_ACK(msg), IOMFB_FLAG9(msg));

    /* The AP's own accounting: total = 0xc + in_len + out_len (0xa0ce4d8). */
    if ((uint64_t)sizeof(h) + h.in_len + h.out_len != size) {
        fprintf(stderr, "iomfb:   note: 0xc + in + out = 0x%" PRIx64 " but the message says "
                "0x%x; trusting the message\n",
                (uint64_t)sizeof(h) + h.in_len + h.out_len, size);
    }

    if (m->debug) {
        uint32_t in_len = h.in_len;
        if (in_len > size - sizeof(h)) in_len = size - sizeof(h);
        iomfb_hexdump("in", buf + sizeof(h), in_len);
    }

    if (m->level < 3) {
        fprintf(stderr, "iomfb:   not answering (DARWIN_DCP_IOMFB=%u; 3 answers RPCs)\n",
                m->level);
        return;
    }

    /*
     * Fill the output region. The default is all zeroes: deterministic, and
     * the only answer that does not invent behaviour for a method we have
     * not derived. DARWIN_DCP_IOMFB_OUT can substitute canned bytes for one
     * FourCC so a probe can test a hypothesis -- see the out_override
     * comment on DarwinIOMFB. Both paths are logged by name.
     *
     * Note the AP poisons its own out buffer with 0xaa before the call (eg.
     * the A401 stub's `movi v0.16b, 0xaa; stur s0, [x29,-4]` at
     * 0xa0c8a90-0xa0c8a94), so leaving the region untouched would hand the
     * driver 0xaaaaaaaa rather than nothing.
     */
    const char *how = "zeroed";
    if (h.out_len && (uint64_t)sizeof(h) + h.in_len + h.out_len <= size) {
        g_autofree uint8_t *out = g_malloc0(h.out_len);
        GByteArray *ov = m->out_override ?
            g_hash_table_lookup(m->out_override, name) : NULL;
        if (ov) {
            memcpy(out, ov->data, MIN(ov->len, h.out_len));
            how = "PROBE override";
        }
        uint64_t out_dva = m->heap_dva + off + sizeof(h) + h.in_len;
        if (!iomfb_dma(m, out_dva, out, h.out_len, true)) {
            fprintf(stderr, "iomfb:   could not write the %u-byte output region at dva "
                    "0x%" PRIx64 "\n", h.out_len, out_dva);
        } else if (m->debug) {
            iomfb_hexdump("out", out, h.out_len);
        }
    }

    /*
     * class 2, subkind 1 (0x42 in the header, which is exactly what the
     * waiter masks for at 0xa0ce750-75c), the request's own tag and ack bit
     * so link_handle_message's (ack<<32)|tag lookup finds the caller, and
     * status 0 in bits[47:16].
     */
    uint64_t reply = 0x42ULL
                   | ((uint64_t)IOMFB_ACK(msg) << 8)
                   | ((uint64_t)IOMFB_TAG(msg) << 10);
    char what[96];
    snprintf(what, sizeof(what), "class-2 completion for '%s', status 0, out %s", name, how);
    iomfb_send(m, ep, reply, what);
}

/* ------------------------------------------------------------- dispatch -- */

bool darwin_iomfb_handle(DarwinIOMFB *m, uint8_t ep, uint64_t msg) {
    unsigned cls = IOMFB_CLASS(msg);

    fprintf(stderr, "iomfb: AP -> IOP ep 0x%02x 0x%016" PRIx64
            " | class %u subkind %u ack %u flag9 %u tag %u payload 0x%" PRIx64 "\n",
            ep, msg, cls, IOMFB_SUBKIND(msg), IOMFB_ACK(msg), IOMFB_FLAG9(msg),
            IOMFB_TAG(msg), msg >> 16);

    if (m->level < 2) {
        return true;    /* decode-only mode: never answer */
    }

    switch (cls) {
    case 0:
        iomfb_class0(m, ep, msg);
        break;
    case 2:
        iomfb_class2(m, ep, msg);
        break;
    case 1:
        /*
         * The AP's own class-1 message, sent by fcn.fffffff00a0ce0f0 when
         * chan+0x260 == 1 (0xa0ce108-0xa0ce118, always 0x0004000000000001).
         * It is the mirror of the ack we send in step 2 and needs no reply
         * that we can source. Logged no-op.
         */
        fprintf(stderr, "iomfb: ep 0x%02x class 1 from the AP (its own init ack); "
                "no reply modelled\n", ep);
        break;
    default:
        /*
         * Class 3 is only inferred to exist from the 2-bit width of the field
         * and an unreached error branch at 0xa0d0310. Never observed.
         */
        fprintf(stderr, "iomfb: ep 0x%02x class %u -- never observed, not modelled, "
                "ignored\n", ep, cls);
        break;
    }
    return true;
}

DarwinIOMFB *darwin_iomfb_new(DeviceState *asc, DeviceState *dart, unsigned sid,
                              unsigned level) {
    DarwinIOMFB *m = g_new0(DarwinIOMFB, 1);
    const char *dbg = getenv("DARWIN_DCP_IOMFB_DEBUG");

    m->asc = asc;
    m->dart = dart;
    m->sid = sid;
    m->level = level;
    m->debug = dbg && dbg[0] && dbg[0] != '0';

    if (level >= 4) {
        for (size_t i = 0; i < ARRAY_SIZE(iomfb_level4); i++) {
            g_autofree char *one = g_strdup_printf("%s=%s", iomfb_level4[i].name,
                                                   iomfb_level4[i].hex);
            iomfb_parse_overrides(m, one);
        }
    }

    /* The environment wins over the table, so a probe can contradict it. */
    const char *ov = getenv("DARWIN_DCP_IOMFB_OUT");
    if (ov && *ov) {
        iomfb_parse_overrides(m, ov);
    }

    fprintf(stderr, "darwin-iomfb: link on ep 0x37, level %u (%s), dart %s sid %u\n",
            level,
            level >= 4 ? "handshake + RPC completions + measured answers" :
            level >= 3 ? "handshake + RPC completions" :
            level >= 2 ? "handshake, RPCs decoded but unanswered" :
                         "decode only",
            dart ? "ok" : "MISSING", sid);
    return m;
}
