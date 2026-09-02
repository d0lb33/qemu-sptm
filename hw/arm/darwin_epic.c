/*
 * darwin-epic: Apple "EPIC" message framing inside an AFK ring queue entry,
 * firmware (IOP) side.
 *
 * AFK (darwin_afk.c) turns one RTKit endpoint into a pair of DMA rings that
 * carry opaque queue entries. EPIC is what those entries contain: a small
 * multiplexing header, a packet header that says report/command/response, and
 * then a per-category body. The report category is the interesting one for
 * bring-up: a PUBLISH report is how firmware tells the AP "this service exists
 * on this endpoint", which is what makes XNU instantiate an
 * `AFKEndpointInterface` nub and run IOKit matching on its properties.
 *
 *
 * WIRE FORMAT -- all of this was read out of *this build's* kernelcache
 * (`firmware/bootkc`, unslid addresses; the boot that produced them had slide
 * 0x20000000), not from the M1-era Linux/m1n1 references, because iOS 27's
 * framing turned out to differ from theirs in every header. See
 * docs/re/afk-epic-references.md for the diff.
 *
 *   afk_qe.data
 *   +0x00  EPIC message header, 8 bytes
 *          +0x00 u8   flags -- bit 0 means "a 0x18-byte extra block follows
 *                     the packet header". The AP tests exactly that bit at
 *                     0xfffffff008b8da88 before appending 0x18 bytes at
 *                     0xfffffff008b8db20, and appends this 8-byte header
 *                     itself at 0xfffffff008b8db90. We never send the extra
 *                     block, so we send 0.
 *          +0x01 u8   unknown. Nothing in the AP's parse reads it; sent as 0.
 *          +0x02 u16  interface id. Read at 0xfffffff008b7bc70 (publish) and
 *                     0xfffffff008b7bc84 (terminate); ends up as the nub's
 *                     "interface-id" property, see below.
 *          +0x04 u32  total length of everything after this header. The AP
 *                     compares it against the fragment length at
 *                     0xfffffff008b8f76c-0xfffffff008b8f780 and only
 *                     dispatches the packet when they are equal (otherwise it
 *                     takes a reassembly path, 0xfffffff008b8f9c8 onwards).
 *                     It writes the same field itself at 0xfffffff008b8db7c.
 *   +0x08  EPIC packet header, 16 bytes. Parsed at
 *          0xfffffff008b8f5f8-0xfffffff008b8f614, built by the AP's own
 *          sendReport at 0xfffffff008b8fd2c-0xfffffff008b8fd4c.
 *          +0x00 u64  timestamp. The AP sends 0 (0xfffffff008b8fcb4); so do we.
 *          +0x08 u8   type
 *          +0x09 u8   category: 0 report, 1 command, 2 response
 *                     (the switch at 0xfffffff008b8f650-0xfffffff008b8f660)
 *          +0x0a u8   options. Only bit 0 is looked at, and only on the
 *                     generic path (`and w5, w27, #1`, 0xfffffff008b8f6e4);
 *                     AFKEPInterfaceServiceKextV2's report handler ignores it
 *                     entirely. The AP sets 1 on every report it sends
 *                     (0xfffffff008b8fcbc, 0xfffffff008b8fe58), so we do too.
 *          +0x0b  5 bytes, zero (the AP zeroes them, 0xfffffff008b8fd1c).
 *   +0x18  body
 *
 * Report types, from AFKEPInterfaceServiceKextV2's handler at
 * 0xfffffff008b7bc58-0xfffffff008b7bc6c (`ldrb w10,[x9,#8]`, then `cmp #0x14`
 * / `cmp #0x11`) and the AP's own senders:
 *
 *   0x11 PUBLISH    firmware -> AP, announces a service      (0xfffffff008b7bc64)
 *   0x12 OPEN       AP -> firmware, empty body               (0xfffffff008b8fe4c)
 *   0x13 CLOSE      AP -> firmware                           (0xfffffff008b8ff8c)
 *   0x14 TERMINATE  either way, tears a service down         (0xfffffff008b7bc5c)
 *
 * Note these are NOT the `EPIC_SUBTYPE_ANNOUNCE = 0x30` / `TEARDOWN = 0x32`
 * of the M1-era Linux driver. Nor is the two-level `epic_hdr`(16) +
 * `epic_sub_hdr`(24) layout that driver documents present here; iOS 27 uses
 * the 8+16 shape above. `0xc0` (standard service call) *is* unchanged --
 * the command and response dispatchers accept nothing else
 * (0xfffffff008b63ce0, 0xfffffff008b63e00, "Unsupported packet type:0x%x").
 *
 *
 * PUBLISH BODY, parsed at 0xfffffff008b7bcd4:
 *
 *   +0x00  char name[32]   copied into a zeroed 32-byte buffer
 *                          (0xfffffff008b7bd18-0xfffffff008b7bd2c)
 *   +0x20  serialized property dictionary, (bodylen - 32) bytes
 *                          (0xfffffff008b7bd14 `sub x20, x1, #0x20`, copied at
 *                          0xfffffff008b7bd3c-0xfffffff008b7bd44)
 *
 * The AP asserts bodylen >= 0x20 first ("packetSize >= sizeof(PublishReport)"
 * @AFKEPInterfaceServiceKextV2.cpp:511, thunk at 0xfffffff008ba3e94 reached
 * from 0xfffffff008b7ee44) -- a *panic*, not an error return, so a short
 * publish takes the guest down.
 *
 * The dictionary is deserialized with OSUnserializeXML(buf, len, NULL)
 * (0xfffffff008b7bf8c -> stub 0xfffffff008ba98c4 -> 0xfffffff00b1b711c), which
 * dispatches to OSUnserializeBinary when the first bytes are the binary
 * signature -- `strcmp("\xd3\0\0", buf)` against the constant at
 * 0xfffffff007044658, whose bytes are literally `d3 00 00 00`. So this is
 * XNU's binary OSSerialize encoding, the same one IOCFSerialize() emits with
 * kIOCFSerializeToBinary; see darwin_epic_serialize_props() for the encoder
 * and for the byte-for-byte reference dump it was checked against.
 *
 * What the AP then does with it (0xfffffff008b7bd5c onwards): allocates an
 * AFKEndpointInterface nub, adds "interface-id" (the u16 from the message
 * header) to the dictionary as an OSNumber -- the OSSymbol is built from the
 * literal "interface-id" at 0xfffffff00740a531, stored to
 * 0xfffffff00b7ce1c8 at 0xfffffff008b7cbb8 -- initialises the nub with that
 * dictionary as its property table, then reads two keys back out of it:
 * "name" (0xfffffff0074089d4, read at 0xfffffff008b7bdf0) and
 * "interface-name" (0xfffffff00740a9b5, read at 0xfffffff008b7be3c, used to
 * setName() the nub). Everything else in the dictionary simply becomes an
 * IORegistry property, which is what the sub-driver personalities match on:
 * every one of them is `IOProviderClass = AFKEndpointInterface` +
 * `IOPropertyMatch = { EPICName: ... }` (kernelcache __PRELINK_INFO).
 *
 * Tracing: the caller decides; this file only builds and describes bytes.
 */

#include "qemu/osdep.h"
#include "qemu/bswap.h"
#include "xnu/darwin_epic.h"

/* ---------------- XNU binary OSSerialize ---------------- */

/*
 * libkern's binary property-list encoding. The tag is one little-endian u32
 * per object: type in bits 30:24, a type-specific length in bits 23:0, and
 * bit 31 set on the last element of the enclosing collection.
 *
 * These values are not guessed: the encoder below was written against a
 * byte-for-byte dump produced by the host's own
 * IOCFSerialize(dict, kIOCFSerializeToBinary) for
 *   { EPICName = "dcpav-controller-epic";
 *     EPICProviderClass = "DCPAVControllerProxy";
 *     EPICUnit = 0; }
 * which is:
 *   000000d3                        signature
 *   81000003                        dictionary, 3 pairs, END
 *   08000009  "EPICName\0"          symbol: length INCLUDES the NUL
 *   09000015  "dcpav-controller-epic"   string: length EXCLUDES the NUL
 *   08000012  "EPICProviderClass\0"
 *   09000014  "DCPAVControllerProxy"
 *   08000009  "EPICUnit\0"
 *   84000040  0000000000000000      number, 0x40 = width in *bits*, END,
 *                                   value as two LE u32s (low, high)
 * Every string/symbol is zero-padded to the next 4-byte boundary. The
 * symbol-includes-NUL / string-excludes-NUL asymmetry is real and is the
 * easiest thing to get wrong.
 */
#define OSS_SIGNATURE     0x000000d3u
#define OSS_DICTIONARY    0x01000000u
#define OSS_NUMBER        0x04000000u
#define OSS_SYMBOL        0x08000000u
#define OSS_STRING        0x09000000u
#define OSS_END           0x80000000u

static void oss_u32(GByteArray *b, uint32_t v)
{
    uint32_t le = cpu_to_le32(v);
    g_byte_array_append(b, (const uint8_t *)&le, 4);
}

/* Append `len` bytes then zero-pad to a 4-byte boundary. */
static void oss_bytes(GByteArray *b, const void *p, size_t len)
{
    static const uint8_t zero[4] = { 0, 0, 0, 0 };
    g_byte_array_append(b, p, len);
    if (len & 3) {
        g_byte_array_append(b, zero, 4 - (len & 3));
    }
}

uint8_t *darwin_epic_serialize_props(const DarwinEpicProp *props, unsigned n,
                                     size_t *out_len)
{
    GByteArray *b = g_byte_array_new();

    oss_u32(b, OSS_SIGNATURE);
    /* The root dictionary is also the last (only) element at the top level,
     * so it carries the END bit -- exactly as IOCFSerialize emits it. */
    oss_u32(b, OSS_DICTIONARY | OSS_END | n);

    for (unsigned i = 0; i < n; i++) {
        const DarwinEpicProp *p = &props[i];
        bool last = (i + 1 == n);
        size_t klen = strlen(p->key) + 1;   /* symbols include the NUL */

        oss_u32(b, OSS_SYMBOL | (uint32_t)klen);
        oss_bytes(b, p->key, klen);

        if (p->str) {
            size_t vlen = strlen(p->str);   /* strings do not */
            oss_u32(b, OSS_STRING | (last ? OSS_END : 0) | (uint32_t)vlen);
            oss_bytes(b, p->str, vlen);
        } else {
            unsigned bits = p->bits ? p->bits : 64;
            uint64_t v = (uint64_t)p->num;
            oss_u32(b, OSS_NUMBER | (last ? OSS_END : 0) | bits);
            oss_u32(b, (uint32_t)v);          /* low half first */
            oss_u32(b, (uint32_t)(v >> 32));
        }
    }

    *out_len = b->len;
    return g_byte_array_free(b, FALSE);
}

/* ---------------- frame builders ---------------- */

#define EPIC_MSG_HDR_SIZE 8
#define EPIC_PKT_HDR_SIZE 16
#define EPIC_PUBLISH_NAME_SIZE 32

uint8_t *darwin_epic_build_publish(uint16_t iface_id, const char *name,
                                   const uint8_t *props, size_t props_len,
                                   uint8_t options, size_t *out_len)
{
    size_t body = EPIC_PUBLISH_NAME_SIZE + props_len;
    size_t total = EPIC_MSG_HDR_SIZE + EPIC_PKT_HDR_SIZE + body;
    uint8_t *buf = g_malloc0(total);

    /* message header */
    buf[0] = 0;                                     /* no extra 0x18 block */
    buf[1] = 0;
    stw_le_p(buf + 2, iface_id);
    stl_le_p(buf + 4, (uint32_t)(EPIC_PKT_HDR_SIZE + body));

    /* packet header */
    uint8_t *pkt = buf + EPIC_MSG_HDR_SIZE;
    stq_le_p(pkt + 0, 0);                           /* timestamp */
    pkt[8] = EPIC_REPORT_PUBLISH;
    pkt[9] = EPIC_CAT_REPORT;
    pkt[10] = options;

    /* body: 32-byte NUL-padded name, then the serialized dictionary */
    uint8_t *b = pkt + EPIC_PKT_HDR_SIZE;
    if (name) {
        size_t n = strlen(name);
        if (n > EPIC_PUBLISH_NAME_SIZE - 1) {
            n = EPIC_PUBLISH_NAME_SIZE - 1;
        }
        memcpy(b, name, n);
    }
    if (props_len) {
        memcpy(b + EPIC_PUBLISH_NAME_SIZE, props, props_len);
    }

    *out_len = total;
    return buf;
}

/* ---------------- decode, for tracing only ---------------- */

static const char *epic_cat_name(unsigned c)
{
    switch (c) {
    case EPIC_CAT_REPORT: return "REPORT";
    case EPIC_CAT_COMMAND: return "COMMAND";
    case EPIC_CAT_RESPONSE: return "RESPONSE";
    default: return "?";
    }
}

static const char *epic_report_name(unsigned t)
{
    switch (t) {
    case EPIC_REPORT_PUBLISH: return "PUBLISH";
    case EPIC_REPORT_OPEN: return "OPEN";
    case EPIC_REPORT_CLOSE: return "CLOSE";
    case EPIC_REPORT_TERMINATE: return "TERMINATE";
    default: return "?";
    }
}

char *darwin_epic_describe(const uint8_t *data, uint32_t len)
{
    if (len < EPIC_MSG_HDR_SIZE) {
        return g_strdup_printf("len 0x%x, too short for the 8-byte message header", len);
    }
    unsigned flags = data[0];
    unsigned iface = lduw_le_p(data + 2);
    uint32_t tlen = ldl_le_p(data + 4);

    if (len < EPIC_MSG_HDR_SIZE + EPIC_PKT_HDR_SIZE) {
        return g_strdup_printf("iface %u tlen 0x%x flags 0x%x, len 0x%x "
                               "too short for the packet header", iface, tlen, flags, len);
    }
    const uint8_t *pkt = data + EPIC_MSG_HDR_SIZE;
    unsigned type = pkt[8], cat = pkt[9], opt = pkt[10];
    uint32_t blen = len - EPIC_MSG_HDR_SIZE - EPIC_PKT_HDR_SIZE;

    if (cat == EPIC_CAT_REPORT) {
        return g_strdup_printf("iface %u tlen 0x%x flags 0x%x | %s %s opt 0x%x body 0x%x",
                               iface, tlen, flags, epic_cat_name(cat),
                               epic_report_name(type), opt, blen);
    }
    /* Commands and responses put an 8-byte header of their own at the front of
     * the body; byte 1 is the command id the AP matches replies against
     * (0xfffffff008b8eca8 `ubfx w1, w26, #8, #8`). */
    if (blen >= 8) {
        const uint8_t *c = pkt + EPIC_PKT_HDR_SIZE;
        return g_strdup_printf("iface %u tlen 0x%x flags 0x%x | %s type 0x%02x opt 0x%x "
                               "body 0x%x [cmdid 0x%02x arg 0x%08x]",
                               iface, tlen, flags, epic_cat_name(cat), type, opt, blen,
                               c[1], (unsigned)ldl_le_p(c + 4));
    }
    return g_strdup_printf("iface %u tlen 0x%x flags 0x%x | %s type 0x%02x opt 0x%x body 0x%x",
                           iface, tlen, flags, epic_cat_name(cat), type, opt, blen);
}
