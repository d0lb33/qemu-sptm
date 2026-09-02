#pragma once

#include "qemu/osdep.h"

/*
 * darwin-epic: the EPIC message framing that rides inside an AFK ring queue
 * entry, firmware (IOP) side. See darwin_epic.c for the wire format and the
 * kernelcache addresses every field was read out of.
 *
 * Not a QOM device and not AFK-specific state: a pure encoder/decoder. The
 * coprocessor personality (darwin_dcp.c) owns the policy of what to announce
 * and when; this file owns the bytes.
 */

/* ---- packet header, epic_pkt_hdr.category (bootkc 0xfffffff008b8f60c) ---- */
#define EPIC_MSG_HDR_SIZE 8
#define EPIC_PKT_HDR_SIZE 16

#define EPIC_CAT_REPORT   0
#define EPIC_CAT_COMMAND  1
#define EPIC_CAT_RESPONSE 2

/* ---- epic_pkt_hdr.type when category == REPORT ---- */
#define EPIC_REPORT_PUBLISH   0x11  /* bootkc 0xfffffff008b7bc64 */
#define EPIC_REPORT_OPEN      0x12  /* bootkc 0xfffffff008b8fe4c (AP sends this) */
#define EPIC_REPORT_CLOSE     0x13  /* bootkc 0xfffffff008b8ff8c (AP sends this) */
#define EPIC_REPORT_TERMINATE 0x14  /* bootkc 0xfffffff008b7bc5c */

/* ---- epic_pkt_hdr.type when category == COMMAND/RESPONSE ---- */
#define EPIC_TYPE_STD_SERVICE 0xc0  /* bootkc 0xfffffff008b63ce0 / 0xfffffff008b63e00 */

/*
 * One entry of a serialized property dictionary. `key` is always emitted as
 * an OSSymbol; the value is either an OSString or an OSNumber.
 */
typedef struct DarwinEpicProp {
    const char *key;
    const char *str;    /* NULL if this is a number */
    int64_t num;
    unsigned bits;      /* OSNumber width; 32 or 64. Ignored when str != NULL */
} DarwinEpicProp;

/*
 * Serialize `n` properties into XNU's *binary* OSSerialize encoding — the
 * format OSUnserializeBinary() consumes, i.e. what the AP feeds the announce
 * payload to. Caller frees with g_free().
 */
uint8_t *darwin_epic_serialize_props(const DarwinEpicProp *props, unsigned n,
                                     size_t *out_len);

/*
 * Build one complete AFK queue-entry payload (afk_qe.data) carrying a
 * REPORT/PUBLISH — the frame that makes XNU instantiate an
 * AFKEndpointInterface nub and run IOKit matching against its properties.
 *
 *   iface_id  the u16 the AP records as the nub's "interface-id" property and
 *             uses to address this service afterwards; firmware's choice
 *   name      the 32-byte raw name field (NUL padded/truncated)
 *   props     serialized property dictionary, or NULL
 *
 * Caller frees with g_free().
 */
uint8_t *darwin_epic_build_publish(uint16_t iface_id, const char *name,
                                   const uint8_t *props, size_t props_len,
                                   uint8_t options, size_t *out_len);

/*
 * Decode one received queue-entry payload into a human-readable line.
 * Returns a g_malloc'd string; never fails, never faults on short frames.
 */
char *darwin_epic_describe(const uint8_t *data, uint32_t len);

/*
 * Build one complete AFK queue-entry payload carrying a COMMAND or RESPONSE.
 *
 * `body` is the category-specific body, which for the standard-service type
 * begins with an 8-byte header whose byte 1 is the command id the AP matches
 * replies against (bootkc 0xfffffff008b8eca8, `ubfx w1, w26, #8, #8`).
 * Caller frees with g_free().
 */
uint8_t *darwin_epic_build_call(uint16_t iface_id, uint8_t category, uint8_t type,
                                const uint8_t *body, size_t body_len,
                                uint8_t options, size_t *out_len);
