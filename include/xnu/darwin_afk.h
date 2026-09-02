#pragma once

#include "qemu/osdep.h"
#include "hw/core/sysbus.h"
#include "xnu/apple_dtree.h"

/*
 * darwin-afk: the AFK ring-buffer transport that rides on top of an RTKit
 * endpoint. See darwin_afk.c for the protocol map and its sources; see
 * docs/re/afk-epic-references.md for the full write-up.
 *
 * This is not a QOM device: it has no MMIO of its own. It is a helper object
 * that a coprocessor personality (darwin_dcp.c today, AOP/other IOPs later)
 * instantiates and then feeds from its DarwinASCOps callbacks.
 */

typedef struct DarwinAFK DarwinAFK;

// Per-queue-entry type, afk_qe.type (linux-asahi afk.h:133-139). Passed
// through verbatim by this layer: the EPIC framing on top owns the meaning.
#define AFK_EPIC_TYPE_NOTIFY     0
#define AFK_EPIC_TYPE_COMMAND    3
#define AFK_EPIC_TYPE_REPLY      4
#define AFK_EPIC_TYPE_NOTIFY_ACK 8

typedef struct DarwinAFKOps {
    // The transport handshake for `ep` completed: we have acked START and
    // both rings are live. This is where an EPIC layer would announce its
    // services.
    void (*ep_started)(void *opaque, uint8_t ep);
    // One queue entry arrived from the AP on `ep`. `data`/`len` is
    // afk_qe.data, i.e. the EPIC frame (epic_hdr + epic_sub_hdr + payload);
    // this layer does not interpret it.
    void (*recv)(void *opaque, uint8_t ep, uint32_t channel, uint32_t type,
                 const uint8_t *data, uint32_t len);
} DarwinAFKOps;

// Ring geometry. Defaults come from the two AP-side references (see
// darwin_afk.c); every field is overridable so a different IOP or a newer
// iOS can be tried without touching the code.
typedef struct DarwinAFKConfig {
    uint32_t block;        // ring granule in bytes (BLOCK_SHIFT 6 -> 0x40)
    uint32_t hdr_blocks;   // ring header size, in `block` units (3)
    uint32_t ring_size;    // bytes per ring, header included
    uint32_t ring_version; // ring header word at +4; selects the queue entry
                           // layout. See AFK_RING_VERSION in darwin_afk.c.
} DarwinAFKConfig;

/*
 * Create an AFK transport bound to an already-created darwin-asc device.
 *
 *   asc   the coprocessor's mailbox, used for darwin_asc_send()
 *   role  name for log lines (the ASC node's "role", eg. "DCP")
 *   dart  the DART the IOP's DMA goes through, or NULL if we could not find
 *         it -- in which case the handshake stops at GETBUF_ACK and says so
 *   sid   the stream id inside that DART (the iommu-mapper node's "reg")
 *   cfg   ring geometry, or NULL for the defaults
 */
DarwinAFK *darwin_afk_new(DeviceState *asc, const char *role,
                          DeviceState *dart, unsigned sid,
                          const DarwinAFKConfig *cfg,
                          const DarwinAFKOps *ops, void *opaque);

// Declare that `ep` speaks AFK. Endpoints not declared here are ignored by
// darwin_afk_handle() so the personality can layer a different protocol
// (eg. IOMFB on 0x37) on the same coprocessor.
void darwin_afk_add_endpoint(DarwinAFK *a, uint8_t ep);
bool darwin_afk_owns_endpoint(DarwinAFK *a, uint8_t ep);

// Wire these into DarwinASCOps.
void darwin_afk_ep_start(DarwinAFK *a, uint8_t ep, uint32_t flag);
bool darwin_afk_handle(DarwinAFK *a, uint8_t ep, uint64_t msg);

// True once we have sent START_ACK for this endpoint.
bool darwin_afk_ep_started(DarwinAFK *a, uint8_t ep);

// Push one queue entry into the AP's RX ring. `data`/`len` become afk_qe.data.
// Returns false if the endpoint is not started, the ring is full, or DMA
// failed.
//
// `notify` sends the RBEP_RECV that tells the AP to drain. Pass false for all
// but the last entry of a burst and call darwin_afk_notify() once at the end:
// RECV carries the new wptr and the AP drains until rptr == wptr, so one
// notify covers any number of entries -- and one per entry overruns the ASC
// mailbox's inbound FIFO ("asc(...): i2a fifo overflow, dropping ep ..."),
// which loses the *last* notify and leaves the burst unread.
bool darwin_afk_send_qe(DarwinAFK *a, uint8_t ep, uint32_t channel,
                        uint32_t type, const void *data, uint32_t len,
                        bool notify);

// Tell the AP about everything written since the last notify.
void darwin_afk_notify(DarwinAFK *a, uint8_t ep);

// Forget all endpoint state (the IOP was reset).
void darwin_afk_reset(DarwinAFK *a);

/*
 * Resolve the DART + stream id a device tree node's DMA goes through, by
 * following its "iommu-parent" phandle to an "iommu-mapper" node and taking
 * that node's "reg" as the stream id. On success *dart_node is the mapper's
 * parent DART node and *sid its stream id. Returns false if the tree does
 * not describe one (eg. the node was stripped by dt_fixup).
 */
bool darwin_afk_find_iommu(struct dtree_node *dt_root, struct dtree_node *node,
                           struct dtree_node **dart_node, unsigned *sid);
