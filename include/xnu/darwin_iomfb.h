#pragma once

#include "qemu/osdep.h"
#include "hw/core/sysbus.h"

/*
 * darwin-iomfb: the "link" protocol on DCP endpoint 0x37
 * (AppleDCPLinkService / AppleDCPLinkServiceSoC), firmware side.
 *
 * Not a QOM device: like darwin_afk.c this is a helper object a coprocessor
 * personality (darwin_dcp.c) creates and feeds from its DarwinASCOps.handle
 * callback. See darwin_iomfb.c for the wire format and every address it was
 * derived from, and docs/re/iomfb-link.md for the long write-up.
 */

typedef struct DarwinIOMFB DarwinIOMFB;

/*
 * level controls how far the model plays along; it is the numeric value of
 * DARWIN_DCP_IOMFB and every step above 1 is opt-in:
 *
 *   1  decode and log endpoint 0x37, answer nothing
 *   2  + the class-0/class-1 link handshake (heap announce -> firmware-hash
 *        ack), and decode + hexdump the class-2 RPC requests that follow
 *   3  + answer those RPCs (class-2/subkind-1 completion), status 0 and an
 *        all-zero output buffer, because no method's semantics have been
 *        derived from this firmware
 *   4  + the per-method canned answers a measurement has justified
 *        (iomfb_level4[] in darwin_iomfb.c carries the evidence for each).
 *        This is the level at which AppleCLCD2 registers.
 *
 * The outbound (DCP -> AP, "D-series") callback direction is orthogonal to
 * the level and off at every one of them. DARWIN_DCP_IOMFB_CB scripts it:
 *
 *   DARWIN_DCP_IOMFB_CB='D000::4,D003:00000000:0x14'
 *      a comma separated list of NAME[:INHEX[:OUTLEN]], issued one at a time,
 *      each after the previous completes.
 *   DARWIN_DCP_IOMFB_CB_AFTER='A353'
 *      which inbound RPC's completion starts the script; empty or 'ack'
 *      starts it as soon as the class-1 handshake finishes. Default A353.
 *
 * That is an experiment harness, not a model: the transport is derived from
 * the firmware (docs/re/iomfb-dseries.md) but nothing tells us which callback
 * a real DCP would send or when, so the model never sends one on its own.
 *
 * asc is the mailbox to reply on; dart/sid is the IOMMU path the DCP's DMA
 * takes, so the model can read the shared RPC heap the AP announces.
 */
DarwinIOMFB *darwin_iomfb_new(DeviceState *asc, DeviceState *dart, unsigned sid,
                              unsigned level);

// One 64-bit mailbox message arrived from the AP on `ep`. Always returns true:
// an endpoint we advertise must never look dead, and never faults.
bool darwin_iomfb_handle(DarwinIOMFB *m, uint8_t ep, uint64_t msg);
