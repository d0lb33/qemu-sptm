#pragma once

#include "qemu/osdep.h"
#include "hw/core/sysbus.h"
#include "xnu/apple_dtree.h"

#define TYPE_DARWIN_ANS "darwin-ans"

/*
 * Create the ANS (Apple NAND Storage) coprocessor described by /arm-io/ans:
 * the generic RTKit mailbox (darwin_asc.c, no ANS-specific endpoints exist)
 * plus the NVMe and NVMMU register windows behind it, backed by a QEMU block
 * device.
 *
 * Returns the darwin-asc DeviceState (as darwin_dcp_create does) or NULL if
 * the node is absent / not enabled by dt_fixup.
 *
 * The block backend is picked up here rather than being passed in, so that
 * darwin.c needs only this one call:
 *
 *     darwin_ans_create(dt_root, iobase, aic);
 *     static const char *const claimed_ascs[] = { "dcp", "sep", "ans" };
 *
 * ...and the disk is attached on the command line the usual QEMU way:
 *
 *     -drive if=none,id=ans,file=/path/to/disk.img,format=raw
 *
 * Lookup order is blk_by_name("ans"), then $DARWIN_ANS_DRIVE as a blockdev
 * id, then the first unclaimed `-drive if=none`. With no drive at all the
 * device still exists and answers registers, but Identify Namespace reports
 * an inactive namespace, so no IOMedia appears. See darwin_ans.c.
 */
DeviceState *darwin_ans_create(struct dtree_node *dt_root, uint64_t iobase, DeviceState *aic);
