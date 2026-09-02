#pragma once

#include "qemu/osdep.h"
#include "hw/core/sysbus.h"
#include "xnu/apple_dtree.h"

#define TYPE_DARWIN_SART "darwin-sart"

// Create a SART address filter (device_type "sart", eg. "sart,coastguard")
// for a device tree node.
DeviceState *darwin_sart_create(struct dtree_node *node, uint64_t iobase, DeviceState *aic);

// Create SARTs for every /arm-io child whose device_type is "sart" and whose
// compatible was kept by dt_fixup (-enable ans).
void darwin_sarts_create(struct dtree_node *dt_root, uint64_t iobase, DeviceState *aic);

// Is [pa, pa+len) inside a region the guest has programmed as allowed?
//
// SART does not translate, it only permits, so this is the entire "mapping"
// question a DMA master needs to ask. Nothing calls it yet: it exists so that
// whoever models ANS's DMA can gate NVMe/RTKit shared-memory accesses through
// the filter the way real hardware does, instead of ignoring it.
bool darwin_sart_allows(DeviceState *dev, uint64_t pa, uint64_t len);
