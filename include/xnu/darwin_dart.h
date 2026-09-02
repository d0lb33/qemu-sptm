#pragma once

#include "qemu/osdep.h"
#include "hw/core/sysbus.h"
#include "xnu/apple_dtree.h"

#define TYPE_DARWIN_DART "darwin-dart"

// Create a DART (Apple IOMMU, "dart,t8110") for a device tree node.
DeviceState *darwin_dart_create(struct dtree_node *node, uint64_t iobase, DeviceState *aic);

// Create DARTs for every /arm-io child whose compatible is dart,t8110 and
// was kept by dt_fixup (-enable ...).
void darwin_darts_create(struct dtree_node *dt_root, uint64_t iobase, DeviceState *aic);

// Translate a device virtual address for a stream id through the DART's
// page tables (as programmed by XNU). Returns false if not mapped.
bool darwin_dart_translate(DeviceState *dev, unsigned sid, uint64_t dva, uint64_t *pa);
