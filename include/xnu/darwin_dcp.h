#pragma once

#include "qemu/osdep.h"
#include "hw/core/sysbus.h"
#include "xnu/apple_dtree.h"

// Create the DCP (display coprocessor) emulation for /arm-io/dcp if the
// device tree still carries its "compatible" (dt_fixup -enable dcp).
// Returns NULL if the DCP is not enabled in this device tree.
DeviceState *darwin_dcp_create(struct dtree_node *dt_root, uint64_t iobase, DeviceState *aic);
