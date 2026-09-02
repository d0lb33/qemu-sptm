#pragma once

#include "qemu/osdep.h"
#include "hw/core/sysbus.h"
#include "xnu/apple_dtree.h"

#define TYPE_DARWIN_SEP "darwin-sep"

// Create the Secure Enclave emulation for /arm-io/sep if the device tree still
// carries its "compatible" (dt_fixup -enable sep). reg[0] is the ASC wrapper +
// mailbox and is mapped at iobase; the node's four "interrupts" are wired to
// the AIC; DMA goes through the DART named by the node's "iommu-parent".
// Returns NULL if the SEP is not enabled in this device tree.
DeviceState *darwin_sep_create(struct dtree_node *dt_root, uint64_t iobase, DeviceState *aic);
