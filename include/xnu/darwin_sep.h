#pragma once

#include "qemu/osdep.h"
#include "hw/core/sysbus.h"
#include "xnu/apple_dtree.h"

#define TYPE_DARWIN_SEP "darwin-sep"

// Create the Secure Enclave emulation for /arm-io/sep if the device tree still
// carries its "compatible" (dt_fixup -enable sep), or when early iBoot has
// already proven that the physical SEP ASC exists by touching its reg[0]
// mailbox. reg[0] is mapped at iobase; the node's four "interrupts" are wired
// to the AIC; DMA goes through the DART named by the node's "iommu-parent".
/*
 * When sepfw is non-NULL, its complete container identity and length are the
 * fail-closed contract for the BOOT_IMG4 DMA transaction.
 */
// Returns NULL when neither condition enables the SEP.
DeviceState *darwin_sep_create(struct dtree_node *dt_root, uint64_t iobase,
                               DeviceState *aic, bool required_by_iboot,
                               const uint8_t *sepfw, size_t sepfw_len);
