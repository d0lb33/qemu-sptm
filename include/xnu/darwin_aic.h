#pragma once

#include "qemu/osdep.h"
#include "hw/core/sysbus.h"
#include "xnu/apple_dtree.h"

#define TYPE_DARWIN_AIC "darwin-aic"

// Create the Apple Interrupt Controller (AIC v2 / v3) described by the
// /arm-io/aic device tree node, map it at its "reg" address (+iobase) and
// connect its output to the CPU's IRQ line.
DeviceState *darwin_aic_create(struct dtree_node *dt_root, uint64_t iobase, qemu_irq cpu_irq);

// Get the input line for an AIC vector number (as found in a node's
// "interrupts" property).
qemu_irq darwin_aic_get_irq(DeviceState *aic, uint32_t vector);
