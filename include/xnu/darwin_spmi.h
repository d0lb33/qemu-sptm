#pragma once

#include "qemu/osdep.h"
#include "hw/core/sysbus.h"
#include "xnu/apple_dtree.h"

#define TYPE_DARWIN_SPMI "darwin-spmi"
#define TYPE_DARWIN_PMU  "darwin-pmu"

/*
 * A slave on the modelled SPMI bus.  The controller decodes the request
 * word (see darwin_spmi.c) and hands the slave a plain register-space
 * transfer.  Both callbacks return the number of bytes acknowledged; a
 * short count is reported to the guest as a NAK on the remaining bytes.
 */
typedef struct DarwinSPMISlaveOps {
    int (*read)(void *opaque, uint16_t addr, uint8_t *buf, unsigned len);
    int (*write)(void *opaque, uint16_t addr, const uint8_t *buf, unsigned len);
} DarwinSPMISlaveOps;

/*
 * Create the AppleSPMIController Gen3 model for /arm-io/nub-spmi0 and every
 * PMU child it describes (compatible "pmu,spmi").  Returns NULL, and creates
 * nothing, unless dt_fixup was run with -enable spmi (the node keeps its
 * "compatible" only then).
 */
DeviceState *darwin_spmi_create(struct dtree_node *dt_root, uint64_t iobase, DeviceState *aic);

void darwin_spmi_attach_slave(DeviceState *ctrl, unsigned sid,
                              const DarwinSPMISlaveOps *ops, void *opaque);

/* Slave-side interrupt line: index into the controller's own interrupt space
 * (a child node's "interrupts" cell), bank = index >> 5, bit = index & 31. */
qemu_irq darwin_spmi_get_irq(DeviceState *ctrl, unsigned index);

DeviceState *darwin_pmu_create(struct dtree_node *node, DeviceState *spmi);
