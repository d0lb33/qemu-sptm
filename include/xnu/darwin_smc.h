#pragma once

#include "qemu/osdep.h"
#include "hw/core/sysbus.h"
#include "xnu/apple_dtree.h"

/*
 * SMC coprocessor: the generic ASC/RTKit mailbox for /arm-io/smc plus the
 * SMC key endpoint (RTKit endpoint 0x20, RTBuddy nub "SMCEndpoint1") that
 * AppleSMCKeysEndpoint binds.  Returns NULL when dt_fixup did not run with
 * -enable smc.  See darwin_smc.c for the traced protocol and key table.
 */
DeviceState *darwin_smc_create(struct dtree_node *dt_root, uint64_t iobase, DeviceState *aic);
