#pragma once

#include "qemu/osdep.h"
#include "hw/arm/boot.h"
#include "cpu.h"
#include "xnu/apple_dtree.h"
#include "hw/arm/apple_amcc.h"
#include "xnu/boot/xnuboot.h"

void apple_regs_init(ARMCPU *cpu, AMCCState *amcc, struct dtree_node *dt_root, struct xnu_boot_info *info);
