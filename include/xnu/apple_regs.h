#pragma once

#include "qemu/osdep.h"
#include "hw/arm/boot.h"
#include "cpu.h"
#include "xnu/apple_dtree.h"
#include "hw/arm/apple_amcc.h"
#include "migration/vmstate.h"
#include "xnu/boot/xnuboot.h"

void apple_regs_init(ARMCPU *cpu, AMCCState *amcc, struct dtree_node *dt_root, struct xnu_boot_info *info);
void apple_regs_pv_cpu_handoff(CPUARMState *dst, CPUARMState *src);

extern const VMStateDescription vmstate_apple_cpu;
