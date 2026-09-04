#pragma once

#include "cpu.h"
#include "xnu/apple_dtree.h"
#include "xnu/boot/xnuboot.h"

#define DARWIN_MAX_CPUS 6

void darwin_smp_init(ARMCPU **cpus, unsigned count,
                     struct dtree_node *dt, struct xnu_boot_info *info);
void darwin_smp_register_cpu(ARMCPU *cpu);
void darwin_smp_connect_cpu(ARMCPU *cpu);
void darwin_smp_reset(void);
