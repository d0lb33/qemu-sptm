#pragma once

#include "qemu/osdep.h"
#include "xnu/apple_dtree.h"

/* Install narrowly evidenced d47 iBoot PMGR state. */
void darwin_pmgr_iboot_init(struct dtree_node *dt_root, uint64_t iobase);
