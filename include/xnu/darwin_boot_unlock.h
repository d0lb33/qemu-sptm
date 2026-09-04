#pragma once

#include "qemu/osdep.h"
#include "xnu/apple_dtree.h"

/* Install d47 iBoot's fixed write-unlock transaction model. */
void darwin_boot_unlock_init(struct dtree_node *dt_root, uint64_t iobase);
