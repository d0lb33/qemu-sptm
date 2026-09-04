#pragma once

#include "qemu/osdep.h"
#include "xnu/apple_dtree.h"

/* Install narrowly evidenced d47 iBoot GPIO capability state. */
void darwin_gpio_iboot_init(struct dtree_node *dt_root, uint64_t iobase);
