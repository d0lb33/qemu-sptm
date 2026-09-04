#pragma once

#include "qemu/osdep.h"
#include "xnu/apple_dtree.h"

/*
 * Install the narrow d47 iBoot PMGR-to-CPM bootstrap transport model.
 * This is deliberately iBoot-only; direct boot keeps its existing mappings.
 */
void darwin_cpm_bootstrap_init(struct dtree_node *dt_root, uint64_t iobase);
