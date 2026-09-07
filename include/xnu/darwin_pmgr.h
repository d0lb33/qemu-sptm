#pragma once
#include "qemu/osdep.h"
#include "xnu/apple_dtree.h"

/*
 * Apple PMGR power-state registers for /arm-io/pmgr (darwin_pmgr.c).
 * Returns false, and maps nothing, unless dt_fixup ran with -enable pmgr.
 * DARWIN_PMGR_DEBUG=1 logs every access.
 */
bool darwin_pmgr_create(struct dtree_node *dt_root, uint64_t iobase);
