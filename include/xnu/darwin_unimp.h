#pragma once
#include "qemu/osdep.h"
#include "xnu/apple_dtree.h"
// Back every /arm-io range with a logging catch-all so unmodelled MMIO reads
// as zero instead of raising external aborts. DARWIN_UNIMP_DEBUG=1 logs accesses.
void darwin_unimp_init(struct dtree_node *dt_root, uint64_t iobase);
