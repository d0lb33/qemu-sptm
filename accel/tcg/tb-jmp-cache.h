/*
 * The per-CPU TranslationBlock jump cache.
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef ACCEL_TCG_TB_JMP_CACHE_H
#define ACCEL_TCG_TB_JMP_CACHE_H

#include "qemu/rcu.h"
#include "exec/cpu-common.h"

/*
 * darwin-vm: overridable from the build (configure --extra-cflags=
 * -DTB_JMP_CACHE_BITS=N).  An idle iOS 27 guest has ~1.45M live TBs and
 * helper_lookup_tb_ptr was 13% of busy-vCPU host samples with the upstream
 * 4096-entry cache (docs/re/tcg-idle-profile.md); the size is a measured
 * trade-off, not a semantic change.
 */
#ifndef TB_JMP_CACHE_BITS
/*
 * 2026-09-07: 2^16 entries.  The measured loss of a 2^16 cache with the
 * upstream flush (docs/re/tcg-idle-profile.md, TCGB_3/4: early boot 9 s ->
 * 55 s) was the flush itself, a 1 MiB clear per TLB flush at ~6,500 flushes
 * per second.  tcg_flush_jmp_cache() now bumps an epoch instead (below), so
 * a flush costs one store whatever the size.
 */
#define TB_JMP_CACHE_BITS 14
#endif
#define TB_JMP_CACHE_SIZE (1 << TB_JMP_CACHE_BITS)

/*
 * Invalidated in parallel; all accesses to 'tb' must be atomic.
 * A valid entry is read/written by a single CPU, therefore there is
 * no need for qatomic_rcu_read() and pc is always consistent with a
 * non-NULL value of 'tb'.  Strictly speaking pc is only needed for
 * CF_PCREL, but it's used always for simplicity.
 *
 * darwin-vm epoch flush: an entry hits only when its epoch equals the
 * cache's.  tcg_flush_jmp_cache() increments the cache epoch (clearing for
 * real only on wraparound), which is what the TLB-flush callers need: they
 * run on the owning vCPU thread, so the new epoch is visible to the next
 * lookup.  Specific-entry invalidation (tb_jmp_cache_clear_page,
 * tb_jmp_cache_inval_tb) still stores NULL, and a stale hit on an
 * invalidated TB is rejected by tb_lookup's CF_INVALID cflags compare as
 * before.
 */
typedef struct CPUJumpCache {
    struct rcu_head rcu;
    uint32_t epoch;
    struct {
        TranslationBlock *tb;
        vaddr pc;
        uint32_t epoch;
    } array[TB_JMP_CACHE_SIZE];
} CPUJumpCache;

#endif /* ACCEL_TCG_TB_JMP_CACHE_H */
