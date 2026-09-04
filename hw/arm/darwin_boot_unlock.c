/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * d47 early write-unlock transaction.
 *
 * Three independent d47 iBoot builds execute the same sequence: preserve the
 * word at arm-io + 0xf98c0010, set bit 0, write 0xa55ac33c to arm-io +
 * 0xf9881d04, then restore the preserved word.  There is no completion read,
 * status value, or conditional branch.  This model validates that transaction
 * and supplies only ordinary register storage; it does not invent a success
 * result or assign an undocumented device name to either address.
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "system/memory.h"
#include "system/address-spaces.h"
#include "xnu/apple_dtree.h"
#include "xnu/darwin_boot_unlock.h"

#define D47_GATE_OFFSET UINT64_C(0xf98c0010)
#define D47_KEY_OFFSET  UINT64_C(0xf9881d04)
#define D47_UNLOCK_KEY  UINT32_C(0xa55ac33c)

typedef enum DarwinBootUnlockPhase {
    D47_UNLOCK_IDLE,
    D47_UNLOCK_GATE_OPEN,
    D47_UNLOCK_KEY_WRITTEN,
    D47_UNLOCK_COMPLETE,
} DarwinBootUnlockPhase;

typedef struct DarwinBootUnlock {
    MemoryRegion gate_mr;
    MemoryRegion key_mr;
    uint32_t gate;
    uint32_t saved_gate;
    DarwinBootUnlockPhase phase;
} DarwinBootUnlock;

static void darwin_boot_unlock_error(const char *what, hwaddr offset,
                                     uint64_t value, unsigned size)
{
    error_report("darwin-boot-unlock: invalid %s offset=0x%" HWADDR_PRIx
                 " value=0x%" PRIx64 " size=%u", what, offset, value, size);
}

static uint64_t darwin_boot_gate_read(void *opaque, hwaddr offset,
                                      unsigned size)
{
    DarwinBootUnlock *s = opaque;

    if (offset != 0 || size != 4) {
        darwin_boot_unlock_error("gate read", offset, 0, size);
        return 0;
    }
    return s->gate;
}

static void darwin_boot_gate_write(void *opaque, hwaddr offset,
                                   uint64_t value, unsigned size)
{
    DarwinBootUnlock *s = opaque;
    uint32_t word = value;

    if (offset != 0 || size != 4) {
        darwin_boot_unlock_error("gate write", offset, value, size);
        return;
    }

    if (s->phase == D47_UNLOCK_IDLE && word == (s->gate | 1)) {
        s->saved_gate = s->gate;
        s->gate = word;
        s->phase = D47_UNLOCK_GATE_OPEN;
        return;
    }
    if (s->phase == D47_UNLOCK_KEY_WRITTEN && word == s->saved_gate) {
        s->gate = word;
        s->phase = D47_UNLOCK_COMPLETE;
        fprintf(stderr,
                "darwin-boot-unlock: validated gate/key/restore transaction;"
                " key=0x%08x\n", D47_UNLOCK_KEY);
        return;
    }

    darwin_boot_unlock_error("gate write", offset, value, size);
}

static uint64_t darwin_boot_key_read(void *opaque, hwaddr offset,
                                     unsigned size)
{
    darwin_boot_unlock_error("unexpected key read", offset, 0, size);
    return 0;
}

static void darwin_boot_key_write(void *opaque, hwaddr offset,
                                  uint64_t value, unsigned size)
{
    DarwinBootUnlock *s = opaque;

    if (offset != 0 || size != 4 || value != D47_UNLOCK_KEY ||
        s->phase != D47_UNLOCK_GATE_OPEN || !(s->gate & 1)) {
        darwin_boot_unlock_error("key write", offset, value, size);
        return;
    }
    s->phase = D47_UNLOCK_KEY_WRITTEN;
}

static const MemoryRegionOps darwin_boot_gate_ops = {
    .read = darwin_boot_gate_read,
    .write = darwin_boot_gate_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

static const MemoryRegionOps darwin_boot_key_ops = {
    .read = darwin_boot_key_read,
    .write = darwin_boot_key_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

void darwin_boot_unlock_init(struct dtree_node *dt_root, uint64_t iobase)
{
    const char *target = adt_get_prop_val(dt_root, "target-type");
    DarwinBootUnlock *s;

    if (!target || strcmp(target, "D47") != 0) {
        error_report("darwin-boot-unlock: transaction is evidenced only for D47");
        exit(EXIT_FAILURE);
    }

    s = g_new0(DarwinBootUnlock, 1);
    memory_region_init_io(&s->gate_mr, NULL, &darwin_boot_gate_ops, s,
                          "darwin-boot-unlock-gate", 4);
    memory_region_add_subregion_overlap(get_system_memory(),
                                        iobase + D47_GATE_OFFSET,
                                        &s->gate_mr, 10);
    memory_region_init_io(&s->key_mr, NULL, &darwin_boot_key_ops, s,
                          "darwin-boot-unlock-key", 4);
    memory_region_add_subregion_overlap(get_system_memory(),
                                        iobase + D47_KEY_OFFSET,
                                        &s->key_mr, 10);
}
