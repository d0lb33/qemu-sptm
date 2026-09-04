/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * d47 iBoot PMGR-to-CPM bootstrap transport.
 *
 * Static analysis of all three available d47 iBoot payloads establishes this
 * contract:
 *
 *   PMGR range 1 + 0x38074: source high word (32-bit read)
 *   PMGR range 1 + 0x38078: source low word  (32-bit read)
 *   cpu0 cpm-impl-reg + 0xc000: combined payload (64-bit write)
 *   cpu0 cpm-impl-reg + 0xc008: command 0x55a01 (64-bit write)
 *
 * iBoot does not branch on the source words, and neither iBoot nor the current
 * machine model reads the CPM tail.  Consequently the hardware value is not
 * observable in this model.  We use zero as the canonical representative of
 * that equivalence class, but do not report it as a silicon reset value or as
 * a success response.  The sink checks that iBoot transported the exact source
 * payload before accepting the command.  A future CPM consumer must replace
 * this abstraction with evidenced payload semantics before observing the
 * value.
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "system/memory.h"
#include "system/address-spaces.h"
#include "xnu/apple_dtree.h"
#include "xnu/darwin_cpm.h"

#define D47_PMGR_SOURCE_OFFSET UINT64_C(0x38074)
#define D47_PMGR_SOURCE_SIZE   UINT64_C(0x8)
#define D47_CPM_TAIL_OFFSET    UINT64_C(0xc000)
#define D47_CPM_TAIL_SIZE      UINT64_C(0x10)
#define D47_CPM_INIT_COMMAND   UINT64_C(0x55a01)
#define D47_CPM_CLEAR_COMMAND  UINT64_C(0x5a5a)

typedef struct DarwinCPMBootstrap {
    MemoryRegion source_mr;
    MemoryRegion sink_mr;
    uint64_t source;
    uint64_t sink;
    uint64_t command;
    bool sink_written;
} DarwinCPMBootstrap;

static uint64_t darwin_cpm_source_read(void *opaque, hwaddr offset,
                                       unsigned size)
{
    DarwinCPMBootstrap *s = opaque;

    if (size != 4 || (offset != 0 && offset != 4)) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "darwin-cpm: invalid source read offset=0x%" HWADDR_PRIx
                      " size=%u\n", offset, size);
        return 0;
    }

    /* iBoot places the first PMGR word in payload bits 63:32. */
    return offset == 0 ? s->source >> 32 : (uint32_t)s->source;
}

static void darwin_cpm_source_write(void *opaque, hwaddr offset,
                                    uint64_t value, unsigned size)
{
    qemu_log_mask(LOG_GUEST_ERROR,
                  "darwin-cpm: unexpected source write offset=0x%" HWADDR_PRIx
                  " value=0x%" PRIx64 " size=%u\n", offset, value, size);
}

static uint64_t darwin_cpm_sink_read(void *opaque, hwaddr offset,
                                     unsigned size)
{
    DarwinCPMBootstrap *s = opaque;

    if (size != 8 || (offset != 0 && offset != 8)) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "darwin-cpm: invalid sink read offset=0x%" HWADDR_PRIx
                      " size=%u\n", offset, size);
        return 0;
    }
    return offset == 0 ? s->sink : s->command;
}

static void darwin_cpm_sink_write(void *opaque, hwaddr offset,
                                  uint64_t value, unsigned size)
{
    DarwinCPMBootstrap *s = opaque;

    if (size != 8 || (offset != 0 && offset != 8)) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "darwin-cpm: invalid sink write offset=0x%" HWADDR_PRIx
                      " value=0x%" PRIx64 " size=%u\n",
                      offset, value, size);
        return;
    }

    if (offset == 0) {
        s->sink = value;
        s->sink_written = true;
        return;
    }

    if (value == D47_CPM_INIT_COMMAND) {
        if (!s->sink_written || s->sink != s->source) {
            error_report("darwin-cpm: init command without exact PMGR payload"
                         " transport (source=0x%016" PRIx64
                         " sink=0x%016" PRIx64 ")",
                         s->source, s->sink);
            return;
        }
        s->command = value;
        fprintf(stderr,
                "darwin-cpm: validated opaque PMGR-to-CPM payload transport;"
                " command=0x%" PRIx64 "\n", value);
        return;
    }

    if (value == D47_CPM_CLEAR_COMMAND && s->sink_written && s->sink == 0) {
        s->command = value;
        fprintf(stderr, "darwin-cpm: validated CPM clear command=0x%" PRIx64
                "\n", value);
        return;
    }

    error_report("darwin-cpm: unsupported command 0x%" PRIx64
                 " (sink=0x%016" PRIx64 ")", value, s->sink);
}

static const MemoryRegionOps darwin_cpm_source_ops = {
    .read = darwin_cpm_source_read,
    .write = darwin_cpm_source_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

static const MemoryRegionOps darwin_cpm_sink_ops = {
    .read = darwin_cpm_sink_read,
    .write = darwin_cpm_sink_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 8,
    .impl.max_access_size = 8,
    .valid.min_access_size = 8,
    .valid.max_access_size = 8,
    .valid.unaligned = false,
};

void darwin_cpm_bootstrap_init(struct dtree_node *dt_root, uint64_t iobase)
{
    struct dtree_node *pmgr = adt_find_node(dt_root, "arm-io/pmgr");
    struct dtree_node *cpu0 = adt_find_node(dt_root, "cpus/cpu0");
    struct adt_io_reg *pmgr_regs;
    struct adt_io_reg *cpm_regs;
    size_t pmgr_count;
    DarwinCPMBootstrap *s;
    uint64_t source_pa;
    uint64_t sink_pa;

    if (!pmgr || !cpu0) {
        error_report("darwin-cpm: d47 PMGR or cpu0 node is absent");
        exit(EXIT_FAILURE);
    }
    pmgr_regs = adt_get_prop_val(pmgr, "reg");
    cpm_regs = adt_get_prop_val(cpu0, "cpm-impl-reg");
    pmgr_count = adt_get_prop_len(pmgr, "reg") / sizeof(*pmgr_regs);
    if (!pmgr_regs || pmgr_count < 2 || !cpm_regs ||
        pmgr_regs[1].len < D47_PMGR_SOURCE_OFFSET + D47_PMGR_SOURCE_SIZE ||
        cpm_regs[0].len < D47_CPM_TAIL_OFFSET + D47_CPM_TAIL_SIZE) {
        error_report("darwin-cpm: device tree lacks the evidenced d47 apertures");
        exit(EXIT_FAILURE);
    }

    source_pa = iobase + pmgr_regs[1].base + D47_PMGR_SOURCE_OFFSET;
    sink_pa = cpm_regs[0].base + D47_CPM_TAIL_OFFSET;
    s = g_new0(DarwinCPMBootstrap, 1);

    memory_region_init_io(&s->source_mr, NULL, &darwin_cpm_source_ops, s,
                          "darwin-cpm-pmgr-source", D47_PMGR_SOURCE_SIZE);
    memory_region_add_subregion_overlap(get_system_memory(), source_pa,
                                        &s->source_mr, 10);
    memory_region_init_io(&s->sink_mr, NULL, &darwin_cpm_sink_ops, s,
                          "darwin-cpm-bootstrap-sink", D47_CPM_TAIL_SIZE);
    memory_region_add_subregion_overlap(get_system_memory(), sink_pa,
                                        &s->sink_mr, 10);

    fprintf(stderr,
            "darwin-cpm: opaque bootstrap bridge source=0x%" PRIx64
            " sink=0x%" PRIx64
            " representative=0 (not a hardware reset-value claim)\n",
            source_pa, sink_pa);
}
