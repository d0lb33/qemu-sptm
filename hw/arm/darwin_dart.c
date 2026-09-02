/*
 * darwin-dart: Apple DART IOMMU (t8110 generation) register model
 *
 *   0x000  PARAMS1   page shift in bits [27:24]
 *   0x004  PARAMS2   bit 0 = bypass support
 *   0x008  PARAMS3   pa width [29:24], va width [21:16], version [15:0]
 *   0x00c  PARAMS4   num clients [24:16], num sids [8:0]
 *   0x080  TLB_CMD   bit 31 busy (self clearing), op [10:8], stream [7:0]
 *   0x100  ERROR     bit 31 flag, stream [27:20], code [14:0]   (w1c)
 *   0x104  ERROR_MASK
 *   0x170  ERROR_ADDR_LO / 0x174 ERROR_ADDR_HI
 *   0x1c0  ERROR_STREAMS
 *   0x200  PROTECT / 0x204 UNPROTECT / 0x208 PROTECT_LOCK
 *   0xc00  ENABLE_STREAMS[8]  (w1s)   0xc20 DISABLE_STREAMS[8] (w1c)
 *   0x1000 TCR[sid]           bit 0 translate, bit 1 bypass, bit 3 four level,
 *                             bit 7 remap enable, bits [12:8] remap target sid
 *                             (that width is from the live t8140 trace:
 *                              TCR[27]=TCR[28]=0x1780 remaps both to sid 0x17,
 *                              matching the dart-dcp node's remap=<0x171b 0x171c>;
 *                              Linux calls it GENMASK(11,8), apple-dart.c:136)
 *   0x1400 TTBR[sid][n]       bit 0 valid, address >> 14 in bits [..:2].
 *                             n = ttbr-count, 1 on t8110 (apple-dart.c:1324),
 *                             4 on t8020. Group per sid is contiguous:
 *                             offset = 0x1400 + ((n * sid) << 2).
 *
 * Page tables are the 16K "L2/L3" format shared with the SMMU-like
 * t8020 DARTs: each level is a 16K page of 64-bit entries, entry bit 0 =
 * valid, address in bits [..:14] (PTE: [..:14] page, plus sub-page start/end
 * fields in bits [63:52]/[51:40] for L3 which we ignore).
 *
 * Reference: Linux drivers/iommu/apple-dart.c (apple,t8110-dart).
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "hw/core/sysbus.h"
#include "hw/core/irq.h"
#include "hw/core/qdev-properties.h"
#include "system/memory.h"
#include "system/address-spaces.h"
#include "exec/memattrs.h"
#include "xnu/boot/xnuboot.h"
#include "xnu/apple_dtree.h"
#include "xnu/darwin_aic.h"
#include "xnu/darwin_dart.h"

OBJECT_DECLARE_SIMPLE_TYPE(DarwinDARTState, DARWIN_DART)

#define DART_PARAMS1        0x000
#define DART_PARAMS2        0x004
#define DART_PARAMS3        0x008
// PARAMS3[15:0]: major in [15:8], minor in [7:0]
#define DART_VERSION_2_0    0x0200
#define DART_PARAMS4        0x00c
#define DART_TLB_CMD        0x080
#define DART_TLB_CMD_BUSY   BIT(31)
#define DART_ERROR          0x100
#define DART_ERROR_MASK     0x104
#define DART_ERROR_ADDR_LO  0x170
#define DART_ERROR_ADDR_HI  0x174
#define DART_ERROR_STREAMS  0x1c0
#define DART_PROTECT        0x200
#define DART_UNPROTECT      0x204
#define DART_PROTECT_LOCK   0x208
#define DART_ENABLE_STREAMS 0xc00
#define DART_DISABLE_STREAMS 0xc20
#define DART_TCR            0x1000
#define DART_TCR_TRANSLATE  BIT(0)
#define DART_TCR_BYPASS     BIT(1)
#define DART_TCR_FOUR_LEVEL BIT(3)
// TTBR[sid][idx] lives at TTBR + ((ttbr_count * sid) << 2), i.e. the whole
// per-sid group is contiguous and the *number of TTBRs per sid is a property
// of the DART generation*: 4 on t8020/t6000, but 1 on t8110 (Linux
// drivers/iommu/apple-dart.c:150-151 DART_TTBR() and :1324 .ttbr_count = 1).
// Getting this wrong is silent: writes land in another sid's slot and every
// translation fails with an all-zero TTBR, which is exactly what happened
// here before -- XNU's `write 0x145c <- 0x1001a505` is TTBR[23] with stride
// 4, and the 4-per-sid layout filed it under sid 5.
// Page table entry, t8110 generation (m1n1 hw/dart8110.py:112-119):
//   [63:52] sub-page start   [51:40] sub-page end (both ignored here)
//   [37:10] OFFSET = address >> 14      [3] rdprot [2] wrprot [1] uncacheable
//   [0]     VALID
// t8020/t6000 put OFFSET at [39:14]/[39:10] instead (dart8020.py:44-56), so
// this decode is generation specific.
#define DART_PTE_VALID          BIT_ULL(0)
#define DART_PTE_OFFSET_SHIFT   10
#define DART_PTE_OFFSET_MASK    ((1ULL << 28) - 1)

#define DART_TTBR           0x1400
#define DART_TTBR_VALID     BIT(0)
#define DART_TTBR_SHIFT     14
#define DART_TTBR_ADDR_FIELD_SHIFT 2
#define DART_MAX_SIDS       256
#define DART_MAX_TTBRS_PER_SID 4

struct DarwinDARTState {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    qemu_irq irq;
    char *name;
    uint32_t mmio_size;
    uint32_t num_sids;
    uint32_t page_shift;
    uint32_t va_width, pa_width;

    uint32_t streams_enabled[8];
    uint32_t tcr[DART_MAX_SIDS];
    uint32_t ttbr[DART_MAX_SIDS][DART_MAX_TTBRS_PER_SID];
    uint32_t ttbr_count;
    bool walk_warned[DART_MAX_SIDS];
    uint32_t protect;
    uint32_t error, error_mask;
    uint32_t *misc;
    bool debug;
};

static uint64_t dart_read(void *opaque, hwaddr offset, unsigned size) {
    DarwinDARTState *s = opaque;
    uint32_t val = 0;

    if (offset == DART_PARAMS1) {
        val = (s->page_shift & 0xf) << 24;
    } else if (offset == DART_PARAMS2) {
        val = 1;    // bypass supported
    } else if (offset == DART_PARAMS3) {
        // The version in bits [15:0] is load bearing: SPTM and XNU both
        // classify the DART by it and then require the device tree's
        // vm-base/vm-size to fall inside a window hardcoded per generation.
        //
        //   1.x  ->  pages [0,          0x400000)    = bytes [0,    2^36)
        //   2.x  ->  pages [0x4000000,  0x10000000)  = bytes [2^40, 2^42)
        //
        // (t8110dart_init_instance, sptm 0xfffffff0270c5878-0xfffffff0270c5998:
        //  it panics "Invalid VM page limits" unless required_lo <= dt_lo and
        //  dt_hi <= required_hi.) Every dart node on t8140 uses vm-base >=
        //  0x10000000000, so they are all generation 2 and reporting 1.0 makes
        //  SPTM reject the tree.
        //
        // XNU's AppleT8110DART accepts only 1.0, 1.1 and 2.0 through 2.4
        // (bootkc 0xfffffff00970853c, else "Unsupported DART version"), so 2.0
        // is the safe choice: SPTM also knows 3.x, but XNU does not.
        //
        // The widths are separate and feed only SPTM's "Inconsistent hardware
        // definition" check, which needs (1 << va_width) >> 14 > required_lo.
        val = ((uint32_t)s->pa_width << 24) | ((uint32_t)s->va_width << 16) | DART_VERSION_2_0;
    } else if (offset == DART_PARAMS4) {
        val = ((s->num_sids & 0x1ff) << 16) | (s->num_sids & 0x1ff);
    } else if (offset == DART_TLB_CMD) {
        val = 0;    // never busy
    } else if (offset == DART_ERROR) {
        val = s->error;
    } else if (offset == DART_ERROR_MASK) {
        val = s->error_mask;
    } else if (offset == DART_PROTECT || offset == DART_UNPROTECT || offset == DART_PROTECT_LOCK) {
        val = s->protect;
    } else if (offset >= DART_ENABLE_STREAMS && offset < DART_ENABLE_STREAMS + 0x20) {
        val = s->streams_enabled[(offset - DART_ENABLE_STREAMS) / 4];
    } else if (offset >= DART_DISABLE_STREAMS && offset < DART_DISABLE_STREAMS + 0x20) {
        val = s->streams_enabled[(offset - DART_DISABLE_STREAMS) / 4];
    } else if (offset >= DART_TCR && offset < DART_TCR + DART_MAX_SIDS * 4) {
        val = s->tcr[(offset - DART_TCR) / 4];
    } else if (offset >= DART_TTBR && offset < DART_TTBR + DART_MAX_SIDS * s->ttbr_count * 4) {
        unsigned idx = (offset - DART_TTBR) / 4;
        val = s->ttbr[idx / s->ttbr_count][idx % s->ttbr_count];
    } else if (offset + 4 <= s->mmio_size) {
        val = s->misc[offset / 4];
    }

    if (s->debug) fprintf(stderr, "dart(%s): read  0x%04" HWADDR_PRIx " -> 0x%08x\n", s->name, offset, val);
    return val;
}

static void dart_write(void *opaque, hwaddr offset, uint64_t value, unsigned size) {
    DarwinDARTState *s = opaque;
    uint32_t val = value;

    if (s->debug) fprintf(stderr, "dart(%s): write 0x%04" HWADDR_PRIx " <- 0x%08x\n", s->name, offset, val);

    if (offset == DART_TLB_CMD) {
        // flush completes instantly; nothing to invalidate in this model
    } else if (offset == DART_ERROR) {
        s->error &= ~val;
    } else if (offset == DART_ERROR_MASK) {
        s->error_mask = val;
    } else if (offset == DART_PROTECT) {
        s->protect |= val;
    } else if (offset == DART_UNPROTECT) {
        s->protect &= ~val;
    } else if (offset == DART_PROTECT_LOCK) {
        s->protect |= val;
    } else if (offset >= DART_ENABLE_STREAMS && offset < DART_ENABLE_STREAMS + 0x20) {
        s->streams_enabled[(offset - DART_ENABLE_STREAMS) / 4] |= val;
    } else if (offset >= DART_DISABLE_STREAMS && offset < DART_DISABLE_STREAMS + 0x20) {
        s->streams_enabled[(offset - DART_DISABLE_STREAMS) / 4] &= ~val;
    } else if (offset >= DART_TCR && offset < DART_TCR + DART_MAX_SIDS * 4) {
        s->tcr[(offset - DART_TCR) / 4] = val;
    } else if (offset >= DART_TTBR && offset < DART_TTBR + DART_MAX_SIDS * s->ttbr_count * 4) {
        unsigned idx = (offset - DART_TTBR) / 4;
        s->ttbr[idx / s->ttbr_count][idx % s->ttbr_count] = val;
    } else if (offset + 4 <= s->mmio_size) {
        s->misc[offset / 4] = val;
    }
}

static const MemoryRegionOps dart_ops = {
    .read = dart_read,
    .write = dart_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 8,
};

// Registry of the DARTs we created, keyed by device tree node name. A
// coprocessor personality (darwin_dcp.c) needs the DeviceState of the DART
// its DMA goes through, and darwin.c creates every DART before any
// personality, so a simple by-name lookup is enough and keeps the machine
// file out of the business of plumbing IOMMUs around.
static GHashTable *dart_registry;

DeviceState *darwin_dart_find(const char *name) {
    if (!dart_registry || !name) return NULL;
    return g_hash_table_lookup(dart_registry, name);
}

static void darwin_dart_register(const char *name, DeviceState *dev) {
    if (!dart_registry) dart_registry = g_hash_table_new(g_str_hash, g_str_equal);
    g_hash_table_insert(dart_registry, g_strdup(name), dev);
}

void darwin_dart_dump_sid(DeviceState *dev, unsigned sid) {
    DarwinDARTState *s = DARWIN_DART(dev);
    if (sid >= s->num_sids) {
        fprintf(stderr, "dart(%s): sid %u out of range (num-sids %u)\n", s->name, sid, s->num_sids);
        return;
    }
    fprintf(stderr, "dart(%s): sid %u enabled=%u tcr=0x%08x (translate=%u bypass=%u four-level=%u) "
            "ttbr=[0x%08x 0x%08x 0x%08x 0x%08x]\n",
            s->name, sid, (s->streams_enabled[sid / 32] >> (sid % 32)) & 1, s->tcr[sid],
            !!(s->tcr[sid] & DART_TCR_TRANSLATE), !!(s->tcr[sid] & DART_TCR_BYPASS),
            !!(s->tcr[sid] & DART_TCR_FOUR_LEVEL),
            s->ttbr[sid][0], s->ttbr[sid][1], s->ttbr[sid][2], s->ttbr[sid][3]);
    fprintf(stderr, "dart(%s): (ttbr-count %u, page-shift %u, va-width %u)\n",
            s->name, s->ttbr_count, s->page_shift, s->va_width);
}

bool darwin_dart_translate(DeviceState *dev, unsigned sid, uint64_t dva, uint64_t *pa) {
    DarwinDARTState *s = DARWIN_DART(dev);
    if (sid >= s->num_sids) return false;
    uint32_t tcr = s->tcr[sid];
    if (tcr & DART_TCR_BYPASS) {
        *pa = dva;
        return true;
    }
    if (!(tcr & DART_TCR_TRANSLATE)) return false;

    /*
     * t8110 walk, from m1n1 proxyclient/m1n1/hw/dart8110.py (DART8110.
     * iotranslate, :350-410 and the PTE/R_TTBR registers at :103-119):
     *
     *   PAGE_BITS 14, IDX_BITS 11, L0_OFF 36, L1_OFF 25, L2_OFF 14
     *   TTBR.ADDR  bits [29:2]  = table address >> 14 (a page number)
     *   PTE.OFFSET bits [37:10] = next table / page address >> 14
     *   PTE.VALID  bit 0
     *
     * Two things here bit us before and are worth stating plainly:
     *
     *  - The PTE address field is NOT the address in place. It is a page
     *    number at bit 10, so decoding it as `pte & ~page_mask` (the t8020
     *    layout, where OFFSET is bits [39:14]) yields an address 16x too
     *    small. m1n1 has separate PTE classes for exactly this reason:
     *    PTE_T8020.OFFSET = 39,14 vs. DART8110 PTE.OFFSET = 37,10.
     *  - Without FOUR_LEVELS the hardware masks the VA to 36 bits
     *    (dart8110.py:365 `start = start & 0xfffffffff`), so the DCP's
     *    vm-base of 0x10000000000 aliases down onto the low end of the same
     *    tables. That is not a bug to work around: XNU programs the tables
     *    the same way, so masking here is what makes us agree with it.
     */
    const unsigned shift = s->page_shift;                  // 14
    const unsigned bits_per_level = shift - 3;             // 11
    const uint64_t page_mask = (1ULL << shift) - 1;
    unsigned levels = (tcr & DART_TCR_FOUR_LEVEL) ? 4 : 3;
    unsigned va_bits = shift + bits_per_level * (levels - 1);
    // With several TTBRs per sid (t8020) the bits above the table's reach
    // select between them, LPAE-concatenation style. t8110 has one, so those
    // bits are simply dropped.
    unsigned ttbr_idx = 0;
    if (s->ttbr_count > 1) {
        ttbr_idx = (unsigned)((dva >> va_bits) & (s->ttbr_count - 1));
        va_bits += ctz32(s->ttbr_count);
    }
    dva &= (va_bits >= 64) ? ~0ULL : ((1ULL << va_bits) - 1);
    uint32_t ttbr = s->ttbr[sid][ttbr_idx];
    if (!(ttbr & DART_TTBR_VALID)) return false;

    uint64_t table = ((uint64_t)(ttbr >> DART_TTBR_ADDR_FIELD_SHIFT)) << DART_TTBR_SHIFT;
    for (int lvl = levels - 2; lvl >= 0; lvl--) {
        unsigned idx = (dva >> (shift + bits_per_level * lvl)) & ((1u << bits_per_level) - 1);
        uint64_t pte = 0;
        address_space_read(&address_space_memory, table + idx * 8, MEMTXATTRS_UNSPECIFIED, &pte, 8);
        if (s->debug) {
            fprintf(stderr, "dart(%s): walk sid %u dva 0x%" PRIx64 " L%d table 0x%" PRIx64
                    " idx %u pte 0x%016" PRIx64 "\n", s->name, sid, dva, lvl, table, idx, pte);
        }
        if (!(pte & DART_PTE_VALID)) {
            // One-shot, so a driver that polls an unmapped address cannot
            // drown the log. Says which level, which entry and what was in
            // it, which is the difference between "the DART is misprogrammed"
            // and "this model walks the table wrong".
            if (!s->walk_warned[sid]) {
                s->walk_warned[sid] = true;
                fprintf(stderr, "dart(%s): sid %u dva 0x%" PRIx64 " unmapped: level %d entry %u "
                        "at 0x%" PRIx64 " reads 0x%016" PRIx64 " (valid bit clear)\n",
                        s->name, sid, dva, lvl, idx, table + idx * 8, pte);
            }
            return false;
        }
        table = ((pte >> DART_PTE_OFFSET_SHIFT) & DART_PTE_OFFSET_MASK) << shift;
    }
    *pa = table | (dva & page_mask);
    return true;
}

static void darwin_dart_realize(DeviceState *dev, Error **errp) {
    DarwinDARTState *s = DARWIN_DART(dev);
    if (!s->mmio_size) {
        error_setg(errp, "darwin-dart: no mmio size");
        return;
    }
    if (!s->num_sids || s->num_sids > DART_MAX_SIDS) s->num_sids = 16;
    if (!s->page_shift) s->page_shift = 14;
    if (!s->ttbr_count || s->ttbr_count > DART_MAX_TTBRS_PER_SID) s->ttbr_count = 1;
    s->misc = g_new0(uint32_t, s->mmio_size / 4);
    s->debug = getenv("DARWIN_DART_DEBUG") != NULL;
    memory_region_init_io(&s->iomem, OBJECT(s), &dart_ops, s, "darwin-dart", s->mmio_size);
    sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->iomem);
    sysbus_init_irq(SYS_BUS_DEVICE(dev), &s->irq);
}

static const Property darwin_dart_properties[] = {
    DEFINE_PROP_STRING("name", DarwinDARTState, name),
    DEFINE_PROP_UINT32("mmio-size", DarwinDARTState, mmio_size, 0),
    DEFINE_PROP_UINT32("num-sids", DarwinDARTState, num_sids, 16),
    DEFINE_PROP_UINT32("page-shift", DarwinDARTState, page_shift, 14),
    DEFINE_PROP_UINT32("va-width", DarwinDARTState, va_width, 42),
    DEFINE_PROP_UINT32("pa-width", DarwinDARTState, pa_width, 42),
    // 1 for dart,t8110 (apple-dart.c:1324); t8020-era DARTs use 4.
    DEFINE_PROP_UINT32("ttbr-count", DarwinDARTState, ttbr_count, 1),
};

static void darwin_dart_class_init(ObjectClass *klass, const void *data) {
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = darwin_dart_realize;
    dc->desc = "Apple DART IOMMU (t8110)";
    device_class_set_props(dc, darwin_dart_properties);
    dc->user_creatable = false;
}

static const TypeInfo darwin_dart_info = {
    .name          = TYPE_DARWIN_DART,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(DarwinDARTState),
    .class_init    = darwin_dart_class_init,
};

static void darwin_dart_register_types(void) {
    type_register_static(&darwin_dart_info);
}

type_init(darwin_dart_register_types)

/* ---------------- device tree glue ---------------- */

DeviceState *darwin_dart_create(struct dtree_node *node, uint64_t iobase, DeviceState *aic) {
    struct adt_io_reg *reg = adt_get_prop_val(node, "reg");
    const char *name = adt_get_prop_val(node, "name");
    uint32_t *sid_count = adt_get_prop_val(node, "sid-count");
    uint32_t *page_size = adt_get_prop_val(node, "page-size");
    uint32_t *irqs = adt_get_prop_val(node, "interrupts");

    DeviceState *dev = qdev_new(TYPE_DARWIN_DART);
    qdev_prop_set_string(dev, "name", name);
    qdev_prop_set_uint32(dev, "mmio-size", reg[0].len);
    if (sid_count) qdev_prop_set_uint32(dev, "num-sids", *sid_count);
    // Only "dart,t8110" reaches darwin_darts_create(), and that generation has
    // exactly one TTBR per stream (apple-dart.c:1324). Spelled out here so a
    // future t8020-style node can set 4 without touching the model.
    qdev_prop_set_uint32(dev, "ttbr-count", 1);
    if (page_size && *page_size) qdev_prop_set_uint32(dev, "page-shift", ctz32(*page_size));

    // Advertise a VA width that covers the largest vm-base + vm-size the node
    // asks for. SPTM checks this and panics otherwise.
    uint64_t top = 0;
    uint64_t *vm_base = adt_get_prop_val(node, "vm-base");
    uint64_t *vm_size = adt_get_prop_val(node, "vm-size");
    if (vm_base && vm_size) top = *vm_base + *vm_size;
    unsigned va_bits = 42;
    while (va_bits < 64 && (top >= (1ULL << va_bits))) va_bits++;
    qdev_prop_set_uint32(dev, "va-width", va_bits);

    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);
    sysbus_realize_and_unref(sbd, &error_fatal);
    sysbus_mmio_map(sbd, 0, reg[0].base + iobase);
    if (aic && irqs) sysbus_connect_irq(sbd, 0, darwin_aic_get_irq(aic, irqs[0]));
    darwin_dart_register(name, dev);
    fprintf(stderr, "darwin-dart: %s at 0x%" PRIx64 " (%u sids)\n", name, reg[0].base + iobase, sid_count ? *sid_count : 16);
    return dev;
}

// Walk /arm-io children; darts still carrying a compatible were selected by dt_fixup
void darwin_darts_create(struct dtree_node *dt_root, uint64_t iobase, DeviceState *aic) {
    struct dtree_node *arm_io = adt_find_node(dt_root, "arm-io");
    // apple_dtree.c has no child iterator; walk by re-finding known names would be
    // fragile, so iterate the raw node layout here.
    struct dtree_prop { char name[32]; uint32_t length; };
    uint8_t *p = (uint8_t *)(arm_io + 1);
    for (uint32_t i = 0; i < arm_io->nProperties; i++) {
        struct dtree_prop *pr = (struct dtree_prop *)p;
        p += sizeof(*pr) + ((pr->length & ~0x80000000u) + 3 & ~3u);
    }
    for (uint32_t c = 0; c < arm_io->nChildren; c++) {
        struct dtree_node *child = (struct dtree_node *)p;
        const char *compat = adt_get_prop_val(child, "compatible");
        const char *type = adt_get_prop_val(child, "device_type");
        if (compat && type && !strcmp(type, "dart") && !strncmp(compat, "dart,t8110", 10)) {
            darwin_dart_create(child, iobase, aic);
        }
        // advance to next sibling: skip props then children recursively
        uint8_t *q = (uint8_t *)(child + 1);
        for (uint32_t i = 0; i < child->nProperties; i++) {
            struct dtree_prop *pr = (struct dtree_prop *)q;
            q += sizeof(*pr) + ((pr->length & ~0x80000000u) + 3 & ~3u);
        }
        // children of child: need full skip; use a small recursive helper
        {
            uint32_t nkids = child->nChildren;
            struct { uint8_t *ptr; uint32_t remaining; } stack[64];
            int sp = 0;
            stack[sp].ptr = q; stack[sp].remaining = nkids; sp++;
            while (sp) {
                if (stack[sp-1].remaining == 0) { q = stack[sp-1].ptr; sp--; if (sp) stack[sp-1].ptr = q; continue; }
                struct dtree_node *n = (struct dtree_node *)stack[sp-1].ptr;
                uint8_t *r = (uint8_t *)(n + 1);
                for (uint32_t i = 0; i < n->nProperties; i++) {
                    struct dtree_prop *pr = (struct dtree_prop *)r;
                    r += sizeof(*pr) + ((pr->length & ~0x80000000u) + 3 & ~3u);
                }
                stack[sp-1].remaining--;
                stack[sp].ptr = r; stack[sp].remaining = n->nChildren; sp++;
            }
        }
        p = q;
    }
}
