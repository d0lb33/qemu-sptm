/*
 * darwin-sart: Apple SART DMA address filter ("sart,coastguard", v1..v4)
 *
 * SART is the thing that sits where a DART would sit next to the ANS storage
 * coprocessor. It is not an IOMMU: it does no translation at all, it just
 * holds a small table of physical ranges that the coprocessor is allowed to
 * touch (Linux drivers/soc/apple/sart.c:6-11, "no remapping can be done").
 *
 * On SPTM machines the AP never programs it directly. AppleSART's
 * IOCoastGuardSARTMapper goes through pmap_iommu_ioctl(SART_IOCTL_*), and it
 * is *SPTM* that owns these registers - which is lucky, because SPTM is also
 * where the register semantics are written down in a form we can read.
 *
 * ---------------------------------------------------------------------------
 * SOURCE OF THIS REGISTER MAP
 * ---------------------------------------------------------------------------
 * Everything below was read out of our own SPTM image (firmware/sptm,
 * __TEXT_EXEC based at 0xfffffff027098000, __TEXT at 0xfffffff027004000).
 * SPTM carries two per-version descriptor tables in __TEXT,__const and indexes
 * them with the device tree's "sart-version" / "sart-throttle-version":
 *
 *   region layout table   sptm:0xfffffff02701a418 + 0x2c * (sart-version - 1)
 *   throttle layout table sptm:0xfffffff02701a368 + 0x2c * (sart-throttle-version - 1)
 *
 * selected in sart_bootstrap_parse_edt at sptm:0xfffffff0270c276c (regions)
 * and sptm:0xfffffff0270c27a8 (throttles); versions outside 1..4 are rejected
 * with "Invalid SART version %d from EDT" (sptm:0xfffffff0270c2760).
 *
 * The region descriptor is decoded by sart_get_registers,
 * sptm:0xfffffff0270c17dc, which gives each field its meaning:
 *
 *   desc+0x04 u32  number of region entries
 *   desc+0x08 u32  CONFIG base offset        desc+0x0c u8 CONFIG stride
 *   desc+0x0d..0x11 u8[5] bit positions of the permission fields in CONFIG
 *   desc+0x14 u32  SIZE base offset (0 => SIZE is packed into CONFIG)
 *   desc+0x18 u8   SIZE stride   desc+0x19 u8 SIZE shift   desc+0x1c u32 SIZE mask
 *   desc+0x20 u32  PADDR base offset
 *   desc+0x24 u8   PADDR stride  desc+0x25 u8 PADDR shift  desc+0x28 u32 PADDR mask
 *
 * which for our t8140 sart-ans (sart-version = 3, descriptor at
 * sptm:0xfffffff02701a470, magic 'SRT3') means, in reg[0]:
 *
 *   0x000 + 4*i   CONFIG[i]   permission/enable bitfield, 0 = entry unused
 *   0x040 + 4*i   PADDR[i]    physical address >> 12, 30-bit field
 *   0x080 + 4*i   SIZE[i]     size >> 12, 30-bit field
 *                             i = 0..15
 *
 * That agrees exactly with the three independent public sources for v3:
 * Linux drivers/soc/apple/sart.c:52-62,152-169, m1n1 src/sart.c:45-56,137-164,
 * and QEMUAppleSilicon hw/arm/apple-silicon/sart.c:69-115. (One disagreement,
 * on v1 only, which does not affect us: QAS masks the size out of CONFIG with
 * a shift of 12, SPTM's v1 descriptor says shift 0.)
 *
 * CONFIG's permission encoding, from sart_add_region sptm:0xfffffff0270c1ac4:
 *   cfg = (1 << p[4]) | (1 << p[3]) | (perm << p[2]) | (perm << p[1]) | (perm << p[0])
 * with perm = 3 for the read/write case and 2 otherwise. For v3's
 * p = {0,2,4,6,7} that is 0xff for full access - the same magic "allow" value
 * Linux and m1n1 write.
 *
 * ---------------------------------------------------------------------------
 * THROTTLE REGISTERS - this is what the panic was about
 * ---------------------------------------------------------------------------
 * The throttle descriptor (sptm:0xfffffff02701a3c0 for v3) is:
 *
 *   desc+0x00 u8    number of throttle channels (3 for v1..v3, 4 for v4)
 *   desc+0x08 u32[] STAT register offsets
 *   desc+0x18 u32[] CONFIG register offsets
 *   desc+0x28 u32   STAT "still busy" mask (0xffff)
 *
 * All offsets are relative to reg[0] + the device tree's "sart-throttle-offset"
 * (absent on t8140, so 0 - sptm:0xfffffff0270c2594 defaults it to zero).
 * For v3 that is three channels of {STAT, CONFIG} on an 8-byte pitch:
 *
 *   0x8010 STAT[0]   0x8014 CONFIG[0]
 *   0x8018 STAT[1]   0x801c CONFIG[1]
 *   0x8020 STAT[2]   0x8024 CONFIG[2]
 *
 * (v1 has the same shape at 0x4010; v4 has four channels starting at 0x8000.)
 *
 * Two pieces of SPTM code read them, and they are the whole reason this file
 * exists:
 *
 *  1. sart_sanity_check_throttles, inlined into SPTM_SART_SET_STATE at
 *     sptm:0xfffffff0270c220c..0xfffffff0270c2240. For each channel it reads
 *     CONFIG and *requires it to be non-zero*:
 *
 *         ldr  w15, [x15]
 *         cbz  w15, <panic>        ; "Sart invalid throttle cfg [%d] = 0x%x"
 *
 *     then caches the values in its instance. With no model at all these
 *     offsets fell through to darwin-unimp, read back 0, and XNU died with
 *         panic(...): sart_sanity_check_throttles: Sart invalid throttle cfg [0] = 0x0
 *     the moment AppleSART called SART_IOCTL_SET_ACTIVE.
 *
 *  2. SPTM_SART_UNMAP_REGION, sptm:0xfffffff0270c0fc4..0xfffffff0270c112c:
 *     writes 0 to every CONFIG, dsb sy, then polls every STAT until
 *     (STAT & 0xffff) == 0, and once drained writes the cached CONFIG values
 *     back. If STAT never drains it gives up and returns an error.
 *
 * So the contract this model has to satisfy is small and exact: CONFIG reads
 * non-zero at reset and remembers writes, STAT reads 0 in its low 16 bits.
 * What the bits of CONFIG *mean* is not stated anywhere we can see - it is
 * some DMA bandwidth/QoS throttle programmed by iBoot - so this model does
 * not pretend to know: it stores the word and its reset value is a property
 * (throttle-cfg-reset, default 1, the smallest value that satisfies every
 * check SPTM makes). SPTM only ever compares it against 0 and against the
 * mask 0x01010000 on the unmap path, and that comparison is not reached while
 * STAT reads 0.
 *
 * ---------------------------------------------------------------------------
 * POWER CANARY - reg[1]
 * ---------------------------------------------------------------------------
 * "power-canary-offset" (0 on t8140) names a word in reg[1] used as a
 * this-block-still-has-power check:
 *   sart_assert_power_canary   sptm:0xfffffff0270c19e4 writes 0xABFEDEED when
 *                              the canary refcount goes 0 -> 1
 *   sart_deassert_power_canary sptm:0xfffffff0270c11ac reads it back and takes
 *                              a violation if it is not still 0xABFEDEED
 * Plain read/write storage is exactly right for that, and is what we do.
 *
 * The node's other power properties - "sart-power-managed" and
 * "sart-power-reg-offset" (0x13e8) - are *not* read by SPTM (they appear in no
 * string in firmware/sptm); they belong to the AppleSART kext's own power
 * gating. We deliberately model nothing for them.
 *
 * ---------------------------------------------------------------------------
 * WHAT WE DELIBERATELY DO NOT MODEL
 * ---------------------------------------------------------------------------
 * - reg[2] of /arm-io/sart-ans (0x17dcc0000, 0x4000) is not mapped by this
 *   device. SPTM only ever asks the device tree for the first two reg entries
 *   (sptm:0xfffffff0270c2644 and 0xfffffff0270c267c), nothing else names it,
 *   and its base is *identical* to /arm-io/ans reg[3] (0x17dcc0000, 0x60000,
 *   the NVMMU). Claiming it here would collide with a future ANS model, so we
 *   leave it to darwin-unimp. See docs/re/ans-nvme-references.md section 6.
 * - Note for whoever models ANS: sart-ans reg[1] (0x17dd44000 + 0x4000), which
 *   we *do* map, overlaps /arm-io/ans reg[6] (0x17dd47c00 + 0x4000) by 0x400
 *   bytes. Nothing maps ans reg[6] today (darwin_asc.c only takes reg[0]), but
 *   whoever does will have to decide who owns 0x17dd47c00..0x17dd48000.
 * - Every offset in a mapped window that is not named above is plain storage:
 *   reads return the last write, or 0. Nothing faults - XNU treats a
 *   synchronous external abort as a hardware error and panics unhelpfully.
 *
 * DARWIN_SART_DEBUG=1 traces every access with the register decoded.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "migration/vmstate.h"
#include "hw/core/sysbus.h"
#include "hw/core/irq.h"
#include "hw/core/qdev-properties.h"
#include "system/memory.h"
#include "system/address-spaces.h"
#include "xnu/boot/xnuboot.h"
#include "xnu/apple_dtree.h"
#include "xnu/darwin_aic.h"
#include "xnu/darwin_sart.h"

OBJECT_DECLARE_SIMPLE_TYPE(DarwinSARTState, DARWIN_SART)

// SPTM accepts sart-version / sart-throttle-version in 1..4 and panics
// otherwise (sptm:0xfffffff0270c2760).
#define SART_MIN_VERSION        1
#define SART_MAX_VERSION        4
// Largest num_regions in SPTM's table (v4 = 24); v1..v3 are 16.
#define SART_MAX_REGIONS        24
#define SART_MAX_THROTTLES      4
// The two reg[] windows SPTM asks the device tree for. See the header comment
// for why reg[2] is not one of them.
#define SART_MAX_WINDOWS        2
// SART's address fields are in 4K units even though the CPU runs 16K pages
// (sart_add_region stores paddr >> 12, sptm:0xfffffff0270c1aa4).
#define SART_PAGE_SHIFT         12

// Per-version region layout, transcribed from SPTM's table at
// sptm:0xfffffff02701a418 (0x2c bytes per entry, index = version - 1).
typedef struct {
    const char *magic;          // as SPTM spells it in the descriptor's first word
    uint32_t num_regions;       // desc+0x04
    uint32_t cfg_off;           // desc+0x08
    uint8_t  cfg_stride;        // desc+0x0c
    uint8_t  perm_bit[5];       // desc+0x0d..0x11
    uint32_t size_off;          // desc+0x14, 0 => SIZE is packed into CONFIG
    uint8_t  size_stride;       // desc+0x18
    uint8_t  size_shift;        // desc+0x19
    uint32_t size_mask;         // desc+0x1c
    uint32_t addr_off;          // desc+0x20
    uint8_t  addr_stride;       // desc+0x24
    uint8_t  addr_shift;        // desc+0x25
    uint32_t addr_mask;         // desc+0x28
} SartRegionLayout;

static const SartRegionLayout sart_region_layouts[SART_MAX_VERSION] = {
    // v1: sptm:0xfffffff02701a418. SIZE lives in the low bits of CONFIG.
    { "SRT1", 16, 0x00, 4, { 0x16, 0x18, 0x1a, 0x1d, 0x1e },
      0x00, 0, 0, 0x0007ffff, 0x40, 4, 0, 0x00ffffff },
    // v2: sptm:0xfffffff02701a444.
    { "SRT2", 16, 0x00, 4, { 0x18, 0x1a, 0x1c, 0x1e, 0x1f },
      0x00, 0, 0, 0x00ffffff, 0x40, 4, 0, 0x00ffffff },
    // v3: sptm:0xfffffff02701a470. This is t8140's.
    { "SRT3", 16, 0x00, 4, { 0x00, 0x02, 0x04, 0x06, 0x07 },
      0x80, 4, 0, 0x3fffffff, 0x40, 4, 0, 0x3fffffff },
    // v4: sptm:0xfffffff02701a49c. Not seen on any SoC we boot, kept because
    // SPTM knows it and it costs nothing.
    { "SRT4", 24, 0x00, 4, { 0x00, 0x02, 0x04, 0x06, 0x07 },
      0xc0, 4, 0, 0x3fffffff, 0x60, 4, 0, 0x3fffffff },
};

// Per-version throttle layout, from SPTM's table at sptm:0xfffffff02701a368.
typedef struct {
    uint32_t count;                         // desc+0x00 (read as a byte)
    uint32_t stat_off[SART_MAX_THROTTLES];  // desc+0x08
    uint32_t cfg_off[SART_MAX_THROTTLES];   // desc+0x18
    uint32_t stat_busy_mask;                // desc+0x28
} SartThrottleLayout;

static const SartThrottleLayout sart_throttle_layouts[SART_MAX_VERSION] = {
    // v1: sptm:0xfffffff02701a368
    { 3, { 0x4010, 0x4018, 0x4020 }, { 0x4014, 0x401c, 0x4024 }, 0xffff },
    // v2: sptm:0xfffffff02701a394
    { 3, { 0x8010, 0x8018, 0x8020 }, { 0x8014, 0x801c, 0x8024 }, 0xffff },
    // v3: sptm:0xfffffff02701a3c0 - t8140's
    { 3, { 0x8010, 0x8018, 0x8020 }, { 0x8014, 0x801c, 0x8024 }, 0xffff },
    // v4: sptm:0xfffffff02701a3ec - four channels, and the block starts at 0x8000
    { 4, { 0x8000, 0x8004, 0x8010, 0x8018 },
         { 0x8008, 0x800c, 0x8014, 0x801c }, 0xffff },
};

// sart_assert_power_canary, sptm:0xfffffff0270c19f0
#define SART_POWER_CANARY_MAGIC 0xabfedeedu

typedef struct DarwinSARTState DarwinSARTState;

typedef struct {
    DarwinSARTState *s;
    unsigned idx;               // which reg[] window this is
    MemoryRegion mr;
    uint32_t *store;            // size/4 words of plain backing storage
    uint32_t size;
    uint64_t base;              // physical base, for logging only
} SartWindow;

struct DarwinSARTState {
    SysBusDevice parent_obj;
    qemu_irq irq;

    char *name;
    uint32_t version;           // "sart-version"
    uint32_t throttle_version;  // "sart-throttle-version", defaults to version
    uint32_t throttle_offset;   // "sart-throttle-offset", defaults to 0
    bool     throttle_disable;  // "sart-throttle-disable" present
    bool     has_canary;        // "power-canary-offset" present
    uint32_t canary_offset;     // its value; indexes reg[1]
    uint32_t num_windows;
    uint32_t window_size[SART_MAX_WINDOWS];
    uint64_t window_base[SART_MAX_WINDOWS];
    uint32_t throttle_cfg_reset;
    uint32_t num_regions;       // overrides the layout table if non-zero

    const SartRegionLayout *rl;
    const SartThrottleLayout *tl;
    SartWindow win[SART_MAX_WINDOWS];
    bool debug;
};

/* ---------------- register naming, for traces only ---------------- */

// Describe an offset in window `w` into `buf`. Purely cosmetic; the read/write
// paths treat every offset the same way.
static const char *sart_reg_name(DarwinSARTState *s, unsigned w, hwaddr off,
                                 char *buf, size_t buflen)
{
    const SartRegionLayout *rl = s->rl;

    if (w == 0) {
        for (unsigned i = 0; i < rl->num_regions; i++) {
            if (off == rl->cfg_off + (hwaddr)i * rl->cfg_stride) {
                snprintf(buf, buflen, "CONFIG[%u]", i);
                return buf;
            }
            if (rl->size_off && off == rl->size_off + (hwaddr)i * rl->size_stride) {
                snprintf(buf, buflen, "SIZE[%u]", i);
                return buf;
            }
            if (off == rl->addr_off + (hwaddr)i * rl->addr_stride) {
                snprintf(buf, buflen, "PADDR[%u]", i);
                return buf;
            }
        }
        if (!s->throttle_disable) {
            for (unsigned i = 0; i < s->tl->count; i++) {
                if (off == s->throttle_offset + s->tl->stat_off[i]) {
                    snprintf(buf, buflen, "THROTTLE_STAT[%u]", i);
                    return buf;
                }
                if (off == s->throttle_offset + s->tl->cfg_off[i]) {
                    snprintf(buf, buflen, "THROTTLE_CFG[%u]", i);
                    return buf;
                }
            }
        }
    } else if (w == 1 && s->has_canary && off == s->canary_offset) {
        return "POWER_CANARY";
    }
    return "?";
}

/* ---------------- mmio ---------------- */

static uint64_t sart_read(void *opaque, hwaddr off, unsigned size)
{
    SartWindow *win = opaque;
    DarwinSARTState *s = win->s;
    uint32_t val = 0;

    // Unknown offsets are not special: SART's whole register file behaves as
    // storage from SPTM's point of view (it writes CONFIG/PADDR/SIZE and reads
    // them back; it writes and restores the throttle CONFIGs; it writes and
    // reads back the power canary). Anything past the end of the window reads
    // 0 rather than faulting.
    if (off + 4 <= win->size) {
        val = win->store[off / 4];
    }

    if (s->debug) {
        char buf[32];
        fprintf(stderr, "sart(%s): read  reg[%u]+0x%04" HWADDR_PRIx " (%s) -> 0x%08x\n",
                s->name, win->idx, off,
                sart_reg_name(s, win->idx, off, buf, sizeof(buf)), val);
    }
    return val;
}

static void sart_write(void *opaque, hwaddr off, uint64_t value, unsigned size)
{
    SartWindow *win = opaque;
    DarwinSARTState *s = win->s;
    uint32_t val = (uint32_t)value;

    if (s->debug) {
        char buf[32];
        fprintf(stderr, "sart(%s): write reg[%u]+0x%04" HWADDR_PRIx " (%s) <- 0x%08x\n",
                s->name, win->idx, off,
                sart_reg_name(s, win->idx, off, buf, sizeof(buf)), val);
    }

    if (off + 4 <= win->size) {
        win->store[off / 4] = val;
    }
}

static const MemoryRegionOps sart_ops = {
    .read = sart_read,
    .write = sart_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 8,
};

/* ---------------- the filter itself ---------------- */

static uint32_t sart_region_word(DarwinSARTState *s, uint32_t base, uint8_t stride,
                                 unsigned i)
{
    uint32_t off = base + (uint32_t)i * stride;
    if (off + 4 > s->win[0].size) {
        return 0;
    }
    return s->win[0].store[off / 4];
}

bool darwin_sart_allows(DeviceState *dev, uint64_t pa, uint64_t len)
{
    DarwinSARTState *s = DARWIN_SART(dev);
    const SartRegionLayout *rl = s->rl;

    for (unsigned i = 0; i < rl->num_regions; i++) {
        uint32_t cfg = sart_region_word(s, rl->cfg_off, rl->cfg_stride, i);
        if (!cfg) {
            continue;           // CONFIG == 0 means the entry is unused
        }
        // v1/v2 pack SIZE into CONFIG (size_off == 0); v3/v4 give it its own
        // register. sart_get_registers, sptm:0xfffffff0270c1828.
        uint32_t sizew = rl->size_off
            ? sart_region_word(s, rl->size_off, rl->size_stride, i)
            : cfg;
        uint64_t rsize = (uint64_t)((sizew >> rl->size_shift) & rl->size_mask)
                         << SART_PAGE_SHIFT;
        uint32_t addrw = sart_region_word(s, rl->addr_off, rl->addr_stride, i);
        uint64_t rbase = (uint64_t)((addrw >> rl->addr_shift) & rl->addr_mask)
                         << SART_PAGE_SHIFT;
        if (rsize && pa >= rbase && pa + len <= rbase + rsize) {
            return true;
        }
    }
    return false;
}

/* ---------------- device ---------------- */

static void darwin_sart_realize(DeviceState *dev, Error **errp)
{
    DarwinSARTState *s = DARWIN_SART(dev);

    if (s->version < SART_MIN_VERSION || s->version > SART_MAX_VERSION) {
        error_setg(errp, "darwin-sart: sart-version %u out of range (SPTM accepts 1..4)",
                   s->version);
        return;
    }
    if (s->throttle_version < SART_MIN_VERSION || s->throttle_version > SART_MAX_VERSION) {
        error_setg(errp, "darwin-sart: sart-throttle-version %u out of range",
                   s->throttle_version);
        return;
    }
    if (!s->num_windows || s->num_windows > SART_MAX_WINDOWS) {
        error_setg(errp, "darwin-sart: %u reg windows, expected 1..%u",
                   s->num_windows, SART_MAX_WINDOWS);
        return;
    }
    if (!s->window_size[0]) {
        error_setg(errp, "darwin-sart: no reg[0] size");
        return;
    }

    s->rl = &sart_region_layouts[s->version - 1];
    s->tl = &sart_throttle_layouts[s->throttle_version - 1];
    if (!s->num_regions) {
        s->num_regions = s->rl->num_regions;
    }
    s->debug = getenv("DARWIN_SART_DEBUG") != NULL;

    for (unsigned w = 0; w < s->num_windows; w++) {
        if (!s->window_size[w]) {
            error_setg(errp, "darwin-sart: reg[%u] has zero size", w);
            return;
        }
        s->win[w].s = s;
        s->win[w].idx = w;
        s->win[w].size = s->window_size[w];
        s->win[w].base = s->window_base[w];
        s->win[w].store = g_new0(uint32_t, s->window_size[w] / 4);
        g_autofree char *nm = g_strdup_printf("darwin-sart[%u]", w);
        memory_region_init_io(&s->win[w].mr, OBJECT(s), &sart_ops, &s->win[w],
                              nm, s->window_size[w]);
        sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->win[w].mr);
    }

    // The one piece of state that is not zero at reset. SPTM's
    // sart_sanity_check_throttles refuses to activate the SART if any throttle
    // CONFIG reads back 0, so seed them; see the header comment for why the
    // value is arbitrary-but-non-zero.
    if (!s->throttle_disable) {
        for (unsigned i = 0; i < s->tl->count; i++) {
            uint32_t off = s->throttle_offset + s->tl->cfg_off[i];
            if (off + 4 > s->win[0].size) {
                error_setg(errp,
                           "darwin-sart: throttle CONFIG[%u] at 0x%x is past reg[0] (0x%x); "
                           "sart-throttle-offset/version wrong for this node",
                           i, off, s->win[0].size);
                return;
            }
            s->win[0].store[off / 4] = s->throttle_cfg_reset;
        }
    }

    sysbus_init_irq(SYS_BUS_DEVICE(dev), &s->irq);
}

static int darwin_sart_post_load(void *opaque, int version_id)
{
    DarwinSARTState *s = opaque;

    if (!s->num_windows || s->num_windows > SART_MAX_WINDOWS ||
        s->version < SART_MIN_VERSION || s->version > SART_MAX_VERSION ||
        s->throttle_version < SART_MIN_VERSION ||
        s->throttle_version > SART_MAX_VERSION) {
        return -EINVAL;
    }
    /*
     * rl/tl and the window back-pointers are destination-process objects
     * reconstructed by realize.  The stream contains only register bytes.
     */
    s->rl = &sart_region_layouts[s->version - 1];
    s->tl = &sart_throttle_layouts[s->throttle_version - 1];
    return 0;
}

static const VMStateDescription vmstate_darwin_sart = {
    .name = TYPE_DARWIN_SART,
    .version_id = 1,
    .minimum_version_id = 1,
    .post_load = darwin_sart_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32_EQUAL(version, DarwinSARTState),
        VMSTATE_UINT32_EQUAL(throttle_version, DarwinSARTState),
        VMSTATE_UINT32_EQUAL(num_windows, DarwinSARTState),
        VMSTATE_UINT32_EQUAL(window_size[0], DarwinSARTState),
        VMSTATE_UINT32_EQUAL(window_size[1], DarwinSARTState),
        VMSTATE_UINT64_EQUAL(window_base[0], DarwinSARTState),
        VMSTATE_UINT64_EQUAL(window_base[1], DarwinSARTState),
        VMSTATE_VBUFFER_UINT32(win[0].store, DarwinSARTState, 1, NULL,
                               window_size[0]),
        VMSTATE_VBUFFER_UINT32(win[1].store, DarwinSARTState, 1, NULL,
                               window_size[1]),
        VMSTATE_END_OF_LIST()
    },
};

static const Property darwin_sart_properties[] = {
    DEFINE_PROP_STRING("name", DarwinSARTState, name),
    DEFINE_PROP_UINT32("version", DarwinSARTState, version, 3),
    DEFINE_PROP_UINT32("throttle-version", DarwinSARTState, throttle_version, 3),
    DEFINE_PROP_UINT32("throttle-offset", DarwinSARTState, throttle_offset, 0),
    DEFINE_PROP_BOOL("throttle-disable", DarwinSARTState, throttle_disable, false),
    DEFINE_PROP_BOOL("has-canary", DarwinSARTState, has_canary, false),
    DEFINE_PROP_UINT32("canary-offset", DarwinSARTState, canary_offset, 0),
    DEFINE_PROP_UINT32("num-windows", DarwinSARTState, num_windows, 1),
    DEFINE_PROP_UINT32("mmio-size", DarwinSARTState, window_size[0], 0),
    DEFINE_PROP_UINT32("mmio-size-1", DarwinSARTState, window_size[1], 0),
    // 0 = take the count from SPTM's per-version table.
    DEFINE_PROP_UINT32("num-regions", DarwinSARTState, num_regions, 0),
    // Reset value of the throttle CONFIG registers. Any non-zero value passes
    // SPTM's check; we have no source for the real one.
    DEFINE_PROP_UINT32("throttle-cfg-reset", DarwinSARTState, throttle_cfg_reset, 1),
};

static void darwin_sart_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = darwin_sart_realize;
    dc->vmsd = &vmstate_darwin_sart;
    dc->desc = "Apple SART DMA address filter";
    device_class_set_props(dc, darwin_sart_properties);
    dc->user_creatable = false;
}

static const TypeInfo darwin_sart_info = {
    .name          = TYPE_DARWIN_SART,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(DarwinSARTState),
    .class_init    = darwin_sart_class_init,
};

static void darwin_sart_register_types(void)
{
    type_register_static(&darwin_sart_info);
}

type_init(darwin_sart_register_types)

/* ---------------- device tree glue ---------------- */

DeviceState *darwin_sart_create(struct dtree_node *node, uint64_t iobase, DeviceState *aic)
{
    struct adt_io_reg *reg = adt_get_prop_val(node, "reg");
    const char *name = adt_get_prop_val(node, "name");
    uint32_t *version = adt_get_prop_val(node, "sart-version");
    uint32_t *tversion = adt_get_prop_val(node, "sart-throttle-version");
    uint32_t *toffset = adt_get_prop_val(node, "sart-throttle-offset");
    uint32_t *canary = adt_get_prop_val(node, "power-canary-offset");
    uint32_t *irqs = adt_get_prop_val(node, "interrupts");
    bool tdisable = adt_get_prop_val(node, "sart-throttle-disable") != NULL;

    if (!reg || !name || !version) {
        fprintf(stderr, "darwin-sart: %s missing reg/name/sart-version, skipping\n",
                name ? name : "?");
        return NULL;
    }
    size_t nreg = adt_get_prop_len(node, "reg") / sizeof(*reg);

    DeviceState *dev = qdev_new(TYPE_DARWIN_SART);
    qdev_prop_set_string(dev, "name", name);
    qdev_prop_set_uint32(dev, "version", *version);
    // sart_bootstrap_parse_edt, sptm:0xfffffff0270c2548: a missing
    // sart-throttle-version falls back to sart-version.
    qdev_prop_set_uint32(dev, "throttle-version", tversion ? *tversion : *version);
    // ... and a missing sart-throttle-offset is 0, sptm:0xfffffff0270c2594.
    qdev_prop_set_uint32(dev, "throttle-offset", toffset ? *toffset : 0);
    qdev_prop_set_bit(dev, "throttle-disable", tdisable);

    // SPTM takes reg[0] (the region table + throttles) always, and reg[1] (the
    // power canary window) only when power-canary-offset is present:
    // sptm:0xfffffff0270c2620 requires the reg property to be >= 0x20 bytes,
    // i.e. two entries, exactly in that case.
    unsigned windows = 1;
    if (canary && nreg >= 2) {
        windows = 2;
        qdev_prop_set_bit(dev, "has-canary", true);
        qdev_prop_set_uint32(dev, "canary-offset", *canary);
        qdev_prop_set_uint32(dev, "mmio-size-1", reg[1].len);
    }
    qdev_prop_set_uint32(dev, "num-windows", windows);
    qdev_prop_set_uint32(dev, "mmio-size", reg[0].len);

    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);
    sysbus_realize_and_unref(sbd, &error_fatal);
    for (unsigned w = 0; w < windows; w++) {
        sysbus_mmio_map(sbd, w, reg[w].base + iobase);
    }
    // SART has no interrupt on any node we have seen; wire one if the tree
    // ever grows one so the line is not silently dropped.
    if (aic && irqs && adt_get_prop_len(node, "interrupts") >= 4) {
        sysbus_connect_irq(sbd, 0, darwin_aic_get_irq(aic, irqs[0]));
    }

    fprintf(stderr, "darwin-sart: %s v%u at 0x%" PRIx64 " (%u windows, %u regions, "
            "%u throttles at +0x%x)\n",
            name, *version, reg[0].base + iobase, windows,
            sart_region_layouts[*version - 1].num_regions,
            tdisable ? 0 : sart_throttle_layouts[(tversion ? *tversion : *version) - 1].count,
            toffset ? *toffset : 0);
    return dev;
}

// Walk /arm-io children; SARTs still carrying a compatible were selected by
// dt_fixup (-enable ans). Same selection rule as darwin_darts_create.
void darwin_sarts_create(struct dtree_node *dt_root, uint64_t iobase, DeviceState *aic)
{
    struct dtree_node *arm_io = adt_find_node(dt_root, "arm-io");
    if (!arm_io) {
        return;
    }
    for (struct dtree_node *c = adt_first_child(arm_io); c;
         c = adt_next_sibling(arm_io, c)) {
        const char *compat = adt_get_prop_val(c, "compatible");
        const char *type = adt_get_prop_val(c, "device_type");
        if (compat && type && !strcmp(type, "sart")) {
            darwin_sart_create(c, iobase, aic);
        }
    }
}
