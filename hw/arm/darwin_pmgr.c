/*
 * darwin-pmgr: Apple PMGR power-state (PS) registers
 *
 * Why: with /arm-io/pmgr stripped, IOMobileFramebuffer's DCPPowerManager
 * logs "IOMFB AP: use_psd_dcp_power2: 0" and manages DCP power through the
 * RTKit sleep path, which reboots the coprocessor every few seconds while
 * the display is on (docs/re/tcg-idle-profile.md). With the node kept
 * (dt_fixup -enable pmgr) AppleT8140PMGR starts and reads the power-state
 * registers of every device in the tree's "devices" table; reading zeros
 * from the catch-all makes ApplePMGR::initDriver:2002 assert
 * "ECPU_0 1 request ECPU.0 > 0" (probe PMGR2). This model backs those
 * registers.
 *
 * Register layout, from Linux drivers/pmdomain/apple/pmgr-pwrstate.c and
 * m1n1 src/pmgr.c (both cite the same hardware; no Apple documentation):
 *
 *   [3:0]   PS_TARGET   requested state (0xf active, 0x4 clock-gated, 0 off)
 *   [7:4]   PS_ACTUAL   current state, follows TARGET after a short delay
 *   [8]     WAS_PWRGATED  sticky flags, write-1-to-clear
 *   [9]     WAS_CLKGATED
 *   [10]    DEV_DISABLE
 *   [11]    PARENT_OFF
 *   [19:16] PS_MIN
 *   [27:24] PS_AUTO
 *   [28]    AUTO_ENABLE
 *   [31]    RESET
 *
 * Linux writes TARGET and polls ACTUAL with a 100 us timeout; here ACTUAL
 * follows TARGET at the write. Reset is a plain read/write bit. Every
 * device listed in "devices" starts ACTIVE, which is how iBoot leaves the
 * domains ApplePMGR finds referenced at boot (the ECPU check above only
 * passes for a powered domain). Nothing here decides which domains a real
 * iBoot would leave gated; that is not known and is logged as such.
 *
 * Device table decoding (m1n1 struct pmgr_device, 48 bytes): flags at +0
 * (0x10 = virtual, no register), group_and_offset u32 at +16
 * (offset:24, group:8), name[16] at +32. "ps-groups" holds u32 triples
 * whose first word is the index into the node's "reg" windows.
 * tools/re/pmgr_devices.py prints the same decode for a tree.
 *
 * Other PMGR windows (perf state, clock control, ...) stay on darwin-unimp.
 * DARWIN_PMGR_DEBUG=1 logs every access.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "migration/vmstate.h"
#include "system/memory.h"
#include "system/address-spaces.h"
#include "xnu/apple_dtree.h"
#include "xnu/darwin_pmgr.h"

#define PMGR_PS_TARGET_MASK   0xfu
#define PMGR_PS_ACTUAL_SHIFT  4
#define PMGR_PS_ACTIVE        0xfu
#define PMGR_PS_STICKY_MASK   (3u << 8)   /* WAS_PWRGATED | WAS_CLKGATED */
#define PMGR_DEVICE_SIZE      48
#define PMGR_FLAG_VIRTUAL     0x10
#define PMGR_MAX_DEVICES      512
#define PMGR_MAX_GROUPS       8

typedef struct {
    uint32_t offset;
    uint32_t value;
    char name[16];
} PmgrPsReg;

typedef struct {
    MemoryRegion mr;
    uint64_t base;
    unsigned group;
    struct DarwinPmgr *pmgr;
} PmgrGroup;

typedef struct DarwinPmgr {
    PmgrGroup groups[PMGR_MAX_GROUPS];
    unsigned n_groups;
    /* Flat register list; group index in the high byte of the key. */
    PmgrPsReg regs[PMGR_MAX_DEVICES];
    uint32_t n_regs;
    uint32_t values[PMGR_MAX_DEVICES];
    /*
     * Registers in the PS windows that the devices table does not name
     * (PMGR4 saw writes of 1 to group 0 +0x60400/+0x60800/+0x60c00/+0x61000
     * and of 0x80000000 to +0x24060/+0x24068, then the SMC power thread
     * spun on a PMGR lock). Their meaning is unknown; they behave as plain
     * memory, the same policy as darwin-unimp, so a driver that writes and
     * reads back sees its value. Logged when DARWIN_PMGR_DEBUG is set.
     */
    GHashTable *other;   /* (group << 32 | offset) -> value */
    struct PmgrOtherEntry *other_entries; /* migration scratch, see below */
    int32_t other_count;
    bool debug;
} DarwinPmgr;

static uint64_t pmgr_other_key(unsigned group, hwaddr offset)
{
    return ((uint64_t)group << 32) | (offset & 0xffffffffu);
}

static PmgrPsReg *pmgr_find(DarwinPmgr *s, unsigned group, uint64_t offset)
{
    for (uint32_t i = 0; i < s->n_regs; i++) {
        if ((s->regs[i].offset >> 24) == group &&
            (s->regs[i].offset & 0xffffff) == offset) {
            return &s->regs[i];
        }
    }
    return NULL;
}

static uint64_t pmgr_read(void *opaque, hwaddr offset, unsigned size)
{
    PmgrGroup *g = opaque;
    DarwinPmgr *s = g->pmgr;
    PmgrPsReg *r = pmgr_find(s, g->group, offset & ~3ull);
    uint64_t val = 0;

    if (r) {
        val = s->values[r - s->regs];
        if (offset & 4) {
            val = 0; /* the register is 32 bits; the upper half is unused */
        }
    } else {
        uint64_t key = pmgr_other_key(g->group, offset);
        gpointer v = g_hash_table_lookup(s->other, &key);
        val = v ? *(uint32_t *)v : 0;
    }
    if (s->debug) {
        fprintf(stderr, "pmgr: read  group %u +0x%" HWADDR_PRIx " (%s) -> 0x%" PRIx64 "\n",
                g->group, offset, r ? r->name : "unknown", val);
    }
    return val;
}

static void pmgr_write(void *opaque, hwaddr offset, uint64_t val, unsigned size)
{
    PmgrGroup *g = opaque;
    DarwinPmgr *s = g->pmgr;
    PmgrPsReg *r = pmgr_find(s, g->group, offset & ~3ull);

    if (r && !(offset & 4)) {
        uint32_t *v = &s->values[r - s->regs];
        uint32_t target = val & PMGR_PS_TARGET_MASK;
        uint32_t keep = *v & PMGR_PS_STICKY_MASK & ~(uint32_t)val; /* W1C */
        *v = ((uint32_t)val & ~(0xfu << PMGR_PS_ACTUAL_SHIFT) & ~PMGR_PS_STICKY_MASK)
             | (target << PMGR_PS_ACTUAL_SHIFT) | keep;
    }
    if (!r) {
        uint64_t *key = g_new(uint64_t, 1);
        uint32_t *v = g_new(uint32_t, 1);
        *key = pmgr_other_key(g->group, offset);
        *v = val;
        g_hash_table_replace(s->other, key, v);
    }
    if (s->debug) {
        fprintf(stderr, "pmgr: write group %u +0x%" HWADDR_PRIx " (%s) <- 0x%" PRIx64 "%s\n",
                g->group, offset, r ? r->name : "unknown", val,
                r ? "" : " (not a listed PS register; stored as memory)");
    }
}

static const MemoryRegionOps pmgr_ops = {
    .read = pmgr_read,
    .write = pmgr_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 1,
    .valid.max_access_size = 8,
};

/*
 * Migration: the PS values travel as a fixed array; the memory-like
 * "other" registers are flattened to sorted (key, value) pairs on save and
 * rebuilt on load, the same scheme darwin-unimp uses for its writes.
 */
typedef struct PmgrOtherEntry {
    uint64_t key;
    uint32_t value;
} PmgrOtherEntry;

static int pmgr_pre_save(void *opaque)
{
    DarwinPmgr *s = opaque;
    GHashTableIter it;
    gpointer k, v;
    unsigned i = 0;

    g_clear_pointer(&s->other_entries, g_free);
    s->other_count = g_hash_table_size(s->other);
    s->other_entries = g_new0(PmgrOtherEntry, s->other_count ? s->other_count : 1);
    g_hash_table_iter_init(&it, s->other);
    while (g_hash_table_iter_next(&it, &k, &v)) {
        s->other_entries[i].key = *(uint64_t *)k;
        s->other_entries[i].value = *(uint32_t *)v;
        i++;
    }
    return 0;
}

static int pmgr_post_load(void *opaque, int version_id)
{
    DarwinPmgr *s = opaque;

    g_hash_table_remove_all(s->other);
    for (uint32_t i = 0; i < s->other_count; i++) {
        uint64_t *k = g_new(uint64_t, 1);
        uint32_t *v = g_new(uint32_t, 1);
        *k = s->other_entries[i].key;
        *v = s->other_entries[i].value;
        g_hash_table_replace(s->other, k, v);
    }
    g_clear_pointer(&s->other_entries, g_free);
    s->other_count = 0;
    return 0;
}

static const VMStateDescription vmstate_pmgr_other = {
    .name = "darwin-pmgr-other",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT64(key, PmgrOtherEntry),
        VMSTATE_UINT32(value, PmgrOtherEntry),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_darwin_pmgr = {
    .name = "darwin-pmgr",
    .version_id = 2,
    .minimum_version_id = 2,
    .pre_save = pmgr_pre_save,
    .post_load = pmgr_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32(n_regs, DarwinPmgr),
        VMSTATE_UINT32_ARRAY(values, DarwinPmgr, PMGR_MAX_DEVICES),
        VMSTATE_INT32(other_count, DarwinPmgr),
        VMSTATE_STRUCT_VARRAY_ALLOC(other_entries, DarwinPmgr, other_count, 0,
                                    vmstate_pmgr_other, PmgrOtherEntry),
        VMSTATE_END_OF_LIST()
    }
};

bool darwin_pmgr_create(struct dtree_node *dt_root, uint64_t iobase)
{
    struct dtree_node *node = adt_find_node(dt_root, "arm-io/pmgr");
    if (!node || !adt_get_prop_val(node, "compatible")) {
        return false; /* dt_fixup ran without -enable pmgr */
    }
    struct adt_io_reg *reg = adt_get_prop_val(node, "reg");
    size_t n_reg = adt_get_prop_len(node, "reg") / sizeof(*reg);
    uint32_t *groups = adt_get_prop_val(node, "ps-groups");
    size_t n_groups = adt_get_prop_len(node, "ps-groups") / 12;
    uint8_t *dev = adt_get_prop_val(node, "devices");
    size_t n_dev = adt_get_prop_len(node, "devices") / PMGR_DEVICE_SIZE;
    if (!reg || !groups || !dev || !n_groups) {
        fprintf(stderr, "darwin-pmgr: pmgr node lacks reg/ps-groups/devices; not modelled\n");
        return false;
    }

    DarwinPmgr *s = g_new0(DarwinPmgr, 1);
    s->debug = getenv("DARWIN_PMGR_DEBUG") != NULL;
    s->other = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, g_free);
    for (size_t i = 0; i < n_dev && s->n_regs < PMGR_MAX_DEVICES; i++) {
        const uint8_t *e = dev + i * PMGR_DEVICE_SIZE;
        uint32_t gao;
        memcpy(&gao, e + 16, sizeof(gao));
        if (e[0] & PMGR_FLAG_VIRTUAL) {
            continue;
        }
        PmgrPsReg *r = &s->regs[s->n_regs];
        r->offset = gao; /* group in the high byte, offset in the low 24 */
        memcpy(r->name, e + 32, 15);
        s->values[s->n_regs] = PMGR_PS_ACTIVE | (PMGR_PS_ACTIVE << PMGR_PS_ACTUAL_SHIFT);
        s->n_regs++;
    }
    for (size_t gi = 0; gi < n_groups && gi < PMGR_MAX_GROUPS; gi++) {
        uint32_t reg_index = groups[3 * gi];
        if (reg_index >= n_reg || !reg[reg_index].len) {
            fprintf(stderr, "darwin-pmgr: ps-group %zu names reg[%u], which is absent\n", gi, reg_index);
            continue;
        }
        PmgrGroup *g = &s->groups[s->n_groups++];
        g->pmgr = s;
        g->group = gi;
        g->base = reg[reg_index].base + iobase;
        char *name = g_strdup_printf("darwin-pmgr-ps%zu", gi);
        memory_region_init_io(&g->mr, NULL, &pmgr_ops, g, name, reg[reg_index].len);
        /* -500: above darwin-unimp (-1000), below precise models such as darwin-smp's CPU-start registers at PMGR+0x34000 (priority 0) that live inside this window */
        memory_region_add_subregion_overlap(get_system_memory(), g->base, &g->mr, -500);
        fprintf(stderr, "darwin-pmgr: PS group %zu at 0x%" PRIx64 " + 0x%" PRIx64 "\n",
                gi, g->base, reg[reg_index].len);
    }
    g_assert(vmstate_register(NULL, 0, &vmstate_darwin_pmgr, s) == 0);
    fprintf(stderr, "darwin-pmgr: %u power-state registers from %zu devices, all initially active\n",
            s->n_regs, n_dev);
    return true;
}
