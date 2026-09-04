/*
 * darwin-unimp: catch-all backing for unmodelled SoC MMIO
 *
 * Apple SoCs have hundreds of MMIO blocks. XNU treats a synchronous external
 * abort on one of them as a hardware error and panics, so instead of letting
 * accesses to unmodelled blocks fault, back every /arm-io range with a
 * low-priority region that reads as zero, remembers writes, and (with
 * DARWIN_UNIMP_DEBUG=1) logs each access with the device tree node that owns
 * the address. Modelled devices are mapped on top with higher priority.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "migration/vmstate.h"
#include "system/memory.h"
#include "system/address-spaces.h"
#include "xnu/boot/xnuboot.h"
#include "xnu/apple_dtree.h"
#include "xnu/darwin_unimp.h"

typedef struct {
    uint64_t base, len;
    char name[64];
} UnimpNode;

typedef struct {
    uint64_t addr;
    uint64_t value;
} UnimpWrite;

typedef struct {
    MemoryRegion mr;
    uint64_t base;
    GHashTable *writes;     // addr -> value (last written)
    GHashTable *seen;       // addr -> count (for log rate limiting)
    int32_t migration_count;
    UnimpWrite *migration_entries;
} UnimpRegion;

#define UNIMP_MIGRATION_MAX_WRITES (1U << 20)

static bool unimp_migration_count_valid(void *opaque, int version_id)
{
    UnimpRegion *r = opaque;

    return r->migration_count >= 0 &&
           r->migration_count <= UNIMP_MIGRATION_MAX_WRITES;
}

static int unimp_write_compare(const void *ap, const void *bp)
{
    const UnimpWrite *a = ap;
    const UnimpWrite *b = bp;

    return (a->addr > b->addr) - (a->addr < b->addr);
}

static int unimp_pre_save(void *opaque)
{
    UnimpRegion *r = opaque;
    GHashTableIter iter;
    gpointer key, value;
    unsigned i = 0;

    g_clear_pointer(&r->migration_entries, g_free);
    r->migration_count = g_hash_table_size(r->writes);
    if (!unimp_migration_count_valid(r, 1)) {
        return -E2BIG;
    }
    r->migration_entries = g_new0(UnimpWrite, r->migration_count);
    g_hash_table_iter_init(&iter, r->writes);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        r->migration_entries[i].addr = *(uint64_t *)key;
        r->migration_entries[i].value = *(uint64_t *)value;
        i++;
    }
    qsort(r->migration_entries, r->migration_count,
          sizeof(*r->migration_entries), unimp_write_compare);
    return 0;
}

static void unimp_post_save(void *opaque)
{
    UnimpRegion *r = opaque;

    g_clear_pointer(&r->migration_entries, g_free);
    r->migration_count = 0;
}

static int unimp_pre_load(void *opaque)
{
    UnimpRegion *r = opaque;

    g_clear_pointer(&r->migration_entries, g_free);
    r->migration_count = 0;
    return 0;
}

static int unimp_post_load(void *opaque, int version_id)
{
    UnimpRegion *r = opaque;

    for (int32_t i = 0; i < r->migration_count; i++) {
        UnimpWrite *entry = &r->migration_entries[i];

        if (entry->addr < r->base || entry->addr - r->base >=
            memory_region_size(&r->mr) ||
            (i && entry->addr <= r->migration_entries[i - 1].addr)) {
            g_clear_pointer(&r->migration_entries, g_free);
            r->migration_count = 0;
            return -EINVAL;
        }
    }

    g_hash_table_remove_all(r->writes);
    for (int32_t i = 0; i < r->migration_count; i++) {
        UnimpWrite *entry = &r->migration_entries[i];
        uint64_t *key;
        uint64_t *value;

        key = g_new(uint64_t, 1);
        value = g_new(uint64_t, 1);
        *key = entry->addr;
        *value = entry->value;
        g_hash_table_replace(r->writes, key, value);
    }
    g_clear_pointer(&r->migration_entries, g_free);
    r->migration_count = 0;
    return 0;
}

static const VMStateDescription vmstate_unimp_write = {
    .name = "darwin-unimp/write",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT64(addr, UnimpWrite),
        VMSTATE_UINT64(value, UnimpWrite),
        VMSTATE_END_OF_LIST()
    },
};

static const VMStateDescription vmstate_darwin_unimp = {
    .name = "darwin-unimp",
    .version_id = 1,
    .minimum_version_id = 1,
    .pre_save = unimp_pre_save,
    .post_save = unimp_post_save,
    .pre_load = unimp_pre_load,
    .post_load = unimp_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT64_EQUAL(base, UnimpRegion),
        VMSTATE_INT32(migration_count, UnimpRegion),
        VMSTATE_VALIDATE("migration_count <= 1048576",
                         unimp_migration_count_valid),
        VMSTATE_STRUCT_VARRAY_ALLOC(migration_entries, UnimpRegion,
                                    migration_count, 1,
                                    vmstate_unimp_write, UnimpWrite),
        VMSTATE_END_OF_LIST()
    },
};

static UnimpNode *g_nodes;
static int g_num_nodes;
static bool g_debug;

static const char *unimp_node_for(uint64_t pa, uint64_t *off) {
    for (int i = 0; i < g_num_nodes; i++) {
        if (pa >= g_nodes[i].base && pa < g_nodes[i].base + g_nodes[i].len) {
            *off = pa - g_nodes[i].base;
            return g_nodes[i].name;
        }
    }
    *off = pa;
    return "?";
}

static void unimp_log(UnimpRegion *r, const char *op, uint64_t pa, uint64_t val, unsigned size) {
    if (!g_debug) return;
    gpointer key = GUINT_TO_POINTER((guint)(pa & 0xffffffff));
    guint n = GPOINTER_TO_UINT(g_hash_table_lookup(r->seen, key));
    if (n >= 8) return;         // rate-limit per address
    g_hash_table_insert(r->seen, key, GUINT_TO_POINTER(n + 1));
    uint64_t off;
    const char *node = unimp_node_for(pa, &off);
    fprintf(stderr, "unimp: %s 0x%" PRIx64 " (%s+0x%" PRIx64 ") %s 0x%" PRIx64 " size %u\n",
            op, pa, node, off, op[0] == 'r' ? "->" : "<-", val, size);
}

static uint64_t unimp_read(void *opaque, hwaddr offset, unsigned size) {
    UnimpRegion *r = opaque;
    uint64_t pa = r->base + offset;
    gpointer v = g_hash_table_lookup(r->writes, &pa);
    uint64_t val = v ? *(uint64_t *)v : 0;
    unimp_log(r, "read ", pa, val, size);
    return val;
}

static void unimp_write(void *opaque, hwaddr offset, uint64_t val, unsigned size) {
    UnimpRegion *r = opaque;
    uint64_t pa = r->base + offset;
    uint64_t *k = g_new(uint64_t, 1); *k = pa;
    uint64_t *v = g_new(uint64_t, 1); *v = val;
    g_hash_table_replace(r->writes, k, v);
    unimp_log(r, "write", pa, val, size);
}

static const MemoryRegionOps unimp_ops = {
    .read = unimp_read,
    .write = unimp_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 1,
    .impl.max_access_size = 8,
    .valid.min_access_size = 1,
    .valid.max_access_size = 8,
};

static guint u64_hash(gconstpointer k) { return g_int64_hash(k); }
static gboolean u64_equal(gconstpointer a, gconstpointer b) { return *(const uint64_t *)a == *(const uint64_t *)b; }

// Collect (name, reg) of every /arm-io child for address -> node naming
static void collect_nodes(struct dtree_node *arm_io, uint64_t iobase) {
    struct dtree_prop { char name[32]; uint32_t length; };
    uint8_t *p = (uint8_t *)(arm_io + 1);
    for (uint32_t i = 0; i < arm_io->nProperties; i++) {
        struct dtree_prop *pr = (struct dtree_prop *)p;
        p += sizeof(*pr) + (((pr->length & ~0x80000000u) + 3) & ~3u);
    }
    GArray *arr = g_array_new(false, false, sizeof(UnimpNode));
    for (uint32_t c = 0; c < arm_io->nChildren; c++) {
        struct dtree_node *child = (struct dtree_node *)p;
        const char *name = adt_get_prop_val(child, "name");
        struct adt_io_reg *reg = adt_get_prop_val(child, "reg");
        if (name && reg) {
            size_t n = adt_get_prop_len(child, "reg") / sizeof(*reg);
            for (size_t k = 0; k < n; k++) {
                if (!reg[k].len) continue;
                UnimpNode un = { .base = reg[k].base + iobase, .len = reg[k].len };
                snprintf(un.name, sizeof(un.name), "%s[%zu]", name, k);
                g_array_append_val(arr, un);
            }
        }
        // skip this child (props + descendants)
        uint8_t *q = (uint8_t *)(child + 1);
        for (uint32_t i = 0; i < child->nProperties; i++) {
            struct dtree_prop *pr = (struct dtree_prop *)q;
            q += sizeof(*pr) + (((pr->length & ~0x80000000u) + 3) & ~3u);
        }
        struct { uint8_t *ptr; uint32_t remaining; } stack[64];
        int sp = 0;
        stack[sp].ptr = q; stack[sp].remaining = child->nChildren; sp++;
        while (sp) {
            if (stack[sp-1].remaining == 0) { q = stack[sp-1].ptr; sp--; if (sp) stack[sp-1].ptr = q; continue; }
            struct dtree_node *n = (struct dtree_node *)stack[sp-1].ptr;
            uint8_t *r = (uint8_t *)(n + 1);
            for (uint32_t i = 0; i < n->nProperties; i++) {
                struct dtree_prop *pr = (struct dtree_prop *)r;
                r += sizeof(*pr) + (((pr->length & ~0x80000000u) + 3) & ~3u);
            }
            stack[sp-1].remaining--;
            stack[sp].ptr = r; stack[sp].remaining = n->nChildren; sp++;
        }
        p = q;
    }
    g_num_nodes = arr->len;
    g_nodes = (UnimpNode *)g_array_free(arr, false);
}

void darwin_unimp_init(struct dtree_node *dt_root, uint64_t iobase) {
    struct dtree_node *arm_io = adt_find_node(dt_root, "arm-io");
    uint64_t *ranges = adt_get_prop_val(arm_io, "ranges");
    size_t n = adt_get_prop_len(arm_io, "ranges") / (3 * sizeof(uint64_t));
    g_debug = getenv("DARWIN_UNIMP_DEBUG") != NULL;
    collect_nodes(arm_io, iobase);

    for (size_t i = 0; i < n; i++) {
        uint64_t child = ranges[3 * i], parent = ranges[3 * i + 1], size = ranges[3 * i + 2];
        (void)child;
        if (!size) continue;
        UnimpRegion *r = g_new0(UnimpRegion, 1);
        r->base = parent;
        r->writes = g_hash_table_new_full(u64_hash, u64_equal, g_free, g_free);
        r->seen = g_hash_table_new(g_direct_hash, g_direct_equal);
        char *name = g_strdup_printf("darwin-unimp-%zu", i);
        memory_region_init_io(&r->mr, NULL, &unimp_ops, r, name, size);
        // priority below every real device (they use priority 0)
        memory_region_add_subregion_overlap(get_system_memory(), parent, &r->mr, -1000);
        g_assert(vmstate_register(NULL, i, &vmstate_darwin_unimp, r) == 0);
        fprintf(stderr, "darwin-unimp: backing arm-io range 0x%" PRIx64 " + 0x%" PRIx64 "\n", parent, size);
    }
}
