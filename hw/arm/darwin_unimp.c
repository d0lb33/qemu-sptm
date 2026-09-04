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
#include "system/runstate.h"
#include "system/memory.h"
#include "system/address-spaces.h"
#include "cpu.h"
#include "xnu/boot/xnuboot.h"
#include "xnu/apple_dtree.h"
#include "xnu/darwin_unimp.h"

typedef struct {
    uint64_t base, len;
    char name[64];
} UnimpNode;

typedef struct {
    MemoryRegion mr;
    uint64_t base;
    GHashTable *writes;     // addr -> value (last written)
    GHashTable *seen;       // addr -> count (for log rate limiting)
} UnimpRegion;

static UnimpNode *g_nodes;
static int g_num_nodes;
static bool g_debug;
static bool g_stop_first;
static int g_stop_requested;

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
    CPUState *cs = current_cpu;
    CPUARMState *env = cs ? &ARM_CPU(cs)->env : NULL;
    uint64_t pstate = env ? pstate_read(env) : 0;
    unsigned int el = (pstate >> 2) & 3;

    fprintf(stderr, "unimp: %s 0x%" PRIx64 " (%s+0x%" PRIx64
            ") %s 0x%" PRIx64 " size %u pc=0x%" PRIx64
            " el=%u pstate=0x%" PRIx64 " sp=0x%" PRIx64
            " x0=0x%" PRIx64 " x1=0x%" PRIx64 " x2=0x%" PRIx64
            " x3=0x%" PRIx64 "%s\n",
            op, pa, node, off, op[0] == 'r' ? "->" : "<-", val, size,
            env ? env->pc : 0, el, pstate, env ? env->xregs[31] : 0,
            env ? env->xregs[0] : 0, env ? env->xregs[1] : 0,
            env ? env->xregs[2] : 0, env ? env->xregs[3] : 0,
            cs ? "" : " (no current CPU)");

    if (g_stop_first &&
        qatomic_cmpxchg(&g_stop_requested, 0, 1) == 0) {
        /* Keep the evidence ahead of the asynchronous pause request. */
        fflush(stderr);
        qemu_system_vmstop_request_prepare();
        qemu_system_vmstop_request(RUN_STATE_PAUSED);
    }
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
    g_stop_first = getenv("DARWIN_UNIMP_STOP_FIRST") != NULL;
    g_stop_requested = 0;
    g_debug = getenv("DARWIN_UNIMP_DEBUG") != NULL || g_stop_first;
    collect_nodes(arm_io, iobase);

    for (size_t i = 0; i < n; i++) {
        uint64_t child = ranges[3 * i], parent = ranges[3 * i + 1], size = ranges[3 * i + 2];
        (void)child;
        if (!size) continue;
        UnimpRegion *r = g_new0(UnimpRegion, 1);
        r->base = parent;
        r->writes = g_hash_table_new(u64_hash, u64_equal);
        r->seen = g_hash_table_new(g_direct_hash, g_direct_equal);
        char *name = g_strdup_printf("darwin-unimp-%zu", i);
        memory_region_init_io(&r->mr, NULL, &unimp_ops, r, name, size);
        // priority below every real device (they use priority 0)
        memory_region_add_subregion_overlap(get_system_memory(), parent, &r->mr, -1000);
        fprintf(stderr, "darwin-unimp: backing arm-io range 0x%" PRIx64 " + 0x%" PRIx64 "\n", parent, size);
    }
}
