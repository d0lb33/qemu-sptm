/* Owned shared RAM + MMIO doorbell. No storage path and no guest debugger.
 * Echo first; optional socket notification backend forwards to host Metal.
 * One outstanding request; completion is a polled MMIO register, not an IRQ.
 */
#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/bswap.h"
#include "qemu/atomic.h"
#include "qapi/error.h"
#include "system/memory.h"
#include "system/address-spaces.h"
#include "migration/blocker.h"
#include "chardev/char-fe.h"
#include "xnu/apple_dtree.h"
#include "xnu/darwin_gpu_transport.h"
#include "xnu/dvm_surface_registry.h"
#include <zlib.h>

typedef struct DVMGPUTransport {
    MemoryRegion ram, regs, registration;
    uint8_t *bytes;
    uint8_t session[16], rx[16];
    unsigned rx_used;
    uint64_t submitted, done;
    uint32_t error;
    bool external, ready, connected, present;
    CharFrontend notify;
    Error *migration_blocker;
    uint64_t managed_pages[759];
    unsigned managed_count;
    bool managed_started, managed_ready;
    int managed_fd;
    int surface_dir;
    DVMSurfaceRegistry *surfaces;
} DVMGPUTransport;
static void failed(DVMGPUTransport *s, unsigned code);

static bool surface_publish(DVMGPUTransport *s, const DVMSurfaceRecord *r)
{
    g_autofree uint8_t *record = g_malloc0(64 + r->count * 8);
    char name[40];
    stq_le_p(record, DVM_SURFACE_MAGIC);
    stq_le_p(record + 8, DVM_SURFACE_VERSION);
    memcpy(record + 16, s->session, 16);
    stq_le_p(record + 32, r->id);
    stq_le_p(record + 40, r->length);
    stq_le_p(record + 48, r->offset);
    stq_le_p(record + 56, r->count);
    for (unsigned i = 0; i < r->count; i++) {
        stq_le_p(record + 64 + i * 8, r->pages[i] - DVM_SURFACE_DRAM_BASE);
    }
    snprintf(name, sizeof(name), "%016" PRIx64 ".pages", r->id);
    int fd = openat(s->surface_dir, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) {
        return false;
    }
    bool ok = write(fd, record, 64 + r->count * 8) == 64 + r->count * 8;
    close(fd);
    if (!ok) {
        unlinkat(s->surface_dir, name, 0);
    }
    return ok;
}

static unsigned surface_retire(DVMGPUTransport *s, uint64_t id)
{
    if (!dvm_surface_find(s->surfaces, id)) {
        return DVM_SURFACE_STALE;
    }
    char name[40]; uint8_t record[32]; struct stat st;
    snprintf(name, sizeof(name), "%016" PRIx64 ".retired", id);
    int fd = openat(s->surface_dir, name, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        return DVM_SURFACE_BUSY;
    }
    bool ok = !fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_uid == getuid() &&
        !(st.st_mode & 077) && st.st_size == sizeof(record) &&
        read(fd, record, sizeof(record)) == sizeof(record) &&
        !memcmp(record, s->session, 16) && ldq_le_p(record + 16) == id &&
        ldq_le_p(record + 24) == DVM_SURFACE_RETIRED_MAGIC;
    close(fd);
    /* Missing/partial/foreign acknowledgements never authorize kernel unpin. */
    return ok ? dvm_surface_retire(s->surfaces, id) : DVM_SURFACE_BUSY;
}

static void surface_write(DVMGPUTransport *s, hwaddr off, uint64_t value)
{
    DVMSurfaceRegistry *r = s->surfaces;
    if (r->poisoned) {
        r->status = DVM_SURFACE_POISONED;
        return;
    }
    switch (off) {
    case 0x100:
        dvm_surface_begin(r, value);
        break;
    case 0x108:
        r->next_offset = value;
        break;
    case 0x110:
        dvm_surface_page(r, value);
        break;
    case 0x118: {
        if (value != 1) {
            r->status = DVM_SURFACE_ARGUMENT;
            break;
        }
        DVMSurfaceRecord *entry = dvm_surface_ready(r);
        if (entry) {
            if (surface_publish(s, entry)) {
                dvm_surface_activate(r);
                info_report("dvm-surface: registered id=%" PRIu64 " bytes=%" PRIu64
                            " offset=%" PRIu64 " pages=%u", entry->id, entry->length, entry->offset, entry->count);
            } else {
                r->status = DVM_SURFACE_IO;
            }
        }
        if (r->status) {
            dvm_surface_abort(r);
        }
        break;
    }
    case 0x120:
        r->status = surface_retire(s, value);
        if (!r->status) {
            info_report("dvm-surface: retired id=%" PRIu64 " host-ack=validated", value);
        }
        break;
    case 0x130:
        r->poisoned = true;
        r->status = DVM_SURFACE_POISONED;
        break;
    default:
        r->status = DVM_SURFACE_ARGUMENT;
        break;
    }
}

/* DVM experimental kernel registration ABI, not Apple hardware semantics.
 * This third DT aperture is never returned by clientMemoryForType. The boot
 * service emits pages from its prepared, VM-lifetime retained descriptor.
 * No page list or address is accepted by the userspace workload protocol. */
static uint64_t managed_read(void *opaque, hwaddr off, unsigned size)
{
    DVMGPUTransport *s = opaque;
    if (size == 8 && s->surfaces && off >= 0x100) {
        if (off == 0x118) {
            return s->surfaces->last_id;
        }
        if (off == 0x128) {
            return s->surfaces->status;
        }
        if (off == 0x138) {
            return DVM_SURFACE_VERSION;
        }
        return 0;
    }
    return off == 16 && size == 8 ? s->managed_ready : 0;
}

static void managed_write(void *opaque, hwaddr off, uint64_t value, unsigned size)
{
    DVMGPUTransport *s = opaque;
    if (size == 8 && s->surfaces && off >= 0x100 && !s->error) {
        surface_write(s, off, value);
        return;
    }
    if (size != 8 || s->managed_ready || s->error) {
        failed(s, 20); return;
    }
    if (off == 0 && !s->managed_started && value == 12435456) {
        s->managed_started = true;
    } else if (off == 8 && s->managed_started && s->managed_count < 759) {
        if ((value & 16383) || value < 0x10000000000ULL ||
            value >= 0x10300000000ULL) {
            failed(s, 21); return;
        }
        for (unsigned i = 0; i < s->managed_count; i++) {
            if (s->managed_pages[i] == value) { failed(s, 22); return; }
        }
        unsigned page = (value - DVM_SURFACE_DRAM_BASE) / DVM_SURFACE_PAGE;
        if (s->surfaces->owners[page]) { failed(s, 22); return; }
        s->surfaces->owners[page] = DVM_SURFACE_LEGACY_OWNER;
        s->managed_pages[s->managed_count++] = value;
    } else if (off == 16 && value == 1 && s->managed_count == 759) {
        uint8_t record[32 + 759 * 8] = {0};
        memcpy(record, s->session, 16);
        stq_le_p(record + 16, 12435456);
        stq_le_p(record + 24, 759);
        for (unsigned i = 0; i < 759; i++) {
            stq_le_p(record + 32 + i * 8, s->managed_pages[i] - 0x10000000000ULL);
        }
        if (pwrite(s->managed_fd, record, sizeof(record), 0) != sizeof(record)) {
            failed(s, 23); return;
        }
        s->managed_ready = true;
        info_report("dvm-managed: registered pages=759 bytes=12435456 lifetime=vm");
    } else {
        failed(s, 24);
    }
}

static const MemoryRegionOps managed_ops = {
    .read = managed_read, .write = managed_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 8, .max_access_size = 8 },
    .impl = { .min_access_size = 8, .max_access_size = 8 },
};

static void failed(DVMGPUTransport *s, unsigned code)
{
    if (!s->error) {
        s->error = code;
        warn_report("dvm-gpu-shm: failed code=%u submitted=%" PRIu64
                    " done=%" PRIu64, code, s->submitted, s->done);
    }
}

static bool valid_header(DVMGPUTransport *s, unsigned offset, uint64_t seq)
{
    uint8_t *h = s->bytes + offset;
    return !memcmp(h, s->session, 16) && ldq_le_p(h + 16) == seq &&
           ldl_le_p(h + 24) <= (s->present ? 0x10000 : DVM_GPU_MAX_BYTES);
}

static void completed(DVMGPUTransport *s, uint64_t seq)
{
    uint8_t *h = s->bytes + DVM_GPU_REPLY_HEADER;
    if (s->error || !s->ready || !seq || seq != s->submitted ||
        seq <= s->done || !valid_header(s, DVM_GPU_REPLY_HEADER, seq)) {
        failed(s, 5);
        return;
    }
    /* ldl_le_p returns signed int; widening it against zlib's unsigned long
     * sign-extends CRCs with bit 31 set. The wire contract is uint32_t. */
    uint32_t expected_crc = ldl_le_p(h + 28);
    uint32_t actual_crc = crc32(0, s->bytes + (s->present ? 0x200000 : DVM_GPU_REPLY_DATA),
                               ldl_le_p(h + 24));
    if (actual_crc != expected_crc) {
        failed(s, 6);
        return;
    }
    smp_wmb();
    s->done = seq;
}

static int notify_can_read(void *opaque)
{
    DVMGPUTransport *s = opaque;
    return sizeof(s->rx) - s->rx_used;
}

static void notify_read(void *opaque, const uint8_t *buf, int size)
{
    DVMGPUTransport *s = opaque;
    for (int i = 0; i < size; i++) {
        s->rx[s->rx_used++] = buf[i];
        if (s->rx_used == sizeof(s->rx)) {
            uint64_t seq = ldq_le_p(s->rx);
            uint32_t status = ldl_le_p(s->rx + 8);
            s->rx_used = 0;
            if (status || ldl_le_p(s->rx + 12)) {
                failed(s, 7);
            } else if (!seq && !s->submitted && !s->ready && !s->error) {
                /* Host sends READY only after initializing its GPU and data. */
                smp_rmb();
                s->ready = true;
            } else {
                completed(s, seq);
            }
        }
    }
}

static void notify_event(void *opaque, QEMUChrEvent event)
{
    DVMGPUTransport *s = opaque;
    if (event == CHR_EVENT_OPENED) {
        s->connected = true;
    } else if (event == CHR_EVENT_CLOSED && s->connected) {
        s->ready = false;
        failed(s, 8);
    }
}

static uint64_t reg_read(void *opaque, hwaddr offset, unsigned size)
{
    DVMGPUTransport *s = opaque;
    switch (offset) {
    case 0: return DVM_GPU_MAGIC;
    case 8: return DVM_GPU_RAM_SIZE;
    case DVM_GPU_REG_DONE: return s->done;
    case DVM_GPU_REG_ERROR: return s->error;
    case DVM_GPU_REG_MODE: return s->external ? (s->present ? 3 : 2) : 1;
    case DVM_GPU_REG_SUBMITTED: return s->submitted;
    case DVM_GPU_REG_READY: return s->ready;
    default: return 0;
    }
}

static void reg_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    DVMGPUTransport *s = opaque;
    uint8_t *h = s->bytes + DVM_GPU_REQUEST_HEADER;
    if (offset != DVM_GPU_REG_DOORBELL || size != 8 || s->error) {
        failed(s, 1);
        return;
    }
    smp_rmb();
    if (!s->ready || !value || s->submitted != s->done ||
        value != s->submitted + 1 ||
        !valid_header(s, DVM_GPU_REQUEST_HEADER, value)) {
        failed(s, 2);
        return;
    }
    uint32_t length = ldl_le_p(h + 24), crc = ldl_le_p(h + 28);
    if (crc32(0, s->bytes + DVM_GPU_REQUEST_DATA, length) != crc) {
        failed(s, 3);
        return;
    }
    s->submitted = value;
    if (s->external) {
        uint8_t packet[16];
        stq_le_p(packet, value);
        stl_le_p(packet + 8, length);
        stl_le_p(packet + 12, crc);
        if (qemu_chr_fe_write_all(&s->notify, packet, sizeof(packet)) !=
            sizeof(packet)) {
            failed(s, 4);
        }
    } else {
        for (uint32_t i = 0; i < length; i++) {
            s->bytes[DVM_GPU_REPLY_DATA + i] =
                s->bytes[DVM_GPU_REQUEST_DATA + i] ^ 0xa5;
        }
        h = s->bytes + DVM_GPU_REPLY_HEADER;
        memcpy(h, s->session, 16);
        stq_le_p(h + 16, value);
        stl_le_p(h + 24, length);
        stl_le_p(h + 28, crc32(0, s->bytes + DVM_GPU_REPLY_DATA, length));
        completed(s, value);
    }
}

static const MemoryRegionOps reg_ops = {
    .read = reg_read,
    .write = reg_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 8 },
    .impl = { .min_access_size = 4, .max_access_size = 8 },
};

void darwin_gpu_transport_init(struct dtree_node *root, unsigned long long iobase)
{
    const char *path = getenv("DARWIN_GPU_SHM_PATH");
    struct dtree_node *node = adt_find_node(root, "arm-io/dvm-transport");
    if (!path && !node) {
        return;
    }
    struct adt_io_reg *ranges = node ? adt_get_prop_val(node, "reg") : NULL;
    const char *managed_path = getenv("DARWIN_GPU_MANAGED_PAGES_PATH");
    bool managed = managed_path != NULL;
    if (!path || !node || adt_get_prop_len(node, "reg") != (managed ? 3 : 2) * sizeof(*ranges) ||
        ranges[0].base + iobase != DVM_GPU_RAM_BASE ||
        ranges[0].len != DVM_GPU_RAM_SIZE ||
        ranges[1].base + iobase != DVM_GPU_REG_BASE ||
        ranges[1].len != DVM_GPU_REG_SIZE) {
        error_report("dvm-gpu-shm: requires paired owned RAM file and exact DT ranges");
        exit(1);
    }
    int fd = open(path, O_RDWR | O_NOFOLLOW);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        st.st_size != DVM_GPU_RAM_SIZE) {
        error_report("dvm-gpu-shm: RAM backend must be an existing 16 MiB regular file");
        exit(1);
    }
    DVMGPUTransport *s = g_new0(DVMGPUTransport, 1);
    s->managed_fd = -1;
    s->surface_dir = -1;
    if (managed) {
        if (!getenv("DARWIN_GPU_MANAGED_RAM_PATH") ||
            ranges[2].base + iobase != DVM_GPU_REG_BASE + DVM_GPU_REG_SIZE ||
            ranges[2].len != DVM_GPU_REG_SIZE) {
            error_report("dvm-managed: exact kernel-only registration range required");
            exit(1);
        }
        s->managed_fd = open(managed_path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
        if (s->managed_fd < 0) { error_report("dvm-managed: exclusive page manifest failed"); exit(1); }
        g_autofree char *surface_path = g_strconcat(managed_path, ".imports", NULL);
        if (mkdir(surface_path, 0700) ||
            (s->surface_dir = open(surface_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)) < 0) {
            error_report("dvm-surface: exclusive registry directory failed"); exit(1);
        }
        s->surfaces = g_new0(DVMSurfaceRegistry, 1);
        memory_region_init_io(&s->registration, NULL, &managed_ops, s,
                              "dvm-managed-registration", DVM_GPU_REG_SIZE);
        memory_region_add_subregion_overlap(get_system_memory(),
            DVM_GPU_REG_BASE + DVM_GPU_REG_SIZE, &s->registration, 1);
    }
    if (!memory_region_init_ram_from_fd(&s->ram, NULL, "dvm-gpu-shared-ram",
                                       DVM_GPU_RAM_SIZE, RAM_SHARED, fd, 0,
                                       &error_fatal)) {
        exit(1);
    }
    s->bytes = memory_region_get_ram_ptr(&s->ram);
    memset(s->bytes, 0, DVM_GPU_RAM_SIZE);
    stl_le_p(s->bytes, DVM_GPU_MAGIC);
    stl_le_p(s->bytes + 4, 1);
    for (unsigned i = 0; i < sizeof(s->session); i += 4) {
        stl_le_p(s->session + i, g_random_int());
    }
    memcpy(s->bytes + 16, s->session, sizeof(s->session));
    Chardev *chr = qemu_chr_find("dvm_gpu_notify");
    s->external = chr != NULL;
    const char *present = getenv("DARWIN_GPU_PRESENT_TRANSPORT");
    s->present = present && !strcmp(present, "1");
    if (s->present && !s->external) {
        error_report("dvm-gpu-shm: compact control layout requires external backend");
        exit(1);
    }
    /* Mode 3 reserves [0x300000,16MiB) for GPU BGRA output. Control replies
     * move to 0x200000; both control payloads are bounded to 64KiB. Mode 2
     * and its existing 4MiB framed layout are unchanged. */
    s->ready = !s->external;
    if (chr) {
        qemu_chr_fe_init(&s->notify, chr, &error_fatal);
        qemu_chr_fe_set_handlers(&s->notify, notify_can_read, notify_read,
                                notify_event, NULL, s, NULL, true);
    }
    memory_region_init_io(&s->regs, NULL, &reg_ops, s, "dvm-gpu-doorbell",
                          DVM_GPU_REG_SIZE);
    memory_region_add_subregion_overlap(get_system_memory(), DVM_GPU_RAM_BASE,
                                        &s->ram, 1);
    memory_region_add_subregion_overlap(get_system_memory(), DVM_GPU_REG_BASE,
                                        &s->regs, 1);
    error_setg(&s->migration_blocker,
               "DVM shared-memory transport needs a drain/reset checkpoint contract");
    if (migrate_add_blocker(&s->migration_blocker, &error_fatal) < 0) {
        exit(1);
    }
    info_report("dvm-gpu-shm: RAM=0x%llx bytes=0x%llx doorbell=0x%llx mode=%s migration=blocked",
                DVM_GPU_RAM_BASE, DVM_GPU_RAM_SIZE, DVM_GPU_REG_BASE,
                s->external ? "external" : "echo");
}
