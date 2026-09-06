/*
 * Diagnostic-only T8140 AES software-key MMIO adapter.
 * Register evidence: superproject docs/re/native-aes-bringup.md.
 * CTRL+8 start1/stop2 (93ef04c/93eef64); INT_STATUS+18 W1C (93eeaa4),
 * INT_ENABLE+1c; FIFO_STATUS+24 occupancy[15:8], empty bit1 (93f1114,
 * 93eef90); completion+30 tag[7:0] (93f0910); FIFO+200 (93f11fc).
 * Completion IRQ bit5 is handled at93eeab8/93eeb48.
 *
 * STATUS+0c readiness follows initialization of seven virtual entropy slots.
 * The guest-visible mask3f80 is checked at93eefd4..93eeff0; reference V5
 * layouts name six text and one key-unwrap random-seeded bits. Host entropy
 * models this initialization state, not physical power-analysis circuitry.
 * Secondary key/fuse windows remain
 * unimplemented. Never expose this partial engine in a baseline image.
 * Enable only with DARWIN_AES=software and a matching diagnostic tree.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "crypto/cipher.h"
#include "crypto/random.h"
#include "migration/vmstate.h"
#include "hw/core/irq.h"
#include "system/address-spaces.h"
#include "hw/arm/darwin_aes_engine.h"
#include "xnu/darwin_aes.h"
#include "xnu/darwin_aic.h"
#include "xnu/darwin_dart.h"

#define TYPE_DARWIN_AES "darwin-aes"
OBJECT_DECLARE_SIMPLE_TYPE(DarwinAESState, DARWIN_AES)
struct DarwinAESState {
    SysBusDevice parent_obj;
    MemoryRegion mmio;
    qemu_irq irq;
    DeviceState *dart;
    DarwinAESEngine engine;
    uint32_t interrupt_status, interrupt_enable, watermark, tag;
    bool active;
    bool entropy_ready;
    uint8_t entropy_seed[7][32];
    unsigned log_count;
};

static void update_irq(DarwinAESState *s)
{
    qemu_set_irq(s->irq, !!(s->interrupt_status & s->interrupt_enable));
}

static bool dma(void *opaque, uint64_t dva, uint8_t *buffer, size_t n, bool write)
{
    DarwinAESState *s = opaque;
    while (n) {
        uint64_t pa;
        size_t part = MIN(n, 0x4000 - (dva & 0x3fff));
        if (!darwin_dart_translate(s->dart, 1, dva, &pa) ||
            address_space_rw(&address_space_memory, pa, MEMTXATTRS_UNSPECIFIED,
                             buffer, part, write) != MEMTX_OK) {
            fprintf(stderr, "aes: DMA %s failed at DVA 0x%" PRIx64 "\n",
                    write ? "write" : "read", dva);
            return false;
        }
        dva += part;
        buffer += part;
        n -= part;
    }
    return true;
}

static void complete(void *opaque, uint8_t tag)
{
    DarwinAESState *s = opaque;
    s->tag = tag;
    s->interrupt_status |= 1 << 5;
    if (s->log_count++ < 32) {
        fprintf(stderr, "aes: software DMA completed tag %u\n", tag);
    }
    update_irq(s);
}

static uint64_t read_reg(void *opaque, hwaddr off, unsigned size)
{
    DarwinAESState *s = opaque;
    switch (off) {
    case 0x08: return s->active ? 1 : 2;
    case 0x0c: return s->entropy_ready ? 0x3f80 : 0;
    case 0x18: return s->interrupt_status;
    case 0x1c: return s->interrupt_enable;
    case 0x20: return s->watermark;
    case 0x24: return (s->engine.count << 8) | (s->engine.count ? 0 : 2);
    case 0x30: return s->tag;
    default:
        if (s->log_count++ < 64) {
            fprintf(stderr, "aes: unimplemented read +0x%" HWADDR_PRIx "\n", off);
        }
        return 0;
    }
}

static void write_reg(void *opaque, hwaddr off, uint64_t value, unsigned size)
{
    DarwinAESState *s = opaque;
    switch (off) {
    case 0x08:
        if (value == 1 || value == 2) {
            s->active = value == 1;
            return;
        }
        break;
    case 0x18:
        s->interrupt_status &= ~value;
        update_irq(s);
        return;
    case 0x1c:
        s->interrupt_enable = value;
        update_irq(s);
        return;
    case 0x20:
        s->watermark = value;
        return;
    case 0x200:
        if (!s->active || s->engine.failed) {
            return;
        }
        if (!darwin_aes_push(&s->engine, value, dma, complete, s)) {
            fprintf(stderr, "aes: unsupported/failed FIFO request header 0x%08x,"
                    " no completion; engine halted\n", s->engine.fifo[0]);
        }
        return;
    }
    if (s->log_count++ < 64) {
        fprintf(stderr, "aes: unimplemented write +0x%" HWADDR_PRIx
                " = 0x%" PRIx64 "\n", off, value);
    }
}

static const MemoryRegionOps ops = {
    .read = read_reg, .write = write_reg, .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

static void realize(DeviceState *dev, Error **errp)
{
    DarwinAESState *s = DARWIN_AES(dev);
    if (!qcrypto_cipher_supports(QCRYPTO_CIPHER_ALGO_AES_256, QCRYPTO_CIPHER_MODE_CBC)) {
        error_setg(errp, "diagnostic AES requires a working host AES/CBC backend");
        return;
    }
    s->dart = darwin_dart_find("dart-sio");
    if (!s->dart) {
        error_setg(errp, "diagnostic AES requires dart-sio mapper SID 1");
        return;
    }
    memory_region_init_io(&s->mmio, OBJECT(dev), &ops, s, "darwin-aes", 0x4000);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->mmio);
    sysbus_init_irq(SYS_BUS_DEVICE(s), &s->irq);
}

static void reset(DeviceState *dev)
{
    DarwinAESState *s = DARWIN_AES(dev);
    memset(&s->engine, 0, sizeof(s->engine));
    s->interrupt_status = s->interrupt_enable = s->watermark = s->tag = 0;
    s->active = false;
    /* Seed contents/width are internal to the virtual model. Only successful
     * initialization is guest-visible. Do not set GID or FairPlay self-test
     * bits: those engines are not implemented. Entropy never substitutes for
     * a hardware UID/GID key and does not change AES's deterministic output. */
    s->entropy_ready = qcrypto_random_bytes(s->entropy_seed,
                                            sizeof(s->entropy_seed), NULL) == 0;
    if (!s->entropy_ready) {
        fprintf(stderr, "aes: entropy initialization failed; readiness remains clear\n");
    }
    update_irq(s);
}

static const VMStateDescription vmstate_aes_diagnostic = {
    .name = "darwin-aes-diagnostic", .unmigratable = true,
};

static void class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    dc->realize = realize;
    device_class_set_legacy_reset(dc, reset);
    /* Until pending-state/IRQ restore tests exist, fail checkpoint creation
     * instead of silently dropping an in-flight cryptographic transaction. */
    dc->vmsd = &vmstate_aes_diagnostic;
    dc->user_creatable = false;
}

static const TypeInfo info = {
    .name = TYPE_DARWIN_AES, .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(DarwinAESState), .class_init = class_init,
};
static void register_types(void) { type_register_static(&info); }
type_init(register_types)

void darwin_aes_create(struct dtree_node *root, uint64_t iobase, DeviceState *aic)
{
    const char *mode = getenv("DARWIN_AES");
    if (!mode || strcmp(mode, "software")) {
        return;
    }
    struct dtree_node *node = adt_find_node(root, "arm-io/aes");
    const char *compat = node ? adt_get_prop_val(node, "compatible") : NULL;
    uint32_t *version = node ? adt_get_prop_val(node, "aes-version") : NULL;
    uint32_t *width = node ? adt_get_prop_val(node, "address-width") : NULL;
    struct adt_io_reg *reg = node ? adt_get_prop_val(node, "reg") : NULL;
    uint32_t *irq = node ? adt_get_prop_val(node, "interrupts") : NULL;
    if (!compat || strcmp(compat, "aes,s8000") || !version || *version != 5 ||
        !width || *width != 42 || !reg || reg[0].len != 0x4000 || !irq) {
        fprintf(stderr, "aes: diagnostic T8140/version5 tree required; not created\n");
        return;
    }
    DeviceState *dev = qdev_new(TYPE_DARWIN_AES);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(dev), 0, iobase + reg[0].base);
    sysbus_connect_irq(SYS_BUS_DEVICE(dev), 0, darwin_aic_get_irq(aic, *irq));
    fprintf(stderr, "aes: diagnostic software engine, host entropy initialization, IRQ 0x%x\n", *irq);
}
