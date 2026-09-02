/*
 * darwin-aic: Apple Interrupt Controller v2 / v3 model
 *
 * The AIC is a very simple level-triggered interrupt controller:
 *
 *   base + 0x00  VERSION   (rev in bits [7:0])
 *   base + 0x04  INFO1     (implemented irq count in bits [15:0], last die [27:24])
 *   base + 0x0c  INFO3     (register array size in bits [15:0], max die [27:24])
 *   base + 0x10  RESET
 *   base + 0x14  CONFIG    (bit 0 = enable)
 *   base + <iack offset>   EVENT: read returns and auto-masks the highest
 *                          priority pending irq as (die << 24 | 1 << 16 | irq)
 *
 * followed, at "extint-baseaddress" (0x2000 for v2, 0x10000 for v3), by one
 * block per die, each "intmaskset-stride" bytes long:
 *
 *   + 0x0000            IRQ_CFG[max_irq]        (u32 per irq: target cpu etc)
 *   + max_irq * 4       SW_SET[max_irq / 32]    (w1s: software pending)
 *   + ... + words       SW_CLR                  (w1c: software pending)
 *   + ... + words       MASK_SET                (w1s: mask)
 *   + ... + words       MASK_CLR                (w1c: mask)
 *   + ... + words       HW_STATE                (ro: raw input level)
 *
 * All offsets/ strides come from the device tree, which is also how XNU's
 * AppleInterruptControllerV3 finds them, so the same model covers every
 * AIC2/AIC3 SoC. Register semantics follow the Linux irq-apple-aic driver and
 * were cross-checked against the XNU driver's event decode
 * (type = bits[18:16] == 1, irq = bits[11:0], die = bits[26:24]).
 *
 * IPIs on these SoCs use IMP-DEF system registers, not the AIC MMIO, and the
 * timer is wired straight to FIQ, so neither is modelled here.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "hw/core/sysbus.h"
#include "hw/core/irq.h"
#include "hw/core/qdev-properties.h"
#include "system/memory.h"
#include "xnu/boot/xnuboot.h"
#include "xnu/apple_dtree.h"
#include "xnu/darwin_aic.h"

OBJECT_DECLARE_SIMPLE_TYPE(DarwinAICState, DARWIN_AIC)

#define AIC_MAX_DIES        8
#define AIC_DEFAULT_MAX_IRQ 0x1000

#define AIC_REG_RESET       0x10

#define AIC_EVENT_TYPE_IRQ  1

struct DarwinAICState {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    qemu_irq irq_out;

    // configuration (from the device tree)
    uint32_t version;
    uint32_t mmio_size;
    uint32_t max_irq;        // size of the per-die register arrays
    uint32_t num_dies;
    uint32_t ext_base;       // "extint-baseaddress"
    uint32_t die_stride;     // "intmaskset-stride" & friends
    uint32_t event_off;      // "aic-iack-offset"
    uint32_t rev_off, cap0_off, info3_off, cfg_off;

    // derived
    uint32_t words;          // max_irq / 32
    uint32_t off_sw_set, off_sw_clr, off_mask_set, off_mask_clr, off_hw_state;

    // state
    uint32_t config;
    uint32_t *irq_cfg;       // [num_dies][max_irq]
    uint32_t *hw_state;      // [num_dies][words]
    uint32_t *sw_pending;    // [num_dies][words]
    uint32_t *mask;          // [num_dies][words]
    uint32_t *misc;          // backing store for everything else
    qemu_irq *irqs_in;       // [num_dies * max_irq]
    bool line;
    bool debug;
};

static inline uint32_t *die_words(uint32_t *arr, DarwinAICState *s, int die) {
    return arr + die * s->words;
}

static bool aic_pending(DarwinAICState *s, int *out_die, int *out_irq) {
    for (int d = 0; d < s->num_dies; d++) {
        uint32_t *hw = die_words(s->hw_state, s, d);
        uint32_t *sw = die_words(s->sw_pending, s, d);
        uint32_t *mk = die_words(s->mask, s, d);
        for (uint32_t w = 0; w < s->words; w++) {
            uint32_t p = (hw[w] | sw[w]) & ~mk[w];
            if (p) {
                if (out_die) *out_die = d;
                if (out_irq) *out_irq = w * 32 + ctz32(p);
                return true;
            }
        }
    }
    return false;
}

static void aic_update(DarwinAICState *s) {
    bool level = aic_pending(s, NULL, NULL);
    if (level != s->line) {
        s->line = level;
        qemu_set_irq(s->irq_out, level);
    }
}

static void aic_set_irq(void *opaque, int n, int level) {
    DarwinAICState *s = opaque;
    int die = n / s->max_irq;
    int irq = n % s->max_irq;
    uint32_t *hw = die_words(s->hw_state, s, die);

    if (level) {
        hw[irq / 32] |= BIT(irq % 32);
    } else {
        hw[irq / 32] &= ~BIT(irq % 32);
    }
    aic_update(s);
}

static uint32_t aic_read_event(DarwinAICState *s) {
    int die, irq;
    if (!aic_pending(s, &die, &irq)) {
        return 0;
    }
    // Delivery auto-masks the interrupt; the driver unmasks it on EOI.
    die_words(s->mask, s, die)[irq / 32] |= BIT(irq % 32);
    aic_update(s);
    uint32_t ev = ((uint32_t)die << 24) | (AIC_EVENT_TYPE_IRQ << 16) | (uint32_t)irq;
    if (s->debug) fprintf(stderr, "aic: event -> die %d irq %d (0x%x)\n", die, irq, ev);
    return ev;
}

// Returns true (and fills die/sub) if offset lies inside a per-die block
static bool aic_die_block(DarwinAICState *s, hwaddr offset, int *die, uint32_t *sub) {
    if (offset < s->ext_base) return false;
    hwaddr rel = offset - s->ext_base;
    int d = rel / s->die_stride;
    if (d >= s->num_dies) return false;
    *die = d;
    *sub = rel % s->die_stride;
    return true;
}

static uint64_t aic_read(void *opaque, hwaddr offset, unsigned size) {
    DarwinAICState *s = opaque;
    uint32_t val = 0;
    int die;
    uint32_t sub;

    if (offset == s->event_off) {
        return aic_read_event(s);
    } else if (offset == s->rev_off) {
        val = s->version;
    } else if (offset == s->cap0_off) {
        val = (s->max_irq & 0xffff) | (((s->num_dies - 1) & 0xf) << 24);
    } else if (offset == s->info3_off) {
        val = (s->max_irq & 0xffff) | ((s->num_dies & 0xf) << 24);
    } else if (offset == s->cfg_off) {
        val = s->config;
    } else if (aic_die_block(s, offset, &die, &sub)) {
        uint32_t w;
        if (sub < s->off_sw_set) {
            val = s->irq_cfg[die * s->max_irq + sub / 4];
        } else if (sub < s->off_sw_clr) {
            w = (sub - s->off_sw_set) / 4;
            val = die_words(s->sw_pending, s, die)[w];
        } else if (sub < s->off_mask_set) {
            w = (sub - s->off_sw_clr) / 4;
            val = die_words(s->sw_pending, s, die)[w];
        } else if (sub < s->off_mask_clr) {
            w = (sub - s->off_mask_set) / 4;
            val = die_words(s->mask, s, die)[w];
        } else if (sub < s->off_hw_state) {
            w = (sub - s->off_mask_clr) / 4;
            val = die_words(s->mask, s, die)[w];
        } else if (sub < s->off_hw_state + s->words * 4) {
            w = (sub - s->off_hw_state) / 4;
            val = die_words(s->hw_state, s, die)[w];
        }
    } else if (offset + 4 <= s->mmio_size) {
        val = s->misc[offset / 4];
    }

    if (s->debug) fprintf(stderr, "aic: read  0x%05" HWADDR_PRIx " -> 0x%08x\n", offset, val);
    return val;
}

static void aic_reset_state(DarwinAICState *s) {
    memset(s->hw_state, 0, s->num_dies * s->words * 4);
    memset(s->sw_pending, 0, s->num_dies * s->words * 4);
    memset(s->mask, 0xff, s->num_dies * s->words * 4);   // everything masked after reset
    memset(s->irq_cfg, 0, s->num_dies * s->max_irq * 4);
    s->config = 0;
    aic_update(s);
}

static void aic_write(void *opaque, hwaddr offset, uint64_t value, unsigned size) {
    DarwinAICState *s = opaque;
    uint32_t val = value;
    int die;
    uint32_t sub;

    if (s->debug) fprintf(stderr, "aic: write 0x%05" HWADDR_PRIx " <- 0x%08x\n", offset, val);

    if (offset == s->event_off) {
        return;     // collides with pubstamp cfg on some device trees; ignore
    } else if (offset == s->rev_off || offset == s->cap0_off || offset == s->info3_off) {
        return;
    } else if (offset == s->cfg_off) {
        s->config = val;
    } else if (offset == AIC_REG_RESET) {
        if (val & 1) aic_reset_state(s);
    } else if (aic_die_block(s, offset, &die, &sub)) {
        uint32_t w;
        if (sub < s->off_sw_set) {
            s->irq_cfg[die * s->max_irq + sub / 4] = val;
        } else if (sub < s->off_sw_clr) {
            w = (sub - s->off_sw_set) / 4;
            die_words(s->sw_pending, s, die)[w] |= val;
        } else if (sub < s->off_mask_set) {
            w = (sub - s->off_sw_clr) / 4;
            die_words(s->sw_pending, s, die)[w] &= ~val;
        } else if (sub < s->off_mask_clr) {
            w = (sub - s->off_mask_set) / 4;
            die_words(s->mask, s, die)[w] |= val;
        } else if (sub < s->off_hw_state) {
            w = (sub - s->off_mask_clr) / 4;
            die_words(s->mask, s, die)[w] &= ~val;
        }
        aic_update(s);
    } else if (offset + 4 <= s->mmio_size) {
        s->misc[offset / 4] = val;
    }
}

static const MemoryRegionOps aic_ops = {
    .read = aic_read,
    .write = aic_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 8,
};

static void darwin_aic_realize(DeviceState *dev, Error **errp) {
    DarwinAICState *s = DARWIN_AIC(dev);

    if (!s->max_irq || (s->max_irq % 32) || !s->num_dies || s->num_dies > AIC_MAX_DIES || !s->mmio_size) {
        error_setg(errp, "darwin-aic: bad configuration");
        return;
    }

    s->words = s->max_irq / 32;
    s->off_sw_set   = s->max_irq * 4;
    s->off_sw_clr   = s->off_sw_set + s->words * 4;
    s->off_mask_set = s->off_sw_clr + s->words * 4;
    s->off_mask_clr = s->off_mask_set + s->words * 4;
    s->off_hw_state = s->off_mask_clr + s->words * 4;

    if (!s->die_stride) s->die_stride = s->off_hw_state + s->words * 4;
    if (s->die_stride < s->off_hw_state + s->words * 4) {
        error_setg(errp, "darwin-aic: die stride 0x%x too small for %u irqs", s->die_stride, s->max_irq);
        return;
    }

    s->irq_cfg    = g_new0(uint32_t, s->num_dies * s->max_irq);
    s->hw_state   = g_new0(uint32_t, s->num_dies * s->words);
    s->sw_pending = g_new0(uint32_t, s->num_dies * s->words);
    s->mask       = g_new0(uint32_t, s->num_dies * s->words);
    s->misc       = g_new0(uint32_t, s->mmio_size / 4);
    s->debug      = getenv("DARWIN_AIC_DEBUG") != NULL;

    memset(s->mask, 0xff, s->num_dies * s->words * 4);

    memory_region_init_io(&s->iomem, OBJECT(s), &aic_ops, s, "darwin-aic", s->mmio_size);
    sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->iomem);
    sysbus_init_irq(SYS_BUS_DEVICE(dev), &s->irq_out);
    s->irqs_in = qemu_allocate_irqs(aic_set_irq, s, s->num_dies * s->max_irq);
    qdev_init_gpio_in(dev, aic_set_irq, s->num_dies * s->max_irq);
}

static const Property darwin_aic_properties[] = {
    DEFINE_PROP_UINT32("version", DarwinAICState, version, 3),
    DEFINE_PROP_UINT32("mmio-size", DarwinAICState, mmio_size, 0),
    DEFINE_PROP_UINT32("max-irq", DarwinAICState, max_irq, AIC_DEFAULT_MAX_IRQ),
    DEFINE_PROP_UINT32("num-dies", DarwinAICState, num_dies, 1),
    DEFINE_PROP_UINT32("ext-base", DarwinAICState, ext_base, 0x10000),
    DEFINE_PROP_UINT32("die-stride", DarwinAICState, die_stride, 0),
    DEFINE_PROP_UINT32("event-offset", DarwinAICState, event_off, 0x1000),
    DEFINE_PROP_UINT32("rev-offset", DarwinAICState, rev_off, 0x0),
    DEFINE_PROP_UINT32("cap0-offset", DarwinAICState, cap0_off, 0x4),
    DEFINE_PROP_UINT32("info3-offset", DarwinAICState, info3_off, 0xc),
    DEFINE_PROP_UINT32("cfg-offset", DarwinAICState, cfg_off, 0x14),
};

static void darwin_aic_class_init(ObjectClass *klass, const void *data) {
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = darwin_aic_realize;
    dc->desc = "Apple Interrupt Controller (AIC v2/v3)";
    device_class_set_props(dc, darwin_aic_properties);
    dc->user_creatable = false;
}

static const TypeInfo darwin_aic_info = {
    .name          = TYPE_DARWIN_AIC,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(DarwinAICState),
    .class_init    = darwin_aic_class_init,
};

static void darwin_aic_register_types(void) {
    type_register_static(&darwin_aic_info);
}

type_init(darwin_aic_register_types)

/* ---------------- device tree glue ---------------- */

static uint32_t dt_u32(struct dtree_node *n, const char *prop, uint32_t dflt) {
    void *v = adt_get_prop_val(n, prop);
    if (!v) return dflt;
    size_t len = adt_get_prop_len(n, prop);
    if (len == 8) return (uint32_t)*(uint64_t *)v;
    if (len == 4) return *(uint32_t *)v;
    return dflt;
}

DeviceState *darwin_aic_create(struct dtree_node *dt_root, uint64_t iobase, qemu_irq cpu_irq) {
    struct dtree_node *aic = adt_find_node(dt_root, "arm-io/aic");
    if (!aic) {
        fprintf(stderr, "error: device tree has no /arm-io/aic\n");
        exit(1);
    }

    struct adt_io_reg *reg = adt_get_prop_val(aic, "reg");
    int version = 0;
    const char *compat = adt_get_prop_val(aic, "compatible");
    if (compat) sscanf(compat, "aic,%d", &version);
    if (version != 2 && version != 3) {
        fprintf(stderr, "error: unsupported AIC '%s' (only aic,2 and aic,3 are modelled)\n", compat ? compat : "?");
        exit(1);
    }

    uint32_t die_stride = dt_u32(aic, "intmaskset-stride", 0x4a00);
    // die stride = 4*max_irq (IRQ_CFG) + 5 bitmaps of max_irq/32 words
    uint32_t max_irq = (uint32_t)(((uint64_t)die_stride * 8) / 37);
    max_irq &= ~31u;
    if (!max_irq) max_irq = AIC_DEFAULT_MAX_IRQ;

    DeviceState *dev = qdev_new(TYPE_DARWIN_AIC);
    qdev_prop_set_uint32(dev, "version", version);
    qdev_prop_set_uint32(dev, "mmio-size", reg[0].len);
    qdev_prop_set_uint32(dev, "max-irq", max_irq);
    qdev_prop_set_uint32(dev, "num-dies", 1);
    qdev_prop_set_uint32(dev, "ext-base", dt_u32(aic, "extint-baseaddress", version == 3 ? 0x10000 : 0x2000));
    qdev_prop_set_uint32(dev, "die-stride", die_stride);
    qdev_prop_set_uint32(dev, "event-offset", dt_u32(aic, "aic-iack-offset", 0x1000));
    qdev_prop_set_uint32(dev, "rev-offset", dt_u32(aic, "rev-offset", 0x0));
    qdev_prop_set_uint32(dev, "cap0-offset", dt_u32(aic, "cap0-offset", 0x4));
    qdev_prop_set_uint32(dev, "info3-offset", dt_u32(aic, "maxnumirq-offset", 0xc));
    qdev_prop_set_uint32(dev, "cfg-offset", dt_u32(aic, "aicglbcfg-offset", 0x14));

    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);
    sysbus_realize_and_unref(sbd, &error_fatal);
    sysbus_mmio_map(sbd, 0, reg[0].base + iobase);
    sysbus_connect_irq(sbd, 0, cpu_irq);

    fprintf(stderr, "darwin-aic: aic,%d at 0x%" PRIx64 " (%u vectors, ext 0x%x, stride 0x%x, iack 0x%x)\n",
            version, reg[0].base + iobase, max_irq,
            dt_u32(aic, "extint-baseaddress", version == 3 ? 0x10000 : 0x2000), die_stride,
            dt_u32(aic, "aic-iack-offset", 0x1000));
    return dev;
}

qemu_irq darwin_aic_get_irq(DeviceState *aic, uint32_t vector) {
    return qdev_get_gpio_in(aic, vector);
}
