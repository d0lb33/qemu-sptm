/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Narrow d47 iBoot GPIO capability register.
 *
 * d47 mBoot-20457.2.37 RELEASE and RESEARCH_RELEASE read physical
 * 0x31a000c4c and consume only bit 0.  The independent d47 23G83 image has
 * the same literal load and bit extraction.  Both current-build consumers
 * require bit 0 before accessing the device-tree-described gpio-canary path.
 * This model exposes that cross-build capability bit and nothing else; it is
 * not a GPIO pin value or a device-completion response.
 *
 * Early platform setup also addresses gpio0 pins 139, 138, 137, 88, 87, and
 * 71, and 70.  The
 * getter consumes configuration/ownership bit 21 before the generic GPIO code
 * may rewrite the same 32-bit register.  The VM starts these observed pins
 * unconfigured (zero) and provides ordinary read/write storage.  No input
 * level or completion bit is asserted.
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "system/memory.h"
#include "system/address-spaces.h"
#include "xnu/apple_dtree.h"
#include "xnu/darwin_gpio.h"

#define D47_GPIO_CAPABILITY_OFFSET UINT64_C(0xc4c)
#define D47_GPIO_CAPABILITY_CANARY UINT32_C(1)
#define D47_GPIO_EARLY_PIN_COUNT 7

typedef struct DarwinGPIOPin {
    MemoryRegion mr;
    uint32_t word;
    unsigned pin;
} DarwinGPIOPin;

typedef struct DarwinGPIOIboot {
    MemoryRegion capability_mr;
    DarwinGPIOPin early_pins[D47_GPIO_EARLY_PIN_COUNT];
} DarwinGPIOIboot;

static uint64_t darwin_gpio_pin_read(void *opaque, hwaddr offset,
                                     unsigned size)
{
    DarwinGPIOPin *slot = opaque;

    if (offset != 0 || size != 4) {
        error_report("darwin-gpio: invalid pin%u read offset=0x%"
                     HWADDR_PRIx " size=%u", slot->pin, offset, size);
        exit(EXIT_FAILURE);
    }
    return slot->word;
}

static void darwin_gpio_pin_write(void *opaque, hwaddr offset,
                                  uint64_t value, unsigned size)
{
    DarwinGPIOPin *slot = opaque;

    if (offset != 0 || size != 4 || value > UINT32_MAX) {
        error_report("darwin-gpio: invalid pin%u write offset=0x%"
                     HWADDR_PRIx " value=0x%" PRIx64 " size=%u",
                     slot->pin, offset, value, size);
        exit(EXIT_FAILURE);
    }
    slot->word = value;
    fprintf(stderr,
            "darwin-gpio: pin%u configuration stored as 0x%08x"
            " (no input/completion bits synthesized)\n", slot->pin,
            slot->word);
}

static uint64_t darwin_gpio_capability_read(void *opaque, hwaddr offset,
                                            unsigned size)
{
    if (offset != 0 || size != 4) {
        error_report("darwin-gpio: invalid capability read offset=0x%"
                     HWADDR_PRIx " size=%u", offset, size);
        exit(EXIT_FAILURE);
    }
    return D47_GPIO_CAPABILITY_CANARY;
}

static void darwin_gpio_capability_write(void *opaque, hwaddr offset,
                                         uint64_t value, unsigned size)
{
    error_report("darwin-gpio: unexpected capability write offset=0x%"
                 HWADDR_PRIx " value=0x%" PRIx64 " size=%u",
                 offset, value, size);
    exit(EXIT_FAILURE);
}

static const MemoryRegionOps darwin_gpio_capability_ops = {
    .read = darwin_gpio_capability_read,
    .write = darwin_gpio_capability_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

static const MemoryRegionOps darwin_gpio_pin_ops = {
    .read = darwin_gpio_pin_read,
    .write = darwin_gpio_pin_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

void darwin_gpio_iboot_init(struct dtree_node *dt_root, uint64_t iobase)
{
    const char *target = adt_get_prop_val(dt_root, "target-type");
    struct dtree_node *gpio = adt_find_node(dt_root, "arm-io/gpio0");
    struct adt_io_reg *regs;
    DarwinGPIOIboot *s;
    uint64_t pa;
    size_t i;
    static const unsigned early_pins[] = {
        139, 138, 137, 88, 87, 71, 70,
    };

    G_STATIC_ASSERT(ARRAY_SIZE(early_pins) == D47_GPIO_EARLY_PIN_COUNT);

    if (!target || strcmp(target, "D47") != 0 || !gpio) {
        error_report("darwin-gpio: capability is evidenced only for d47 gpio0");
        exit(EXIT_FAILURE);
    }
    regs = adt_get_prop_val(gpio, "reg");
    if (!regs || adt_get_prop_len(gpio, "reg") < sizeof(*regs) ||
        regs[0].len < D47_GPIO_CAPABILITY_OFFSET + 4 ||
        regs[0].len < (early_pins[0] + 1) * 4) {
        error_report("darwin-gpio: device tree lacks the d47 gpio0 aperture");
        exit(EXIT_FAILURE);
    }

    s = g_new0(DarwinGPIOIboot, 1);
    for (i = 0; i < D47_GPIO_EARLY_PIN_COUNT; i++) {
        DarwinGPIOPin *slot = &s->early_pins[i];

        slot->pin = early_pins[i];
        pa = iobase + regs[0].base + slot->pin * 4;
        memory_region_init_io(&slot->mr, NULL, &darwin_gpio_pin_ops, slot,
                              "darwin-gpio-iboot-early-pin", 4);
        memory_region_add_subregion_overlap(get_system_memory(), pa,
                                            &slot->mr, 10);
    }
    fprintf(stderr,
            "darwin-gpio: gpio0 early pins 139/138/137/88/87/71/70 initialized as"
            " unconfigured storage\n");

    pa = iobase + regs[0].base + D47_GPIO_CAPABILITY_OFFSET;
    memory_region_init_io(&s->capability_mr, NULL,
                          &darwin_gpio_capability_ops, s,
                          "darwin-gpio-iboot-capability", 4);
    memory_region_add_subregion_overlap(get_system_memory(), pa,
                                        &s->capability_mr, 10);
    fprintf(stderr,
            "darwin-gpio: d47 gpio-canary capability bit0=1 at 0x%" PRIx64
            " (cross-build capability, not a completion response)\n", pa);
}
