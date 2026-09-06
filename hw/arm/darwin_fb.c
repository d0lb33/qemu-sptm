/*
 * darwin-fb: boot framebuffer display for the -M darwin machine
 *
 * XNU draws its verbose-boot text console (and, in graphics mode, the boot
 * progress spinner) into the framebuffer described by boot_args.Video. That
 * framebuffer lives at the top of guest DRAM (see setup_framebuffer in
 * xnuboot_sptm.c). This device exposes that guest memory zero-copy as a
 * DisplaySurface so any QEMU UI (cocoa, sdl, gtk, vnc, ...) can show it.
 *
 * Since the emulated machine has no HID hardware, keyboard input from the QEMU
 * display window is translated to ASCII / VT100 escape sequences and injected
 * into the guest's UART, so the window works as a terminal for the serial
 * console (boot with serial=2: serial input, video console output).
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "qemu/timer.h"
#include "hw/core/sysbus.h"
#include "hw/core/qdev-properties.h"
#include "migration/vmstate.h"
#include "ui/console.h"
#include "ui/surface.h"
#include "ui/input.h"
#include "system/memory.h"
#include "hw/arm/exynos4210.h"
#include "standard-headers/linux/input-event-codes.h"
#include "xnu/boot/xnuboot.h"
#include "xnu/darwin_fb.h"
#include "xnu/darwin_input.h"

#define TYPE_DARWIN_FB "darwin-fb"
OBJECT_DECLARE_SIMPLE_TYPE(DarwinFBState, DARWIN_FB)

struct DarwinFBState {
    SysBusDevice parent_obj;

    QemuConsole *con;
    DisplaySurface *surface;
    bool surface_attached;

    uint8_t *scanout_pixels;
    uint32_t scanout_size;
    bool scanout_valid;
    uint8_t *host;
    uint32_t width, height, scale;
    hwaddr guest_base;
    bool graphics;

    DeviceState *uart;
    QemuInputHandlerState *kbd;
    QemuInputHandlerState *touch;
    int touch_fd;
    int touch_x, touch_y;
    bool touch_down, touch_sent_down, touch_dirty;
    bool shift, ctrl, alt, caps;
    DarwinInputState input;   /* native UART transport, DARWIN_INPUT_UART=1 */
};

/* ---------------- display ---------------- */

static bool darwin_fb_gfx_update(void *opaque)
{
    DarwinFBState *s = opaque;

    if (!s->surface_attached) {
        // Ownership of the surface passes to the console
        qemu_console_set_surface(s->con, s->surface);
        s->surface_attached = true;
    }

    // The surface is backed directly by guest RAM, so just flag a full refresh.
    // The UI backends (vnc in particular) do their own dirty-tile detection.
    qemu_console_update_full(s->con);
    return true;
}

/* The console owns attached surfaces; external pixel storage remains ours. */
static void darwin_fb_scanout_surface(DarwinFBState *s)
{
    DisplaySurface *next = qemu_create_displaysurface_from(
        s->width, s->height, PIXMAN_x8r8g8b8, s->width * 4,
        s->scanout_pixels);
    if (!s->surface_attached) {
        qemu_free_displaysurface(s->surface);
    }
    s->surface = next;
    qemu_console_set_surface(s->con, next);
    s->surface_attached = true;
}

bool darwin_fb_present_bgra(const uint8_t *pixels, uint32_t width,
                            uint32_t height, uint32_t stride)
{
    bool ambiguous = false;
    Object *obj = object_resolve_path_type("", TYPE_DARWIN_FB, &ambiguous);
    DarwinFBState *s;
    if (!obj || ambiguous || !pixels) {
        return false;
    }
    s = DARWIN_FB(obj);
    if (width != s->width || height != s->height ||
        (uint64_t)stride < (uint64_t)width * 4) {
        return false;
    }
    for (uint32_t y = 0; y < height; y++) {
        memcpy(s->scanout_pixels + (size_t)y * width * 4,
               pixels + (size_t)y * stride, width * 4);
    }
    if (!s->scanout_valid) {
        darwin_fb_scanout_surface(s);
        s->scanout_valid = true;
    }
    qemu_console_update_full(s->con);
    darwin_input_presented(&s->input);
    return true;
}

static void darwin_fb_invalidate(void *opaque)
{
}

static const GraphicHwOps darwin_fb_ops = {
    .invalidate = darwin_fb_invalidate,
    .gfx_update = darwin_fb_gfx_update,
};

/* ---------------- keyboard -> UART ---------------- */

// US keyboard layout, indexed by linux keycode
static const char keymap_lower[] = {
    [KEY_ESC] = 0x1b,
    [KEY_1] = '1', [KEY_2] = '2', [KEY_3] = '3', [KEY_4] = '4', [KEY_5] = '5',
    [KEY_6] = '6', [KEY_7] = '7', [KEY_8] = '8', [KEY_9] = '9', [KEY_0] = '0',
    [KEY_MINUS] = '-', [KEY_EQUAL] = '=', [KEY_BACKSPACE] = 0x7f, [KEY_TAB] = '\t',
    [KEY_Q] = 'q', [KEY_W] = 'w', [KEY_E] = 'e', [KEY_R] = 'r', [KEY_T] = 't',
    [KEY_Y] = 'y', [KEY_U] = 'u', [KEY_I] = 'i', [KEY_O] = 'o', [KEY_P] = 'p',
    [KEY_LEFTBRACE] = '[', [KEY_RIGHTBRACE] = ']', [KEY_ENTER] = '\r',
    [KEY_A] = 'a', [KEY_S] = 's', [KEY_D] = 'd', [KEY_F] = 'f', [KEY_G] = 'g',
    [KEY_H] = 'h', [KEY_J] = 'j', [KEY_K] = 'k', [KEY_L] = 'l',
    [KEY_SEMICOLON] = ';', [KEY_APOSTROPHE] = '\'', [KEY_GRAVE] = '`',
    [KEY_BACKSLASH] = '\\',
    [KEY_Z] = 'z', [KEY_X] = 'x', [KEY_C] = 'c', [KEY_V] = 'v', [KEY_B] = 'b',
    [KEY_N] = 'n', [KEY_M] = 'm', [KEY_COMMA] = ',', [KEY_DOT] = '.', [KEY_SLASH] = '/',
    [KEY_KPASTERISK] = '*', [KEY_SPACE] = ' ',
    [KEY_KP7] = '7', [KEY_KP8] = '8', [KEY_KP9] = '9', [KEY_KPMINUS] = '-',
    [KEY_KP4] = '4', [KEY_KP5] = '5', [KEY_KP6] = '6', [KEY_KPPLUS] = '+',
    [KEY_KP1] = '1', [KEY_KP2] = '2', [KEY_KP3] = '3', [KEY_KP0] = '0', [KEY_KPDOT] = '.',
    [KEY_102ND] = '\\', [KEY_KPENTER] = '\r', [KEY_KPSLASH] = '/',
};

static const char keymap_upper[] = {
    [KEY_ESC] = 0x1b,
    [KEY_1] = '!', [KEY_2] = '@', [KEY_3] = '#', [KEY_4] = '$', [KEY_5] = '%',
    [KEY_6] = '^', [KEY_7] = '&', [KEY_8] = '*', [KEY_9] = '(', [KEY_0] = ')',
    [KEY_MINUS] = '_', [KEY_EQUAL] = '+', [KEY_BACKSPACE] = 0x7f, [KEY_TAB] = '\t',
    [KEY_Q] = 'Q', [KEY_W] = 'W', [KEY_E] = 'E', [KEY_R] = 'R', [KEY_T] = 'T',
    [KEY_Y] = 'Y', [KEY_U] = 'U', [KEY_I] = 'I', [KEY_O] = 'O', [KEY_P] = 'P',
    [KEY_LEFTBRACE] = '{', [KEY_RIGHTBRACE] = '}', [KEY_ENTER] = '\r',
    [KEY_A] = 'A', [KEY_S] = 'S', [KEY_D] = 'D', [KEY_F] = 'F', [KEY_G] = 'G',
    [KEY_H] = 'H', [KEY_J] = 'J', [KEY_K] = 'K', [KEY_L] = 'L',
    [KEY_SEMICOLON] = ':', [KEY_APOSTROPHE] = '"', [KEY_GRAVE] = '~',
    [KEY_BACKSLASH] = '|',
    [KEY_Z] = 'Z', [KEY_X] = 'X', [KEY_C] = 'C', [KEY_V] = 'V', [KEY_B] = 'B',
    [KEY_N] = 'N', [KEY_M] = 'M', [KEY_COMMA] = '<', [KEY_DOT] = '>', [KEY_SLASH] = '?',
    [KEY_KPASTERISK] = '*', [KEY_SPACE] = ' ',
    [KEY_KP7] = '7', [KEY_KP8] = '8', [KEY_KP9] = '9', [KEY_KPMINUS] = '-',
    [KEY_KP4] = '4', [KEY_KP5] = '5', [KEY_KP6] = '6', [KEY_KPPLUS] = '+',
    [KEY_KP1] = '1', [KEY_KP2] = '2', [KEY_KP3] = '3', [KEY_KP0] = '0', [KEY_KPDOT] = '.',
    [KEY_102ND] = '|', [KEY_KPENTER] = '\r', [KEY_KPSLASH] = '/',
};

static const char *darwin_kbd_special(unsigned key)
{
    switch (key) {
    case KEY_UP:       return "\x1b[A";
    case KEY_DOWN:     return "\x1b[B";
    case KEY_RIGHT:    return "\x1b[C";
    case KEY_LEFT:     return "\x1b[D";
    case KEY_HOME:     return "\x1b[H";
    case KEY_END:      return "\x1b[F";
    case KEY_INSERT:   return "\x1b[2~";
    case KEY_DELETE:   return "\x1b[3~";
    case KEY_PAGEUP:   return "\x1b[5~";
    case KEY_PAGEDOWN: return "\x1b[6~";
    case KEY_F1:       return "\x1bOP";
    case KEY_F2:       return "\x1bOQ";
    case KEY_F3:       return "\x1bOR";
    case KEY_F4:       return "\x1bOS";
    default:           return NULL;
    }
}

static void darwin_kbd_event(DeviceState *dev, QemuConsole *src, QemuInputEvent *evt)
{
    DarwinFBState *s = DARWIN_FB(dev);
    unsigned key;
    bool down;
    uint8_t buf[8];
    int len = 0;

    if (!s->uart || evt->type != INPUT_EVENT_KIND_KEY) {
        return;
    }

    key = evt->key.key;
    down = evt->key.down;

    /* With the native transport, F5/F6 are the guest's Home and Power
     * buttons (consumer page 0x0c usages 0x40/0x30), both edges forwarded;
     * the right mouse button is Home as well (darwin_touch_event). */
    if (s->input.enabled && (key == KEY_F5 || key == KEY_F6)) {
        darwin_input_consumer(&s->input, key == KEY_F5 ? 0x40 : 0x30, down);
        return;
    }

    switch (key) {
    case KEY_LEFTSHIFT:
    case KEY_RIGHTSHIFT:
        s->shift = down;
        return;
    case KEY_LEFTCTRL:
    case KEY_RIGHTCTRL:
        s->ctrl = down;
        return;
    case KEY_LEFTALT:
    case KEY_RIGHTALT:
    case KEY_LEFTMETA:
    case KEY_RIGHTMETA:
        s->alt = down;
        return;
    case KEY_CAPSLOCK:
        if (down) {
            s->caps = !s->caps;
        }
        return;
    default:
        break;
    }

    if (!down) {
        return;
    }

    const char *seq = darwin_kbd_special(key);
    if (seq) {
        len = strlen(seq);
        memcpy(buf, seq, len);
    } else {
        char c = 0;
        if (key < ARRAY_SIZE(keymap_lower)) {
            c = (s->shift ? keymap_upper : keymap_lower)[key];
        }
        if (!c) {
            return;
        }
        if (s->caps) {
            if (c >= 'a' && c <= 'z') {
                c = c - 'a' + 'A';
            } else if (c >= 'A' && c <= 'Z') {
                c = c - 'A' + 'a';
            }
        }
        if (s->ctrl) {
            if (c >= 'a' && c <= 'z') {
                c = c - 'a' + 1;
            } else if (c >= 'A' && c <= 'Z') {
                c = c - 'A' + 1;
            } else if (c >= '@' && c <= '_') {
                c = c - '@';
            } else if (c == '?') {
                c = 0x7f;
            }
        }
        buf[0] = c;
        len = 1;
    }

    exynos4210_uart_inject(s->uart, buf, len);
}

static const QemuInputHandler darwin_kbd_handler = {
    .name  = "darwin-fb keyboard (to serial console)",
    .mask  = INPUT_EVENT_MASK_KEY,
    .event = darwin_kbd_event,
};

/* Explicit host-to-debugger input bridge, not an Apple touch device model.
 * Cocoa supplies absolute coordinates after window scaling (ui/cocoa.m).
 * Commit at input sync: Cocoa queues the button before its current position.
 * Each record is a complete state, so loss of a motion record cannot lose UP.
 * Transient host input is intentionally not restored with guest checkpoints.
 */
static void darwin_touch_event(DeviceState *dev, QemuConsole *src,
                               QemuInputEvent *evt)
{
    DarwinFBState *s = DARWIN_FB(dev);
    if (evt->type == INPUT_EVENT_KIND_ABS) {
        if (evt->abs.axis == INPUT_AXIS_X) {
            s->touch_x = CLAMP(evt->abs.value, 0, INPUT_EVENT_ABS_MAX);
            darwin_input_abs(&s->input, true, s->touch_x);
        } else if (evt->abs.axis == INPUT_AXIS_Y) {
            s->touch_y = CLAMP(evt->abs.value, 0, INPUT_EVENT_ABS_MAX);
            darwin_input_abs(&s->input, false, s->touch_y);
        }
        s->touch_dirty = true;
    } else if (evt->type == INPUT_EVENT_KIND_BTN &&
               evt->btn.button == INPUT_BUTTON_LEFT) {
        s->touch_down = evt->btn.down;
        darwin_input_button(&s->input, evt->btn.down);
        s->touch_dirty = true;
    } else if (evt->type == INPUT_EVENT_KIND_BTN &&
               evt->btn.button == INPUT_BUTTON_RIGHT) {
        /* Right button = the guest's Home button, both edges forwarded. */
        darwin_input_consumer(&s->input, 0x40, evt->btn.down);
    } else if (evt->type == INPUT_EVENT_KIND_BTN && evt->btn.down &&
               (evt->btn.button == INPUT_BUTTON_WHEEL_UP ||
                evt->btn.button == INPUT_BUTTON_WHEEL_DOWN)) {
        /* QEMU reports one press/release pair per notch; count presses. */
        darwin_input_wheel(&s->input,
                           evt->btn.button == INPUT_BUTTON_WHEEL_UP ? 1 : -1);
    }
}

static void darwin_touch_sync(DeviceState *dev)
{
    DarwinFBState *s = DARWIN_FB(dev);
    char line[192];
    int len;
    darwin_input_sync(&s->input);
    if (s->touch_fd < 0 || !s->touch_dirty ||
        (!s->touch_down && !s->touch_sent_down)) {
        s->touch_dirty = false;
        return;
    }
    len = snprintf(line, sizeof(line),
                   "{\"t\":%" PRId64 ",\"x\":%d,\"y\":%d,\"down\":%s}\n",
                   qemu_clock_get_ms(QEMU_CLOCK_REALTIME),
                   s->touch_x, s->touch_y, s->touch_down ? "true" : "false");
    if (write(s->touch_fd, line, len) != len) {
        fprintf(stderr, "darwin-touch: event write failed: %s\n", strerror(errno));
    }
    s->touch_sent_down = s->touch_down;
    s->touch_dirty = false;
}

static const QemuInputHandler darwin_touch_handler = {
    .name = "darwin single-touch debugger bridge",
    .mask = INPUT_EVENT_MASK_ABS | INPUT_EVENT_MASK_BTN,
    .event = darwin_touch_event,
    .sync = darwin_touch_sync,
};

static int darwin_fb_post_load(void *opaque, int version_id)
{
    DarwinFBState *s = opaque;

    if (s->scanout_valid) {
        darwin_fb_scanout_surface(s);
    }
    qemu_console_update_full(s->con);
    /* Host pointer state did not travel with the snapshot; release. */
    darwin_input_reset(&s->input, "migration restore");
    return 0;
}

static void darwin_fb_reset(DeviceState *dev)
{
    DarwinFBState *s = DARWIN_FB(dev);

    darwin_input_reset(&s->input, "device reset");
}

static bool darwin_fb_input_needed(void *opaque)
{
    return ((DarwinFBState *)opaque)->input.enabled;
}

static const VMStateDescription vmstate_darwin_fb_input = {
    .name = TYPE_DARWIN_FB "/input",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = darwin_fb_input_needed,
    .fields = (const VMStateField[]) {
        VMSTATE_STRUCT(input, DarwinFBState, 1, vmstate_darwin_input,
                       DarwinInputState),
        VMSTATE_END_OF_LIST()
    },
};

static bool darwin_fb_scanout_needed(void *opaque)
{
    return ((DarwinFBState *)opaque)->scanout_valid;
}

static const VMStateDescription vmstate_darwin_fb_scanout = {
    .name = TYPE_DARWIN_FB "/scanout",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = darwin_fb_scanout_needed,
    .fields = (const VMStateField[]) {
        /* Destination geometry fixes the allocation before loading any bytes. */
        VMSTATE_UINT32_EQUAL(width, DarwinFBState),
        VMSTATE_UINT32_EQUAL(height, DarwinFBState),
        VMSTATE_UINT32_EQUAL(scanout_size, DarwinFBState),
        VMSTATE_VBUFFER_UINT32(scanout_pixels, DarwinFBState, 0, NULL,
                              scanout_size),
        VMSTATE_BOOL(scanout_valid, DarwinFBState),
        VMSTATE_END_OF_LIST()
    },
};

static const VMStateDescription vmstate_darwin_fb = {
    .name = TYPE_DARWIN_FB,
    .version_id = 1,
    .minimum_version_id = 1,
    .post_load = darwin_fb_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_BOOL(shift, DarwinFBState),
        VMSTATE_BOOL(ctrl, DarwinFBState),
        VMSTATE_BOOL(alt, DarwinFBState),
        VMSTATE_BOOL(caps, DarwinFBState),
        VMSTATE_END_OF_LIST()
    },
    .subsections = (const VMStateDescription * const []) {
        &vmstate_darwin_fb_scanout, &vmstate_darwin_fb_input, NULL
    },
};

/* ---------------- device ---------------- */

static void darwin_fb_realize(DeviceState *dev, Error **errp)
{
    DarwinFBState *s = DARWIN_FB(dev);
    const char *touch_path = getenv("DARWIN_TOUCH_EVENTS");
    const char *native_input = getenv("DARWIN_INPUT_UART");
    bool native = native_input && *native_input && strcmp(native_input, "0");

    if (!s->host || !s->width || !s->height) {
        error_setg(errp, "darwin-fb: no framebuffer memory configured");
        return;
    }

    if ((uint64_t)s->width * s->height * 4 > 64 * 1024 * 1024) {
        error_setg(errp, "darwin-fb: framebuffer exceeds 64 MiB");
        return;
    }
    s->scanout_size = s->width * s->height * 4;
    s->scanout_pixels = g_malloc0(s->scanout_size);

    // XNU's boot video pixel format is "BBBBBBBBGGGGGGGGRRRRRRRR" (32bpp,
    // little endian B,G,R,X in memory), which is pixman x8r8g8b8.
    s->surface = qemu_create_displaysurface_from(s->width, s->height,
                                                 PIXMAN_x8r8g8b8,
                                                 s->width * 4, s->host);
    s->con = qemu_graphic_console_create(dev, 0, &darwin_fb_ops, s);

    s->touch_fd = -1;
    if (touch_path && *touch_path) {
        s->touch_fd = open(touch_path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW, 0600);
        if (s->touch_fd < 0) {
            error_setg_errno(errp, errno, "darwin-touch: cannot open event log");
            return;
        }
        fprintf(stderr, "darwin-touch: single-touch input -> %s\n", touch_path);
    }
    if (native) {
        if (!s->uart) {
            error_setg(errp, "darwin-input: DARWIN_INPUT_UART needs the console UART");
            return;
        }
        darwin_input_init(&s->input, s->uart, getenv("DARWIN_INPUT_STATUS"));
    }
    if (s->touch_fd >= 0 || native) {
        s->touch = qemu_input_handler_register(dev, &darwin_touch_handler);
        qemu_input_handler_activate(s->touch);
    }

    if (s->uart) {
        s->kbd = qemu_input_handler_register(dev, &darwin_kbd_handler);
        qemu_input_handler_activate(s->kbd);
    }

    fprintf(stderr, "darwin-fb: %ux%u@%u framebuffer at 0x%" HWADDR_PRIx
            " (%s mode%s)\n", s->width, s->height, s->scale, s->guest_base,
            s->graphics ? "graphics" : "text",
            s->uart ? ", keyboard -> serial console" : "");
}

static void darwin_fb_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    set_bit(DEVICE_CATEGORY_DISPLAY, dc->categories);
    dc->realize = darwin_fb_realize;
    device_class_set_legacy_reset(dc, darwin_fb_reset);
    dc->vmsd = &vmstate_darwin_fb;
    dc->desc = "XNU boot framebuffer";
    dc->user_creatable = false;
}

static const TypeInfo darwin_fb_info = {
    .name          = TYPE_DARWIN_FB,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(DarwinFBState),
    .class_init    = darwin_fb_class_init,
};

static void darwin_fb_register_types(void)
{
    type_register_static(&darwin_fb_info);
}

type_init(darwin_fb_register_types)

void darwin_fb_init(struct xnu_boot_info *info, DeviceState *uart)
{
    if (!info->fb_width || !info->fb_height || !info->fb_size) {
        return;
    }

    assert(info->dram_mr);
    assert(info->fb_base >= info->dram_base);
    assert(info->fb_base + info->fb_size <= info->dram_base + info->dram_size);

    DeviceState *dev = qdev_new(TYPE_DARWIN_FB);
    DarwinFBState *s = DARWIN_FB(dev);

    s->host = (uint8_t *)memory_region_get_ram_ptr(info->dram_mr) + (info->fb_base - info->dram_base);
    s->width = info->fb_width;
    s->height = info->fb_height;
    s->scale = info->fb_scale;
    s->guest_base = info->fb_base;
    s->graphics = info->fb_graphics;
    s->uart = uart;

    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
}
