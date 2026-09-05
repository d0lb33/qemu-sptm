#pragma once

#include "qemu/osdep.h"
#include "hw/core/sysbus.h"
#include "xnu/boot/xnuboot.h"

// Create the boot framebuffer display device (if -fb was given).
// uart may be NULL; if given, keyboard input from the QEMU display window is
// forwarded into it so the window works as a serial terminal to the guest.
void darwin_fb_init(struct xnu_boot_info *info, DeviceState *uart);

/* Present a copied DCP surface without modifying guest boot framebuffer RAM. */
bool darwin_fb_present_bgra(const uint8_t *pixels, uint32_t width,
                            uint32_t height, uint32_t stride);
