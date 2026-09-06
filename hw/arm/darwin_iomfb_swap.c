#include "qemu/osdep.h"
#include "qemu/bswap.h"
#include "hw/arm/darwin_iomfb_swap.h"

bool darwin_iomfb_swap_id(const uint8_t *input, size_t size,
                         size_t output_size, uint32_t *id)
{
    /* a0c3730 -> queue-item+0x3d4; a0c9088 copies the record verbatim.
     * a0c90d4 encodes its optional/null flag at wire +0xfea. */
    if (!input || !id || size != DARWIN_IOMFB_SWAP_INPUT_SIZE ||
        output_size != 12 || input[0xfea] != 0) {
        return false;
    }
    *id = ldl_le_p(input + 0x98);
    return true;
}

void darwin_iomfb_swap_completion(uint8_t output[DARWIN_IOMFB_SWAP_COMPLETION_SIZE],
                                 uint32_t id)
{
    /* a0db034 decodes D594, then a0c58bc removes the matching pending ID.
     * Not cancelled, no optional record, zero timing records (count +0x727),
     * and null swap-info (+0x72c). No invented timestamp or refresh rate.
     * The same packet completed a real pending swap in DISPLAY_COMPLETE_R25. */
    memset(output, 0, DARWIN_IOMFB_SWAP_COMPLETION_SIZE);
    stl_le_p(output, id);
    output[0x72c] = 1;
}

/* Measured packed primary BGRA profile from DISPLAY_SMP6_COMPLETE_R5 A408.
 * Descriptor fields match IOSurface accessors; wire+f90 follows a0c9128.
 * disp0/sid0 translation byte-matched the source IOSurface in VISIBLE_R6.
 * This is deliberately not a general multi-plane compositor. */
bool darwin_iomfb_swap_surface(const uint8_t *input, size_t size,
                               DarwinIOMFBSurface *surface)
{
    const uint8_t *d;
    DarwinIOMFBSurface v;
    uint64_t bytes;
    if (!input || !surface || size != DARWIN_IOMFB_SWAP_INPUT_SIZE ||
        input[0xfea] || input[0xfeb] || input[0xfec] != 1 ||
        input[0xfed] != 1 || input[0xfee] != 1) {
        return false;
    }
    d = input + 0x6e0;
    if ((uint32_t)ldl_le_p(d + 0xb) != 0x42475241) {
        return false;
    }
    v.width = ldl_le_p(d + 0x21);
    v.height = ldl_le_p(d + 0x25);
    v.stride = ldl_le_p(d + 0x15);
    v.dva = ldq_le_p(input + 0xf90);
    bytes = (uint64_t)v.stride * v.height;
    if (!v.width || !v.height || v.width > 8192 || v.height > 8192 ||
        v.stride < (uint64_t)v.width * 4 || (v.stride & 3) ||
        bytes > 64 * 1024 * 1024 || bytes > (uint32_t)ldl_le_p(d + 0x29) ||
        !v.dva || v.dva > UINT64_MAX - bytes) {
        return false;
    }
    v.size = bytes;
    *surface = v;
    return true;
}
