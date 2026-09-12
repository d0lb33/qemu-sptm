#include "qemu/osdep.h"
#include "qemu/bswap.h"
#include "hw/arm/darwin_iomfb_swap.h"

#if defined(__aarch64__) && defined(__ARM_NEON)
#include <arm_neon.h>
#define DARWIN_IOMFB_NEON_RGBA16 1
#endif

bool darwin_iomfb_marked_frame(const DarwinIOMFBSurface *surface,
                             const uint8_t *pixels, uint32_t *frame)
{
    /* swap_surface.size is the DMA-visible row span, not padded IOSurface
     * allocation size. The owned diagnostic writes these four BGRA pixels. */
    if (!surface || !pixels || !frame || surface->format != 0x42475241 ||
        surface->width != 1179 ||
        surface->height != 2556 || surface->stride != 4864 ||
        surface->size != 4864 * 2556 ||
        (uint32_t)ldl_le_p(pixels) != 0xff44564dU ||
        (uint32_t)ldl_le_p(pixels + 4) != 0xff505253U ||
        (uint32_t)ldl_le_p(pixels + 8) != 0xff424c52U ||
        ((uint32_t)ldl_le_p(pixels + 12) & 0xff000000U) != 0xff000000U ||
        (ldl_le_p(pixels + 12) & 0xffffffU) < 1 ||
        (ldl_le_p(pixels + 12) & 0xffffffU) > 8192) {
        return false;
    }
    *frame = ldl_le_p(pixels + 12) & 0xffffffU;
    return true;
}

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

bool darwin_iomfb_swap_empty(const uint8_t *input, size_t size)
{
    /* a0c9088..a0c9128 packs optional surfaces, with null flags feb..fee.
     * CA_BINDING_GUEST1 RPC 15892 has all four absent (descriptor bytes aa).
     * It still carries the pending main record: retire it without pixel DMA
     * or claiming a new scanout. Power state is handled by the power RPCs. */
    return input && size == DARWIN_IOMFB_SWAP_INPUT_SIZE &&
           input[0xfea] == 0 && input[0xfeb] == 1 &&
           input[0xfec] == 1 && input[0xfed] == 1 && input[0xfee] == 1;
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
 * CA_PURGEABILITY_GUEST1 also submits RGhA, row9472, transfer13/primaries1.
 * Exact QuartzCore 18452bff8..18452c01c assigns tags (1,13) to sRGB and
 * extended sRGB; IOSurface 1bffbf8dc[13] selects sRGB at 1bffbf888.
 * Descriptor fields match IOSurface accessors; wire+f90 follows a0c9128.
 * disp0/sid0 translation byte-matched the source IOSurface in VISIBLE_R6.
 * This is deliberately not a general multi-plane compositor. */
bool darwin_iomfb_swap_surface(const uint8_t *input, size_t size,
                               DarwinIOMFBSurface *surface)
{
    const uint8_t *d;
    DarwinIOMFBSurface v;
    uint64_t bytes;
    uint32_t bpp;
    if (!input || !surface || size != DARWIN_IOMFB_SWAP_INPUT_SIZE ||
        input[0xfea] || input[0xfeb] || input[0xfec] != 1 ||
        input[0xfed] != 1 || input[0xfee] != 1) {
        return false;
    }
    d = input + 0x6e0;
    v.format = ldl_le_p(d + 0xb);
    v.transfer = d[0x13];
    v.colorspace = d[0x14];
    bpp = v.format == 0x42475241 ? 4 : v.format == 0x52476841 ? 8 : 0;
    if (!bpp) {
        return false;
    }
    /* No tone-map/EDR-compensation implementation. _kern_SwapSetLayerEDR-
     * Compensation stores enabled at object+564, corresponding to wire+54c
     * (SwapEnd sends object+18). Preserve the existing BGRA profile separately.
     * This RGhA extension covers the observed packed, nonplanar sRGB profile;
     * other compression metadata and tone-map curves remain unmodelled. */
    if (bpp == 8 && (v.transfer != 13 || v.colorspace != 1 ||
                    lduw_le_p(d + 0x19) != 8 || d[0x1b] != 1 ||
                    d[0x1c] != 1 || d[0] || ldl_le_p(d + 3) ||
                    ldl_le_p(d + 7) || input[0x54c])) {
        return false;
    }
    v.width = ldl_le_p(d + 0x21);
    v.height = ldl_le_p(d + 0x25);
    v.stride = ldl_le_p(d + 0x15);
    v.dva = ldq_le_p(input + 0xf90);
    bytes = (uint64_t)v.stride * v.height;
    if (!v.width || !v.height || v.width > 8192 || v.height > 8192 ||
        v.stride < (uint64_t)v.width * bpp || (v.stride & (bpp - 1)) ||
        bytes > 64 * 1024 * 1024 || bytes > (uint32_t)ldl_le_p(d + 0x29) ||
        !v.dva || v.dva > UINT64_MAX - bytes) {
        return false;
    }
    v.size = bytes;
    *surface = v;
    return true;
}

/* IEEE binary16 already carrying sRGB-encoded components -> SDR byte output.
 * Integer quantization avoids host FP rounding modes and an extra sRGB OETF.
 * Above-range finite values clip at the SDR output boundary; HDR display is
 * not claimed. Nonfinite components reject the entire scanout before publish. */
static uint8_t half_unorm8(uint16_t value)
{
    unsigned exponent = (value >> 10) & 31;
    if (value & 0x8000 || !exponent) {
        return 0;
    }
    if (exponent >= 15) {
        return 255;
    }
    unsigned shift = 25 - exponent;
    return (((value & 1023) + 1024) * 255 + (1U << (shift - 1))) >> shift;
}

#ifdef DARWIN_IOMFB_NEON_RGBA16
static inline uint8x8_t half8_unorm8(uint16x8_t bits)
{
    float16x8_t half = vreinterpretq_f16_u16(bits);
    float32x4_t low = vcvt_f32_f16(vget_low_f16(half));
    float32x4_t high = vcvt_f32_f16(vget_high_f16(half));
    const float32x4_t zero = vdupq_n_f32(0.0f);
    const float32x4_t one = vdupq_n_f32(1.0f);
    const float32x4_t scale = vdupq_n_f32(255.0f);

    low = vmulq_f32(vminq_f32(vmaxq_f32(low, zero), one), scale);
    high = vmulq_f32(vminq_f32(vmaxq_f32(high, zero), one), scale);

    return vmovn_u16(vcombine_u16(vmovn_u32(vcvtaq_u32_f32(low)),
                                  vmovn_u32(vcvtaq_u32_f32(high))));
}

static inline bool half8_has_nonfinite(uint16x8_t value)
{
    uint16x8_t exponent = vandq_u16(value, vdupq_n_u16(0x7c00));

    return vmaxvq_u16(vceqq_u16(exponent, vdupq_n_u16(0x7c00))) != 0;
}
#endif

bool darwin_iomfb_rgha_to_bgra(const DarwinIOMFBSurface *s,
                              const uint8_t *source, size_t source_size,
                              uint8_t *output, size_t output_size)
{
    if (!s || !source || !output || s->format != 0x52476841 ||
        s->transfer != 13 || s->colorspace != 1 || !s->width || !s->height ||
        s->width > 8192 || s->height > 8192 ||
        s->stride < (uint64_t)s->width * 8 || (s->stride & 7) ||
        (uint64_t)s->stride * s->height > source_size ||
        (uint64_t)s->width * s->height * 4 > output_size) {
        return false;
    }
    for (uint32_t y = 0; y < s->height; y++) {
        const uint8_t *src = source + (size_t)y * s->stride;
        uint8_t *dst = output + (size_t)y * s->width * 4;
        uint32_t x = 0;
#ifdef DARWIN_IOMFB_NEON_RGBA16
        for (; x + 8 <= s->width; x += 8, src += 64, dst += 32) {
            uint16x8x4_t rgba = vld4q_u16((const uint16_t *)src);
            if (half8_has_nonfinite(rgba.val[0]) ||
                half8_has_nonfinite(rgba.val[1]) ||
                half8_has_nonfinite(rgba.val[2]) ||
                half8_has_nonfinite(rgba.val[3])) {
                return false;
            }
            uint8x8x4_t bgra = {
                .val = {
                    half8_unorm8(rgba.val[2]),
                    half8_unorm8(rgba.val[1]),
                    half8_unorm8(rgba.val[0]),
                    half8_unorm8(rgba.val[3]),
                },
            };
            vst4_u8(dst, bgra);
        }
#endif
        for (; x < s->width; x++, src += 8, dst += 4) {
            uint16_t r = lduw_le_p(src), g = lduw_le_p(src + 2);
            uint16_t b = lduw_le_p(src + 4), a = lduw_le_p(src + 6);
            if ((r & 0x7c00) == 0x7c00 || (g & 0x7c00) == 0x7c00 ||
                (b & 0x7c00) == 0x7c00 || (a & 0x7c00) == 0x7c00) {
                return false;
            }
            dst[0] = half_unorm8(b); dst[1] = half_unorm8(g);
            dst[2] = half_unorm8(r); dst[3] = half_unorm8(a);
        }
    }
    return true;
}
