/* iOS 27 (24A5430a) A408/D594 wire contract; see surface-cache-and-completion.md. */
#ifndef HW_ARM_DARWIN_IOMFB_SWAP_H
#define HW_ARM_DARWIN_IOMFB_SWAP_H
#include "qemu/osdep.h"
#define DARWIN_IOMFB_SWAP_INPUT_SIZE 0xff4
#define DARWIN_IOMFB_SWAP_COMPLETION_SIZE 0x730
bool darwin_iomfb_swap_id(const uint8_t *input, size_t size,
                         size_t output_size, uint32_t *id);
void darwin_iomfb_swap_completion(uint8_t output[DARWIN_IOMFB_SWAP_COMPLETION_SIZE],
                                 uint32_t id);
typedef struct DarwinIOMFBSurface {
    uint32_t width, height, stride, size;
    uint64_t dva;
} DarwinIOMFBSurface;
bool darwin_iomfb_swap_surface(const uint8_t *input, size_t size,
                               DarwinIOMFBSurface *surface);
#endif
