/* Experimental software-key subset of the native T8140 AES FIFO. */
#ifndef HW_ARM_DARWIN_AES_ENGINE_H
#define HW_ARM_DARWIN_AES_ENGINE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef bool (*DarwinAESDMA)(void *opaque, uint64_t dva, uint8_t *buffer,
                             size_t length, bool write);
typedef void (*DarwinAESComplete)(void *opaque, uint8_t tag);

typedef struct DarwinAESEngine {
    uint32_t fifo[9];
    uint32_t count;
    uint32_t key_header[2];
    uint8_t keys[2][32];
    uint8_t ivs[4][16];
    bool key_valid[2];
    bool iv_valid[4];
    bool failed;
} DarwinAESEngine;

/* Returns false and latches failed for unsupported or failed requests.
 * No completion is emitted after a failure. Callbacks are synchronous;
 * pointers are not retained. All persistent state is in the engine struct.
 */
bool darwin_aes_push(DarwinAESEngine *s, uint32_t word, DarwinAESDMA dma,
                     DarwinAESComplete complete, void *opaque);
#endif
