/*
 * Native software-key AES FIFO, independently implemented from the T8140
 * AppleS8000AES command builders. See docs/re/native-aes-bringup.md in the
 * superproject. No hardware UID/GID keys, wrapped keys, DPA or fake replies.
 *
 * KEY 93efcbc: software key length bits23:22, payload 16/24/32 bytes.
 * IV 93ef884: context27:26 and 16 bytes. DATA 93f05c4/93f06d0: four words,
 * including packed 42-bit source/destination DVAs. STORE_IV 93f0368:
 * two words, 42-bit DVA. FLAG 93f04d4: tag7:0, interrupt bit27.
 * CBC mode=1 also agrees with the Apple AES register reference's enum;
 * the cryptographic implementation is QEMU's existing QCryptoCipher API.
 * This deliberately supports only observed barrier 80000100, context-zero
 * IV writeback, ordinary unwrapped ECB/CBC software keys and final flags.
 */
#include "qemu/osdep.h"
#include "qemu/bswap.h"
#include "crypto/cipher.h"
#include "hw/arm/darwin_aes_engine.h"

static unsigned packet_words(uint32_t h)
{
    switch (h >> 28) {
    case 1:
        /* Unknown key selectors/functions/wrapping never consume guessed
         * key bytes or fall back to the previous context's key. */
        if ((h & 0x072cffff) || ((h >> 22) & 3) == 3 ||
            ((h >> 16) & 3) > 1) {
            return 0;
        }
        return 5 + 2 * ((h >> 22) & 3);
    case 2:
        return (h & 0x03ffffff) ? 0 : 5;
    case 5:
        return (h & 0x01000000) ? 0 : 4;
    case 6:
        return (h & 0x0ffffc00) ? 0 : 2;
    case 8:
        return h == 0x80000100 || (h & 0xffffff00) == 0x88000000;
    default:
        return 0;
    }
}

static bool crypt_data(DarwinAESEngine *s, DarwinAESDMA dma, void *opaque)
{
    uint32_t *p = s->fifo;
    unsigned k = (p[0] >> 27) & 1, v = (p[0] >> 25) & 3;
    size_t n = p[0] & 0xffffff;
    uint32_t h = s->key_header[k];
    unsigned size = (h >> 22) & 3;
    bool cbc = (h >> 16) & 1, encrypt = (h >> 20) & 1;
    uint64_t src = ((uint64_t)((p[1] >> 16) & 0x3ff) << 32) | p[2];
    uint64_t dst = ((uint64_t)(p[1] & 0x3ff) << 32) | p[3];
    uint8_t next_iv[16];
    QCryptoCipherAlgo algo[] = { QCRYPTO_CIPHER_ALGO_AES_128,
        QCRYPTO_CIPHER_ALGO_AES_192, QCRYPTO_CIPHER_ALGO_AES_256 };
    if (!dma || !s->key_valid[k] || (cbc && !s->iv_valid[v]) ||
        !n || (n & 15) || (p[1] & 0xfc00fc00) ||
        src + n > (1ULL << 42) || dst + n > (1ULL << 42)) {
        return false;
    }
    g_autofree uint8_t *input = g_malloc(n);
    g_autofree uint8_t *output = g_malloc(n);
    if (!dma(opaque, src, input, n, false)) {
        return false;
    }
    QCryptoCipher *cipher = qcrypto_cipher_new(algo[size],
        cbc ? QCRYPTO_CIPHER_MODE_CBC : QCRYPTO_CIPHER_MODE_ECB,
        s->keys[k], 16 + 8 * size, NULL);
    if (!cipher) {
        return false;
    }
    bool ok = !cbc || qcrypto_cipher_setiv(cipher, s->ivs[v], 16, NULL) == 0;
    if (ok) {
        ok = (encrypt ? qcrypto_cipher_encrypt(cipher, input, output, n, NULL) :
                        qcrypto_cipher_decrypt(cipher, input, output, n, NULL)) == 0;
    }
    qcrypto_cipher_free(cipher);
    if (!ok) {
        return false;
    }
    if (cbc) {
        memcpy(next_iv, (encrypt ? output : input) + n - 16, 16);
    }
    if (!dma(opaque, dst, output, n, true)) {
        return false;
    }
    if (cbc) {
        memcpy(s->ivs[v], next_iv, 16);
    }
    return true;
}

bool darwin_aes_push(DarwinAESEngine *s, uint32_t word, DarwinAESDMA dma,
                     DarwinAESComplete complete, void *opaque)
{
    if (s->failed || s->count >= ARRAY_SIZE(s->fifo)) {
        s->failed = true;
        return false;
    }
    s->fifo[s->count++] = word;
    uint32_t h = s->fifo[0];
    unsigned expected = packet_words(h);
    if (!expected) {
        s->failed = true;
        return false;
    }
    if (s->count < expected) {
        return true;
    }
    bool ok = true;
    switch (h >> 28) {
    case 1: {
        unsigned k = (h >> 27) & 1;
        memset(s->keys[k], 0, sizeof(s->keys[k]));
        for (unsigned i = 1; i < expected; i++) {
            stl_le_p(s->keys[k] + (i - 1) * 4, s->fifo[i]);
        }
        s->key_header[k] = h;
        s->key_valid[k] = true;
        break;
    }
    case 2: {
        unsigned v = (h >> 26) & 3;
        for (unsigned i = 0; i < 4; i++) {
            stl_le_p(s->ivs[v] + i * 4, s->fifo[i + 1]);
        }
        s->iv_valid[v] = true;
        break;
    }
    case 5:
        ok = crypt_data(s, dma, opaque);
        break;
    case 6:
        ok = s->iv_valid[0] && dma && dma(opaque,
            ((uint64_t)(h & 0x3ff) << 32) | s->fifo[1], s->ivs[0], 16, true);
        break;
    case 8:
        /* Synchronous DMA makes the observed barrier already ordered.
         * Final flags are never delivered before preceding writes finish. */
        if (h & (1U << 27)) {
            if (complete) {
                complete(opaque, h & 0xff);
            } else {
                ok = false;
            }
        }
        break;
    }
    s->failed = !ok;
    s->count = 0;
    return ok;
}
