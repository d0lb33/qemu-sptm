#include "qemu/osdep.h"
#include "qemu/bswap.h"
#include "crypto/init.h"
#include "hw/arm/darwin_aes_engine.h"

typedef struct Fixture {
    DarwinAESEngine engine;
    uint8_t memory[256];
    unsigned completions, writes;
    bool fail_dma;
} Fixture;

static bool dma(void *opaque, uint64_t dva, uint8_t *buffer, size_t n, bool write)
{
    Fixture *f = opaque;
    const uint64_t base = 0x10000000000;
    if (f->fail_dma || dva < base || dva - base > sizeof(f->memory) ||
        n > sizeof(f->memory) - (dva - base)) {
        return false;
    }
    if (write) {
        memcpy(f->memory + dva - base, buffer, n);
        f->writes++;
    } else {
        memcpy(buffer, f->memory + dva - base, n);
    }
    return true;
}

static void complete(void *opaque, uint8_t tag)
{
    Fixture *f = opaque;
    g_assert_cmpuint(tag, ==, 1);
    g_assert_cmpuint(f->writes, >=, 2); /* data and IV precede interrupt */
    f->completions++;
}

static void push(Fixture *f, uint32_t word)
{
    g_assert_true(darwin_aes_push(&f->engine, word, dma, complete, f));
}

static void bytes(Fixture *f, const uint8_t *data, unsigned n)
{
    for (unsigned i = 0; i < n; i += 4) {
        push(f, ldl_le_p(data + i));
    }
}

static void data(Fixture *f, unsigned source, unsigned destination, unsigned n)
{
    push(f, 0x50000000 | n);
    push(f, 0x01000100);
    push(f, source);
    push(f, destination);
}

static void finish(Fixture *f)
{
    push(f, 0x80000100);
    g_assert_cmpuint(f->completions, ==, 0);
    push(f, 0x60000100);
    push(f, 0xc0);
    push(f, 0x88000001);
    g_assert_cmpuint(f->completions, ==, 1);
}

static void test_zero256(void)
{
    Fixture f = { 0 };
    const uint8_t expected[] = { 0xdc,0x95,0xc0,0x78,0xa2,0x40,0x89,0x89,
        0xad,0x48,0xa2,0x14,0x92,0x84,0x20,0x87 };
    /* Captured native headers; DMA addresses relocated into this fixture.
     * The zero plaintext here is a known-answer test, not a claim about
     * the uncaptured guest input in APP_AES_COMMANDS1. */
    push(&f, 0x10910000);
    for (unsigned i = 0; i < 8; i++) {
        push(&f, 0);
    }
    push(&f, 0x20000000);
    for (unsigned i = 0; i < 4; i++) {
        push(&f, 0);
    }
    data(&f, 0, 0x40, 16);
    finish(&f);
    g_assert_cmpmem(f.memory + 0x40, 16, expected, 16);
    g_assert_cmpmem(f.memory + 0xc0, 16, expected, 16);
}

static void test_cbc_chain(void)
{
    const uint8_t key[] = { 0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c };
    const uint8_t iv[] = { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 };
    const uint8_t plain[] = { 0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
        0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
        0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51 };
    const uint8_t cipher[] = { 0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,
        0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d,
        0x50,0x86,0xcb,0x9b,0x50,0x72,0x19,0xee,
        0x95,0xdb,0x11,0x3a,0x91,0x76,0x78,0xb2 };
    for (unsigned decrypt = 0; decrypt < 2; decrypt++) {
        Fixture f = { 0 };
        memcpy(f.memory, decrypt ? cipher : plain, 32);
        push(&f, decrypt ? 0x10010000 : 0x10110000);
        bytes(&f, key, 16);
        push(&f, 0x20000000);
        bytes(&f, iv, 16);
        /* In-place, separately queued blocks test IV preservation. */
        data(&f, 0, 0, 16);
        data(&f, 16, 16, 16);
        finish(&f);
        g_assert_cmpmem(f.memory, 32, decrypt ? plain : cipher, 32);
        g_assert_cmpmem(f.memory + 0xc0, 16, cipher + 16, 16);
    }
}

static void test_reject(void)
{
    const uint32_t bad[] = { 0x11910000, 0x10b10000, 0x10d10000,
        0x10990000, 0x10930000, 0x30000000, 0x60000400, 0x88000101 };
    for (unsigned i = 0; i < ARRAY_SIZE(bad); i++) {
        Fixture f = { 0 };
        g_assert_false(darwin_aes_push(&f.engine, bad[i], dma, complete, &f));
        g_assert_false(darwin_aes_push(&f.engine, 0x88000001, dma, complete, &f));
        g_assert_cmpuint(f.completions, ==, 0);
        g_assert_cmpuint(f.writes, ==, 0);
    }
    Fixture f = { 0 };
    push(&f, 0x10110000);
    for (unsigned i = 0; i < 4; i++) {
        push(&f, 0);
    }
    push(&f, 0x20000000);
    for (unsigned i = 0; i < 4; i++) {
        push(&f, 0);
    }
    f.fail_dma = true;
    push(&f, 0x50000010);
    push(&f, 0x01000100);
    push(&f, 0);
    g_assert_false(darwin_aes_push(&f.engine, 0x40, dma, complete, &f));
    g_assert_false(darwin_aes_push(&f.engine, 0x88000001, dma, complete, &f));
    g_assert_cmpuint(f.writes, ==, 0);
    g_assert_cmpuint(f.completions, ==, 0);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_assert_cmpint(qcrypto_init(NULL), ==, 0);
    g_test_add_func("/darwin-aes/native-zero256", test_zero256);
    g_test_add_func("/darwin-aes/cbc-chain", test_cbc_chain);
    g_test_add_func("/darwin-aes/reject", test_reject);
    return g_test_run();
}
