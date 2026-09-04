/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Minimal raw iBoot experiment loader.
 *
 * This is deliberately not an IMG4, ticket, device-tree, trust-cache, or XNU
 * handoff implementation.  docs/re/iboot-image.md statically establishes for
 * mBoot-20457.2.37 on d47 that the unwrapped payload enters in place at
 * 0x1fc080000, begins with EL2 setup, names its own base at raw +0x380, and
 * carries image/BSS bounds in the adjacent startup literal pool.  The release
 * and RESEARCH_RELEASE BSS ends fit below IBOOT_IMAGE_MEMORY_END.  Runtime
 * page-table evidence also maps both builds' statically declared root scratch
 * region onto the immediately following physical pages.  No other RAM is
 * justified, and this loader supplies no boot inputs.  Its sole purpose is to
 * make the first missing runtime dependency observable.
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "exec/memattrs.h"
#include "system/address-spaces.h"
#include "system/memory.h"
#include "cpu.h"
#include "xnu/boot/xnuboot.h"

#define IBOOT_MEMORY_BASE       UINT64_C(0x1fc000000)
#define IBOOT_IMAGE_MEMORY_END  UINT64_C(0x1fc480000)
#define IBOOT_ROOT_PHYS_BASE    UINT64_C(0x1fc470000)
#define IBOOT_ROOT_SIZE         UINT64_C(0x58000)
#define IBOOT_MEMORY_END        (IBOOT_ROOT_PHYS_BASE + IBOOT_ROOT_SIZE)
#define IBOOT_LOAD_ADDR         UINT64_C(0x1fc080000)
#define IBOOT_CANONICAL_BASE    UINT64_C(0xfffffc0000000000)
#define IBOOT_CANONICAL_MASK    UINT64_C(0xfffffc0000000000)
#define IBOOT_ROOT_VA_BASE      UINT64_C(0x3f000000000)
#define IBOOT_ROOT_NAME_QWORD   UINT64_C(0x746f6f72)

#define IBOOT_COPY_ALIGN        64
#define IBOOT_PAGE_SIZE         0x4000
#define IBOOT_STARTUP_SIZE      0x410
#define IBOOT_COPY_END_OFFSET   0x388
#define IBOOT_BSS_END_OFFSET    0x3c0
#define IBOOT_SELF_BASE_OFFSET  0x380
#define IBOOT_MEMORY_OFFSET     0x3e0
#define IBOOT_CANON_BASE_OFFSET 0x408
#define IBOOT_BANNER_OFFSET     0x280

static const char iboot_banner[] =
    "iBoot for d47 Copyright 2007-2026, Apple Inc.";

typedef struct IbootInsn {
    uint16_t offset;
    uint32_t insn;
    uint32_t mask;
} IbootInsn;

/*
 * Raw +0x0..+0x48, decoded independently with radare2 and Capstone in
 * docs/re/iboot-image.md.  The BL target at +0x28 differs between the release
 * and research payloads, so validate the opcode class there and every other
 * startup instruction exactly.
 */
static const IbootInsn iboot_startup[] = {
    { 0x00, 0xd51c211f, UINT32_MAX }, /* msr vttbr_el2, xzr */
    { 0x04, 0xd5033fdf, UINT32_MAX }, /* isb */
    { 0x08, 0xd53c1102, UINT32_MAX }, /* mrs x2, hcr_el2 */
    { 0x0c, 0xb25e0042, UINT32_MAX },
    { 0x10, 0xb2650042, UINT32_MAX },
    { 0x14, 0xd51c1102, UINT32_MAX }, /* msr hcr_el2, x2 */
    { 0x18, 0xd5033fdf, UINT32_MAX }, /* isb */
    { 0x1c, 0x90000000, UINT32_MAX }, /* adrp x0, 0x1fc080000 */
    { 0x20, 0x91000000, UINT32_MAX }, /* add x0, x0, #0 */
    { 0x24, 0x58001ae1, UINT32_MAX }, /* ldr x1, raw +0x380 */
    { 0x28, 0x94000000, 0xfc000000 }, /* bl <build-specific target> */
    { 0x2c, 0xeb00003f, UINT32_MAX }, /* cmp x1, x0 */
    { 0x30, 0x54000ae0, UINT32_MAX }, /* b.eq raw +0x18c */
    { 0x34, 0x58001aa2, UINT32_MAX }, /* ldr x2, raw +0x388 */
    { 0x38, 0x58001e8c, UINT32_MAX }, /* ldr x12, raw +0x408 */
    { 0x3c, 0xcb0c0042, UINT32_MAX },
    { 0x40, 0xcb010042, UINT32_MAX },
    { 0x44, 0x9100fc42, UINT32_MAX },
    { 0x48, 0x927ae442, UINT32_MAX },
};

static void iboot_reject(const char *reason)
{
    error_report("invalid raw iBoot image: %s", reason);
    exit(EXIT_FAILURE);
}

static uint64_t iboot_canonical_phys(uint64_t literal, const char *name)
{
    if ((literal & IBOOT_CANONICAL_MASK) != IBOOT_CANONICAL_BASE) {
        error_report("invalid raw iBoot image: %s literal 0x%" PRIx64
                     " is not in the evidenced canonical range", name,
                     literal);
        exit(EXIT_FAILURE);
    }
    return literal - IBOOT_CANONICAL_BASE;
}

static bool iboot_has_root_descriptor(const mmap_file_t *image)
{
    const uint8_t *buf = image->buf;

    for (size_t off = 0; off <= image->len - 3 * sizeof(uint64_t);
         off += sizeof(uint64_t)) {
        uint64_t end;

        if (ldq_le_p(buf + off) != IBOOT_ROOT_NAME_QWORD ||
            ldq_le_p(buf + off + sizeof(uint64_t)) != IBOOT_ROOT_VA_BASE) {
            continue;
        }

        end = ldq_le_p(buf + off + 2 * sizeof(uint64_t));
        if (end > IBOOT_ROOT_VA_BASE &&
            ROUND_UP_POW2(end - IBOOT_ROOT_VA_BASE, IBOOT_PAGE_SIZE) ==
            IBOOT_ROOT_SIZE) {
            return true;
        }
    }

    return false;
}

static void iboot_validate(const mmap_file_t *image)
{
    const uint8_t *buf = image->buf;
    uint64_t copy_end, bss_end, rounded_len;

    if (!buf || image->len < IBOOT_STARTUP_SIZE) {
        iboot_reject("payload is too small for the startup code and literals");
    }
    if (image->len > IBOOT_IMAGE_MEMORY_END - IBOOT_LOAD_ADDR) {
        iboot_reject("payload does not fit in the evidenced boot-memory range");
    }

    for (size_t i = 0; i < ARRAY_SIZE(iboot_startup); i++) {
        uint32_t actual = ldl_le_p(buf + iboot_startup[i].offset);

        if ((actual & iboot_startup[i].mask) != iboot_startup[i].insn) {
            error_report("invalid raw iBoot image: startup instruction at"
                         " +0x%x is 0x%08x, expected 0x%08x/mask 0x%08x",
                         iboot_startup[i].offset, actual,
                         iboot_startup[i].insn, iboot_startup[i].mask);
            exit(EXIT_FAILURE);
        }
    }

    if (memcmp(buf + IBOOT_BANNER_OFFSET, iboot_banner,
               sizeof(iboot_banner)) != 0) {
        iboot_reject("d47 mBoot-20457.2.37 identity banner is absent");
    }
    if (ldq_le_p(buf + IBOOT_SELF_BASE_OFFSET) != IBOOT_LOAD_ADDR) {
        iboot_reject("self-base literal is not 0x1fc080000");
    }
    if (ldq_le_p(buf + IBOOT_MEMORY_OFFSET) != IBOOT_MEMORY_BASE) {
        iboot_reject("boot-memory base literal is not 0x1fc000000");
    }
    if (ldq_le_p(buf + IBOOT_CANON_BASE_OFFSET) != IBOOT_CANONICAL_BASE) {
        iboot_reject("canonical-address base literal is unexpected");
    }

    rounded_len = ROUND_UP_POW2((uint64_t)image->len, IBOOT_COPY_ALIGN);
    copy_end = iboot_canonical_phys(
        ldq_le_p(buf + IBOOT_COPY_END_OFFSET), "copy-end");
    bss_end = iboot_canonical_phys(
        ldq_le_p(buf + IBOOT_BSS_END_OFFSET), "BSS-end");

    if (copy_end != IBOOT_LOAD_ADDR + rounded_len) {
        iboot_reject("copy-end literal does not match the payload length");
    }
    if (bss_end < copy_end || bss_end > IBOOT_IMAGE_MEMORY_END) {
        iboot_reject("BSS-end literal is outside the evidenced boot-memory"
                     " range");
    }
    if (!iboot_has_root_descriptor(image)) {
        iboot_reject("root descriptor does not match the evidenced virtual"
                     " address and rounded size");
    }
}

void arm_load_xnu_iboot(ARMCPU *cpu, MachineState *ms,
                        struct xnu_boot_info *info)
{
    MemoryRegion *boot_memory;
    MemTxResult tx;

    iboot_validate(&info->iboot_f);

    boot_memory = g_new0(MemoryRegion, 1);
    memory_region_init_ram(boot_memory, NULL, "darwin.iboot-memory",
                           IBOOT_MEMORY_END - IBOOT_MEMORY_BASE, &error_fatal);
    memory_region_add_subregion(get_system_memory(), IBOOT_MEMORY_BASE,
                                boot_memory);

    tx = address_space_write(&address_space_memory, IBOOT_LOAD_ADDR,
                             MEMTXATTRS_UNSPECIFIED, info->iboot_f.buf,
                             info->iboot_f.len);
    if (tx != MEMTX_OK) {
        error_report("failed to load raw iBoot at 0x%" PRIx64
                     " (memory transaction result 0x%x)",
                     IBOOT_LOAD_ADDR, tx);
        exit(EXIT_FAILURE);
    }

    info->init_pc = IBOOT_LOAD_ADDR;
    info->init_x0 = 0;

    fprintf(stderr, "iBoot experiment: mapped [0x%" PRIx64 ",0x%" PRIx64
            ") including root scratch [0x%" PRIx64 ",0x%" PRIx64
            "), loaded %zu bytes at 0x%" PRIx64 ", entry +0x0, x0=0\n",
            IBOOT_MEMORY_BASE, IBOOT_MEMORY_END, IBOOT_ROOT_PHYS_BASE,
            IBOOT_MEMORY_END, info->iboot_f.len, IBOOT_LOAD_ADDR);

    (void)cpu;
    (void)ms;
}
