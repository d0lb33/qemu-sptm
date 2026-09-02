#include "qemu/compiler.h"
#include "xnu/patch.h"
#include "xnu/mach-o/loader.h"
#include "xnu/mach-o/macho_arm64.h"
#include "xnu/boot/xnuboot.h"
#include "xnu/macho.h"

#define PACIBSP                (( 0xD503237F ))
#define RETAB                  (( 0xD65F0FFF ))
#define MOVX(rd,v)             (( 0xD2800000 | ( ((v)) << 5) | ((rd)) ))

#define IS_LDG(v)              (( (0b11011001011 == (((v)) >> 21)) && (0 == ((((v)) >> 10) & 0b011)) ))

// Assuming all pointers are DYLD_CHAINED_PTR_64_KERNEL_CACHE, strip everything
// but target (treating this pointer as a dyld_chained_ptr_64_kernel_cache_rebase).
#define REMOVE_DYLD_FIXUP_DATA(p)    (( ((p)) & (( BIT(30) - 1 )) ))

struct sysctl_oid {
    void   *oid_parent;
    void   *oid_link;
    int     oid_number;
    int     oid_kind;
    void    *oid_arg1;
    int     oid_arg2;
    char   *oid_name;
    u64     oid_handler;
    char   *oid_fmt;
    char   *oid_descr;
    int     oid_version;
    int     oid_refcnt;
};

static void patch_img4_deadlock(u8 *bkc_macho) {
    // Find the sysctl__security_mac_img4_ignition_blob struct in AppleImage4.kext,
    // then patch its oid handler (_darwin_trap_ignition_get_blob) to return 0.

    fse_t *img4_fse = macho_find_fileset_entry(bkc_macho, "com.apple.security.AppleImage4");
    if (!img4_fse) {
        fprintf(stderr, "warning: couldn't find img4 kext\n");
        return;
    }

    u8 *img4_macho = &bkc_macho[img4_fse->fileoff];

    seg_t *img4_exc_seg = macho_find_seg(img4_macho, "__TEXT_EXEC");
    sect_t *img4_dat_sect = macho_find_sect(img4_macho, "__DATA", "__data");
    sect_t *img4_str_sect = macho_find_sect(img4_macho, "__TEXT", "__cstring");

    i64 *img4_dat = (i64*)&bkc_macho[img4_dat_sect->offset];
    u8  *img4_str = (u8*)&bkc_macho[img4_str_sect->offset];

    u64 ignition_blob_str = 0;
    for (size_t i = 0; i < img4_str_sect->size; i++) {
        if (0 == strcmp("ignition_blob", (char*)&img4_str[i])) {
            ignition_blob_str = img4_str_sect->offset + i;
        }
    }

    if (0 == ignition_blob_str) {
        fprintf(stderr, "couldn't find ignition_blob sysctl struct\n");
        return;
    }

    u64 oid_handler = 0;
    for (size_t i = 0; i < img4_dat_sect->size / sizeof(u64); i++) {
        // This is sysctl__security_mac_img4_ignition_blob.oid_name
        u64 stripped_ptr = REMOVE_DYLD_FIXUP_DATA(img4_dat[i]);
        if (stripped_ptr == ignition_blob_str) {
            struct sysctl_oid *blob_oid = container_of((char**)&img4_dat[i], struct sysctl_oid, oid_name);
            oid_handler = REMOVE_DYLD_FIXUP_DATA(blob_oid->oid_handler);
        }
    }

    if (0 == oid_handler) {
        fprintf(stderr, "couldn't find _darwin_trap_ignition_get_blob\n");
        return;
    }

    if (oid_handler < img4_exc_seg->fileoff || oid_handler > img4_exc_seg->fileoff + img4_exc_seg->filesize) {
        fprintf(stderr, "Warning: _darwin_trap_ignition_get_blob isn't in __TEXT_EXEC\n");
    }

    u32 *sysctl_handler_fn = (u32*)&bkc_macho[oid_handler];

    if (PACIBSP != sysctl_handler_fn[0]) {
        fprintf(stderr, "Warning: _darwin_trap_ignition_get_blob doesn't start with PACIBSP\n");
    }

    sysctl_handler_fn[0] = PACIBSP;
    sysctl_handler_fn[1] = MOVX(0,0);
    sysctl_handler_fn[2] = RETAB;
}

/* ==========================================================================
 * memdev: lift XNU's 4 GiB ceiling on `rd=md0` memory-backed root disks
 * ==========================================================================
 *
 * WHY
 * ---
 * `rd=md0` wraps a range of physical pages as a block device (bsd/dev/memdev.c,
 * reached from IOFindBSDRoot in iokit/bsddev/IOKitBSDInit.cpp).  That is the
 * cheapest way to boot a real iOS system volume: no storage hardware at all.
 * But `struct mdev`'s mdSize field is a uint32_t holding a *page* count, and
 * memdev.c keeps converting it back to bytes with `mdev[devid].mdSize << 12`,
 * which C evaluates in 32-bit arithmetic.  Anything over 4 GiB wraps.
 *
 * Observed on iOS 27.0b (24A5430a, t8140) with a 10,026,483,712 byte system
 * volume = 2,447,872 pages.  `2447872 << 12` truncated to 32 bits is
 * 0x55A00000 = 1,436,549,120, and the guest says exactly that:
 *
 *   dev_init:299: md0 device_handle block size 512 block count 2805760 ...
 *   nx_dev_init:740: md0 superblock container size 10026483712 greater than
 *                    device size 1436549120
 *
 * (1,436,549,120 / 512 = 2,805,760 blocks.  The arithmetic matches bit for bit,
 * so this is the only thing wrong.)  Full analysis: docs/re/rootfs-boot.md.
 *
 * mdevadd() itself is *correct* in the shipping kernelcache — its only caller,
 * IOFindBSDRoot, computes the page count with a 64-bit `lsr x2, x8, #0xc`
 * (0xfffffff00ac954cc unslid in firmware/bootkc).  Nothing here touches it.
 *
 * WHAT IS PATCHED
 * ---------------
 * Three expressions, all in the base kernel fileset ("com.apple.kernel", not a
 * kext).  Unslid addresses below are from firmware/bootkc
 * (xnu-13432.2.10~5/RELEASE_ARM64_T8140); runtime = unslid + 0x20000000.  They
 * are quoted for the reader only — the code finds them by pattern, never by
 * address, because this has to keep working on other SoCs and iOS versions.
 *
 *   A. mdevioctl / DKIOCGETBLOCKCOUNT (_IOR('d',25,uint64_t) = 0x40086419).
 *      THE critical one: this is the number APFS reads.  @0xfffffff00ac95404
 *          ldr  w9, [x8, #8]           ; mdSize   (pages)
 *          ldr  w8, [x8, #0x10]        ; mdSecsize
 *          add  w9, w8, w9, lsl #12    ; <-- 32-bit, overflows
 *          sub  w9, w9, #1
 *          udiv w8, w9, w8
 *          str  x8, [x19]              ; already a 64-bit store
 *      Widened to add/sub/udiv on X registers.  Both inputs came from 32-bit
 *      LDRs, which zero-extend, so the 64-bit forms are exact.
 *
 *   B. mdevstrategy, the block I/O bounds check.  @0xfffffff00ac95690
 *          ldr  w9, [x20, #8] ; lsl w9, w9, #12   <-- 32-bit
 *          cmp  x19, x9  /  cmp x8, x9            ; consumers already 64-bit
 *      Only the shift needs widening.  The one 32-bit consumer downstream,
 *      `sub w8, w9, w19` clamping bp->b_bcount, is fine: b_bcount is an int and
 *      that path only runs when the request straddles the end of the device, so
 *      the difference is bounded by the request size.
 *
 *   C. mdevrw, the character-device read()/write() path.  @0xfffffff00ac95534
 *          ldr  w9, [x9, #8] ; lsl w9, w9, #12    <-- 32-bit
 *          sub  w11, w9, w8                       ; remaining = size - offset
 *          cmp  w10, w11                          ; vs uio_resid
 *          csel w10, w10, w11, lt                 ; min()
 *          cmp  x8, x9                            ; offset past end?
 *          csel w8, wzr, w10, gt
 *      Here the shift must NOT be widened alone: `sub w11, w9, w8` would then
 *      compute (size & 0xffffffff) - offset and hand uiomove() a bogus, possibly
 *      negative length.  The SUB and the CMP are widened with it.  The two CSELs
 *      stay 32-bit on purpose — whichever operand they select is bounded by
 *      uio_resid, and uiomove() takes an `int` length anyway.
 *
 * Every widening except the shifts is literally "set sf (bit 31)".  The shifts
 * are `LSL wD, wN, #12` = UBFM(sf=0,N=0,immr=20,imms=19) = 0x53144C00|Rn<<5|Rd,
 * and become `LSL xD, xN, #12` = UBFM(sf=1,N=1,immr=52,imms=51) =
 * 0xD374CC00|Rn<<5|Rd.  (ARM DDI 0487, C6.2 UBFM / "LSL (immediate)".)
 *
 * HOW THE SITES ARE FOUND
 * -----------------------
 * Anchor on the panic string that only mdevadd() emits,
 * "mdevadd: attempt to add more than %d memory devices", in the base kernel's
 * __TEXT __cstring.  The ADRP+ADD pair in __TEXT_EXEC __text that materialises
 * its address lands inside mdevadd, i.e. inside the memdev compilation unit.
 * All of memdev.c is emitted contiguously, so a +/- MEMDEV_WINDOW byte window
 * around that pair contains every site.  Inside the window we match on
 * instruction encodings with the register fields masked off, so register
 * allocation changes between builds do not break us, and we require the whole
 * surrounding idiom (the mdSize load at +8, the consumers) before touching
 * anything.  A site whose neighbourhood does not match exactly is logged and
 * skipped: a half-applied patch here corrupts disk I/O silently, which is far
 * worse than not booting.
 *
 * Set DARWIN_MEMDEV_PATCH=0 to disable (useful for A/B probes).
 * Set DARWIN_PATCH_DEBUG=1 for the full scan trace.
 */

/* --- A64 encodings, ARM DDI 0487 C4.1.  Rd/Rt is [4:0], Rn [9:5], Rm [20:16]. */
#define INSN_RD(w)                 (( ((w)) & 0x1F ))
#define INSN_RN(w)                 (( (((w)) >> 5) & 0x1F ))
#define INSN_RM(w)                 (( (((w)) >> 16) & 0x1F ))

/* LDR (immediate, unsigned offset), 32-bit: 1011 1001 01 imm12 Rn Rt */
#define IS_LDR_W_UOFF(w)           (( 0xB9400000 == (((w)) & 0xFFC00000) ))
#define LDR_UOFF_IMM12(w)          (( (((w)) >> 10) & 0xFFF ))

/* LSL wD, wN, #12  ==  UBFM wD, wN, #20, #19 */
#define LSL_W12(rn,rd)             (( 0x53144C00 | (((rn)) << 5) | ((rd)) ))
/* LSL xD, xN, #12  ==  UBFM xD, xN, #52, #51 */
#define LSL_X12(rn,rd)             (( 0xD374CC00 | (((rn)) << 5) | ((rd)) ))

/* ADD (shifted register), 32-bit, LSL #imm6 */
#define IS_ADD_W_SHIFTED(w)        (( 0x0B000000 == (((w)) & 0xFFE00000) ))
#define SHIFTED_IMM6(w)            (( (((w)) >> 10) & 0x3F ))
/* SUB (immediate), 32-bit, shift=0 */
#define IS_SUB_W_IMM(w)            (( 0x51000000 == (((w)) & 0xFFC00000) ))
#define SUB_IMM12(w)               (( (((w)) >> 10) & 0xFFF ))
/* UDIV, 32-bit */
#define IS_UDIV_W(w)               (( 0x1AC00800 == (((w)) & 0xFFE0FC00) ))
/* STR (immediate, unsigned offset), 64-bit */
#define IS_STR_X_UOFF(w)           (( 0xF9000000 == (((w)) & 0xFFC00000) ))
/* SUB (shifted register), 32-bit */
#define IS_SUB_W_SHIFTED(w)        (( 0x4B000000 == (((w)) & 0xFFE00000) ))
/* CMP (shifted register) == SUBS wzr/xzr, Rn, Rm */
#define IS_CMP_W_SHIFTED(w)        (( 0x6B00001F == (((w)) & 0xFFE0001F) && 0 == SHIFTED_IMM6(w) ))
#define IS_CMP_X_SHIFTED(w)        (( 0xEB00001F == (((w)) & 0xFFE0001F) && 0 == SHIFTED_IMM6(w) ))
/* ADRP / ADD (immediate), 64-bit, shift=0 */
#define IS_ADRP(w)                 (( 0x90000000 == (((w)) & 0x9F000000) ))
#define IS_ADD_X_IMM(w)            (( 0x91000000 == (((w)) & 0xFFC00000) ))
#define ADD_IMM12(w)               (( (((w)) >> 10) & 0xFFF ))

/* Widening a 32-bit data-processing instruction to 64-bit is just sf = 1. */
#define SET_SF(w)                  (( ((w)) | 0x80000000u ))

/* How far either side of mdevadd's panic string reference we search, in bytes.
 * memdev.c is ~2 KB of code in this build (mdevadd at 0xfffffff00ac94ff0,
 * mdevstrategy's bounds check at 0xfffffff00ac95690, so the furthest site is
 * 0x42c past the anchor); 8 KB each way is generous without wandering out of
 * the compilation unit. */
#define MEMDEV_WINDOW              (( 0x2000 ))

#define MDEVADD_PANIC_STR          "mdevadd: attempt to add more than"

/* mdev entry layout, bsd/dev/memdev.c: mdBase at +0, mdSize at +8 (pages),
 * mdSecsize at +0x10.  We only care about the mdSize offset. */
#define MDEV_MDSIZE_OFF            (( 8 ))

typedef struct {
    u64          va;        /* unslid virtual address of the instruction */
    u32          expect;    /* what must be there now, else we refuse       */
    u32          replace;   /* what we write                                */
    const char  *what;      /* for the log                                  */
} insn_fixup_t;

static bool patch_dbg(void) {
    return getenv("DARWIN_PATCH_DEBUG") != NULL;
}

/* Verify every instruction of a site first, then write.  All-or-nothing: a
 * partially widened expression is worse than an untouched one. */
static bool apply_fixups(u8 *bkc_macho, sect_t *text,
                         insn_fixup_t *f, size_t n, const char *site) {
    for (size_t i = 0; i < n; i++) {
        u32 *p = (u32*)&bkc_macho[text->offset + (f[i].va - text->addr)];
        if (*p != f[i].expect) {
            fprintf(stderr, "warning: memdev patch (%s): refusing to patch, "
                    "%#llx holds %08x, expected %08x (%s)\n",
                    site, (unsigned long long)f[i].va, *p, f[i].expect, f[i].what);
            return false;
        }
    }

    for (size_t i = 0; i < n; i++) {
        u32 *p = (u32*)&bkc_macho[text->offset + (f[i].va - text->addr)];
        fprintf(stderr, "memdev patch (%s): %#llx  %08x -> %08x  %s\n",
                site, (unsigned long long)f[i].va, *p, f[i].replace, f[i].what);
        *p = f[i].replace;
    }

    return true;
}

/* Find the ADRP(+ADD) pair in __text that materialises string address strva.
 * Returns the address of the ADRP, or 0.  The ADD is allowed to trail the ADRP
 * by a few instructions as long as nothing else redefines the ADRP's Rd. */
static u64 find_adrp_add_to(u8 *bkc_macho, sect_t *text, u64 strva, int *nfound) {
    u32 *insns = (u32*)&bkc_macho[text->offset];
    size_t count = text->size / sizeof(u32);
    u64 first = 0;

    *nfound = 0;
    for (size_t i = 0; i + 1 < count; i++) {
        u32 adrp = insns[i];
        if (!IS_ADRP(adrp)) continue;

        i64 immlo = (adrp >> 29) & 0x3;
        i64 immhi = (adrp >> 5) & 0x7FFFF;
        i64 imm   = (immhi << 2) | immlo;
        if (imm & (1LL << 20)) imm -= (1LL << 21);   /* sign extend 21 bits */

        u64 pc   = text->addr + i * sizeof(u32);
        u64 page = (pc & ~0xFFFULL) + (u64)(imm * 4096);   /* imm is signed */
        u32 rd   = INSN_RD(adrp);

        for (size_t j = i + 1; j < count && j <= i + 4; j++) {
            u32 w = insns[j];
            if (IS_ADD_X_IMM(w) && INSN_RN(w) == rd &&
                page + ADD_IMM12(w) == strva) {
                if (0 == first) first = pc;
                (*nfound)++;
                break;
            }
            /* crude liveness: anything writing Rd kills the ADRP result */
            if (INSN_RD(w) == rd) break;
        }
    }

    return first;
}

/* Site A: the DKIOCGETBLOCKCOUNT computation.  See the header comment. */
static bool patch_memdev_blockcount(u8 *bkc_macho, sect_t *text,
                                    size_t lo, size_t hi) {
    u32 *insns = (u32*)&bkc_macho[text->offset];

    for (size_t i = lo + 2; i + 3 < hi; i++) {
        u32 add = insns[i];
        if (!IS_ADD_W_SHIFTED(add) || SHIFTED_IMM6(add) != 12) continue;

        u32 ld_size = insns[i - 2];   /* ldr wM, [xB, #8]     -> mdSize    */
        u32 ld_secs = insns[i - 1];   /* ldr wN, [xB, #0x10]  -> mdSecsize */
        u32 sub     = insns[i + 1];   /* sub wD, wD, #1                    */
        u32 udiv    = insns[i + 2];   /* udiv wE, wD, wN                   */
        u32 str     = insns[i + 3];   /* str xE, [x?]                      */

        u32 rd_size = INSN_RM(add);   /* register holding mdSize   */
        u32 rd_secs = INSN_RN(add);   /* register holding mdSecsize */
        u32 rd_sum  = INSN_RD(add);

        if (!IS_LDR_W_UOFF(ld_size) || LDR_UOFF_IMM12(ld_size) * 4 != MDEV_MDSIZE_OFF ||
            INSN_RD(ld_size) != rd_size) continue;
        if (!IS_LDR_W_UOFF(ld_secs) || LDR_UOFF_IMM12(ld_secs) * 4 != 0x10 ||
            INSN_RD(ld_secs) != rd_secs || INSN_RN(ld_secs) != INSN_RN(ld_size)) continue;

        u64 va = text->addr + i * sizeof(u32);

        /* From here on this is unambiguously the block-count expression, so a
         * mismatch is a real problem and gets reported rather than skipped. */
        if (!IS_SUB_W_IMM(sub) || SUB_IMM12(sub) != 1 ||
            INSN_RD(sub) != rd_sum || INSN_RN(sub) != rd_sum) {
            fprintf(stderr, "warning: memdev patch (blockcount): %#llx looks like "
                    "(mdSize<<12)+secsize but is not followed by 'sub w,w,#1' "
                    "(%08x); not patching\n", (unsigned long long)va, sub);
            return false;
        }
        if (!IS_UDIV_W(udiv) || INSN_RN(udiv) != rd_sum || INSN_RM(udiv) != rd_secs) {
            fprintf(stderr, "warning: memdev patch (blockcount): %#llx not followed "
                    "by 'udiv w,w,secsize' (%08x); not patching\n",
                    (unsigned long long)va, udiv);
            return false;
        }
        /* The quotient must already be stored 64-bit, otherwise widening the
         * arithmetic would not reach the caller and we have the wrong idiom. */
        if (!IS_STR_X_UOFF(str) || INSN_RD(str) != INSN_RD(udiv)) {
            fprintf(stderr, "warning: memdev patch (blockcount): quotient at %#llx "
                    "is not stored with a 64-bit STR (%08x); not patching\n",
                    (unsigned long long)va, str);
            return false;
        }

        insn_fixup_t f[] = {
            { va + 0,  add,  SET_SF(add),  "add x,x,x,lsl #12  (mdSize<<12 + mdSecsize)" },
            { va + 4,  sub,  SET_SF(sub),  "sub x,x,#1" },
            { va + 8,  udiv, SET_SF(udiv), "udiv x,x,x         (-> DKIOCGETBLOCKCOUNT)" },
        };
        return apply_fixups(bkc_macho, text, f, ARRAY_SIZE(f), "blockcount");
    }

    fprintf(stderr, "warning: memdev patch: DKIOCGETBLOCKCOUNT expression not found; "
            "memory disks over 4GiB will still be truncated\n");
    return false;
}

/* Sites B and C: every `ldr wD,[xN,#8] ; lsl wD,wD,#12` pair in the window.
 * Returns the number of pairs successfully patched. */
static int patch_memdev_shifts(u8 *bkc_macho, sect_t *text,
                               size_t lo, size_t hi) {
    u32 *insns = (u32*)&bkc_macho[text->offset];
    int patched = 0;

    for (size_t i = lo; i + 5 < hi; i++) {
        u32 ld  = insns[i];
        if (!IS_LDR_W_UOFF(ld) || LDR_UOFF_IMM12(ld) * 4 != MDEV_MDSIZE_OFF) continue;

        u32 rd  = INSN_RD(ld);
        u32 lsl = insns[i + 1];
        if (lsl != LSL_W12(rd, rd)) continue;   /* not a 32-bit mdSize<<12 */

        u64 va = text->addr + (i + 1) * sizeof(u32);

        /* Form B (mdevstrategy): the shifted value is consumed straight away by
         * a 64-bit compare, so widening the shift alone is complete. */
        u32 c1 = insns[i + 2];
        if (IS_CMP_X_SHIFTED(c1) && INSN_RM(c1) == rd) {
            insn_fixup_t f[] = {
                { va, lsl, LSL_X12(rd, rd), "lsl x,x,#12  (mdevstrategy bounds check)" },
            };
            if (apply_fixups(bkc_macho, text, f, ARRAY_SIZE(f), "strategy")) patched++;
            continue;
        }

        /* Form C (mdevrw): sub / cmp / csel / cmp.  The SUB and the first CMP
         * must be widened together with the shift; see the header comment. */
        u32 sub = insns[i + 2];
        u32 cmw = insns[i + 3];
        u32 cmx = insns[i + 5];
        if (IS_SUB_W_SHIFTED(sub) && SHIFTED_IMM6(sub) == 0 && INSN_RN(sub) == rd &&
            IS_CMP_W_SHIFTED(cmw) && INSN_RM(cmw) == INSN_RD(sub) &&
            IS_CMP_X_SHIFTED(cmx) && INSN_RM(cmx) == rd &&
            INSN_RN(cmx) == INSN_RM(sub)) {
            insn_fixup_t f[] = {
                { va,     lsl, LSL_X12(rd, rd), "lsl x,x,#12  (mdevrw device size)" },
                { va + 4, sub, SET_SF(sub),     "sub x,x,x    (size - uio_offset)" },
                { va + 8, cmw, SET_SF(cmw),     "cmp x,x      (vs uio_resid)" },
            };
            if (apply_fixups(bkc_macho, text, f, ARRAY_SIZE(f), "rw")) patched++;
            continue;
        }

        fprintf(stderr, "warning: memdev patch: 32-bit mdSize<<12 at %#llx sits in an "
                "unrecognised expression (%08x %08x %08x); left alone\n",
                (unsigned long long)va, insns[i + 2], insns[i + 3], insns[i + 4]);
    }

    return patched;
}

static void patch_memdev_4gib(u8 *bkc_macho) {
    const char *off = getenv("DARWIN_MEMDEV_PATCH");
    if (off && 0 == strcmp(off, "0")) {
        fprintf(stderr, "memdev patch: disabled by DARWIN_MEMDEV_PATCH=0\n");
        return;
    }

    /* memdev lives in the base kernel, not in a kext. */
    fse_t *kern_fse = macho_find_fileset_entry(bkc_macho, "com.apple.kernel");
    if (!kern_fse) {
        fprintf(stderr, "warning: memdev patch: no com.apple.kernel fileset entry\n");
        return;
    }
    u8 *kern_macho = &bkc_macho[kern_fse->fileoff];

    sect_t *cstr = macho_find_sect(kern_macho, "__TEXT", "__cstring");
    sect_t *text = macho_find_sect(kern_macho, "__TEXT_EXEC", "__text");
    if (!cstr || !text) {
        fprintf(stderr, "warning: memdev patch: kernel __cstring/__text not found\n");
        return;
    }

    /* Anchor: the panic string only mdevadd() emits. */
    u64 strva = 0;
    size_t needle = strlen(MDEVADD_PANIC_STR);
    char *strs = (char*)&bkc_macho[cstr->offset];
    for (size_t i = 0; i + needle < cstr->size; i++) {
        /* only consider real string starts, so we cannot match a suffix */
        if (i != 0 && strs[i - 1] != '\0') continue;
        if (0 == strncmp(&strs[i], MDEVADD_PANIC_STR, needle)) {
            strva = cstr->addr + i;
            break;
        }
    }
    if (0 == strva) {
        fprintf(stderr, "warning: memdev patch: anchor string \"%s\" not found; "
                "memory disks stay capped at 4GiB\n", MDEVADD_PANIC_STR);
        return;
    }

    int nrefs = 0;
    u64 anchor = find_adrp_add_to(bkc_macho, text, strva, &nrefs);
    if (0 == anchor) {
        fprintf(stderr, "warning: memdev patch: nothing in __TEXT_EXEC references "
                "the mdevadd panic string at %#llx\n", (unsigned long long)strva);
        return;
    }
    if (nrefs > 1) {
        fprintf(stderr, "warning: memdev patch: %d references to the mdevadd panic "
                "string; using the first, at %#llx\n", nrefs, (unsigned long long)anchor);
    }
    if (patch_dbg()) {
        fprintf(stderr, "memdev patch: anchor string %#llx, mdevadd reference %#llx, "
                "__text %#llx+%#llx\n", (unsigned long long)strva,
                (unsigned long long)anchor, (unsigned long long)text->addr,
                (unsigned long long)text->size);
    }

    /* Window, in instruction indices, clamped to the section. */
    size_t count  = text->size / sizeof(u32);
    size_t centre = (anchor - text->addr) / sizeof(u32);
    size_t lo = centre > MEMDEV_WINDOW / 4 ? centre - MEMDEV_WINDOW / 4 : 0;
    size_t hi = centre + MEMDEV_WINDOW / 4;
    if (hi > count) hi = count;

    bool ok_a = patch_memdev_blockcount(bkc_macho, text, lo, hi);
    int  n_bc = patch_memdev_shifts(bkc_macho, text, lo, hi);

    fprintf(stderr, "memdev patch: %s block-count ioctl, %d of the 2 expected "
            "mdSize<<12 shifts widened; ramdisks over 4GiB %s\n",
            ok_a ? "widened" : "DID NOT widen", n_bc,
            (ok_a && n_bc == 2) ? "should now work" : "may still be truncated");
}

/* ---- bsd_rooted_ramdisk(): let rootdev= boot the memory disk ---------------
 *
 * Booting with "rd=md0" puts iOS on its restore path and it never reaches a
 * usable system: launchd decides "Restore environment" from a plain
 * strstr(kern.bootargs, "rd=md0"), and libignition (statically linked into
 * /usr/lib/dyld) selects its two-stage "ramdisk" boot spec when the rd boot-arg
 * is exactly "md0". Between them that skips mount-phase-1/2, usermanagerd,
 * keybag and tzinit, leaves the root read-only, and so no persona is ever
 * created and SpringBoard's spawn never completes.
 *
 * XNU accepts "rootdev=" as an alias of "rd=" for the memory-disk root
 * (iokit/bsddev/IOKitBSDInit.cpp:725-728 and :1027-1028), and neither launchd's
 * substring test nor libignition's exact-token parser recognises that spelling.
 * So "rootdev=md0" boots the same memory disk down the normal path.
 *
 * The one thing that breaks is bsd_rooted_ramdisk() (bsd/kern/bsd_init.c:460),
 * which only ever reads "rd". With "rootdev=" its PE_parse_boot_argn fails, it
 * returns false, and bsd_init then enforces FSIOC_KERNEL_ROOTAUTH and panics
 * with "rootvp not authenticated after mounting" on our unsealed volume
 * (bsd_init.c:934-950). Forcing its return to true restores exactly the
 * behaviour "rd=md0" already gets today.
 *
 * The site, in com.apple.kernel __TEXT_EXEC __text, is the tail of that
 * function:
 *
 *      cmp   w0, #0          71 00 00 1f
 *      cset  w20, eq         1a 9f 17 f4
 *      b     .+8             14 00 00 02
 *      mov   w20, #0         52 80 00 14   <-- becomes mov w20, #1
 *
 * That run is not unique on its own — this kernel has two of them in __text —
 * so we additionally require the site to sit just after code that materialises
 * the "md0" string, which is what bsd_rooted_ramdisk compares the boot-arg
 * against. Exactly one site must qualify, so a kernel the pattern does not fit
 * is left alone rather than corrupted.
 *
 * Only correct because our root really is a memory disk. Set
 * DARWIN_ROOTDEV_PATCH=0 to skip it.
 */
#define ROOTED_RD_CMP     0x7100001Fu   /* cmp  w0, #0   */
#define ROOTED_RD_CSET    0x1A9F17F4u   /* cset w20, eq  */
#define ROOTED_RD_B8      0x14000002u   /* b    .+8      */
#define ROOTED_RD_MOV0    0x52800014u   /* mov  w20, #0  */
#define ROOTED_RD_MOV1    0x52800034u   /* mov  w20, #1  */
#define ROOTED_RD_WINDOW  64            /* insns back to look for the "md0" ref */

static void patch_rooted_ramdisk(u8 *bkc_macho) {
    const char *off = getenv("DARWIN_ROOTDEV_PATCH");
    if (off && 0 == strcmp(off, "0")) {
        fprintf(stderr, "rootdev patch: disabled by DARWIN_ROOTDEV_PATCH=0\n");
        return;
    }

    fse_t *kern_fse = macho_find_fileset_entry(bkc_macho, "com.apple.kernel");
    if (!kern_fse) {
        fprintf(stderr, "warning: rootdev patch: no com.apple.kernel fileset entry\n");
        return;
    }
    u8 *kern_macho = &bkc_macho[kern_fse->fileoff];

    sect_t *cstr = macho_find_sect(kern_macho, "__TEXT", "__cstring");
    sect_t *text = macho_find_sect(kern_macho, "__TEXT_EXEC", "__text");
    if (!cstr || !text) {
        fprintf(stderr, "warning: rootdev patch: kernel __cstring/__text not found\n");
        return;
    }

    /* The "md0" the boot-arg is compared against, as a whole string. */
    u64 strva = 0;
    char *strs = (char*)&bkc_macho[cstr->offset];
    for (size_t i = 0; i + 4 <= cstr->size; i++) {
        if (i != 0 && strs[i - 1] != '\0') continue;      /* real string start */
        if (0 == strncmp(&strs[i], "md0", 4)) {           /* includes the NUL */
            strva = cstr->addr + i;
            break;
        }
    }
    if (0 == strva) {
        fprintf(stderr, "warning: rootdev patch: \"md0\" string not found in the kernel\n");
        return;
    }

    u32 *insns = (u32*)&bkc_macho[text->offset];
    size_t count = text->size / sizeof(u32);
    size_t hits = 0, at = 0;

    for (size_t i = 0; i + 3 < count; i++) {
        if (insns[i]     != ROOTED_RD_CMP  ||
            insns[i + 1] != ROOTED_RD_CSET ||
            insns[i + 2] != ROOTED_RD_B8   ||
            insns[i + 3] != ROOTED_RD_MOV0) continue;

        /* Does an ADRP(+ADD) for "md0" appear shortly before this run?  Only
         * bsd_rooted_ramdisk both ends this way and mentions md0. */
        bool near_md0 = false;
        size_t lo = i > ROOTED_RD_WINDOW ? i - ROOTED_RD_WINDOW : 0;
        for (size_t k = lo; k < i && !near_md0; k++) {
            u32 adrp = insns[k];
            if (!IS_ADRP(adrp)) continue;

            i64 immlo = (adrp >> 29) & 0x3;
            i64 immhi = (adrp >> 5) & 0x7FFFF;
            i64 imm   = (immhi << 2) | immlo;
            if (imm & (1LL << 20)) imm -= (1LL << 21);

            u64 pc   = text->addr + k * sizeof(u32);
            u64 page = (pc & ~0xFFFULL) + (u64)(imm * 4096);
            u32 rd   = INSN_RD(adrp);

            for (size_t j = k + 1; j < count && j <= k + 4; j++) {
                u32 w = insns[j];
                if (IS_ADD_X_IMM(w) && INSN_RN(w) == rd &&
                    page + ADD_IMM12(w) == strva) { near_md0 = true; break; }
                if (INSN_RD(w) == rd) break;
            }
        }
        if (!near_md0) continue;

        if (0 == hits) at = i + 3;
        hits++;
    }

    if (0 == hits) {
        fprintf(stderr, "warning: rootdev patch: bsd_rooted_ramdisk tail not found; "
                "boot with rd=md0, not rootdev=md0\n");
        return;
    }
    if (hits > 1) {
        fprintf(stderr, "warning: rootdev patch: %zu candidate sites near \"md0\", "
                "expected 1; refusing to patch\n", hits);
        return;
    }

    u64 va = text->addr + at * sizeof(u32);
    fprintf(stderr, "rootdev patch: %#llx  %08x -> %08x  mov w20,#1  "
            "(bsd_rooted_ramdisk returns true, so rootdev=md0 boots)\n",
            (unsigned long long)va, insns[at], ROOTED_RD_MOV1);
    insns[at] = ROOTED_RD_MOV1;
}

/* ---- silence the TXM log flood ------------------------------------------
 *
 * XNU emits one line often enough to dominate everything else:
 *
 *   TXM [Error]: selector: 38 | 42
 *
 * 1,626,184 times in a 300-second boot, 5,371,513 in a 900-second one — about
 * 99.8% of all serial output, and over 2,000,000 lines against 42,000 useful
 * ones on the boots that now get furthest. Every byte is an MMIO trap out to
 * the emulated UART, so this is not merely noisy, it is the guest's largest
 * single consumer of time.
 *
 * It is not a failure we need to fix. The string lives in the kernelcache, not
 * in TXM (firmware/txm and firmware/sptm contain no "selector: " strings at
 * all; bootkc contains 28), so this is XNU logging a TXM return code. It is the
 * generic fallback of five sibling formats, meaning the code is in none of the
 * TrustCache / CodeSignature / Errno / Image4_V2 domains, and the boot proceeds
 * regardless. See docs/re/txm-selectors.md.
 *
 * We suppress exactly that one message by NOPing its call to the log function,
 * leaving the other four TXM error formats — including the immediately
 * preceding "TXM [Error]: Errno: selector: %u | %d" — intact, so a genuinely
 * new TXM failure still reaches the console.
 *
 * Located by string, not by address. On our kernelcache the site is:
 *
 *   0xfffffff00b044380  adrp x0, ...        ; -> "TXM [Error]: selector: %u | %u\n"
 *   0xfffffff00b044384  add  x0, x0, #0x640 ;    at 0xfffffff0070a6640
 *   0xfffffff00b044388  bl   0xfffffff00b1e1060
 *
 * Set DARWIN_TXM_LOG_PATCH=0 to keep the flood (useful if you suspect the
 * message has become meaningful).
 */
#define TXM_FLOOD_STR   "TXM [Error]: selector: %u | %u\n"
#define IS_BL(w)        (( 0x94000000u == (((w)) & 0xFC000000u) ))
#define A64_NOP         0xD503201Fu

static void patch_txm_log_flood(u8 *bkc_macho) {
    const char *off = getenv("DARWIN_TXM_LOG_PATCH");
    if (off && 0 == strcmp(off, "0")) {
        fprintf(stderr, "txm log patch: disabled by DARWIN_TXM_LOG_PATCH=0\n");
        return;
    }

    fse_t *kern_fse = macho_find_fileset_entry(bkc_macho, "com.apple.kernel");
    if (!kern_fse) {
        fprintf(stderr, "warning: txm log patch: no com.apple.kernel fileset entry\n");
        return;
    }
    u8 *kern_macho = &bkc_macho[kern_fse->fileoff];

    sect_t *cstr = macho_find_sect(kern_macho, "__TEXT", "__cstring");
    sect_t *text = macho_find_sect(kern_macho, "__TEXT_EXEC", "__text");
    if (!cstr || !text) {
        fprintf(stderr, "warning: txm log patch: kernel __cstring/__text not found\n");
        return;
    }

    u64 strva = 0;
    size_t needle = strlen(TXM_FLOOD_STR);
    char *strs = (char*)&bkc_macho[cstr->offset];
    for (size_t i = 0; i + needle < cstr->size; i++) {
        if (i != 0 && strs[i - 1] != '\0') continue;      /* real string start */
        if (0 == strncmp(&strs[i], TXM_FLOOD_STR, needle + 1)) {  /* +1: exact */
            strva = cstr->addr + i;
            break;
        }
    }
    if (0 == strva) {
        fprintf(stderr, "warning: txm log patch: format string not found; "
                "the serial log will be swamped\n");
        return;
    }

    int nrefs = 0;
    u64 adrp = find_adrp_add_to(bkc_macho, text, strva, &nrefs);
    if (0 == adrp) {
        fprintf(stderr, "warning: txm log patch: nothing references %#llx\n",
                (unsigned long long)strva);
        return;
    }
    if (nrefs > 1) {
        fprintf(stderr, "warning: txm log patch: %d references to the format "
                "string, expected 1; refusing to patch\n", nrefs);
        return;
    }

    /* The ADD completing the pair is within a few instructions; the BL that
     * consumes x0 is the next instruction after it. */
    u32 *insns = (u32*)&bkc_macho[text->offset];
    size_t count = text->size / sizeof(u32);
    size_t i = (adrp - text->addr) / sizeof(u32);
    u32 rd = INSN_RD(insns[i]);

    for (size_t j = i + 1; j < count && j <= i + 5; j++) {
        if (!(IS_ADD_X_IMM(insns[j]) && INSN_RN(insns[j]) == rd)) continue;
        if (j + 1 >= count || !IS_BL(insns[j + 1])) {
            fprintf(stderr, "warning: txm log patch: %#llx is not followed by a "
                    "BL (%08x); refusing to patch\n",
                    (unsigned long long)(text->addr + (j + 1) * 4), insns[j + 1]);
            return;
        }
        u64 va = text->addr + (j + 1) * sizeof(u32);
        fprintf(stderr, "txm log patch: %#llx  %08x -> %08x  nop  "
                "(drops \"TXM [Error]: selector: %%u | %%u\", ~99%% of serial output)\n",
                (unsigned long long)va, insns[j + 1], A64_NOP);
        insns[j + 1] = A64_NOP;
        return;
    }

    fprintf(stderr, "warning: txm log patch: no ADD completing the ADRP at %#llx\n",
            (unsigned long long)adrp);
}

void patch_kc(u8 *bkc_macho) {
    patch_img4_deadlock(bkc_macho);
    patch_memdev_4gib(bkc_macho);
    patch_rooted_ramdisk(bkc_macho);
    patch_txm_log_flood(bkc_macho);
}

bool kc_uses_mte(u8 *bkc_macho) {
    seg_t *kc_exec_seg = macho_find_seg(bkc_macho, "__TEXT_EXEC");
    assert(kc_exec_seg);

    u32 *kc_text = (u32*)&bkc_macho[kc_exec_seg->fileoff];
    for (size_t i = 0; i < kc_exec_seg->vmsize / sizeof(u32); i++) {
        if (IS_LDG(kc_text[i])) return true;
    }

    return false;
}
