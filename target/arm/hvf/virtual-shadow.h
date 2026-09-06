/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Initial persistent virtual-EL2 shadow context. The architectural walker
 * owns guest translation and permission decisions. Private native tables
 * contain only individually checked 16 KiB RAM aliases. Native exceptions
 * return through a private vector without borrowing guest registers/stack.
 *
 * This first context stops on unsupported stores and code/protection
 * changes, MMIO, and guest faults; it does not yet deliver those faults or
 * support DMA invalidation, EL transitions, multiple CPUs or snapshots.
 */
#define VSH_PAGE 0x4000
#define VSH_BASE UINT64_C(0xe00000000)
#define VSH_ALIAS UINT64_C(0xe40000000)
#define VSH_TABLES 512
#define VSH_PAGES 8192

typedef struct HVFVirtualShadowPage {
    uint64_t va, pa, ipa;
    hv_memory_flags_t flags;
    MemTxAttrs attrs;
    /* Stage-1 descriptor rights granted so far: EL0 access, exec per EL. */
    bool user, exec0, exec2;
} HVFVirtualShadowPage;

/*
 * Knobs read once in hvf_virtual_init(). QUIET drops the per-operation
 * diagnostics from the hot paths (they are stderr writes on every trap).
 * FASTREAD answers the hottest register reads without a vCPU sync. The
 * earlier KEEP_ALIASES experiment (docs/re/hvf-fastpath-ceiling.md) is
 * superseded by the per-world alias contexts below.
 */
static bool hvf_virtual_quiet, hvf_virtual_fastread;
/*
 * STOP_ON_FAULT keeps the pre-kernel behaviour for the permission matrix:
 * a guest-denied access stops the experiment at the faulting instruction
 * instead of being delivered as the guest's own abort.
 */
static bool hvf_virtual_stop_on_fault;
static bool hvf_virtual_instruction(CPUState *cpu, uint32_t word,
                                    bool *advance);

/*
 * One alias context per (permission world, exception level): EL2, EL0,
 * GL2, GL0. All four share the guest's translation tables but each sees a
 * different SPRR permission bank, and ARM's AP[2:1] cannot express the
 * asymmetric combinations SPRR allows (a page writable at GL0 but read-only
 * at GL2 stopped TXM at 0xfffffff01708406c in HVF_KC_BOOT20 when GL2 and
 * GL0 shared one leaf). Each context keeps its own private table tree (a
 * quarter of the pool) and alias set (a quarter of the IPA window). The
 * context is selected on every resume from CURRENTG and the current level,
 * so GENTER/GEXIT, ERET and exception entry switch trees instead of
 * discarding aliases: the kernel makes thousands of guarded calls per
 * second (docs/re/hvf-fastpath-ceiling.md) and each discard cost a full
 * refault of its working set (HVF_KC_BOOT19: 209 identical 60-page cycles
 * in 30,000 log lines). Table-page dependencies are shared.
 */
typedef struct {
    unsigned tables, pages;
    /*
     * Highest alias index whose stage-2 mapping may still exist. Invalidation
     * clears the stage-1 tree (making stale mappings unreachable) but defers
     * the per-alias hv_vm_unmap syscalls; a slot is unmapped only when its
     * index is reused, which removes the bulk of the boot-time syscall storm.
     */
    unsigned mapped_high;
    uint64_t root[2];
    unsigned root_bits[2];
    HVFVirtualShadowPage page[VSH_PAGES];
} HVFVirtualShadowContext;

#define VSH_CONTEXTS 4
#define VSH_CTX_TABLES (VSH_TABLES / VSH_CONTEXTS)

static struct {
    bool active, icache_pending;
    uint8_t *mem;
    unsigned dependencies;
    unsigned generation, installed;
    uint64_t tcr;
    unsigned current;
    HVFVirtualShadowContext ctx[VSH_CONTEXTS];
    uint64_t dependency[VSH_PAGES];
    /* Last guest walk denial, for delivery as the guest's own abort. */
    ARMMMUFaultInfo fault;
    bool fault_valid;
} hvf_vsh;

#define hvf_ctx (&hvf_vsh.ctx[hvf_vsh.current])

static unsigned hvf_vsh_context_for(CPUARMState *env)
{
    return (arm_apple_is_gl(env) ? 2 : 0) + (arm_current_el(env) == 0 ? 1 : 0);
}

static bool hvf_vsh_depends(uint64_t pa)
{
    for (unsigned i = 0; i < hvf_vsh.dependencies; i++) {
        if (hvf_vsh.dependency[i] == pa) {
            return true;
        }
    }
    return false;
}

static uint64_t hvf_vsh_descriptor(const HVFVirtualShadowPage *p);
static uint64_t *hvf_vsh_slot(uint64_t va);

static void hvf_vsh_revoke_write(uint64_t pa)
{
    unsigned saved = hvf_vsh.current;

    for (unsigned c = 0; c < VSH_CONTEXTS; c++) {
        HVFVirtualShadowContext *ctx = &hvf_vsh.ctx[c];
        for (unsigned i = 0; i < ctx->pages; i++) {
            HVFVirtualShadowPage *p = &ctx->page[i];
            if (p->pa == pa && (p->flags & HV_MEMORY_WRITE)) {
                p->flags &= ~HV_MEMORY_WRITE;
                assert_hvf_ok(hv_vm_protect(p->ipa, VSH_PAGE, p->flags));
                /*
                 * The stage-1 leaf must agree with the stage-2 rights, or a
                 * later store takes a stage-2 permission fault the bridge
                 * cannot attribute (HVF_KC_BOOT21, ESR 0x9200004f at IPA
                 * 0xe50090008). The next resume flushes the native TLB.
                 */
                hvf_vsh.current = c;
                uint64_t *slot = hvf_vsh_slot(p->va);
                if (slot) {
                    stq_le_p(slot, hvf_vsh_descriptor(p) |
                             (ldq_le_p(slot) & (UINT64_C(1) << 50)));
                }
                hvf_vsh.generation++;
            }
        }
    }
    hvf_vsh.current = saved;
}

/* True if any alias in either context executes from this backing page. */
static bool hvf_vsh_pa_executable(uint64_t pa)
{
    for (unsigned c = 0; c < VSH_CONTEXTS; c++) {
        HVFVirtualShadowContext *ctx = &hvf_vsh.ctx[c];
        for (unsigned i = 0; i < ctx->pages; i++) {
            if (ctx->page[i].pa == pa &&
                (ctx->page[i].flags & HV_MEMORY_EXEC)) {
                return true;
            }
        }
    }
    return false;
}

static MemTxResult hvf_vsh_read(void *opaque, hwaddr pa, MemTxAttrs attrs,
                                unsigned size, bool be, uint64_t *value)
{
    HVFPTWProbe *probe = opaque;
    uint64_t page = pa & ~(uint64_t)(VSH_PAGE - 1);

    if (!hvf_vsh_depends(page)) {
        if (hvf_vsh.dependencies == VSH_PAGES) {
            return MEMTX_ERROR;
        }
        hvf_vsh.dependency[hvf_vsh.dependencies++] = page;
        /* Prevent later guest stores through aliases installed earlier. */
        hvf_vsh_revoke_write(page);
    }
    return hvf_ptw_probe_read(probe, pa, attrs, size, be, value);
}

/* Table read without alias dependency tracking: for AT-style queries. */
static MemTxResult hvf_vsh_plain_read(void *opaque, hwaddr pa,
                                      MemTxAttrs attrs, unsigned size,
                                      bool be, uint64_t *value)
{
    return hvf_ptw_probe_read(opaque, pa, attrs, size, be, value);
}

static MemTxResult hvf_vsh_cmpxchg(void *opaque, hwaddr pa, MemTxAttrs attrs,
                                   bool be, uint64_t old, uint64_t new,
                                   uint64_t *observed)
{
    /* AF/dirty mutation needs invalidation; never silently set guest bits. */
    error_report("Virtual shadow requires table update at 0x%" PRIx64, pa);
    return MEMTX_ERROR;
}

static uint64_t hvf_vsh_table(void)
{
    if (hvf_ctx->tables == VSH_CTX_TABLES) {
        return 0;
    }
    return VSH_BASE + (hvf_vsh.current * VSH_CTX_TABLES + ++hvf_ctx->tables) *
                      VSH_PAGE;
}

static uint64_t *hvf_vsh_slot(uint64_t va)
{
    unsigned half = (va >> 55) & 1;
    uint64_t table = hvf_ctx->root[half];
    const unsigned shifts[] = { 36, 25, 14 };

    for (unsigned i = 0; i < ARRAY_SIZE(shifts); i++) {
        unsigned mask = i ? 0x7ff : (1 << hvf_ctx->root_bits[half]) - 1;
        uint64_t *slot = (uint64_t *)(hvf_vsh.mem + table - VSH_BASE) +
                         ((va >> shifts[i]) & mask);
        if (i == 2) {
            return slot;
        }
        if (!ldq_le_p(slot)) {
            uint64_t next = hvf_vsh_table();
            if (!next) {
                return NULL;
            }
            stq_le_p(slot, next | 3);
        }
        table = ldq_le_p(slot) & ~(uint64_t)(VSH_PAGE - 1);
    }
    g_assert_not_reached();
}

static void hvf_vsh_destroy(void)
{
    if (!hvf_vsh.mem) {
        return;
    }
    for (unsigned c = 0; c < VSH_CONTEXTS; c++) {
        unsigned high = hvf_vsh.ctx[c].pages > hvf_vsh.ctx[c].mapped_high ?
                        hvf_vsh.ctx[c].pages : hvf_vsh.ctx[c].mapped_high;
        for (unsigned i = 0; i < high; i++) {
            uint64_t ipa = VSH_ALIAS + (c * VSH_PAGES + i) * VSH_PAGE;
            assert_hvf_ok(hv_vm_unmap(ipa, VSH_PAGE));
        }
    }
    assert_hvf_ok(hv_vm_unmap(VSH_BASE, (VSH_TABLES + 1) * VSH_PAGE));
    free(hvf_vsh.mem);
    memset(&hvf_vsh, 0, sizeof(hvf_vsh));
}

static bool hvf_vsh_tcr_valid(uint64_t tcr)
{
    unsigned t0sz = tcr & 63, t1sz = (tcr >> 16) & 63;

    /* Three-level, 16 KiB tables with 39..47 input address bits. */
    return t0sz >= 17 && t0sz <= 25 && t1sz >= 17 && t1sz <= 25 &&
           ((tcr >> 14) & 3) == 2 && ((tcr >> 30) & 3) == 1;
}

static void hvf_vsh_roots(uint64_t tcr)
{
    uint64_t *slot;

    hvf_ctx->root_bits[0] = 64 - (tcr & 63) - 36;
    hvf_ctx->root_bits[1] = 64 - ((tcr >> 16) & 63) - 36;
    /*
     * Match VA widths and TBI/TBID for native pointer authentication. Other
     * translation controls apply in the software walker, while the private
     * native tables use AF=1, 40-bit IPAs and no guest ASIDs or table writes.
     */
    uint64_t mask = 63 | (UINT64_C(63) << 16) |
                    (UINT64_C(3) << 37) | (UINT64_C(3) << 51);
    hvf_vsh.tcr = (UINT64_C(0x17519b519) & ~mask) | (tcr & mask);
    hvf_ctx->root[0] = hvf_vsh_table();
    hvf_ctx->root[1] = hvf_vsh_table();
    slot = hvf_vsh_slot(VSH_BASE);
    assert(slot);
    stq_le_p(slot, VSH_BASE | 0x783 | (UINT64_C(1) << 54));
}

static bool hvf_vsh_create(CPUState *cpu)
{
    MemoryRegionSection overlap;
    uint64_t tcr = cpu_env(cpu)->cp15.tcr_el[2];

    if (!hvf_vsh_tcr_valid(tcr)) {
        return false;
    }

    for (unsigned i = 0; i < 2; i++) {
        overlap = memory_region_find(get_system_memory(),
                    i ? VSH_ALIAS : VSH_BASE,
                    (i ? VSH_CONTEXTS * VSH_PAGES : VSH_TABLES + 1) * VSH_PAGE);
        if (overlap.mr) {
            memory_region_unref(overlap.mr);
            return false;
        }
    }
    if (posix_memalign((void **)&hvf_vsh.mem, VSH_PAGE,
                      (VSH_TABLES + 1) * VSH_PAGE)) {
        return false;
    }
    memset(hvf_vsh.mem, 0, (VSH_TABLES + 1) * VSH_PAGE);
    stl_le_p(hvf_vsh.mem, 0xd508871f);     /* TLBI VMALLE1 */
    stl_le_p(hvf_vsh.mem + 4, 0xd5033f9f); /* DSB SY */
    stl_le_p(hvf_vsh.mem + 8, 0xd5033fdf); /* ISB */
    stl_le_p(hvf_vsh.mem + 12, 0xd4000003 | (0xda00 << 5));
    /* Cache-maintenance entry: run at native EL1 without guest mappings. */
    stl_le_p(hvf_vsh.mem + 0x20, 0xd508871f); /* TLBI VMALLE1 */
    stl_le_p(hvf_vsh.mem + 0x24, 0xd5033f9f); /* DSB SY */
    stl_le_p(hvf_vsh.mem + 0x28, 0xd508751f); /* IC IALLU */
    stl_le_p(hvf_vsh.mem + 0x2c, 0xd5033f9f); /* DSB SY */
    stl_le_p(hvf_vsh.mem + 0x30, 0xd5033fdf); /* ISB */
    stl_le_p(hvf_vsh.mem + 0x34, 0xd4000003 | (0xda00 << 5));
    for (unsigned i = 0; i < 16; i++) {
        stl_le_p(hvf_vsh.mem + 0x800 + i * 128,
                 0xd4000003 | (0xda01 << 5));
    }
    hvf_vsh.current = hvf_vsh_context_for(cpu_env(cpu));
    hvf_vsh_roots(tcr);
    assert_hvf_ok(hv_vm_map(hvf_vsh.mem, VSH_BASE, VSH_PAGE,
                            HV_MEMORY_READ | HV_MEMORY_EXEC));
    assert_hvf_ok(hv_vm_map(hvf_vsh.mem + VSH_PAGE, VSH_BASE + VSH_PAGE,
                            VSH_TABLES * VSH_PAGE, HV_MEMORY_READ));
    return true;
}

static void hvf_vsh_icache(CPUState *cpu)
{
    /*
     * Current executable backings cannot be written natively. Synchronize
     * host stores, then perform native IC IALLU in the private helper before
     * guest execution resumes. Previously unmapped code is synchronized at
     * its next checked executable mapping. This remains a single-vCPU path.
     */
    for (unsigned c = 0; c < VSH_CONTEXTS; c++) {
        HVFVirtualShadowContext *ctx = &hvf_vsh.ctx[c];
        for (unsigned i = 0; i < ctx->pages; i++) {
            HVFVirtualShadowPage *p = &ctx->page[i];
            if (p->flags & HV_MEMORY_EXEC) {
                address_space_flush_icache_range(
                    arm_addressspace(cpu, p->attrs), p->pa, VSH_PAGE);
            }
        }
    }
    hvf_vsh.icache_pending = true;
}

static void hvf_vsh_invalidate(CPUState *cpu)
{
    /*
     * A single stopped vCPU owns this context. Remove every native alias,
     * including its stage-2 mapping, before any execution with new TCR/TTBR
     * state. Rewalk faults under the new register bank; never retain rights
     * derived from the old tables. hvf_vsh_put flushes native TLBs before
     * resuming, using the unchanged private helper page with the MMU off.
     */
    if (!hvf_virtual_quiet) {
        error_report("Virtual shadow invalidate %u aliases at pc=0x%" PRIx64,
                     hvf_ctx->pages, cpu_env(cpu)->pc);
    }
    if (hvf_ctx->pages > hvf_ctx->mapped_high) {
        hvf_ctx->mapped_high = hvf_ctx->pages;
    }
    /* Only the tables actually built need clearing; roots are rebuilt below. */
    memset(hvf_vsh.mem + (1 + hvf_vsh.current * VSH_CTX_TABLES) * VSH_PAGE,
           0, hvf_ctx->tables * VSH_PAGE);
    hvf_ctx->pages = hvf_ctx->tables = 0;
    hvf_vsh_roots(cpu_env(cpu)->cp15.tcr_el[2]);
    hvf_vsh.generation++;
}

/*
 * Guest-visible translation or permission state changed (table store,
 * TCR/TTBR/SCTLR/MAIR write, SPRR bank write): both worlds rewalk, and the
 * shared table-page dependency list starts over.
 */
static void hvf_vsh_invalidate_all(CPUState *cpu)
{
    unsigned saved = hvf_vsh.current;

    for (unsigned c = 0; c < VSH_CONTEXTS; c++) {
        hvf_vsh.current = c;
        if (hvf_ctx->root[0] || hvf_ctx->pages) {
            hvf_vsh_invalidate(cpu);
        }
    }
    hvf_vsh.current = saved;
    hvf_vsh.dependencies = 0;
}

/* Select the alias context of the world and level about to execute. */
static void hvf_vsh_switch(CPUState *cpu, unsigned ctx)
{
    if (!hvf_vsh.active || ctx == hvf_vsh.current) {
        return;
    }
    hvf_vsh.current = ctx;
    if (!hvf_ctx->root[0]) {
        hvf_vsh_roots(cpu_env(cpu)->cp15.tcr_el[2]);
    }
    hvf_vsh.generation++;
}

static void hvf_vsh_select(CPUState *cpu)
{
    hvf_vsh_switch(cpu, hvf_vsh_context_for(cpu_env(cpu)));
}

static bool hvf_vsh_code_safe(const uint8_t *host)
{
    for (unsigned i = 0; i < VSH_PAGE; i += 4) {
        uint32_t w = ldl_le_p(host + i);
        /*
         * TPIDR_EL0 (S3_3_C13_C0_2) is an unprivileged software-thread
         * register: HVF never traps it and no permission or translation
         * state depends on it, so it may execute natively at any level.
         * The bridge benchmark uses it as the non-trapping read reference.
         */
        if ((w & 0xffdfffe0) == 0xd51bd040) {
            continue;
        }
        /*
         * DC ZVA (kernelcache only, native_sptm_patch.py --native-zva):
         * zeroing through a writable alias is an ordinary store as far as
         * the stage-1 rights go; an unmapped or read-only target faults to
         * the private vector like any store. The kernel's page zeroing at
         * XNU 0xfffffff02b34b348 issues one per 64-byte line.
         */
        if ((w & 0xffffffe0) == 0xd50b7420) {
            continue;
        }
        /*
         * Classes that execute correctly at physical EL1 without a ledger,
         * needed by the unpatched corecrypto kext (HVF_KC_BOOT23 stopped on
         * its MRS ID_AA64ISAR0_EL1): ID registers (op0=3 op1=0 CRn=0) trap
         * to the host and reach the same dispatcher; the PSTATE group
         * (op0=3 op1=3 CRn=4 CRm=2: NZCV, DAIF, DIT, SSBS, TCO, PAN, UAO)
         * and the MSR-immediate forms act on the physical PSTATE, which the
         * bridge mirrors in both directions.
         */
        if ((w & 0xfff80000) == 0xd5380000 && ((w >> 12) & 15) == 0 &&
            ((w >> 16) & 7) == 0) {
            continue;                       /* MRS Xt, ID_*_EL1 */
        }
        if ((w & 0xffdff000) == 0xd51b4000 && ((w >> 8) & 15) == 2) {
            continue;                       /* MRS/MSR NZCV/DAIF/DIT/... */
        }
        if ((w & 0xfff8f01f) == 0xd500401f) {
            continue;                       /* MSR (immediate) */
        }
        if (((w & 0xffc00000) == 0xd5000000 && ((w >> 19) & 3)) ||
            (w & 0xfffff000) == 0xd69f0000 ||
            /* Also reject the wider TCG decode's unverified bit-4 forms. */
            (w & 0xffffffe0) == 0x00201420 || w == 0x00201400 ||
            /* PSTATE changes except SPSel need context reconciliation. */
            ((w & 0xfff8f01f) == 0xd500401f &&
             (w & 0xfffffeff) != 0xd50040bf)) {
            error_report("Virtual shadow unadapted instruction 0x%08x "
                         "at page offset 0x%x", w, i);
            return false;
        }
    }
    return true;
}

/*
 * Private stage-1 leaf for one alias. AP[1] (bit 6) opens the page to EL0;
 * UXN (bit 54) and PXN (bit 53) are cleared only for the levels that have
 * fetched it through a granted walk. A page writable from EL0 is never
 * executable at EL1 by architecture (ARM DDI 0487 D8.6.2), which matches
 * the guest's own split: TXM code is fetched at EL0 only, SPTM code at EL2.
 */
static uint64_t hvf_vsh_descriptor(const HVFVirtualShadowPage *p)
{
    uint64_t d = p->ipa | 0x703;

    if (p->user) {
        d |= 1 << 6;
    }
    if (!(p->flags & HV_MEMORY_WRITE)) {
        d |= 1 << 7;
    }
    if (!p->exec0) {
        d |= UINT64_C(1) << 54;
    }
    if (!p->exec2) {
        d |= UINT64_C(1) << 53;
    }
    return d;
}

static bool hvf_vsh_fill(CPUState *cpu, uint64_t va, MMUAccessType access)
{
    static const ARMPTWMemoryOps ops = {
        .read = hvf_vsh_read,
        .cmpxchg64 = hvf_vsh_cmpxchg,
    };
    CPUARMState *env = cpu_env(cpu);
    HVFPTWProbe probe = { .cpu = cpu };
    GetPhysAddrResult result = {};
    ARMMMUFaultInfo fi = {};
    MemoryRegion *mr;
    MemoryRegionSection section;
    hwaddr offset;
    uint64_t *slot, pa, ipa, descriptor;
    uint8_t *host;
    hv_memory_flags_t flags;
    ARMVAParameters param = aa64_va_parameters(env, va, arm_mmu_idx(env),
                                               access != MMU_INST_FETCH, false);
    unsigned bits = 64 - param.tsz;

    if (param.tsz_oob || bits < 39 || bits > 47) {
        error_report("Virtual shadow unsupported address width %u", bits);
        return false;
    }
    if (param.tbi) {
        va = sextract64(va, 0, 56);
    }
    uint64_t top = va >> bits;
    if (top != 0 && top != (UINT64_C(1) << param.tsz) - 1) {
        error_report("Virtual shadow unsupported VA 0x%" PRIx64, va);
        return false;
    }
    va &= ~(uint64_t)(VSH_PAGE - 1);
    if (va == VSH_BASE) {
        return false;
    }
    if (hvf_ctx->pages == VSH_PAGES || hvf_ctx->tables + 3 > VSH_CTX_TABLES) {
        /*
         * Capacity eviction: drop every alias and rewalk, the same way a
         * TLB flush would. The kernel's working set exceeded the original
         * fixed pool within three seconds (HVF_KC_BOOT10, silent stop at
         * 0xfffffff02ab54880 with the counters frozen).
         */
        static unsigned flushes;
        hvf_vsh_invalidate(cpu);
        if (flushes++ < 8 || !(flushes & 63)) {
            error_report("Virtual shadow capacity flush #%u at pc=0x%" PRIx64,
                         flushes, env->pc);
        }
    }
    unsigned el = arm_current_el(env);
    HVFVirtualShadowPage *existing = NULL;
    for (unsigned i = 0; i < hvf_ctx->pages; i++) {
        if (hvf_ctx->page[i].va == va) {
            existing = &hvf_ctx->page[i];
        }
    }
    hvf_vsh.fault_valid = false;
    if (!get_phys_addr_with_ops(env, va, access, 0, arm_mmu_idx(env),
                               &result, &fi, &ops, &probe)) {
        hvf_vsh.fault = fi;
        hvf_vsh.fault_valid = true;
        if (!hvf_virtual_quiet) {
            error_report("Virtual shadow guest walk denied va=0x%" PRIx64
                         " el=%u access=%u FSC=0x%x", va, el, access,
                         arm_fi_to_lfsc(&fi));
        }
        return false;
    }
    if (existing) {
        /*
         * The alias exists but was installed for the other exception level
         * (SPTM at EL2 and TXM at EL0 share the EL2&0 translation regime).
         * Widen the private leaf to what this level's granted walk allows.
         * An EL0 fetch of a page mapped without execute rights, or an EL2
         * fetch of an EL0-only page, still stops: the stage-2 rights and
         * code validation of the original mapping are not revisited here.
         */
        bool need_exec = access == MMU_INST_FETCH;
        if (result.f.phys_addr != existing->pa ||
            (need_exec && !(existing->flags & HV_MEMORY_EXEC)) ||
            (need_exec && el == 2 && !existing->exec2) ||
            (access == MMU_DATA_STORE &&
             !(existing->flags & HV_MEMORY_WRITE))) {
            error_report("Virtual shadow access to existing alias "
                         "va=0x%" PRIx64 " el=%u access=%u", va, el, access);
            return false;
        }
        if (el == 0) {
            existing->user = true;
            existing->exec0 |= need_exec;
        }
        slot = hvf_vsh_slot(va);
        assert(slot);
        stq_le_p(slot, hvf_vsh_descriptor(existing));
        hvf_vsh.generation++;
        if (!hvf_virtual_quiet) {
            error_report("Virtual shadow widened va=0x%" PRIx64 " el=%u "
                         "user=%u exec0=%u exec2=%u", va, el, existing->user,
                         existing->exec0, existing->exec2);
        }
        return true;
    }
    if (result.f.lg_page_size < 14 || (result.f.phys_addr & (VSH_PAGE - 1)) ||
        result.cacheattrs.attrs != 0xff || result.cacheattrs.is_s2_format) {
        error_report("Virtual shadow unsupported mapping va=0x%" PRIx64
                     " pa=0x%" PRIx64 " page=2^%u attrs=0x%x", va,
                     (uint64_t)result.f.phys_addr, result.f.lg_page_size,
                     result.cacheattrs.attrs);
        return false;
    }
    pa = result.f.phys_addr;
    host = hvf_ptw_probe_ram(&probe, pa, result.f.attrs, VSH_PAGE,
                            false, &mr, &offset);
    if (!host || ((uintptr_t)host & (VSH_PAGE - 1))) {
        error_report("Virtual shadow requires normal RAM pa=0x%" PRIx64, pa);
        return false;
    }
    flags = (result.f.prot & PAGE_READ ? HV_MEMORY_READ : 0) |
            (result.f.prot & PAGE_WRITE ? HV_MEMORY_WRITE : 0);
    if (access == MMU_INST_FETCH) {
        /*
         * EL0 code needs no ledger: privileged instructions executed at
         * physical EL0 trap to the private vector and are delivered to the
         * guest as its own exceptions, exactly as hardware would.
         */
        if (el == 2 && !hvf_vsh_code_safe(host)) {
            return false;
        }
        flags = (flags & ~HV_MEMORY_WRITE) | HV_MEMORY_EXEC;
        hvf_vsh_revoke_write(pa);
        address_space_flush_icache_range(arm_addressspace(cpu, result.f.attrs),
                                         pa, VSH_PAGE);
    }
    /* An executable backing must remain immutable through every alias. */
    if (hvf_vsh_pa_executable(pa)) {
        flags &= ~HV_MEMORY_WRITE;
    }
    section = memory_region_find(arm_addressspace(cpu, result.f.attrs)->root,
                                 pa, VSH_PAGE);
    if (!section.mr) {
        return false;
    }
    if (section.readonly || memory_region_is_rom(mr) || hvf_vsh_depends(pa)) {
        flags &= ~HV_MEMORY_WRITE;
    }
    memory_region_unref(section.mr);
    if (!hvf_ctx->pages &&
        g_strcmp0(getenv("QEMU_HVF_VIRTUAL_SHADOW_DENY_EXEC"), "1") == 0) {
        /* Diskless boot negative control: revoke, never grant, a right. */
        flags &= ~HV_MEMORY_EXEC;
    }
    slot = hvf_vsh_slot(va);
    if (!slot) {
        error_report("Virtual shadow table pool exhausted at va=0x%" PRIx64,
                     va);
        return false;
    }
    ipa = VSH_ALIAS + (hvf_vsh.current * VSH_PAGES + hvf_ctx->pages) * VSH_PAGE;
    /* Reused slot: its previous stage-2 mapping is still present, drop it. */
    if (hvf_ctx->pages < hvf_ctx->mapped_high) {
        assert_hvf_ok(hv_vm_unmap(ipa, VSH_PAGE));
    }
    assert_hvf_ok(hv_vm_map(host, ipa, VSH_PAGE, flags));
    HVFVirtualShadowPage page = {
        .va = va, .pa = pa, .ipa = ipa, .flags = flags,
        .attrs = result.f.attrs, .user = el == 0,
        .exec0 = el == 0 && (flags & HV_MEMORY_EXEC),
        .exec2 = el == 2 && (flags & HV_MEMORY_EXEC),
    };
    descriptor = hvf_vsh_descriptor(&page);
    if (result.f.extra.arm.guarded) {
        descriptor |= UINT64_C(1) << 50; /* Preserve BTI's guarded-page bit. */
    }
    stq_le_p(slot, descriptor);
    hvf_ctx->page[hvf_ctx->pages++] = page;
    hvf_vsh.generation++;
    if (!hvf_virtual_quiet) {
        error_report("Virtual shadow mapped va=0x%" PRIx64 " pa=0x%" PRIx64
                     " ipa=0x%" PRIx64 " rights=%u el=%u access=%u deps=%u",
                     va, pa, ipa, (unsigned)flags, el, access,
                     hvf_vsh.dependencies);
    }
    return true;
}

static bool hvf_vsh_zero(CPUState *cpu, uint64_t address)
{
    static const uint8_t zeros[2048];
    CPUARMState *env = cpu_env(cpu);
    unsigned bs = get_dczid_bs(ARM_CPU(cpu));
    HVFVirtualShadowPage *page = NULL;
    ARMVAParameters param;
    uint64_t va, length;

    /* DCZID.BS uses log2(words); valid blocks fit within a 16 KiB page. */
    if (!hvf_vsh.active || bs > 9) {
        return false;
    }
    length = 4ULL << bs;
    param = aa64_va_parameters(env, address, arm_mmu_idx(env), true, false);
    va = param.tbi ? sextract64(address, 0, 56) : address;
    va &= ~(length - 1);
    uint64_t base = va & ~(uint64_t)(VSH_PAGE - 1);
    for (unsigned i = 0; i < hvf_ctx->pages; i++) {
        if (hvf_ctx->page[i].va == base) {
            page = &hvf_ctx->page[i];
            break;
        }
    }
    if (!page) {
        if (!hvf_vsh_fill(cpu, address, MMU_DATA_STORE)) {
            return false;
        }
        page = &hvf_ctx->page[hvf_ctx->pages - 1];
    }
    /*
     * The alias includes guest walk rights plus stricter code/table/ROM
     * write exclusions. Never use a host memset to evade those exclusions.
     * Context/table changes still stop, so installed permissions stay valid.
     */
    if (!(page->flags & HV_MEMORY_WRITE)) {
        error_report("Virtual shadow zero denied va=0x%" PRIx64, address);
        return false;
    }
    return address_space_write(arm_addressspace(cpu, page->attrs),
                               page->pa + va - base, page->attrs,
                               zeros, length) == MEMTX_OK;
}

static bool hvf_vsh_ctrr_write_allowed(CPUState *cpu, uint64_t pa)
{
    /*
     * Guarded EL2 is the agent that programs CTRR and keeps writing inside
     * the ranges afterwards: with CTRR_C_CTL=1 (WRPROTECT) already set at
     * SPTM 0xfffffff0270bbefc, SPTM 0xfffffff0270d5ce4 stores page-table
     * words into the kernelcache __DATA_SPTM segment, which lies inside
     * CTRR C ([DeviceTree, SPTM-rx], hw/arm/apple_regs.c). Hardware and
     * TCG both complete that store, so the exclusion applies to
     * non-guarded execution only. This is still not a full CTRR model.
     */
    if (arm_apple_is_gl(cpu_env(cpu))) {
        return true;
    }
    static const uint32_t keys[][3] = {
        { ENCODE_AA64_CP_REG(3, 4, 15, 6, 2),
          ENCODE_AA64_CP_REG(3, 4, 15, 6, 4),
          ENCODE_AA64_CP_REG(3, 4, 15, 6, 5) },
        { ENCODE_AA64_CP_REG(3, 4, 15, 6, 3),
          ENCODE_AA64_CP_REG(3, 4, 15, 6, 6),
          ENCODE_AA64_CP_REG(3, 4, 15, 6, 7) },
        { ENCODE_AA64_CP_REG(3, 0, 11, 2, 0),
          ENCODE_AA64_CP_REG(3, 0, 11, 1, 0),
          ENCODE_AA64_CP_REG(3, 0, 11, 1, 1) },
        { ENCODE_AA64_CP_REG(3, 0, 11, 2, 1),
          ENCODE_AA64_CP_REG(3, 0, 11, 1, 2),
          ENCODE_AA64_CP_REG(3, 0, 11, 1, 3) },
    };

    /* Conservative exclusion for this store path, not a full CTRR model. */
    for (unsigned i = 0; i < ARRAY_SIZE(keys); i++) {
        uint64_t value[3];
        for (unsigned j = 0; j < 3; j++) {
            const ARMCPRegInfo *ri = get_arm_cp_reginfo(ARM_CPU(cpu)->cp_regs,
                                                        keys[i][j]);
            if (!ri || !ri->readfn) {
                return false;
            }
            value[j] = ri->readfn(cpu_env(cpu), ri);
        }
        if ((value[0] & 1) && pa >= (value[1] & ~UINT64_C(0xfff)) &&
            pa <= (value[2] | UINT64_C(0xfff))) {
            return false;
        }
    }
    return true;
}

/*
 * Write permission fault on an alias that lost WRITE because its backing
 * was executable: the kernel reuses freed boot code as data (HVF_KC_BOOT25,
 * STP at XNU 0xfffffff02b34b320 to 0xffffffe28a200000 right after a GEXIT).
 * If the guest walk grants the store, executable aliases of that backing
 * are demoted in every context (they re-validate on their next fetch) and
 * this alias regains WRITE. Table-page dependencies keep the emulated path.
 */
static bool hvf_vsh_grant_write(CPUState *cpu, uint64_t far)
{
    static const ARMPTWMemoryOps ops = {
        .read = hvf_vsh_read,
        .cmpxchg64 = hvf_vsh_cmpxchg,
    };
    CPUARMState *env = cpu_env(cpu);
    HVFPTWProbe probe = { .cpu = cpu };
    GetPhysAddrResult result = {};
    ARMMMUFaultInfo fi = {};
    HVFVirtualShadowPage *p = NULL;
    MemoryRegionSection section;
    uint64_t va = far & ~(uint64_t)(VSH_PAGE - 1);
    unsigned saved = hvf_vsh.current;

    for (unsigned i = 0; i < hvf_ctx->pages; i++) {
        if (hvf_ctx->page[i].va == va) {
            p = &hvf_ctx->page[i];
        }
    }
    if (!p || (p->flags & HV_MEMORY_WRITE)) {
        error_report("Virtual shadow grant: %s alias for va=0x%" PRIx64
                     " (flags=%u)", p ? "writable" : "no", va,
                     p ? (unsigned)p->flags : 0);
        return false;
    }
    bool dependency = hvf_vsh_depends(p->pa);
    if (!get_phys_addr_with_ops(env, va, MMU_DATA_STORE, 0, arm_mmu_idx(env),
                               &result, &fi, &ops, &probe)) {
        error_report("Virtual shadow grant: guest walk denies store at va=0x%"
                     PRIx64 " FSC=0x%x", va, arm_fi_to_lfsc(&fi));
        hvf_vsh.fault = fi;
        hvf_vsh.fault_valid = true;
        return false;
    }
    if (result.f.phys_addr != p->pa || !(result.f.prot & PAGE_WRITE)) {
        error_report("Virtual shadow grant: va=0x%" PRIx64 " pa=0x%" PRIx64
                     " alias pa=0x%" PRIx64 " prot=%u", va,
                     (uint64_t)result.f.phys_addr, p->pa, result.f.prot);
        return false;
    }
    if (dependency || hvf_vsh_depends(p->pa)) {
        /*
         * A page once used as a translation table is being written with a
         * form the emulator does not handle (HVF_KC_BOOT26: STP at XNU
         * 0xfffffff02b34b320 to 0xffffffe70d048000). Freed table pages are
         * reused as data and the dependency list never retires entries, so
         * start over: every alias and dependency is dropped, the retried
         * store refaults as a translation fault and maps writable, and a
         * page that is still a live table is rediscovered by the next walk.
         * A page that keeps coming back here is a live table written with
         * an unsupported form; stop instead of looping.
         */
        static uint64_t last_far;
        static unsigned repeats;
        repeats = far == last_far ? repeats + 1 : 0;
        last_far = far;
        if (repeats >= 3) {
            error_report("Virtual shadow live table page written natively "
                         "at 0x%" PRIx64 " pc=0x%" PRIx64, far, env->pc);
            return false;
        }
        hvf_vsh_invalidate_all(cpu);
        if (!hvf_virtual_quiet) {
            error_report("Virtual shadow table page reused as data at 0x%"
                         PRIx64 ": aliases and dependencies restarted", va);
        }
        return true;
    }
    section = memory_region_find(arm_addressspace(cpu, p->attrs)->root,
                                 p->pa, VSH_PAGE);
    if (!section.mr) {
        return false;
    }
    bool readonly = section.readonly || memory_region_is_rom(section.mr);
    memory_region_unref(section.mr);
    if (readonly) {
        return false;
    }
    for (unsigned c = 0; c < VSH_CONTEXTS; c++) {
        HVFVirtualShadowContext *ctx = &hvf_vsh.ctx[c];
        for (unsigned i = 0; i < ctx->pages; i++) {
            HVFVirtualShadowPage *q = &ctx->page[i];
            if (q->pa == p->pa && (q->flags & HV_MEMORY_EXEC)) {
                q->flags &= ~HV_MEMORY_EXEC;
                q->exec0 = q->exec2 = false;
                assert_hvf_ok(hv_vm_protect(q->ipa, VSH_PAGE, q->flags));
                hvf_vsh.current = c;
                uint64_t *slot = hvf_vsh_slot(q->va);
                if (slot) {
                    stq_le_p(slot, hvf_vsh_descriptor(q) |
                             (ldq_le_p(slot) & (UINT64_C(1) << 50)));
                }
            }
        }
    }
    hvf_vsh.current = saved;
    p->flags |= HV_MEMORY_WRITE;
    assert_hvf_ok(hv_vm_protect(p->ipa, VSH_PAGE, p->flags));
    uint64_t *slot = hvf_vsh_slot(p->va);
    assert(slot);
    stq_le_p(slot, hvf_vsh_descriptor(p) |
             (ldq_le_p(slot) & (UINT64_C(1) << 50)));
    hvf_vsh.generation++;
    if (!hvf_virtual_quiet) {
        error_report("Virtual shadow write granted va=0x%" PRIx64
                     " pa=0x%" PRIx64 " (executable aliases demoted)",
                     va, p->pa);
    }
    return true;
}

static bool hvf_vsh_guarded_store(CPUState *cpu, uint64_t far)
{
    static const ARMPTWMemoryOps ops = {
        .read = hvf_vsh_read,
        .cmpxchg64 = hvf_vsh_cmpxchg,
    };
    CPUARMState *env = cpu_env(cpu);
    HVFPTWProbe probe = { .cpu = cpu };
    HVFVirtualShadowPage *source = NULL, *dest = NULL;
    GetPhysAddrResult result = {};
    ARMMMUFaultInfo fi = {};
    MemoryRegion *mr;
    MemoryRegionSection section;
    hwaddr offset;
    uint8_t *host;
    uint32_t word;
    uint64_t address, value;
    bool executable = false, table;
    g_autofree uint8_t *candidate = NULL;

    for (unsigned i = 0; i < hvf_ctx->pages; i++) {
        HVFVirtualShadowPage *p = &hvf_ctx->page[i];
        if (p->va == (env->pc & ~(uint64_t)(VSH_PAGE - 1))) {
            source = p;
        }
        if (p->va == (far & ~(uint64_t)(VSH_PAGE - 1))) {
            dest = p;
        }
    }
    if (!source || !(source->flags & HV_MEMORY_EXEC) || !dest ||
        (dest->flags & HV_MEMORY_WRITE)) {
        return false;
    }
    executable = hvf_vsh_pa_executable(dest->pa);
    if (!executable && !hvf_vsh_depends(dest->pa)) {
        return false;
    }
    host = hvf_ptw_probe_ram(&probe, source->pa, source->attrs, VSH_PAGE,
                             false, &mr, &offset);
    if (!host) {
        return false;
    }
    word = ldl_le_p(host + env->pc - source->va);
    /*
     * Store forms the firmware uses on table and code pages:
     *   STR  Xt, [Xn|SP, #imm12*8]           (SPTM 0xfffffff0270d5ce4)
     *   STLR Xt, [Xn|SP]
     *   CAS{A,L,AL} Xs, Xt, [Xn|SP]          (SPTM 0xfffffff0270edccc, PTE
     *                                        compare-and-swap, HVF_KC_BOOT22)
     * The compare-and-swap is atomic with respect to the guest because the
     * single vCPU is stopped; on mismatch Xs receives the old word and no
     * store happens.
     */
    unsigned rn = (word >> 5) & 31, rs = (word >> 16) & 31;
    unsigned size = 1 << (word >> 30);            /* B/H/W/X from size bits */
    bool cas = (word & 0x3fa07c00) == 0x08a07c00; /* CAS{A,L,AL}{B,H,,} */
    bool stlr = (word & 0x3fffc00) == 0x089ffc00;  /* STLR{B,H,,} */
    /*
     * Atomic memory operations (LSE): LDADD/LDCLR/LDEOR/LDSET and SWP in
     * every size and ordering (SPTM 0xfffffff0270eeb40 does LDADDAH on a
     * table page, HVF_KC_BOOT30). Rt receives the old value; the stored
     * value is computed here since the vCPU is stopped.
     */
    bool atomic = (word & 0x3f200c00) == 0x38200000 &&
                  (((word >> 12) & 7) < 4 || (word & 0x8000));
    if ((word & 0x3fc00000) == 0x39000000) {       /* STR{B,H,,} imm12 */
        address = env->xregs[rn] + (((word >> 10) & 0xfff) * size);
    } else if (cas || stlr || atomic) {
        address = env->xregs[rn];
    } else {
        error_report("Virtual shadow unsupported store form 0x%08x at 0x%"
                     PRIx64 " to 0x%" PRIx64, word, env->pc, far);
        return false;
    }
    if (address != far ||
        !get_phys_addr_with_ops(env, far, MMU_DATA_STORE, 0, arm_mmu_idx(env),
                               &result, &fi, &ops, &probe) ||
        !(result.f.prot & PAGE_WRITE) || result.cacheattrs.attrs != 0xff ||
        result.cacheattrs.is_s2_format ||
        result.f.phys_addr != dest->pa + far - dest->va ||
        !hvf_vsh_ctrr_write_allowed(cpu, result.f.phys_addr)) {
        error_report("Virtual shadow guarded store denied at 0x%" PRIx64
                     " pc=0x%" PRIx64 " address=0x%" PRIx64 " prot=%u"
                     " pa=0x%" PRIx64 " expected=0x%" PRIx64 " ctrr=%u",
                     far, env->pc, address, result.f.prot,
                     (uint64_t)result.f.phys_addr, dest->pa + far - dest->va,
                     hvf_vsh_ctrr_write_allowed(cpu, result.f.phys_addr));
        return false;
    }
    section = memory_region_find(arm_addressspace(cpu, result.f.attrs)->root,
                                 result.f.phys_addr, size);
    if (!section.mr) {
        return false;
    }
    bool readonly = section.readonly || memory_region_is_rom(section.mr);
    memory_region_unref(section.mr);
    if (readonly) {
        return false;
    }
    host = hvf_ptw_probe_ram(&probe, dest->pa, result.f.attrs, VSH_PAGE,
                             true, &mr, &offset);
    if (!host) {
        return false;
    }
    if (far & (size - 1)) {
        return false;
    }
    value = (word & 31) == 31 ? 0 : env->xregs[word & 31];
    bool be = env->cp15.sctlr_el[2] & SCTLR_EE;
    if (atomic) {
        const uint8_t *at = host + far - dest->va;
        uint64_t old = size == 8 ? (be ? ldq_be_p(at) : ldq_le_p(at)) :
                       size == 4 ? (be ? ldl_be_p(at) : ldl_le_p(at)) :
                       size == 2 ? (be ? lduw_be_p(at) : lduw_le_p(at)) :
                       ldub_p(at);
        uint64_t operand = rs == 31 ? 0 : env->xregs[rs];
        unsigned opc = word & 0x8000 ? 8 : (word >> 12) & 7;
        switch (opc) {
        case 0:
            value = old + operand;
            break;
        case 1:
            value = old & ~operand;
            break;
        case 2:
            value = old ^ operand;
            break;
        case 3:
            value = old | operand;
            break;
        default:
            value = operand;                     /* SWP */
            break;
        }
        if ((word & 31) != 31) {
            env->xregs[word & 31] = old;
        }
    }
    if (cas) {
        const uint8_t *at = host + far - dest->va;
        uint64_t old = size == 8 ? (be ? ldq_be_p(at) : ldq_le_p(at)) :
                       size == 4 ? (be ? ldl_be_p(at) : ldl_le_p(at)) :
                       size == 2 ? (be ? lduw_be_p(at) : lduw_le_p(at)) :
                       ldub_p(at);
        uint64_t expected = rs == 31 ? 0 : env->xregs[rs];
        if (size < 8) {
            expected &= (UINT64_C(1) << (size * 8)) - 1;
        }
        if (rs != 31) {
            env->xregs[rs] = old;
        }
        if (old != expected) {
            env->pc += 4;
            return true;
        }
    }
    candidate = g_memdup2(host, VSH_PAGE);
    {
        uint8_t *at = candidate + far - dest->va;
        switch (size) {
        case 8:
            be ? stq_be_p(at, value) : stq_le_p(at, value);
            break;
        case 4:
            be ? stl_be_p(at, value) : stl_le_p(at, value);
            break;
        case 2:
            be ? stw_be_p(at, value) : stw_le_p(at, value);
            break;
        default:
            stb_p(at, value);
            break;
        }
    }
    if (executable && !hvf_vsh_code_safe(candidate)) {
        return false;
    }
    table = hvf_vsh_depends(dest->pa);
    if (address_space_write(arm_addressspace(cpu, result.f.attrs),
                            result.f.phys_addr, result.f.attrs,
                            candidate + far - dest->va, size) != MEMTX_OK) {
        return false;
    }
    if (executable) {
        address_space_flush_icache_range(arm_addressspace(cpu, result.f.attrs),
                                         result.f.phys_addr, size);
    }
    if (table) {
        /*
         * The store obeyed the old guest mapping. No native guest execution
         * may use permissions derived from the replaced descriptor. Drop
         * all aliases and rewalk subsequent fetches/data accesses, including
         * self-referential table aliases, before any instruction can retire.
         */
        hvf_vsh_invalidate_all(cpu);
    }
    error_report("Virtual shadow emulated STR64 pc=0x%" PRIx64
                 " va=0x%" PRIx64 " value=0x%" PRIx64 " table=%u",
                 env->pc, far, value, table);
    env->pc += 4;
    return true;
}

static bool hvf_vsh_start(CPUState *cpu, const ARMCPRegInfo *ri, uint64_t value)
{
    CPUARMState *env = cpu_env(cpu);
    uint64_t saved = env->cp15.sctlr_el[2];
    bool ok;

    if (g_strcmp0(getenv("QEMU_HVF_VIRTUAL_SHADOW"), "1") ||
        hvf_vsh.mem || strcmp(ri->name, "SCTLR_EL2") ||
        (env->cp15.hcr_el2 & (HCR_E2H | HCR_TGE | HCR_VM | HCR_DC)) !=
        (HCR_E2H | HCR_TGE) || env->sprr_config_el[2] ||
        env->gxf_config_el[2] || (pstate_read(env) & PSTATE_PAN)) {
        return false;
    }
    if (!hvf_vsh_create(cpu)) {
        return false;
    }
    /* Use the actual architectural SCTLR write callback while walking. */
    ri->writefn(env, ri, value);
    WITH_RCU_READ_LOCK_GUARD() {
        ok = hvf_vsh_fill(cpu, env->pc + 4, MMU_INST_FETCH);
    }
    env->cp15.sctlr_el[2] = saved;
    if (!ok) {
        hvf_vsh_destroy();
        return false;
    }
    hvf_vsh.active = true;
    return true;
}

static void hvf_vsh_put(CPUState *cpu)
{
    hv_vcpu_t fd = cpu->accel->fd;
    CPUARMState *env = cpu_env(cpu);
    uint64_t pc, pstate, debug;
    bool timer_mask;
    hv_vcpu_exit_t exit = {};

    if (!hvf_vsh.active) {
        return;
    }
    hvf_vsh_select(cpu);
    if (hvf_vsh.installed == hvf_vsh.generation && !hvf_vsh.icache_pending) {
        return;
    }
    assert_hvf_ok(hv_vcpu_get_reg(fd, HV_REG_PC, &pc));
    assert_hvf_ok(hv_vcpu_get_reg(fd, HV_REG_CPSR, &pstate));
    assert_hvf_ok(hv_vcpu_get_sys_reg(fd, HV_SYS_REG_MDSCR_EL1, &debug));
    assert_hvf_ok(hv_vcpu_get_vtimer_mask(fd, &timer_mask));
    assert_hvf_ok(hv_vcpu_set_vtimer_mask(fd, true));
    assert_hvf_ok(hv_vcpu_set_sys_reg(fd, HV_SYS_REG_MDSCR_EL1, 0));
    assert_hvf_ok(hv_vcpu_set_sys_reg(fd, HV_SYS_REG_SCTLR_EL1, 0));
    assert_hvf_ok(hv_vcpu_set_reg(fd, HV_REG_CPSR, 0x3c5));
    unsigned helper_offset = hvf_vsh.icache_pending ? 0x20 : 0;
    unsigned helper_end = hvf_vsh.icache_pending ? 0x34 : 12;
    assert_hvf_ok(hv_vcpu_set_reg(fd, HV_REG_PC, VSH_BASE + helper_offset));
    for (unsigned i = 0; i < 16; i++) {
        assert_hvf_ok(hv_vcpu_run(fd));
        exit = *cpu->accel->exit;
        if (exit.reason != HV_EXIT_REASON_CANCELED) {
            break;
        }
    }
    uint64_t helper_pc;
    assert_hvf_ok(hv_vcpu_get_reg(fd, HV_REG_PC, &helper_pc));
    if (exit.reason != HV_EXIT_REASON_EXCEPTION ||
        exit.exception.syndrome != 0x5e00da00 ||
        helper_pc != VSH_BASE + helper_end) {
        error_report("Virtual shadow TLB helper failed at 0x%" PRIx64,
                     helper_pc);
        abort();
    }
    assert_hvf_ok(hv_vcpu_set_sys_reg(fd, HV_SYS_REG_TCR_EL1, hvf_vsh.tcr));
    assert_hvf_ok(hv_vcpu_set_sys_reg(fd, HV_SYS_REG_TTBR0_EL1,
                                      hvf_ctx->root[0]));
    assert_hvf_ok(hv_vcpu_set_sys_reg(fd, HV_SYS_REG_TTBR1_EL1,
                                      hvf_ctx->root[1]));
    assert_hvf_ok(hv_vcpu_set_sys_reg(fd, HV_SYS_REG_MAIR_EL1, 0xff));
    assert_hvf_ok(hv_vcpu_set_sys_reg(fd, HV_SYS_REG_VBAR_EL1,
                                      VSH_BASE + 0x800));
    assert_hvf_ok(hv_vcpu_set_sys_reg(fd, HV_SYS_REG_SCTLR_EL1,
                                      env->cp15.sctlr_el[2]));
    assert_hvf_ok(hv_vcpu_set_sys_reg(fd, HV_SYS_REG_MDSCR_EL1, debug));
    assert_hvf_ok(hv_vcpu_set_vtimer_mask(fd, timer_mask));
    assert_hvf_ok(hv_vcpu_set_reg(fd, HV_REG_CPSR, pstate));
    assert_hvf_ok(hv_vcpu_set_reg(fd, HV_REG_PC, pc));
    hvf_vsh.installed = hvf_vsh.generation;
    if (hvf_vsh.icache_pending) {
        error_report("Virtual shadow completed native IC IALLU");
        hvf_vsh.icache_pending = false;
    }
}

/*
 * Native load/store to guest device memory. No stage-2 alias can back an
 * emulated MMIO region, so the stage-1 translation fault arrives here with
 * the same ISV/SAS/SSE/SRT/SF/WnR syndrome fields a stage-2 abort would
 * carry (ARM DDI 0487, ESR_ELx.ISS for data aborts). The access is replayed
 * through the QEMU address space exactly as hvf.c does for EC_DATAABORT,
 * after the guest walk has granted it. Instructions without ISV (pairs,
 * SIMD, atomics) stop. First observed at SPTM 0xfffffff0270dd99c, a 32-bit
 * device register read.
 */
static bool hvf_vsh_mmio(CPUState *cpu, uint64_t far, uint64_t esr,
                         uint64_t elr, bool *handled)
{
    static const ARMPTWMemoryOps ops = {
        .read = hvf_vsh_read,
        .cmpxchg64 = hvf_vsh_cmpxchg,
    };
    static unsigned logged;
    CPUARMState *env = cpu_env(cpu);
    HVFPTWProbe probe = { .cpu = cpu };
    GetPhysAddrResult result = {};
    ARMMMUFaultInfo fi = {};
    bool write = esr & (1 << 6);
    MMUAccessType access = write ? MMU_DATA_STORE : MMU_DATA_LOAD;
    MemoryRegion *mr;
    hwaddr offset;
    uint64_t pa, value = 0;
    unsigned size, srt;
    MemTxResult res;

    *handled = false;
    if (!get_phys_addr_with_ops(env, far, access, 0, arm_mmu_idx(env),
                               &result, &fi, &ops, &probe)) {
        return false;
    }
    pa = (result.f.phys_addr & ~((UINT64_C(1) << result.f.lg_page_size) - 1))
         | (far & ((UINT64_C(1) << result.f.lg_page_size) - 1));
    if (result.cacheattrs.attrs == 0xff &&
        hvf_ptw_probe_ram(&probe, pa & ~(uint64_t)(VSH_PAGE - 1),
                          result.f.attrs, VSH_PAGE, false, &mr, &offset)) {
        /* Ordinary RAM: the caller installs an alias instead. */
        return false;
    }
    *handled = true;
    /*
     * A stage-1 translation fault taken at EL1 does not carry ISV (ARM DDI
     * 0487 D19.2.37: ISV is valid for stage-2 aborts only). Decode the
     * faulting instruction instead. Only single-register integer loads and
     * stores are handled: unsigned-immediate, unscaled, pre/post-indexed
     * and register-offset forms, with LDRB/LDRH/LDRSx sign/zero extension.
     * Pairs, exclusives, atomics and SIMD forms stop.
     */
    uint32_t word;
    if (cpu_memory_rw_debug(cpu, elr, &word, 4, false)) {
        error_report("Virtual shadow cannot read device access instruction "
                     "at 0x%" PRIx64, elr);
        return false;
    }
    unsigned sz = word >> 30, opc = (word >> 22) & 3, rn = (word >> 5) & 31;
    bool imm12 = (word & 0x3b000000) == 0x39000000;
    bool other = (word & 0x3b200000) == 0x38000000;   /* unscaled/indexed */
    bool regoff = (word & 0x3b200c00) == 0x38200800;
    int64_t wb = 0;
    bool writeback = false;
    uint64_t base = rn == 31 ? env->xregs[31] : env->xregs[rn];
    if (word & (1 << 26) || (!imm12 && !other && !regoff) ||
        (opc == 2 && sz == 3) || (opc == 3 && sz >= 2)) {
        error_report("Virtual shadow unsupported device access 0x%08x at 0x%"
                     PRIx64 " va=0x%" PRIx64 " pa=0x%" PRIx64,
                     word, elr, far, pa);
        return false;
    }
    if (other) {
        unsigned mode = (word >> 10) & 3;   /* 0 unscaled, 1 post, 3 pre */
        if (mode == 2) {
            error_report("Virtual shadow unsupported device access 0x%08x "
                         "at 0x%" PRIx64, word, elr);
            return false;
        }
        wb = sextract32(word, 12, 9);
        writeback = mode != 0;
    }
    if ((opc & 1) != !write) {
        error_report("Virtual shadow device access direction mismatch 0x%08x"
                     " at 0x%" PRIx64, word, elr);
        return false;
    }
    (void)base;
    size = 1 << sz;
    srt = word & 31;
    if (write) {
        value = srt == 31 ? 0 : env->xregs[srt];
        res = address_space_write(arm_addressspace(cpu, result.f.attrs), pa,
                                  result.f.attrs, &value, size);
    } else {
        res = address_space_read(arm_addressspace(cpu, result.f.attrs), pa,
                                 result.f.attrs, &value, size);
        if (opc >= 2) {
            value = sextract64(value, 0, size * 8);
            if (opc == 3) {
                value = (uint32_t)value;
            }
        }
        if (srt != 31) {
            env->xregs[srt] = value;
        }
    }
    if (writeback && res == MEMTX_OK) {
        uint64_t next = base + wb;
        if (rn == 31) {
            env->xregs[31] = next;
        } else {
            env->xregs[rn] = next;
        }
    }
    if (res != MEMTX_OK) {
        error_report("Virtual shadow device access failed at 0x%" PRIx64
                     " pa=0x%" PRIx64, elr, pa);
        return false;
    }
    if (logged++ < 64) {
        error_report("Virtual shadow device %s pc=0x%" PRIx64 " va=0x%"
                     PRIx64 " pa=0x%" PRIx64 " size=%u value=0x%" PRIx64,
                     write ? "write" : "read", elr, far, pa, size, value);
    }
    env->pc = elr + 4;
    return true;
}

/*
 * Instruction permission fault on an alias installed for data. The guest
 * walk is repeated for a fetch at the current level; if it grants execute,
 * the stage-2 mapping gains EXEC (and loses WRITE, as executable backing is
 * immutable through every alias), the code is validated for EL2, the
 * host icache is synchronised, and the leaf's UXN/PXN reflect the level.
 * The kernel reads kext text before executing it (HVF_KC_BOOT14 stopped
 * on ESR 0x8600000f at 0xfffffff02ab08220 for exactly this pattern).
 */
static bool hvf_vsh_upgrade_exec(CPUState *cpu, uint64_t va)
{
    static const ARMPTWMemoryOps ops = {
        .read = hvf_vsh_read,
        .cmpxchg64 = hvf_vsh_cmpxchg,
    };
    CPUARMState *env = cpu_env(cpu);
    HVFPTWProbe probe = { .cpu = cpu };
    GetPhysAddrResult result = {};
    ARMMMUFaultInfo fi = {};
    HVFVirtualShadowPage *p = NULL;
    MemoryRegion *mr;
    hwaddr offset;
    uint8_t *host;
    unsigned el = arm_current_el(env);

    va &= ~(uint64_t)(VSH_PAGE - 1);
    for (unsigned i = 0; i < hvf_ctx->pages; i++) {
        if (hvf_ctx->page[i].va == va) {
            p = &hvf_ctx->page[i];
        }
    }
    if (!p) {
        return false;
    }
    hvf_vsh.fault_valid = false;
    if (!get_phys_addr_with_ops(env, va, MMU_INST_FETCH, 0, arm_mmu_idx(env),
                               &result, &fi, &ops, &probe)) {
        hvf_vsh.fault = fi;
        hvf_vsh.fault_valid = true;
        return false;
    }
    if (result.f.phys_addr != p->pa || !(result.f.prot & PAGE_EXEC)) {
        return false;
    }
    host = hvf_ptw_probe_ram(&probe, p->pa, p->attrs, VSH_PAGE, false, &mr,
                             &offset);
    if (!host) {
        return false;
    }
    if (!(p->flags & HV_MEMORY_EXEC)) {
        if (el == 2 && !hvf_vsh_code_safe(host)) {
            return false;
        }
        p->flags = (p->flags & ~HV_MEMORY_WRITE) | HV_MEMORY_EXEC;
        hvf_vsh_revoke_write(p->pa);
        assert_hvf_ok(hv_vm_protect(p->ipa, VSH_PAGE, p->flags));
        address_space_flush_icache_range(arm_addressspace(cpu, p->attrs),
                                         p->pa, VSH_PAGE);
    } else if (el == 2 && !p->exec2 && !hvf_vsh_code_safe(host)) {
        return false;
    }
    if (el == 0) {
        p->user = true;
        p->exec0 = true;
    } else {
        p->exec2 = true;
    }
    uint64_t *slot = hvf_vsh_slot(va);
    assert(slot);
    stq_le_p(slot, hvf_vsh_descriptor(p) |
             (ldq_le_p(slot) & (UINT64_C(1) << 50)));
    hvf_vsh.generation++;
    if (!hvf_virtual_quiet) {
        error_report("Virtual shadow exec upgrade va=0x%" PRIx64 " el=%u "
                     "rights=%u", va, el, (unsigned)p->flags);
    }
    return true;
}

static bool hvf_vsh_exception(CPUState *cpu)
{
    CPUARMState *env = cpu_env(cpu);
    hv_vcpu_t fd = cpu->accel->fd;
    uint64_t esr, elr, far, spsr;
    bool ok = false;

    cpu_synchronize_state(cpu);
    if (!hvf_vsh.active || env->pc < VSH_BASE + 0x800 ||
        env->pc >= VSH_BASE + 0x1000 || (env->pc & 127)) {
        return false;
    }
    assert_hvf_ok(hv_vcpu_get_sys_reg(fd, HV_SYS_REG_ESR_EL1, &esr));
    assert_hvf_ok(hv_vcpu_get_sys_reg(fd, HV_SYS_REG_ELR_EL1, &elr));
    assert_hvf_ok(hv_vcpu_get_sys_reg(fd, HV_SYS_REG_FAR_EL1, &far));
    assert_hvf_ok(hv_vcpu_get_sys_reg(fd, HV_SYS_REG_SPSR_EL1, &spsr));
    if (!hvf_virtual_quiet) {
        error_report("Virtual shadow native exception ESR=0x%" PRIx64
                     " ELR=0x%" PRIx64 " FAR=0x%" PRIx64
                     " SPSR=0x%" PRIx64, esr, elr, far, spsr);
    }
    /* Restore the interrupted virtual state even when the experiment stops. */
    unsigned from_el = (spsr >> 2) & 3;
    if (from_el != 1 && from_el != 0) {
        return false;
    }
    env->pc = elr;
    pstate_write(env, from_el == 1 ? (spsr & ~UINT64_C(0xc)) | 8 : spsr);
    aarch64_restore_sp(env, arm_current_el(env));
    unsigned ec = syn_get_ec(esr), fsc = esr & 0x3f;
    if (from_el == 0 && ec == EC_UNCATEGORIZED) {
        /*
         * An unprivileged instruction the hardware refused. The one system
         * operation user code legitimately performs on this platform is
         * the SPRR user-bank access; try the dispatcher first and deliver
         * the undefined-instruction exception only if it declines.
         */
        uint32_t word;
        bool advance;
        if (!cpu_memory_rw_debug(cpu, elr, &word, 4, false) &&
            (word & 0xffc00000) == 0xd5000000 && ((word >> 19) & 3) &&
            hvf_virtual_instruction(cpu, word, &advance)) {
            env->pc = elr + (advance ? 4 : 0);
            return true;
        }
    }
    if (from_el == 1 && ec == EC_UNCATEGORIZED) {
        /*
         * Undefined instruction at virtual EL2. An unledgered system
         * instruction (unpatched kext) is emulated like a ledgered one;
         * otherwise the kernel's own trap opcodes (0xe7ffdeff at XNU
         * 0xfffffff02aab2e44, HVF_KC_BOOT16) must reach its handler so
         * the panic path can report itself. Same-EL delivery uses the
         * vector at VBAR_EL2 + 0x200.
         */
        uint32_t word;
        bool advance;
        if (!cpu_memory_rw_debug(cpu, elr, &word, 4, false) &&
            ((word & 0xffc00000) == 0xd5000000 || word == 0xd69f03e0) &&
            hvf_virtual_instruction(cpu, word, &advance)) {
            env->pc = elr + (advance ? 4 : 0);
            return true;
        }
        cpu->exception_index = EXCP_UDEF;
        env->exception.syndrome = esr;
        env->exception.target_el = 2;
        arm_cpu_do_interrupt(cpu);
        if (!hvf_virtual_quiet) {
            error_report("Virtual EL2 undefined instruction at 0x%" PRIx64
                         " delivered to 0x%" PRIx64, elr, env->pc);
        }
        return true;
    }
    if (from_el == 0 && (ec == EC_AA64_SVC || ec == EC_UNCATEGORIZED)) {
        /*
         * Virtual EL0 (GL0 for TXM) exception into the guest's EL2 handler.
         * ELR is the architectural return address (after an SVC, at an
         * undefined instruction). arm_cpu_do_interrupt selects VBAR_GL2 and
         * the guarded ESR/ELR/SPSR banks while CURRENTG is set, matching
         * the TCG entries "Taking exception 2 [SVC] ... from EL0 to EL2"
         * recorded for TXM's calls at 0xfffffff01708425c/17065bc0.
         */
        cpu->exception_index = ec == EC_AA64_SVC ? EXCP_SWI : EXCP_UDEF;
        env->exception.syndrome = esr;
        env->exception.target_el = 2;
        arm_cpu_do_interrupt(cpu);
        if (!hvf_virtual_quiet) {
            error_report("Virtual EL0 exception EC=0x%x delivered from 0x%"
                         PRIx64 " to 0x%" PRIx64 " currentg=%" PRIu64,
                         ec, elr, env->pc, env->currentg);
        }
        return true;
    }
    /* EC 0x20/0x24 are the lower-EL (EL0) forms of 0x21/0x25. */
    bool insn_abort = ec == EC_INSNABORT || ec == EC_INSNABORT + 1;
    bool data_abort = ec == EC_DATAABORT || ec == EC_DATAABORT + 1;
    if ((insn_abort || data_abort) && fsc >= 4 && fsc <= 7) {
        MMUAccessType access = insn_abort ? MMU_INST_FETCH :
                               (esr & (1 << 6)) ? MMU_DATA_STORE :
                                                 MMU_DATA_LOAD;
        bool handled = false;
        WITH_RCU_READ_LOCK_GUARD() {
            if (data_abort) {
                ok = hvf_vsh_mmio(cpu, far, esr, elr, &handled);
            }
            if (!handled) {
                ok = hvf_vsh_fill(cpu, far, access);
            }
        }
        if (!ok && hvf_vsh.fault_valid && !hvf_virtual_stop_on_fault &&
            (hvf_vsh.fault.type == ARMFault_Translation ||
             hvf_vsh.fault.type == ARMFault_Permission ||
             hvf_vsh.fault.type == ARMFault_AccessFlag)) {
            /*
             * The guest's own tables refuse this access: deliver the abort
             * the hardware would, with the long-format FSC, into the
             * virtual EL2 vectors (same-EL offset 0x200 from EL2, lower-EL
             * offset 0x400 from EL0). FAR comes from exception.vaddress in
             * arm_cpu_do_interrupt. First needed by the kernel's
             * demand-fault paths (1,251 data aborts in 6 s of HVF_KC_EXEC1).
             */
            ARMMMUFaultInfo *f = &hvf_vsh.fault;
            unsigned fsc = arm_fi_to_lfsc(f);
            bool same_el = from_el == 1;
            cpu->exception_index = insn_abort ? EXCP_PREFETCH_ABORT :
                                                EXCP_DATA_ABORT;
            env->exception.vaddress = far;
            env->exception.syndrome = insn_abort ?
                syn_insn_abort(same_el, f->ea, f->s1ptw, fsc) :
                syn_data_abort_no_iss(same_el, 0, f->ea, 0, f->s1ptw,
                                      access == MMU_DATA_STORE, fsc);
            env->exception.target_el = 2;
            arm_cpu_do_interrupt(cpu);
            if (!hvf_virtual_quiet) {
                error_report("Virtual guest abort EC=0x%x FSC=0x%x va=0x%"
                             PRIx64 " from EL%u pc=0x%" PRIx64 " to 0x%"
                             PRIx64, syn_get_ec(env->exception.syndrome),
                             fsc, far, from_el == 1 ? 2 : 0, elr, env->pc);
            }
            hvf_vsh.fault_valid = false;
            return true;
        }
    } else if (data_abort && (esr & (1 << 6)) &&
               fsc >= 13 && fsc <= 15) {
        WITH_RCU_READ_LOCK_GUARD() {
            /* Emulated table/code stores first; grant is the fallback. */
            ok = hvf_vsh_guarded_store(cpu, far) ||
                 hvf_vsh_grant_write(cpu, far);
        }
        if (!ok && hvf_vsh.fault_valid && !hvf_virtual_stop_on_fault &&
            hvf_vsh.fault.type == ARMFault_Permission) {
            ARMMMUFaultInfo *f = &hvf_vsh.fault;
            cpu->exception_index = EXCP_DATA_ABORT;
            env->exception.vaddress = far;
            env->exception.syndrome =
                syn_data_abort_no_iss(from_el == 1, 0, f->ea, 0, f->s1ptw, 1,
                                      arm_fi_to_lfsc(f));
            env->exception.target_el = 2;
            arm_cpu_do_interrupt(cpu);
            hvf_vsh.fault_valid = false;
            ok = true;
        }
        if (!ok) {
            error_report("Virtual shadow write not granted at 0x%" PRIx64
                         " pc=0x%" PRIx64 " el=%u", far, elr, from_el ? 2 : 0);
        }
    } else if (insn_abort && fsc >= 13 && fsc <= 15) {
        WITH_RCU_READ_LOCK_GUARD() {
            ok = hvf_vsh_upgrade_exec(cpu, far);
        }
        if (!ok && hvf_vsh.fault_valid && !hvf_virtual_stop_on_fault &&
            hvf_vsh.fault.type == ARMFault_Permission) {
            /* The guest really forbids execution here: its own abort. */
            ARMMMUFaultInfo *f = &hvf_vsh.fault;
            cpu->exception_index = EXCP_PREFETCH_ABORT;
            env->exception.vaddress = far;
            env->exception.syndrome = syn_insn_abort(from_el == 1, f->ea,
                                                     f->s1ptw,
                                                     arm_fi_to_lfsc(f));
            env->exception.target_el = 2;
            arm_cpu_do_interrupt(cpu);
            hvf_vsh.fault_valid = false;
            ok = true;
        }
        if (!ok) {
            error_report("Virtual shadow execute permission at va=0x%" PRIx64
                         " el=%u could not be granted", far, from_el ? 2 : 0);
        }
    }
    return ok;
}
