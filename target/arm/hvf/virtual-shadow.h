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
#define VSH_TABLES 128
#define VSH_PAGES 2048

typedef struct HVFVirtualShadowPage {
    uint64_t va, pa, ipa;
    hv_memory_flags_t flags;
    MemTxAttrs attrs;
    /* Stage-1 descriptor rights granted so far: EL0 access, exec per EL. */
    bool user, exec0, exec2;
} HVFVirtualShadowPage;

/*
 * Experiment knobs, read once in hvf_virtual_init(). QUIET drops the
 * per-operation diagnostics from the hot paths (they are stderr writes on
 * every trap). KEEP_ALIASES retains native aliases across GENTER/GEXIT;
 * that is NOT permission-correct across the GL/EL permission banks and is
 * only for measuring the cost ceiling of a proper alias-reuse design.
 * See docs/re/hvf-fastpath-ceiling.md.
 */
static bool hvf_virtual_quiet, hvf_virtual_keep_aliases, hvf_virtual_fastread;

static struct {
    bool active, icache_pending;
    uint8_t *mem;
    unsigned tables, pages, dependencies;
    unsigned generation, installed;
    uint64_t root[2];
    uint64_t tcr;
    unsigned root_bits[2];
    uint64_t dependency[VSH_PAGES];
    HVFVirtualShadowPage page[VSH_PAGES];
} hvf_vsh;

static bool hvf_vsh_depends(uint64_t pa)
{
    for (unsigned i = 0; i < hvf_vsh.dependencies; i++) {
        if (hvf_vsh.dependency[i] == pa) {
            return true;
        }
    }
    return false;
}

static void hvf_vsh_revoke_write(uint64_t pa)
{
    for (unsigned i = 0; i < hvf_vsh.pages; i++) {
        HVFVirtualShadowPage *p = &hvf_vsh.page[i];
        if (p->pa == pa && (p->flags & HV_MEMORY_WRITE)) {
            p->flags &= ~HV_MEMORY_WRITE;
            assert_hvf_ok(hv_vm_protect(p->ipa, VSH_PAGE, p->flags));
        }
    }
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
    if (hvf_vsh.tables == VSH_TABLES) {
        return 0;
    }
    return VSH_BASE + ++hvf_vsh.tables * VSH_PAGE;
}

static uint64_t *hvf_vsh_slot(uint64_t va)
{
    unsigned half = (va >> 55) & 1;
    uint64_t table = hvf_vsh.root[half];
    const unsigned shifts[] = { 36, 25, 14 };

    for (unsigned i = 0; i < ARRAY_SIZE(shifts); i++) {
        unsigned mask = i ? 0x7ff : (1 << hvf_vsh.root_bits[half]) - 1;
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
    for (unsigned i = 0; i < hvf_vsh.pages; i++) {
        assert_hvf_ok(hv_vm_unmap(hvf_vsh.page[i].ipa, VSH_PAGE));
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

    hvf_vsh.root_bits[0] = 64 - (tcr & 63) - 36;
    hvf_vsh.root_bits[1] = 64 - ((tcr >> 16) & 63) - 36;
    /*
     * Match VA widths and TBI/TBID for native pointer authentication. Other
     * translation controls apply in the software walker, while the private
     * native tables use AF=1, 40-bit IPAs and no guest ASIDs or table writes.
     */
    uint64_t mask = 63 | (UINT64_C(63) << 16) |
                    (UINT64_C(3) << 37) | (UINT64_C(3) << 51);
    hvf_vsh.tcr = (UINT64_C(0x17519b519) & ~mask) | (tcr & mask);
    hvf_vsh.root[0] = hvf_vsh_table();
    hvf_vsh.root[1] = hvf_vsh_table();
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
                    (i ? VSH_PAGES : VSH_TABLES + 1) * VSH_PAGE);
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
    for (unsigned i = 0; i < hvf_vsh.pages; i++) {
        HVFVirtualShadowPage *p = &hvf_vsh.page[i];
        if (p->flags & HV_MEMORY_EXEC) {
            address_space_flush_icache_range(arm_addressspace(cpu, p->attrs),
                                             p->pa, VSH_PAGE);
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
                     hvf_vsh.pages, cpu_env(cpu)->pc);
    }
    for (unsigned i = 0; i < hvf_vsh.pages; i++) {
        assert_hvf_ok(hv_vm_unmap(hvf_vsh.page[i].ipa, VSH_PAGE));
    }
    memset(hvf_vsh.mem + VSH_PAGE, 0, VSH_TABLES * VSH_PAGE);
    hvf_vsh.pages = hvf_vsh.dependencies = hvf_vsh.tables = 0;
    hvf_vsh_roots(cpu_env(cpu)->cp15.tcr_el[2]);
    hvf_vsh.generation++;
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
    if (va == VSH_BASE || hvf_vsh.pages == VSH_PAGES) {
        return false;
    }
    unsigned el = arm_current_el(env);
    HVFVirtualShadowPage *existing = NULL;
    for (unsigned i = 0; i < hvf_vsh.pages; i++) {
        if (hvf_vsh.page[i].va == va) {
            existing = &hvf_vsh.page[i];
        }
    }
    if (!get_phys_addr_with_ops(env, va, access, 0, arm_mmu_idx(env),
                               &result, &fi, &ops, &probe)) {
        error_report("Virtual shadow guest walk denied va=0x%" PRIx64
                     " el=%u access=%u FSC=0x%x", va, el, access,
                     arm_fi_to_lfsc(&fi));
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
    for (unsigned i = 0; i < hvf_vsh.pages; i++) {
        if (hvf_vsh.page[i].pa == pa &&
            (hvf_vsh.page[i].flags & HV_MEMORY_EXEC)) {
            flags &= ~HV_MEMORY_WRITE;
        }
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
    if (!hvf_vsh.pages &&
        g_strcmp0(getenv("QEMU_HVF_VIRTUAL_SHADOW_DENY_EXEC"), "1") == 0) {
        /* Diskless boot negative control: revoke, never grant, a right. */
        flags &= ~HV_MEMORY_EXEC;
    }
    slot = hvf_vsh_slot(va);
    if (!slot) {
        return false;
    }
    ipa = VSH_ALIAS + hvf_vsh.pages * VSH_PAGE;
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
    hvf_vsh.page[hvf_vsh.pages++] = page;
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
    for (unsigned i = 0; i < hvf_vsh.pages; i++) {
        if (hvf_vsh.page[i].va == base) {
            page = &hvf_vsh.page[i];
            break;
        }
    }
    if (!page) {
        if (!hvf_vsh_fill(cpu, address, MMU_DATA_STORE)) {
            return false;
        }
        page = &hvf_vsh.page[hvf_vsh.pages - 1];
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

    if (far & 7) {
        return false;
    }
    for (unsigned i = 0; i < hvf_vsh.pages; i++) {
        HVFVirtualShadowPage *p = &hvf_vsh.page[i];
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
    for (unsigned i = 0; i < hvf_vsh.pages; i++) {
        executable |= hvf_vsh.page[i].pa == dest->pa &&
                      (hvf_vsh.page[i].flags & HV_MEMORY_EXEC);
    }
    if (!executable && !hvf_vsh_depends(dest->pa)) {
        return false;
    }
    host = hvf_ptw_probe_ram(&probe, source->pa, source->attrs, VSH_PAGE,
                             false, &mr, &offset);
    if (!host) {
        return false;
    }
    word = ldl_le_p(host + env->pc - source->va);
    /* STR Xt,[Xn|SP,#imm12*8], without writeback or exclusive semantics. */
    if ((word & 0xffc00000) != 0xf9000000) {
        return false;
    }
    address = env->xregs[(word >> 5) & 31] + (((word >> 10) & 0xfff) * 8);
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
                                 result.f.phys_addr, 8);
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
    value = (word & 31) == 31 ? 0 : env->xregs[word & 31];
    candidate = g_memdup2(host, VSH_PAGE);
    if (env->cp15.sctlr_el[2] & SCTLR_EE) {
        stq_be_p(candidate + far - dest->va, value);
    } else {
        stq_le_p(candidate + far - dest->va, value);
    }
    if (executable && !hvf_vsh_code_safe(candidate)) {
        return false;
    }
    table = hvf_vsh_depends(dest->pa);
    if (address_space_write(arm_addressspace(cpu, result.f.attrs),
                            result.f.phys_addr, result.f.attrs,
                            candidate + far - dest->va, 8) != MEMTX_OK) {
        return false;
    }
    if (executable) {
        address_space_flush_icache_range(arm_addressspace(cpu, result.f.attrs),
                                         result.f.phys_addr, 8);
    }
    if (table) {
        /*
         * The store obeyed the old guest mapping. No native guest execution
         * may use permissions derived from the replaced descriptor. Drop
         * all aliases and rewalk subsequent fetches/data accesses, including
         * self-referential table aliases, before any instruction can retire.
         */
        hvf_vsh_invalidate(cpu);
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

    if (!hvf_vsh.active || (hvf_vsh.installed == hvf_vsh.generation &&
                            !hvf_vsh.icache_pending)) {
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
                                      hvf_vsh.root[0]));
    assert_hvf_ok(hv_vcpu_set_sys_reg(fd, HV_SYS_REG_TTBR1_EL1,
                                      hvf_vsh.root[1]));
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
        hvf_vsh_invalidate(cpu);
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
    } else if (data_abort && (esr & (1 << 6)) &&
               fsc >= 13 && fsc <= 15) {
        WITH_RCU_READ_LOCK_GUARD() {
            ok = hvf_vsh_guarded_store(cpu, far);
        }
    }
    return ok;
}
