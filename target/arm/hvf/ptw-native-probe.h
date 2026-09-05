/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Bounded native read through a shadow leaf produced from the ARM walker.
 * Test-only, single stopped MMU-off vCPU. No persistent shadow cache yet.
 * The source tables remain unmodified; stage 2 retains the walker permissions.
 */
static bool hvf_ptw_native_read(HVFPTWProbe *probe, uint64_t va,
                                GetPhysAddrResult *result, bool deny_read,
                                uint64_t *value)
{
    const uint64_t base = UINT64_C(0xe00000000);
    const uint64_t alias = base + 0x40000000;
    const size_t page = 0x4000, size = 8 * page;
    hv_vcpu_t fd = probe->cpu->accel->fd;
    static const hv_sys_reg_t sysregs[] = {
        HV_SYS_REG_SCTLR_EL1, HV_SYS_REG_TCR_EL1, HV_SYS_REG_TTBR0_EL1,
        HV_SYS_REG_TTBR1_EL1, HV_SYS_REG_MAIR_EL1, HV_SYS_REG_VBAR_EL1,
        HV_SYS_REG_MDSCR_EL1,
    };
    static const hv_reg_t regs[] = {
        HV_REG_PC, HV_REG_CPSR, HV_REG_X0, HV_REG_X6, HV_REG_X16,
    };
    uint64_t saved_sys[ARRAY_SIZE(sysregs)], saved[ARRAY_SIZE(regs)];
    uint64_t top = va >> 39, pa = result->f.phys_addr & ~(page - 1);
    uint64_t offset = va & (page - 1), descriptor;
    hv_memory_flags_t flags = 0;
    uint8_t *mem = NULL;
    MemoryRegion *mr;
    MemoryRegionSection overlap;
    bool readonly;
    hwaddr xlat;
    void *host;
    bool mapped = false, tables_mapped = false;
    bool aliased = false, state_saved = false;
    bool timer_mask = false, ok = false;
    hv_return_t err = HV_SUCCESS;
    hv_vcpu_exit_t exit = {};
    uint64_t pc = 0;

    /* Reject unsupported extents/attributes, never widen a smaller mapping. */
    if ((top != 0 && top != 0x1ffffff) || offset > page - 8 || (va & 7) ||
        (result->f.phys_addr & (page - 1)) != offset ||
        result->f.lg_page_size < 14 || result->cacheattrs.attrs != 0xff ||
        result->cacheattrs.is_s2_format || !(result->f.prot & PAGE_READ)) {
        return false;
    }
    host = hvf_ptw_probe_ram(probe, pa, result->f.attrs, page, false,
                             &mr, &xlat);
    if (!host || ((uintptr_t)host & (page - 1))) {
        return false;
    }
    overlap = memory_region_find(arm_addressspace(probe->cpu,
                                                   result->f.attrs)->root,
                                 pa, page);
    if (!overlap.mr) {
        return false;
    }
    readonly = overlap.readonly;
    memory_region_unref(overlap.mr);
    for (unsigned i = 0; i < 2; i++) {
        overlap = memory_region_find(get_system_memory(), i ? alias : base,
                                     i ? page : size);
        if (overlap.mr) {
            memory_region_unref(overlap.mr);
            return false;
        }
    }
    if (posix_memalign((void **)&mem, page, size)) {
        return false;
    }
    memset(mem, 0, size);
    /* Invalidate the previous private stage-1 context before enabling it. */
    stl_le_p(mem + 0, 0xd508871f);  /* TLBI VMALLE1 */
    stl_le_p(mem + 4, 0xd5033f9f);  /* DSB SY */
    stl_le_p(mem + 8, 0xd5033fdf);  /* ISB */
    stl_le_p(mem + 12, 0xd5181006); /* MSR SCTLR_EL1, X6 */
    stl_le_p(mem + 16, 0xd5033fdf); /* ISB */
    stl_le_p(mem + 20, 0xf9400010); /* LDR X16, [X0] */
    stl_le_p(mem + 24, 0xd4000003 | (0xd3fe << 5));
    for (unsigned i = 0; i < 16; i++) {
        stl_le_p(mem + 0x800 + i * 128, 0xd4000003 | (0xd3ff << 5));
    }
    uint64_t *l1low = (uint64_t *)(mem + page);
    uint64_t *l2low = (uint64_t *)(mem + 2 * page);
    uint64_t *codeleaf = (uint64_t *)(mem + 3 * page);
    uint64_t *lowleaf = (uint64_t *)(mem + 4 * page);
    uint64_t *l1high = (uint64_t *)(mem + 5 * page);
    uint64_t *l2high = (uint64_t *)(mem + 6 * page);
    uint64_t *highleaf = (uint64_t *)(mem + 7 * page);

    /* The helper and tested address must use different low L2 entries. */
    if (!top && ((va >> 25) & 0x7ff) == ((base >> 25) & 0x7ff)) {
        goto cleanup;
    }
    stq_le_p(&l1low[(base >> 36) & 7], base + 2 * page + 3);
    stq_le_p(&l2low[(base >> 25) & 0x7ff], base + 3 * page + 3);
    stq_le_p(&codeleaf[(base >> 14) & 0x7ff], base | 0x783);
    descriptor = alias | 0x703;
    if (!(result->f.prot & PAGE_WRITE)) {
        descriptor |= 1 << 7;
    }
    if (!(result->f.prot & PAGE_EXEC)) {
        descriptor |= UINT64_C(3) << 53;
    }
    if (top) {
        stq_le_p(&l1high[(va >> 36) & 7], base + 6 * page + 3);
        stq_le_p(&l2high[(va >> 25) & 0x7ff], base + 7 * page + 3);
        stq_le_p(&highleaf[(va >> 14) & 0x7ff], descriptor);
    } else {
        stq_le_p(&l1low[(va >> 36) & 7], base + 2 * page + 3);
        stq_le_p(&l2low[(va >> 25) & 0x7ff], base + 4 * page + 3);
        stq_le_p(&lowleaf[(va >> 14) & 0x7ff], descriptor);
    }
    if (result->f.prot & PAGE_READ) {
        flags |= HV_MEMORY_READ;
    }
    if (result->f.prot & PAGE_WRITE) {
        flags |= HV_MEMORY_WRITE;
    }
    if (result->f.prot & PAGE_EXEC) {
        flags |= HV_MEMORY_EXEC;
    }
    if (readonly || memory_region_is_rom(mr)) {
        flags &= ~HV_MEMORY_WRITE;
    }
    if (deny_read) {
        /* Negative control for the diskless probe only. */
        flags &= ~HV_MEMORY_READ;
    }
#define PTW_HV(call) do { err = (call); if (err != HV_SUCCESS) { \
    goto cleanup; } } while (0)
    PTW_HV(hv_vm_map(mem, base, page, HV_MEMORY_READ | HV_MEMORY_EXEC));
    mapped = true;
    PTW_HV(hv_vm_map(mem + page, base + page, size - page, HV_MEMORY_READ));
    tables_mapped = true;
    PTW_HV(hv_vm_map(host, alias, page, flags));
    aliased = true;
    for (unsigned i = 0; i < ARRAY_SIZE(sysregs); i++) {
        PTW_HV(hv_vcpu_get_sys_reg(fd, sysregs[i], &saved_sys[i]));
    }
    for (unsigned i = 0; i < ARRAY_SIZE(regs); i++) {
        PTW_HV(hv_vcpu_get_reg(fd, regs[i], &saved[i]));
    }
    PTW_HV(hv_vcpu_get_vtimer_mask(fd, &timer_mask));
    state_saved = true;
    PTW_HV(hv_vcpu_set_vtimer_mask(fd, true));
    PTW_HV(hv_vcpu_set_sys_reg(fd, HV_SYS_REG_MDSCR_EL1, 0));
    PTW_HV(hv_vcpu_set_sys_reg(fd, HV_SYS_REG_TCR_EL1,
                              UINT64_C(0x17519b519)));
    PTW_HV(hv_vcpu_set_sys_reg(fd, HV_SYS_REG_TTBR0_EL1, base + page));
    PTW_HV(hv_vcpu_set_sys_reg(fd, HV_SYS_REG_TTBR1_EL1, base + 5 * page));
    PTW_HV(hv_vcpu_set_sys_reg(fd, HV_SYS_REG_MAIR_EL1, 0xff));
    PTW_HV(hv_vcpu_set_sys_reg(fd, HV_SYS_REG_VBAR_EL1, base + 0x800));
    PTW_HV(hv_vcpu_set_reg(fd, HV_REG_PC, base));
    PTW_HV(hv_vcpu_set_reg(fd, HV_REG_CPSR, 0x3c5));
    PTW_HV(hv_vcpu_set_reg(fd, HV_REG_X0, va));
    PTW_HV(hv_vcpu_set_reg(fd, HV_REG_X6, 0x1005));
    for (unsigned i = 0; i < 16; i++) {
        PTW_HV(hv_vcpu_run(fd));
        exit = *probe->cpu->accel->exit;
        if (exit.reason != HV_EXIT_REASON_CANCELED) {
            break;
        }
    }
    PTW_HV(hv_vcpu_get_reg(fd, HV_REG_PC, &pc));
    if (exit.reason == HV_EXIT_REASON_EXCEPTION &&
        exit.exception.syndrome == 0x5e00d3fe && pc == base + 24) {
        PTW_HV(hv_vcpu_get_reg(fd, HV_REG_X16, value));
        ok = true;
    }
cleanup:
    if (state_saved) {
        /* MMU off before replacing or unmapping any private table. */
        assert_hvf_ok(hv_vcpu_set_sys_reg(fd, sysregs[0], saved_sys[0]));
        for (unsigned i = 1; i < ARRAY_SIZE(sysregs); i++) {
            assert_hvf_ok(hv_vcpu_set_sys_reg(fd, sysregs[i], saved_sys[i]));
        }
        for (unsigned i = 0; i < ARRAY_SIZE(regs); i++) {
            assert_hvf_ok(hv_vcpu_set_reg(fd, regs[i], saved[i]));
        }
        assert_hvf_ok(hv_vcpu_set_vtimer_mask(fd, timer_mask));
    }
    if (aliased) {
        assert_hvf_ok(hv_vm_unmap(alias, page));
    }
    if (tables_mapped) {
        assert_hvf_ok(hv_vm_unmap(base + page, size - page));
    }
    if (mapped) {
        assert_hvf_ok(hv_vm_unmap(base, page));
    }
    free(mem);
    if (!ok) {
        error_report("HVF native PTW read failed: API=0x%x reason=%u "
                     "syndrome=0x%" PRIx64 " pc=0x%" PRIx64
                     " ipa=0x%" PRIx64 " va=0x%" PRIx64,
                     err, exit.reason, exit.exception.syndrome, pc,
                     exit.exception.physical_address,
                     exit.exception.virtual_address);
    }
#undef PTW_HV
    return ok;
}
