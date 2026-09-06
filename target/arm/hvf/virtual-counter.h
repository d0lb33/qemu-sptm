/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Initial virtual-platform counter contract. Both counter domains have a
 * common epoch and 24 MHz rate while offsets are zero and timers disabled.
 * Redirection is then observationally equivalent for counter reads, without
 * assuming how Apple's independently programmable timer banks redirect.
 * No native host uptime leaks into a counter that should stop with the VM.
 */
static uint32_t hvf_virtual_counter_key(uint32_t key, bool read)
{
    /*
     * helper.c:gen_timer_ecv_cp_reginfo gives SS reads the same accessfn and
     * readfn as ordinary reads. A synchronous host exit also orders the read.
     * The tested HVF feature profile omits ECV despite accepting CNTVCTSS.
     * Supply these two read aliases without advertising the rest of ECV or
     * making their architecturally undefined write encodings writable.
     */
    if (read && key == ENCODE_AA64_CP_REG(3, 3, 14, 0, 6)) {
        return ENCODE_AA64_CP_REG(3, 3, 14, 0, 2);
    }
    if (read && key == ENCODE_AA64_CP_REG(3, 3, 14, 0, 5)) {
        return ENCODE_AA64_CP_REG(3, 3, 14, 0, 1);
    }
    return key;
}

static bool hvf_virtual_counter_common(CPUState *cpu)
{
    ARMCPU *armcpu = ARM_CPU(cpu);
    CPUARMState *env = &armcpu->env;
    const ARMCPRegInfo *offset = get_arm_cp_reginfo(armcpu->cp_regs,
                                   ENCODE_AA64_CP_REG(3, 1, 15, 9, 4));

    /*
     * Enabled timers no longer disqualify reads: the value is the same
     * 24 MHz zero-offset clock whether or not a comparator is armed. Timer
     * interrupt delivery is a separate, still unimplemented, path.
     */
    if (armcpu->gt_cntfrq_hz != 24000000 ||
        env->cp15.cntvoff_el2 || env->cp15.cntpoff_el2 || !offset ||
        !offset->readfn || offset->readfn(env, offset)) {
        return false;
    }
    return true;
}

static bool hvf_virtual_counter_read(const ARMCPRegInfo *ri)
{
    return !strcmp(ri->name, "CNTVCT_EL0") ||
           !strcmp(ri->name, "CNTVCTSS_EL0") ||
           !strcmp(ri->name, "CNTPCT_EL0") ||
           !strcmp(ri->name, "CNTPCTSS_EL0") ||
           !strcmp(ri->name, "ACNTVCT_EL0") ||
           !strcmp(ri->name, "ACNTPCT_EL0") ||
           !strcmp(ri->name, "AGTCNTVCT_EL0") ||
           !strcmp(ri->name, "AGTCNTPCT_EL0");
}

static uint64_t hvf_virtual_counter_value(CPUState *cpu)
{
    /* Preserve fractional ticks; integer nanoseconds-per-tick loses 1.6%. */
    return muldiv64(qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
                    ARM_CPU(cpu)->gt_cntfrq_hz, NANOSECONDS_PER_SECOND);
}
