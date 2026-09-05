/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Disabled Apple PMU bootstrap. Linux drivers/perf/apple_m1_cpu_pmu.c
 * separates PMCR1 event filters from PMCR0 counter enables. SPTM programs
 * guarded filters at 0xfffffff0270b4154/4158 while PMCR0 remains zero.
 * GL field positions: M5 register dump, PMCR1_GL2 GL0EN/GL2EN0..9.
 * No host PMU registers or host performance counts are exposed.
 */
static bool hvf_virtual_pmu_disabled(CPUState *cpu)
{
    const ARMCPRegInfo *control = get_arm_cp_reginfo(ARM_CPU(cpu)->cp_regs,
                                      ENCODE_AA64_CP_REG(3, 1, 15, 0, 0));

    return control && control->readfn &&
           control->readfn(cpu_env(cpu), control) == 0;
}

static bool hvf_virtual_pmu_counter(const ARMCPRegInfo *ri)
{
    return !strcmp(ri->name, "PMC0") || !strcmp(ri->name, "PMC1");
}

static int hvf_virtual_pmu_write(CPUState *cpu, const ARMCPRegInfo *ri,
                                uint64_t value)
{
    if (strcmp(ri->name, "PMCR1_GL1") && strcmp(ri->name, "PMCR1_GL2")) {
        return 0;
    }
    if (!hvf_vsh.active || arm_current_el(cpu_env(cpu)) != 2 ||
        !arm_apple_is_gl(cpu_env(cpu)) || !ri->writefn ||
        !hvf_virtual_pmu_disabled(cpu) ||
        (value & ~UINT64_C(0x3030000ffff00))) {
        error_report("Virtual PMU requires disabled counters and guarded "
                     "filter fields: %s at 0x%" PRIx64,
                     ri->name, cpu_env(cpu)->pc);
        return -1;
    }
    return 1;
}
