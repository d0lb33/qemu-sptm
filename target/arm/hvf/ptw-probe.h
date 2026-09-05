/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Opt-in diskless walker probe, driven by tools/perf/native_ptw_qemu.py.
 * This does not install shadow mappings or alter the iOS boot path.
 * Its single vCPU executes an MMU-off fixture while the software walker
 * checks separately supplied architectural state. No MMIO tables are allowed.
 */
typedef struct HVFPTWProbe {
    CPUState *cpu;
    unsigned reads;
    unsigned exchanges;
    hwaddr deny_read;
    bool deny_exchange;
} HVFPTWProbe;

static void *hvf_ptw_probe_ram(HVFPTWProbe *p, hwaddr pa, MemTxAttrs attrs,
                              unsigned size, bool write, MemoryRegion **mr,
                              hwaddr *offset)
{
    hwaddr len = size;

    *mr = address_space_translate(arm_addressspace(p->cpu, attrs), pa,
                                   offset, &len, write, attrs);
    if (len < size || (pa & (size - 1)) ||
        !memory_region_is_ram(*mr) ||
        (write && memory_region_is_rom(*mr))) {
        return NULL;
    }
    return memory_region_get_ram_ptr(*mr) + *offset;
}

static MemTxResult hvf_ptw_probe_read(void *opaque, hwaddr pa,
                                     MemTxAttrs attrs, unsigned size,
                                     bool be, uint64_t *value)
{
    HVFPTWProbe *p = opaque;
    MemoryRegion *mr;
    hwaddr offset;
    void *host = hvf_ptw_probe_ram(p, pa, attrs, size, false, &mr, &offset);

    p->reads++;
    if (!host || pa == p->deny_read) {
        return MEMTX_ERROR;
    }
    if (size == 8) {
        uint64_t v = qatomic_read((uint64_t *)host);
        *value = be ? be64_to_cpu(v) : le64_to_cpu(v);
    } else {
        uint32_t v = qatomic_read((uint32_t *)host);
        *value = be ? be32_to_cpu(v) : le32_to_cpu(v);
    }
    return MEMTX_OK;
}

static MemTxResult hvf_ptw_probe_cmpxchg(void *opaque, hwaddr pa,
                                        MemTxAttrs attrs, bool be,
                                        uint64_t old, uint64_t new,
                                        uint64_t *observed)
{
    HVFPTWProbe *p = opaque;
    MemoryRegion *mr;
    hwaddr offset;
    uint64_t *host = hvf_ptw_probe_ram(p, pa, attrs, 8, true, &mr, &offset);
    uint64_t v;

    p->exchanges++;
    if (!host || p->deny_exchange) {
        return MEMTX_ERROR;
    }
    old = be ? cpu_to_be64(old) : cpu_to_le64(old);
    new = be ? cpu_to_be64(new) : cpu_to_le64(new);
    v = qatomic_cmpxchg(host, old, new);
    *observed = be ? be64_to_cpu(v) : le64_to_cpu(v);
    if (v == old) {
        memory_region_set_dirty(mr, offset, 8);
    }
    return MEMTX_OK;
}

#include "ptw-native-probe.h"

static bool hvf_ptw_probe(CPUState *cpu)
{
    ARMCPU *armcpu = ARM_CPU(cpu);
    CPUARMState *env = &armcpu->env;
    static const ARMPTWMemoryOps ops = {
        .read = hvf_ptw_probe_read,
        .cmpxchg64 = hvf_ptw_probe_cmpxchg,
    };
    HVFPTWProbe probe = { .cpu = cpu };
    GetPhysAddrResult result = {};
    ARMMMUFaultInfo fi = {};
    typeof(env->cp15) saved;
    uint32_t pstate;
    uint64_t mmfr1;
    ARMMMUIdx idx;
    bool ok;
    bool native_read, deny_native_read;
    uint64_t va, native_value = 0;

    cpu_synchronize_state(cpu);
    if (hvf_nested_virt_enabled() || CPU_NEXT(first_cpu) ||
        (env->cp15.sctlr_el[1] & SCTLR_M) ||
        arm_current_el(env) != 1 || env->xregs[1] > 2 || env->xregs[2] > 1 ||
        env->xregs[8] > 2 || env->xregs[9] > 2) {
        error_report("HVF PTW probe requires one MMU-off EL1 vCPU");
        return false;
    }
    saved = env->cp15;
    va = env->xregs[0];
    native_read = env->xregs[9] != 0;
    deny_native_read = env->xregs[9] == 2;
    if (native_read && (env->cp15.hcr_el2 & (HCR_VM | HCR_DC))) {
        /* A combined walk's TCG extent can exceed its mapping coverage. */
        error_report("HVF native PTW probe requires stage-1-only translation");
        return false;
    }
    pstate = pstate_read(env);
    mmfr1 = armcpu->isar.idregs[ID_AA64MMFR1_EL1_IDX];
    /*
     * Exercise software HA/HD independently of the native feature set.
     * Never write this feature override to HVF or expose it to the fixture.
     * A zero request keeps the host feature set as a negative control.
     */
    if (env->xregs[8]) {
        armcpu->isar.idregs[ID_AA64MMFR1_EL1_IDX] =
            deposit64(mmfr1, 0, 4, env->xregs[8]);
    }
    idx = env->xregs[2] ? ARMMMUIdx_E10_1 : ARMMMUIdx_E10_0;
    env->cp15.tcr_el[1] = env->xregs[3];
    env->cp15.ttbr0_el[1] = env->xregs[4];
    env->cp15.ttbr1_el[1] = env->xregs[5];
    env->cp15.sctlr_el[1] = env->xregs[6];
    env->cp15.mair_el[1] = env->xregs[7];
    probe.deny_read = env->xregs[12];
    probe.deny_exchange = env->xregs[13];
    pstate_write(env, env->xregs[2] ? 0x3c5 : 0x3c0);
    WITH_RCU_READ_LOCK_GUARD() {
        ok = get_phys_addr_with_ops(env, env->xregs[0], env->xregs[1], 0,
                                    idx, &result, &fi, &ops, &probe);
    }
    env->cp15 = saved;
    armcpu->isar.idregs[ID_AA64MMFR1_EL1_IDX] = mmfr1;
    pstate_write(env, pstate);
    if (ok && native_read) {
        WITH_RCU_READ_LOCK_GUARD() {
            if (!hvf_ptw_native_read(&probe, va, &result, deny_native_read,
                                     &native_value)) {
                return false;
            }
        }
    }
    env->xregs[0] = ok;
    env->xregs[1] = ok ? result.f.phys_addr : 0;
    env->xregs[2] = ok ? result.f.prot : 0;
    env->xregs[3] = ok ? 0 : arm_fi_to_lfsc(&fi);
    env->xregs[4] = probe.reads;
    env->xregs[5] = probe.exchanges;
    env->xregs[6] = mmfr1;
    env->xregs[7] = native_value;
    env->xregs[8] = ok && native_read;
    return true;
}
