#!/usr/bin/env python3
import sys
from sysregs import all_regs

'''
This script automatically generates MSRs for Qemu using the defs in sysregs.py.

Registers are sorted into two storage classes: "opaque" and "CPU state".

"Opaque" regs are stored in a giant automatically generated struct called
"apple_state". This way we can add/ remove registers quickly without
recompiling everything that includes the arm.h header. The CPU state holds a
pointer to this struct. These registers have default setters/ getters that do
nothing except remember what was previously written.

"CPU state" MSRs are stored directly as fields in the CPUARMState struct (in
target/arm/cpu.h). This header touches a ton of Qemu code so changes to these
require long recompilation. We only put registers that are actually important/
touch lots of core Qemu code in here.

"Banked sysregs" are a special sub-class of CPU state regs, as they are stored
as arrays for each exception level. Therefore we need to know which element of
the array to access when we use them.
'''

SUPPORTED_GLS=[1,2]

rs_cpustate = [
    "CURRENTG",
    "SPRR_UPERM_EL0",
]

rs_banked = [
    "SPRR_CONFIG_EL",
    "SPRR_PPERM_EL",
    "GXF_CONFIG_EL",
    "GXF_ENTRY_EL",
    "GXF_PABENTRY_EL",
    "SP_GL",
    "TPIDR_GL",
    "ASPSR_GL",
    "VBAR_GL",
    "FAR_GL",
    "ESR_GL",
    "ELR_GL",
    "SPSR_GL",
    "PMCR1_GL",
    "AFSR1_GL",
]

rs_opaque = [
    "TAG_OFFSET_EL2",
    "ACC_CTRR_A_LWR_EL2",
    "ACC_CTRR_A_UPR_EL2",
    "ACC_CTRR_B_LWR_EL2",
    "ACC_CTRR_B_UPR_EL2",
    "ACC_CTRR_A_CTL_EL2",
    "ACC_CTRR_B_CTL_EL2",
    "CTRR_A_CTL_EL1",
    "CTRR_B_CTL_EL1",
    "CTRR_A_LWR_EL1",
    "CTRR_A_UPR_EL1",
    "CTRR_B_LWR_EL1",
    "CTRR_B_UPR_EL1",
    "CTRR_C_LWR_EL1",
    "CTRR_C_UPR_EL1",
    "CTRR_D_LWR_EL1",
    "CTRR_D_UPR_EL1",
    "CTRR_C_LWR_EL2",
    "CTRR_C_UPR_EL2",
    "CTRR_D_LWR_EL2",
    "CTRR_D_UPR_EL2",
    "CTRR_C_CTL_EL1",
    "CTRR_D_CTL_EL1",
    "CTRR_C_CTL_EL2",
    "CTRR_D_CTL_EL2",
    "CTXR_A_LWR_EL1",
    "CTXR_A_UPR_EL1",
    "CTXR_B_LWR_EL1",
    "CTXR_B_UPR_EL1",
    "CTXR_C_LWR_EL1",
    "CTXR_C_UPR_EL1",
    "CTXR_D_LWR_EL1",
    "CTXR_D_UPR_EL1",
    "CTXR_A_LWR_EL2",
    "CTXR_A_UPR_EL2",
    "CTXR_B_LWR_EL2",
    "CTXR_B_UPR_EL2",
    "CTXR_C_LWR_EL2",
    "CTXR_C_UPR_EL2",
    "CTXR_D_LWR_EL2",
    "CTXR_D_UPR_EL2",
    "CTXR_A_CTL_EL1",
    "CTXR_B_CTL_EL1",
    "CTXR_C_CTL_EL1",
    "CTXR_D_CTL_EL1",
    "CTXR_A_CTL_EL2",
    "CTXR_B_CTL_EL2",
    "CTXR_C_CTL_EL2",
    "CTXR_D_CTL_EL2",
    "ACC_CTRR_C_LWR_EL2",
    "ACC_CTRR_C_UPR_EL2",
    "ACC_CTRR_D_LWR_EL2",
    "ACC_CTRR_D_UPR_EL2",
    "ACC_CTXR_A_LWR_EL2",
    "ACC_CTXR_A_UPR_EL2",
    "ACC_CTXR_B_LWR_EL2",
    "ACC_CTXR_B_UPR_EL2",
    "ACC_CTXR_C_LWR_EL2",
    "ACC_CTXR_C_UPR_EL2",
    "ACC_CTXR_D_LWR_EL2",
    "ACC_CTXR_D_UPR_EL2",
    "ACC_CTRR_C_CTL_EL2",
    "ACC_CTRR_D_CTL_EL2",
    "ACC_CTXR_A_CTL_EL2",
    "ACC_CTXR_B_CTL_EL2",
    "ACC_CTXR_C_CTL_EL2",
    "ACC_CTXR_D_CTL_EL2",
    "BP_OBJC_CTL_EL1",
    "BP_OBJC_ADR_EL1",
    "KTRACE_MESSAGE",
    "PROD_TRC_CORE_CFG_EL2",
    "AGTCNTKCTL_EL1",
    "SIQ_CFG_EL1",
    "AGTCNTVOFF_EL2",
    "IMP_MSR_LOCK_EL1",
    "MMU_SFAR_EL2",
    "APL_INTENABLE_EL2",
    "IMP_MSR_RO_CTRL0_EL1",
    "HIST_TRIG",
    "IPI_SR",
    "HPFAR_GL2",
    "E_FED_ERR_STS",
    "E_FED_ERR_CTL",
    "PREDAKEYLO_EL1",
    "PREDAKEYHI_EL1",
    "PREDBKEYLO_EL1",
    "PREDBKEYHI_EL1",
    "AHCR_EL2",
    "PMC2",
    "PMC3",
    "PMC4",
    "PMC5",
    "PMC6",
    "PMC7",
    "PMC8",
    "PMC9",
    "PMCR0_EL1",
    "PMCR1_EL1",
    "PMCR2_EL1",
    "PMCR3_EL1",
    "PMCR4_EL1",
    "PMESR0_EL1",
    "PMESR1_EL1",
    "APSTS_EL1",
    "CYC_OVRD",
    "ACC_CFG",
    "AMXIDR_EL1",
    "AMX_STATE_T_EL1",
    "AMX_CONFIG_EL1",
    "AMX_CONTEXT_EL1",
    "ASPSR_EL1",
    "VMSA_LOCK_EL1",
    "APCTL_EL1",
    "KERNKEYHI_EL1",
    "KERNKEYLO_EL1",
    "SPRR_AMRANGE_EL1",
    "SPRR_PMPRR_EL1",
    "SPRR_UMPRR_EL1",
    "SPRR_PPERM_SH01_EL1",
    "SPRR_PPERM_SH02_EL1",
    "SPRR_PPERM_SH03_EL1",
    "SPRR_PPERM_SH04_EL1",
    "SPRR_PPERM_SH05_EL1",
    "SPRR_PPERM_SH06_EL1",
    "SPRR_PPERM_SH07_EL1",
    "SPRR_UPERM_SH01_EL1",
    "SPRR_UPERM_SH02_EL1",
    "SPRR_UPERM_SH03_EL1",
    "SPRR_UPERM_SH04_EL1",
    "SPRR_UPERM_SH05_EL1",
    "SPRR_UPERM_SH06_EL1",
    "SPRR_UPERM_SH07_EL1",
    "ACFG_EL1",
    "JRANGE_EL1",
    "JCTL_EL1",
    "JCTL_EL0",
    "JAPIAKEYHI_EL1",
    "JAPIAKEYLO_EL1",
    "JAPIBKEYHI_EL1",
    "JAPIBKEYLO_EL1",
    "AGTCNTRDIR_EL1",
]

macros = '''
/*
 * gxfstat_sysreg_{rd,wr} count guest accesses to Apple IMP-DEF system
 * registers. Under Hypervisor.framework these all trap to the VMM at guest
 * EL1 with EC=0x18 (hvf-probe/FINDINGS.md), so each is one VM exit; the
 * counters size that cost. See include/xnu/gxfstat.h.
 *
 * The CPU-state and banked registers keep their .fieldoffset so raw/migration
 * access is unchanged; adding .readfn/.writefn only redirects *guest* access
 * through a helper. Note QEMU already ends the TB on every sysreg write
 * (translate-a64.c handle_sys(), "need_exit_tb = true"), so adding a writefn
 * does not change TB shape; only reads gain a helper call.
 */
/* PSTATE.M[3:2] is the current EL in AArch64; same expression as
 * arm_current_el() in target/arm/cpu.h, which is not visible from hw/arm. */
#define GXFSTAT_SYSREG(env, ri, wr) \\
    gxfstat_note_sysreg((ri)->name, ((env)->pstate >> 2) & 3, (wr))

#define OPAQUE_SYSREG_ACCESSORS(n) \\
static uint64_t n##_read(CPUARMState *env, const ARMCPRegInfo *ri) { GXFSTAT_SYSREG(env, ri, 0); return APPLE_STATE(env)->n; } \\
static void n##_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t val) { GXFSTAT_SYSREG(env, ri, 1); APPLE_STATE(env)->n = val; }

static uint64_t apple_cnt_read(CPUARMState *env, const ARMCPRegInfo *ri) {
    GXFSTAT_SYSREG(env, ri, 0);
    return raw_read(env, ri);   /* target/arm/cpregs.h: the .fieldoffset access */
}
static void apple_cnt_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t val) {
    GXFSTAT_SYSREG(env, ri, 1);
    raw_write(env, ri, val);
}
'''

def decode_name(regname):
    return regname.lower().replace('c','').replace('s','').split("_")

# r: register name
# is_cpustate: True if this reg is stored in cpu.h, False if it is stored in opaque storage
# is_banked: True if reg is stored as u64 reg[el], False if stored as u64 reg_el
def dump_struct(r, is_cpustate=False, is_banked=False):
    if "_EL12" in r or "_GL12" in r:
        print("#error Do not include EL12/GL12 regs in the register lists")
        return

    d = decode_name(all_regs[r])

    el = 1
    if "_EL" in r:
        el = int(r.split("_EL")[1])
    if "_GL" in r:
        el = int(r.split("_GL")[1])

    s = f"""    {{
        .name = "{r.upper()}", .state = ARM_CP_STATE_AA64, .access = PL{el}_RW,
        .opc0 = {d[0]}, .opc1 = {d[1]}, .crn = {d[2]}, .crm = {d[3]}, .opc2 = {d[4]},\n"""

    if is_cpustate:
        if is_banked:
            if "_GL" in r:
                s += f"        .fieldoffset = offsetof(CPUARMState, {(r.split("_GL")[0]+"_gl").lower()}[{el}]),\n"
            elif "_EL" in r:
                s += f"        .fieldoffset = offsetof(CPUARMState, {(r.split("_EL")[0]+"_el").lower()}[{el}]),\n"
            else:
                raise ValueError("banked register isn't GL or EL")
        else:
            s += f"        .fieldoffset = offsetof(CPUARMState, {r.lower()}),\n"
        # gxfstat: count guest accesses. .fieldoffset stays, so raw access is
        # unaffected; these accessors just make guest access visible.
        s += f"        .readfn = apple_cnt_read, .writefn = apple_cnt_write,\n"
    else:
        s += f"        .readfn = {r.lower()}_read, .writefn = {r.lower()}_write,\n"

    if "_EL1" in r or "_GL1" in r:
        r2 = r.replace("_EL1", "_EL2").replace("_GL1", "_GL2")
        r12 = r.replace("_EL1", "_EL12").replace("_GL1", "_GL12")

        if r2 in all_regs and r12 in all_regs:
            d=decode_name(all_regs[r2])
            s += f"        .vhe_redir_to_el2  = ENCODE_AA64_CP_REG({d[0]},{d[1]},{d[2]},{d[3]},{d[4]}),\n"
            d=decode_name(all_regs[r12])
            s += f"        .vhe_redir_to_el01 = ENCODE_AA64_CP_REG({d[0]},{d[1]},{d[2]},{d[3]},{d[4]}),\n"

    s += "    },"

    print(s)

# rs: list of registers to inject missing _EL2 regs into
# We only list EL1 regs; if there is an EL2 version of a reg, this adds it automatically
def inject_el2(rs):
    for r in rs:
        r_el2 = r.replace("_EL1", "_EL2")
        r_gl2 = r.replace("_GL1", "_GL2")
        if "_EL1" in r and r_el2 not in rs and r_el2 in all_regs:
            rs.append(r_el2)
        if "_GL1" in r and r_gl2 not in rs and r_gl2 in all_regs:
            rs.append(r_gl2)

def main():
    global rs_opaque, rs_cpustate, rs_banked

    hid_regs = [i for i in all_regs if 'HID' in i]
    rs_opaque.extend(hid_regs)

    print(macros)

    inject_el2(rs_opaque)
    inject_el2(rs_cpustate)
    # don't inject into banked regs, as we always fill in all known modes for them

    for r in rs_opaque + rs_cpustate:
        if r not in all_regs:
            print(f"Unknown register: {r}")
            sys.exit(1)
    print("typedef struct {")
    for r in rs_opaque:
        print(f"    uint64_t   {r.lower()};")
    print("} apple_state_t;\n")
    for r in rs_opaque:
        print(f"OPAQUE_SYSREG_ACCESSORS({r.lower()})")
    print("\nstatic const ARMCPRegInfo apple_sysregs[] = {")
    print("    // OPAQUE REGISTERS:")
    for r in rs_opaque:
        dump_struct(r, False)
    print("\n    // CPUSTATE REGISTERS:")
    for r in rs_cpustate:
        dump_struct(r, True)
    print("\n    // BANKED REGISTERS:")
    for r in rs_banked:
        for gl in SUPPORTED_GLS:
            dump_struct(r + str(gl),True,True)
    print("};")

main()
