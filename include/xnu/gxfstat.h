/*
 * gxfstat.h - event counters for the "can we run iOS under Hypervisor.framework
 *             and emulate only the Apple parts?" study.
 *
 * MEASUREMENT SCAFFOLDING ONLY. Nothing here changes emulated behaviour; it
 * counts the guest events that would each become one VM exit if the CPU were
 * executed natively under HVF instead of interpreted by TCG.
 *
 * Why each counter matters, with its evidence:
 *
 *  genter / gexit  GXF guarded-mode transitions. hvf-probe/results.txt records
 *                  them as "genter exec GUEST-EXC@EL1 ESR=0x02000000 EC=0x00
 *                  UNKNOWN/UNDEF", i.e. HVF does not trap them to the VMM; the
 *                  only proposed way to emulate them is to patch them to HVC,
 *                  which does exit (ESR=0x5a000000, EC=0x16). So under that
 *                  scheme each one costs a full VM exit + entry.
 *
 *  sysreg rd/wr    Accesses to Apple IMP-DEF system registers (the whole
 *                  apple_sysregs[] table in hw/arm/apple_regs.c). At guest EL1
 *                  under HVF these trap to the VMM with EC=0x18
 *                  (hvf-probe/FINDINGS.md, "70 of the probes in this mode are
 *                  trap-to-vmm"), so one exit each.
 *
 *  exceptions      Every guest exception, bucketed by EXCP_* index (cpu.h).
 *                  Informational: most of these are handled inside the guest
 *                  under HVF and cost nothing. Included so the genter rate can
 *                  be read against total guest exception traffic.
 *
 *  mmio rd/wr      CPU-initiated MMIO. One exit each under HVF too.
 *
 * Output: one line on stderr every second from a background thread, and one
 * final line at exit. Set DARWIN_GXFSTAT=0 to silence the periodic line.
 */
#ifndef XNU_GXFSTAT_H
#define XNU_GXFSTAT_H

#include <stdint.h>
#include <stdbool.h>

/* Set at machine construction, before any vCPU executes. */
extern bool gxfstat_enabled;

#define GXFSTAT_NEXC 64

extern uint64_t gxfstat_genter;
extern uint64_t gxfstat_gexit;
extern uint64_t gxfstat_sysreg_rd;
extern uint64_t gxfstat_sysreg_wr;
extern uint64_t gxfstat_mmio_rd;
extern uint64_t gxfstat_mmio_wr;
extern uint64_t gxfstat_exc[GXFSTAT_NEXC];

/*
 * Same events, broken down by the exception level the guest was running at.
 * This is the number that decides whether the HVF scheme is possible at all:
 * hvf-probe/results.txt shows the Apple IMP-DEF registers trap to the VMM
 * (EC=0x18) only at *guest EL1*; at guest EL2 they are plain UNDEF and the VMM
 * never sees them (and HVC is taken by the guest at EL2 too, so even the
 * patch-to-HVC trick has nothing to land on there).
 */
extern uint64_t gxfstat_genter_el[4];
extern uint64_t gxfstat_gexit_el[4];
extern uint64_t gxfstat_sysreg_el[4];

/*
 * Record one guest access to an Apple IMP-DEF system register. @name is the
 * ARMCPRegInfo .name, a static string, so its pointer is used as the key.
 * Called from the generated accessors in hw/arm/apple_regs_autogen.h.
 */
void gxfstat_note_sysreg(const char *name, int el, int is_write);

/* Called once from the machine init; starts the reporting thread. */
void gxfstat_start(void);
/* Print one summary line to stderr. */
void gxfstat_dump(const char *why);

#endif /* XNU_GXFSTAT_H */
