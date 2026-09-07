/*
 * Apple AMX state and machine hooks (darwin-vm).  Implementation in
 * tcg/amx_helper.c; semantics from corsix/amx (tcg/amx/); the enable and trap
 * contract from the iOS 27 24A5430a kernelcache (docs/re/native-amx.md).
 */
#ifndef TARGET_ARM_AMX_H
#define TARGET_ARM_AMX_H

#include "qemu/osdep.h"

/* AMX_CONFIG_EL1 (S3_4_C15_C1_4) bits the kernel uses. */
#define AMX_CONFIG_CPU_ENABLE    (1ull << 8)   /* written as 0x100 at CPU init, kernel+0xc6da0c */
#define AMX_CONFIG_THREAD_ENABLE (1ull << 63)  /* ORed in at kernel+0xc701dc before a thread may use AMX */

/*
 * The trap the kernel's synchronous handler recognises as "AMX used while
 * disabled": exception class 0x3f (kernel+0xc65624) with ISS bits [24:3]
 * equal to 3 (kernel+0xc65f88: (esr & 0x1fffff8) == 0x18). IL is set for a
 * 32-bit instruction.
 */
#define AMX_TRAP_SYNDROME 0xfe000018u

typedef struct AMXState {
    /* Register file: 8 X, 8 Y and 64 Z rows of 64 bytes (amx_emulate.h). */
    uint8_t regs[(8 + 8 + 64) * 64];
    uint64_t config;   /* AMX_CONFIG_EL1 */
    uint64_t context;  /* AMX_CONTEXT_EL1, opaque */
    uint32_t active;   /* set by `set`, cleared by `clr`; AMX_STATE_T_EL1 != 0 */
    uint32_t version;  /* advertised as AMXIDR_EL1 bit (version - 1); 0 = no AMX */
} AMXState;

struct ArchCPU;
/* Called by the Apple machine: version 0 leaves the space unallocated. */
void arm_amx_init(struct ArchCPU *cpu, uint32_t version);

#endif
