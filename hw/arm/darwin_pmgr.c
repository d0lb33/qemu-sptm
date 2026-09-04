/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Narrow d47 iBoot PMGR state.
 *
 * At early startup iBoot reads PMGR range 0 + 0x30000, tests bit 7, and sets
 * that bit only when it was clear.  It returns the prior bit and separately
 * records whether it changed the latch.  There is no completion/status poll.
 * A newly created VM represents a cold/off machine, so the modeled enable
 * latch starts clear and subsequently behaves as ordinary storage.
 *
 * The d47 chip-revision getter reads range 1 + 0x48988 and extracts register
 * bits [9:7] into revision bits [2:0], and register bits [12:10] into revision
 * bits [6:4].  The iBootData paired with mBoot-20457.2.37 contains exact
 * (0x8140, revision, 0) records for 0x00, 0x10, and 0x11.  An opt-in probe may
 * therefore select one of those virtual revisions without claiming a physical
 * d47 reset value.  The register is read-only in every observed iBoot path.
 *
 * The CPFM getter reads two adjacent words at range 1 + 0x48038.  It accepts
 * exactly (0xa050c030, 0xa050c030) -> 0 or
 * (0xa55ac33c, 0xa050c030) -> 1 and panics on every other pair.  Its value is
 * emitted as CPFM in iBoot's SDOM/CPID/CPRV/CPFM identity record.  An opt-in
 * virtual CPFM identity can select either firmware-defined tuple; this is not
 * a completion value and does not bypass the getter's validation.
 *
 * The adjacent identity word at range 1 + 0x48910 supplies board-id bits
 * [7:5] from register bits [2:0] and SCEP from register bits [9:3].  The
 * paired BuildManifest fixes d47's ApBoardID at 0x08, so its upper board-id
 * bits are zero.  The paired iBootData gfCR records fix SCEP at zero.  The
 * resulting raw word is therefore zero; modeling it as a named identity
 * register records why zero is valid instead of accepting the catch-all
 * region's accidental zero.
 *
 * d47's board ID is assembled from two sources.  The getter at research raw
 * +0x43b44 preserves bits [4:0] of physical 0x3082dc020 and replaces bits
 * [31:5] with the low three bits from the PMGR identity getter above.  The
 * paired BuildManifest fixes ApBoardID at 0x08, so the exact d47 selector is
 * 8: low five bits 8 here and upper bits zero in PMGR.  This selector is then
 * consumed by the t8140 GPIO-default dispatcher, which accepts 8..11.  Model
 * the manifest-defined identity word as read-only; it is neither a guessed
 * hardware reset value nor a protocol-completion response.
 *
 * Both pinned iBoot variants use the standard PMGR device-state contract:
 * target state is written in bits [3:0], and the caller polls until actual
 * state bits [7:4] match.  The d47 `ps-groups` and `devices` properties locate
 * each state word.  This model creates exact, sparse 4-byte subregions for
 * every word declared by those tables; holes remain
 * unimplemented.  Each virtual device starts off and mirrors a valid target
 * transition into actual state.  It does not manufacture a completion bit.
 *
 * At the next cross-build-identical boundary, the CPU-index helper selects
 * one of range-0 words +0x82000/+0x82004.  iBoot clears bits 1 and 4 and polls
 * bits 0 and 5 until both are clear.  For the VM's sole boot CPU it selects
 * +0x82004.  A zero word is the canonical cold representative for that exact
 * observation (not a claimed T8140 reset value); writes must be precisely the
 * firmware's clear operation and the model supplies no independent success.
 *
 * A second routine, identical in all three pinned d47 images, operates five
 * control/status channels at range 0 +0x60000 + n*0x400.  It clears control
 * bit 0, then waits for status bit 0 to become set.  The model makes that
 * transition only after the exact evidenced control write; status does not
 * start asserted and unrelated accesses fail closed.
 *
 * Platform selector 10 expands to selectors 0..8, which map to nine adjacent
 * range-0 words +0x28004..+0x28024.  Each path only sets bit 0 and has no
 * completion read.  These are modeled as cold-clear storage bits.
 * The following platform-reset routine performs two unconditional zero writes
 * to PMGR range 0 +0x38000 and range 2 +0x40174.  They are modeled only as
 * write-only zero sinks; no read value or completion state is implied.
 * It then clears five sparse range-3 words at +0x52000 + n*0x4000 and polls
 * bit 30 of the same word until clear.  Storing the written zero is sufficient
 * for that protocol; no separate status is asserted.
 * Three bounded setters write range 2 +0x58000/+0x60000/+0x64000 (limits
 * 15/15/7 respectively) and poll bit 31 of the same stored word until clear.
 * The adjacent +0x5c000 setter moves one step toward a target in [0,15],
 * writing the step in bits [3:0] and re-reading actual state bits [11:8].
 * A valid request updates those actual bits and leaves busy bit 31 clear.
 *
 * The following seven-block setup loop asks the firmware's recursive hardware
 * descriptor table for three indices to omit.  In all three pinned d47
 * images, descriptor IDs 0x64, 0x82, and 0x83 read the high nibble of PMGR
 * range 2 +0x40044/+0x400bc/+0x400c0.  A zero nibble selects descriptor 0,
 * whose type makes the getter return -1.  The caller treats -1 as no match,
 * skips its fixed boot block 0, and configures blocks 1..6.  An opt-in VM
 * identity can therefore declare that none of those six virtual blocks is
 * harvested.  This is a topology choice following an exact firmware-defined
 * path, not a claim about the physical T8140 reset values.
 * The same initialization pass programs eleven adjacent range-2 words
 * +0x40148..+0x40170.  It preserves selector bits [23:20], writes a command
 * with bit 31 set, and polls bit 30 clear.  The exact request is retained; no
 * separate completion bit is invented.
 * A later signed tuning list revisits blocks 1..6 after setup.  It performs
 * one masked RMW on word 0 of every block and additional word 3/4 RMWs on
 * blocks 1, 3, and 4.  Those literal records contain no completion polls, so
 * the topology model admits only that exact second phase after setup.
 *
 * Matching range-5 and range-14 state setters at +0x20 accept targets [0,15].
 * They read-modify-write the target in bits [4:0] with command bit 25, poll
 * bit 31 clear, and read back the target.  Cold zero plus exact storage
 * implements that observed contract without asserting an unrelated
 * completion response.
 *
 * The subsequent t8140 initialization table contains three 32-bit masked
 * updates at range 3 +0x2004/+0x400c/+0x4010.  The signed table records at
 * research raw +0x273530/+0x2738a0/+0x2738b0 encode their addresses and point
 * at literal (mask,value) pairs.  Runtime reaches the generic 32-bit load at
 * raw +0x8b610 and issues the matching writes from raw +0x8b6b0.  A bounded
 * run first stopped at +0x2004; after modeling that exact entry, the next run
 * stopped at +0x400c.  Model these adjacent table entries as cold-storage
 * RMWs; there is no completion read or synthesized status.
 *
 * The caller then operates five range-3 words at +0/+0x2000/+0x4000/
 * +0x6000/+0x6004 (research raw +0x69124..+0x691c0).  It clears bit 27 in
 * the first three and polls bit 25 clear; for +0x6000 it also clears then
 * later sets bit 31 before another bit-27 clear and bit-25 poll; for +0x6004
 * it sets bit 21.  A cold-zero VM word plus storing those exact writes makes
 * every polled bit remain clear.  Enforce the complete observed sequence and
 * do not assert an independent completion value.
 *
 * A later SoC-tuning pass configures seven 0x1000-spaced blocks in PMGR
 * range 2.  Each block's +0x204 word applies mask 0x7300 with a value derived
 * at research raw +0x97328 from bits [6:2] of range 1 +0x480d0.  Some blocks
 * also receive a signed-table literal at +0x248 through mask 0x0ffffff7.
 * The firmware neither validates the source nor waits for completion.  The
 * opt-in virtual tuning bin 0 supplies a raw zero source, selecting no
 * per-silicon adjustment, and retains the exact literal configuration.  This
 * is a VM identity choice, not a physical d47 reset-value claim.
 *
 * The next signed-table record at research raw +0x278d68 applies
 * (mask,value)=(0x0003ffc0,0x00002ac0) to range 2 +0xc.  It is another plain
 * one-shot RMW with no completion read.
 * The following independently selected record targets range 2 +0x10 with
 * (mask,value)=(0xffffc000,0x6c800000).
 * Research raw +0x6d968 then walks topology blocks 0..6 at stride 0x4000.
 * For each block it sets bits 31 and 0 in word +8, sets word +0 low bits to
 * one, clears word +4 bit 0, and polls word +0 bit 31 until clear.  The
 * preceding exact writes leave that polled bit clear; the model therefore
 * stores each request without inventing a completion transition.
 * A later signed-list record at raw +0x273548 applies mask/value 1/1 to
 * range 3 +0x3c000.  The following list revisits sparse range-3 selector 39
 * with the observed and table-derived second request 0x10000000; it retains
 * the same bit-30-clear poll contract as the first request.
 * The next research path hard-codes two auxiliary configuration banks at
 * 0x300340000 and 0x300350000 (raw +0x65e18/+0x65e74).  The selected list at
 * raw +0x24b110 applies eight literal masked RMW records, followed by the
 * one-record list at +0x24b100.  Raw +0x6da10 then issues a finite request to
 * both banks and polls bit 31 of word zero.  The DT's soc-tuner calls this
 * operation MCC control; that name is attribution, not a reset-value claim.
 * The next signed table applies sixteen literal masked RMW records at range 2
 * +0x40000..+0x40040, then revisits descriptor 0x64 at +0x40044 for one final
 * RMW.  The masks and values are stored beside the table at research raw
 * +0x2745a8..+0x2746b8, and the exact runtime sequence is recorded in
 * IBOOT_RANGE3_SECOND_EXACT_20260904.stderr.log:375-407.  These are plain
 * writes with no completion poll.  Admit only the observed order and values;
 * descriptor 0x64 remains read-only until the preceding sixteen records have
 * completed.
 * The immediately following eight records at range 2 +0x40048..+0x40064
 * are the same one-shot form.  Research raw +0x2746c8..+0x274740 and
 * release raw +0x272278..+0x2722f0 contain identical descriptor/mask/value
 * pairs; both builds produced the same writes in the bounded continuation
 * traces.  This second block is unavailable until descriptor 0x64's final
 * RMW has completed.
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "qemu/cutils.h"
#include "qemu/bswap.h"
#include "system/memory.h"
#include "system/address-spaces.h"
#include "cpu.h"
#include "xnu/apple_dtree.h"
#include "xnu/darwin_pmgr.h"

#define D47_PMGR_START_LATCH_OFFSET UINT64_C(0x30000)
#define D47_PMGR_START_LATCH_ENABLE UINT32_C(0x80)
#define D47_PMGR_CPU_READY_OFFSET    UINT64_C(0x82000)
#define D47_PMGR_CPU_READY_CLEAR     UINT32_C(0x12)
#define D47_PMGR_HANDSHAKE_OFFSET    UINT64_C(0x60000)
#define D47_PMGR_HANDSHAKE_STRIDE    UINT64_C(0x400)
#define D47_PMGR_HANDSHAKE_STATUS    UINT64_C(0xc)
#define D47_PMGR_HANDSHAKE_COUNT     5
#define D47_PMGR_PLATFORM_FLAGS_OFFSET UINT64_C(0x28004)
#define D47_PMGR_PLATFORM_FLAGS_COUNT  9
#define D47_PMGR_ZERO0_OFFSET        UINT64_C(0x38000)
#define D47_PMGR_ZERO2_OFFSET        UINT64_C(0x40174)
#define D47_PMGR_POLL_CLEAR_OFFSET   UINT64_C(0x52000)
#define D47_PMGR_POLL_CLEAR_STRIDE   UINT64_C(0x4000)
#define D47_PMGR_POLL_CLEAR_COUNT    5
#define D47_PMGR_BOUNDED_STATE_COUNT 3
#define D47_PMGR_STEPPED_STATE_OFFSET UINT64_C(0x5c000)
#define D47_PMGR_TOPOLOGY_SELECTOR_COUNT 3
#define D47_PMGR_TOPOLOGY_BLOCK_FIRST 1
#define D47_PMGR_TOPOLOGY_BLOCK_COUNT 6
#define D47_PMGR_TOPOLOGY_BLOCK_STRIDE UINT64_C(0x4000)
#define D47_PMGR_CONFIG_SELECTOR_OFFSET UINT64_C(0x40148)
#define D47_PMGR_CONFIG_SELECTOR_COUNT 11
#define D47_PMGR_RANGE3_CONFIG_OFFSET UINT64_C(0x40000)
#define D47_PMGR_RANGE3_CONFIG_COUNT 64
#define D47_PMGR_RANGE2_SIGNED_OFFSET UINT64_C(0x40000)
#define D47_PMGR_RANGE2_SIGNED_COUNT 16
#define D47_PMGR_RANGE2_SIGNED_CONT_OFFSET UINT64_C(0x40048)
#define D47_PMGR_RANGE2_SIGNED_CONT_COUNT 8
#define D47_PMGR_DOMAIN_STATE_OFFSET UINT64_C(0x20)
#define D47_PMGR_DOMAIN_STATE_COUNT 2
#define D47_PMGR_MASKED_TUNABLE_COUNT 26
#define D47_PMGR_STARTUP_WORD_COUNT 5
#define D47_PMGR_SOC_TUNABLE_COUNT 12
#define D47_PMGR_TUNING_FUSE_OFFSET UINT64_C(0x480d0)
#define D47_MCC_CONFIG_BASE          UINT64_C(0x300340000)
#define D47_MCC_CONFIG_STRIDE        UINT64_C(0x10000)
#define D47_MCC_CONFIG_COUNT         2
#define D47_MCC_TUNABLE_COUNT        2
#define D47_PMGR_DEVICE_NAME_LEN     16
#define D47_PMGR_STATE_TARGET_MASK   UINT32_C(0x0000000f)
#define D47_PMGR_STATE_ACTUAL_MASK   UINT32_C(0x000000f0)
#define D47_PMGR_STATE_CONTROL_MASK  UINT32_C(0x9000000f)
#define D47_PMGR_CPFM_OFFSET         UINT64_C(0x48038)
#define D47_PMGR_CPFM_SECOND         UINT32_C(0xa050c030)
#define D47_PMGR_CPFM_FIRST_ONE      UINT32_C(0xa55ac33c)
#define D47_PMGR_IDENTITY_OFFSET      UINT64_C(0x48910)
#define D47_PMGR_IDENTITY_RAW         UINT32_C(0)
#define D47_PMGR_CHIP_REV_OFFSET     UINT64_C(0x48988)
#define D47_BOARD_ID_LOW_PA          UINT64_C(0x3082dc020)
#define D47_BOARD_ID_LOW             UINT32_C(0x08)

typedef struct QEMU_PACKED DarwinPMGRDevice {
    uint8_t flags;
    uint8_t opaque0[15];
    uint32_t group_and_offset;
    uint8_t opaque1[12];
    char name[D47_PMGR_DEVICE_NAME_LEN];
} DarwinPMGRDevice;

typedef struct DarwinPMGRStateSlot {
    MemoryRegion mr;
    uint32_t state;
    unsigned reg_index;
    uint64_t offset;
    char name[D47_PMGR_DEVICE_NAME_LEN + 1];
} DarwinPMGRStateSlot;

typedef struct DarwinPMGRHandshake {
    MemoryRegion control_mr;
    MemoryRegion status_mr;
    uint32_t control;
    uint32_t status;
    unsigned index;
} DarwinPMGRHandshake;

typedef struct DarwinPMGRPollClear {
    MemoryRegion mr;
    uint32_t word;
    unsigned index;
    unsigned phase;
} DarwinPMGRPollClear;

typedef struct DarwinPMGRBoundedState {
    MemoryRegion mr;
    uint32_t word;
    uint32_t max;
    uint64_t offset;
} DarwinPMGRBoundedState;

typedef struct DarwinPMGRTopologySelector {
    MemoryRegion mr;
    uint64_t offset;
    uint32_t descriptor_id;
    uint32_t word;
    bool observed;
    bool *tuning_ready;
    bool tuning_read;
    bool tuned;
} DarwinPMGRTopologySelector;

typedef struct DarwinPMGRRange2SignedTuning {
    MemoryRegion mr;
    uint32_t words[D47_PMGR_RANGE2_SIGNED_COUNT];
    unsigned step;
    bool complete;
} DarwinPMGRRange2SignedTuning;

typedef struct DarwinPMGRRange2SignedContinuation {
    MemoryRegion mr;
    uint32_t words[D47_PMGR_RANGE2_SIGNED_CONT_COUNT];
    unsigned step;
    bool *ready;
    bool complete;
} DarwinPMGRRange2SignedContinuation;

typedef struct DarwinPMGRTopologyBlock {
    MemoryRegion mr;
    uint32_t words[5];
    unsigned index;
    unsigned phase;
    unsigned post_step;
    unsigned power_step;
} DarwinPMGRTopologyBlock;

typedef struct DarwinPMGRConfigSelector {
    MemoryRegion mr;
    uint32_t word;
    unsigned index;
    unsigned phase;
    const char *kind;
    bool second_valid;
    uint32_t second_value;
} DarwinPMGRConfigSelector;

typedef struct DarwinPMGRDomainState {
    MemoryRegion mr;
    uint64_t word;
    unsigned reg_index;
    unsigned phase;
} DarwinPMGRDomainState;

typedef struct DarwinPMGRMaskedTunable {
    MemoryRegion mr;
    uint32_t word;
    uint32_t mask;
    uint32_t value;
    uint64_t offset;
    unsigned reg_index;
    unsigned phase;
} DarwinPMGRMaskedTunable;

typedef struct DarwinPMGRStartupWord {
    MemoryRegion mr;
    uint32_t word;
    uint64_t offset;
    unsigned index;
    unsigned phase;
} DarwinPMGRStartupWord;

typedef struct DarwinPMGRRootZero {
    MemoryRegion mr;
    uint32_t words[3];
    unsigned tuning_phase;
    unsigned power_step;
} DarwinPMGRRootZero;

typedef struct DarwinPMGRMCCConfig {
    MemoryRegion mr;
    uint32_t words[8];
    unsigned index;
    unsigned config_step;
    unsigned cleanup_step;
    unsigned power_step;
} DarwinPMGRMCCConfig;

typedef struct DarwinPMGRMCCTunable {
    MemoryRegion mr;
    uint32_t word;
    uint32_t mask;
    uint32_t value;
    uint64_t offset;
    unsigned bank;
    unsigned phase;
} DarwinPMGRMCCTunable;

typedef struct DarwinPMGRIboot {
    MemoryRegion start_latch_mr;
    MemoryRegion cpu_ready_mr;
    MemoryRegion platform_flags_mr;
    MemoryRegion zero0_mr;
    MemoryRegion zero2_mr;
    MemoryRegion stepped_state_mr;
    MemoryRegion cpfm_mr;
    MemoryRegion identity_mr;
    MemoryRegion board_id_low_mr;
    MemoryRegion chip_revision_mr;
    MemoryRegion tuning_fuse_mr;
    DarwinPMGRMaskedTunable masked_tunables[
        D47_PMGR_MASKED_TUNABLE_COUNT];
    DarwinPMGRStartupWord startup_words[D47_PMGR_STARTUP_WORD_COUNT];
    DarwinPMGRMaskedTunable soc_tunables[D47_PMGR_SOC_TUNABLE_COUNT];
    DarwinPMGRMaskedTunable root_tunable_c;
    DarwinPMGRMaskedTunable root_tunable_10;
    DarwinPMGRRootZero root_zero;
    DarwinPMGRMCCConfig mcc_configs[D47_MCC_CONFIG_COUNT];
    DarwinPMGRMCCTunable mcc_tunables[
        D47_MCC_CONFIG_COUNT * D47_MCC_TUNABLE_COUNT];
    DarwinPMGRDomainState domain_states[D47_PMGR_DOMAIN_STATE_COUNT];
    uint32_t start_latch;
    uint32_t cpu_ready[2];
    uint32_t platform_flags[D47_PMGR_PLATFORM_FLAGS_COUNT];
    DarwinPMGRBoundedState bounded_states[D47_PMGR_BOUNDED_STATE_COUNT];
    DarwinPMGRTopologySelector topology_selectors[
        D47_PMGR_TOPOLOGY_SELECTOR_COUNT];
    DarwinPMGRRange2SignedTuning range2_signed_tuning;
    DarwinPMGRRange2SignedContinuation range2_signed_continuation;
    DarwinPMGRTopologyBlock topology_blocks[D47_PMGR_TOPOLOGY_BLOCK_COUNT];
    DarwinPMGRConfigSelector config_selectors[
        D47_PMGR_CONFIG_SELECTOR_COUNT];
    DarwinPMGRConfigSelector range3_config_words[
        D47_PMGR_RANGE3_CONFIG_COUNT];
    uint32_t stepped_state;
    DarwinPMGRHandshake handshakes[D47_PMGR_HANDSHAKE_COUNT];
    DarwinPMGRPollClear poll_clear[D47_PMGR_POLL_CLEAR_COUNT];
    DarwinPMGRStateSlot *state_slots;
    size_t state_slot_count;
    uint32_t cpfm[2];
    uint32_t chip_revision_raw;
} DarwinPMGRIboot;

static const uint32_t d47_range2_signed_offsets[
    D47_PMGR_RANGE2_SIGNED_COUNT] = {
    0x00, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c, 0x20,
    0x24, 0x28, 0x2c, 0x30, 0x34, 0x38, 0x3c, 0x40,
};

static const uint32_t d47_range2_signed_masks[
    D47_PMGR_RANGE2_SIGNED_COUNT] = {
    0x0f000000, 0x3f000000, 0x30000000, 0x30000000,
    0x30000000, 0x0f000000, 0x30000000, 0x30000000,
    0x30000000, 0x30000000, 0x30000000, 0x30000000,
    0x30000000, 0x3f000000, 0x3f000000, 0x30000000,
};

static const uint32_t d47_range2_signed_values[
    D47_PMGR_RANGE2_SIGNED_COUNT] = {
    0x05000000, 0x05000000, 0x00000000, 0x00000000,
    0x00000000, 0x05000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x07000000, 0x05000000, 0x00000000,
};

static const uint32_t d47_range2_signed_cont_masks[
    D47_PMGR_RANGE2_SIGNED_CONT_COUNT] = {
    0x30000000, 0x30000000, 0x30000000, 0x30000000,
    0x30000000, 0x30000000, 0x3f000000, 0x3f000000,
};

static const uint32_t d47_range2_signed_cont_values[
    D47_PMGR_RANGE2_SIGNED_CONT_COUNT] = {
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x05000000, 0x05000000,
};

static uint64_t darwin_pmgr_mcc_tunable_read(void *opaque, hwaddr offset,
                                              unsigned size)
{
    DarwinPMGRMCCTunable *slot = opaque;

    if (offset != 0 || size != 4 || slot->phase != 0) {
        error_report("darwin-pmgr: invalid MCC bank %u tunable +0x%"
                     PRIx64 " read offset=0x%" HWADDR_PRIx
                     " size=%u phase=%u", slot->bank, slot->offset,
                     offset, size, slot->phase);
        exit(EXIT_FAILURE);
    }
    slot->phase++;
    return slot->word;
}

static void darwin_pmgr_mcc_tunable_write(void *opaque, hwaddr offset,
                                           uint64_t value, unsigned size)
{
    DarwinPMGRMCCTunable *slot = opaque;
    uint32_t expected = (slot->word & ~slot->mask) |
                        (slot->value & slot->mask);

    if (offset != 0 || size != 4 || value > UINT32_MAX ||
        slot->phase != 1 || value != expected) {
        error_report("darwin-pmgr: invalid MCC bank %u tunable +0x%"
                     PRIx64 " write offset=0x%" HWADDR_PRIx
                     " value=0x%" PRIx64 " size=%u phase=%u"
                     " expected=0x%08x", slot->bank, slot->offset,
                     offset, value, size, slot->phase, expected);
        exit(EXIT_FAILURE);
    }
    slot->word = expected;
    slot->phase++;
    fprintf(stderr,
            "darwin-pmgr: MCC bank %u tunable +0x%" PRIx64
            " applied mask=0x%08x value=0x%08x result=0x%08x\n",
            slot->bank, slot->offset, slot->mask, slot->value, slot->word);
}

static uint64_t darwin_pmgr_mcc_config_read(void *opaque, hwaddr offset,
                                             unsigned size)
{
    DarwinPMGRMCCConfig *block = opaque;

    if (size == 4 && block->config_step < 16 &&
        !(block->config_step & 1) &&
        offset == (block->config_step / 2) * 4) {
        block->config_step++;
        return block->words[offset / 4];
    }
    if (size == 4 && block->config_step == 16 &&
        block->cleanup_step == 0 && offset == 4) {
        block->cleanup_step++;
        return block->words[1];
    }
    if (size == 4 && block->cleanup_step == 2 &&
        ((block->power_step == 0 && offset == 4) ||
         (block->power_step == 2 && offset == 0) ||
         (block->power_step == 4 && offset == 0) ||
         (block->power_step == 6 && offset == 0))) {
        block->power_step++;
        if (block->power_step == 7) {
            fprintf(stderr,
                    "darwin-pmgr: MCC configuration bank %u exact request"
                    " complete; polled bit31 is clear\n", block->index);
        }
        return block->words[offset / 4];
    }
    error_report("darwin-pmgr: invalid MCC bank %u read offset=0x%"
                 HWADDR_PRIx " size=%u config-step=%u cleanup-step=%u"
                 " power-step=%u", block->index, offset, size,
                 block->config_step, block->cleanup_step,
                 block->power_step);
    exit(EXIT_FAILURE);
}

static void darwin_pmgr_mcc_config_write(void *opaque, hwaddr offset,
                                          uint64_t value, unsigned size)
{
    DarwinPMGRMCCConfig *block = opaque;
    static const uint32_t masks[] = {
        0x000000e0, 0x00000010, 0x0003ffc0, 0xffffc000,
        0x0003ffc0, 0xffffc000, 0x0003ffc0, 0xffffc000,
    };
    static const uint32_t values[] = {
        0x00000020, 0x00000000, 0x00008900, 0x2160c000,
        0x00008900, 0x21604000, 0x0000c900, 0x22004000,
    };
    uint32_t expected;

    if (size == 4 && value <= UINT32_MAX && block->config_step < 16 &&
        (block->config_step & 1) &&
        offset == (block->config_step / 2) * 4) {
        expected = (block->words[offset / 4] &
                    ~masks[offset / 4]) |
                   (values[offset / 4] & masks[offset / 4]);
        if (value != expected) {
            goto invalid_write;
        }
        block->words[offset / 4] = expected;
        block->config_step++;
        if (block->config_step == 16) {
            fprintf(stderr,
                    "darwin-pmgr: MCC configuration bank %u eight-record"
                    " signed tuning phase complete\n", block->index);
        }
        return;
    }
    if (size == 4 && value <= UINT32_MAX && block->config_step == 16 &&
        block->cleanup_step == 1 && offset == 4) {
        expected = block->words[1] & ~UINT32_C(0x10);
        if (value != expected) {
            goto invalid_write;
        }
        block->words[1] = expected;
        block->cleanup_step++;
        return;
    }
    if (size == 4 && value <= UINT32_MAX && block->cleanup_step == 2) {
        if (block->power_step == 1 && offset == 4) {
            expected = block->words[1] | UINT32_C(0x80000001);
        } else if (block->power_step == 3 && offset == 0) {
            expected = (block->words[0] & ~UINT32_C(7)) | 1;
        } else if (block->power_step == 5 && offset == 0) {
            expected = block->words[0] & ~UINT32_C(0x18);
        } else {
            goto invalid_write;
        }
        if (value != expected) {
            goto invalid_write;
        }
        block->words[offset / 4] = expected;
        block->power_step++;
        return;
    }

invalid_write:
    error_report("darwin-pmgr: invalid MCC bank %u write offset=0x%"
                 HWADDR_PRIx " value=0x%" PRIx64
                 " size=%u config-step=%u cleanup-step=%u power-step=%u",
                 block->index, offset, value, size, block->config_step,
                 block->cleanup_step, block->power_step);
    exit(EXIT_FAILURE);
}

static uint64_t darwin_pmgr_range2_signed_cont_read(void *opaque,
                                                     hwaddr offset,
                                                     unsigned size)
{
    DarwinPMGRRange2SignedContinuation *tuning = opaque;
    unsigned record = tuning->step / 2;

    if (!tuning->ready || !*tuning->ready || size != 4 ||
        tuning->step >= 2 * D47_PMGR_RANGE2_SIGNED_CONT_COUNT ||
        (tuning->step & 1) || offset != record * 4) {
        error_report("darwin-pmgr: invalid range2 signed continuation read"
                     " offset=0x%" HWADDR_PRIx " size=%u step=%u ready=%u",
                     offset, size, tuning->step,
                     tuning->ready ? *tuning->ready : 0);
        exit(EXIT_FAILURE);
    }
    tuning->step++;
    return tuning->words[record];
}

static void darwin_pmgr_range2_signed_cont_write(void *opaque,
                                                  hwaddr offset,
                                                  uint64_t value,
                                                  unsigned size)
{
    DarwinPMGRRange2SignedContinuation *tuning = opaque;
    unsigned record = tuning->step / 2;
    uint32_t expected;

    if (!tuning->ready || !*tuning->ready || size != 4 ||
        value > UINT32_MAX ||
        tuning->step >= 2 * D47_PMGR_RANGE2_SIGNED_CONT_COUNT ||
        !(tuning->step & 1) || offset != record * 4) {
        goto invalid_write;
    }
    expected = (tuning->words[record] &
                ~d47_range2_signed_cont_masks[record]) |
               (d47_range2_signed_cont_values[record] &
                d47_range2_signed_cont_masks[record]);
    if (value != expected) {
        goto invalid_write;
    }
    tuning->words[record] = expected;
    tuning->step++;
    if (tuning->step == 2 * D47_PMGR_RANGE2_SIGNED_CONT_COUNT) {
        tuning->complete = true;
        fprintf(stderr,
                "darwin-pmgr: eight range2 signed-table continuation RMW"
                " records complete through +0x40064\n");
    }
    return;

invalid_write:
    error_report("darwin-pmgr: invalid range2 signed continuation write"
                 " offset=0x%" HWADDR_PRIx " value=0x%" PRIx64
                 " size=%u step=%u ready=%u", offset, value, size,
                 tuning->step, tuning->ready ? *tuning->ready : 0);
    exit(EXIT_FAILURE);
}

static uint64_t darwin_pmgr_root_zero_read(void *opaque, hwaddr offset,
                                           unsigned size)
{
    DarwinPMGRRootZero *slot = opaque;

    if (size == 4 && offset == 0 &&
        (slot->tuning_phase == 0 ||
         (slot->tuning_phase == 2 && slot->power_step == 7))) {
        slot->tuning_phase++;
        return slot->words[0];
    }
    if (size == 4 &&
        ((slot->power_step == 0 && offset == 8) ||
         (slot->power_step == 2 && offset == 0) ||
         (slot->power_step == 4 && offset == 4) ||
         (slot->power_step == 6 && offset == 0))) {
        slot->power_step++;
        if (slot->power_step == 7) {
            fprintf(stderr,
                    "darwin-pmgr: topology power block 0 exact request"
                    " complete; polled bit31 is clear\n");
        }
        return slot->words[offset / 4];
    }
    error_report("darwin-pmgr: invalid root-block read offset=0x%"
                 HWADDR_PRIx " size=%u tuning-phase=%u power-step=%u",
                 offset, size, slot->tuning_phase, slot->power_step);
    exit(EXIT_FAILURE);
}

static void darwin_pmgr_root_zero_write(void *opaque, hwaddr offset,
                                        uint64_t value, unsigned size)
{
    DarwinPMGRRootZero *slot = opaque;
    uint32_t mask;
    uint32_t expected;

    if (offset == 0 && size == 4 && value <= UINT32_MAX &&
        (slot->tuning_phase == 1 || slot->tuning_phase == 3)) {
        mask = slot->tuning_phase == 1 ? UINT32_C(0x00050000) :
                                         UINT32_C(0x00070000);
        expected = (slot->words[0] & ~mask) | mask;
        if (value != expected) {
            goto invalid_write;
        }
        slot->words[0] = expected;
        slot->tuning_phase++;
        fprintf(stderr,
                "darwin-pmgr: range2 root word tuning pass %u"
                " result=0x%08x\n",
                slot->tuning_phase / 2, slot->words[0]);
        return;
    }

    if (size == 4 && value <= UINT32_MAX &&
        ((slot->power_step == 1 && offset == 8) ||
         (slot->power_step == 3 && offset == 0) ||
         (slot->power_step == 5 && offset == 4))) {
        if (offset == 8) {
            expected = slot->words[2] | UINT32_C(0x80000001);
        } else if (offset == 0) {
            expected = (slot->words[0] & ~UINT32_C(7)) | 1;
        } else {
            expected = slot->words[1] & ~UINT32_C(1);
        }
        if (value != expected) {
            goto invalid_write;
        }
        slot->words[offset / 4] = expected;
        slot->power_step++;
        return;
    }

invalid_write:
    error_report("darwin-pmgr: invalid root-block write offset=0x%"
                 HWADDR_PRIx " value=0x%" PRIx64
                 " size=%u tuning-phase=%u power-step=%u",
                 offset, value, size, slot->tuning_phase,
                 slot->power_step);
    exit(EXIT_FAILURE);
}

static uint64_t darwin_pmgr_tuning_fuse_read(void *opaque, hwaddr offset,
                                              unsigned size)
{
    if (offset != 0 || size != 4) {
        error_report("darwin-pmgr: invalid tuning-bin read offset=0x%"
                     HWADDR_PRIx " size=%u", offset, size);
        exit(EXIT_FAILURE);
    }
    return 0;
}

static void darwin_pmgr_tuning_fuse_write(void *opaque, hwaddr offset,
                                           uint64_t value, unsigned size)
{
    error_report("darwin-pmgr: unexpected tuning-bin write offset=0x%"
                 HWADDR_PRIx " value=0x%" PRIx64 " size=%u",
                 offset, value, size);
    exit(EXIT_FAILURE);
}

static uint64_t darwin_pmgr_startup_word_read(void *opaque, hwaddr offset,
                                               unsigned size)
{
    DarwinPMGRStartupWord *slot = opaque;
    bool valid = false;

    if (offset == 0 && size == 4) {
        if (slot->index < 3) {
            valid = slot->phase == 0 || slot->phase == 2;
        } else if (slot->index == 3) {
            valid = slot->phase == 0 || slot->phase == 2 ||
                    slot->phase == 3 || slot->phase == 5 ||
                    slot->phase == 7;
        } else {
            valid = slot->phase == 0;
        }
    }
    if (!valid) {
        error_report("darwin-pmgr: invalid startup word +0x%" PRIx64
                     " read offset=0x%" HWADDR_PRIx " size=%u phase=%u",
                     slot->offset, offset, size, slot->phase);
        exit(EXIT_FAILURE);
    }
    slot->phase++;
    if ((slot->index < 3 && slot->phase == 3) ||
        (slot->index == 3 && slot->phase == 8)) {
        fprintf(stderr,
                "darwin-pmgr: startup word range3+0x%" PRIx64
                " sequence complete result=0x%08x\n",
                slot->offset, slot->word);
    }
    return slot->word;
}

static void darwin_pmgr_startup_word_write(void *opaque, hwaddr offset,
                                            uint64_t value, unsigned size)
{
    DarwinPMGRStartupWord *slot = opaque;
    uint32_t expected = slot->word;
    bool valid_phase;

    if (slot->index < 3) {
        valid_phase = slot->phase == 1;
        expected &= ~UINT32_C(0x08000000);
    } else if (slot->index == 3) {
        valid_phase = slot->phase == 1 || slot->phase == 4 ||
                      slot->phase == 6;
        if (slot->phase == 1) {
            expected &= ~UINT32_C(0x80000000);
        } else if (slot->phase == 4) {
            expected |= UINT32_C(0x80000000);
        } else {
            expected &= ~UINT32_C(0x08000000);
        }
    } else {
        valid_phase = slot->phase == 1;
        expected |= UINT32_C(0x00200000);
    }

    if (offset != 0 || size != 4 || value > UINT32_MAX || !valid_phase ||
        value != expected) {
        error_report("darwin-pmgr: invalid startup word +0x%" PRIx64
                     " write offset=0x%" HWADDR_PRIx " value=0x%" PRIx64
                     " size=%u phase=%u prior=0x%08x expected=0x%08x",
                     slot->offset, offset, value, size, slot->phase,
                     slot->word, expected);
        exit(EXIT_FAILURE);
    }
    slot->word = expected;
    slot->phase++;
    if (slot->index == 4 && slot->phase == 2) {
        fprintf(stderr,
                "darwin-pmgr: startup word range3+0x%" PRIx64
                " sequence complete result=0x%08x\n",
                slot->offset, slot->word);
    }
}

static uint64_t darwin_pmgr_masked_tunable_read(void *opaque, hwaddr offset,
                                                 unsigned size)
{
    DarwinPMGRMaskedTunable *slot = opaque;

    if (offset != 0 || size != 4 || slot->phase != 0) {
        error_report("darwin-pmgr: invalid masked tunable range%u+0x%" PRIx64
                     " read offset=0x%" HWADDR_PRIx " size=%u phase=%u",
                     slot->reg_index, slot->offset, offset, size, slot->phase);
        exit(EXIT_FAILURE);
    }
    slot->phase = 1;
    return slot->word;
}

static void darwin_pmgr_masked_tunable_write(void *opaque, hwaddr offset,
                                              uint64_t value, unsigned size)
{
    DarwinPMGRMaskedTunable *slot = opaque;
    uint32_t expected = (slot->word & ~slot->mask) |
                        (slot->value & slot->mask);

    if (offset != 0 || size != 4 || value > UINT32_MAX ||
        slot->phase != 1 || value != expected) {
        error_report("darwin-pmgr: invalid masked tunable range%u+0x%" PRIx64
                     " write offset=0x%" HWADDR_PRIx " value=0x%" PRIx64
                     " size=%u phase=%u prior=0x%08x expected=0x%08x",
                     slot->reg_index, slot->offset, offset, value, size,
                     slot->phase,
                     slot->word, expected);
        exit(EXIT_FAILURE);
    }
    slot->word = expected;
    slot->phase = 2;
    fprintf(stderr,
            "darwin-pmgr: masked tunable range%u+0x%" PRIx64
            " applied mask=0x%08x value=0x%08x result=0x%08x\n",
            slot->reg_index, slot->offset, slot->mask, slot->value,
            slot->word);
}

static uint64_t darwin_pmgr_domain_state_read(void *opaque, hwaddr offset,
                                               unsigned size)
{
    DarwinPMGRDomainState *state = opaque;

    if (offset != 0 || size != 8 || state->phase == 1) {
        error_report("darwin-pmgr: invalid range%u state read offset=0x%"
                     HWADDR_PRIx " size=%u phase=%u", state->reg_index,
                     offset, size, state->phase);
        exit(EXIT_FAILURE);
    }
    if (state->phase == 0) {
        state->phase = 1;
    } else if (state->phase == 2) {
        state->phase = 3;
    } else if (state->phase == 3) {
        state->phase = 0;
    }
    return state->word;
}

static void darwin_pmgr_domain_state_write(void *opaque, hwaddr offset,
                                            uint64_t value, unsigned size)
{
    DarwinPMGRDomainState *state = opaque;
    const uint64_t mutable = UINT64_C(0x0200001f);

    if (offset != 0 || size != 8 || state->phase != 1 ||
        !(value & UINT64_C(0x02000000)) || (value & 0x1f) > 0xf ||
        ((value ^ state->word) & ~mutable)) {
        error_report("darwin-pmgr: invalid range%u state write offset=0x%"
                     HWADDR_PRIx " value=0x%" PRIx64
                     " size=%u phase=%u prior=0x%" PRIx64,
                     state->reg_index, offset, value, size, state->phase,
                     state->word);
        exit(EXIT_FAILURE);
    }
    state->word = value;
    state->phase = 2;
    fprintf(stderr,
            "darwin-pmgr: range%u state target=%u command bit25 stored;"
            " busy bit31 remains clear\n", state->reg_index,
            (unsigned)(value & 0x1f));
}

static uint64_t darwin_pmgr_config_selector_read(void *opaque, hwaddr offset,
                                                  unsigned size)
{
    DarwinPMGRConfigSelector *slot = opaque;

    if (offset != 0 || size != 4 || slot->phase == 1 || slot->phase == 4 ||
        (slot->phase == 3 && !slot->second_valid) || slot->phase > 5) {
        error_report("darwin-pmgr: invalid %s config word %u read"
                     " offset=0x%" HWADDR_PRIx " size=%u phase=%u",
                     slot->kind, slot->index, offset, size, slot->phase);
        exit(EXIT_FAILURE);
    }
    if (slot->phase == 0 || slot->phase == 2 || slot->phase == 3 ||
        slot->phase == 5) {
        slot->phase++;
    }
    return slot->word;
}

static void darwin_pmgr_config_selector_write(void *opaque, hwaddr offset,
                                               uint64_t value, unsigned size)
{
    DarwinPMGRConfigSelector *slot = opaque;
    uint32_t word = value;

    /*
     * The common helper inserts the prior selector nibble [23:20], writes its
     * caller-computed value, and then polls bit 30.  Preserve that exact
     * request.  Since the request leaves bit 30 clear, no independent
     * completion response is synthesized.  Some descriptor subtypes assert
     * bit 31 and others do not, so bit 31 is deliberately not generalized
     * into a protocol requirement here.
     */
    if (offset != 0 || size != 4 || value != word ||
        (slot->phase != 1 && slot->phase != 4) ||
        (word & UINT32_C(0x40000000)) ||
        (word & UINT32_C(0x00f00000)) !=
        (slot->word & UINT32_C(0x00f00000)) ||
        (slot->phase == 4 &&
         (!slot->second_valid || word != slot->second_value))) {
        error_report("darwin-pmgr: invalid %s config word %u write"
                     " offset=0x%" HWADDR_PRIx " value=0x%" PRIx64
                     " size=%u phase=%u prior=0x%08x",
                     slot->kind, slot->index, offset, value, size, slot->phase,
                     slot->word);
        exit(EXIT_FAILURE);
    }
    slot->word = word;
    slot->phase++;
    fprintf(stderr,
            "darwin-pmgr: %s config word %u request=0x%08x stored;"
            " polled busy bit30 is clear and selector[27:24]=%u\n",
            slot->kind, slot->index, word, (word >> 24) & 0xf);
}

static uint64_t darwin_pmgr_topology_block_read(void *opaque, hwaddr offset,
                                                 unsigned size)
{
    DarwinPMGRTopologyBlock *block = opaque;
    static const uint8_t post_count[] = { 3, 1, 3, 3, 3, 1 };
    static const uint8_t post_offsets[] = { 0, 0xc, 0x10 };
    unsigned count;
    unsigned record;

    if (size != 4 || (offset != 0 && offset != 4 && offset != 8 &&
                      offset != 0xc && offset != 0x10)) {
        error_report("darwin-pmgr: invalid topology block %u read"
                     " offset=0x%" HWADDR_PRIx " size=%u",
                     block->index, offset, size);
        exit(EXIT_FAILURE);
    }
    if (block->phase == 11) {
        count = post_count[block->index - D47_PMGR_TOPOLOGY_BLOCK_FIRST];
        if (block->post_step < count * 2) {
            record = block->post_step / 2;
            if ((block->post_step & 1) ||
                offset != post_offsets[record]) {
                goto invalid_read;
            }
            block->post_step++;
            return block->words[offset / 4];
        }
        if ((block->power_step == 0 && offset == 8) ||
            (block->power_step == 2 && offset == 0) ||
            (block->power_step == 4 && offset == 4) ||
            (block->power_step == 6 && offset == 0)) {
            block->power_step++;
            if (block->power_step == 7) {
                fprintf(stderr,
                        "darwin-pmgr: topology power block %u exact request"
                        " complete; polled bit31 is clear\n", block->index);
            }
            return block->words[offset / 4];
        }
        goto invalid_read;
    }
    if ((block->phase == 0 && offset == 4) ||
        ((block->phase == 2 || block->phase == 3 || block->phase == 5 ||
          block->phase == 7) && offset == 0)) {
        block->phase++;
        return block->words[offset / 4];
    }
invalid_read:
    error_report("darwin-pmgr: unexpected topology block %u read"
                 " offset=0x%" HWADDR_PRIx " phase=%u pc=0x%" PRIx64,
                 block->index, offset, block->phase,
                 current_cpu ? ARM_CPU(current_cpu)->env.pc : 0);
    exit(EXIT_FAILURE);
}

static void darwin_pmgr_topology_block_write(void *opaque, hwaddr offset,
                                              uint64_t value, unsigned size)
{
    DarwinPMGRTopologyBlock *block = opaque;
    static const uint8_t post_count[] = { 3, 1, 3, 3, 3, 1 };
    static const uint8_t post_offsets[] = { 0, 0xc, 0x10 };
    static const uint32_t post_masks[][3] = {
        { 0x00070000, 0x0003ffc0, 0xffffc000 },
        { 0x00050000, 0, 0 },
        { 0x00050000, 0x0003ffc0, 0xffffc000 },
        { 0x00350000, 0x0003ffc0, 0xffffc000 },
        { 0x00050000, 0x0003ffc0, 0xffffc000 },
        { 0x00050000, 0, 0 },
    };
    static const uint32_t post_values[][3] = {
        { 0x00070000, 0x0000a900, 0x25900000 },
        { 0x00050000, 0, 0 },
        { 0x00050000, 0x0000c900, 0x29668000 },
        { 0x00050000, 0x00008900, 0x24b00000 },
        { 0x00050000, 0x0000ca40, 0x27708000 },
        { 0x00050000, 0, 0 },
    };
    uint32_t expected;
    unsigned array_index;
    unsigned count;
    unsigned record;

    if (size != 4 || value > UINT32_MAX || (offset & 3) || offset > 0x10) {
        error_report("darwin-pmgr: invalid topology block %u write"
                     " offset=0x%" HWADDR_PRIx " value=0x%" PRIx64
                     " size=%u", block->index, offset, value, size);
        exit(EXIT_FAILURE);
    }
    if (block->phase == 11) {
        array_index = block->index - D47_PMGR_TOPOLOGY_BLOCK_FIRST;
        count = post_count[array_index];
        if (block->post_step < count * 2) {
            record = block->post_step / 2;
            if (!(block->post_step & 1) ||
                offset != post_offsets[record]) {
                goto invalid_sequence;
            }
            expected = (block->words[offset / 4] &
                        ~post_masks[array_index][record]) |
                       (post_values[array_index][record] &
                        post_masks[array_index][record]);
            if (value != expected) {
                goto invalid_sequence;
            }
            block->words[offset / 4] = expected;
            block->post_step++;
            if (block->post_step == count * 2) {
                fprintf(stderr,
                        "darwin-pmgr: topology block %u signed tuning phase"
                        " complete\n", block->index);
            }
            return;
        }

        if (block->power_step == 1 && offset == 8) {
            expected = block->words[2] | UINT32_C(0x80000001);
        } else if (block->power_step == 3 && offset == 0) {
            expected = (block->words[0] & ~UINT32_C(7)) | 1;
        } else if (block->power_step == 5 && offset == 4) {
            expected = block->words[1] & ~UINT32_C(1);
        } else {
            goto invalid_sequence;
        }
        if (value != expected) {
            goto invalid_sequence;
        }
        block->words[offset / 4] = expected;
        block->power_step++;
        return;
    }
    switch (block->phase) {
    case 1:
        expected = block->words[1] | UINT32_C(1);
        if (offset != 4 || value != expected) {
            goto invalid_sequence;
        }
        block->words[1] = expected;
        break;
    case 4:
        expected = block->words[0] | UINT32_C(1);
        if (offset != 0 || value != expected) {
            goto invalid_sequence;
        }
        block->words[0] = expected;
        break;
    case 6:
        expected = block->words[0] | UINT32_C(2);
        if (offset != 0 || value != expected) {
            goto invalid_sequence;
        }
        block->words[0] = expected;
        break;
    case 8:
        expected = block->words[0] | UINT32_C(4);
        if (offset != 0 || value != expected) {
            goto invalid_sequence;
        }
        block->words[0] = expected;
        break;
    case 9:
        if (offset != 0xc || value != 0) {
            goto invalid_sequence;
        }
        block->words[3] = 0;
        break;
    case 10:
        if (offset != 0x10 || value != 0) {
            goto invalid_sequence;
        }
        block->words[4] = 0;
        break;
    default:
        goto invalid_sequence;
    }
    block->phase++;
    if (block->phase == 11) {
        fprintf(stderr,
                "darwin-pmgr: topology block %u exact setup complete"
                " words=(0x%08x,0x%08x,0,0)\n",
                block->index, block->words[0], block->words[1]);
    }
    return;

invalid_sequence:
    error_report("darwin-pmgr: unexpected topology block %u write"
                 " offset=0x%" HWADDR_PRIx " value=0x%" PRIx64
                 " phase=%u pc=0x%" PRIx64, block->index, offset, value,
                 block->phase,
                 current_cpu ? ARM_CPU(current_cpu)->env.pc : 0);
    exit(EXIT_FAILURE);
}

static uint64_t darwin_pmgr_range2_signed_read(void *opaque, hwaddr offset,
                                                unsigned size)
{
    DarwinPMGRRange2SignedTuning *tuning = opaque;
    unsigned record = tuning->step / 2;

    if (size != 4 || tuning->step >= 2 * D47_PMGR_RANGE2_SIGNED_COUNT ||
        (tuning->step & 1) ||
        offset != d47_range2_signed_offsets[record]) {
        error_report("darwin-pmgr: invalid range2 signed-table read"
                     " offset=0x%" HWADDR_PRIx " size=%u step=%u",
                     offset, size, tuning->step);
        exit(EXIT_FAILURE);
    }
    tuning->step++;
    return tuning->words[record];
}

static void darwin_pmgr_range2_signed_write(void *opaque, hwaddr offset,
                                             uint64_t value, unsigned size)
{
    DarwinPMGRRange2SignedTuning *tuning = opaque;
    unsigned record = tuning->step / 2;
    uint32_t expected;

    if (size != 4 || value > UINT32_MAX ||
        tuning->step >= 2 * D47_PMGR_RANGE2_SIGNED_COUNT ||
        !(tuning->step & 1) ||
        offset != d47_range2_signed_offsets[record]) {
        goto invalid_write;
    }
    expected = (tuning->words[record] &
                ~d47_range2_signed_masks[record]) |
               (d47_range2_signed_values[record] &
                d47_range2_signed_masks[record]);
    if (value != expected) {
        goto invalid_write;
    }
    tuning->words[record] = expected;
    tuning->step++;
    if (tuning->step == 2 * D47_PMGR_RANGE2_SIGNED_COUNT) {
        tuning->complete = true;
        fprintf(stderr,
                "darwin-pmgr: sixteen range2 signed-table RMW records"
                " complete through +0x40040\n");
    }
    return;

invalid_write:
    error_report("darwin-pmgr: invalid range2 signed-table write"
                 " offset=0x%" HWADDR_PRIx " value=0x%" PRIx64
                 " size=%u step=%u", offset, value, size, tuning->step);
    exit(EXIT_FAILURE);
}

static uint64_t darwin_pmgr_topology_selector_read(void *opaque,
                                                    hwaddr offset,
                                                    unsigned size)
{
    DarwinPMGRTopologySelector *slot = opaque;

    if (offset != 0 || size != 4 || slot->tuned ||
        (slot->tuning_ready && *slot->tuning_ready && slot->tuning_read)) {
        error_report("darwin-pmgr: invalid topology selector 0x%x read"
                     " offset=0x%" HWADDR_PRIx
                     " size=%u tuning-read=%u tuned=%u",
                     slot->descriptor_id, offset, size, slot->tuning_read,
                     slot->tuned);
        exit(EXIT_FAILURE);
    }
    if (slot->tuning_ready && *slot->tuning_ready) {
        slot->tuning_read = true;
        return slot->word;
    }
    if (!slot->observed) {
        fprintf(stderr,
                "darwin-pmgr: descriptor 0x%x topology selector"
                " range2+0x%" PRIx64 "=0; firmware path returns -1"
                " (no harvested VM block)\n",
                slot->descriptor_id, slot->offset);
        slot->observed = true;
    }
    return slot->word;
}

static void darwin_pmgr_topology_selector_write(void *opaque, hwaddr offset,
                                                 uint64_t value,
                                                 unsigned size)
{
    DarwinPMGRTopologySelector *slot = opaque;

    if (slot->descriptor_id == 0x64 && slot->tuning_ready &&
        *slot->tuning_ready && slot->tuning_read && !slot->tuned &&
        offset == 0 && size == 4 && value == UINT32_C(0x05000000)) {
        slot->word = value;
        slot->tuned = true;
        fprintf(stderr,
                "darwin-pmgr: descriptor 0x64 final range2 RMW stored"
                " value=0x%08x\n", slot->word);
        return;
    }
    error_report("darwin-pmgr: unexpected topology selector 0x%x write"
                 " offset=0x%" HWADDR_PRIx " value=0x%" PRIx64
                 " size=%u ready=%u tuning-read=%u tuned=%u",
                 slot->descriptor_id, offset, value, size,
                 slot->tuning_ready ? *slot->tuning_ready : 0,
                 slot->tuning_read, slot->tuned);
    exit(EXIT_FAILURE);
}

static uint64_t darwin_pmgr_stepped_state_read(void *opaque, hwaddr offset,
                                               unsigned size)
{
    DarwinPMGRIboot *s = opaque;

    if (offset != 0 || size != 4) {
        error_report("darwin-pmgr: invalid stepped-state read offset=0x%"
                     HWADDR_PRIx " size=%u", offset, size);
        exit(EXIT_FAILURE);
    }
    return s->stepped_state;
}

static void darwin_pmgr_stepped_state_write(void *opaque, hwaddr offset,
                                            uint64_t value, unsigned size)
{
    DarwinPMGRIboot *s = opaque;
    uint32_t actual = (s->stepped_state >> 8) & 0xf;

    if (offset != 0 || size != 4 || value > 0xf ||
        (value != actual + 1 && value + 1 != actual)) {
        error_report("darwin-pmgr: invalid stepped-state write offset=0x%"
                     HWADDR_PRIx " value=0x%" PRIx64 " size=%u actual=%u",
                     offset, value, size, actual);
        exit(EXIT_FAILURE);
    }
    s->stepped_state = (uint32_t)value | ((uint32_t)value << 8);
    fprintf(stderr,
            "darwin-pmgr: stepped-state target/actual advanced to %u with"
            " busy bit31 clear\n", (unsigned)value);
}

static uint64_t darwin_pmgr_perf_state_read(void *opaque, hwaddr offset,
                                            unsigned size)
{
    DarwinPMGRBoundedState *slot = opaque;

    if (offset != 0 || size != 4) {
        error_report("darwin-pmgr: invalid perf-state read offset=0x%"
                     HWADDR_PRIx " size=%u", offset, size);
        exit(EXIT_FAILURE);
    }
    return slot->word;
}

static void darwin_pmgr_perf_state_write(void *opaque, hwaddr offset,
                                         uint64_t value, unsigned size)
{
    DarwinPMGRBoundedState *slot = opaque;

    if (offset != 0 || size != 4 || value > slot->max) {
        error_report("darwin-pmgr: invalid perf-state write offset=0x%"
                     HWADDR_PRIx " value=0x%" PRIx64 " size=%u",
                     offset, value, size);
        exit(EXIT_FAILURE);
    }
    slot->word = value;
    fprintf(stderr,
            "darwin-pmgr: bounded state range2+0x%" PRIx64
            " request=%u stored with busy bit31 clear\n",
            slot->offset, slot->word);
}

static uint64_t darwin_pmgr_poll_clear_read(void *opaque, hwaddr offset,
                                            unsigned size)
{
    DarwinPMGRPollClear *slot = opaque;

    if (offset != 0 || size != 4 ||
        (slot->phase != 1 && slot->phase != 2 && slot->phase != 4)) {
        error_report("darwin-pmgr: invalid poll-clear-%u read offset=0x%"
                     HWADDR_PRIx " size=%u phase=%u", slot->index,
                     offset, size, slot->phase);
        exit(EXIT_FAILURE);
    }
    slot->phase++;
    return slot->word;
}

static void darwin_pmgr_poll_clear_write(void *opaque, hwaddr offset,
                                         uint64_t value, unsigned size)
{
    DarwinPMGRPollClear *slot = opaque;

    if (offset != 0 || size != 4 ||
        !((slot->phase == 0 && value == 0) ||
          (slot->phase == 3 && value == UINT32_C(0x21000000)))) {
        error_report("darwin-pmgr: invalid poll-clear-%u write offset=0x%"
                     HWADDR_PRIx " value=0x%" PRIx64 " size=%u phase=%u",
                     slot->index, offset, value, size, slot->phase);
        exit(EXIT_FAILURE);
    }
    slot->word = value;
    slot->phase++;
    fprintf(stderr,
            "darwin-pmgr: poll-clear-%u stored request 0x%08x;"
            " bit30 remains clear\n", slot->index, slot->word);
}

static uint64_t darwin_pmgr_zero_read(void *opaque, hwaddr offset,
                                      unsigned size)
{
    error_report("darwin-pmgr: unexpected read from write-only zero sink"
                 " offset=0x%" HWADDR_PRIx " size=%u", offset, size);
    exit(EXIT_FAILURE);
}

static void darwin_pmgr_zero_write(void *opaque, hwaddr offset,
                                   uint64_t value, unsigned size)
{
    if (offset != 0 || size != 4 || value != 0) {
        error_report("darwin-pmgr: invalid write-only zero-sink access"
                     " offset=0x%" HWADDR_PRIx " value=0x%" PRIx64
                     " size=%u", offset, value, size);
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, "darwin-pmgr: validated platform-reset zero write\n");
}

static uint64_t darwin_pmgr_platform_flags_read(void *opaque, hwaddr offset,
                                                unsigned size)
{
    DarwinPMGRIboot *s = opaque;

    if (size != 4 || (offset & 3) ||
        offset / 4 >= D47_PMGR_PLATFORM_FLAGS_COUNT) {
        error_report("darwin-pmgr: invalid platform-flags read offset=0x%"
                     HWADDR_PRIx " size=%u", offset, size);
        exit(EXIT_FAILURE);
    }
    return s->platform_flags[offset / 4];
}

static void darwin_pmgr_platform_flags_write(void *opaque, hwaddr offset,
                                             uint64_t value, unsigned size)
{
    DarwinPMGRIboot *s = opaque;
    uint32_t word = value;
    unsigned index;

    if (value != word || size != 4 || (offset & 3) ||
        offset / 4 >= D47_PMGR_PLATFORM_FLAGS_COUNT) {
        error_report("darwin-pmgr: invalid platform-flags write offset=0x%"
                     HWADDR_PRIx " value=0x%" PRIx64 " size=%u",
                     offset, value, size);
        exit(EXIT_FAILURE);
    }
    index = offset / 4;
    if (word != (s->platform_flags[index] | UINT32_C(1))) {
        error_report("darwin-pmgr: platform flag %u write 0x%08x is not the"
                     " evidenced bit0 set of 0x%08x", index, word,
                     s->platform_flags[index]);
        exit(EXIT_FAILURE);
    }
    s->platform_flags[index] = word;
    fprintf(stderr, "darwin-pmgr: platform flag %u bit0 set\n", index);
}

static uint64_t darwin_pmgr_handshake_control_read(void *opaque,
                                                   hwaddr offset,
                                                   unsigned size)
{
    DarwinPMGRHandshake *channel = opaque;

    if (offset != 0 || size != 4) {
        error_report("darwin-pmgr: invalid handshake-%u control read"
                     " offset=0x%" HWADDR_PRIx " size=%u", channel->index,
                     offset, size);
        exit(EXIT_FAILURE);
    }
    return channel->control;
}

static void darwin_pmgr_handshake_control_write(void *opaque, hwaddr offset,
                                                 uint64_t value,
                                                 unsigned size)
{
    DarwinPMGRHandshake *channel = opaque;
    uint32_t word = value;

    if (value != word || offset != 0 || size != 4 ||
        word != (channel->control & ~UINT32_C(1))) {
        error_report("darwin-pmgr: invalid handshake-%u control write"
                     " offset=0x%" HWADDR_PRIx " value=0x%" PRIx64
                     " size=%u (prior=0x%08x)", channel->index, offset,
                     value, size, channel->control);
        exit(EXIT_FAILURE);
    }
    channel->control = word;
    channel->status |= UINT32_C(1);
    fprintf(stderr,
            "darwin-pmgr: handshake-%u validated control bit0 clear;"
            " status bit0 transitioned to 1\n", channel->index);
}

static uint64_t darwin_pmgr_handshake_status_read(void *opaque,
                                                  hwaddr offset,
                                                  unsigned size)
{
    DarwinPMGRHandshake *channel = opaque;

    if (offset != 0 || size != 4) {
        error_report("darwin-pmgr: invalid handshake-%u status read"
                     " offset=0x%" HWADDR_PRIx " size=%u", channel->index,
                     offset, size);
        exit(EXIT_FAILURE);
    }
    return channel->status;
}

static void darwin_pmgr_handshake_status_write(void *opaque, hwaddr offset,
                                                uint64_t value,
                                                unsigned size)
{
    DarwinPMGRHandshake *channel = opaque;

    error_report("darwin-pmgr: unexpected handshake-%u status write"
                 " offset=0x%" HWADDR_PRIx " value=0x%" PRIx64
                 " size=%u", channel->index, offset, value, size);
    exit(EXIT_FAILURE);
}

static uint64_t darwin_pmgr_cpu_ready_read(void *opaque, hwaddr offset,
                                           unsigned size)
{
    DarwinPMGRIboot *s = opaque;

    if (size != 4 || (offset != 0 && offset != 4)) {
        error_report("darwin-pmgr: invalid CPU-ready read offset=0x%"
                     HWADDR_PRIx " size=%u", offset, size);
        exit(EXIT_FAILURE);
    }
    return s->cpu_ready[offset / 4];
}

static void darwin_pmgr_cpu_ready_write(void *opaque, hwaddr offset,
                                        uint64_t value, unsigned size)
{
    DarwinPMGRIboot *s = opaque;
    uint32_t word = value;
    unsigned index;

    if (value != word || size != 4 || (offset != 0 && offset != 4)) {
        error_report("darwin-pmgr: invalid CPU-ready write offset=0x%"
                     HWADDR_PRIx " value=0x%" PRIx64 " size=%u",
                     offset, value, size);
        exit(EXIT_FAILURE);
    }
    index = offset / 4;
    if (word != (s->cpu_ready[index] & ~D47_PMGR_CPU_READY_CLEAR)) {
        error_report("darwin-pmgr: CPU-ready write 0x%08x is not the"
                     " evidenced bits[4,1] clear of 0x%08x", word,
                     s->cpu_ready[index]);
        exit(EXIT_FAILURE);
    }
    s->cpu_ready[index] = word;
    fprintf(stderr,
            "darwin-pmgr: CPU-ready word +0x%x cleared bits[4,1];"
            " polled bits[5,0]=0x%x\n", index * 4,
            word & UINT32_C(0x21));
}

static uint64_t darwin_pmgr_state_read(void *opaque, hwaddr offset,
                                       unsigned size)
{
    DarwinPMGRStateSlot *slot = opaque;

    if (size != 4 || offset != 0) {
        error_report("darwin-pmgr: invalid %s state read offset=0x%"
                     HWADDR_PRIx " size=%u", slot->name, offset, size);
        exit(EXIT_FAILURE);
    }
    return slot->state;
}

static void darwin_pmgr_state_write(void *opaque, hwaddr offset,
                                    uint64_t value, unsigned size)
{
    DarwinPMGRStateSlot *slot = opaque;
    uint32_t word = value;
    uint32_t target;

    if (size != 4 || offset != 0) {
        error_report("darwin-pmgr: invalid %s state write offset=0x%"
                     HWADDR_PRIx " value=0x%" PRIx64 " size=%u", slot->name,
                     offset, value, size);
        exit(EXIT_FAILURE);
    }
    if (value != word ||
        (word & D47_PMGR_STATE_ACTUAL_MASK) !=
        (slot->state & D47_PMGR_STATE_ACTUAL_MASK) ||
        ((word ^ slot->state) &
         ~(D47_PMGR_STATE_CONTROL_MASK | D47_PMGR_STATE_ACTUAL_MASK))) {
        error_report("darwin-pmgr: invalid %s state write value=0x%" PRIx64,
                     slot->name, value);
        exit(EXIT_FAILURE);
    }
    target = word & D47_PMGR_STATE_TARGET_MASK;
    slot->state = (word & ~D47_PMGR_STATE_ACTUAL_MASK) | (target << 4);
    fprintf(stderr,
            "darwin-pmgr: %s range%u+0x%" PRIx64
            " target=%u actual=%u raw=0x%08x\n",
            slot->name, slot->reg_index, slot->offset, target,
            (slot->state & D47_PMGR_STATE_ACTUAL_MASK) >> 4, slot->state);
}

static uint64_t darwin_pmgr_identity_read(void *opaque, hwaddr offset,
                                          unsigned size)
{
    if (offset != 0 || size != 4) {
        error_report("darwin-pmgr: invalid identity read offset=0x%"
                     HWADDR_PRIx " size=%u", offset, size);
        exit(EXIT_FAILURE);
    }
    return D47_PMGR_IDENTITY_RAW;
}

static void darwin_pmgr_identity_write(void *opaque, hwaddr offset,
                                       uint64_t value, unsigned size)
{
    error_report("darwin-pmgr: unexpected identity write offset=0x%"
                 HWADDR_PRIx " value=0x%" PRIx64 " size=%u",
                 offset, value, size);
    exit(EXIT_FAILURE);
}

static uint64_t darwin_board_id_low_read(void *opaque, hwaddr offset,
                                         unsigned size)
{
    if (offset != 0 || size != 4) {
        error_report("darwin-pmgr: invalid board-id-low read offset=0x%"
                     HWADDR_PRIx " size=%u", offset, size);
        exit(EXIT_FAILURE);
    }
    return D47_BOARD_ID_LOW;
}

static void darwin_board_id_low_write(void *opaque, hwaddr offset,
                                      uint64_t value, unsigned size)
{
    error_report("darwin-pmgr: unexpected board-id-low write offset=0x%"
                 HWADDR_PRIx " value=0x%" PRIx64 " size=%u",
                 offset, value, size);
    exit(EXIT_FAILURE);
}

static uint64_t darwin_pmgr_cpfm_read(void *opaque, hwaddr offset,
                                      unsigned size)
{
    DarwinPMGRIboot *s = opaque;

    if (size != 4 || (offset != 0 && offset != 4)) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "darwin-pmgr: invalid CPFM read offset=0x%"
                      HWADDR_PRIx " size=%u\n", offset, size);
        return 0;
    }
    return s->cpfm[offset / 4];
}

static void darwin_pmgr_cpfm_write(void *opaque, hwaddr offset,
                                   uint64_t value, unsigned size)
{
    qemu_log_mask(LOG_GUEST_ERROR,
                  "darwin-pmgr: unexpected CPFM write offset=0x%"
                  HWADDR_PRIx " value=0x%" PRIx64 " size=%u\n",
                  offset, value, size);
}

static uint64_t darwin_pmgr_chip_revision_read(void *opaque, hwaddr offset,
                                               unsigned size)
{
    DarwinPMGRIboot *s = opaque;

    if (offset != 0 || size != 4) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "darwin-pmgr: invalid chip-revision read offset=0x%"
                      HWADDR_PRIx " size=%u\n", offset, size);
        return 0;
    }
    return s->chip_revision_raw;
}

static void darwin_pmgr_chip_revision_write(void *opaque, hwaddr offset,
                                            uint64_t value, unsigned size)
{
    qemu_log_mask(LOG_GUEST_ERROR,
                  "darwin-pmgr: unexpected chip-revision write offset=0x%"
                  HWADDR_PRIx " value=0x%" PRIx64 " size=%u\n",
                  offset, value, size);
}

static uint64_t darwin_pmgr_start_latch_read(void *opaque, hwaddr offset,
                                             unsigned size)
{
    DarwinPMGRIboot *s = opaque;

    if (offset != 0 || size != 4) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "darwin-pmgr: invalid start-latch read offset=0x%"
                      HWADDR_PRIx " size=%u\n", offset, size);
        return 0;
    }
    return s->start_latch;
}

static void darwin_pmgr_start_latch_write(void *opaque, hwaddr offset,
                                          uint64_t value, unsigned size)
{
    DarwinPMGRIboot *s = opaque;
    uint32_t word = value;

    if (offset != 0 || size != 4 ||
        (word & ~D47_PMGR_START_LATCH_ENABLE) !=
        (s->start_latch & ~D47_PMGR_START_LATCH_ENABLE)) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "darwin-pmgr: invalid start-latch write offset=0x%"
                      HWADDR_PRIx " value=0x%" PRIx64 " size=%u\n",
                      offset, value, size);
        return;
    }
    s->start_latch = word;
    fprintf(stderr, "darwin-pmgr: start latch bit7=%u\n",
            !!(word & D47_PMGR_START_LATCH_ENABLE));
}

static const MemoryRegionOps darwin_pmgr_start_latch_ops = {
    .read = darwin_pmgr_start_latch_read,
    .write = darwin_pmgr_start_latch_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

static const MemoryRegionOps darwin_board_id_low_ops = {
    .read = darwin_board_id_low_read,
    .write = darwin_board_id_low_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

static const MemoryRegionOps darwin_pmgr_cpu_ready_ops = {
    .read = darwin_pmgr_cpu_ready_read,
    .write = darwin_pmgr_cpu_ready_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

static const MemoryRegionOps darwin_pmgr_handshake_control_ops = {
    .read = darwin_pmgr_handshake_control_read,
    .write = darwin_pmgr_handshake_control_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

static const MemoryRegionOps darwin_pmgr_handshake_status_ops = {
    .read = darwin_pmgr_handshake_status_read,
    .write = darwin_pmgr_handshake_status_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

static const MemoryRegionOps darwin_pmgr_platform_flags_ops = {
    .read = darwin_pmgr_platform_flags_read,
    .write = darwin_pmgr_platform_flags_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

static const MemoryRegionOps darwin_pmgr_zero_ops = {
    .read = darwin_pmgr_zero_read,
    .write = darwin_pmgr_zero_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

static const MemoryRegionOps darwin_pmgr_poll_clear_ops = {
    .read = darwin_pmgr_poll_clear_read,
    .write = darwin_pmgr_poll_clear_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

static const MemoryRegionOps darwin_pmgr_perf_state_ops = {
    .read = darwin_pmgr_perf_state_read,
    .write = darwin_pmgr_perf_state_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

static const MemoryRegionOps darwin_pmgr_stepped_state_ops = {
    .read = darwin_pmgr_stepped_state_read,
    .write = darwin_pmgr_stepped_state_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

static const MemoryRegionOps darwin_pmgr_topology_selector_ops = {
    .read = darwin_pmgr_topology_selector_read,
    .write = darwin_pmgr_topology_selector_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

static const MemoryRegionOps darwin_pmgr_range2_signed_ops = {
    .read = darwin_pmgr_range2_signed_read,
    .write = darwin_pmgr_range2_signed_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

static const MemoryRegionOps darwin_pmgr_range2_signed_cont_ops = {
    .read = darwin_pmgr_range2_signed_cont_read,
    .write = darwin_pmgr_range2_signed_cont_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

static const MemoryRegionOps darwin_pmgr_topology_block_ops = {
    .read = darwin_pmgr_topology_block_read,
    .write = darwin_pmgr_topology_block_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

static const MemoryRegionOps darwin_pmgr_config_selector_ops = {
    .read = darwin_pmgr_config_selector_read,
    .write = darwin_pmgr_config_selector_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

static const MemoryRegionOps darwin_pmgr_domain_state_ops = {
    .read = darwin_pmgr_domain_state_read,
    .write = darwin_pmgr_domain_state_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 8,
    .impl.max_access_size = 8,
    .valid.min_access_size = 8,
    .valid.max_access_size = 8,
    .valid.unaligned = false,
};

static const MemoryRegionOps darwin_pmgr_masked_tunable_ops = {
    .read = darwin_pmgr_masked_tunable_read,
    .write = darwin_pmgr_masked_tunable_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

static const MemoryRegionOps darwin_pmgr_startup_word_ops = {
    .read = darwin_pmgr_startup_word_read,
    .write = darwin_pmgr_startup_word_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

static const MemoryRegionOps darwin_pmgr_tuning_fuse_ops = {
    .read = darwin_pmgr_tuning_fuse_read,
    .write = darwin_pmgr_tuning_fuse_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

static const MemoryRegionOps darwin_pmgr_root_zero_ops = {
    .read = darwin_pmgr_root_zero_read,
    .write = darwin_pmgr_root_zero_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

static const MemoryRegionOps darwin_pmgr_mcc_config_ops = {
    .read = darwin_pmgr_mcc_config_read,
    .write = darwin_pmgr_mcc_config_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

static const MemoryRegionOps darwin_pmgr_mcc_tunable_ops = {
    .read = darwin_pmgr_mcc_tunable_read,
    .write = darwin_pmgr_mcc_tunable_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

static const MemoryRegionOps darwin_pmgr_state_ops = {
    .read = darwin_pmgr_state_read,
    .write = darwin_pmgr_state_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

static const MemoryRegionOps darwin_pmgr_chip_revision_ops = {
    .read = darwin_pmgr_chip_revision_read,
    .write = darwin_pmgr_chip_revision_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

static const MemoryRegionOps darwin_pmgr_identity_ops = {
    .read = darwin_pmgr_identity_read,
    .write = darwin_pmgr_identity_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

static const MemoryRegionOps darwin_pmgr_cpfm_ops = {
    .read = darwin_pmgr_cpfm_read,
    .write = darwin_pmgr_cpfm_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

void darwin_pmgr_iboot_init(struct dtree_node *dt_root, uint64_t iobase)
{
    struct dtree_node *pmgr = adt_find_node(dt_root, "arm-io/pmgr");
    struct adt_io_reg *regs;
    const DarwinPMGRDevice *devices;
    const uint8_t *ps_groups;
    size_t count;
    size_t device_count;
    size_t ps_group_count;
    size_t i;
    size_t j;
    DarwinPMGRIboot *s;
    uint64_t pa;
    const char *revision_env = getenv("DARWIN_IBOOT_CHIP_REVISION");
    const char *cpfm_env = getenv("DARWIN_IBOOT_CPFM");
    const char *no_harvest_env = getenv("DARWIN_IBOOT_PMGR_NO_HARVEST");
    const char *tuning_bin_env = getenv("DARWIN_IBOOT_PMGR_TUNING_BIN");
    unsigned revision;
    unsigned cpfm;
    static const uint64_t bounded_state_offsets[] = {
        0x58000, 0x60000, 0x64000,
    };
    static const uint32_t bounded_state_max[] = {
        0xf, 0xf, 0x7,
    };
    static const uint64_t topology_selector_offsets[] = {
        0x40044, 0x400bc, 0x400c0,
    };
    static const uint32_t topology_descriptor_ids[] = {
        0x64, 0x82, 0x83,
    };
    static const unsigned domain_state_reg_indices[] = {
        5, 14,
    };
    static const uint64_t masked_tunable_offsets[] = {
        0x2004, 0x400c, 0x4010, 0x3c000, 0x4032c,
        0x44004,
        0x52004, 0x52008, 0x5200c, 0x52010,
        0x56004, 0x56008, 0x5600c, 0x56010,
        0x5a004, 0x5a008, 0x5a00c, 0x5a010,
        0x5e004, 0x5e008, 0x5e00c, 0x5e010,
        0x62004, 0x62008, 0x6200c, 0x62010,
    };
    static const uint32_t masked_tunable_masks[] = {
        0x0003ffff, 0x3f0703ff, 0xc0ffffff, 0x00000001,
        0x0000003f,
        0x000000ff,
        0x00001fff, 0xffffffff, 0xffffffff, 0xffffffff,
        0x00001fff, 0xffffffff, 0xffffffff, 0xffffffff,
        0x00001fff, 0xffffffff, 0xffffffff, 0xffffffff,
        0x00001fff, 0xffffffff, 0xffffffff, 0xffffffff,
        0x00001fff, 0xffffffff, 0xffffffff, 0xffffffff,
    };
    static const uint32_t masked_tunable_values[] = {
        0x00000120, 0x0000000f, 0x00000000, 0x00000001,
        0x00000010,
        0x00000010,
        0x00000e51, 0x000ca2dd, 0xfffd609d, 0x7ffd609d,
        0x0000122b, 0x000a037a, 0xfffac13a, 0x7ffac13a,
        0x00001afa, 0x00061fd1, 0xfff6dd91, 0x7ff6dd91,
        0x00000fe7, 0x0004c4b4, 0xfff58274, 0x7ff58274,
        0x0000023c, 0x000c3fa1, 0xfffcfd61, 0x7ffcfd61,
    };
    static const uint64_t startup_word_offsets[] = {
        0x0000, 0x2000, 0x4000, 0x6000, 0x6004,
    };
    static const uint64_t soc_tunable_offsets[] = {
        0x70204, 0x70248,
        0x71204, 0x71248,
        0x72204,
        0x73204, 0x73248,
        0x74204, 0x74248,
        0x75204, 0x75248,
        0x76204,
    };
    static const uint32_t soc_tunable_masks[] = {
        0x00007300, 0x0ffffff7,
        0x00007300, 0x0ffffff7,
        0x00007300,
        0x00007300, 0x0ffffff7,
        0x00007300, 0x0ffffff7,
        0x00007300, 0x0ffffff7,
        0x00007300,
    };
    static const uint32_t soc_tunable_values[] = {
        0x00000000, 0x01681680,
        0x00000000, 0x00c00c00,
        0x00000000,
        0x00000000, 0x00c00c00,
        0x00000000, 0x00b40b40,
        0x00000000, 0x01091090,
        0x00000000,
    };
    static const uint64_t mcc_tunable_offsets[] = { 0x8204, 0x8250 };
    static const uint32_t mcc_tunable_masks[] = {
        0x00007300, 0x0ffffff7,
    };
    static const uint32_t mcc_tunable_values[] = {
        0x00000000, 0x01d31d30,
    };
    static const uint32_t range3_second_requests[
        D47_PMGR_RANGE3_CONFIG_COUNT] = {
        [0] = 0x83000000,
        [1] = 0x84000000,
        [2] = 0x83000000,
        [3] = 0x84000000,
        [6] = 0x80000000,
        [7] = 0x81000000,
        [13] = 0x81000000,
        [14] = 0x81000000,
        [23] = 0x82000000,
        [25] = 0x82000000,
        [29] = 0x81000000,
        [30] = 0x90000000,
        [31] = 0x90000000,
        [32] = 0x82000000,
        [33] = 0x86000000,
        [35] = 0x81000000,
        [38] = 0x81000000,
        [39] = 0x10000000,
        [40] = 0x01000000,
    };
    const uint64_t range3_second_valid =
        (UINT64_C(1) << 0) | (UINT64_C(1) << 1) |
        (UINT64_C(1) << 2) | (UINT64_C(1) << 3) |
        (UINT64_C(1) << 6) | (UINT64_C(1) << 7) |
        (UINT64_C(1) << 13) | (UINT64_C(1) << 14) |
        (UINT64_C(1) << 23) | (UINT64_C(1) << 25) |
        (UINT64_C(1) << 29) |
        (UINT64_C(1) << 30) | (UINT64_C(1) << 31) |
        (UINT64_C(1) << 32) | (UINT64_C(1) << 33) |
        (UINT64_C(1) << 35) | (UINT64_C(1) << 38) |
        (UINT64_C(1) << 39) | (UINT64_C(1) << 40);

    G_STATIC_ASSERT(ARRAY_SIZE(bounded_state_offsets) ==
                    D47_PMGR_BOUNDED_STATE_COUNT);
    G_STATIC_ASSERT(ARRAY_SIZE(bounded_state_max) ==
                    D47_PMGR_BOUNDED_STATE_COUNT);
    G_STATIC_ASSERT(ARRAY_SIZE(topology_selector_offsets) ==
                    D47_PMGR_TOPOLOGY_SELECTOR_COUNT);
    G_STATIC_ASSERT(ARRAY_SIZE(topology_descriptor_ids) ==
                    D47_PMGR_TOPOLOGY_SELECTOR_COUNT);
    G_STATIC_ASSERT(ARRAY_SIZE(d47_range2_signed_offsets) ==
                    D47_PMGR_RANGE2_SIGNED_COUNT);
    G_STATIC_ASSERT(ARRAY_SIZE(d47_range2_signed_masks) ==
                    D47_PMGR_RANGE2_SIGNED_COUNT);
    G_STATIC_ASSERT(ARRAY_SIZE(d47_range2_signed_values) ==
                    D47_PMGR_RANGE2_SIGNED_COUNT);
    G_STATIC_ASSERT(ARRAY_SIZE(d47_range2_signed_cont_masks) ==
                    D47_PMGR_RANGE2_SIGNED_CONT_COUNT);
    G_STATIC_ASSERT(ARRAY_SIZE(d47_range2_signed_cont_values) ==
                    D47_PMGR_RANGE2_SIGNED_CONT_COUNT);
    G_STATIC_ASSERT(ARRAY_SIZE(domain_state_reg_indices) ==
                    D47_PMGR_DOMAIN_STATE_COUNT);
    G_STATIC_ASSERT(ARRAY_SIZE(masked_tunable_offsets) ==
                    D47_PMGR_MASKED_TUNABLE_COUNT);
    G_STATIC_ASSERT(ARRAY_SIZE(masked_tunable_masks) ==
                    D47_PMGR_MASKED_TUNABLE_COUNT);
    G_STATIC_ASSERT(ARRAY_SIZE(masked_tunable_values) ==
                    D47_PMGR_MASKED_TUNABLE_COUNT);
    G_STATIC_ASSERT(ARRAY_SIZE(startup_word_offsets) ==
                    D47_PMGR_STARTUP_WORD_COUNT);
    G_STATIC_ASSERT(ARRAY_SIZE(soc_tunable_offsets) ==
                    D47_PMGR_SOC_TUNABLE_COUNT);
    G_STATIC_ASSERT(ARRAY_SIZE(soc_tunable_masks) ==
                    D47_PMGR_SOC_TUNABLE_COUNT);
    G_STATIC_ASSERT(ARRAY_SIZE(soc_tunable_values) ==
                    D47_PMGR_SOC_TUNABLE_COUNT);
    G_STATIC_ASSERT(ARRAY_SIZE(mcc_tunable_offsets) ==
                    D47_MCC_TUNABLE_COUNT);

    if (!pmgr) {
        error_report("darwin-pmgr: PMGR node is absent");
        exit(EXIT_FAILURE);
    }
    G_STATIC_ASSERT(sizeof(DarwinPMGRDevice) == 48);

    regs = adt_get_prop_val(pmgr, "reg");
    count = adt_get_prop_len(pmgr, "reg") / sizeof(*regs);
    if (!regs || count < 15 ||
        regs[0].len < D47_PMGR_START_LATCH_OFFSET + 4 ||
        regs[0].len < D47_PMGR_ZERO0_OFFSET + 4 ||
        regs[2].len < D47_PMGR_ZERO2_OFFSET + 4 ||
        regs[2].len < bounded_state_offsets[
                      D47_PMGR_BOUNDED_STATE_COUNT - 1] + 4 ||
        regs[2].len < D47_PMGR_STEPPED_STATE_OFFSET + 4 ||
        regs[2].len < D47_PMGR_RANGE2_SIGNED_OFFSET +
                      d47_range2_signed_offsets[
                          D47_PMGR_RANGE2_SIGNED_COUNT - 1] + 4 ||
        regs[2].len < D47_PMGR_RANGE2_SIGNED_CONT_OFFSET +
                      D47_PMGR_RANGE2_SIGNED_CONT_COUNT * 4 ||
        regs[2].len < D47_PMGR_CONFIG_SELECTOR_OFFSET +
                      D47_PMGR_CONFIG_SELECTOR_COUNT * 4 ||
        regs[2].len < soc_tunable_offsets[
                      D47_PMGR_SOC_TUNABLE_COUNT - 1] + 4 ||
        regs[3].len < D47_PMGR_RANGE3_CONFIG_OFFSET + 0x374 ||
        regs[2].len < topology_selector_offsets[
                      D47_PMGR_TOPOLOGY_SELECTOR_COUNT - 1] + 4 ||
        regs[3].len < masked_tunable_offsets[
                      D47_PMGR_MASKED_TUNABLE_COUNT - 1] + 4 ||
        regs[3].len < startup_word_offsets[
                      D47_PMGR_STARTUP_WORD_COUNT - 1] + 4 ||
        regs[3].len < D47_PMGR_POLL_CLEAR_OFFSET +
                      (D47_PMGR_POLL_CLEAR_COUNT - 1) *
                      D47_PMGR_POLL_CLEAR_STRIDE + 4 ||
        regs[0].len < D47_PMGR_CPU_READY_OFFSET + 8 ||
        regs[0].len < D47_PMGR_PLATFORM_FLAGS_OFFSET +
                      D47_PMGR_PLATFORM_FLAGS_COUNT * 4 ||
        regs[0].len < D47_PMGR_HANDSHAKE_OFFSET +
                      (D47_PMGR_HANDSHAKE_COUNT - 1) *
                      D47_PMGR_HANDSHAKE_STRIDE +
                      D47_PMGR_HANDSHAKE_STATUS + 4 ||
        regs[1].len < D47_PMGR_CPFM_OFFSET + 8 ||
        regs[1].len < D47_PMGR_TUNING_FUSE_OFFSET + 4 ||
        regs[1].len < D47_PMGR_IDENTITY_OFFSET + 4 ||
        regs[1].len < D47_PMGR_CHIP_REV_OFFSET + 4 ||
        regs[5].len < D47_PMGR_DOMAIN_STATE_OFFSET + 8 ||
        regs[14].len < D47_PMGR_DOMAIN_STATE_OFFSET + 8) {
        error_report("darwin-pmgr: device tree lacks evidenced d47 PMGR ranges");
        exit(EXIT_FAILURE);
    }

    pa = iobase + regs[0].base + D47_PMGR_START_LATCH_OFFSET;
    s = g_new0(DarwinPMGRIboot, 1);
    memory_region_init_io(&s->start_latch_mr, NULL,
                          &darwin_pmgr_start_latch_ops, s,
                          "darwin-pmgr-iboot-start-latch", 4);
    memory_region_add_subregion_overlap(get_system_memory(), pa,
                                        &s->start_latch_mr, 10);
    fprintf(stderr,
            "darwin-pmgr: cold-reset start latch at 0x%" PRIx64
            " initialized clear\n", pa);

    pa = iobase + regs[0].base + D47_PMGR_ZERO0_OFFSET;
    memory_region_init_io(&s->zero0_mr, NULL, &darwin_pmgr_zero_ops, s,
                          "darwin-pmgr-iboot-zero-range0", 4);
    memory_region_add_subregion_overlap(get_system_memory(), pa,
                                        &s->zero0_mr, 10);
    pa = iobase + regs[2].base + D47_PMGR_ZERO2_OFFSET;
    memory_region_init_io(&s->zero2_mr, NULL, &darwin_pmgr_zero_ops, s,
                          "darwin-pmgr-iboot-zero-range2", 4);
    memory_region_add_subregion_overlap(get_system_memory(), pa,
                                        &s->zero2_mr, 10);

    for (i = 0; i < D47_PMGR_BOUNDED_STATE_COUNT; i++) {
        DarwinPMGRBoundedState *slot = &s->bounded_states[i];

        slot->offset = bounded_state_offsets[i];
        slot->max = bounded_state_max[i];
        pa = iobase + regs[2].base + slot->offset;
        memory_region_init_io(&slot->mr, NULL, &darwin_pmgr_perf_state_ops,
                              slot, "darwin-pmgr-iboot-bounded-state", 4);
        memory_region_add_subregion_overlap(get_system_memory(), pa,
                                            &slot->mr, 10);
    }

    pa = iobase + regs[2].base + D47_PMGR_STEPPED_STATE_OFFSET;
    memory_region_init_io(&s->stepped_state_mr, NULL,
                          &darwin_pmgr_stepped_state_ops, s,
                          "darwin-pmgr-iboot-stepped-state", 4);
    memory_region_add_subregion_overlap(get_system_memory(), pa,
                                        &s->stepped_state_mr, 10);

    for (i = 0; i < D47_PMGR_DOMAIN_STATE_COUNT; i++) {
        DarwinPMGRDomainState *state = &s->domain_states[i];

        state->reg_index = domain_state_reg_indices[i];
        pa = iobase + regs[state->reg_index].base +
             D47_PMGR_DOMAIN_STATE_OFFSET;
        memory_region_init_io(&state->mr, NULL,
                              &darwin_pmgr_domain_state_ops, state,
                              "darwin-pmgr-iboot-domain-state", 8);
        memory_region_add_subregion_overlap(get_system_memory(), pa,
                                            &state->mr, 10);
    }

    for (i = 0; i < D47_PMGR_MASKED_TUNABLE_COUNT; i++) {
        DarwinPMGRMaskedTunable *slot = &s->masked_tunables[i];

        slot->offset = masked_tunable_offsets[i];
        slot->reg_index = 3;
        slot->mask = masked_tunable_masks[i];
        slot->value = masked_tunable_values[i];
        pa = iobase + regs[3].base + slot->offset;
        memory_region_init_io(&slot->mr, NULL,
                              &darwin_pmgr_masked_tunable_ops, slot,
                              "darwin-pmgr-iboot-masked-tunable", 4);
        memory_region_add_subregion_overlap(get_system_memory(), pa,
                                            &slot->mr, 10);
    }

    for (i = 0; i < D47_PMGR_STARTUP_WORD_COUNT; i++) {
        DarwinPMGRStartupWord *slot = &s->startup_words[i];

        slot->offset = startup_word_offsets[i];
        slot->index = i;
        pa = iobase + regs[3].base + slot->offset;
        memory_region_init_io(&slot->mr, NULL, &darwin_pmgr_startup_word_ops,
                              slot, "darwin-pmgr-iboot-startup-word", 4);
        memory_region_add_subregion_overlap(get_system_memory(), pa,
                                            &slot->mr, 10);
    }

    s->root_tunable_c.offset = 0xc;
    s->root_tunable_c.reg_index = 2;
    s->root_tunable_c.mask = UINT32_C(0x0003ffc0);
    s->root_tunable_c.value = UINT32_C(0x00002ac0);
    pa = iobase + regs[2].base + s->root_tunable_c.offset;
    memory_region_init_io(&s->root_tunable_c.mr, NULL,
                          &darwin_pmgr_masked_tunable_ops,
                          &s->root_tunable_c,
                          "darwin-pmgr-iboot-root-tunable-c", 4);
    memory_region_add_subregion_overlap(get_system_memory(), pa,
                                        &s->root_tunable_c.mr, 10);

    s->root_tunable_10.offset = 0x10;
    s->root_tunable_10.reg_index = 2;
    s->root_tunable_10.mask = UINT32_C(0xffffc000);
    s->root_tunable_10.value = UINT32_C(0x6c800000);
    pa = iobase + regs[2].base + s->root_tunable_10.offset;
    memory_region_init_io(&s->root_tunable_10.mr, NULL,
                          &darwin_pmgr_masked_tunable_ops,
                          &s->root_tunable_10,
                          "darwin-pmgr-iboot-root-tunable-10", 4);
    memory_region_add_subregion_overlap(get_system_memory(), pa,
                                        &s->root_tunable_10.mr, 10);

    pa = iobase + regs[2].base;
    memory_region_init_io(&s->root_zero.mr, NULL,
                          &darwin_pmgr_root_zero_ops, &s->root_zero,
                          "darwin-pmgr-iboot-root-block", 0xc);
    memory_region_add_subregion_overlap(get_system_memory(), pa,
                                        &s->root_zero.mr, 10);

    for (i = 0; i < D47_MCC_CONFIG_COUNT; i++) {
        DarwinPMGRMCCConfig *block = &s->mcc_configs[i];

        block->index = i;
        pa = D47_MCC_CONFIG_BASE + i * D47_MCC_CONFIG_STRIDE;
        memory_region_init_io(&block->mr, NULL,
                              &darwin_pmgr_mcc_config_ops, block,
                              "darwin-pmgr-iboot-mcc-config", 0x20);
        memory_region_add_subregion_overlap(get_system_memory(), pa,
                                            &block->mr, 10);
        for (j = 0; j < D47_MCC_TUNABLE_COUNT; j++) {
            DarwinPMGRMCCTunable *slot =
                &s->mcc_tunables[i * D47_MCC_TUNABLE_COUNT + j];

            slot->bank = i;
            slot->offset = mcc_tunable_offsets[j];
            slot->mask = mcc_tunable_masks[j];
            slot->value = mcc_tunable_values[j];
            pa = D47_MCC_CONFIG_BASE + i * D47_MCC_CONFIG_STRIDE +
                 slot->offset;
            memory_region_init_io(&slot->mr, NULL,
                                  &darwin_pmgr_mcc_tunable_ops, slot,
                                  "darwin-pmgr-iboot-mcc-tunable", 4);
            memory_region_add_subregion_overlap(get_system_memory(), pa,
                                                &slot->mr, 10);
        }
    }

    if (tuning_bin_env) {
        if (strcmp(tuning_bin_env, "0")) {
            error_report("DARWIN_IBOOT_PMGR_TUNING_BIN currently supports"
                         " only the explicit no-adjustment bin 0");
            exit(EXIT_FAILURE);
        }
        pa = iobase + regs[1].base + D47_PMGR_TUNING_FUSE_OFFSET;
        memory_region_init_io(&s->tuning_fuse_mr, NULL,
                              &darwin_pmgr_tuning_fuse_ops, s,
                              "darwin-pmgr-iboot-tuning-bin", 4);
        memory_region_add_subregion_overlap(get_system_memory(), pa,
                                            &s->tuning_fuse_mr, 10);
        for (i = 0; i < D47_PMGR_SOC_TUNABLE_COUNT; i++) {
            DarwinPMGRMaskedTunable *slot = &s->soc_tunables[i];

            slot->offset = soc_tunable_offsets[i];
            slot->reg_index = 2;
            slot->mask = soc_tunable_masks[i];
            slot->value = soc_tunable_values[i];
            pa = iobase + regs[2].base + slot->offset;
            memory_region_init_io(&slot->mr, NULL,
                                  &darwin_pmgr_masked_tunable_ops, slot,
                                  "darwin-pmgr-iboot-soc-tunable", 4);
            memory_region_add_subregion_overlap(get_system_memory(), pa,
                                                &slot->mr, 10);
        }
        fprintf(stderr,
                "darwin-pmgr: virtual tuning bin 0 at range1+0x%" PRIx64
                " selects no per-silicon adjustment; %u signed-table"
                " targets installed\n",
                D47_PMGR_TUNING_FUSE_OFFSET,
                D47_PMGR_SOC_TUNABLE_COUNT);
    }

    if (no_harvest_env) {
        if (strcmp(no_harvest_env, "1")) {
            error_report("DARWIN_IBOOT_PMGR_NO_HARVEST must be exactly 1"
                         " when present");
            exit(EXIT_FAILURE);
        }
        for (i = 0; i < D47_PMGR_TOPOLOGY_SELECTOR_COUNT; i++) {
            DarwinPMGRTopologySelector *slot = &s->topology_selectors[i];

            slot->offset = topology_selector_offsets[i];
            slot->descriptor_id = topology_descriptor_ids[i];
            pa = iobase + regs[2].base + slot->offset;
            memory_region_init_io(&slot->mr, NULL,
                                  &darwin_pmgr_topology_selector_ops, slot,
                                  "darwin-pmgr-iboot-topology-selector", 4);
            memory_region_add_subregion_overlap(get_system_memory(), pa,
                                                &slot->mr, 10);
        }
        s->topology_selectors[0].tuning_ready =
            &s->range2_signed_tuning.complete;
        pa = iobase + regs[2].base + D47_PMGR_RANGE2_SIGNED_OFFSET;
        memory_region_init_io(&s->range2_signed_tuning.mr, NULL,
                              &darwin_pmgr_range2_signed_ops,
                              &s->range2_signed_tuning,
                              "darwin-pmgr-iboot-range2-signed", 0x44);
        memory_region_add_subregion_overlap(get_system_memory(), pa,
                                            &s->range2_signed_tuning.mr, 10);
        s->range2_signed_continuation.ready =
            &s->topology_selectors[0].tuned;
        pa = iobase + regs[2].base + D47_PMGR_RANGE2_SIGNED_CONT_OFFSET;
        memory_region_init_io(&s->range2_signed_continuation.mr, NULL,
                              &darwin_pmgr_range2_signed_cont_ops,
                              &s->range2_signed_continuation,
                              "darwin-pmgr-iboot-range2-signed-cont", 0x20);
        memory_region_add_subregion_overlap(
            get_system_memory(), pa,
            &s->range2_signed_continuation.mr, 10);
        for (i = 0; i < D47_PMGR_TOPOLOGY_BLOCK_COUNT; i++) {
            DarwinPMGRTopologyBlock *block = &s->topology_blocks[i];

            block->index = i + D47_PMGR_TOPOLOGY_BLOCK_FIRST;
            pa = iobase + regs[2].base +
                 block->index * D47_PMGR_TOPOLOGY_BLOCK_STRIDE;
            memory_region_init_io(&block->mr, NULL,
                                  &darwin_pmgr_topology_block_ops, block,
                                  "darwin-pmgr-iboot-topology-block", 0x14);
            memory_region_add_subregion_overlap(get_system_memory(), pa,
                                                &block->mr, 10);
        }
        for (i = 0; i < D47_PMGR_CONFIG_SELECTOR_COUNT; i++) {
            DarwinPMGRConfigSelector *slot = &s->config_selectors[i];

            slot->index = i;
            slot->kind = "range2 selector";
            pa = iobase + regs[2].base + D47_PMGR_CONFIG_SELECTOR_OFFSET +
                 i * 4;
            memory_region_init_io(&slot->mr, NULL,
                                  &darwin_pmgr_config_selector_ops, slot,
                                  "darwin-pmgr-iboot-config-selector", 4);
            memory_region_add_subregion_overlap(get_system_memory(), pa,
                                                &slot->mr, 10);
        }
        fprintf(stderr,
                "darwin-pmgr: virtual no-harvest topology enabled for"
                " descriptor IDs 0x64/0x82/0x83, blocks 1..6, and eleven"
                " firmware-programmed selector words\n");
    }

    for (i = 0; i < D47_PMGR_RANGE3_CONFIG_COUNT; i++) {
        DarwinPMGRConfigSelector *slot = &s->range3_config_words[i];
        uint64_t config_offset;

        if (i < 39) {
            config_offset = i * 4;
        } else if (i < 47) {
            config_offset = 0x304 + (i - 39) * 4;
        } else {
            config_offset = 0x330 + (i - 47) * 4;
        }
        slot->index = i;
        slot->kind = "range3 descriptor";
        slot->second_valid = range3_second_valid & (UINT64_C(1) << i);
        slot->second_value = range3_second_requests[i];
        pa = iobase + regs[3].base + D47_PMGR_RANGE3_CONFIG_OFFSET +
             config_offset;
        memory_region_init_io(&slot->mr, NULL,
                              &darwin_pmgr_config_selector_ops, slot,
                              "darwin-pmgr-iboot-range3-config", 4);
        memory_region_add_subregion_overlap(get_system_memory(), pa,
                                            &slot->mr, 10);
    }
    fprintf(stderr,
            "darwin-pmgr: 64 sparse range3 configuration words installed"
            " from the cross-build-identical firmware descriptor table\n");

    for (i = 0; i < D47_PMGR_POLL_CLEAR_COUNT; i++) {
        DarwinPMGRPollClear *slot = &s->poll_clear[i];

        slot->index = i;
        pa = iobase + regs[3].base + D47_PMGR_POLL_CLEAR_OFFSET +
             i * D47_PMGR_POLL_CLEAR_STRIDE;
        memory_region_init_io(&slot->mr, NULL, &darwin_pmgr_poll_clear_ops,
                              slot, "darwin-pmgr-iboot-poll-clear", 4);
        memory_region_add_subregion_overlap(get_system_memory(), pa,
                                            &slot->mr, 10);
    }

    pa = iobase + regs[0].base + D47_PMGR_PLATFORM_FLAGS_OFFSET;
    memory_region_init_io(&s->platform_flags_mr, NULL,
                          &darwin_pmgr_platform_flags_ops, s,
                          "darwin-pmgr-iboot-platform-flags",
                          D47_PMGR_PLATFORM_FLAGS_COUNT * 4);
    memory_region_add_subregion_overlap(get_system_memory(), pa,
                                        &s->platform_flags_mr, 10);
    fprintf(stderr,
            "darwin-pmgr: %u platform flag words at 0x%" PRIx64
            " initialized clear\n", D47_PMGR_PLATFORM_FLAGS_COUNT, pa);

    pa = iobase + regs[0].base + D47_PMGR_CPU_READY_OFFSET;
    memory_region_init_io(&s->cpu_ready_mr, NULL,
                          &darwin_pmgr_cpu_ready_ops, s,
                          "darwin-pmgr-iboot-cpu-ready", 8);
    memory_region_add_subregion_overlap(get_system_memory(), pa,
                                        &s->cpu_ready_mr, 10);
    fprintf(stderr,
            "darwin-pmgr: CPU-ready pair at 0x%" PRIx64
            " initialized to the canonical cold representative\n", pa);

    for (i = 0; i < D47_PMGR_HANDSHAKE_COUNT; i++) {
        DarwinPMGRHandshake *channel = &s->handshakes[i];
        uint64_t channel_pa = iobase + regs[0].base +
                              D47_PMGR_HANDSHAKE_OFFSET +
                              i * D47_PMGR_HANDSHAKE_STRIDE;

        channel->index = i;
        memory_region_init_io(&channel->control_mr, NULL,
                              &darwin_pmgr_handshake_control_ops, channel,
                              "darwin-pmgr-iboot-handshake-control", 4);
        memory_region_add_subregion_overlap(get_system_memory(), channel_pa,
                                            &channel->control_mr, 10);
        memory_region_init_io(&channel->status_mr, NULL,
                              &darwin_pmgr_handshake_status_ops, channel,
                              "darwin-pmgr-iboot-handshake-status", 4);
        memory_region_add_subregion_overlap(get_system_memory(),
                                            iobase + regs[0].base +
                                            D47_PMGR_HANDSHAKE_OFFSET +
                                            i * D47_PMGR_HANDSHAKE_STRIDE +
                                            D47_PMGR_HANDSHAKE_STATUS,
                                            &channel->status_mr, 10);
    }
    fprintf(stderr,
            "darwin-pmgr: %u exact control/status handshake channels at"
            " range0+0x%" PRIx64 " initialized pending\n",
            D47_PMGR_HANDSHAKE_COUNT, D47_PMGR_HANDSHAKE_OFFSET);

    devices = adt_get_prop_val(pmgr, "devices");
    ps_groups = adt_get_prop_val(pmgr, "ps-groups");
    if (!devices || !ps_groups ||
        adt_get_prop_len(pmgr, "devices") % sizeof(*devices) ||
        adt_get_prop_len(pmgr, "ps-groups") % 12) {
        error_report("darwin-pmgr: invalid d47 devices/ps-groups tables");
        exit(EXIT_FAILURE);
    }
    device_count = adt_get_prop_len(pmgr, "devices") / sizeof(*devices);
    ps_group_count = adt_get_prop_len(pmgr, "ps-groups") / 12;
    if (!ps_group_count) {
        error_report("darwin-pmgr: d47 state-group table is empty");
        exit(EXIT_FAILURE);
    }
    s->state_slots = g_new0(DarwinPMGRStateSlot, device_count);
    j = 0;
    for (i = 0; i < device_count; i++) {
        uint32_t group_and_offset = ldl_le_p(&devices[i].group_and_offset);
        uint32_t group = group_and_offset >> 24;
        uint32_t device_offset = group_and_offset & 0x00ffffff;
        const uint8_t *group_record;
        uint32_t reg_index;
        uint32_t group_offset;
        uint64_t offset;
        DarwinPMGRStateSlot *slot;
        size_t k;

        if (group >= ps_group_count) {
            error_report("darwin-pmgr: device %zu selects invalid state"
                         " group %u", i, group);
            exit(EXIT_FAILURE);
        }
        group_record = ps_groups + group * 12;
        reg_index = ldl_le_p(group_record);
        group_offset = ldl_le_p(group_record + 4);
        offset = (uint64_t)group_offset + device_offset;
        if (reg_index >= count || offset > UINT32_MAX) {
            error_report("darwin-pmgr: device %zu has invalid state mapping",
                         i);
            exit(EXIT_FAILURE);
        }
        if ((offset & 7) || offset + 4 > regs[reg_index].len) {
            error_report("darwin-pmgr: invalid state offset 0x%" PRIx64,
                         offset);
            exit(EXIT_FAILURE);
        }
        for (k = 0; k < j; k++) {
            if (s->state_slots[k].reg_index == reg_index &&
                s->state_slots[k].offset == offset) {
                break;
            }
        }
        if (k != j) {
            continue;
        }
        slot = &s->state_slots[j++];
        slot->reg_index = reg_index;
        slot->offset = offset;
        memcpy(slot->name, devices[i].name, D47_PMGR_DEVICE_NAME_LEN);
        slot->name[D47_PMGR_DEVICE_NAME_LEN] = '\0';
        pa = iobase + regs[reg_index].base + offset;
        memory_region_init_io(&slot->mr, NULL, &darwin_pmgr_state_ops, slot,
                              slot->name, 4);
        memory_region_add_subregion_overlap(get_system_memory(), pa,
                                            &slot->mr, 10);
    }
    s->state_slot_count = j;
    fprintf(stderr,
            "darwin-pmgr: %zu sparse d47 state words initialized off from"
            " ps-groups/devices\n", s->state_slot_count);

    pa = iobase + regs[1].base + D47_PMGR_IDENTITY_OFFSET;
    memory_region_init_io(&s->identity_mr, NULL, &darwin_pmgr_identity_ops, s,
                          "darwin-pmgr-iboot-identity", 4);
    memory_region_add_subregion_overlap(get_system_memory(), pa,
                                        &s->identity_mr, 10);
    fprintf(stderr,
            "darwin-pmgr: d47 identity raw=0 at 0x%" PRIx64
            " (BDID[7:5]=0, SCEP=0 from paired manifest/iBootData)\n",
            pa);

    memory_region_init_io(&s->board_id_low_mr, NULL,
                          &darwin_board_id_low_ops, s,
                          "darwin-pmgr-iboot-board-id-low", 4);
    memory_region_add_subregion_overlap(get_system_memory(),
                                        D47_BOARD_ID_LOW_PA,
                                        &s->board_id_low_mr, 10);
    fprintf(stderr,
            "darwin-pmgr: d47 board-id low word=0x%x at 0x%" PRIx64
            " (ApBoardID=0x08 from paired BuildManifest)\n",
            D47_BOARD_ID_LOW, D47_BOARD_ID_LOW_PA);

    if (cpfm_env) {
        if (qemu_strtoui(cpfm_env, NULL, 0, &cpfm) < 0 || cpfm > 1) {
            error_report("DARWIN_IBOOT_CPFM must select one of the two exact"
                         " firmware-defined identities: 0 or 1");
            exit(EXIT_FAILURE);
        }
        s->cpfm[0] = cpfm ? D47_PMGR_CPFM_FIRST_ONE : D47_PMGR_CPFM_SECOND;
        s->cpfm[1] = D47_PMGR_CPFM_SECOND;
        pa = iobase + regs[1].base + D47_PMGR_CPFM_OFFSET;
        memory_region_init_io(&s->cpfm_mr, NULL, &darwin_pmgr_cpfm_ops, s,
                              "darwin-pmgr-iboot-cpfm", 8);
        memory_region_add_subregion_overlap(get_system_memory(), pa,
                                            &s->cpfm_mr, 10);
        fprintf(stderr,
                "darwin-pmgr: virtual CPFM=%u tuple=(0x%08x,0x%08x)"
                " at 0x%" PRIx64 " (firmware-defined identity, not a"
                " completion response)\n",
                cpfm, s->cpfm[0], s->cpfm[1], pa);
    }

    if (!revision_env) {
        return;
    }
    if (qemu_strtoui(revision_env, NULL, 0, &revision) < 0 ||
        (revision != 0 && revision != 0x10 && revision != 0x11)) {
        error_report("DARWIN_IBOOT_CHIP_REVISION must be an exact revision"
                     " present in paired d47 iBootData: 0, 0x10, or 0x11");
        exit(EXIT_FAILURE);
    }

    s->chip_revision_raw = ((revision & 0x7) << 7) |
                           ((revision & 0x70) << 6);
    pa = iobase + regs[1].base + D47_PMGR_CHIP_REV_OFFSET;
    memory_region_init_io(&s->chip_revision_mr, NULL,
                          &darwin_pmgr_chip_revision_ops, s,
                          "darwin-pmgr-iboot-chip-revision", 4);
    memory_region_add_subregion_overlap(get_system_memory(), pa,
                                        &s->chip_revision_mr, 10);
    fprintf(stderr,
            "darwin-pmgr: virtual chip revision=0x%x encoded raw=0x%x"
            " at 0x%" PRIx64 " (supported iBootData tuple, not a hardware"
            " reset-value claim)\n",
            revision, s->chip_revision_raw, pa);
}
