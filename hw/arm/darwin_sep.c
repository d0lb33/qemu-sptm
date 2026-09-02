/*
 * darwin-sep: a Secure Enclave that answers the AP, without the enclave
 *
 * The SEP is an ASC-family coprocessor (device tree "iop-sep,ascwrap-v6"),
 * so its wrapper and mailbox registers are the ones every other IOP has. What
 * differs is everything above the mailbox: the SEP does not speak RTKit. It
 * has its own 8-byte message frame, its own endpoint numbering, and a boot
 * conversation with the SEP ROM that the AP kernel (AppleSEPManager) drives
 * itself. This file models the AP-visible half of that conversation well
 * enough for AppleSEPManager to believe the enclave booted and to publish the
 * endpoint nubs (`sep-endpoint,scrd`, `sep-endpoint,sks`, ...) that the rest
 * of the OS waits on. No cryptography lives here and none is intended to:
 * where a real SEP would wrap or sign something, the AP gets a constant it
 * accepts, and every such constant is marked as one.
 *
 * ---------------------------------------------------------------------------
 * Register map (reg[0], "iop-sep,ascwrap-v6")
 *
 * Identical to darwin_asc.c, which cross-checked it against the
 * AppleA7IOP-ASCWrap-v6 kext, m1n1 hw/asc.py and Linux apple-mailbox.c:
 *
 *   +0x0044  CPU_CONTROL  bit 4 = RUN
 *   +0x0048  CPU_STATUS   bit 0 running, bit 1 stopped, bit 5 idle
 *   mailbox at +0x8000 (asc-mailbox-v4):
 *   +0x110  A2I_CTRL     AP -> IOP fifo status (bit 16 FULL, 17 EMPTY, [23:20] count)
 *   +0x114  I2A_CTRL     IOP -> AP fifo status, same layout
 *   +0x800  A2I_SEND0    64-bit message; the SEP frame lives here (see below)
 *   +0x808  A2I_SEND1    second word; the write commits the message. The AP
 *                        writes 0 for every SEP message (AppleSEPManager::
 *                        _sendMessageGated, kext 0xfffffff0095a67e0: stp x8, xzr)
 *   +0x830  I2A_RECV0    64-bit message
 *   +0x838  I2A_RECV1    second word; the read pops the message. Bits [55:52]
 *                        mirror the fifo occupancy (darwin_asc.c explains why
 *                        AppleASCWrapV6::getMailboxBulk needs this).
 *
 * The SEP node's reg[1] (0x72050000, 0x60000 on t8140) is not mapped here.
 * Nothing in the boot we traced touches it; darwin_unimp backs it with
 * read-zero/remember-writes and logs any access under DARWIN_UNIMP_DEBUG.
 *
 * ---------------------------------------------------------------------------
 * Message frame
 *
 * One 64-bit word: { u8 endpoint; u8 tag; u8 opcode; u8 param; u32 data; }.
 * AppleSEPManager builds it that way in _sendMessageGated (kext
 * 0xfffffff0095a67a0: opcode <<16, param at bits [31:24], endpoint written
 * into byte 0 with bfxil, data in the upper 32 bits) and its dispatcher reads
 * the endpoint back from byte 0 of the first mailbox word (0xfffffff0095a3c3c).
 * The addresses carried in `data` are 4 KiB page numbers regardless of the
 * AP's own page size: AppleSEPControl::cmsgSET_OOL_IN shifts by 12
 * (0xfffffff00959a060), so does bootSEP for the firmware, ART and shared
 * memory addresses (0xfffffff00959c2f8, 0x59c39c, 0x59c438).
 *
 * Endpoint numbers and 4CC names come from AppleSEPManager's own strings
 * (EP_CONTROL, EP_DISCOVERY, EP_BOOTSTRAP, EP_XART_SEP_SLAVE...) and from the
 * two public models cited at the bottom; the ids are the same in both and in
 * our kernelcache where it names them:
 *
 *   0    'cntl'  control: OOL buffer setup, sleep, security mode, self test
 *   10   'scrd'  secure credentials, AppleSEPCredentialManager ("ACMTRM")
 *   16   'xars'  xART slave    18   'sks '  AppleSEPKeyStore (the keybag)
 *   19   'xarm'  xART master   253  discovery   254  L4Info   255  bootstrap
 *
 * ---------------------------------------------------------------------------
 * Bootstrap endpoint (255), what AppleSEPBooter sends and what it accepts
 *
 * Requests, from AppleSEPBooter::bootSEP (kext 0xfffffff00959bc6c) and
 * _captureiBICKCV (0x59b878); the immediate is the frame with tag=1:
 *
 *   GET_STATUS      2   0x020100   reply 102 with data = status; bootSEP
 *                                  requires 1 before BOOT_TZ0 and 2 after
 *                                  ("unexpected status 1:%u" / "2:%u")
 *   BOOT_TZ0        5   0x050100   reply 105
 *   BOOT_IMG4       6   0x060100   reply 106; param = firmware type | slot<<4
 *   LOAD_SEP_ART    7   0x070100   reply 107
 *   RESUME          8   0x080100   reply 108 ("SEP resumed from RAM"); sent
 *                                  instead of 6 when there is no firmware
 *   iBIC query     30   0x1e0100   reply op 0 with data 30 = "unsupported",
 *                                  which _bootAction accepts (0x59b280) and
 *                                  logs "Platform doesn't support SEPROM iBIC
 *                                  retrieval"; anything else there panics
 *   BOOT_TMM_MANIFEST 36, BOOT_PATCH 37: reply 136 / 137
 *   PING 1, GENERATE_NONCE 3, GET_NONCE_WORD 4: reply 101 / 103 / 104
 *
 * Replies are decoded by AppleSEPBooter::_bootAction (0xfffffff00959b0b4):
 * 102 and 210 store `data` as the SEP status (booter+0xb2); 105-108,
 * 136, 137 and 101 clear the "waiting" flag; 202 is a printable log line
 * (param = byte count in data); 255 marks the ROM panicked (status 0xca)
 * and the next message panics the AP. The tag is not checked but is echoed.
 *
 * After BOOT_IMG4 the AP sends L4Info on endpoint 254:
 *   { ep 254, tag 0, u16 size_pages @2, u32 addr_pages @4 } ("Shmbuf for
 *   SEP: { slave addr = 0x%llx, size = 0x%lx }", 0x59c4e4) and waits for the
 *   boot reply already in flight. A real sepOS then announces itself: an
 *   unsolicited control message op 13 (AppleSEPControl's unsolicited-message
 *   switch at 0xfffffff009599764 handles 1, 13, 16, 17, 21 and 41), and one
 *   discovery pair per endpoint, which is what AppleSEPDiscovery::_msgReceived
 *   (0xfffffff009584e78) consumes:
 *     op 0  ADVERTISE  param = endpoint id, data = 4CC name
 *     op 1  OOL        param = endpoint id, data = { in_min, in_max, out_min,
 *                      out_max } page counts, one byte each, low byte first
 *   The 4CC is read as a little-endian u32 and its bytes are written to the
 *   nub name most-significant first (0xfffffff009584850..0x584878), so
 *   'scrd' is the u32 0x73637264. Trailing spaces are trimmed ('sks ' ->
 *   "sep-endpoint,sks").
 *
 * Control endpoint (0), AP -> SEP, all acknowledged with op 1 and the tag:
 *   2 SET_OOL_IN_ADDR   3 SET_OOL_OUT_ADDR   param = endpoint, data = page
 *   4 SET_OOL_IN_SIZE   5 SET_OOL_OUT_SIZE   param = endpoint, data = bytes
 *   (cmsgSET_OOL_IN sends 4 then 2, 0xfffffff00959a030..0x59a07c)
 *   20 security mode, 24 self test, 37 erase-install: acknowledged
 *
 * xART endpoints (16, 19): every request is acknowledged with op 0 and the
 * tag, which is all AppleSEPXART checks ("received message for invalid tag").
 *
 * ---------------------------------------------------------------------------
 * The TXM secure channel
 *
 * Once the SEP reports alive, AMFI calls into TXM ("AMFI: AMFIUpdateDeviceState")
 * and TXM reads a shared page that sepOS's SCRD service is expected to have
 * filled in. The page is the fixed device virtual address the dart-sep node
 * names in "txm-secure-channel-base" (0x10000004000, "-size" 0x4000 on t8140;
 * AppleSEPManager::_loadFlagData logs "Detected hardcoded TXM-SEP secure
 * channel DVA"). TXM (firmware/txm, linear from 0xfffffff017004000):
 *
 *   0x1704123c  reads u32 at page+0x200; low 16 bits must equal 0x5c01 or it
 *               returns 9, and its caller 0x17033954 then panics with
 *               "TXM [Panic]: [code: 0x000000F3 | 9]" -- the exact panic we
 *               got before this page was written. Bit 16 is logged as
 *               "SecureChannel: SCRD |  xART: %u".
 *   0x17033bd4  with bit 16 clear TXM takes the no-xART policy path and never
 *               touches the seqlock record at page+0x290; with it set it
 *               would read that record (0x17041328) and act on Lockdown /
 *               Demo mode from it.
 *   0x1704129c  the lockdown query wants u16 0x5c02 at page+0x400 and reads
 *               the flag byte at page+0x448.
 *
 * So the model writes { +0x200: 0x00005c01, +0x400: 0x5c02, +0x448: 0 }
 * through the DART as soon as the AP has mapped the page. Zero xART and zero
 * lockdown are the permissive answers, chosen so nothing downstream changes
 * policy on their account; they are constants standing in for SEP state,
 * not modelled behaviour.
 *
 * ---------------------------------------------------------------------------
 * Sources. Every number above was re-derived from this kernelcache (iOS 27,
 * t8140, com.apple.driver.AppleSEPManager 928.0.2, unslid addresses; runtime
 * is +0x20000000). The hypothesis of *which* messages to send was informed
 * by two public models and then checked here, not copied:
 *   ChefKissInc/Inferno hw/arm/apple-silicon/sep-sim.c (AGPL-3.0)
 *   TrungNguyen1909/qemu-t8030 hw/arm/apple_sep.c (GPL-2.0)
 * No code, struct or comment from either is reproduced in this file.
 *
 * Tracing: DARWIN_SEP_DEBUG=1 logs every register access and message.
 * Milestones (boot handshake, discovery, unknown opcodes) always log with
 * the "sep:" prefix.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "qemu/guest-random.h"
#include "hw/core/sysbus.h"
#include "hw/core/irq.h"
#include "hw/core/qdev-properties.h"
#include "system/memory.h"
#include "system/address-spaces.h"
#include "exec/memattrs.h"
#include "xnu/boot/xnuboot.h"
#include "xnu/apple_dtree.h"
#include "xnu/darwin_aic.h"
#include "xnu/darwin_dart.h"
#include "xnu/darwin_sep.h"

OBJECT_DECLARE_SIMPLE_TYPE(DarwinSEPState, DARWIN_SEP)

/* ---------------- wrapper + mailbox registers (see darwin_asc.c) ---------------- */

#define ASC_CPU_CONTROL         0x44
#define ASC_CPU_CONTROL_RUN     BIT(4)
#define ASC_CPU_STATUS          0x48
#define ASC_CPU_STATUS_RUNNING  BIT(0)
#define ASC_CPU_STATUS_STOPPED  BIT(1)

#define MBOX_A2I_CTRL   0x110
#define MBOX_I2A_CTRL   0x114
#define MBOX_A2I_SEND0  0x800
#define MBOX_A2I_SEND1  0x808
#define MBOX_I2A_RECV0  0x830
#define MBOX_I2A_RECV1  0x838

#define MBOX_CTRL_ENABLE     BIT(0)
#define MBOX_CTRL_FULL       BIT(16)
#define MBOX_CTRL_EMPTY      BIT(17)
#define MBOX_CTRL_CNT_SHIFT  20
#define MBOX_CTRL_RPTR_SHIFT 12
#define MBOX_CTRL_WPTR_SHIFT 8
#define MBOX_CTRL_PTR_MASK   0xf

// Same constraint as darwin_asc.c: occupancy is mirrored in a 4-bit field, so
// at most 15 messages are ever visible; the rest wait in a staging queue.
#define MBOX_FIFO_DEPTH   16
#define MBOX_FIFO_VISIBLE 15
#define MBOX_PEND_DEPTH   256

/* ---------------- SEP protocol ---------------- */

#define SEP_EP_CONTROL     0
#define SEP_EP_DISCOVERY   253
#define SEP_EP_L4INFO      254
#define SEP_EP_BOOTSTRAP   255
#define SEP_MAX_EPS        256

// bootstrap (ROM) requests
#define BOOT_PING              1
#define BOOT_GET_STATUS        2
#define BOOT_GENERATE_NONCE    3
#define BOOT_GET_NONCE_WORD    4
#define BOOT_TZ0               5
#define BOOT_IMG4              6
#define BOOT_LOAD_SEP_ART      7
#define BOOT_RESUME            8
#define BOOT_IBIC_QUERY        30
#define BOOT_IBIC_WORD         31
#define BOOT_TMM_MANIFEST      36
#define BOOT_PATCH             37
// bootstrap replies: request + 100 for the acknowledgements
#define BOOT_REPLY_UNSUPPORTED 0
#define BOOT_REPLY_ACK_BASE    100
#define BOOT_REPLY_IBIC_WORD   131
#define BOOT_REPLY_LOG_TEXT    202
#define BOOT_REPLY_STATUS      210
#define BOOT_REPLY_PANIC       255

// SEP status values as AppleSEPBooter checks them
#define SEP_STATUS_ROM      1
#define SEP_STATUS_TZ0      2

// control endpoint requests (AP -> SEP)
#define CTRL_NOP              0
#define CTRL_ACK              1
#define CTRL_SET_OOL_IN_ADDR  2
#define CTRL_SET_OOL_OUT_ADDR 3
#define CTRL_SET_OOL_IN_SIZE  4
#define CTRL_SET_OOL_OUT_SIZE 5
#define CTRL_TTY_IN           10
#define CTRL_SLEEP            12
#define CTRL_NOTIFY_ALIVE     13   // SEP -> AP
#define CTRL_NAP              19
#define CTRL_SECURITY_MODE    20
#define CTRL_SELF_TEST        24
#define CTRL_ERASE_INSTALL    37
// GET_ENTROPY_FOR_XNU_PRNG: AppleSEPControl (kext 0xfffffff009599a4c, next
// to "GET_ENTROPY_FOR_XNU_PRNG call to SEP returned unknown error") sends op
// 54 and reads the reply's param as a status (0 ok, 2 error, anything else
// is "Unreachable.") and its data as four bytes of entropy; the FIPS reseed
// asks a dozen times in a row. Not in either public model.
#define CTRL_GET_ENTROPY      54

#define DISC_ADVERTISE  0
#define DISC_OOL        1

// Length, in bits, that GENERATE_NONCE reports. Both public models use 160;
// AppleSEPBooter::generateROMNonce checks the reply against NONCE_BIT_LEN
// (string 0xfffffff007710dbe) but the boot path we exercise never calls it.
#define SEP_NONCE_BITS 160

typedef struct {
    uint64_t msg0, msg1;
} SEPMsg;

typedef struct {
    const char *name;    // 4 characters, space padded
    uint8_t id;
    uint8_t in_min, in_max, out_min, out_max;   // OOL page counts advertised
} SEPEndpointDef;

/*
 * What we advertise. cntl is mandatory. scrd is what AppleSEPCredentialManager
 * waits for, sks what AppleSEPKeyStore waits for, xars/xarm what
 * AppleSEPManager itself sets relay buffers on ("setReceiveRelayBuffer(
 * EP_XART_SEP_SLAVE ...)", kext 0xfffffff007714b35). The page counts are the
 * generous defaults both public models use; each AppleSEP*Service asserts
 * that its own buffer fits between min and max ("ool_size >= ds->
 * getSepPageSize() * ds->getSendOolMinPages()", 0xfffffff00770f6b0), so a wide
 * range is the safe choice. DARWIN_SEP_EPS=name,name,... overrides the list.
 */
static const SEPEndpointDef sep_all_eps[] = {
    { "cntl", 0,   0, 0, 0, 0 },
    { "log ", 1,   0, 0, 1, 1 },
    { "arts", 2,   1, 1, 1, 1 },
    { "artr", 3,   1, 1, 1, 1 },
    { "scrd", 10,  1, 4, 1, 4 },
    { "xars", 16,  1, 4, 1, 4 },
    { "sks ", 18,  1, 4, 1, 4 },
    { "xarm", 19,  1, 4, 1, 4 },
};
static const char *const sep_default_eps = "cntl,scrd,xars,sks,xarm";

typedef struct {
    bool advertised;
    uint64_t ool_in_addr, ool_out_addr;     // device virtual addresses
    uint32_t ool_in_size, ool_out_size;
} SEPEndpointState;

struct DarwinSEPState {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    char *role;
    uint32_t mmio_size;
    uint32_t mbox_off;
    uint32_t addr_shift;
    qemu_irq irq[4];

    // wrapper
    uint32_t cpu_control, cpu_status;
    uint32_t *misc;

    // mailbox
    uint32_t a2i_ctrl_raw, i2a_ctrl_raw;
    uint64_t a2i_send0;
    SEPMsg i2a_fifo[MBOX_FIFO_DEPTH];
    int i2a_head, i2a_count;
    SEPMsg pend_fifo[MBOX_PEND_DEPTH];
    int pend_head, pend_count;
    bool announced;

    // DMA: the DART the SEP's traffic is mapped through, and the stream ids
    // the tree lists for it (mapper-sep and mapper-sep-mpm on t8140)
    DeviceState *dart;
    char *dart_name;
    unsigned sids[4];
    int n_sids;
    bool dma_warned;

    // protocol
    uint32_t status;
    bool os_alive;
    uint64_t shm_dva;
    uint32_t shm_size;
    uint64_t txm_dva;        // dart-sep "txm-secure-channel-base"
    uint64_t txm_size;       // dart-sep "txm-secure-channel-size"
    bool txm_published;
    SEPEndpointState ep[SEP_MAX_EPS];
    const SEPEndpointDef *adv[ARRAY_SIZE(sep_all_eps)];
    int n_adv;
    bool debug;
};

/* ---------------- frame helpers ---------------- */

static inline uint8_t frame_ep(uint64_t m)     { return m & 0xff; }
static inline uint8_t frame_tag(uint64_t m)    { return (m >> 8) & 0xff; }
static inline uint8_t frame_op(uint64_t m)     { return (m >> 16) & 0xff; }
static inline uint8_t frame_param(uint64_t m)  { return (m >> 24) & 0xff; }
static inline uint32_t frame_data(uint64_t m)  { return m >> 32; }

static inline uint64_t frame(uint8_t ep, uint8_t tag, uint8_t op, uint8_t param, uint32_t data) {
    return (uint64_t)ep | ((uint64_t)tag << 8) | ((uint64_t)op << 16) |
           ((uint64_t)param << 24) | ((uint64_t)data << 32);
}

static uint32_t fourcc(const char *s) {
    return ((uint32_t)(uint8_t)s[0] << 24) | ((uint32_t)(uint8_t)s[1] << 16) |
           ((uint32_t)(uint8_t)s[2] << 8) | (uint32_t)(uint8_t)s[3];
}

static const char *ep_name(DarwinSEPState *s, uint8_t ep) {
    switch (ep) {
    case SEP_EP_DISCOVERY: return "disc";
    case SEP_EP_L4INFO:    return "l4in";
    case SEP_EP_BOOTSTRAP: return "boot";
    }
    for (size_t i = 0; i < ARRAY_SIZE(sep_all_eps); i++) {
        if (sep_all_eps[i].id == ep) return sep_all_eps[i].name;
    }
    return "?";
}

/* ---------------- mailbox ---------------- */

// Interrupt order follows the node's "interrupts": 0 = a2i not-empty,
// 1 = a2i empty, 2 = i2a not-empty, 3 = i2a empty (darwin_asc.c).
static void sep_update_irqs(DarwinSEPState *s) {
    bool i2a_empty = (s->i2a_count == 0);
    qemu_set_irq(s->irq[0], 0);
    qemu_set_irq(s->irq[1], 1);
    qemu_set_irq(s->irq[2], !i2a_empty);
    qemu_set_irq(s->irq[3], i2a_empty);
}

static void sep_push_visible(DarwinSEPState *s, uint64_t msg) {
    int idx = (s->i2a_head + s->i2a_count) % MBOX_FIFO_DEPTH;
    s->i2a_fifo[idx].msg0 = msg;
    s->i2a_fifo[idx].msg1 = 0;
    s->i2a_count++;
}

static void sep_refill_visible(DarwinSEPState *s) {
    while (s->i2a_count < MBOX_FIFO_VISIBLE && s->pend_count) {
        SEPMsg m = s->pend_fifo[s->pend_head];
        s->pend_head = (s->pend_head + 1) % MBOX_PEND_DEPTH;
        s->pend_count--;
        sep_push_visible(s, m.msg0);
    }
}

static void sep_send_raw(DarwinSEPState *s, uint64_t msg) {
    if (s->debug) {
        fprintf(stderr, "sep(%s): SEP -> AP ep %3u (%s) tag %u op %3u param %3u data 0x%08x\n",
                s->role, frame_ep(msg), ep_name(s, frame_ep(msg)), frame_tag(msg),
                frame_op(msg), frame_param(msg), frame_data(msg));
    }
    if (s->i2a_count < MBOX_FIFO_VISIBLE) {
        sep_push_visible(s, msg);
    } else if (s->pend_count < MBOX_PEND_DEPTH) {
        int idx = (s->pend_head + s->pend_count) % MBOX_PEND_DEPTH;
        s->pend_fifo[idx].msg0 = msg;
        s->pend_fifo[idx].msg1 = 0;
        s->pend_count++;
    } else {
        fprintf(stderr, "sep(%s): i2a fifo and staging queue full, dropping 0x%016" PRIx64 "\n",
                s->role, msg);
        return;
    }
    sep_update_irqs(s);
}

static void sep_send(DarwinSEPState *s, uint8_t ep, uint8_t tag, uint8_t op,
                     uint8_t param, uint32_t data) {
    sep_send_raw(s, frame(ep, tag, op, param, data));
}

/* ---------------- DMA through the DART ---------------- */

/*
 * Every SEP-side buffer address is a device virtual address the AP mapped
 * through dart-sep ("IOSlaveMemory::getSlaveAddress", the vtable+0x80 call in
 * cmsgSET_OOL_IN). Which stream id a given buffer belongs to is not in the
 * message, and the tree lists several mappers for the SEP (mapper-sep for
 * plain buffers, mapper-sep-mpm for the "MPM" allocator AppleSEPManager sets
 * up at start), so each translation tries the listed sids in order. Reads and
 * writes are chunked at 4 KiB, the finest granule any Apple DART uses.
 */
static bool sep_dma(DarwinSEPState *s, uint64_t dva, void *buf, uint32_t len, bool is_write) {
    uint8_t *p = buf;
    if (!s->dart) {
        if (!s->dma_warned) {
            s->dma_warned = true;
            fprintf(stderr, "sep(%s): no DART; cannot reach dva 0x%" PRIx64 "\n", s->role, dva);
        }
        return false;
    }
    while (len) {
        uint64_t pa = 0;
        bool ok = false;
        for (int i = 0; i < s->n_sids && !ok; i++) {
            ok = darwin_dart_translate(s->dart, s->sids[i], dva, &pa);
        }
        if (!ok) {
            if (!s->dma_warned) {
                s->dma_warned = true;
                fprintf(stderr, "sep(%s): %s has no mapping for dva 0x%" PRIx64
                        " on any of its %d sids (%s)\n", s->role, s->dart_name, dva,
                        s->n_sids, is_write ? "write" : "read");
                for (int i = 0; i < s->n_sids; i++) darwin_dart_dump_sid(s->dart, s->sids[i]);
            }
            return false;
        }
        uint32_t chunk = 0x1000 - (uint32_t)(dva & 0xfff);
        if (chunk > len) chunk = len;
        if (address_space_rw(&address_space_memory, pa, MEMTXATTRS_UNSPECIFIED,
                             p, chunk, is_write) != MEMTX_OK) {
            fprintf(stderr, "sep(%s): guest memory access failed at pa 0x%" PRIx64 "\n", s->role, pa);
            return false;
        }
        dva += chunk;
        p += chunk;
        len -= chunk;
    }
    return true;
}

/* ---------------- TXM secure channel ---------------- */

#define TXM_SCRD_MAGIC_OFF   0x200
#define TXM_SCRD_MAGIC       0x5c01u     // low 16 bits; bit 16 = xART present
#define TXM_LOCK_MAGIC_OFF   0x400
#define TXM_LOCK_MAGIC       0x5c02u
#define TXM_LOCK_FLAG_OFF    0x448

// Write the SCRD state TXM validates. Retried from every later AP message
// until the DART mapping for the page exists; returns true once written.
static bool sep_txm_publish(DarwinSEPState *s) {
    uint32_t scrd = TXM_SCRD_MAGIC;      // xART bit clear: see the header
    uint16_t lock = TXM_LOCK_MAGIC;
    uint8_t flag = 0;

    if (s->txm_published || !s->txm_dva) return s->txm_published;
    if (!sep_dma(s, s->txm_dva + TXM_SCRD_MAGIC_OFF, &scrd, sizeof(scrd), true)) {
        s->dma_warned = false;   // the mapping may simply not exist yet
        return false;
    }
    sep_dma(s, s->txm_dva + TXM_LOCK_MAGIC_OFF, &lock, sizeof(lock), true);
    sep_dma(s, s->txm_dva + TXM_LOCK_FLAG_OFF, &flag, sizeof(flag), true);
    s->txm_published = true;
    fprintf(stderr, "sep(%s): TXM secure channel page at dva 0x%" PRIx64 " published "
            "(SCRD magic 0x%04x, xART 0, lockdown 0)\n", s->role, s->txm_dva, TXM_SCRD_MAGIC);
    return true;
}

/* ---------------- discovery ---------------- */

static void sep_advertise(DarwinSEPState *s) {
    for (int i = 0; i < s->n_adv; i++) {
        const SEPEndpointDef *d = s->adv[i];
        uint32_t ool = d->in_min | (d->in_max << 8) | (d->out_min << 16) | ((uint32_t)d->out_max << 24);
        sep_send(s, SEP_EP_DISCOVERY, 0, DISC_ADVERTISE, d->id, fourcc(d->name));
        sep_send(s, SEP_EP_DISCOVERY, 0, DISC_OOL, d->id, ool);
        s->ep[d->id].advertised = true;
        fprintf(stderr, "sep(%s): advertised endpoint %u '%s' (ool in %u..%u out %u..%u pages)\n",
                s->role, d->id, d->name, d->in_min, d->in_max, d->out_min, d->out_max);
    }
}

// sepOS is up: tell the control endpoint, then publish the endpoint directory.
static void sep_os_alive(DarwinSEPState *s) {
    if (s->os_alive) return;
    s->os_alive = true;
    sep_txm_publish(s);
    fprintf(stderr, "sep(%s): reporting sepOS alive and advertising %d endpoints\n", s->role, s->n_adv);
    sep_send(s, SEP_EP_CONTROL, 0, CTRL_NOTIFY_ALIVE, 0, 0);
    sep_advertise(s);
}

/* ---------------- endpoint handlers ---------------- */

static void sep_handle_bootstrap(DarwinSEPState *s, uint64_t m) {
    uint8_t tag = frame_tag(m), op = frame_op(m), param = frame_param(m);
    uint32_t data = frame_data(m);
    uint32_t word;

    switch (op) {
    case BOOT_PING:
        sep_send(s, SEP_EP_BOOTSTRAP, tag, BOOT_REPLY_ACK_BASE + op, 0, 0);
        break;
    case BOOT_GET_STATUS:
        fprintf(stderr, "sep(%s): ROM: status queried -> %u\n", s->role, s->status);
        sep_send(s, SEP_EP_BOOTSTRAP, tag, BOOT_REPLY_ACK_BASE + op, 0, s->status);
        break;
    case BOOT_GENERATE_NONCE:
        sep_send(s, SEP_EP_BOOTSTRAP, tag, BOOT_REPLY_ACK_BASE + op, 0, SEP_NONCE_BITS);
        break;
    case BOOT_GET_NONCE_WORD:
        // A nonce is only ever compared with itself later, so random is fine.
        qemu_guest_getrandom_nofail(&word, sizeof(word));
        sep_send(s, SEP_EP_BOOTSTRAP, tag, BOOT_REPLY_ACK_BASE + op, param, word);
        break;
    case BOOT_TZ0:
        s->status = SEP_STATUS_TZ0;
        fprintf(stderr, "sep(%s): ROM: TZ0 accepted (param 0x%02x), status -> %u\n", s->role, param, s->status);
        sep_send(s, SEP_EP_BOOTSTRAP, tag, BOOT_REPLY_ACK_BASE + op, 0, 0);
        break;
    case BOOT_LOAD_SEP_ART:
        fprintf(stderr, "sep(%s): ROM: SEP ART at page 0x%x accepted\n", s->role, data);
        sep_send(s, SEP_EP_BOOTSTRAP, tag, BOOT_REPLY_ACK_BASE + op, 0, 0);
        break;
    case BOOT_IMG4:
    case BOOT_RESUME:
        fprintf(stderr, "sep(%s): ROM: %s (firmware page 0x%x, param 0x%02x); sepOS \"running\"\n",
                s->role, op == BOOT_IMG4 ? "IMG4 accepted" : "resumed", data, param);
        sep_send(s, SEP_EP_BOOTSTRAP, tag, BOOT_REPLY_ACK_BASE + op, 0, 0);
        sep_os_alive(s);
        break;
    case BOOT_TMM_MANIFEST:
    case BOOT_PATCH:
        fprintf(stderr, "sep(%s): ROM: op %u (page 0x%x) accepted\n", s->role, op, data);
        sep_send(s, SEP_EP_BOOTSTRAP, tag, BOOT_REPLY_ACK_BASE + op, 0, 0);
        break;
    case BOOT_IBIC_QUERY:
        // "unsupported opcode 30" is the one non-ack _bootAction tolerates
        fprintf(stderr, "sep(%s): ROM: iBIC key capture declined as unsupported\n", s->role);
        sep_send(s, SEP_EP_BOOTSTRAP, tag, BOOT_REPLY_UNSUPPORTED, 0, BOOT_IBIC_QUERY);
        break;
    default:
        // Not answered on purpose: a wrong reply opcode panics the AP through
        // _bootAction's "SEP Boot failure, op %u" path, whereas silence ends in
        // "SEP ROM timeout - no response", which is a warning we can read.
        fprintf(stderr, "sep(%s): ROM: unhandled bootstrap op %u (param %u data 0x%08x); not replying\n",
                s->role, op, param, data);
        break;
    }
}

static void sep_handle_control(DarwinSEPState *s, uint64_t m) {
    uint8_t tag = frame_tag(m), op = frame_op(m), param = frame_param(m);
    uint32_t data = frame_data(m);
    SEPEndpointState *e = &s->ep[param];

    switch (op) {
    case CTRL_NOP:
        break;
    case CTRL_SET_OOL_IN_ADDR:
        e->ool_in_addr = (uint64_t)data << s->addr_shift;
        fprintf(stderr, "sep(%s): ep %u '%s' OOL in  dva 0x%" PRIx64 " size 0x%x\n",
                s->role, param, ep_name(s, param), e->ool_in_addr, e->ool_in_size);
        break;
    case CTRL_SET_OOL_OUT_ADDR:
        e->ool_out_addr = (uint64_t)data << s->addr_shift;
        fprintf(stderr, "sep(%s): ep %u '%s' OOL out dva 0x%" PRIx64 " size 0x%x\n",
                s->role, param, ep_name(s, param), e->ool_out_addr, e->ool_out_size);
        break;
    case CTRL_SET_OOL_IN_SIZE:
        e->ool_in_size = data;
        break;
    case CTRL_SET_OOL_OUT_SIZE:
        e->ool_out_size = data;
        break;
    case CTRL_SECURITY_MODE:
    case CTRL_SELF_TEST:
    case CTRL_ERASE_INSTALL:
    case CTRL_SLEEP:
    case CTRL_NAP:
    case CTRL_TTY_IN:
        if (s->debug) fprintf(stderr, "sep(%s): control op %u acknowledged\n", s->role, op);
        break;
    case CTRL_GET_ENTROPY: {
        uint32_t word;
        qemu_guest_getrandom_nofail(&word, sizeof(word));
        sep_send(s, SEP_EP_CONTROL, tag, CTRL_ACK, 0, word);
        return;
    }
    default:
        // Acknowledged rather than ignored: AppleSEPControl::_cmsgSend blocks
        // on the reply for every control message it sends, and a hang is
        // harder to diagnose than an ack we logged as a guess.
        fprintf(stderr, "sep(%s): control op %u (param %u data 0x%08x) is not understood; "
                "acknowledging blindly\n", s->role, op, param, data);
        break;
    }
    sep_send(s, SEP_EP_CONTROL, tag, CTRL_ACK, 0, 0);
}

static void sep_handle_l4info(DarwinSEPState *s, uint64_t m) {
    // { ep, tag, u16 size_pages, u32 addr_pages }: AppleSEPBooter::bootSEP
    // 0xfffffff00959c430..0x59c4b4
    uint32_t size_pages = (m >> 16) & 0xffff;
    uint32_t addr_pages = m >> 32;
    s->shm_dva = (uint64_t)addr_pages << s->addr_shift;
    s->shm_size = size_pages << s->addr_shift;
    fprintf(stderr, "sep(%s): L4Info: shared memory at dva 0x%" PRIx64 " size 0x%x\n",
            s->role, s->shm_dva, s->shm_size);
}

static void sep_handle_xart(DarwinSEPState *s, uint64_t m) {
    // Every xART request gets the generic ack (op 0) it waits for. What the
    // request meant is logged so a future pass can give real answers.
    fprintf(stderr, "sep(%s): xART ep %u op %u param %u data 0x%08x: acknowledged without action\n",
            s->role, frame_ep(m), frame_op(m), frame_param(m), frame_data(m));
    sep_send(s, frame_ep(m), frame_tag(m), 0, 0, 0);
}

static void sep_receive(DarwinSEPState *s, uint64_t m) {
    uint8_t ep = frame_ep(m);
    if (s->os_alive && !s->txm_published) sep_txm_publish(s);
    if (s->debug) {
        fprintf(stderr, "sep(%s): AP -> SEP ep %3u (%s) tag %u op %3u param %3u data 0x%08x\n",
                s->role, ep, ep_name(s, ep), frame_tag(m), frame_op(m), frame_param(m), frame_data(m));
    }
    switch (ep) {
    case SEP_EP_BOOTSTRAP: sep_handle_bootstrap(s, m); break;
    case SEP_EP_CONTROL:   sep_handle_control(s, m); break;
    case SEP_EP_L4INFO:    sep_handle_l4info(s, m); break;
    case 16: case 19:      sep_handle_xart(s, m); break;
    default:
        // scrd, sks and friends: logged and left unanswered until their
        // protocols are modelled. This is the honest hole, not a guess.
        fprintf(stderr, "sep(%s): ep %u '%s' op %u tag %u param %u data 0x%08x: no handler\n",
                s->role, ep, ep_name(s, ep), frame_op(m), frame_tag(m), frame_param(m), frame_data(m));
        break;
    }
}

/*
 * The ROM announces itself as soon as the AP opens the mailbox. On hardware
 * the SEP ROM is running from power-on and the announce is already sitting in
 * the fifo; sending it when the AP first enables a fifo direction is the
 * closest we can get without raising an interrupt before the AIC exists.
 */
static void sep_maybe_announce(DarwinSEPState *s) {
    if (s->announced) return;
    s->announced = true;
    fprintf(stderr, "sep(%s): mailbox opened by the AP; announcing ROM status %u\n", s->role, s->status);
    sep_send(s, SEP_EP_BOOTSTRAP, 0, BOOT_REPLY_STATUS, 0, s->status);
}

/* ---------------- MMIO ---------------- */

static uint64_t sep_read(void *opaque, hwaddr offset, unsigned size) {
    DarwinSEPState *s = opaque;
    uint64_t val = 0;

    if (offset == ASC_CPU_CONTROL) {
        val = s->cpu_control;
    } else if (offset == ASC_CPU_STATUS) {
        val = s->cpu_status;
    } else if (offset >= s->mbox_off && offset < s->mbox_off + 0x1000) {
        uint32_t r = offset - s->mbox_off;
        switch (r) {
        case MBOX_A2I_CTRL:
            val = s->a2i_ctrl_raw | MBOX_CTRL_EMPTY;
            break;
        case MBOX_I2A_CTRL: {
            uint32_t rptr = s->i2a_head & MBOX_CTRL_PTR_MASK;
            uint32_t wptr = (s->i2a_head + s->i2a_count) & MBOX_CTRL_PTR_MASK;
            val = s->i2a_ctrl_raw & ~(MBOX_CTRL_FULL | MBOX_CTRL_EMPTY |
                                      (0xf << MBOX_CTRL_CNT_SHIFT) |
                                      (MBOX_CTRL_PTR_MASK << MBOX_CTRL_RPTR_SHIFT) |
                                      (MBOX_CTRL_PTR_MASK << MBOX_CTRL_WPTR_SHIFT));
            if (s->i2a_count == 0) val |= MBOX_CTRL_EMPTY;
            if (s->i2a_count >= MBOX_FIFO_VISIBLE) val |= MBOX_CTRL_FULL;
            val |= (uint64_t)(s->i2a_count & 0xf) << MBOX_CTRL_CNT_SHIFT;
            val |= (uint64_t)rptr << MBOX_CTRL_RPTR_SHIFT;
            val |= (uint64_t)wptr << MBOX_CTRL_WPTR_SHIFT;
            break;
        }
        case MBOX_I2A_RECV0:
            if (s->i2a_count) val = s->i2a_fifo[s->i2a_head].msg0;
            break;
        case MBOX_I2A_RECV1:
            if (s->i2a_count) {
                val = s->i2a_fifo[s->i2a_head].msg1;
                val |= (uint64_t)(s->i2a_count & 0xf) << 52;
                s->i2a_head = (s->i2a_head + 1) % MBOX_FIFO_DEPTH;
                s->i2a_count--;
                sep_refill_visible(s);
                sep_update_irqs(s);
            }
            break;
        case MBOX_A2I_SEND0:
            val = s->a2i_send0;
            break;
        default:
            if (offset + 4 <= s->mmio_size) val = s->misc[offset / 4];
            break;
        }
    } else if (offset + 4 <= s->mmio_size) {
        val = s->misc[offset / 4];
    }

    if (s->debug) fprintf(stderr, "sep(%s): read  0x%05" HWADDR_PRIx " -> 0x%" PRIx64 "\n", s->role, offset, val);
    return val;
}

static void sep_write(void *opaque, hwaddr offset, uint64_t val, unsigned size) {
    DarwinSEPState *s = opaque;

    if (s->debug) fprintf(stderr, "sep(%s): write 0x%05" HWADDR_PRIx " <- 0x%" PRIx64 "\n", s->role, offset, val);

    if (offset == ASC_CPU_CONTROL) {
        bool was_run = s->cpu_control & ASC_CPU_CONTROL_RUN;
        s->cpu_control = val;
        if ((val & ASC_CPU_CONTROL_RUN) && !was_run) {
            fprintf(stderr, "sep(%s): AP set CPU_CONTROL.RUN\n", s->role);
            s->cpu_status = ASC_CPU_STATUS_RUNNING;
            sep_maybe_announce(s);
        } else if (!(val & ASC_CPU_CONTROL_RUN) && was_run) {
            fprintf(stderr, "sep(%s): AP cleared CPU_CONTROL.RUN\n", s->role);
            s->cpu_status = ASC_CPU_STATUS_STOPPED;
        }
    } else if (offset == ASC_CPU_STATUS) {
        // read only
    } else if (offset >= s->mbox_off && offset < s->mbox_off + 0x1000) {
        uint32_t r = offset - s->mbox_off;
        switch (r) {
        case MBOX_A2I_CTRL:
            s->a2i_ctrl_raw = val & ~(MBOX_CTRL_FULL | MBOX_CTRL_EMPTY | (0xf << MBOX_CTRL_CNT_SHIFT));
            if (val & MBOX_CTRL_ENABLE) sep_maybe_announce(s);
            break;
        case MBOX_I2A_CTRL:
            s->i2a_ctrl_raw = val & ~(MBOX_CTRL_FULL | MBOX_CTRL_EMPTY | (0xf << MBOX_CTRL_CNT_SHIFT));
            if (val & MBOX_CTRL_ENABLE) sep_maybe_announce(s);
            break;
        case MBOX_A2I_SEND0:
            s->a2i_send0 = val;
            break;
        case MBOX_A2I_SEND1:
            // The AP writes 0 here for every SEP message; the frame in SEND0
            // carries the endpoint. Consumed on the spot, so a2i never fills.
            sep_receive(s, s->a2i_send0);
            break;
        default:
            if (offset + 4 <= s->mmio_size) s->misc[offset / 4] = val;
            break;
        }
    } else if (offset + 4 <= s->mmio_size) {
        s->misc[offset / 4] = val;
    }
}

static const MemoryRegionOps sep_ops = {
    .read = sep_read,
    .write = sep_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 8,
    .valid.min_access_size = 4,
    .valid.max_access_size = 8,
};

/* ---------------- device ---------------- */

static void sep_pick_endpoints(DarwinSEPState *s) {
    const char *env = getenv("DARWIN_SEP_EPS");
    g_autofree char *list = g_strdup(env ? env : sep_default_eps);
    char *save = NULL;
    s->n_adv = 0;
    for (char *tok = strtok_r(list, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        bool found = false;
        for (size_t i = 0; i < ARRAY_SIZE(sep_all_eps); i++) {
            if (strncmp(tok, sep_all_eps[i].name, strlen(tok)) == 0 && strlen(tok) >= 3) {
                s->adv[s->n_adv++] = &sep_all_eps[i];
                found = true;
                break;
            }
        }
        if (!found) fprintf(stderr, "sep(%s): DARWIN_SEP_EPS: unknown endpoint '%s' ignored\n", s->role, tok);
    }
}

static void darwin_sep_realize(DeviceState *dev, Error **errp) {
    DarwinSEPState *s = DARWIN_SEP(dev);
    if (!s->mmio_size) {
        error_setg(errp, "darwin-sep: no mmio size");
        return;
    }
    s->misc = g_new0(uint32_t, s->mmio_size / 4);
    s->cpu_status = ASC_CPU_STATUS_STOPPED;
    s->status = SEP_STATUS_ROM;
    s->debug = getenv("DARWIN_SEP_DEBUG") != NULL;
    sep_pick_endpoints(s);
    memory_region_init_io(&s->iomem, OBJECT(s), &sep_ops, s, "darwin-sep", s->mmio_size);
    sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->iomem);
    for (int i = 0; i < 4; i++) sysbus_init_irq(SYS_BUS_DEVICE(dev), &s->irq[i]);
}

static const Property darwin_sep_properties[] = {
    DEFINE_PROP_STRING("role", DarwinSEPState, role),
    DEFINE_PROP_UINT32("mmio-size", DarwinSEPState, mmio_size, 0),
    DEFINE_PROP_UINT32("mbox-offset", DarwinSEPState, mbox_off, 0x8000),
    // page-number unit of every address the protocol carries (see header)
    DEFINE_PROP_UINT32("addr-shift", DarwinSEPState, addr_shift, 12),
};

static void darwin_sep_class_init(ObjectClass *klass, const void *data) {
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = darwin_sep_realize;
    dc->desc = "Apple Secure Enclave, AP-facing protocol only";
    device_class_set_props(dc, darwin_sep_properties);
    dc->user_creatable = false;
}

static const TypeInfo darwin_sep_info = {
    .name          = TYPE_DARWIN_SEP,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(DarwinSEPState),
    .class_init    = darwin_sep_class_init,
};

static void darwin_sep_register_types(void) {
    type_register_static(&darwin_sep_info);
}

type_init(darwin_sep_register_types)

/* ---------------- device tree glue ---------------- */

// Resolve one iommu-mapper phandle to (dart node, stream id).
static struct dtree_node *sep_find_mapper(struct dtree_node *arm_io, uint32_t phandle, unsigned *sid) {
    for (struct dtree_node *dart = adt_first_child(arm_io); dart; dart = adt_next_sibling(arm_io, dart)) {
        const char *dtype = adt_get_prop_val(dart, "device_type");
        if (!dtype || strcmp(dtype, "dart")) continue;
        for (struct dtree_node *m = adt_first_child(dart); m; m = adt_next_sibling(dart, m)) {
            uint32_t *ph = adt_get_prop_val(m, "AAPL,phandle");
            uint32_t *reg = adt_get_prop_val(m, "reg");
            if (!ph || !reg || *ph != phandle) continue;
            *sid = *reg;
            return dart;
        }
    }
    return NULL;
}

DeviceState *darwin_sep_create(struct dtree_node *dt_root, uint64_t iobase, DeviceState *aic) {
    struct dtree_node *node = adt_find_node(dt_root, "arm-io/sep");
    if (!node || !adt_get_prop_val(node, "compatible")) return NULL;

    struct adt_io_reg *reg = adt_get_prop_val(node, "reg");
    const char *role = adt_get_prop_val(node, "role");
    const char *name = adt_get_prop_val(node, "name");
    uint32_t *irqs = adt_get_prop_val(node, "interrupts");
    size_t n_irqs = irqs ? adt_get_prop_len(node, "interrupts") / 4 : 0;
    if (!reg) return NULL;

    DeviceState *dev = qdev_new(TYPE_DARWIN_SEP);
    qdev_prop_set_string(dev, "role", role ? role : name);
    qdev_prop_set_uint32(dev, "mmio-size", reg[0].len);
    DarwinSEPState *s = DARWIN_SEP(dev);

    /*
     * DMA geometry from the tree: "iommu-parent" lists one phandle per mapper
     * the SEP may use (<&mapper-sep &mapper-sep-mpm> on t8140); each mapper's
     * "reg" is its stream id on the DART that owns it.
     */
    struct dtree_node *arm_io = adt_find_node(dt_root, "arm-io");
    uint32_t *parents = adt_get_prop_val(node, "iommu-parent");
    size_t n_parents = parents ? adt_get_prop_len(node, "iommu-parent") / 4 : 0;
    struct dtree_node *dart_node = NULL;
    for (size_t i = 0; i < n_parents && s->n_sids < (int)ARRAY_SIZE(s->sids); i++) {
        unsigned sid;
        struct dtree_node *d = sep_find_mapper(arm_io, parents[i], &sid);
        if (!d) continue;
        if (dart_node && d != dart_node) continue;   // one DART per model
        dart_node = d;
        s->sids[s->n_sids++] = sid;
    }
    if (dart_node) {
        s->dart_name = g_strdup(adt_get_prop_val(dart_node, "name"));
        s->dart = darwin_dart_find(s->dart_name);
        // The TXM secure channel page lives at a fixed DVA on this DART.
        uint64_t *txm_base = adt_get_prop_val(dart_node, "txm-secure-channel-base");
        uint64_t *txm_size = adt_get_prop_val(dart_node, "txm-secure-channel-size");
        if (txm_base && txm_size) {
            s->txm_dva = *txm_base;
            s->txm_size = *txm_size;
        }
        if (!s->dart) {
            fprintf(stderr, "sep: device tree points at DART \"%s\" but no darwin-dart was "
                    "created for it; OOL buffers will be unreachable\n", s->dart_name);
        }
    } else {
        fprintf(stderr, "sep: no iommu-parent -> iommu-mapper chain; OOL buffers will be unreachable\n");
    }

    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);
    sysbus_realize_and_unref(sbd, &error_fatal);
    sysbus_mmio_map(sbd, 0, reg[0].base + iobase);
    for (size_t i = 0; i < 4 && i < n_irqs; i++) {
        if (aic) sysbus_connect_irq(sbd, i, darwin_aic_get_irq(aic, irqs[i]));
    }

    fprintf(stderr, "darwin-sep: %s (%s) at 0x%" PRIx64 " irqs", s->role, name, reg[0].base + iobase);
    for (size_t i = 0; i < n_irqs; i++) fprintf(stderr, " 0x%x", irqs[i]);
    fprintf(stderr, "; dma via %s sids", s->dart_name ? s->dart_name : "(none)");
    for (int i = 0; i < s->n_sids; i++) fprintf(stderr, " %u", s->sids[i]);
    if (s->txm_dva) fprintf(stderr, "; txm channel dva 0x%" PRIx64 " size 0x%" PRIx64, s->txm_dva, s->txm_size);
    fprintf(stderr, "; advertising");
    for (int i = 0; i < s->n_adv; i++) fprintf(stderr, " %s", s->adv[i]->name);
    fprintf(stderr, "\n");
    return dev;
}
