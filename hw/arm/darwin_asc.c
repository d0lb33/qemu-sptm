/*
 * darwin-asc: Apple "ASC" coprocessor wrapper + mailbox + RTKit protocol
 *
 * Every Apple Silicon coprocessor (DCP, ANS, SMC, AOP, SIO, MTP, GFX, ...)
 * is an ARM core running Apple's RTKit RTOS, talking to the AP through a
 * small hardware mailbox. This models the AP-visible side of that:
 *
 *   ASC core status (device tree "reg[1]"):
 *     +0x0000  FIRMWARE_STATUS bit 0 = firmware image loaded
 *   ASC wrapper (device tree "reg[0]", compatible iop,ascwrap-v*):
 *     +0x0040  AKF_RUNNING  bit 0 = firmware running
 *     +0x0044  CPU_CONTROL  bit 4 = RUN
 *     +0x0048  CPU_STATUS   bit 0 = running, bit 1 = stopped, bit 5 = idle
 *   Mailbox at +0x8000 (the "asc-mailbox-v4" layout):
 *     +0x110  A2I_CTRL     AP -> IOP fifo status (bit 16 FULL, bit 17 EMPTY, [23:20] count)
 *     +0x114  I2A_CTRL     IOP -> AP fifo status
 *     +0x800  A2I_SEND0    64-bit message payload
 *     +0x808  A2I_SEND1    endpoint in bits [7:0]; the write commits the message
 *     +0x830  I2A_RECV0    64-bit message payload
 *     +0x838  I2A_RECV1    endpoint in bits [7:0]; the read pops the message
 *
 * Interrupts (node "interrupts"): a2i empty, a2i not-empty, i2a empty, i2a
 * not-empty, all level triggered.
 *
 * On top of the mailbox we speak RTKit's management endpoint (endpoint 0):
 * HELLO / HELLO_ACK version negotiation, endpoint map, endpoint start,
 * power state requests and pings. Per-coprocessor behaviour (the DCP's
 * display protocol, ANS's NVMe, ...) is layered on through DarwinASCOps.
 *
 * References: Linux drivers/soc/apple/{mailbox,rtkit}.c, m1n1 fw/asc,
 * and XNU's AppleA7IOP-ASCWrap-v6 / RTBuddy kexts (register offsets
 * cross-checked by disassembly).
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "qemu/timer.h"
#include "hw/core/sysbus.h"
#include "hw/core/irq.h"
#include "hw/core/qdev-properties.h"
#include "system/memory.h"
#include "xnu/boot/xnuboot.h"
#include "xnu/apple_dtree.h"
#include "xnu/darwin_aic.h"
#include "xnu/darwin_asc.h"

OBJECT_DECLARE_SIMPLE_TYPE(DarwinASCState, DARWIN_ASC)

#define ASC_FIRMWARE_STATUS        0x00
#define ASC_FIRMWARE_STATUS_LOADED BIT(0)
#define ASC_CPU_CONTROL     0x44
#define ASC_CPU_CONTROL_RUN BIT(4)
#define ASC_CPU_STATUS      0x48
#define ASC_CPU_STATUS_RUNNING BIT(0)
#define ASC_CPU_STATUS_STOPPED BIT(1)
#define ASC_CPU_STATUS_IDLE    BIT(5)

/*
 * Nodes with the `idle-ctrl-check` device-tree property first require bit 0
 * of this register before consulting IDLE_STATUS.  AppleASCWrapV6::fn_0x720
 * performs that gate at static 0xfffffff0085384cc..0xfffffff008538500, and
 * the kext diagnostic string names the condition "AKF_RUNNING: False".
 */
#define ASC_AKF_RUNNING          0x40
#define ASC_AKF_RUNNING_FIRMWARE BIT(0)

/*
 * AppleASCWrapV6::fn_0x720 reads this mailbox-block register and considers
 * the IOP idle when either low bit is set (iOS 27 static 0xfffffff00853852c
 * through 0xfffffff008538544).  AppleA7IOP's sleep path polls that method
 * before it releases the power transition.
 */
#define ASC_IDLE_STATUS        0x8000
#define ASC_IDLE_STATUS_IDLE   BIT(0)
#define ASC_IDLE_STATUS_MASK   0x3

#define MBOX_A2I_CTRL   0x110
#define MBOX_I2A_CTRL   0x114
#define MBOX_A2I_SEND0  0x800
#define MBOX_A2I_SEND1  0x808
#define MBOX_A2I_RECV0  0x810
#define MBOX_A2I_RECV1  0x818
#define MBOX_I2A_SEND0  0x820
#define MBOX_I2A_SEND1  0x828
#define MBOX_I2A_RECV0  0x830
#define MBOX_I2A_RECV1  0x838

// Control register layout, from m1n1's R_MBOX_CTRL (hw/asc.py):
//   [23:20] FIFOCNT   number of messages queued
//   [18]    OVERFLOW
//   [17]    EMPTY
//   [16]    FULL
//   [15:12] RPTR      read pointer
//   [11:8]  WPTR      write pointer
//   [0]     ENABLE    (written by the guest)
#define MBOX_CTRL_FULL      BIT(16)
#define MBOX_CTRL_EMPTY     BIT(17)
#define MBOX_CTRL_CNT_SHIFT 20
#define MBOX_CTRL_RPTR_SHIFT 12
#define MBOX_CTRL_WPTR_SHIFT 8
#define MBOX_CTRL_PTR_MASK   0xf

#define MBOX_FIFO_DEPTH 16

// Occupancy is mirrored into a *four-bit* field — I2A_CTRL bits [55:52], and
// the same count in the high half of I2A_RECV1 (see the comment on that read).
// Four bits express 0..15, so an occupancy of 16 would mirror as 0 and read as
// an empty FIFO. Never make more than 15 entries visible at once.
#define MBOX_FIFO_VISIBLE 15

// Anything beyond that is staged here rather than dropped. A burst of EPIC
// service announces (16 services on one endpoint) overflowed the visible FIFO,
// and the message lost was the last and only meaningful one, which stalled the
// guest. Deepening the visible FIFO is not an option, so we hold the surplus
// behind it and refill as the AP drains. Real hardware back-pressures the
// coprocessor instead; a staging queue is the same thing seen from the AP side,
// since the AP cannot tell how much the IOP has yet to send.
#define MBOX_PEND_DEPTH 256

// RTKit management endpoint
#define EP_MGMT       0
#define EP_CRASHLOG   1
#define EP_SYSLOG     2
#define EP_DEBUG      3
#define EP_IOREPORT   4
#define EP_OSLOG      8
#define EP_TRACEKIT   0xa

#define MGMT_TYPE_SHIFT     52
#define MGMT_TYPE(m)        (((m) >> MGMT_TYPE_SHIFT) & 0xff)
#define MGMT_MSG(type)      ((uint64_t)(type) << MGMT_TYPE_SHIFT)

#define MGMT_HELLO          1
#define MGMT_HELLO_ACK      2
#define MGMT_PING           3
#define MGMT_PONG           4
#define MGMT_START_EP       5
#define MGMT_SET_IOP_PWR    6
#define MGMT_IOP_PWR_ACK    7
#define MGMT_EPMAP          8
#define MGMT_SET_AP_PWR     0xb

#define MGMT_EPMAP_LAST     BIT_ULL(51)
#define MGMT_EPMAP_BASE(b)  ((uint64_t)((b) & 7) << 32)
#define MGMT_EPMAP_ACK_MORE BIT_ULL(0)

#define MGMT_STARTEP_EP(m)   (((m) >> 32) & 0xff)
#define MGMT_STARTEP_FLAG(m) ((m) & 3)

#define MGMT_PWR_STATE(m)    ((m) & 0xffff)
#define PWR_STATE_BASE(s)    ((s) & 0xff)
#define PWR_STATE_SLEEP      0x01
#define PWR_STATE_QUIESCED   0x10
#define PWR_STATE_ON         0x20
#define PWR_STATE_INIT       0x220

#define RTKIT_MIN_VERSION    11
#define RTKIT_MAX_VERSION    12

enum {
    RTK_IDLE = 0,       // not booted
    RTK_WAIT_HELLO_ACK,
    RTK_WAIT_EPMAP_ACK,
    RTK_BOOTED,
};

typedef struct {
    uint64_t msg0, msg1;
} ASCMsg;

struct DarwinASCState {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    MemoryRegion firmware_status_iomem;
    char *role;
    uint32_t mmio_size;
    uint32_t mbox_off;
    qemu_irq irq[4];

    // asc
    uint32_t firmware_status, cpu_control, cpu_status;
    uint32_t *misc;

    // mailbox
    uint32_t a2i_ctrl_raw, i2a_ctrl_raw;
    uint64_t a2i_send0;
    ASCMsg i2a_fifo[MBOX_FIFO_DEPTH];
    int i2a_head, i2a_count;
    ASCMsg pend_fifo[MBOX_PEND_DEPTH];
    int pend_head, pend_count;

    // rtkit
    int rtk_state;
    uint16_t proto_version;
    uint64_t ep_map[8];         // bit per endpoint, 256 endpoints
    int epmap_next_block;
    bool iop_pwr_pending;
    uint16_t iop_pwr_state, ap_pwr_state;
    bool ep_started[256];

    const DarwinASCOps *ops;
    void *opaque;
    bool debug;

    // DARWIN_ASC_AUTOSTART=<seconds>: bring the IOP up on our own after this
    // many seconds of guest time, without waiting for the AP to write
    // CPU_CONTROL.RUN. This is a diagnostic, not hardware behaviour: it tells
    // us whether the AP-side RTKit stack will talk to a coprocessor it never
    // asked to start, which distinguishes "nothing requested power" from
    // "the mailbox path itself is wrong".
    QEMUTimer *autostart_timer;
};

static const char *rtk_type_name(unsigned t) {
    switch (t) {
    case MGMT_HELLO: return "HELLO";
    case MGMT_HELLO_ACK: return "HELLO_ACK";
    case MGMT_PING: return "PING";
    case MGMT_PONG: return "PONG";
    case MGMT_START_EP: return "START_EP";
    case MGMT_SET_IOP_PWR: return "SET_IOP_PWR";
    case MGMT_IOP_PWR_ACK: return "IOP_PWR_ACK";
    case MGMT_EPMAP: return "EPMAP";
    case MGMT_SET_AP_PWR: return "SET_AP_PWR";
    default: return "?";
    }
}

/* ---------------- mailbox ---------------- */

// Interrupt line order follows Apple's A7IOP convention (index into the
// node's "interrupts"): 0 = IOP inbox (a2i) not-empty, 1 = IOP inbox empty,
// 2 = AP inbox (i2a) not-empty, 3 = AP inbox empty.
static void asc_update_irqs(DarwinASCState *s) {
    bool i2a_empty = (s->i2a_count == 0);
    qemu_set_irq(s->irq[0], 0);              // a2i never stays non-empty: we consume instantly
    qemu_set_irq(s->irq[1], 1);
    qemu_set_irq(s->irq[2], !i2a_empty);
    qemu_set_irq(s->irq[3], i2a_empty);
}

static void asc_push_visible(DarwinASCState *s, uint8_t ep, uint64_t msg) {
    int idx = (s->i2a_head + s->i2a_count) % MBOX_FIFO_DEPTH;
    s->i2a_fifo[idx].msg0 = msg;
    s->i2a_fifo[idx].msg1 = ep;
    s->i2a_count++;
}

// Move staged messages into the visible FIFO as the AP makes room.
static void asc_refill_visible(DarwinASCState *s) {
    while (s->i2a_count < MBOX_FIFO_VISIBLE && s->pend_count) {
        ASCMsg m = s->pend_fifo[s->pend_head];
        s->pend_head = (s->pend_head + 1) % MBOX_PEND_DEPTH;
        s->pend_count--;
        asc_push_visible(s, (uint8_t)m.msg1, m.msg0);
    }
}

void darwin_asc_send(DeviceState *dev, uint8_t ep, uint64_t msg) {
    DarwinASCState *s = DARWIN_ASC(dev);

    if (s->i2a_count < MBOX_FIFO_VISIBLE) {
        asc_push_visible(s, ep, msg);
    } else if (s->pend_count < MBOX_PEND_DEPTH) {
        int idx = (s->pend_head + s->pend_count) % MBOX_PEND_DEPTH;
        s->pend_fifo[idx].msg0 = msg;
        s->pend_fifo[idx].msg1 = ep;
        s->pend_count++;
        if (s->debug) {
            fprintf(stderr, "asc(%s): i2a full, staged ep 0x%02x (%d waiting)\n",
                    s->role, ep, s->pend_count);
        }
    } else {
        // Only reachable if the AP has stopped draining entirely.
        fprintf(stderr, "asc(%s): i2a fifo and %d-deep staging queue both full, "
                "dropping ep %u msg 0x%016" PRIx64 "\n",
                s->role, MBOX_PEND_DEPTH, ep, msg);
        return;
    }

    if (s->debug) fprintf(stderr, "asc(%s): IOP -> AP ep 0x%02x 0x%016" PRIx64 "\n", s->role, ep, msg);
    asc_update_irqs(s);
}

/* ---------------- rtkit management ---------------- */

static void rtk_send_mgmt(DarwinASCState *s, uint64_t msg) {
    if (s->debug) fprintf(stderr, "asc(%s): mgmt -> AP %s\n", s->role, rtk_type_name(MGMT_TYPE(msg)));
    darwin_asc_send(DEVICE(s), EP_MGMT, msg);
}

static void rtk_send_epmap_block(DarwinASCState *s) {
    // find next block with endpoints, from epmap_next_block on
    int last_block = 7;
    while (last_block > 0 && !s->ep_map[last_block]) last_block--;
    int b = s->epmap_next_block;
    while (b < last_block && !s->ep_map[b]) b++;
    bool last = (b >= last_block);
    uint64_t msg = MGMT_MSG(MGMT_EPMAP) | MGMT_EPMAP_BASE(b) | (uint32_t)s->ep_map[b];
    if (last) msg |= MGMT_EPMAP_LAST;
    s->epmap_next_block = b + 1;
    rtk_send_mgmt(s, msg);
}

static void asc_set_idle(DarwinASCState *s, bool idle);

static void rtk_boot(DarwinASCState *s) {
    if (s->rtk_state != RTK_IDLE) return;
    /*
     * This model's RTKit implementation is the firmware image.  Once it has
     * booted, retain the loaded-image witness across CPU power transitions.
     * AppleASCWrapV6::fn_0x2ec reads bit 0 at wrapper offset 0 before a
     * restart and otherwise panics "ASC firmware must be loaded by iBoot"
     * (static 0xfffffff00853832c..0xfffffff00853834c).
     */
    s->firmware_status = ASC_FIRMWARE_STATUS_LOADED;
    s->misc[ASC_AKF_RUNNING / sizeof(uint32_t)] =
        ASC_AKF_RUNNING_FIRMWARE;
    asc_set_idle(s, false);
    s->rtk_state = RTK_WAIT_HELLO_ACK;
    if (s->debug) fprintf(stderr, "asc(%s): booting, sending HELLO\n", s->role);
    rtk_send_mgmt(s, MGMT_MSG(MGMT_HELLO) | ((uint64_t)RTKIT_MAX_VERSION << 16) | RTKIT_MIN_VERSION);
}

static void rtk_booted(DarwinASCState *s) {
    s->rtk_state = RTK_BOOTED;
    fprintf(stderr, "asc(%s): RTKit handshake complete (protocol v%u)\n", s->role, s->proto_version);
    if (s->iop_pwr_pending) {
        s->iop_pwr_pending = false;
        s->iop_pwr_state = PWR_STATE_ON;
        rtk_send_mgmt(s, MGMT_MSG(MGMT_IOP_PWR_ACK) | PWR_STATE_ON);
    }
    if (s->ops && s->ops->started) s->ops->started(s->opaque);
}

static void asc_set_idle(DarwinASCState *s, bool idle)
{
    if (idle) {
        s->cpu_status = ASC_CPU_STATUS_RUNNING | ASC_CPU_STATUS_IDLE;
    } else {
        s->cpu_status = ASC_CPU_STATUS_RUNNING;
    }
    if (ASC_IDLE_STATUS + sizeof(uint32_t) <= s->mmio_size) {
        uint32_t *status = &s->misc[ASC_IDLE_STATUS / sizeof(uint32_t)];
        *status = (*status & ~ASC_IDLE_STATUS_MASK) |
                  (idle ? ASC_IDLE_STATUS_IDLE : 0);
    }
}

static void rtk_handle_mgmt(DarwinASCState *s, uint64_t msg) {
    unsigned type = MGMT_TYPE(msg);
    if (s->debug) fprintf(stderr, "asc(%s): mgmt <- AP %s 0x%016" PRIx64 "\n", s->role, rtk_type_name(type), msg);

    switch (type) {
    case MGMT_HELLO_ACK: {
        uint16_t minv = msg & 0xffff, maxv = (msg >> 16) & 0xffff;
        s->proto_version = maxv;
        fprintf(stderr, "asc(%s): AP accepted RTKit protocol [%u,%u]\n", s->role, minv, maxv);
        s->rtk_state = RTK_WAIT_EPMAP_ACK;
        s->epmap_next_block = 0;
        rtk_send_epmap_block(s);
        break;
    }
    case MGMT_EPMAP:
        // ack from the AP
        if (msg & MGMT_EPMAP_LAST || !(msg & MGMT_EPMAP_ACK_MORE)) {
            if (s->rtk_state == RTK_WAIT_EPMAP_ACK) rtk_booted(s);
        } else {
            rtk_send_epmap_block(s);
        }
        break;
    case MGMT_PING:
        rtk_send_mgmt(s, MGMT_MSG(MGMT_PONG) | (msg & ((1ULL << MGMT_TYPE_SHIFT) - 1)));
        break;
    case MGMT_START_EP: {
        uint8_t ep = MGMT_STARTEP_EP(msg);
        uint32_t flag = MGMT_STARTEP_FLAG(msg);
        s->ep_started[ep] = (flag == 2);
        fprintf(stderr, "asc(%s): AP %s endpoint 0x%02x\n", s->role, flag == 2 ? "started" : "stopped", ep);
        if (s->ops && s->ops->ep_start) s->ops->ep_start(s->opaque, ep, flag);
        break;
    }
    case MGMT_SET_IOP_PWR: {
        uint16_t st = MGMT_PWR_STATE(msg);
        fprintf(stderr, "asc(%s): AP requests IOP power state 0x%x\n", s->role, st);
        if (st == PWR_STATE_INIT || st == PWR_STATE_ON) {
            /*
             * INIT carries the ON state in its low byte.  AppleASCWrapV6
             * separately polls CPU_STATUS.IDLE during the inverse transition,
             * so a later wake must make that hardware status visible before
             * acknowledging the RTKit request.
             */
            asc_set_idle(s, false);
            if (s->rtk_state == RTK_BOOTED) {
                s->iop_pwr_state = PWR_STATE_ON;
                rtk_send_mgmt(s, MGMT_MSG(MGMT_IOP_PWR_ACK) | PWR_STATE_ON);
            } else {
                s->iop_pwr_pending = true;
                rtk_boot(s);
            }
        } else {
            /*
             * iOS requests sleep as 0x201: the low byte is the RTKit power
             * state and the upper bits are transition flags.  The management
             * ACK retains the complete value, while the ASC wrapper exposes
             * the corresponding hardware-idle bit.  Quiesced has the same
             * AP-visible idle property.
             */
            uint16_t base = PWR_STATE_BASE(st);
            if (base == PWR_STATE_SLEEP || base == PWR_STATE_QUIESCED) {
                asc_set_idle(s, true);
            }
            s->iop_pwr_state = st;
            rtk_send_mgmt(s, MGMT_MSG(MGMT_IOP_PWR_ACK) | st);
            if (base == PWR_STATE_SLEEP || base == PWR_STATE_QUIESCED) {
                /*
                 * The ACK completes the old RTKit instance.  On iOS 27 DCP,
                 * XNU then writes CPU_CONTROL from 0 to RUN and expects a new
                * HELLO: ROOT_SM_FWREG1_UI1.stderr.log:4134-4147 shows the
                * complete 0x201 ACK, idle/core-status checks, and that edge.
                * Remaining RTK_BOOTED here suppresses rtk_boot() and leaves
                * RTBuddy in _iopStatus 4 until its 20-second timeout.
                *
                * Endpoint state survives this firmware restart.  The AP's
                * second EPMAP advertises the retained map and it does not
                * replay START_EP messages (ROOT_SM_RESTART_ACK1_UI1).  Do not
                * clear ep_started here or QEMU and the AP disagree about the
                * live endpoint set after the new HELLO handshake.
                 */
                s->rtk_state = RTK_IDLE;
            }
        }
        break;
    }
    case MGMT_SET_AP_PWR: {
        uint16_t st = MGMT_PWR_STATE(msg);
        s->ap_pwr_state = st;
        rtk_send_mgmt(s, MGMT_MSG(MGMT_SET_AP_PWR) | st);
        break;
    }
    default:
        fprintf(stderr, "asc(%s): unhandled management message type %u: 0x%016" PRIx64 "\n", s->role, type, msg);
        break;
    }
}

/*
 * RTBuddyTraceKitEndpoint, endpoint 0x0a. The AP-side protocol was read out of
 * RTBuddyTraceKitEndpoint.cpp in the iOS 27 kernelcache (com.apple.driver.RTBuddy,
 * unslid addresses): the message type is bits [55:52] of the mailbox word
 * (`ubfx x1, x2, #0x34, #4` in _messageHandler at 0xfffffff00a7dec68).
 *
 *   AP -> IOP                                   what the AP then does
 *   0  host version, payload 1  (_hostVersionGated 0xa7e0c54)   nothing, no reply awaited
 *   1  flush                    (_flushGated 0xa7dfa14)         outstanding++, sleeps
 *   2/3 disable/enable          (_enableGated 0xa7df7d0)        busy-ACK wait on +0xac
 *   4  configure, cfg in [46:0], kind in [51:47] (0xa7e0738)    busy-ACK wait, then
 *                                                               requires _stateIOP == 1
 *   IOP -> AP (handler cases)
 *   0  flush complete: clears the flush flag, outstanding--
 *   1/2  _stateIOP = 2 / 3, wake        3  _stateIOP = (payload != 0), wake
 *   4  _stateIOP = 0, wake
 *
 * Without these replies every RTBuddy instance's boot-time power-on transition
 * parks in RTBuddyTraceKitEndpoint::_waitForOutstandingRequestsGated holding
 * _powerStateChangeLocked, and the DCP can never be powered off or on again
 * (docs/re/setup-launch-runtime.md, "The RTBuddy transition that never ended").
 */
#define TK_TYPE(m)  (((m) >> 52) & 0xf)
#define TK_MSG(t)   ((uint64_t)(t) << 52)

static void rtk_handle_tracekit(DarwinASCState *s, uint64_t msg) {
    unsigned type = TK_TYPE(msg);
    uint64_t reply;
    switch (type) {
    case 0:
        fprintf(stderr, "asc(%s): tracekit host version %" PRIu64 " (no reply awaited)\n", s->role, msg & 0xffffffffff);
        return;
    case 1:
        reply = TK_MSG(0);              // flush complete
        break;
    case 2:
    case 3:
    case 4:
        reply = TK_MSG(3) | 1;          // _stateIOP = Configured
        break;
    default:
        fprintf(stderr, "asc(%s): tracekit AP -> IOP type %u 0x%016" PRIx64 " (unhandled)\n", s->role, type, msg);
        return;
    }
    fprintf(stderr, "asc(%s): tracekit AP -> IOP type %u 0x%016" PRIx64 ", reply 0x%016" PRIx64 "\n", s->role, type, msg, reply);
    darwin_asc_send(DEVICE(s), EP_TRACEKIT, reply);
}

static void rtk_receive(DarwinASCState *s, uint8_t ep, uint64_t msg) {
    if (ep == EP_MGMT) {
        rtk_handle_mgmt(s, msg);
        return;
    }
    if (ep == EP_TRACEKIT) {
        rtk_handle_tracekit(s, msg);
        return;
    }
    if (s->ops && s->ops->handle && s->ops->handle(s->opaque, ep, msg)) {
        return;
    }
    fprintf(stderr, "asc(%s): AP -> ep 0x%02x 0x%016" PRIx64 " (unhandled)\n", s->role, ep, msg);
}

/* ---------------- MMIO ---------------- */

static uint64_t asc_read(void *opaque, hwaddr offset, unsigned size) {
    DarwinASCState *s = opaque;
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
                // Hardware mirrors the FIFO occupancy, counting the entry being
                // returned, into bits [55:52] of this register.
                // AppleASCWrapV6::getMailboxBulk (kext 0xfffffff008538758) reads
                // I2A_CTRL once to check FIFOCNT != 0, then pops repeatedly with a
                // single `ldp x8, x9, [base+0x8830]` and ends the loop only when
                // this field reads 1. It never re-reads I2A_CTRL. Leaving these
                // bits zero means the loop never terminates: the driver keeps
                // popping an empty FIFO and treats what it reads as real
                // messages, which XNU then rejects ("invalid management message
                // 0", RTBuddyManagementEndpoint.cpp:448).
                val |= (uint64_t)(s->i2a_count & 0xf) << 52;
                s->i2a_head = (s->i2a_head + 1) % MBOX_FIFO_DEPTH;
                s->i2a_count--;
                asc_refill_visible(s);
                asc_update_irqs(s);
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

    if (s->debug) fprintf(stderr, "asc(%s): read  0x%05" HWADDR_PRIx " -> 0x%" PRIx64 "\n", s->role, offset, val);
    return val;
}

static void asc_write(void *opaque, hwaddr offset, uint64_t val, unsigned size) {
    DarwinASCState *s = opaque;

    if (s->debug) fprintf(stderr, "asc(%s): write 0x%05" HWADDR_PRIx " <- 0x%" PRIx64 "\n", s->role, offset, val);

    if (offset == ASC_CPU_CONTROL) {
        bool was_run = s->cpu_control & ASC_CPU_CONTROL_RUN;
        s->cpu_control = val;
        if ((val & ASC_CPU_CONTROL_RUN) && !was_run) {
            /*
             * A CPU_CONTROL-driven restart has no preceding SET_IOP_PWR(ON),
             * but RTBuddy still waits for IOP_PWR_ACK(ON) after the new
             * HELLO/EPMAP handshake.  Use the same deferred-ACK path as the
             * management-request-driven initial boot.
             */
            if (s->rtk_state == RTK_IDLE) {
                s->iop_pwr_pending = true;
            }
            rtk_boot(s);
        } else if (!(val & ASC_CPU_CONTROL_RUN) && was_run) {
            fprintf(stderr, "asc(%s): AP stopped the IOP\n", s->role);
            s->misc[ASC_AKF_RUNNING / sizeof(uint32_t)] = 0;
            s->cpu_status = ASC_CPU_STATUS_STOPPED;
            s->rtk_state = RTK_IDLE;
            s->i2a_count = 0;
            s->pend_count = 0;
            s->pend_head = 0;
            asc_update_irqs(s);
        }
    } else if (offset == ASC_CPU_STATUS) {
        // read only
    } else if (offset >= s->mbox_off && offset < s->mbox_off + 0x1000) {
        uint32_t r = offset - s->mbox_off;
        switch (r) {
        case MBOX_A2I_CTRL:
            s->a2i_ctrl_raw = val & ~(MBOX_CTRL_FULL | MBOX_CTRL_EMPTY | (0xf << MBOX_CTRL_CNT_SHIFT));
            break;
        case MBOX_I2A_CTRL:
            s->i2a_ctrl_raw = val & ~(MBOX_CTRL_FULL | MBOX_CTRL_EMPTY | (0xf << MBOX_CTRL_CNT_SHIFT));
            break;
        case MBOX_A2I_SEND0:
            s->a2i_send0 = val;
            break;
        case MBOX_A2I_SEND1: {
            uint8_t ep = val & 0xff;
            if (s->debug) fprintf(stderr, "asc(%s): AP -> IOP ep 0x%02x 0x%016" PRIx64 "\n", s->role, ep, s->a2i_send0);
            rtk_receive(s, ep, s->a2i_send0);
            break;
        }
        default:
            if (offset + 4 <= s->mmio_size) s->misc[offset / 4] = val;
            break;
        }
    } else if (offset + 4 <= s->mmio_size) {
        s->misc[offset / 4] = val;
    }
}

static const MemoryRegionOps asc_ops = {
    .read = asc_read,
    .write = asc_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 8,
    .valid.min_access_size = 4,
    .valid.max_access_size = 8,
};

static uint64_t asc_firmware_status_read(void *opaque, hwaddr offset,
                                         unsigned size)
{
    DarwinASCState *s = opaque;
    uint64_t val = offset == ASC_FIRMWARE_STATUS ? s->firmware_status : 0;

    if (s->debug) {
        fprintf(stderr,
                "asc(%s): core status read 0x%02" HWADDR_PRIx " -> 0x%" PRIx64 "\n",
                s->role, offset, val);
    }
    return val;
}

static void asc_firmware_status_write(void *opaque, hwaddr offset,
                                      uint64_t val, unsigned size)
{
    DarwinASCState *s = opaque;

    if (s->debug) {
        fprintf(stderr,
                "asc(%s): ignored core status write 0x%02" HWADDR_PRIx
                " <- 0x%" PRIx64 "\n",
                s->role, offset, val);
    }
}

static const MemoryRegionOps asc_firmware_status_ops = {
    .read = asc_firmware_status_read,
    .write = asc_firmware_status_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
};

static void asc_autostart_fire(void *opaque) {
    DarwinASCState *s = opaque;
    fprintf(stderr, "asc(%s): DARWIN_ASC_AUTOSTART firing, starting IOP without an AP request\n", s->role);
    rtk_boot(s);
}

static void darwin_asc_realize(DeviceState *dev, Error **errp) {
    DarwinASCState *s = DARWIN_ASC(dev);
    if (!s->mmio_size) {
        error_setg(errp, "darwin-asc: no mmio size");
        return;
    }
    s->misc = g_new0(uint32_t, s->mmio_size / 4);
    s->cpu_status = ASC_CPU_STATUS_STOPPED;
    s->debug = getenv("DARWIN_ASC_DEBUG") != NULL;
    memory_region_init_io(&s->iomem, OBJECT(s), &asc_ops, s, "darwin-asc", s->mmio_size);
    sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->iomem);
    memory_region_init_io(&s->firmware_status_iomem, OBJECT(s),
                          &asc_firmware_status_ops, s,
                          "darwin-asc-firmware-status", sizeof(uint32_t));
    sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->firmware_status_iomem);
    for (int i = 0; i < 4; i++) sysbus_init_irq(SYS_BUS_DEVICE(dev), &s->irq[i]);

    const char *autostart = getenv("DARWIN_ASC_AUTOSTART");
    if (autostart) {
        int secs = atoi(autostart);
        if (secs <= 0) secs = 30;
        s->autostart_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL, asc_autostart_fire, s);
        timer_mod(s->autostart_timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + (int64_t)secs * 1000);
        fprintf(stderr, "asc(%s): will force-start the IOP after %ds (DARWIN_ASC_AUTOSTART)\n", s->role, secs);
    }
}

static const Property darwin_asc_properties[] = {
    DEFINE_PROP_STRING("role", DarwinASCState, role),
    DEFINE_PROP_UINT32("mmio-size", DarwinASCState, mmio_size, 0),
    DEFINE_PROP_UINT32("mbox-offset", DarwinASCState, mbox_off, 0x8000),
};

static void darwin_asc_class_init(ObjectClass *klass, const void *data) {
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = darwin_asc_realize;
    dc->desc = "Apple ASC coprocessor mailbox (RTKit)";
    device_class_set_props(dc, darwin_asc_properties);
    dc->user_creatable = false;
}

static const TypeInfo darwin_asc_info = {
    .name          = TYPE_DARWIN_ASC,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(DarwinASCState),
    .class_init    = darwin_asc_class_init,
};

static void darwin_asc_register_types(void) {
    type_register_static(&darwin_asc_info);
}

type_init(darwin_asc_register_types)

/* ---------------- device tree glue ---------------- */

void darwin_ascs_create(struct dtree_node *dt_root, uint64_t iobase, DeviceState *aic,
                        const char *const *claimed, int n_claimed) {
    struct dtree_node *arm_io = adt_find_node(dt_root, "arm-io");
    if (!arm_io) return;

    for (struct dtree_node *c = adt_first_child(arm_io); c; c = adt_next_sibling(arm_io, c)) {
        const char *compat = adt_get_prop_val(c, "compatible");
        const char *name = adt_get_prop_val(c, "name");
        if (!compat || !name) continue;
        // dt_fixup only leaves "compatible" on hardware we emulate, so anything
        // still claiming to be an ASC wrapper is one we are expected to provide.
        if (!strstr(compat, "ascwrap")) continue;

        bool skip = false;
        for (int i = 0; i < n_claimed; i++) {
            if (0 == strcmp(name, claimed[i])) skip = true;
        }
        if (skip) continue;

        if (!adt_get_prop_val(c, "reg")) continue;
        darwin_asc_create(c, iobase, aic, NULL, 0, NULL, NULL);
    }
}

const char *darwin_asc_role(DeviceState *dev) {
    return DARWIN_ASC(dev)->role;
}

DeviceState *darwin_asc_create(struct dtree_node *node, uint64_t iobase, DeviceState *aic,
                               const uint8_t *eps, int n_eps,
                               const DarwinASCOps *ops, void *opaque) {
    struct adt_io_reg *reg = adt_get_prop_val(node, "reg");
    size_t n_regs = adt_get_prop_len(node, "reg") / sizeof(*reg);
    const char *role = adt_get_prop_val(node, "role");
    const char *name = adt_get_prop_val(node, "name");
    uint32_t *irqs = adt_get_prop_val(node, "interrupts");
    size_t n_irqs = irqs ? adt_get_prop_len(node, "interrupts") / 4 : 0;

    DeviceState *dev = qdev_new(TYPE_DARWIN_ASC);
    qdev_prop_set_string(dev, "role", role ? role : name);
    qdev_prop_set_uint32(dev, "mmio-size", reg[0].len);
    DarwinASCState *s = DARWIN_ASC(dev);
    s->ops = ops;
    s->opaque = opaque;

    // standard RTKit system endpoints + the personality's endpoints
    static const uint8_t sys_eps[] = { EP_MGMT, EP_CRASHLOG, EP_SYSLOG, EP_DEBUG, EP_IOREPORT, EP_OSLOG, EP_TRACEKIT };
    for (size_t i = 0; i < ARRAY_SIZE(sys_eps); i++) s->ep_map[sys_eps[i] / 32] |= BIT_ULL(sys_eps[i] % 32);
    for (int i = 0; i < n_eps; i++) s->ep_map[eps[i] / 32] |= BIT_ULL(eps[i] % 32);

    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);
    sysbus_realize_and_unref(sbd, &error_fatal);
    sysbus_mmio_map(sbd, 0, reg[0].base + iobase);
    if (n_regs > 1 && reg[1].len >= sizeof(uint32_t)) {
        /*
         * AppleASCWrapV6::initialize maps reg[1] as _coreMappedRegs, and its
         * restart path reads bit 0 at reg[1]+0 (static
         * 0xfffffff00853832c..0xfffffff00853834c).  Only that status word is
         * claimed here; the remainder stays in the low-priority unimplemented
         * backing region until its semantics are established.
         */
        sysbus_mmio_map(sbd, 1, reg[1].base + iobase);
    }
    for (size_t i = 0; i < 4 && i < n_irqs; i++) {
        if (aic) sysbus_connect_irq(sbd, i, darwin_aic_get_irq(aic, irqs[i]));
    }

    fprintf(stderr, "darwin-asc: %s (%s) at 0x%" PRIx64 " irqs", s->role, name, reg[0].base + iobase);
    for (size_t i = 0; i < n_irqs; i++) fprintf(stderr, " 0x%x", irqs[i]);
    fprintf(stderr, "\n");
    return dev;
}
