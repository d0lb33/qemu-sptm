/*
 * darwin-asc: Apple "ASC" coprocessor wrapper + mailbox + RTKit protocol
 *
 * Every Apple Silicon coprocessor (DCP, ANS, SMC, AOP, SIO, MTP, GFX, ...)
 * is an ARM core running Apple's RTKit RTOS, talking to the AP through a
 * small hardware mailbox. This models the AP-visible side of that:
 *
 *   ASC wrapper (device tree "reg[0]", compatible iop,ascwrap-v*):
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
#include "hw/core/sysbus.h"
#include "hw/core/irq.h"
#include "hw/core/qdev-properties.h"
#include "system/memory.h"
#include "xnu/boot/xnuboot.h"
#include "xnu/apple_dtree.h"
#include "xnu/darwin_aic.h"
#include "xnu/darwin_asc.h"

OBJECT_DECLARE_SIMPLE_TYPE(DarwinASCState, DARWIN_ASC)

#define ASC_CPU_CONTROL     0x44
#define ASC_CPU_CONTROL_RUN BIT(4)
#define ASC_CPU_STATUS      0x48
#define ASC_CPU_STATUS_RUNNING BIT(0)
#define ASC_CPU_STATUS_STOPPED BIT(1)
#define ASC_CPU_STATUS_IDLE    BIT(5)

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

#define MBOX_CTRL_FULL      BIT(16)
#define MBOX_CTRL_EMPTY     BIT(17)
#define MBOX_CTRL_CNT_SHIFT 20

#define MBOX_FIFO_DEPTH 16

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
    char *role;
    uint32_t mmio_size;
    uint32_t mbox_off;
    qemu_irq irq[4];

    // asc
    uint32_t cpu_control, cpu_status;
    uint32_t *misc;

    // mailbox
    uint32_t a2i_ctrl_raw, i2a_ctrl_raw;
    uint64_t a2i_send0;
    ASCMsg i2a_fifo[MBOX_FIFO_DEPTH];
    int i2a_head, i2a_count;

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

void darwin_asc_send(DeviceState *dev, uint8_t ep, uint64_t msg) {
    DarwinASCState *s = DARWIN_ASC(dev);
    if (s->i2a_count >= MBOX_FIFO_DEPTH) {
        fprintf(stderr, "asc(%s): i2a fifo overflow, dropping ep %u msg 0x%016" PRIx64 "\n", s->role, ep, msg);
        return;
    }
    int idx = (s->i2a_head + s->i2a_count) % MBOX_FIFO_DEPTH;
    s->i2a_fifo[idx].msg0 = msg;
    s->i2a_fifo[idx].msg1 = ep;
    s->i2a_count++;
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

static void rtk_boot(DarwinASCState *s) {
    if (s->rtk_state != RTK_IDLE) return;
    s->cpu_status = ASC_CPU_STATUS_RUNNING;
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
            if (s->rtk_state == RTK_BOOTED) {
                s->iop_pwr_state = PWR_STATE_ON;
                rtk_send_mgmt(s, MGMT_MSG(MGMT_IOP_PWR_ACK) | PWR_STATE_ON);
            } else {
                s->iop_pwr_pending = true;
                rtk_boot(s);
            }
        } else {
            s->iop_pwr_state = st;
            rtk_send_mgmt(s, MGMT_MSG(MGMT_IOP_PWR_ACK) | st);
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

static void rtk_receive(DarwinASCState *s, uint8_t ep, uint64_t msg) {
    if (ep == EP_MGMT) {
        rtk_handle_mgmt(s, msg);
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
        case MBOX_I2A_CTRL:
            val = s->i2a_ctrl_raw & ~(MBOX_CTRL_FULL | MBOX_CTRL_EMPTY | (0xf << MBOX_CTRL_CNT_SHIFT));
            if (s->i2a_count == 0) val |= MBOX_CTRL_EMPTY;
            if (s->i2a_count >= MBOX_FIFO_DEPTH) val |= MBOX_CTRL_FULL;
            val |= (uint64_t)(s->i2a_count & 0xf) << MBOX_CTRL_CNT_SHIFT;
            break;
        case MBOX_I2A_RECV0:
            if (s->i2a_count) val = s->i2a_fifo[s->i2a_head].msg0;
            break;
        case MBOX_I2A_RECV1:
            if (s->i2a_count) {
                val = s->i2a_fifo[s->i2a_head].msg1;
                s->i2a_head = (s->i2a_head + 1) % MBOX_FIFO_DEPTH;
                s->i2a_count--;
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
            rtk_boot(s);
        } else if (!(val & ASC_CPU_CONTROL_RUN) && was_run) {
            fprintf(stderr, "asc(%s): AP stopped the IOP\n", s->role);
            s->cpu_status = ASC_CPU_STATUS_STOPPED;
            s->rtk_state = RTK_IDLE;
            s->i2a_count = 0;
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
    for (int i = 0; i < 4; i++) sysbus_init_irq(SYS_BUS_DEVICE(dev), &s->irq[i]);
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

const char *darwin_asc_role(DeviceState *dev) {
    return DARWIN_ASC(dev)->role;
}

DeviceState *darwin_asc_create(struct dtree_node *node, uint64_t iobase, DeviceState *aic,
                               const uint8_t *eps, int n_eps,
                               const DarwinASCOps *ops, void *opaque) {
    struct adt_io_reg *reg = adt_get_prop_val(node, "reg");
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
    for (size_t i = 0; i < 4 && i < n_irqs; i++) {
        if (aic) sysbus_connect_irq(sbd, i, darwin_aic_get_irq(aic, irqs[i]));
    }

    fprintf(stderr, "darwin-asc: %s (%s) at 0x%" PRIx64 " irqs", s->role, name, reg[0].base + iobase);
    for (size_t i = 0; i < n_irqs; i++) fprintf(stderr, " 0x%x", irqs[i]);
    fprintf(stderr, "\n");
    return dev;
}
