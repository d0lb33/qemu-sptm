/*
 * darwin-spmi: Apple SPMI controller, T8140 "Gen3" register layout.
 *
 * Everything here is derived from the iPhone17,3 / T8140 24A5430a kernelcache
 * (com.apple.driver.AppleSPMI, class AppleSPMIController, and its Gen3
 * handler) plus /arm-io/nub-spmi0 in the target device tree.  The two open
 * implementations we compared against are Inferno's hw/spmi/apple_spmi.c
 * (T8030, "reg-vers" 0/1) and Linux drivers/spmi/spmi-apple-controller.c
 * (T8103); where they agree with the T8140 code that is noted, where the
 * T8140 code differs the T8140 code wins.
 *
 * Device tree (tools/dt_dump.py /tmp/dvm/dtree_raw arm-io/nub-spmi0):
 *   compatible  aapl,spmi        gen 3        queue-depth 0x100 / 0x100
 *   reg[0] 0xf8714000+0x4000    reg[1] 0xf8704000+0x4000   reg[2] 0xf8700000+0x4000
 *   interrupts  0x100 0x1e7 0x119 0x104 ...   interrupt-parent 0x96 0x20 0x96
 *
 * AppleSPMIController::start (0xfffffff00960ec4c) maps reg index 0 as the
 * "spmiMemoryMap" and index 1 as the "faultMemoryMap"
 * (mapDeviceMemoryWithIndex(0) at 0xfffffff00960ef38, (1) at 0xfffffff00960efa0),
 * then selects the handler by the "gen" property (switch at
 * 0xfffffff009613a4c; 3 -> 0xfffffff00960c57c).  The Gen3 handler's init at
 * 0xfffffff00960c614 fills a register-pointer block from those two maps and
 * additionally maps reg index 2 (0xfffffff00960c750).  The pointer block is
 * what fixes every offset below:
 *
 *   reg[0] ("queue" block, spmiMemoryMap)
 *     +0x00  STATUS     bit 8 request queue empty, bit 9 request queue full,
 *                       bit 24 response queue empty, bit 25 response queue full
 *                       (masks 0x100/0x200 and 0x1000000/0x2000000 stored at
 *                       block+0x48/+0x50; the empty checks are at
 *                       0xfffffff00960fe0c-0xfffffff00960fe2c and the response
 *                       wait at 0xfffffff00961090c).  Linux uses the same
 *                       RX-empty bit 24; Inferno the same four bits.
 *     +0x04  REQ_PUSH   request word, then payload words for writes
 *                       (0xfffffff009614540 / 0xfffffff009614620)
 *     +0x08  RSP_POP    response word (0xfffffff009610974), then payload
 *                       words for reads
 *     +0x20  INT_ENABLE[0..8]   9 banks of 32, stride 4 (block+0x78, stride
 *                       block+0x70 = 4, bank loop bound 9 at 0xfffffff0096120a0)
 *     +0x60  INT_STATUS[0..8]   write-one-to-clear: the wait loop writes back
 *                       the bit it consumed (0xfffffff009610264) and the Gen3
 *                       clear method stores the mask (0xfffffff00960cc68)
 *     +0xa0, +0xa4, +0xb0, +0xb4, +0xb8   only read/written by the panic dump
 *                       and quiesce paths; kept as plain storage
 *   reg[1] ("fault" block)
 *     +0x00  STATUS (same bit layout), +0x08 fault response pop
 *     +0x400..+0x4d8  fault counters, names in the table at
 *                       0xfffffff008123998 ("unmapped write", ...)
 *   reg[2] (Gen3 control block)
 *     +0x20  QUEUE_RESET  write 1, then polled until bit 0 clears
 *                       (0xfffffff00960c80c: 10 ms, else 0xe00002d6)
 *     +0xb0..+0xd4  queue pointer / arbitration log dump registers
 *
 * Request word (built at 0xfffffff0096144e4-0xfffffff009614514 for extended
 * transfers and 0xfffffff009610de4-0xfffffff009610e14 for the short forms):
 *
 *   [7:0]   opcode byte from the table at 0xfffffff0077389c8
 *           (EXT_WRITE 0x00, EXT_READ 0x20, EXT_WRITEL 0x30, EXT_READL 0x38,
 *           WRITE 0x40, READ 0x60, ZERO_WRITE 0x80, RESET 0x10 ... DDB 0x1c)
 *           ORed with len-1 for the extended forms
 *   [11:8]  slave id            [15] final transfer of a command
 *   [31:16] register address    [31:24] data byte for WRITE / ZERO_WRITE
 *
 * That is exactly Linux's apple_spmi_pack_cmd(): opc | sid<<8 | addr<<16 |
 * (len-1) | 1<<15.  Payload for writes follows as little-endian words
 * (0xfffffff0096145f8-0xfffffff009614620), four bytes each; reads pop the
 * same number of words after the header (0xfffffff009614bac loop).
 *
 * Response word: the driver requires bits [11:0] to match the request under
 * a per-opcode mask (table at 0xfffffff0077389dc: 0xfff, 0xfe0 for
 * EXT_READL/WRITE, 0xf80 for READ; compare at 0xfffffff009614cc4) and bit 15
 * to be set, otherwise it reports kIOReturnNotResponding
 * (0xfffffff009614cf4 -> 0xfffffff009615104, 0x2d6+0x17 = 0xe00002ed).
 * Bits [31:16] carry one "parity ok" flag per transferred byte: at
 * 0xfffffff009614a00-0xfffffff009614a18 the driver takes the length from
 * the response's own low bits, masks [31:16] with 0xff (<= 8 bytes) or
 * 0xffff, and requires it to equal (1 << len) - 1.  The first probe
 * (RTC_NATIVE_RESTORE1) showed the guest-side message that pins this down:
 * "parity error: parity_rcv=0x00FF parity_exp=0x0001" when a stale 8-byte
 * mask was returned for a 1-byte transfer.  Inferno's per-byte ack mask in
 * [23:16] is the same field.
 *
 * Opcode length fields follow the SPMI spec, and the traffic confirms it:
 * EXT_WRITE/EXT_READ (0x00-0x0f / 0x20-0x2f) carry len-1 in [3:0], up to 16
 * bytes; EXT_WRITEL/EXT_READL (0x30-0x37 / 0x38-0x3f) carry len-1 in [2:0],
 * up to 8 bytes (the driver's 8-byte LPM log writes are 0x...0e37, its
 * one-byte scratchpad reads 0x...8e38).
 *
 * Interrupts: the controller is its own interrupt parent for index 0x100
 * (response ready), the error/fatal indexes 0x104-0x11d and child devices;
 * only "interrupts"[1] = 0x1e7 is an AIC vector (IODTFindInterruptParent
 * takes interrupt-parent[i], wrapping to [0] past the end, so entries 0 and
 * 2.. resolve to phandle 0x96 = this node).  Bank = index >> 5, bit = index
 * & 31 (0xfffffff00961021c / 0xfffffff009610228).  The line is asserted
 * while any bank has status & enable.
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qapi/error.h"
#include "migration/vmstate.h"
#include "hw/core/irq.h"
#include "hw/core/qdev-properties.h"
#include "system/memory.h"
#include "xnu/darwin_aic.h"
#include "xnu/darwin_spmi.h"

#define SPMI_BLOCK_SIZE       0x4000
#define SPMI_NUM_BANKS        9
#define SPMI_RSP_DEPTH        256
#define SPMI_MAX_SLAVES       16
#define SPMI_RESP_IRQ_INDEX   0x100

#define R_STATUS              0x00
#define R_REQ_PUSH            0x04
#define R_RSP_POP             0x08
#define R_INT_ENABLE          0x20
#define R_INT_STATUS          0x60
#define R_CTRL_QUEUE_RESET    0x20

#define STATUS_REQ_EMPTY      (1u << 8)
#define STATUS_REQ_FULL       (1u << 9)
#define STATUS_RSP_EMPTY      (1u << 24)
#define STATUS_RSP_FULL       (1u << 25)

#define REQ_FINAL             (1u << 15)

/* SPMI opcodes as encoded by the kext's table at 0xfffffff0077389c8 */
#define OPC_EXT_WRITE         0x00
#define OPC_EXT_READ          0x20
#define OPC_EXT_WRITEL        0x30
#define OPC_EXT_READL         0x38
#define OPC_WRITE             0x40
#define OPC_READ              0x60
#define OPC_ZERO_WRITE        0x80

OBJECT_DECLARE_SIMPLE_TYPE(DarwinSPMIState, DARWIN_SPMI)

typedef struct {
    const DarwinSPMISlaveOps *ops;
    void *opaque;
} SPMISlave;

struct DarwinSPMIState {
    SysBusDevice parent_obj;
    MemoryRegion queue_mr;
    MemoryRegion fault_mr;
    MemoryRegion ctrl_mr;
    qemu_irq irq;
    char *name;
    bool debug;

    uint32_t int_enable[SPMI_NUM_BANKS];
    uint32_t int_status[SPMI_NUM_BANKS];
    uint32_t queue_regs[SPMI_BLOCK_SIZE / 4];
    uint32_t fault_regs[SPMI_BLOCK_SIZE / 4];
    uint32_t ctrl_regs[SPMI_BLOCK_SIZE / 4];

    uint32_t rsp[SPMI_RSP_DEPTH];
    uint32_t rsp_head;
    uint32_t rsp_count;

    /* A write request whose payload words are still arriving. */
    uint32_t pending_cmd;
    uint32_t pending_len;
    uint32_t pending_filled;
    uint8_t pending_data[16];

    uint64_t n_requests;
    uint64_t n_nak;

    SPMISlave slaves[SPMI_MAX_SLAVES];
};

static void spmi_update_irq(DarwinSPMIState *s)
{
    bool level = false;
    for (int b = 0; b < SPMI_NUM_BANKS; b++) {
        if (s->int_status[b] & s->int_enable[b]) {
            level = true;
            break;
        }
    }
    qemu_set_irq(s->irq, level);
}

static void spmi_raise_index(DarwinSPMIState *s, unsigned index, bool level)
{
    unsigned bank = index >> 5;
    if (bank >= SPMI_NUM_BANKS) {
        return;
    }
    if (level) {
        s->int_status[bank] |= 1u << (index & 31);
    }
    /* Status is sticky until the guest clears it; a falling edge on a
     * level-triggered slave line does not clear a latched bit. */
    spmi_update_irq(s);
}

static void spmi_slave_irq(void *opaque, int n, int level)
{
    DarwinSPMIState *s = opaque;
    if (s->debug) {
        fprintf(stderr, "spmi(%s): slave irq index 0x%x -> %d\n", s->name, n, level);
    }
    spmi_raise_index(s, n, level);
}

static void spmi_push_response(DarwinSPMIState *s, uint32_t word)
{
    if (s->rsp_count >= SPMI_RSP_DEPTH) {
        qemu_log_mask(LOG_GUEST_ERROR, "spmi(%s): response queue overflow\n", s->name);
        return;
    }
    s->rsp[(s->rsp_head + s->rsp_count) % SPMI_RSP_DEPTH] = word;
    s->rsp_count++;
}

static uint32_t spmi_pop_response(DarwinSPMIState *s)
{
    if (!s->rsp_count) {
        qemu_log_mask(LOG_GUEST_ERROR, "spmi(%s): response queue pop while empty\n", s->name);
        return 0;
    }
    uint32_t w = s->rsp[s->rsp_head];
    s->rsp_head = (s->rsp_head + 1) % SPMI_RSP_DEPTH;
    s->rsp_count--;
    return w;
}

static uint32_t spmi_status(DarwinSPMIState *s)
{
    uint32_t v = STATUS_REQ_EMPTY;
    if (!s->rsp_count) v |= STATUS_RSP_EMPTY;
    if (s->rsp_count >= SPMI_RSP_DEPTH) v |= STATUS_RSP_FULL;
    return v;
}

static const char *opc_name(unsigned opc)
{
    switch (opc & 0xf0) {
    case OPC_EXT_WRITE: return "EXT_WRITE";
    case OPC_EXT_READ: return "EXT_READ";
    case 0x30: return (opc & 8) ? "EXT_READL" : "EXT_WRITEL";
    default: break;
    }
    if ((opc & 0xe0) == OPC_WRITE) return "WRITE";
    if ((opc & 0xe0) == OPC_READ) return "READ";
    if (opc & 0x80) return "ZERO_WRITE";
    return "CMD";
}

/*
 * Decode a request word.  Returns the payload length in bytes (0 for the
 * command frames 0x10-0x1c) and whether it is a write.
 */
static unsigned spmi_decode(uint32_t w, unsigned *opc, unsigned *sid,
                            uint16_t *addr, bool *is_write, uint8_t *short_data)
{
    unsigned op = w & 0xff;
    *sid = (w >> 8) & 0xf;
    *addr = w >> 16;
    *short_data = w >> 24;
    *opc = op;
    *is_write = false;
    switch (op & 0xf0) {
    case OPC_EXT_WRITE:
        *is_write = true;
        return (op & 0xf) + 1;
    case OPC_EXT_READ:
        return (op & 0xf) + 1;
    case 0x30:
        if (op & 8) {
            return (op & 7) + 1;          /* EXT_READL */
        }
        *is_write = true;
        return (op & 7) + 1;              /* EXT_WRITEL */
    default:
        break;
    }
    if ((op & 0xe0) == OPC_WRITE) {
        /* Register-space write: 5-bit address, one data byte in [31:24].
         * The kext still places the address in [31:16], see
         * 0xfffffff009610dec. */
        *is_write = true;
        *addr &= 0x1f;
        return 1;
    }
    if ((op & 0xe0) == OPC_READ) {
        *addr &= 0x1f;
        return 1;
    }
    if (op & 0x80) {
        /* Register-0 write: data in [31:24] (0xfffffff009611494). */
        *is_write = true;
        *addr = 0;
        return 1;
    }
    return 0;
}

static void spmi_complete(DarwinSPMIState *s, uint32_t cmd, unsigned opc, unsigned sid,
                          uint16_t addr, unsigned len, bool is_write, const uint8_t *wdata)
{
    uint8_t rdata[16] = { 0 };
    int acked = 0;
    SPMISlave *sl = sid < SPMI_MAX_SLAVES ? &s->slaves[sid] : NULL;

    s->n_requests++;
    if (sl && sl->ops) {
        if (is_write) {
            acked = sl->ops->write(sl->opaque, addr, wdata, len);
        } else if (len) {
            acked = sl->ops->read(sl->opaque, addr, rdata, len);
        } else {
            acked = 0; /* command frame: nothing to transfer, ack the frame */
        }
    }
    bool ok = sl && sl->ops && (len == 0 || acked == (int)len);
    if (!ok) {
        s->n_nak++;
    }

    if (s->debug) {
        fprintf(stderr, "spmi(%s): %s sid %u addr 0x%04x len %u%s", s->name,
                opc_name(opc), sid, addr, len, ok ? "" : " NAK");
        const uint8_t *d = is_write ? wdata : rdata;
        if (len) {
            fprintf(stderr, " data");
            for (unsigned i = 0; i < len; i++) fprintf(stderr, " %02x", d[i]);
        }
        fprintf(stderr, "\n");
    }

    /* Header: request bits [11:0], bit 15 = acknowledged, [31:16] = one
     * parity-ok bit per acknowledged byte. */
    uint32_t hdr = cmd & 0xfff;
    if (ok) {
        hdr |= REQ_FINAL;
    }
    if (acked > 0 && acked <= 16) {
        hdr |= ((1u << acked) - 1) << 16;
    }
    spmi_push_response(s, hdr);
    if (!is_write) {
        for (unsigned i = 0; i < len; i += 4) {
            uint32_t w = 0;
            for (unsigned j = 0; j < 4 && i + j < len; j++) {
                w |= (uint32_t)rdata[i + j] << (8 * j);
            }
            spmi_push_response(s, w);
        }
    }
    spmi_raise_index(s, SPMI_RESP_IRQ_INDEX, true);
}

static void spmi_request(DarwinSPMIState *s, uint32_t w)
{
    if (s->pending_len > s->pending_filled) {
        for (unsigned j = 0; j < 4 && s->pending_filled < s->pending_len; j++) {
            s->pending_data[s->pending_filled++] = w >> (8 * j);
        }
        if (s->pending_filled < s->pending_len) {
            return;
        }
        unsigned opc, sid;
        uint16_t addr;
        bool is_write;
        uint8_t short_data;
        unsigned len = spmi_decode(s->pending_cmd, &opc, &sid, &addr, &is_write, &short_data);
        spmi_complete(s, s->pending_cmd, opc, sid, addr, len, true, s->pending_data);
        s->pending_len = s->pending_filled = 0;
        return;
    }

    unsigned opc, sid;
    uint16_t addr;
    bool is_write;
    uint8_t short_data;
    unsigned len = spmi_decode(w, &opc, &sid, &addr, &is_write, &short_data);
    if (is_write && len && (opc & 0xf0) != OPC_EXT_WRITE && (opc & 0xf8) != OPC_EXT_WRITEL) {
        /* WRITE / ZERO_WRITE carry their byte in the request word. */
        spmi_complete(s, w, opc, sid, addr, 1, true, &short_data);
        return;
    }
    if (is_write) {
        s->pending_cmd = w;
        s->pending_len = len;
        s->pending_filled = 0;
        return;
    }
    spmi_complete(s, w, opc, sid, addr, len, false, NULL);
}

static uint64_t queue_read(void *opaque, hwaddr off, unsigned size)
{
    DarwinSPMIState *s = opaque;
    uint32_t v;
    switch (off) {
    case R_STATUS:
        v = spmi_status(s);
        break;
    case R_RSP_POP:
        v = spmi_pop_response(s);
        break;
    case R_INT_ENABLE ... R_INT_ENABLE + 4 * SPMI_NUM_BANKS - 1:
        v = s->int_enable[(off - R_INT_ENABLE) / 4];
        break;
    case R_INT_STATUS ... R_INT_STATUS + 4 * SPMI_NUM_BANKS - 1:
        v = s->int_status[(off - R_INT_STATUS) / 4];
        break;
    default:
        v = s->queue_regs[off / 4];
        break;
    }
    if (s->debug && off != R_STATUS) {
        fprintf(stderr, "spmi(%s): rd queue+0x%03" HWADDR_PRIx " = 0x%08x\n", s->name, off, v);
    }
    return v;
}

static void queue_write(void *opaque, hwaddr off, uint64_t val, unsigned size)
{
    DarwinSPMIState *s = opaque;
    if (s->debug) {
        fprintf(stderr, "spmi(%s): wr queue+0x%03" HWADDR_PRIx " = 0x%08" PRIx64 "\n", s->name, off, val);
    }
    switch (off) {
    case R_REQ_PUSH:
        spmi_request(s, val);
        break;
    case R_INT_ENABLE ... R_INT_ENABLE + 4 * SPMI_NUM_BANKS - 1:
        s->int_enable[(off - R_INT_ENABLE) / 4] = val;
        spmi_update_irq(s);
        break;
    case R_INT_STATUS ... R_INT_STATUS + 4 * SPMI_NUM_BANKS - 1:
        s->int_status[(off - R_INT_STATUS) / 4] &= ~(uint32_t)val;
        spmi_update_irq(s);
        break;
    case R_STATUS:
    case R_RSP_POP:
        break;
    default:
        s->queue_regs[off / 4] = val;
        break;
    }
}

static const MemoryRegionOps queue_ops = {
    .read = queue_read,
    .write = queue_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
};

static uint64_t fault_read(void *opaque, hwaddr off, unsigned size)
{
    DarwinSPMIState *s = opaque;
    uint32_t v;
    switch (off) {
    case R_STATUS:
        /* No fault has ever been queued: both queues empty. */
        v = STATUS_REQ_EMPTY | STATUS_RSP_EMPTY;
        break;
    case R_RSP_POP:
        v = 0;
        break;
    default:
        v = s->fault_regs[off / 4];
        break;
    }
    if (s->debug) {
        fprintf(stderr, "spmi(%s): rd fault+0x%03" HWADDR_PRIx " = 0x%08x\n", s->name, off, v);
    }
    return v;
}

static void fault_write(void *opaque, hwaddr off, uint64_t val, unsigned size)
{
    DarwinSPMIState *s = opaque;
    if (s->debug) {
        fprintf(stderr, "spmi(%s): wr fault+0x%03" HWADDR_PRIx " = 0x%08" PRIx64 "\n", s->name, off, val);
    }
    s->fault_regs[off / 4] = val;
}

static const MemoryRegionOps fault_ops = {
    .read = fault_read,
    .write = fault_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
};

static uint64_t ctrl_read(void *opaque, hwaddr off, unsigned size)
{
    DarwinSPMIState *s = opaque;
    uint32_t v = s->ctrl_regs[off / 4];
    if (off == R_CTRL_QUEUE_RESET) {
        v &= ~1u;   /* the reset request completes immediately */
    }
    if (s->debug) {
        fprintf(stderr, "spmi(%s): rd ctrl+0x%03" HWADDR_PRIx " = 0x%08x\n", s->name, off, v);
    }
    return v;
}

static void ctrl_write(void *opaque, hwaddr off, uint64_t val, unsigned size)
{
    DarwinSPMIState *s = opaque;
    if (s->debug) {
        fprintf(stderr, "spmi(%s): wr ctrl+0x%03" HWADDR_PRIx " = 0x%08" PRIx64 "\n", s->name, off, val);
    }
    if (off == R_CTRL_QUEUE_RESET && (val & 1)) {
        s->rsp_head = s->rsp_count = 0;
        s->pending_len = s->pending_filled = 0;
    }
    s->ctrl_regs[off / 4] = val;
}

static const MemoryRegionOps ctrl_ops = {
    .read = ctrl_read,
    .write = ctrl_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
};

void darwin_spmi_attach_slave(DeviceState *ctrl, unsigned sid,
                              const DarwinSPMISlaveOps *ops, void *opaque)
{
    DarwinSPMIState *s = DARWIN_SPMI(ctrl);
    assert(sid < SPMI_MAX_SLAVES);
    assert(!s->slaves[sid].ops);
    s->slaves[sid].ops = ops;
    s->slaves[sid].opaque = opaque;
}

qemu_irq darwin_spmi_get_irq(DeviceState *ctrl, unsigned index)
{
    return qdev_get_gpio_in(ctrl, index);
}

static void darwin_spmi_realize(DeviceState *dev, Error **errp)
{
    DarwinSPMIState *s = DARWIN_SPMI(dev);
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);

    s->debug = getenv("DARWIN_SPMI_DEBUG") != NULL;
    memory_region_init_io(&s->queue_mr, OBJECT(dev), &queue_ops, s, "darwin-spmi.queue", SPMI_BLOCK_SIZE);
    memory_region_init_io(&s->fault_mr, OBJECT(dev), &fault_ops, s, "darwin-spmi.fault", SPMI_BLOCK_SIZE);
    memory_region_init_io(&s->ctrl_mr, OBJECT(dev), &ctrl_ops, s, "darwin-spmi.ctrl", SPMI_BLOCK_SIZE);
    sysbus_init_mmio(sbd, &s->queue_mr);
    sysbus_init_mmio(sbd, &s->fault_mr);
    sysbus_init_mmio(sbd, &s->ctrl_mr);
    sysbus_init_irq(sbd, &s->irq);
    qdev_init_gpio_in(dev, spmi_slave_irq, 32 * SPMI_NUM_BANKS);
}

static void darwin_spmi_reset(DeviceState *dev)
{
    DarwinSPMIState *s = DARWIN_SPMI(dev);
    memset(s->int_enable, 0, sizeof(s->int_enable));
    memset(s->int_status, 0, sizeof(s->int_status));
    memset(s->queue_regs, 0, sizeof(s->queue_regs));
    memset(s->fault_regs, 0, sizeof(s->fault_regs));
    memset(s->ctrl_regs, 0, sizeof(s->ctrl_regs));
    s->rsp_head = s->rsp_count = 0;
    s->pending_cmd = s->pending_len = s->pending_filled = 0;
    spmi_update_irq(s);
}

static int darwin_spmi_post_load(void *opaque, int version_id)
{
    DarwinSPMIState *s = opaque;
    if (s->rsp_head >= SPMI_RSP_DEPTH || s->rsp_count > SPMI_RSP_DEPTH ||
        s->pending_len > sizeof(s->pending_data) || s->pending_filled > s->pending_len) {
        return -EINVAL;
    }
    spmi_update_irq(s);
    return 0;
}

static const VMStateDescription vmstate_darwin_spmi = {
    .name = TYPE_DARWIN_SPMI,
    .version_id = 1,
    .minimum_version_id = 1,
    .post_load = darwin_spmi_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32_ARRAY(int_enable, DarwinSPMIState, SPMI_NUM_BANKS),
        VMSTATE_UINT32_ARRAY(int_status, DarwinSPMIState, SPMI_NUM_BANKS),
        VMSTATE_UINT32_ARRAY(queue_regs, DarwinSPMIState, SPMI_BLOCK_SIZE / 4),
        VMSTATE_UINT32_ARRAY(fault_regs, DarwinSPMIState, SPMI_BLOCK_SIZE / 4),
        VMSTATE_UINT32_ARRAY(ctrl_regs, DarwinSPMIState, SPMI_BLOCK_SIZE / 4),
        VMSTATE_UINT32_ARRAY(rsp, DarwinSPMIState, SPMI_RSP_DEPTH),
        VMSTATE_UINT32(rsp_head, DarwinSPMIState),
        VMSTATE_UINT32(rsp_count, DarwinSPMIState),
        VMSTATE_UINT32(pending_cmd, DarwinSPMIState),
        VMSTATE_UINT32(pending_len, DarwinSPMIState),
        VMSTATE_UINT32(pending_filled, DarwinSPMIState),
        VMSTATE_UINT8_ARRAY(pending_data, DarwinSPMIState, 16),
        VMSTATE_UINT64(n_requests, DarwinSPMIState),
        VMSTATE_UINT64(n_nak, DarwinSPMIState),
        VMSTATE_END_OF_LIST()
    },
};

static const Property darwin_spmi_properties[] = {
    DEFINE_PROP_STRING("name", DarwinSPMIState, name),
};

static void darwin_spmi_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = darwin_spmi_realize;
    device_class_set_legacy_reset(dc, darwin_spmi_reset);
    dc->vmsd = &vmstate_darwin_spmi;
    device_class_set_props(dc, darwin_spmi_properties);
    dc->user_creatable = false;
}

static const TypeInfo darwin_spmi_info = {
    .name = TYPE_DARWIN_SPMI,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(DarwinSPMIState),
    .class_init = darwin_spmi_class_init,
};

static void darwin_spmi_register_types(void)
{
    type_register_static(&darwin_spmi_info);
}

type_init(darwin_spmi_register_types)

DeviceState *darwin_spmi_create(struct dtree_node *dt_root, uint64_t iobase, DeviceState *aic)
{
    struct dtree_node *node = adt_find_node(dt_root, "arm-io/nub-spmi0");
    if (!node || !adt_get_prop_val(node, "compatible")) {
        return NULL;
    }
    struct adt_io_reg *reg = adt_get_prop_val(node, "reg");
    size_t n_reg = reg ? adt_get_prop_len(node, "reg") / sizeof(*reg) : 0;
    uint32_t *irqs = adt_get_prop_val(node, "interrupts");
    size_t n_irqs = irqs ? adt_get_prop_len(node, "interrupts") / 4 : 0;
    uint32_t *gen = adt_get_prop_val(node, "gen");
    const char *name = adt_get_prop_val(node, "name");
    if (n_reg < 3) {
        fprintf(stderr, "darwin-spmi: %s has %zu reg windows, need 3; not created\n", name, n_reg);
        return NULL;
    }
    if (!gen || *gen != 3) {
        fprintf(stderr, "darwin-spmi: %s is gen %u; only the traced Gen3 layout is modelled, not created\n",
                name, gen ? *gen : 0);
        return NULL;
    }

    DeviceState *dev = qdev_new(TYPE_DARWIN_SPMI);
    qdev_prop_set_string(dev, "name", name);
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);
    sysbus_realize_and_unref(sbd, &error_fatal);
    for (int i = 0; i < 3; i++) {
        sysbus_mmio_map(sbd, i, reg[i].base + iobase);
    }
    /* interrupts[1] is the only entry whose interrupt-parent is the AIC. */
    uint32_t vector = 0;
    if (n_irqs >= 2) {
        vector = irqs[1];
    } else if (n_irqs) {
        vector = irqs[0];
    }
    if (aic && n_irqs) {
        sysbus_connect_irq(sbd, 0, darwin_aic_get_irq(aic, vector));
    }
    fprintf(stderr, "darwin-spmi: %s gen %u queue 0x%" PRIx64 " fault 0x%" PRIx64
            " ctrl 0x%" PRIx64 " aic irq 0x%x\n", name, *gen,
            reg[0].base + iobase, reg[1].base + iobase, reg[2].base + iobase, vector);

    for (struct dtree_node *c = adt_first_child(node); c; c = adt_next_sibling(node, c)) {
        const char *compat = adt_get_prop_val(c, "compatible");
        if (compat && !strcmp(compat, "pmu,spmi")) {
            darwin_pmu_create(c, dev);
        }
    }
    return dev;
}
