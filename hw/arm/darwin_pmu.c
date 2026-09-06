/*
 * darwin-pmu: Dialog "baku" SPMI PMU, as far as the T8140 RTC driver needs it.
 *
 * The slave is a 64 KiB byte-addressed register file behind SPMI slave id
 * reg[0] of /arm-io/nub-spmi0/pmu-main (0x0e on iPhone17,3).  Only the RTC
 * registers have semantics; everything else is plain storage that reads back
 * what was written (zero initially) so the rest of AppleDialogSPMIPMU::start
 * proceeds.  DARWIN_PMU_DEBUG=1 logs every transfer so unmodelled registers
 * the driver relies on can be traced from the guest rather than guessed.
 *
 * RTC evidence, all static addresses in the 24A5430a kernelcache
 * (com.apple.driver.AppleSPMIPMU, class AppleDialogSPMIPMURTC):
 *
 *  - readConfiguration (0xfffffff009621098) takes the register addresses
 *    from the nub: info-rtc (0xf802), info-leg_scrpad (0xf700, used as
 *    +4 for the 32-bit seconds and +0x15 for the 16-bit ticks of the clock
 *    offset, 0xfffffff0096211d8-0xfffffff0096211e8), info-rtc_alarm_ctrl,
 *    info-rtc_alarm_event, info-rtc_alarm_offset, info-rtc_irq_mask_offset
 *    and the three masks.  "info-clock_offset" would select a 6-byte
 *    48-bit offset register instead; this tree has none.
 *  - The upcount read (0xfffffff00962255c) asks the provider for six bytes
 *    at info-rtc (EXT_READL through AppleDialogSPMIPMU::_readRegs,
 *    0xfffffff00961a4ac) and decodes b0>>1 | b1<<7 | b2<<15 | b3<<23 |
 *    b4<<31 | b5<<39 (0xfffffff009622724-0xfffffff009622750): a 47-bit
 *    32,768 Hz counter with bit 0 of the first byte unused.
 *  - getGMTTimeOfDay (0xfffffff0096220f4) returns (upcount + offset) >> 15
 *    seconds and ((upcount + offset) & 0x7fff) * 10^9 >> 15 nanoseconds.
 *  - _readCurrentOffsetTicks (0xfffffff00962168c): offset = sext47(
 *    secs << 15 | (ticks_b1 & 0x7f) << 8 | ticks_b0) from the two scratchpad
 *    reads; _writeOffset (0xfffffff009621878) stores offset >> 15 as four
 *    bytes at +4 and (offset & 0xff, (offset >> 8) & 0x7f) at +0x15.
 *    setGMTTimeOfDay only ever rewrites this offset (0xfffffff009621bd8);
 *    the upcount is never written.
 *
 * Inferno's hw/misc/apple-silicon/spmi-pmu.c serialises the same six-byte
 * tick layout and the same +4/+0x15 scratchpad split; that agreement is why
 * its shape was adopted.  Its alarm handling is copied with the register
 * offsets and masks taken from this tree, but no alarm transaction has been
 * traced on this guest yet, so treat the alarm path as unverified.
 *
 * Time base and persistence.  On real hardware the counter runs from the
 * PMU's own supply and the offset lives in battery-backed scratchpad, so
 * both survive reboots.  Here:
 *  - the upcount is (rtc_clock now - clock_base_ns) in ticks, so it advances
 *    at wall-clock rate and keeps advancing across a snapshot restore;
 *  - at first power-on the scratchpad offset is seeded so that upcount +
 *    offset equals QEMU's RTC time (honouring -rtc base=), which is what
 *    puts the guest at host UTC on a fresh boot;
 *  - with DARWIN_PMU_STATE=<file> the register file and the epoch at which
 *    the upcount was zero are loaded at start and saved after every guest
 *    write and at exit, so a guest-set clock survives a QEMU restart.
 *    Without it every fresh QEMU start is a "battery pull": host time again.
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/cutils.h"
#include "qemu/bitops.h"
#include "qemu/bswap.h"
#include "qemu/error-report.h"
#include "qemu/timer.h"
#include "qapi/error.h"
#include "migration/vmstate.h"
#include "hw/core/irq.h"
#include "hw/core/qdev-properties.h"
#include "system/rtc.h"
#include "system/system.h"
#include "system/runstate.h"
#include "xnu/darwin_spmi.h"

#define PMU_REG_SIZE      0x10000
#define RTC_TICK_HZ       32768ULL
#define RTC_TICK_MASK     ((1ULL << 47) - 1)

#define LEG_SCRPAD_SECS   4       /* +4: u32 offset seconds (0xfffffff0096211dc) */
#define LEG_SCRPAD_TICKS  0x15    /* +0x15: u16 offset ticks (0xfffffff0096211e4) */

#define PMU_STATE_MAGIC   "DVMPMU01"

OBJECT_DECLARE_SIMPLE_TYPE(DarwinPMUState, DARWIN_PMU)

struct DarwinPMUState {
    DeviceState parent_obj;
    qemu_irq irq;
    QEMUTimer *alarm_timer;
    char *name;
    char *state_path;
    bool debug;
    uint32_t sid;

    uint32_t reg_rtc;
    uint32_t reg_leg_scrpad;
    uint32_t reg_alarm_ctrl;
    uint32_t reg_alarm_event;
    uint32_t reg_alarm;
    uint32_t reg_irq_mask;
    uint32_t alarm_ctrl_en_mask;
    uint32_t alarm_mask;
    uint32_t alarm_monitor_mask;

    /* rtc_clock timestamp at which the upcount read zero. */
    int64_t clock_base_ns;
    /* Host epoch (ns) at that instant; only used for the state file. */
    int64_t upcount_epoch0_ns;

    uint8_t *regs;
    uint64_t n_reads;
    uint64_t n_writes;
};

static uint64_t ns_to_ticks(int64_t ns)
{
    if (ns < 0) {
        return 0;
    }
    uint64_t secs = ns / NANOSECONDS_PER_SECOND;
    uint64_t frac = ns % NANOSECONDS_PER_SECOND;
    return (secs << 15) | (frac * RTC_TICK_HZ / NANOSECONDS_PER_SECOND);
}

static uint64_t pmu_upcount(DarwinPMUState *s)
{
    return ns_to_ticks(qemu_clock_get_ns(rtc_clock) - s->clock_base_ns) & RTC_TICK_MASK;
}

static int64_t pmu_offset_ticks(DarwinPMUState *s)
{
    const uint8_t *p = s->regs + s->reg_leg_scrpad;
    uint64_t secs = ldl_le_p(p + LEG_SCRPAD_SECS);
    uint64_t t = (secs << 15) | ((uint64_t)(p[LEG_SCRPAD_TICKS + 1] & 0x7f) << 8) | p[LEG_SCRPAD_TICKS];
    return sextract64(t, 0, 47);
}

static void pmu_set_offset_ticks(DarwinPMUState *s, int64_t off)
{
    uint8_t *p = s->regs + s->reg_leg_scrpad;
    stl_le_p(p + LEG_SCRPAD_SECS, (uint32_t)(off >> 15));
    p[LEG_SCRPAD_TICKS] = off & 0xff;
    p[LEG_SCRPAD_TICKS + 1] = (off >> 8) & 0x7f;
}

/* QEMU RTC time (after -rtc base=) as host-epoch nanoseconds. */
static int64_t pmu_rtc_epoch_ns(void)
{
    struct tm tm;
    qemu_get_timedate(&tm, 0);
    return (int64_t)mktimegm(&tm) * NANOSECONDS_PER_SECOND;
}

static void pmu_save_state(DarwinPMUState *s)
{
    if (!s->state_path) {
        return;
    }
    g_autofree char *tmp = g_strdup_printf("%s.tmp", s->state_path);
    FILE *f = fopen(tmp, "wb");
    if (!f) {
        warn_report("darwin-pmu: cannot write %s: %s", tmp, strerror(errno));
        return;
    }
    bool ok = fwrite(PMU_STATE_MAGIC, 8, 1, f) == 1 &&
              fwrite(&s->upcount_epoch0_ns, sizeof(s->upcount_epoch0_ns), 1, f) == 1 &&
              fwrite(s->regs, PMU_REG_SIZE, 1, f) == 1;
    ok = fclose(f) == 0 && ok;
    if (!ok || rename(tmp, s->state_path) != 0) {
        warn_report("darwin-pmu: cannot save %s: %s", s->state_path, strerror(errno));
        unlink(tmp);
    }
}

static bool pmu_load_state(DarwinPMUState *s)
{
    if (!s->state_path) {
        return false;
    }
    FILE *f = fopen(s->state_path, "rb");
    if (!f) {
        return false;
    }
    char magic[8];
    int64_t epoch0;
    bool ok = fread(magic, 8, 1, f) == 1 && !memcmp(magic, PMU_STATE_MAGIC, 8) &&
              fread(&epoch0, sizeof(epoch0), 1, f) == 1 &&
              fread(s->regs, PMU_REG_SIZE, 1, f) == 1;
    fclose(f);
    if (!ok) {
        warn_report("darwin-pmu: %s is not a PMU state file; starting fresh", s->state_path);
        memset(s->regs, 0, PMU_REG_SIZE);
        return false;
    }
    s->upcount_epoch0_ns = epoch0;
    return true;
}

static void pmu_update_irq(DarwinPMUState *s)
{
    bool level = s->regs[s->reg_irq_mask] & s->regs[s->reg_alarm_event] & s->alarm_mask;
    qemu_set_irq(s->irq, level);
}

static void pmu_alarm_fire(void *opaque)
{
    DarwinPMUState *s = opaque;
    s->regs[s->reg_alarm_event] |= s->alarm_mask;
    if (s->debug) {
        fprintf(stderr, "pmu(%s): alarm fired\n", s->name);
    }
    pmu_update_irq(s);
    qemu_system_wakeup_request(QEMU_WAKEUP_REASON_RTC, NULL);
}

/*
 * Alarm: Inferno compares a 32-bit seconds value at the alarm register with
 * the upcount's seconds when the control enable bit is set.  The T8140 driver
 * strings name the same registers (info-rtc_alarm_offset/ctrl/event) but its
 * arm/fire sequence has not been traced on this guest; this is the untested
 * part of the model.
 */
static void pmu_alarm_update(DarwinPMUState *s)
{
    if (!(s->regs[s->reg_alarm_ctrl] & s->alarm_ctrl_en_mask)) {
        timer_del(s->alarm_timer);
        return;
    }
    int64_t now = qemu_clock_get_ns(rtc_clock);
    int64_t alarm_secs = (int64_t)ldl_le_p(s->regs + s->reg_alarm);
    int64_t delta = alarm_secs - (int64_t)(pmu_upcount(s) >> 15);
    if (s->debug) {
        fprintf(stderr, "pmu(%s): alarm armed for upcount second %" PRId64 " (in %" PRId64 " s)\n",
                s->name, alarm_secs, delta);
    }
    if (delta <= 0) {
        timer_del(s->alarm_timer);
        pmu_alarm_fire(s);
    } else {
        timer_mod_ns(s->alarm_timer, now + delta * NANOSECONDS_PER_SECOND);
    }
}

static int pmu_read(void *opaque, uint16_t addr, uint8_t *buf, unsigned len)
{
    DarwinPMUState *s = opaque;
    s->n_reads++;
    if ((uint32_t)addr + len > PMU_REG_SIZE) {
        return 0;
    }
    if (addr < s->reg_rtc + 6 && addr + len > s->reg_rtc) {
        uint64_t t = pmu_upcount(s);
        uint8_t *p = s->regs + s->reg_rtc;
        p[0] = (t << 1) & 0xff;
        p[1] = t >> 7;
        p[2] = t >> 15;
        p[3] = t >> 23;
        p[4] = t >> 31;
        p[5] = t >> 39;
    }
    memcpy(buf, s->regs + addr, len);
    if (s->debug) {
        fprintf(stderr, "pmu(%s): read  0x%04x len %u:", s->name, addr, len);
        for (unsigned i = 0; i < len; i++) fprintf(stderr, " %02x", buf[i]);
        if (addr == s->reg_rtc) {
            fprintf(stderr, "  (upcount %" PRIu64 " ticks, offset %" PRId64 ", guest epoch %" PRId64 ")",
                    pmu_upcount(s), pmu_offset_ticks(s),
                    (int64_t)((pmu_upcount(s) + pmu_offset_ticks(s)) >> 15));
        }
        fprintf(stderr, "\n");
    }
    return len;
}

static int pmu_write(void *opaque, uint16_t addr, const uint8_t *buf, unsigned len)
{
    DarwinPMUState *s = opaque;
    s->n_writes++;
    if ((uint32_t)addr + len > PMU_REG_SIZE) {
        return 0;
    }
    if (s->debug) {
        fprintf(stderr, "pmu(%s): write 0x%04x len %u:", s->name, addr, len);
        for (unsigned i = 0; i < len; i++) fprintf(stderr, " %02x", buf[i]);
        fprintf(stderr, "\n");
    }
    /* The upcount is read-only; a write lands in the shadow bytes and is
     * overwritten by the next read. */
    memcpy(s->regs + addr, buf, len);

    bool touches = false;
    for (unsigned i = 0; i < len; i++) {
        uint32_t a = addr + i;
        if (a == s->reg_alarm_ctrl || a == s->reg_alarm_event || a == s->reg_irq_mask ||
            (a >= s->reg_alarm && a < s->reg_alarm + 4)) {
            touches = true;
        }
    }
    if (touches) {
        pmu_alarm_update(s);
        pmu_update_irq(s);
    }
    if (s->debug && addr >= s->reg_leg_scrpad && addr < s->reg_leg_scrpad + 0x20) {
        fprintf(stderr, "pmu(%s): clock offset now %" PRId64 " ticks; guest epoch %" PRId64 "\n",
                s->name, pmu_offset_ticks(s),
                (int64_t)((pmu_upcount(s) + pmu_offset_ticks(s)) >> 15));
    }
    pmu_save_state(s);
    return len;
}

static const DarwinSPMISlaveOps pmu_ops = {
    .read = pmu_read,
    .write = pmu_write,
};

static Notifier pmu_exit_notifier;
static DarwinPMUState *pmu_singleton;

static void pmu_exit(Notifier *n, void *data)
{
    if (pmu_singleton) {
        pmu_save_state(pmu_singleton);
    }
}

static void darwin_pmu_realize(DeviceState *dev, Error **errp)
{
    DarwinPMUState *s = DARWIN_PMU(dev);
    s->debug = getenv("DARWIN_PMU_DEBUG") != NULL;
    s->regs = g_malloc0(PMU_REG_SIZE);
    s->alarm_timer = timer_new_ns(rtc_clock, pmu_alarm_fire, s);
    qdev_init_gpio_out(dev, &s->irq, 1);

    const char *path = getenv("DARWIN_PMU_STATE");
    if (path && *path) {
        s->state_path = g_strdup(path);
    }

    int64_t now_ns = qemu_clock_get_ns(rtc_clock);
    int64_t host_epoch_ns = get_clock_realtime();
    if (pmu_load_state(s)) {
        /* The counter kept running while QEMU was down. */
        s->clock_base_ns = now_ns - (host_epoch_ns - s->upcount_epoch0_ns);
        fprintf(stderr, "darwin-pmu: %s restored from %s; upcount %" PRIu64 " ticks, guest epoch %" PRId64 "\n",
                s->name, s->state_path, pmu_upcount(s),
                (int64_t)((pmu_upcount(s) + pmu_offset_ticks(s)) >> 15));
    } else {
        s->clock_base_ns = now_ns;
        s->upcount_epoch0_ns = host_epoch_ns;
        pmu_set_offset_ticks(s, ns_to_ticks(pmu_rtc_epoch_ns()));
        fprintf(stderr, "darwin-pmu: %s power-on; offset seeded to guest epoch %" PRId64 "%s\n",
                s->name, pmu_offset_ticks(s) >> 15,
                s->state_path ? " (will persist)" : " (volatile: no DARWIN_PMU_STATE)");
        pmu_save_state(s);
    }
    if (!pmu_singleton) {
        pmu_singleton = s;
        pmu_exit_notifier.notify = pmu_exit;
        qemu_add_exit_notifier(&pmu_exit_notifier);
    }
    qemu_system_wakeup_enable(QEMU_WAKEUP_REASON_RTC, true);
}

static int darwin_pmu_post_load(void *opaque, int version_id)
{
    DarwinPMUState *s = opaque;
    if (s->reg_rtc + 6 > PMU_REG_SIZE || s->reg_leg_scrpad + LEG_SCRPAD_TICKS + 2 > PMU_REG_SIZE ||
        s->reg_alarm + 4 > PMU_REG_SIZE || s->reg_alarm_ctrl >= PMU_REG_SIZE ||
        s->reg_alarm_event >= PMU_REG_SIZE || s->reg_irq_mask >= PMU_REG_SIZE) {
        return -EINVAL;
    }
    pmu_alarm_update(s);
    pmu_update_irq(s);
    return 0;
}

static const VMStateDescription vmstate_darwin_pmu = {
    .name = TYPE_DARWIN_PMU,
    .version_id = 1,
    .minimum_version_id = 1,
    .post_load = darwin_pmu_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32(reg_rtc, DarwinPMUState),
        VMSTATE_UINT32(reg_leg_scrpad, DarwinPMUState),
        VMSTATE_UINT32(reg_alarm_ctrl, DarwinPMUState),
        VMSTATE_UINT32(reg_alarm_event, DarwinPMUState),
        VMSTATE_UINT32(reg_alarm, DarwinPMUState),
        VMSTATE_UINT32(reg_irq_mask, DarwinPMUState),
        VMSTATE_UINT32(alarm_ctrl_en_mask, DarwinPMUState),
        VMSTATE_UINT32(alarm_mask, DarwinPMUState),
        VMSTATE_UINT32(alarm_monitor_mask, DarwinPMUState),
        VMSTATE_INT64(clock_base_ns, DarwinPMUState),
        VMSTATE_INT64(upcount_epoch0_ns, DarwinPMUState),
        VMSTATE_BUFFER_POINTER_UNSAFE(regs, DarwinPMUState, 1, PMU_REG_SIZE),
        VMSTATE_TIMER_PTR(alarm_timer, DarwinPMUState),
        VMSTATE_UINT64(n_reads, DarwinPMUState),
        VMSTATE_UINT64(n_writes, DarwinPMUState),
        VMSTATE_END_OF_LIST()
    },
};

static const Property darwin_pmu_properties[] = {
    DEFINE_PROP_STRING("name", DarwinPMUState, name),
    DEFINE_PROP_UINT32("sid", DarwinPMUState, sid, 0),
    DEFINE_PROP_UINT32("reg-rtc", DarwinPMUState, reg_rtc, 0xf802),
    DEFINE_PROP_UINT32("reg-leg-scrpad", DarwinPMUState, reg_leg_scrpad, 0xf700),
    DEFINE_PROP_UINT32("reg-alarm-ctrl", DarwinPMUState, reg_alarm_ctrl, 0xf800),
    DEFINE_PROP_UINT32("reg-alarm-event", DarwinPMUState, reg_alarm_event, 0xf80c),
    DEFINE_PROP_UINT32("reg-alarm", DarwinPMUState, reg_alarm, 0xf808),
    DEFINE_PROP_UINT32("reg-irq-mask", DarwinPMUState, reg_irq_mask, 0xf80e),
    DEFINE_PROP_UINT32("alarm-ctrl-en-mask", DarwinPMUState, alarm_ctrl_en_mask, 0x40),
    DEFINE_PROP_UINT32("alarm-mask", DarwinPMUState, alarm_mask, 1),
    DEFINE_PROP_UINT32("alarm-monitor-mask", DarwinPMUState, alarm_monitor_mask, 1),
};

static void darwin_pmu_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = darwin_pmu_realize;
    dc->vmsd = &vmstate_darwin_pmu;
    device_class_set_props(dc, darwin_pmu_properties);
    dc->user_creatable = false;
}

static const TypeInfo darwin_pmu_info = {
    .name = TYPE_DARWIN_PMU,
    .parent = TYPE_DEVICE,
    .instance_size = sizeof(DarwinPMUState),
    .class_init = darwin_pmu_class_init,
};

static void darwin_pmu_register_types(void)
{
    type_register_static(&darwin_pmu_info);
}

type_init(darwin_pmu_register_types)

static bool dt_u32(struct dtree_node *n, const char *key, uint32_t *out)
{
    uint32_t *p = adt_get_prop_val(n, key);
    if (!p || adt_get_prop_len(n, key) < 4) {
        return false;
    }
    *out = *p;
    return true;
}

DeviceState *darwin_pmu_create(struct dtree_node *node, DeviceState *spmi)
{
    const char *name = adt_get_prop_val(node, "name");
    uint32_t *reg = adt_get_prop_val(node, "reg");
    uint32_t v;
    if (!reg) {
        fprintf(stderr, "darwin-pmu: %s has no reg; not created\n", name);
        return NULL;
    }
    DeviceState *dev = qdev_new(TYPE_DARWIN_PMU);
    qdev_prop_set_string(dev, "name", name);
    /* reg is six cells (0e 03 00 04 00 00 on this tree); only the first is
     * consumed as the slave id, as in Inferno's apple_spmi_pmu_from_node. */
    qdev_prop_set_uint32(dev, "sid", reg[0] & 0xf);
    struct { const char *dt; const char *prop; } map[] = {
        { "info-rtc", "reg-rtc" },
        { "info-leg_scrpad", "reg-leg-scrpad" },
        { "info-rtc_alarm_ctrl", "reg-alarm-ctrl" },
        { "info-rtc_alarm_event", "reg-alarm-event" },
        { "info-rtc_alarm_offset", "reg-alarm" },
        { "info-rtc_irq_mask_offset", "reg-irq-mask" },
        { "info-rtc_alarm_ctrl_en_mask", "alarm-ctrl-en-mask" },
        { "info-rtc_alarm_mask", "alarm-mask" },
        { "info-rtc_alarm_monitor_mask", "alarm-monitor-mask" },
    };
    for (size_t i = 0; i < ARRAY_SIZE(map); i++) {
        if (dt_u32(node, map[i].dt, &v)) {
            qdev_prop_set_uint32(dev, map[i].prop, v);
        } else {
            fprintf(stderr, "darwin-pmu: %s lacks %s; using the iPhone17,3 default\n", name, map[i].dt);
        }
    }
    if (adt_get_prop_val(node, "info-clock_offset")) {
        fprintf(stderr, "darwin-pmu: %s has info-clock_offset, which selects the untraced "
                "48-bit offset register; only the legacy scratchpad is modelled\n", name);
    }
    qdev_realize_and_unref(dev, NULL, &error_fatal);
    DarwinPMUState *s = DARWIN_PMU(dev);
    darwin_spmi_attach_slave(spmi, s->sid, &pmu_ops, s);
    if (dt_u32(node, "interrupts", &v)) {
        qdev_connect_gpio_out(dev, 0, darwin_spmi_get_irq(spmi, v));
    }
    fprintf(stderr, "darwin-pmu: %s sid %u rtc 0x%04x scrpad 0x%04x alarm ctrl 0x%04x/%02x "
            "value 0x%04x event 0x%04x irq-mask 0x%04x spmi irq %u\n",
            name, s->sid, s->reg_rtc, s->reg_leg_scrpad, s->reg_alarm_ctrl,
            s->alarm_ctrl_en_mask, s->reg_alarm, s->reg_alarm_event, s->reg_irq_mask,
            dt_u32(node, "interrupts", &v) ? v : 0);
    return dev;
}
