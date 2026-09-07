/*
 * darwin-input: bounded, acknowledged single-touch transport over the
 * console UART.  See include/xnu/darwin_input.h for the wire format and the
 * reasoning behind not modelling Apple's touch controller.
 *
 * Flow control comes from the emulated 16-byte RX FIFO: a record is pushed
 * byte-wise as space appears (the fixed full/empty bit in exynos4210_uart.c
 * reports it exactly), at most DARWIN_INPUT_WINDOW records are outstanding
 * before an ACK, and motion behind an unsent motion record is coalesced so a
 * slow guest sees the newest position rather than a backlog.  Button edges
 * are never coalesced away.  Everything runs under the BQL: input events and
 * timers on the main loop, the TX observer from the vCPU's MMIO write.
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/timer.h"
#include "hw/arm/exynos4210.h"
#include "xnu/darwin_input.h"

#define ACK_TIMEOUT_NS      (10LL * NANOSECONDS_PER_SECOND)
#define DISPATCH_TIMEOUT_NS (30LL * NANOSECONDS_PER_SECOND)
#define PING_INTERVAL_NS    (2LL * NANOSECONDS_PER_SECOND)
#define STATUS_INTERVAL_NS  (250LL * SCALE_MS)
#define BUSY_TICK_NS        (1LL * SCALE_MS)
#define IDLE_TICK_NS        (100LL * SCALE_MS)
#define WHEEL_BATCH_NS      (40LL * SCALE_MS)
#define WHEEL_MAX_NOTCHES   8

static void darwin_input_pump(DarwinInputState *s);

static int64_t vnow(void)
{
    return qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
}

static int64_t rnow(void)
{
    return qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
}

static void arm_timer(DarwinInputState *s)
{
    int64_t delay = (s->wire_pos < s->wire_len || s->q_len || s->cancel_pending)
                    ? BUSY_TICK_NS : s->wheel_notches ? WHEEL_BATCH_NS / 2 : IDLE_TICK_NS;
    timer_mod(s->timer, vnow() + delay);
}

static void log_line(DarwinInputState *s, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "darwin-input: epoch=%u ", s->epoch);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    s->status_dirty = true;
}

static bool guest_accepts_input(DarwinInputState *s)
{
    return s->guest_state == 'R';
}

/* ---------------- queue ---------------- */

static DarwinInputRecord *queue_tail(DarwinInputState *s)
{
    if (!s->q_len) {
        return NULL;
    }
    return &s->queue[(s->q_head + s->q_len - 1) % DARWIN_INPUT_QUEUE];
}

static void queue_push(DarwinInputState *s, uint8_t kind, uint16_t a, uint16_t b,
                       int32_t c)
{
    DarwinInputRecord *r = &s->queue[(s->q_head + s->q_len) % DARWIN_INPUT_QUEUE];
    r->kind = kind;
    r->a = a;
    r->b = b;
    r->c = c;
    r->host_ms = rnow() / SCALE_MS;
    s->q_len++;
    s->status_dirty = true;
}

static bool queue_pop(DarwinInputState *s, DarwinInputRecord *out)
{
    if (!s->q_len) {
        return false;
    }
    *out = s->queue[s->q_head];
    s->q_head = (s->q_head + 1) % DARWIN_INPUT_QUEUE;
    s->q_len--;
    return true;
}

static void queue_clear(DarwinInputState *s)
{
    s->q_head = s->q_len = 0;
}

/* Start a new epoch: the guest must drop any contact it holds, and nothing
 * queued or in flight from before can be trusted to still make sense. */
static void new_epoch(DarwinInputState *s, const char *why)
{
    queue_clear(s);
    /* Terminate any prefix already delivered to the tty before the cancel.
     * Dropping only our remaining bytes would splice two records together. */
    s->wire[0] = '\n';
    s->wire_len = 1;
    s->wire_pos = 0;
    s->inflight_n = 0;
    s->contact_sent = false;
    s->wheel_notches = 0;
    s->wheel_deadline_vns = 0;
    s->cancel_pending = true;
    s->btn_down = false;
    s->dirty = false;
    s->probe_sent_rns = s->probe_present_rns = 0;
    s->epoch++;
    s->c_epochs++;
    log_line(s, "new epoch (%s); cancelling any guest contact", why);
}

static void enqueue(DarwinInputState *s, uint8_t kind, uint16_t a, uint16_t b,
                    int32_t c)
{
    DarwinInputRecord *tail;

    if (!guest_accepts_input(s)) {
        /* Never let input pile up in the console tty while nobody reads it:
         * it would replay as surprise taps once the helper appears. */
        s->c_overflow++;
        s->status_dirty = true;
        return;
    }
    tail = queue_tail(s);
    if (kind == 'M' && tail && tail->kind == 'M') {
        tail->a = a;
        tail->b = b;
        tail->host_ms = rnow() / SCALE_MS;
        s->c_coalesced++;
        return;
    }
    if (kind == 'W' && tail && tail->kind == 'W') {
        /* Trackpads can produce batches faster than iOS can perform the
         * drag. Keep one bounded pending displacement, not seconds of
         * scrolling after the user has stopped moving the wheel. */
        tail->a = a;
        tail->b = b;
        tail->c = CLAMP(tail->c + c, -WHEEL_MAX_NOTCHES, WHEEL_MAX_NOTCHES);
        tail->host_ms = rnow() / SCALE_MS;
        if (!tail->c) s->q_len--;
        s->c_coalesced++;
        s->status_dirty = true;
        return;
    }
    if (s->q_len >= DARWIN_INPUT_QUEUE) {
        if (kind == 'M') {
            s->c_coalesced++;
            return;                 /* newer motion will follow */
        }
        /* Too many unsent edges: the gesture history is unrecoverable, so
         * restart from a released contact instead of replaying it late. */
        s->c_overflow++;
        new_epoch(s, "queue overflow");
    }
    queue_push(s, kind, a, b, c);
}

/* ---------------- host input ---------------- */

void darwin_input_abs(DarwinInputState *s, bool is_x, int value)
{
    if (!s->enabled) {
        return;
    }
    value = CLAMP(value, 0, 32767);
    if (is_x) {
        s->abs_x = value;
    } else {
        s->abs_y = value;
    }
    s->dirty = true;
}

void darwin_input_button(DarwinInputState *s, bool down)
{
    if (!s->enabled) {
        return;
    }
    s->btn_down = down;
    s->dirty = true;
}

void darwin_input_consumer(DarwinInputState *s, uint16_t usage, bool down)
{
    if (!s->enabled) {
        return;
    }
    s->c_host_events++;
    enqueue(s, 'B', usage, down, 0);
    darwin_input_pump(s);
    arm_timer(s);
}

void darwin_input_wheel(DarwinInputState *s, int notches)
{
    if (!s->enabled) {
        return;
    }
    s->c_host_events++;
    if (!guest_accepts_input(s)) {
        s->c_overflow++;
        s->status_dirty = true;
        return;
    }
    /* A wheel while a finger is down would fight the drag; ignore it. */
    if (s->btn_down || s->contact_sent) {
        return;
    }
    s->wheel_notches = CLAMP(s->wheel_notches + notches, -WHEEL_MAX_NOTCHES, WHEEL_MAX_NOTCHES);
    if (!s->wheel_notches) {
        s->wheel_deadline_vns = 0;
    } else if (!s->wheel_deadline_vns) {
        s->wheel_deadline_vns = vnow() + WHEEL_BATCH_NS;
    }
    arm_timer(s);
}

static void flush_wheel(DarwinInputState *s)
{
    if (!s->wheel_notches || vnow() < s->wheel_deadline_vns) {
        return;
    }
    if (!s->btn_down && !s->contact_sent) {
        enqueue(s, 'W', s->abs_x, s->abs_y, s->wheel_notches);
    }
    s->wheel_notches = 0;
    s->wheel_deadline_vns = 0;
    darwin_input_pump(s);
}

void darwin_input_sync(DarwinInputState *s)
{
    if (!s->enabled || !s->dirty) {
        return;
    }
    s->dirty = false;
    s->c_host_events++;
    if (s->btn_down && !s->contact_sent) {
        enqueue(s, 'D', s->abs_x, s->abs_y, 0);
        s->contact_sent = guest_accepts_input(s);
    } else if (!s->btn_down && s->contact_sent) {
        enqueue(s, 'U', s->abs_x, s->abs_y, 0);
        s->contact_sent = false;
    } else if (s->btn_down && s->contact_sent) {
        enqueue(s, 'M', s->abs_x, s->abs_y, 0);
    }
    /* A hover without contact is not a touch; nothing to send. */
    darwin_input_pump(s);
    arm_timer(s);
}

/* ---------------- wire ---------------- */

static void wire_load(DarwinInputState *s, uint8_t kind, uint16_t a, uint16_t b,
                      int32_t c, int64_t host_ms)
{
    uint32_t seq = s->next_seq++;
    int len = snprintf((char *)s->wire, sizeof(s->wire),
                       "DVMI2 %u %u %c %u %u %d %" PRId64 "\n",
                       s->epoch, seq, kind, a, b, c, host_ms);
    assert(len > 0 && (size_t)len < sizeof(s->wire));
    s->wire_len = len;
    s->wire_pos = 0;
    if (s->inflight_n < DARWIN_INPUT_WINDOW) {
        DarwinInputInflight *f = &s->inflight[s->inflight_n++];
        f->seq = seq;
        f->kind = kind;
        f->acked = f->dispatched = false;
        f->sent_vns = vnow();
        f->sent_rns = rnow();
    }
    if (kind == 'D' || kind == 'U') {
        s->probe_sent_rns = rnow();
        s->probe_present_rns = 0;
    }
    s->c_sent++;
    if (kind != 'P' && kind != 'C' && getenv("DARWIN_INPUT_TIMING")) {
        fprintf(stderr, "darwin-input: timing epoch=%u seq=%u kind=%c a=%u b=%u c=%d monotonic_ns=%" PRId64 "\n",
                s->epoch, seq, kind, a, b, c, rnow());
    }
    if (kind == 'P') {
        s->c_pings++;
    }
    s->status_dirty = true;
}

static void wire_push(DarwinInputState *s)
{
    while (s->wire_pos < s->wire_len) {
        int n = exynos4210_uart_inject(s->uart, s->wire + s->wire_pos,
                                       s->wire_len - s->wire_pos);
        if (n <= 0) {
            return;             /* FIFO full: retry on the next tick */
        }
        s->wire_pos += n;
    }
}

static void darwin_input_pump(DarwinInputState *s)
{
    DarwinInputRecord r;

    if (!s->enabled || !s->guest_state) {
        return;
    }
    for (;;) {
        wire_push(s);
        if (s->wire_pos < s->wire_len) {
            return;             /* still draining the last record */
        }
        if (s->inflight_n >= DARWIN_INPUT_WINDOW) {
            return;             /* wait for ACKs */
        }
        if (s->cancel_pending) {
            s->cancel_pending = false;
            wire_load(s, 'C', 0, 0, 0, rnow() / SCALE_MS);
            continue;
        }
        if (s->q_len && s->queue[s->q_head].kind == 'W') {
            for (uint32_t i = 0; i < s->inflight_n; i++) {
                if (s->inflight[i].kind == 'W' && !s->inflight[i].dispatched) {
                    return; /* one active wheel drag plus one coalesced batch */
                }
            }
        }
        if (!queue_pop(s, &r)) {
            return;
        }
        wire_load(s, r.kind, r.a, r.b, r.c, r.host_ms);
    }
}

/* ---------------- guest replies ---------------- */

static bool needs_dispatch(uint8_t kind)
{
    return kind != 'P' && kind != 'C';
}

static void retire_record(DarwinInputState *s, uint32_t i)
{
    memmove(&s->inflight[i], &s->inflight[i + 1],
            (s->inflight_n - i - 1) * sizeof(s->inflight[0]));
    s->inflight_n--;
}

static void ack_line(DarwinInputState *s, const char *p)
{
    unsigned epoch, seq;
    char code, state;
    long long guest_us, delivery_ms = -1;
    uint32_t i;

    if (sscanf(p, "%u %u %c %c %lld %lld", &epoch, &seq, &code, &state,
               &guest_us, &delivery_ms) < 5 || guest_us < 0 ||
        !strchr("SQFNE", code) || !strchr("IRL", state)) {
        s->c_parse_errors++;
        return;
    }
    for (i = 0; i < s->inflight_n; i++) {
        if (s->inflight[i].seq == seq) {
            break;
        }
    }
    /* A delayed/duplicate reply cannot revive a lost helper or retire a
     * current record, and must never count as a successful submission. */
    if (epoch != s->epoch || i == s->inflight_n || s->inflight[i].acked) {
        s->c_ack_rejected++;
        s->status_dirty = true;
        return;
    }
    s->last_guest_vns = vnow();
    if (delivery_ms >= 0 && delivery_ms < 60000) {
        s->delivery_last_ms = delivery_ms;
        s->delivery_max_ms = MAX(s->delivery_max_ms, delivery_ms);
    }
    int64_t us = (rnow() - s->inflight[i].sent_rns) / SCALE_US;
    s->last_ack_us = us;
    s->max_ack_us = MAX(s->max_ack_us, us);
    s->sum_ack_us += us;
    s->n_ack_us++;
    s->inflight[i].acked = true;
    if (code == 'S' || code == 'Q') {
        s->c_acked++;
        if (!needs_dispatch(s->inflight[i].kind) || s->inflight[i].dispatched) {
            retire_record(s, i);
        }
    } else {
        if (code == 'F') s->c_ack_failed++;
        else if (code == 'N') s->c_ack_not_ready++;
        else s->c_ack_rejected++;
        retire_record(s, i);
    }
    if (s->guest_state != state) {
        s->c_ready_changes++;
        if (s->guest_state == 'R' && state != 'R') {
            new_epoch(s, "helper unavailable");
        }
        s->guest_state = state;
    }
    s->status_dirty = true;
    darwin_input_pump(s);
}

static void dispatch_line(DarwinInputState *s, const char *p)
{
    unsigned epoch, seq;
    char code;
    long long us;
    uint32_t i;

    if (sscanf(p, "%u %u %c %lld", &epoch, &seq, &code, &us) != 4 ||
        (code != 'S' && code != 'F') || us < 0) {
        s->c_parse_errors++;
        return;
    }
    for (i = 0; i < s->inflight_n; i++) {
        if (s->inflight[i].seq == seq) break;
    }
    if (epoch != s->epoch || i == s->inflight_n ||
        !needs_dispatch(s->inflight[i].kind) || s->inflight[i].dispatched) {
        return;
    }
    s->inflight[i].dispatched = true;
    if (code == 'S') s->c_dispatched++;
    else s->c_dispatch_failed++;
    s->dispatch_last_us = us;
    s->dispatch_max_us = MAX(s->dispatch_max_us, us);
    if (s->inflight[i].acked) retire_record(s, i);
    s->status_dirty = true;
    darwin_input_pump(s);
}

static void ready_line(DarwinInputState *s, const char *p)
{
    char state;
    unsigned pid, epoch;

    if (sscanf(p, "%c %u %u", &state, &pid, &epoch) != 3 ||
        !(state == 'I' || state == 'R' || state == 'L')) {
        s->c_parse_errors++;
        return;
    }
    s->last_guest_vns = vnow();
    if (s->guest_pid && pid != s->guest_pid) {
        s->c_guest_restarts++;
        log_line(s, "guest helper restarted (pid %u -> %u)", s->guest_pid, pid);
        new_epoch(s, "guest helper restart");
    } else if (s->guest_state == 'R' && state != 'R') {
        new_epoch(s, "helper unavailable");
    }
    if (s->guest_state != state) {
        s->c_ready_changes++;
        log_line(s, "guest state %c -> %c (pid %u)", s->guest_state ? s->guest_state : '?', state, pid);
    }
    s->guest_state = state;
    s->guest_pid = pid;
    s->guest_epoch = epoch;
    s->status_dirty = true;
    darwin_input_pump(s);
}

static void tx_observer(void *opaque, uint8_t ch)
{
    DarwinInputState *s = opaque;
    const char *p;

    if (ch != '\n') {
        if (s->line_len < sizeof(s->line) - 1) {
            s->line[s->line_len++] = ch;
        } else {
            /* Overlong console line: keep only its tail so a marker that
             * follows interleaved kernel output can still be found. */
            memmove(s->line, s->line + 32, s->line_len - 32);
            s->line_len -= 32;
            s->line[s->line_len++] = ch;
        }
        return;
    }
    s->line[s->line_len] = '\0';
    s->line_len = 0;
    p = strstr(s->line, "DVMI2A ");
    if (p) {
        ack_line(s, p + 7);
        return;
    }
    p = strstr(s->line, "DVMI2R ");
    if (p) {
        ready_line(s, p + 7);
        return;
    }
    p = strstr(s->line, "DVMI2D ");
    if (p) {
        dispatch_line(s, p + 7);
    }
}

/* ---------------- timer ---------------- */

static void check_timeouts(DarwinInputState *s)
{
    int64_t now = vnow();
    uint32_t i = 0;

    while (i < s->inflight_n) {
        int64_t deadline = s->inflight[i].acked ? DISPATCH_TIMEOUT_NS : ACK_TIMEOUT_NS;
        if (now - s->inflight[i].sent_vns > deadline) {
            s->c_timeouts++;
            log_line(s, "seq %u (%c) %s timeout", s->inflight[i].seq,
                     s->inflight[i].kind, s->inflight[i].acked ? "dispatch" : "ACK");
            /* Nothing behind a timed-out edge can safely be replayed. */
            new_epoch(s, "input timeout");
            if (s->guest_state != 'L') s->c_ready_changes++;
            s->guest_state = 'L';
            return;
        }
        i++;
    }
}

static void write_status(DarwinInputState *s)
{
    char *json;
    GError *err = NULL;

    if (!s->status_path) {
        return;
    }
    json = darwin_input_status_json(s);
    if (!g_file_set_contents(s->status_path, json, -1, &err)) {
        warn_report("darwin-input: cannot write %s: %s", s->status_path, err->message);
        g_error_free(err);
    }
    g_free(json);
}

static void timer_cb(void *opaque)
{
    DarwinInputState *s = opaque;
    int64_t now = vnow();

    check_timeouts(s);
    flush_wheel(s);
    darwin_input_pump(s);
    if (s->guest_state && !s->inflight_n && !s->q_len &&
        s->wire_pos >= s->wire_len && now - s->last_ping_vns > PING_INTERVAL_NS) {
        s->last_ping_vns = now;
        wire_load(s, 'P', 0, 0, 0, rnow() / SCALE_MS);
        wire_push(s);
    }
    if (s->status_dirty && now - s->last_status_vns > STATUS_INTERVAL_NS) {
        s->status_dirty = false;
        s->last_status_vns = now;
        write_status(s);
    }
    arm_timer(s);
}

/* ---------------- lifecycle ---------------- */

void darwin_input_presented(DarwinInputState *s)
{
    if (!s->enabled) {
        return;
    }
    s->c_presents++;
    if (s->probe_sent_rns && !s->probe_present_rns) {
        s->probe_present_rns = rnow();
        s->last_input_to_present_ms = (s->probe_present_rns - s->probe_sent_rns) / SCALE_MS;
        s->n_probe++;
        s->status_dirty = true;
    }
}

void darwin_input_reset(DarwinInputState *s, const char *why)
{
    if (!s->enabled) {
        return;
    }
    s->dirty = false;
    s->btn_down = false;
    s->line_len = 0;
    s->probe_sent_rns = s->probe_present_rns = 0;
    new_epoch(s, why);
    arm_timer(s);
}

void darwin_input_init(DarwinInputState *s, DeviceState *uart,
                       const char *status_path)
{
    memset(s, 0, sizeof(*s));
    s->uart = uart;
    s->enabled = true;
    s->epoch = 1;
    s->next_seq = 1;
    s->status_path = status_path && *status_path ? g_strdup(status_path) : NULL;
    s->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, timer_cb, s);
    exynos4210_uart_set_tx_observer(uart, tx_observer, s);
    s->cancel_pending = true;
    log_line(s, "native UART input transport enabled (status %s)",
             s->status_path ? s->status_path : "none");
    arm_timer(s);
}

char *darwin_input_status_json(DarwinInputState *s)
{
    GString *g = g_string_new("{");
    g_string_append_printf(g, "\"enabled\":%s,", s->enabled ? "true" : "false");
    g_string_append_printf(g, "\"epoch\":%u,\"next_seq\":%u,", s->epoch, s->next_seq);
    g_string_append_printf(g, "\"guest_state\":\"%c\",\"guest_pid\":%u,\"guest_epoch\":%u,",
                           s->guest_state ? s->guest_state : '?', s->guest_pid, s->guest_epoch);
    g_string_append_printf(g, "\"contact_sent\":%s,\"btn_down\":%s,\"abs_x\":%d,\"abs_y\":%d,",
                           s->contact_sent ? "true" : "false", s->btn_down ? "true" : "false",
                           s->abs_x, s->abs_y);
    g_string_append_printf(g, "\"wheel_pending\":%d,\"queue_len\":%u,\"inflight\":%u,\"wire_pending\":%u,",
                           s->wheel_notches, s->q_len, s->inflight_n, s->wire_len - s->wire_pos);
    g_string_append_printf(g, "\"host_events\":%" PRIu64 ",\"coalesced\":%" PRIu64
                           ",\"overflow_or_not_ready_drops\":%" PRIu64 ",",
                           s->c_host_events, s->c_coalesced, s->c_overflow);
    g_string_append_printf(g, "\"sent\":%" PRIu64 ",\"acked\":%" PRIu64 ",\"ack_failed\":%" PRIu64
                           ",\"ack_not_ready\":%" PRIu64 ",\"ack_rejected\":%" PRIu64
                           ",\"timeouts\":%" PRIu64 ",\"pings\":%" PRIu64 ",",
                           s->c_sent, s->c_acked, s->c_ack_failed, s->c_ack_not_ready,
                           s->c_ack_rejected, s->c_timeouts, s->c_pings);
    g_string_append_printf(g, "\"ready_changes\":%" PRIu64 ",\"guest_restarts\":%" PRIu64
                           ",\"epochs\":%" PRIu64 ",\"parse_errors\":%" PRIu64 ",\"presents\":%" PRIu64 ",",
                           s->c_ready_changes, s->c_guest_restarts, s->c_epochs,
                           s->c_parse_errors, s->c_presents);
    g_string_append_printf(g, "\"ack_last_us\":%" PRId64 ",\"ack_max_us\":%" PRId64
                           ",\"ack_mean_us\":%" PRId64 ",\"ack_samples\":%" PRIu64 ",",
                           s->last_ack_us, s->max_ack_us,
                           s->n_ack_us ? s->sum_ack_us / (int64_t)s->n_ack_us : 0, s->n_ack_us);
    g_string_append_printf(g, "\"delivery_last_ms\":%" PRId64 ",\"delivery_max_ms\":%" PRId64
                           ",\"dispatched\":%" PRIu64 ",\"dispatch_failed\":%" PRIu64
                           ",\"dispatch_last_us\":%" PRId64 ",\"dispatch_max_us\":%" PRId64 ",",
                           s->delivery_last_ms, s->delivery_max_ms, s->c_dispatched,
                           s->c_dispatch_failed, s->dispatch_last_us, s->dispatch_max_us);
    g_string_append_printf(g, "\"input_to_present_ms\":%" PRId64 ",\"input_to_present_samples\":%" PRIu64
                           ",\"probe_open\":%s,",
                           s->last_input_to_present_ms, s->n_probe,
                           (s->probe_sent_rns && !s->probe_present_rns) ? "true" : "false");
    g_string_append_printf(g, "\"virtual_ns\":%" PRId64 ",\"realtime_ns\":%" PRId64 "}\n",
                           vnow(), rnow());
    return g_string_free(g, FALSE);
}

/* Only durable identity and accounting migrate.  Queued, in-flight and wire
 * state are deliberately dropped: after a restore the host pointer is in an
 * unknown state, so darwin_input_reset() opens a new epoch and cancels. */
const VMStateDescription vmstate_darwin_input = {
    .name = "darwin-input",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32(epoch, DarwinInputState),
        VMSTATE_UINT32(next_seq, DarwinInputState),
        VMSTATE_UINT8(guest_state, DarwinInputState),
        VMSTATE_UINT32(guest_pid, DarwinInputState),
        VMSTATE_UINT32(guest_epoch, DarwinInputState),
        VMSTATE_UINT64(c_host_events, DarwinInputState),
        VMSTATE_UINT64(c_coalesced, DarwinInputState),
        VMSTATE_UINT64(c_overflow, DarwinInputState),
        VMSTATE_UINT64(c_sent, DarwinInputState),
        VMSTATE_UINT64(c_acked, DarwinInputState),
        VMSTATE_UINT64(c_ack_failed, DarwinInputState),
        VMSTATE_UINT64(c_ack_not_ready, DarwinInputState),
        VMSTATE_UINT64(c_ack_rejected, DarwinInputState),
        VMSTATE_UINT64(c_timeouts, DarwinInputState),
        VMSTATE_UINT64(c_pings, DarwinInputState),
        VMSTATE_UINT64(c_ready_changes, DarwinInputState),
        VMSTATE_UINT64(c_guest_restarts, DarwinInputState),
        VMSTATE_UINT64(c_epochs, DarwinInputState),
        VMSTATE_UINT64(c_parse_errors, DarwinInputState),
        VMSTATE_UINT64(c_presents, DarwinInputState),
        VMSTATE_INT64(last_ack_us, DarwinInputState),
        VMSTATE_INT64(max_ack_us, DarwinInputState),
        VMSTATE_INT64(sum_ack_us, DarwinInputState),
        VMSTATE_UINT64(n_ack_us, DarwinInputState),
        VMSTATE_INT64(last_input_to_present_ms, DarwinInputState),
        VMSTATE_UINT64(n_probe, DarwinInputState),
        VMSTATE_END_OF_LIST()
    },
};
