/*
 * darwin-input: native single-touch/button transport into the iOS guest.
 *
 * This is a host-to-guest input *transport*, not a model of Apple's touch
 * controller.  The t8140 device tree routes real touch through
 * /arm-io/dockchannel-mtp/mtp-transport/multi-touch (AppleDockChannel ->
 * RTBuddy over DockChannel -> AppleHIDTransportDeviceMailbox "MTPEndpoint1"
 * -> AppleMultitouchHIDService, parser-type 1); that stack speaks the
 * proprietary Z2/HBPP multitouch protocol and is documented, not modelled,
 * in docs/re/native-input.md.  Instead the host serialises pointer state
 * into short ASCII records, injects them into the console UART RX FIFO that
 * XNU already polls for its console, and a tiny IOKit-only guest helper
 * (tools/input/dvm_hid.c) turns them into IOHIDEvents on a virtual HID
 * service.  The helper's replies are parsed straight out of the UART TX
 * stream, so every stage is observable from QEMU:
 *
 *   host event -> bounded queue -> UART FIFO -> guest helper -> HID system
 *
 * Wire format (host -> guest, one record per line, < DARWIN_INPUT_WIRE bytes):
 *   DVMI2 <epoch> <seq> <K> <a> <b> <c> <host_ms>\n
 *     K = D down, M move, U up, C cancel (release any contact),
 *         P ping, B button (a = consumer usage, b = 1 down / 0 up),
 *         W wheel (a,b = pointer, c = signed notches; the guest performs a
 *         short drag that ends at rest so nothing flings)
 *     a,b = normalised 0..32767 touch coordinates for D/M/U/W
 * Guest -> host:
 *   DVMI2A <epoch> <seq> <code> <state> <guest_us> [<delivery_ms>]\n
 *     code  = S submitted, F dispatch failed, N not ready (dropped),
 *             Q accepted without HID (C/P), E rejected (epoch/parse)
 *     state = I initialising, R ready, L lost (HID service gone)
 *   DVMI2R <state> <pid> <epoch>\n   readiness announcements
 *   DVMI2D <epoch> <seq> <S|F> <dispatch_us>\n   asynchronous HID dispatch result
 *
 * The epoch changes whenever host-side state can no longer be trusted:
 * device reset, migration restore, guest helper restart, or queue overflow.
 * A record carrying a new epoch tells the helper to drop any held contact
 * before applying it, so a stale event never becomes a tap or a stuck finger.
 */
#pragma once

#include "qemu/osdep.h"
#include "qemu/timer.h"
#include "hw/core/qdev.h"
#include "migration/vmstate.h"

#define DARWIN_INPUT_QUEUE   64
#define DARWIN_INPUT_WINDOW  4
#define DARWIN_INPUT_WIRE    64
#define DARWIN_INPUT_LINE    192

typedef struct DarwinInputRecord {
    uint8_t kind;          /* 'D','M','U','C','P','B','W' */
    uint16_t a, b;
    int32_t c;             /* W: notches, positive = content scrolls up */
    int64_t host_ms;       /* host monotonic QEMU_CLOCK_REALTIME ms when produced */
} DarwinInputRecord;

typedef struct DarwinInputInflight {
    uint32_t seq;
    uint8_t kind;
    bool acked, dispatched;
    int64_t sent_vns;      /* virtual ns, for timeouts that pause with the guest */
    int64_t sent_rns;      /* realtime ns, for reported latency */
} DarwinInputInflight;

typedef struct DarwinInputState {
    bool enabled;
    DeviceState *uart;
    QEMUTimer *timer;
    char *status_path;

    /* Host pointer state, committed at input sync. */
    int32_t abs_x, abs_y;
    bool btn_down, dirty;
    bool contact_sent;     /* the guest is believed to hold a contact */
    /* Wheel notches are batched for a short window so one flick of a
     * wheel becomes one guest gesture rather than a burst of drags. */
    int32_t wheel_notches;
    int64_t wheel_deadline_vns;

    /* Bounded record queue (ring). */
    DarwinInputRecord queue[DARWIN_INPUT_QUEUE];
    uint32_t q_head, q_len;

    /* Record currently being pushed through the 16-byte RX FIFO. */
    uint8_t wire[DARWIN_INPUT_WIRE];
    uint32_t wire_len, wire_pos;

    /* Sent, unacknowledged records. */
    DarwinInputInflight inflight[DARWIN_INPUT_WINDOW];
    uint32_t inflight_n;

    uint32_t epoch, next_seq;

    /* Guest helper readiness as last reported on the UART. */
    uint8_t guest_state;   /* 0 unknown, 'I', 'R', 'L' */
    uint32_t guest_pid, guest_epoch;
    int64_t last_guest_vns, last_ping_vns;
    bool cancel_pending;

    /* TX line parser. */
    char line[DARWIN_INPUT_LINE];
    uint32_t line_len;

    /* Counters, all monotonic since device creation. */
    uint64_t c_host_events, c_coalesced, c_overflow, c_sent, c_acked;
    uint64_t c_ack_failed, c_ack_not_ready, c_ack_rejected, c_timeouts;
    uint64_t c_pings, c_ready_changes, c_guest_restarts, c_epochs;
    uint64_t c_parse_errors, c_presents;
    int64_t last_ack_us, max_ack_us, sum_ack_us;
    uint64_t n_ack_us;

    /* Input-to-presented-frame probe: realtime ns of the newest D/U send and
     * of the first DCP presentation after it. */
    int64_t probe_sent_rns, probe_present_rns, last_input_to_present_ms;
    uint64_t n_probe;

    /* Guest-reported stage timings (runtime only, not migrated): delivery
     * from injection to the helper's fgets, and the HID dispatch itself. */
    int64_t delivery_last_ms, delivery_max_ms;
    uint64_t c_dispatched, c_dispatch_failed;
    int64_t dispatch_last_us, dispatch_max_us;

    bool status_dirty;
    int64_t last_status_vns;
} DarwinInputState;

void darwin_input_init(DarwinInputState *s, DeviceState *uart,
                       const char *status_path);
/* Absolute pointer/button state from the QEMU input layer. */
void darwin_input_abs(DarwinInputState *s, bool is_x, int value);
void darwin_input_button(DarwinInputState *s, bool down);
/* Consumer-page button (0x40 Home, 0x30 Power) from a host key. */
void darwin_input_consumer(DarwinInputState *s, uint16_t usage, bool down);
/* One wheel notch at the current pointer position; +1 = wheel up. */
void darwin_input_wheel(DarwinInputState *s, int notches);
void darwin_input_sync(DarwinInputState *s);
/* A frame reached the host display; closes the latency probe. */
void darwin_input_presented(DarwinInputState *s);
/* Device reset and post-load: forget host state, bump the epoch, cancel. */
void darwin_input_reset(DarwinInputState *s, const char *why);
/* Human-readable JSON status for tools and the status file. */
char *darwin_input_status_json(DarwinInputState *s);

extern const VMStateDescription vmstate_darwin_input;
