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
 * 'sks' implements the iOS 27 IPC v1 negotiation and the media-key create /
 * unwrap path used by encrypted APFS.  The default list only gained it after
 * a guest-created encrypted volume survived a reboot and mounted successfully
 * (/tmp/dvm/probe/SKS_REMOUNT_V10.serial.log:476..500).
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
 * xART endpoints (16 'xars', 19 'xarm'), AppleSEPXART. The frame is the
 * generic one, but the reply's byte 2 is a status and bytes 3..4 are a u16
 * byte count, both read by the gated sender (0xfffffff00959f20c, called from
 * the 17 request builders through 0x59f0c4):
 *
 *   0x59ef60  the receive handler (0x59eea4) matches byte 1 against the
 *             outstanding tag and stores the whole 64-bit reply into the
 *             sender's message ("received message for invalid tag %u opcode
 *             %u" otherwise)
 *   0x59f4bc  ldrb w22, [msg, 2]: nonzero is returned to the caller as the
 *             IOReturn; zero means success
 *   0x59f530  ldurh w8, [msg, 3]: the byte count, capped at 0x8000, that it
 *             then copies out of the endpoint's OOL out-buffer (this+0xd0)
 *             into the caller's buffer and stores through its out_len pointer
 *             (0x59f568). With no out buffer a nonzero count is an error.
 *
 * Requests seen or read out of the builders (op = byte 2 of the message):
 *
 *   0x15  get one epoch slot: index in byte 6 (0x5a1c08), 8 bytes out,
 *         REQUIRE out_len == 8 (0x5a1c44)
 *   0x16  SEPEpoch::commitEpochs: 8 x u16 Epoch (16 bytes, 0x5a1d14) in the
 *         OOL in-buffer, no out buffer (0x5a1d1c)
 *   0x17  AppleSEPXART::getFullEpochs: 8 x 4-byte EpochSlot out. The block
 *         (0x5a1e3c) sends the bare 0x170000, expects 8 << 2 = 32 bytes
 *         (0x5a1e5c) and panics "REQUIRE fail: expected_out_len == out_len"
 *         (0x5bfd30) on anything else -- the AppleSEPXART_embedded.cpp:1021
 *         panic six lines after "Early boot complete". Consumers read only
 *         byte 0 of each slot (DispatchGetEpochs, 0x595df4..0x595dfc).
 *   0x11, 0x12, 0x18..0x1c and the blob save/fetch family (0x5a0a38..)
 *         not yet modelled; acknowledged with status 0 and length 0.
 *
 * The epoch values are constants (zero) standing in for SEP state that this
 * model does not have, chosen because nothing in the kext validates them.
 *
 * scrd (10), AppleSEPCredentialManager: its frame is not the generic one.
 * The receive handler (kext 0xfffffff00952a808) requires byte 0 == 10, takes
 * byte 1 as the tag, bits [31:16] as the byte length of a response it then
 * copies out of the endpoint's OOL out-buffer ("readFromSEP == msg.call.
 * length"), and stores the upper 32 bits as the SEP's status word. Requests
 * arrive the same way: {ep 10, tag, length of the body in the OOL in-buffer,
 * 0}; observed 36 bytes for cmd 10 and 40 for cmd 25.  The bounded v1/SCRD
 * positive-control replies below are derived from the ACM receiver checks in
 * docs/re/acm-scrd-response-contract.md.  All other shapes stay unanswered:
 * a status-only acknowledgement would hide an unmodelled protocol decision.
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
 * DARWIN_SKS_REQUEST_DEBUG=1 logs all AppleSEPKeyStore request bytes;
 * DARWIN_SKS_REQUEST_DEBUG_CODE=N limits byte dumps to one wire opcode.
 * Routine successful op19 traffic is sampled unless full debug is enabled.
 * Milestones (boot handshake, discovery, unknown opcodes) always log with
 * the "sep:" prefix.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "migration/vmstate.h"
#include "qemu/guest-random.h"
#include "crypto/hash.h"
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
#include "hw/arm/darwin_sks.h"

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
#define SEP_EP_CREDENTIALS 10
#define SEP_EP_KEYSTORE    18
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

// xART requests (AppleSEPXART, see the header). Only the three whose reply
// shape was read out of the kext are named; the rest are acknowledged blind.
#define XART_GET_EPOCH        0x15
#define XART_COMMIT_EPOCHS    0x16
#define XART_GET_FULL_EPOCHS  0x17
#define XART_STATUS_OK        0
#define XART_EPOCH_COUNT      8      // SEPEpoch::EPOCH_COUNT, cmp x2, 8 at 0x5a1db8
#define XART_EPOCH_SLOT_SIZE  4      // lsl x20, x8, 2 at 0x5a1e5c
#define XART_EPOCH_SIZE       2      // lsl x10, x10, 1 at 0x5a1d14
#define XART_GET_EPOCH_LEN    8      // stp x8(8), xzr at 0x5a1c14

/*
 * AppleSEPCredentialManager endpoint-10 requests observed on iOS 27.0 beta 8.
 * The receiver checks the response version, u16 header length and sequence at
 * 0xfffffff0095291e4..0xfffffff009529218; see
 * docs/re/acm-scrd-response-contract.md.
 * The service's logical FourCC is SCRD but its observed wire bytes at +0x1c
 * are `DRCS` (the little-endian representation).
 * These are deliberately not a general SCRD protocol implementation.
 */
#define SCRD_REQUEST_VERSION        1
#define SCRD_REQUEST_HEADER_LEN     0x1c
#define SCRD_REQUEST_TAG_OFF        0x1c
#define SCRD_REQUEST_COMMAND_OFF    0x20
#define SCRD_REQUEST_CMD10_LEN      36
#define SCRD_REQUEST_CMD25_LEN      40
#define SCRD_COMMAND_GET_STATE      10
#define SCRD_COMMAND_GET_ENV        25
#define SCRD_RESPONSE_VERSION       1
#define SCRD_RESPONSE_HEADER_LEN    12
#define SCRD_RESPONSE_CMD10_LEN     12
#define SCRD_RESPONSE_CMD25_LEN     13

/*
 * AppleSEPKeyStore IPC version 1.  The first live request is 0x5c bytes and
 * begins with header_body_size 0x48 (docs/re/sep-protocol.md).  In the kext's
 * decoded representation the 16-byte payload hash is omitted from the field
 * offsets, so the digest routine at 0xfffffff00956eab0 sees:
 *
 *   +0x10  ipc_version, 4 bytes     (wire +0x14)
 *   +0x14  time_msecs, 8 bytes      (wire +0x18)
 *   +0x1c  flags, 4 bytes           (wire +0x20)
 *   +0x20  id, 8 bytes              (wire +0x24)
 *   +0x28  v1 tail, 0x20 bytes      (wire +0x2c)
 *
 * The five updates are at 0xfffffff00956eb48..0x956ebc4, followed by the
 * payload update at 0xfffffff00956ebc8..0x956ebd8.  The first 16 digest bytes
 * are compared with wire +4 at 0xfffffff00956ec64..0x956ec70.  Version 1
 * therefore has a 0x4c-byte wire header and hashes [0x14, 0x4c) plus payload.
 */
#define SKS_IPC_V1_HEADER_BODY_SIZE  0x48
#define SKS_IPC_V1_HEADER_SIZE       0x4c
#define SKS_IPC_HASH_OFF             0x04
#define SKS_IPC_VERSION_OFF          0x14
#define SKS_IPC_TIME_OFF             0x18
#define SKS_IPC_FLAGS_OFF            0x20
#define SKS_IPC_ID_OFF               0x24
#define SKS_IPC_V1_TAIL_OFF          0x2c
#define SKS_IPC_V1_HASHED_SIZE       0x38
#define SKS_IPC_HASH_SIZE            0x10
#define SKS_IPC_VERSION_1            1
#define SKS_MSG_REPLY                0x80

/* iOS 27 operations established by the live trace and the call sites that
 * pass them to the IPC serializer: 0xfffffff00957ed30 passes 0x4d for
 * negotiation, and 0xfffffff00955eb84 passes 0x2a for set_env.  Byte 1 holds
 * this code plus the reply bit; byte 2 is a request ID. */
#define SKS_LOAD_KEYBAG 0x03
#define SKS_CHANGE_LOCK_STATE 0x04
#define SKS_UNWRAP_FILE_KEY 0x09
#define SKS_NEGOTIATE  0x4d
#define SKS_SET_ENV    0x2a
#define SKS_MIGRATE_MEDIA_KEY_TO_CLASS 0x0f
#define SKS_CHECK_CLASS 0x10
#define SKS_GET_DEVICE_STATE 0x19
#define SKS_NEW_MEDIA_KEY 0x31
#define SKS_UNWRAP_MEDIA_KEY 0x32

/* Load Keybag request shape observed at
 * /tmp/dvm/probe/PERSIST_DATA_BOOT1.stderr.log:977..988.  The public sep-sim
 * reference answers this operation with the deterministic handle 'BAG1'
 * (/tmp/dvm/sep-sim.c:745..769).  docs/re/sks-feasibility.md:182..201 warns
 * that its constants are hand-picked and do not prove an encrypted-volume
 * result, so this is an interoperability experiment, not modeled SEP secrecy
 * or persistent keybag state.  The native iOS 27 schema remains inferred from
 * that reference until the guest consumes this reply successfully. */
#define SKS_LOAD_KEYBAG_REQUEST_SIZE  0x6c
#define SKS_LOAD_KEYBAG_VARIANT_OFF   0x4c
#define SKS_LOAD_KEYBAG_CONTEXT_OFF   0x50
#define SKS_LOAD_KEYBAG_UUID_LEN_OFF  0x58
#define SKS_LOAD_KEYBAG_UUID_OFF      0x5c
#define SKS_LOAD_KEYBAG_VARIANT       0
#define SKS_LOAD_KEYBAG_UUID_SIZE     16
#define SKS_LOAD_KEYBAG_HANDLE        0x42414731u /* 'BAG1' */

/*
 * Change Lock State's iOS 27 wrapper is fcn.fffffff00957b058.  It seeds the
 * request inputs at 0xfffffff00957b0d4..0xfffffff00957b0e8 and invokes IPC
 * opcode 4 at 0xfffffff00957b0ec..0xfffffff00957b0f8.  Captures at
 * /tmp/dvm/probe/SKS_OP09_CAPTURE_1.stderr.log:707..737 and
 * /tmp/dvm/probe/SKS_OP04_AB_1.stderr.log:736 have the same body except for
 * the nonzero u64 at +0x50 (0xbe3138e73ca977e1 versus
 * 0x8e5143704e6a5385), proving it is an opaque per-boot handle rather than a
 * protocol constant.  Four boots also capture +0x58 as either zero or
 * 0xfffffe0b, including the immediate A-to-B sequence at
 * /tmp/dvm/probe/SKS_OP04_AB_2.stderr.log:717..749 and the same transition at
 * /tmp/dvm/probe/SKS_OP09_CAPTURE_1.stderr.log:984..993.  Those values are
 * treated as two qualified request variants; their sequence does not justify
 * inventing model-side session or handle-arithmetic state.  The success path
 * consumes a u32 output at
 * 0xfffffff00957b104..0xfffffff00957b10c and a u64 output at
 * 0xfffffff00957b110..0xfffffff00957b118.  Keep every stable captured field
 * strict until another native request shape is proven.
 */
#define SKS_CHANGE_LOCK_STATE_REQUEST_SIZE       0x6c
#define SKS_CHANGE_LOCK_STATE_SELECTOR_OFF       0x4c
#define SKS_CHANGE_LOCK_STATE_HANDLE_OFF         0x50
#define SKS_CHANGE_LOCK_STATE_STATE_ACTION_OFF   0x58
#define SKS_CHANGE_LOCK_STATE_FIXED_MAX_OFF      0x5c
#define SKS_CHANGE_LOCK_STATE_ZERO_TAIL_OFF       0x60
#define SKS_CHANGE_LOCK_STATE_ZERO_TAIL_SIZE      12
#define SKS_CHANGE_LOCK_STATE_REQUEST_SELECTOR    1
#define SKS_CHANGE_LOCK_STATE_ACTION_A             0
#define SKS_CHANGE_LOCK_STATE_ACTION_B             UINT32_C(0xfffffe0b)
#define SKS_CHANGE_LOCK_STATE_RESPONSE_SIZE       16
#define SKS_CHANGE_LOCK_STATE_RESPONSE_SELECTOR   0

/* fs_new_media_key's first output is the live CPX key: the bridge stores it at
 * descriptor +0/+8 (0xfffffff00957789c..0x95778b8), and APFS passes that
 * pointer/length to cpx_set_key_len and memcpy at
 * 0xfffffff00a8720e8..0xa872190.  AppleNVMeRequest requires exactly 0x40
 * bytes when the wrapped/composite bit is set
 * (0xfffffff00a139230..0xa13925c); 0x20 reaches its explicit
 * "Invalid key length for unwrapped key" branch at 0xfffffff00a1392ac. */
#define SKS_MEDIA_KEY_SIZE       64
#define SKS_FILE_KEY_SIZE        16

/* The third output is the opaque record which fs_new_media_key gives back to
 * APFS (0xfffffff009572d90..0x9572da8).  A 0x28-byte value is stored verbatim
 * in the guest's 80-byte keybag record: the write is logged at
 * /tmp/dvm/probe/SKS_KEYOP_V7A.serial.log:67 and the next boot sends the same
 * 0x28-byte record back in /tmp/dvm/probe/SKS_LIVEKEY_V9.stderr.log:6463..6473. */
#define SKS_WRAPPED_KEY_SIZE     40

/* fs_migrate_media_key_to_class request shape captured at
 * /tmp/dvm/probe/BOOTSTRAP_SEED_SKSDEBUG.stderr.log:579-595 and decoded in
 * docs/re/sks-op0f-media-key-migration.md.  The pure request parser and its
 * replayable constants live in darwin_sks.c; the record itself stays opaque. */
#define SKS_MIGRATE_RESPONSE_VARIANT   3

/* Later output-less calls use the same opcode and outer variant, but their
 * input is a 28-byte tagged APFS volume identity rather than the 40-byte
 * wrapped media-key record.  The exact class-4 User-volume request was
 * recovered from the live SEP OOL page through dart-sep while
 * ROOT_CCS_WAIT_TRACE3 was frozen before the strike-20 timeout.  Its first
 * eight record bytes are opaque and vary with the filesystem; the remaining
 * bytes are the User volume's stable qualified identity.  The class-3 call is
 * the corresponding Data-volume operation: APFS identifies that volume as
 * 61706673-7575-6964-0000-766F6C756D01 at
 * /tmp/dvm/probe/ROOT_SKS_OP0F_DUMP1.serial.log:467-469, and the same 20-byte
 * suffix is present in the live protected-object request captured at RAM
 * 0x1a3c8074 in /tmp/dvm/lsd-scan.pCCjEq/ram2g.bin.  The full request at
 * /tmp/dvm/probe/ROOT_SKS_OP0F_DATA_POS1.stderr.log:4117924-4117936 proves
 * that the Data identity is record kind 4, target class 3.  It is the first
 * unanswered request there and alone begins the selector 7/142 timeout at
 * serial lines 1401-1418.
 * Pair each observed class with its exact volume identity; do not accept an
 * arbitrary tag or class/volume combination. */
#define SKS_CHECK_CLASS_RESPONSE_SCALAR0_OFF 56
#define SKS_CHECK_CLASS_RESPONSE_SCALAR1_OFF 60

/*
 * Opcode 0x09 is the filesystem file-key unwrap used by APFS.  Its only
 * observed iOS 27 request is the 0x20-byte native descriptor selected at
 * 0xfffffff0081085b0.  SKS_OP09_CAPTURE_1.stderr.log records 52
 * byte-identical payload shapes; the initial mount requests use class 4.
 * Later userspace emits the same request with class 3 as the first unanswered
 * SKS message after Early Boot Complete
 * (/tmp/dvm/probe/PERSIST_DCP_OP09_FIXED_3.stderr.log:698).  The same class-3
 * boundary is independently present in the storage-only cold boot at
 * /tmp/dvm/probe/SKS_OP09_COMPLETE_2.stderr.log:511.  The crash-recovered
 * persistent-Data control ROOT_SKS_TAGGED_POS1 then completed 714 qualified
 * class-3/class-4 unwraps before the same exact request shape requested class
 * 2 at stderr line 6183; its rejection is followed by the serial timeout
 * sequence at lines 816-824.  After the display power-on path completed and
 * userspace data migration reached dir-stats key 50987, the same exact shape
 * requested class 17 at
 * /tmp/dvm/probe/ROOT_DCP_WAKE_UI1.stderr.log:21307.  That unanswered request
 * is immediately followed by PID 53's selector 17/35/7 timeout strikes at
 * /tmp/dvm/probe/ROOT_DCP_WAKE_UI1.serial.log:1300-1318.  The positive-control
 * reboot accepted class 17 and continued until this same exact request asked
 * for class 1 at
 * /tmp/dvm/probe/ROOT_SKS_OP09_CLASS17_UI2.stderr.log:138895; its rejection
 * alone starts the selector 10/7 timeout sequence at serial lines 1330-1331.
 * Accept these five observed protection classes while keeping every
 * other invariant strict.  ROOT_SKS_LATE_HOST2 later emitted a 0x94-byte
 * form after two successful tagged User-volume migrations.  Its live OOL
 * page contains the same fields followed by a 40-byte wrapped record and
 * selector 2; rejecting it without a reply caused the sole first panic at
 * serial line 2054.  The request was recovered from DART-translated DVA
 * 0x1000004c000 at PA 0x1001a478000 after the panic, rather than inferred
 * from an absent breakpoint.
 * DISPLAY_SMP6_WARM2 cold-boots a completed-migration disk and adds a sixth
 * observed class, 13, only in the 108-byte empty-record shape. Its endpoint-18
 * request at DVA 0x1000000c000 (PA 0x1001a3d8000) has class at +0x60,
 * zero record length at +0x64 and selector 2 at +0x68. Rejecting this request
 * at stderr line 5782 leaves SKS and preference services waiting. The exact
 * capture and malformed variants are covered by test-darwin-sks-migrate.
 *
 * The selector-2 codec at 0xfffffff0095619e8..0x9561a4c calls the blob helper
 * at 0xfffffff00957f830 three times, then the scalar helper at
 * 0xfffffff00957f7d8.  The generated bridge at 0xfffffff00957b4c0 publishes
 * the first two blob pointer/length pairs and the trailing scalar at
 * 0xfffffff00957b5fc..0x957b668.  The live class-4 entry at runtime
 * 0xfffffff029547ffc receives capacities 64 and 16 bytes for the raw key and IV
 * respectively
 * (/tmp/dvm/FEXT_LLDB_1C.lldb.log:25..50).  Returning only { selector, scalar }
 * made that bridge fail with 0xe00002bc at runtime 0xfffffff02957b5f0, which
 * propagated directly to APFS at 0xfffffff02a95d9d8 (same log:66..119).
 * A 124-byte response was then observed consuming the third empty blob before
 * reaching EOF at the scalar helper and returning -13
 * (/tmp/dvm/SKS_OP09_DECODE_1.lldb.log:876..924,982..1060).
 */
#define SKS_UNWRAP_FILE_KEY_RESPONSE_SELECTOR   2
#define SKS_UNWRAP_FILE_KEY_RESPONSE_THIRD_BLOB_SIZE 0
#define SKS_UNWRAP_FILE_KEY_RESPONSE_SCALAR     0
#define SKS_UNWRAP_FILE_KEY_RESPONSE_PAYLOAD_SIZE 52

/*
 * The op19 wrapper at 0xfffffff00957c36c/0xfffffff00957c458 emits a
 * 0x14-byte payload.  Its context and signed state argument vary (live
 * captures include -6 and 'BAG1'), while selector 0 and the trailing zero
 * are invariant.  The generated reply's normal-success arm is selector zero
 * followed by a length-prefixed DER blob.  The direct consumer at
 * 0xfffffff00956e6ac accepts decoded `bh` values -6 and -10.  Its parser
 * descriptor uses the literal DER UTF8String `bh`, and the load/store at
 * 0xfffffff0095812f0..0x95812f8 places that INTEGER at parsed-record offset
 * +0x2a. Each key/value pair needs a SEQUENCE inside the outer SET. The
 * previous nine-byte record lacked that wrapper and decoded as all zeros.
 * darwin_sks_build_unlocked_device_state supplies the guest-validated
 * 20-byte DER record with bh=-6 and ss=4 (first unlock has occurred).
 */
#define SKS_GET_DEVICE_STATE_REQUEST_SIZE       0x60
#define SKS_GET_DEVICE_STATE_SELECTOR_OFF       0x4c
#define SKS_GET_DEVICE_STATE_CONTEXT_OFF        0x50
#define SKS_GET_DEVICE_STATE_STATE_OFF          0x58
#define SKS_GET_DEVICE_STATE_TRAILING_ZERO_OFF  0x5c
#define SKS_GET_DEVICE_STATE_REQUEST_SELECTOR   0
#define SKS_GET_DEVICE_STATE_RESPONSE_PAYLOAD_SIZE \
    DARWIN_SKS_DEVICE_STATE_PAYLOAD_SIZE

static const uint8_t sks_media_key[SKS_MEDIA_KEY_SIZE] = {
    0x44, 0x56, 0x4d, 0x2d, 0x53, 0x4b, 0x53, 0x2d,
    0x4d, 0x45, 0x44, 0x49, 0x41, 0x2d, 0x4b, 0x45,
    0x59, 0x2d, 0x30, 0x31, 0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
};

static const uint8_t sks_wrapped_key[SKS_WRAPPED_KEY_SIZE] = {
    0x44, 0x56, 0x4d, 0x2d, 0x53, 0x4b, 0x53, 0x2d,
    0x57, 0x52, 0x41, 0x50, 0x50, 0x45, 0x44, 0x2d,
    0x4b, 0x45, 0x59, 0x2d, 0x30, 0x31, 0x00, 0x01,
    0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
};

/* The 0x1c-byte tagged object in the long op10 request contains an opaque,
 * per-volume UUID at +0x76.  Data and User requests prove that it cannot be
 * matched as a constant: DATA_SEED_VISIBLE.stderr.log:1573..1582 carries
 * 61706673-7575-6964-0001-766f6c756d01, while
 * SKS_OP10_CAPTURE.stderr.log:710..719 carries
 * 61706673-7575-6964-0002-766f6c756d02.  The surrounding u16 valid marker
 * and six-byte zero tail are invariant and remain validated. */

static const uint8_t sks_change_lock_state_zero_tail[
    SKS_CHANGE_LOCK_STATE_ZERO_TAIL_SIZE] = { 0 };

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
/*
 * An advertised but unanswered sks endpoint is fatal: AppleSEPKeyStore sends
 * its first IPC request the moment `sep-endpoint,sks` appears, re-sends it
 * every ~5 s logging
 *
 *   "AppleSEPKeyStore":pid:0,:3466: sks timeout strike N
 *
 * (kext AppleSEPKeyStore 0xfffffff00954c118) and at strike 20 --
 * `cmp w21, 0x14` / `b.ge` at 0xfffffff00954c0b4 -- hands over to
 * AppleSEPManager, which panics the kernel outright:
 *
 *   panic(cpu 0 caller 0xfffffff0295a6e4c): AppleSEPManager panic for
 *     "AppleSEPKeyStore": sks request timeout
 *   Firmware type: UNKNOWN SEPOS   SEP state: 8   PM state: 2
 *
 * Measured both ways on the system-volume boot (docs/re/seputil-data-
 * protection.md): advertising sks, the boot dies at that panic 16,720 serial
 * lines in, part way through mount-phase-2; not advertising it, the same boot
 * runs to 42,018 lines with zero panics, finishes mount-phase-2 and reaches
 * launchd's `keybag` boot task. The restore-ramdisk boot is only two strikes
 * short of the same panic inside a 120 s probe.
 *
 * This model answers the request captured in docs/re/sep-protocol.md with an
 * AppleKeyStore ipc.c header of its own.  The
 * kext logs "negotiated to ipc header theirs:v%llu, ours:v%u -> negotiated:
 * v%llu" (0xfffffff00954cd10) after computing
 * `negotiated = theirs < 2 ? theirs : ours` (0xfffffff00954ccdc).  It was
 * promoted to the default only after op31 and op32 let the guest mount its
 * encrypted volume after a reboot
 * (/tmp/dvm/probe/SKS_REMOUNT_V10.serial.log:476..500).
 */
static const char *const sep_default_eps = "cntl,scrd,sks,xars,xarm";

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
    bool sks_request_debug;
    bool sks_request_debug_code_set;
    uint8_t sks_request_debug_code;
    uint64_t sks_op19_requests;
    bool sks_log_current;
};

/* ---------------- frame helpers ---------------- */

static inline uint8_t frame_ep(uint64_t m)     { return m & 0xff; }
static inline uint8_t frame_tag(uint64_t m)    { return (m >> 8) & 0xff; }
static inline uint8_t frame_op(uint64_t m)     { return (m >> 16) & 0xff; }
static inline uint8_t frame_param(uint64_t m)  { return (m >> 24) & 0xff; }
static inline uint32_t frame_data(uint64_t m)  { return m >> 32; }
static inline uint8_t sks_code(uint64_t m)     { return frame_tag(m) & 0x7f; }

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

static bool sep_sks_hash_response(DarwinSEPState *s, uint8_t *buf,
                                  uint32_t size)
{
    struct iovec iov[2];
    g_autofree uint8_t *digest = NULL;
    size_t digest_len = 0;
    Error *local_err = NULL;

    if (size < SKS_IPC_V1_HEADER_SIZE) {
        return false;
    }

    iov[0].iov_base = buf + SKS_IPC_VERSION_OFF;
    iov[0].iov_len = SKS_IPC_V1_HASHED_SIZE;
    iov[1].iov_base = buf + SKS_IPC_V1_HEADER_SIZE;
    iov[1].iov_len = size - SKS_IPC_V1_HEADER_SIZE;
    if (qcrypto_hash_bytesv(QCRYPTO_HASH_ALGO_SHA256, iov, ARRAY_SIZE(iov),
                            &digest, &digest_len, &local_err) < 0 ||
        digest_len < SKS_IPC_HASH_SIZE) {
        fprintf(stderr, "sep(%s): sks SHA-256 failed: %s\n", s->role,
                local_err ? error_get_pretty(local_err) : "short digest");
        error_free(local_err);
        return false;
    }
    memcpy(buf + SKS_IPC_HASH_OFF, digest, SKS_IPC_HASH_SIZE);
    return true;
}

static bool sep_sks_init_response(DarwinSEPState *s, const uint8_t *request,
                                  uint32_t request_size, uint8_t *response,
                                  uint32_t response_size)
{
    uint32_t header_body_size;
    uint32_t ipc_version;

    if (request_size < SKS_IPC_V1_HEADER_SIZE ||
        response_size < SKS_IPC_V1_HEADER_SIZE) {
        fprintf(stderr, "sep(%s): sks IPC message is shorter than the v1 "
                "header (request 0x%x, response 0x%x)\n", s->role,
                request_size, response_size);
        return false;
    }
    header_body_size = ldl_le_p(request);
    ipc_version = ldl_le_p(request + SKS_IPC_VERSION_OFF);
    if (header_body_size != SKS_IPC_V1_HEADER_BODY_SIZE ||
        ipc_version != SKS_IPC_VERSION_1) {
        fprintf(stderr, "sep(%s): sks unsupported IPC header body 0x%x "
                "version %u; no reply\n", s->role, header_body_size,
                ipc_version);
        return false;
    }

    memset(response, 0, response_size);
    stl_le_p(response, SKS_IPC_V1_HEADER_BODY_SIZE);
    stl_le_p(response + SKS_IPC_VERSION_OFF, SKS_IPC_VERSION_1);

    /* Preserve the request identity fields used to match an IPC response.
     * Their v1 offsets are the fields hashed at 0xfffffff00956eb5c..
     * 0xfffffff00956ebc4.  Flags stay zero, as in the captured request. */
    memcpy(response + SKS_IPC_TIME_OFF, request + SKS_IPC_TIME_OFF, 8);
    memcpy(response + SKS_IPC_ID_OFF, request + SKS_IPC_ID_OFF, 8);
    memcpy(response + SKS_IPC_V1_TAIL_OFF,
           request + SKS_IPC_V1_TAIL_OFF,
           SKS_IPC_V1_HEADER_SIZE - SKS_IPC_V1_TAIL_OFF);
    return true;
}

static bool sep_sks_validate_load_keybag_request(DarwinSEPState *s,
                                                  const uint8_t *request,
                                                  uint32_t request_size)
{
    uint32_t header_body_size = 0;
    uint32_t ipc_version = 0;
    uint32_t variant = UINT32_MAX;
    uint32_t uuid_len = 0;
    uint64_t context = 0;

    if (request_size >= SKS_IPC_V1_HEADER_SIZE) {
        header_body_size = ldl_le_p(request);
        ipc_version = ldl_le_p(request + SKS_IPC_VERSION_OFF);
    }
    if (request_size >= SKS_LOAD_KEYBAG_UUID_OFF) {
        variant = ldl_le_p(request + SKS_LOAD_KEYBAG_VARIANT_OFF);
        context = ldq_le_p(request + SKS_LOAD_KEYBAG_CONTEXT_OFF);
        uuid_len = ldl_le_p(request + SKS_LOAD_KEYBAG_UUID_LEN_OFF);
    }

    /* Only the live-captured variant-0 request is understood.  Context and
     * UUID are deliberately opaque/dynamic, but every established framing
     * and length field must match before returning a fabricated handle. */
    if (request_size != SKS_LOAD_KEYBAG_REQUEST_SIZE ||
        header_body_size != SKS_IPC_V1_HEADER_BODY_SIZE ||
        ipc_version != SKS_IPC_VERSION_1 ||
        variant != SKS_LOAD_KEYBAG_VARIANT ||
        uuid_len != SKS_LOAD_KEYBAG_UUID_SIZE ||
        SKS_LOAD_KEYBAG_UUID_OFF + uuid_len != request_size) {
        fprintf(stderr, "sep(%s): sks op03 rejected unsupported load-keybag "
                "shape: request %u header 0x%x version %u variant %u UUID "
                "length %u; no reply\n", s->role, request_size,
                header_body_size, ipc_version, variant, uuid_len);
        return false;
    }

    fprintf(stderr, "sep(%s): sks op03 accepted request length %u variant "
            "%u context 0x%016" PRIx64 " UUID "
            "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
            "%02x%02x%02x%02x%02x%02x\n", s->role, request_size,
            variant, context,
            request[SKS_LOAD_KEYBAG_UUID_OFF + 0],
            request[SKS_LOAD_KEYBAG_UUID_OFF + 1],
            request[SKS_LOAD_KEYBAG_UUID_OFF + 2],
            request[SKS_LOAD_KEYBAG_UUID_OFF + 3],
            request[SKS_LOAD_KEYBAG_UUID_OFF + 4],
            request[SKS_LOAD_KEYBAG_UUID_OFF + 5],
            request[SKS_LOAD_KEYBAG_UUID_OFF + 6],
            request[SKS_LOAD_KEYBAG_UUID_OFF + 7],
            request[SKS_LOAD_KEYBAG_UUID_OFF + 8],
            request[SKS_LOAD_KEYBAG_UUID_OFF + 9],
            request[SKS_LOAD_KEYBAG_UUID_OFF + 10],
            request[SKS_LOAD_KEYBAG_UUID_OFF + 11],
            request[SKS_LOAD_KEYBAG_UUID_OFF + 12],
            request[SKS_LOAD_KEYBAG_UUID_OFF + 13],
            request[SKS_LOAD_KEYBAG_UUID_OFF + 14],
            request[SKS_LOAD_KEYBAG_UUID_OFF + 15]);
    return true;
}

static bool sep_sks_validate_change_lock_state_request(
    DarwinSEPState *s, const uint8_t *request, uint32_t request_size)
{
    uint32_t header_body_size = 0;
    uint32_t ipc_version = 0;
    uint32_t selector = UINT32_MAX;
    uint64_t handle = 0;
    uint32_t state_action = UINT32_MAX;
    uint32_t fixed_max = 0;

    if (request_size >= SKS_IPC_V1_HEADER_SIZE) {
        header_body_size = ldl_le_p(request);
        ipc_version = ldl_le_p(request + SKS_IPC_VERSION_OFF);
    }
    if (request_size == SKS_CHANGE_LOCK_STATE_REQUEST_SIZE) {
        selector = ldl_le_p(request + SKS_CHANGE_LOCK_STATE_SELECTOR_OFF);
        handle = ldq_le_p(request + SKS_CHANGE_LOCK_STATE_HANDLE_OFF);
        state_action =
            ldl_le_p(request + SKS_CHANGE_LOCK_STATE_STATE_ACTION_OFF);
        fixed_max = ldl_le_p(request + SKS_CHANGE_LOCK_STATE_FIXED_MAX_OFF);
    }

    if (request_size != SKS_CHANGE_LOCK_STATE_REQUEST_SIZE ||
        header_body_size != SKS_IPC_V1_HEADER_BODY_SIZE ||
        ipc_version != SKS_IPC_VERSION_1 ||
        selector != SKS_CHANGE_LOCK_STATE_REQUEST_SELECTOR ||
        handle == 0 ||
        (state_action != SKS_CHANGE_LOCK_STATE_ACTION_A &&
         state_action != SKS_CHANGE_LOCK_STATE_ACTION_B) ||
        fixed_max != UINT32_MAX ||
        memcmp(request + SKS_CHANGE_LOCK_STATE_ZERO_TAIL_OFF,
               sks_change_lock_state_zero_tail,
               sizeof(sks_change_lock_state_zero_tail))) {
        fprintf(stderr, "sep(%s): sks op04 rejected unsupported change-lock-"
                "state shape: request %u header 0x%x version %u selector %u "
                "handle 0x%016" PRIx64 " state/action 0x%x max 0x%x; no "
                "reply\n",
                s->role, request_size, header_body_size, ipc_version,
                selector, handle, state_action, fixed_max);
        return false;
    }

    fprintf(stderr, "sep(%s): sks op04 accepted request length %u selector "
            "%u opaque handle 0x%016" PRIx64 " state/action 0x%x\n",
            s->role, request_size, selector, handle, state_action);
    return true;
}

static bool sep_sks_validate_migrate_request(DarwinSEPState *s,
                                             const uint8_t *request,
                                             uint32_t request_size,
                                             uint32_t *response_class)
{
    DarwinSKSMigrateRequest parsed;

    /* Do not turn another union variant or record shape into fake success.
     * Both accepted forms are exact live captures; the opaque record bytes
     * are deliberately neither interpreted nor persisted. */
    if (!darwin_sks_parse_migrate_request(request, request_size, &parsed)) {
        fprintf(stderr, "sep(%s): sks op0f rejected unsupported migration "
                "shape: request %u header 0x%x version %u variant %u "
                "class %u record length %u output capacity %u output "
                "scalar %u; no reply\n",
                s->role, request_size, parsed.header_body_size,
                parsed.ipc_version, parsed.variant, parsed.target_class,
                parsed.record_len, parsed.output_cap, parsed.output_scalar);
        return false;
    }

    *response_class = parsed.target_class;
    if (parsed.shape == DARWIN_SKS_MIGRATE_WRAPPED_KEY) {
        fprintf(stderr, "sep(%s): sks op0f accepted wrapped-key request "
                "length %u variant %u class %u, opaque record length %u, "
                "output capacity %u, output scalar %u\n",
                s->role, request_size, parsed.variant, parsed.target_class,
                parsed.record_len, parsed.output_cap, parsed.output_scalar);
    } else {
        fprintf(stderr, "sep(%s): sks op0f accepted tagged-volume request "
                "length %u variant %u record-kind %u class %u, opaque "
                "record length %u, no output tail\n",
                s->role, request_size, parsed.variant, parsed.record_kind,
                parsed.target_class, parsed.record_len);
    }
    return true;
}

static bool sep_sks_validate_check_class_request(DarwinSEPState *s,
                                                const uint8_t *request,
                                                uint32_t request_size,
                                                uint32_t *requested_class,
                                                bool *echo_class)
{
    DarwinSKSCheckClassRequest parsed = { 0 };

    if (!darwin_sks_parse_check_class_request(request, request_size, &parsed)) {
        fprintf(stderr, "sep(%s): sks op10 rejected unsupported check-class "
                "shape: request %u header 0x%x version %u variant %u class "
                "%u; no reply\n", s->role, request_size, parsed.header_body_size,
                parsed.ipc_version, parsed.variant, parsed.protection_class);
        return false;
    }
    *requested_class = parsed.protection_class;
    *echo_class = parsed.echo_class;
    fprintf(stderr, "sep(%s): sks op10 accepted %s request length %u "
            "variant %u class %u\n", s->role,
            parsed.echo_class ? "protected-object" : "availability",
            request_size, parsed.variant, parsed.protection_class);
    return true;
}

static bool sep_sks_validate_unwrap_file_key_request(
    DarwinSEPState *s, const uint8_t *request, uint32_t request_size)
{
    DarwinSKSUnwrapFileKeyRequest parsed;

    if (!darwin_sks_parse_unwrap_file_key_request(request, request_size,
                                                   &parsed)) {
        fprintf(stderr, "sep(%s): sks op09 rejected unsupported filesystem "
                "unwrap shape: request %u header 0x%x version %u variant %u "
                "class %u output selector %u; no reply\n", s->role,
                request_size, parsed.header_body_size, parsed.ipc_version,
                parsed.variant, parsed.protection_class,
                parsed.output_selector);
        return false;
    }

    fprintf(stderr, "sep(%s): sks op09 accepted %s filesystem unwrap request "
            "length %u variant %u class %u record length %u output selector "
            "%u\n", s->role,
            parsed.shape == DARWIN_SKS_UNWRAP_FILE_KEY_WRAPPED_RECORD ?
                "wrapped-record" : "empty-record",
            request_size, parsed.variant, parsed.protection_class,
            parsed.record_len, parsed.output_selector);
    return true;
}

static bool sep_sks_validate_get_device_state_request(
    DarwinSEPState *s, const uint8_t *request, uint32_t request_size)
{
    uint32_t header_body_size = 0;
    uint32_t ipc_version = 0;
    uint32_t selector = UINT32_MAX;
    uint64_t context = 0;
    int32_t state = 0;
    uint32_t trailing = UINT32_MAX;

    if (request_size >= SKS_IPC_V1_HEADER_SIZE) {
        header_body_size = ldl_le_p(request);
        ipc_version = ldl_le_p(request + SKS_IPC_VERSION_OFF);
    }
    if (request_size == SKS_GET_DEVICE_STATE_REQUEST_SIZE) {
        selector = ldl_le_p(request + SKS_GET_DEVICE_STATE_SELECTOR_OFF);
        context = ldq_le_p(request + SKS_GET_DEVICE_STATE_CONTEXT_OFF);
        state = (int32_t)ldl_le_p(request +
                                  SKS_GET_DEVICE_STATE_STATE_OFF);
        trailing =
            ldl_le_p(request + SKS_GET_DEVICE_STATE_TRAILING_ZERO_OFF);
    }

    /*
     * The context and state are opaque inputs to the generated wrapper, not
     * framing constants.  Strictness applies to the observed v1 union shape:
     * exact length, request selector zero, and trailing zero.
     */
    if (request_size != SKS_GET_DEVICE_STATE_REQUEST_SIZE ||
        header_body_size != SKS_IPC_V1_HEADER_BODY_SIZE ||
        ipc_version != SKS_IPC_VERSION_1 ||
        selector != SKS_GET_DEVICE_STATE_REQUEST_SELECTOR || trailing != 0) {
        fprintf(stderr, "sep(%s): sks op19 rejected unsupported device-state "
                "shape: request %u header 0x%x version %u selector %u "
                "trailing 0x%x; no reply\n", s->role, request_size,
                header_body_size, ipc_version, selector, trailing);
        return false;
    }

    if (s->sks_log_current) {
        fprintf(stderr, "sep(%s): sks op19 request #%" PRIu64
                " accepted length %u selector %u opaque context "
                "0x%016" PRIx64 " state %" PRId32 "\n",
                s->role, s->sks_op19_requests, request_size, selector,
                context, state);
    }
    return true;
}

static bool sep_sks_send_response(DarwinSEPState *s, uint64_t m,
                                  uint8_t *response, uint32_t response_size)
{
    SEPEndpointState *e = &s->ep[SEP_EP_KEYSTORE];

    if (response_size > e->ool_out_size || !e->ool_out_addr) {
        fprintf(stderr, "sep(%s): sks response 0x%x does not fit OOL out "
                "buffer at dva 0x%" PRIx64 " size 0x%x; no reply\n",
                s->role, response_size, e->ool_out_addr, e->ool_out_size);
        return false;
    }
    if (!sep_sks_hash_response(s, response, response_size) ||
        !sep_dma(s, e->ool_out_addr, response, response_size, true)) {
        return false;
    }

    if (s->sks_log_current) {
        fprintf(stderr, "sep(%s): sks code 0x%02x id %u replied with %u-byte "
                "SHA-256-authenticated IPC v1 message\n", s->role,
                sks_code(m), frame_op(m), response_size);
    }
    sep_send(s, SEP_EP_KEYSTORE, frame_tag(m) | SKS_MSG_REPLY, frame_op(m),
             0, response_size << 16);
    return true;
}

static void sep_handle_sks(DarwinSEPState *s, uint64_t m)
{
    SEPEndpointState *e = &s->ep[SEP_EP_KEYSTORE];
    uint32_t request_size = frame_data(m) >> 16;
    g_autofree uint8_t *request = NULL;
    g_autofree uint8_t *response = NULL;
    uint8_t *payload;
    uint32_t payload_size;
    uint32_t check_class = 0;
    uint32_t migrate_class = 0;
    bool check_class_echo = false;
    bool request_debug;
    const char *name;

    if (!request_size || request_size > e->ool_in_size || !e->ool_in_addr) {
        fprintf(stderr, "sep(%s): sks code 0x%02x id %u has invalid OOL in "
                "size 0x%x (buffer 0x%x); no reply\n", s->role, sks_code(m),
                frame_op(m), request_size, e->ool_in_size);
        return;
    }
    request = g_malloc(request_size);
    if (!sep_dma(s, e->ool_in_addr, request, request_size, false)) {
        return;
    }

    request_debug = s->debug || s->sks_request_debug ||
                    (s->sks_request_debug_code_set &&
                     s->sks_request_debug_code == sks_code(m));

    /*
     * A normal boot can issue hundreds of thousands of successful op19
     * device-state queries.  Logging every accepted request and reply once
     * produced a 280 MB stderr transcript and materially slowed the run.
     * Keep every malformed/error report, every non-op19 operation, and every
     * explicitly requested debug dump.  For routine successful op19 traffic,
     * log enough samples to prove continued progress without turning stderr
     * into part of the workload.
     */
    s->sks_log_current = true;
    if (sks_code(m) == SKS_GET_DEVICE_STATE) {
        uint64_t n = ++s->sks_op19_requests;

        s->sks_log_current = request_debug || n <= 8 ||
                             (n & (n - 1)) == 0 || n % 10000 == 0;
    }

    if (request_debug) {
        uint32_t n = MIN(request_size, SKS_IPC_V1_HEADER_SIZE + 96);
        fprintf(stderr, "sep(%s): sks code 0x%02x id %u request bytes:",
                s->role, sks_code(m), frame_op(m));
        for (uint32_t i = 0; i < n; i++) {
            if ((i & 15) == 0) {
                fprintf(stderr, "\n  %04x:", i);
            }
            fprintf(stderr, " %02x", request[i]);
        }
        fprintf(stderr, "\n");
    }

    switch (sks_code(m)) {
    case SKS_LOAD_KEYBAG:
        if (!sep_sks_validate_load_keybag_request(s, request,
                                                  request_size)) {
            return;
        }
        name = "load keybag (deterministic interoperability handle)";
        payload_size = 2 * sizeof(uint32_t);
        break;
    case SKS_CHANGE_LOCK_STATE:
        if (!sep_sks_validate_change_lock_state_request(s, request,
                                                         request_size)) {
            return;
        }
        name = "change lock state (captured zero-output contract)";
        payload_size = SKS_CHANGE_LOCK_STATE_RESPONSE_SIZE;
        break;
    case SKS_UNWRAP_FILE_KEY:
        /*
         * The codec at 0xfffffff0095619e8..0x9561a4c consumes a selector-2
         * union with three length-prefixed blobs and a scalar.  The bridge
         * publishes the first two blob pairs at
         * 0xfffffff00957b5fc..0x957b668.
         */
        if (!sep_sks_validate_unwrap_file_key_request(s, request,
                                                       request_size)) {
            return;
        }
        name = "unwrap filesystem file key (fake-key mode)";
        payload_size = SKS_UNWRAP_FILE_KEY_RESPONSE_PAYLOAD_SIZE;
        break;
    case SKS_NEGOTIATE:
        name = "negotiate IPC version";
        payload_size = 16;
        break;
    case SKS_SET_ENV:
        /* The first probe named the caller by panicking with "set_env failed"
         * at AppleKeyStore.cpp:6790 after receiving a wrong-sized reply
         * (/tmp/dvm/probe/SKS_V1.serial.log:227). */
        name = "set environment";
        payload_size = 4;
        break;
    case SKS_MIGRATE_MEDIA_KEY_TO_CLASS:
        /* The request's variant-3 decoder publishes one pointer/length output
         * pair (AppleSEPKeyStore 0xfffffff00957bbcc..0x957bc60).  Reject any
         * unobserved input shape rather than returning a misleading success. */
        if (!sep_sks_validate_migrate_request(s, request, request_size,
                                              &migrate_class)) {
            return;
        }
        name = "migrate media key to class (fake-key mode)";
        payload_size = 4 + 4 + SKS_WRAPPED_KEY_SIZE + 4;
        break;
    case SKS_CHECK_CLASS:
        /* fs_check_class emits union selector 2 at wire payload +0x00
         * (/tmp/dvm/probe/SKS_REMOUNT_V10.stderr.log:1912..1919).  Its
         * variant-2 reply decoder at 0xfffffff009562ee8..0x956302c consumes
         * five length-prefixed blobs and two u32 scalars after the selector.
         * Runtime mask controls establish that outputs 0 and 1 must carry
         * 16-byte file and IV keys.  The protected-object form additionally
         * requires both trailing scalars to echo its requested class. */
        if (!sep_sks_validate_check_class_request(s, request, request_size,
                                                  &check_class,
                                                  &check_class_echo)) {
            return;
        }
        name = "check class available (fake-key mode)";
        payload_size = 4 + 5 * 4 + 2 * SKS_FILE_KEY_SIZE + 2 * 4;
        break;
    case SKS_GET_DEVICE_STATE:
        /*
         * 0xfffffff00957c36c/0xfffffff00957c458 emit the observed wrapper
         * shape.  Unknown selector or trailing data remains fail-closed.
         */
        if (!sep_sks_validate_get_device_state_request(s, request,
                                                        request_size)) {
            return;
        }
        name = "get device state (minimal DER normal-success reply)";
        payload_size = SKS_GET_DEVICE_STATE_RESPONSE_PAYLOAD_SIZE;
        break;
    case SKS_NEW_MEDIA_KEY:
        /* The generated IPC decoder at 0xfffffff00957d6f8..0x957d7a8
         * consumes three length-prefixed blobs with a scalar between the
         * second and third.  fs_new_media_key reaches that decoder through
         * 0xfffffff009572d64 -> 0xfffffff009577870 -> 0xfffffff00957d6e4.
         * The values are deliberately stable constants: this model has no
         * SEP secret, and AppleSEPKeyStore treats these fields as opaque. */
        name = "new media key (fake-key mode)";
        payload_size = 4 + 4 + SKS_MEDIA_KEY_SIZE + 4 + 4 + 4 +
                       SKS_WRAPPED_KEY_SIZE;
        break;
    case SKS_UNWRAP_MEDIA_KEY:
        /* fs_unwrap_media_key_from_uid reaches the 0x32 serializer through
         * 0xfffffff009572e24 -> 0xfffffff009577900 ->
         * 0xfffffff00957d974.  Its decoder publishes two blobs and a scalar
         * at 0xfffffff00957da90..0x957db00. */
        name = "unwrap media key (fake-key mode)";
        payload_size = 4 + 4 + SKS_MEDIA_KEY_SIZE + 4 + 4;
        break;
    default:
        /* A status-only success is a logged no-op, not a claim that the
         * operation's side effects are implemented.  It lets the guest name
         * the next missing operation without fabricating a payload shape. */
        name = "unknown status-only no-op";
        payload_size = 4;
        break;
    }

    response = g_malloc(SKS_IPC_V1_HEADER_SIZE + payload_size);
    if (!sep_sks_init_response(s, request, request_size, response,
                               SKS_IPC_V1_HEADER_SIZE + payload_size)) {
        return;
    }
    payload = response + SKS_IPC_V1_HEADER_SIZE;

    /* Negotiation payload is established by the live request at
     * /tmp/dvm/probe/SKS_CTL.stderr.log:374-381: status zero followed by
     * offered version one.  Every unknown operation returns only status zero. */
    switch (sks_code(m)) {
    case SKS_LOAD_KEYBAG:
        stl_le_p(payload, 0);
        stl_le_p(payload + sizeof(uint32_t), SKS_LOAD_KEYBAG_HANDLE);
        fprintf(stderr, "sep(%s): sks op03 returns deterministic keybag "
                "handle 0x%08x ('BAG1'); no SEP secret or persistent keybag "
                "state is modeled\n", s->role, SKS_LOAD_KEYBAG_HANDLE);
        break;
    case SKS_CHANGE_LOCK_STATE:
        stl_le_p(payload, SKS_CHANGE_LOCK_STATE_RESPONSE_SELECTOR);
        stl_le_p(payload + sizeof(uint32_t), 0);
        stq_le_p(payload + 2 * sizeof(uint32_t), 0);
        fprintf(stderr, "sep(%s): sks op04 returns selector %u, u32 output "
                "0, and u64 output 0 in a %u-byte IPC v1 reply\n", s->role,
                SKS_CHANGE_LOCK_STATE_RESPONSE_SELECTOR,
                SKS_IPC_V1_HEADER_SIZE +
                    SKS_CHANGE_LOCK_STATE_RESPONSE_SIZE);
        break;
    case SKS_UNWRAP_FILE_KEY: {
        uint32_t off = 0;

        stl_le_p(payload + off, SKS_UNWRAP_FILE_KEY_RESPONSE_SELECTOR);
        off += sizeof(uint32_t);
        stl_le_p(payload + off, SKS_FILE_KEY_SIZE);
        off += sizeof(uint32_t);
        memcpy(payload + off, sks_media_key, SKS_FILE_KEY_SIZE);
        off += SKS_FILE_KEY_SIZE;
        stl_le_p(payload + off, SKS_FILE_KEY_SIZE);
        off += sizeof(uint32_t);
        /*
         * Keep the IV deterministic and distinct from the file key by using
         * the next 16 bytes of the established stable fake-key material.
         */
        memcpy(payload + off, sks_media_key + SKS_FILE_KEY_SIZE,
               SKS_FILE_KEY_SIZE);
        off += SKS_FILE_KEY_SIZE;
        stl_le_p(payload + off,
                 SKS_UNWRAP_FILE_KEY_RESPONSE_THIRD_BLOB_SIZE);
        off += sizeof(uint32_t);
        stl_le_p(payload + off, SKS_UNWRAP_FILE_KEY_RESPONSE_SCALAR);
        off += sizeof(uint32_t);
        g_assert(off == SKS_UNWRAP_FILE_KEY_RESPONSE_PAYLOAD_SIZE);
        fprintf(stderr, "sep(%s): sks op09 supplies %u-byte file key and "
                "%u-byte IV, empty third blob, and scalar 0 through selector "
                "%u in a %u-byte IPC v1 reply\n", s->role, SKS_FILE_KEY_SIZE,
                SKS_FILE_KEY_SIZE, SKS_UNWRAP_FILE_KEY_RESPONSE_SELECTOR,
                SKS_IPC_V1_HEADER_SIZE +
                    SKS_UNWRAP_FILE_KEY_RESPONSE_PAYLOAD_SIZE);
        break;
    }
    case SKS_GET_DEVICE_STATE:
        g_assert(darwin_sks_build_unlocked_device_state(payload, payload_size)
                 == payload_size);
        if (s->sks_log_current) {
            fprintf(stderr, "sep(%s): sks op19 returns selector 0 with a "
                    "20-byte DER device-state blob (bh=-6 ss=4) in a %u-byte "
                    "IPC v1 reply\n", s->role,
                    SKS_IPC_V1_HEADER_SIZE +
                        SKS_GET_DEVICE_STATE_RESPONSE_PAYLOAD_SIZE);
        }
        break;
    case SKS_NEGOTIATE:
        stl_le_p(payload, 0);
        stl_le_p(payload + 4, SKS_IPC_VERSION_1);
        break;
    case SKS_MIGRATE_MEDIA_KEY_TO_CLASS: {
        /* The opaque input stays unparsed.  APFS stores the reply as another
         * wrapped record and rejects lengths >= 0x39 at
         * 0xfffffff00a875648..0xa875660, so the request's 0x40 is capacity,
         * not the required returned length.  Reuse the stable wrapped record
         * already emitted by op31; op32 remains the operation that turns it
         * into the 64-byte live key. */
        stl_le_p(payload, SKS_MIGRATE_RESPONSE_VARIANT);
        stl_le_p(payload + 4, SKS_WRAPPED_KEY_SIZE);
        memcpy(payload + 8, sks_wrapped_key, SKS_WRAPPED_KEY_SIZE);
        /* The generated bridge copies a trailing scalar back through its
         * optional output pointer at 0xfffffff00957bbf4..0x957bc60.  The
         * established APFS path requires it to match requested class 14 at
         * 0xfffffff00a875598..0xa8755a4.  The later tagged-volume caller has
         * no output pointer, but receives the same valid union with its
         * captured class 4 rather than a fabricated fixed class. */
        stl_le_p(payload + 8 + SKS_WRAPPED_KEY_SIZE, migrate_class);
        fprintf(stderr, "sep(%s): sks op0f supplies migrated record length %u "
                "and output class %u for variant %u\n", s->role,
                SKS_WRAPPED_KEY_SIZE, migrate_class,
                SKS_MIGRATE_RESPONSE_VARIANT);
        break;
    }
    case SKS_CHECK_CLASS: {
        uint32_t off = 0;

        stl_le_p(payload, 2);
        off += 4;
        for (uint32_t i = 0; i < 5; i++) {
            uint32_t key_size = i < 2 ? SKS_FILE_KEY_SIZE : 0;

            stl_le_p(payload + off, key_size);
            off += 4;
            memcpy(payload + off, sks_media_key, key_size);
            off += key_size;
        }
        /* APFS consumes output 0 as the file key and output 1 as its IV key;
         * each is required to be 16 bytes by apfs_crypto_state_init at
         * 0xfffffff00a915158..0xa915174.  For the 140-byte request,
         * get_new_crypto_id compares the first returned scalar with the
         * requested class at 0xfffffff02a91c200; leaving it zero reaches the
         * EPERM path at 0xfffffff02a915300/0xfffffff02a915344
         * (/tmp/dvm/probe/DATA_SEED_VISIBLE.stderr.log:1644-1694). */
        if (check_class_echo) {
            g_assert(off == SKS_CHECK_CLASS_RESPONSE_SCALAR0_OFF);
            stl_le_p(payload + SKS_CHECK_CLASS_RESPONSE_SCALAR0_OFF,
                     check_class);
            stl_le_p(payload + SKS_CHECK_CLASS_RESPONSE_SCALAR1_OFF,
                     check_class);
        }
        fprintf(stderr, "sep(%s): sks op10 reports class %u available with "
                "%u-byte file and IV keys%s through fake-key union variant "
                "2\n", s->role, check_class, SKS_FILE_KEY_SIZE,
                check_class_echo ? " and two matching class scalars" : "");
        break;
    }
    case SKS_NEW_MEDIA_KEY: {
        uint32_t off = 0;

        /* This is the union selector, not a separate status word.  The
         * request selects variant 1 at payload+0x04; the matching v1 reply
         * layout is decoded at 0xfffffff009567394..0x9567408. */
        stl_le_p(payload + off, 1);
        off += 4;
        stl_le_p(payload + off, SKS_MEDIA_KEY_SIZE);
        off += 4;
        memcpy(payload + off, sks_media_key, SKS_MEDIA_KEY_SIZE);
        off += SKS_MEDIA_KEY_SIZE;
        /* The auxiliary AES-IV key is optional: APFS only calls
         * cpx_set_aes_iv_key when this length is nonzero at
         * 0xfffffff00a8721a0..0xa8721ac. */
        stl_le_p(payload + off, 0);
        off += 4;
        /* Bit 1 tells the bridge this is a raw wrapped-key reply; it becomes
         * bit 0 in the AP-side key descriptor at 0xfffffff0095778d4..0x95778e4.
         * Without it APFS panics "CP_RAW_KEY_WRAPPEDKEY is NOT set" at
         * keybag_common.c:1086 (/tmp/dvm/probe/SKS_KEYOP_V5.serial.log:199). */
        stl_le_p(payload + off, BIT(1));
        off += 4;
        stl_le_p(payload + off, SKS_WRAPPED_KEY_SIZE);
        off += 4;
        memcpy(payload + off, sks_wrapped_key, SKS_WRAPPED_KEY_SIZE);
        fprintf(stderr, "sep(%s): sks op31 supplies CPX key length %u, "
                "no auxiliary key, wrapped record length %u\n", s->role,
                SKS_MEDIA_KEY_SIZE, SKS_WRAPPED_KEY_SIZE);
        break;
    }
    case SKS_UNWRAP_MEDIA_KEY: {
        uint32_t off = 0;

        /* The request's wrapped record is intentionally opaque.  In the
         * first-party no-effaceable-storage mode observed at
         * /tmp/dvm/probe/SKS_LIVEKEY_V9.serial.log:481, a stable fake key is
         * the modeled side effect; there is no unknown storage operation to
         * pretend succeeded. */
        stl_le_p(payload + off, 1);
        off += 4;
        stl_le_p(payload + off, SKS_MEDIA_KEY_SIZE);
        off += 4;
        memcpy(payload + off, sks_media_key, SKS_MEDIA_KEY_SIZE);
        off += SKS_MEDIA_KEY_SIZE;
        stl_le_p(payload + off, 0);
        off += 4;
        stl_le_p(payload + off, BIT(1));
        fprintf(stderr, "sep(%s): sks op32 restores CPX key length %u, "
                "no auxiliary key\n", s->role, SKS_MEDIA_KEY_SIZE);
        break;
    }
    default:
        stl_le_p(payload, 0);
        break;
    }

    if (s->sks_log_current) {
        fprintf(stderr,
                "sep(%s): sks code 0x%02x id %u (%s), request %u bytes\n",
                s->role, sks_code(m), frame_op(m), name, request_size);
    }
    sep_sks_send_response(s, m, response,
                          SKS_IPC_V1_HEADER_SIZE + payload_size);
}

/*
 * Show `n` bytes of an endpoint's OOL in-buffer, so the next protocol can be
 * worked out from a live boot rather than guessed. Capped at 256 bytes and at
 * the buffer size the AP declared.
 */
static void sep_dump_ool_in_len(DarwinSEPState *s, uint8_t ep, uint32_t n) {
    SEPEndpointState *e = &s->ep[ep];
    if (!n || !e->ool_in_addr) return;
    if (n > 256) n = 256;
    if (n > e->ool_in_size && e->ool_in_size) n = e->ool_in_size;
    uint8_t buf[256];
    if (!sep_dma(s, e->ool_in_addr, buf, n, false)) return;
    fprintf(stderr, "sep(%s): ep %u OOL in (%u bytes):", s->role, ep, n);
    for (uint32_t i = 0; i < n; i++) {
        if ((i & 15) == 0) fprintf(stderr, "\n  %04x:", i);
        fprintf(stderr, " %02x", buf[i]);
    }
    fprintf(stderr, "\n");
}

/*
 * Under DARWIN_SEP_DEBUG, show the request body an unhandled endpoint left in
 * its OOL in-buffer. The byte count comes from the frame: AppleSEPKeyStore
 * puts the IPC message size in the top 16 bits of `data`, ACM puts the body
 * length in the 16 bits at [31:16]; both are tried.
 */
static void sep_dump_ool_in(DarwinSEPState *s, uint8_t ep, uint64_t m) {
    uint32_t n = frame_data(m) >> 16;
    if (!n) n = (m >> 16) & 0xffff;
    sep_dump_ool_in_len(s, ep, n);
}

/*
 * Endpoint-10 SCRD has a distinct response frame: its length is the u16 at
 * mailbox bits [31:16], while its status occupies the upper word.  This only
 * accepts the two request bodies recorded in
 * docs/re/acm-scrd-response-contract.md.  In particular, an unknown command
 * remains unanswered rather than being mistaken for a successful SEP call.
 */
static void sep_handle_scrd(DarwinSEPState *s, uint64_t m)
{
    SEPEndpointState *e = &s->ep[SEP_EP_CREDENTIALS];
    uint32_t request_size = (m >> 16) & 0xffff;
    g_autofree uint8_t *request = NULL;
    uint8_t response[SCRD_RESPONSE_CMD25_LEN] = { 0 };
    uint8_t command;
    uint32_t response_size = 0;

    if (!request_size || request_size > e->ool_in_size || !e->ool_in_addr) {
        fprintf(stderr, "sep(%s): scrd tag %u has invalid OOL in size %u "
                "(dva 0x%" PRIx64 " size 0x%x); no reply\n", s->role,
                frame_tag(m), request_size, e->ool_in_addr, e->ool_in_size);
        return;
    }
    request = g_malloc(request_size);
    if (!sep_dma(s, e->ool_in_addr, request, request_size, false)) {
        fprintf(stderr, "sep(%s): scrd tag %u could not read %u-byte OOL "
                "request; no reply\n", s->role, frame_tag(m), request_size);
        return;
    }

    if (request_size < SCRD_REQUEST_COMMAND_OFF + 1 ||
        frame_data(m) != 0 ||
        lduw_le_p(request) != SCRD_REQUEST_VERSION ||
        lduw_le_p(request + 2) != SCRD_REQUEST_HEADER_LEN ||
        memcmp(request + SCRD_REQUEST_TAG_OFF, "DRCS", 4)) {
        fprintf(stderr, "sep(%s): scrd tag %u unsupported request shape "
                "(body %u status 0x%08x v %u hdr 0x%x service %02x%02x%02x%02x); no reply\n",
                s->role, frame_tag(m), request_size,
                frame_data(m),
                request_size >= 2 ? lduw_le_p(request) : 0,
                request_size >= 4 ? lduw_le_p(request + 2) : 0,
                request_size >= SCRD_REQUEST_TAG_OFF + 4 ?
                    request[SCRD_REQUEST_TAG_OFF] : 0,
                request_size >= SCRD_REQUEST_TAG_OFF + 4 ?
                    request[SCRD_REQUEST_TAG_OFF + 1] : 0,
                request_size >= SCRD_REQUEST_TAG_OFF + 4 ?
                    request[SCRD_REQUEST_TAG_OFF + 2] : 0,
                request_size >= SCRD_REQUEST_TAG_OFF + 4 ?
                    request[SCRD_REQUEST_TAG_OFF + 3] : 0);
        if (s->debug) {
            sep_dump_ool_in_len(s, SEP_EP_CREDENTIALS, request_size);
        }
        return;
    }

    command = request[SCRD_REQUEST_COMMAND_OFF];
    switch (command) {
    case SCRD_COMMAND_GET_STATE:
        if (request_size != SCRD_REQUEST_CMD10_LEN) {
            break;
        }
        response_size = SCRD_RESPONSE_CMD10_LEN;
        goto send_reply;
    case SCRD_COMMAND_GET_ENV:
        if (request_size != SCRD_REQUEST_CMD25_LEN) {
            break;
        }
        response_size = SCRD_RESPONSE_CMD25_LEN;
        goto send_reply;
    default:
        break;
    }

    fprintf(stderr, "sep(%s): scrd tag %u cmd 0x%02x body %u is unmodelled; "
            "no reply\n", s->role, frame_tag(m), command, request_size);
    if (s->debug) {
        sep_dump_ool_in_len(s, SEP_EP_CREDENTIALS, request_size);
    }
    return;

send_reply:
    response[0] = SCRD_RESPONSE_VERSION;
    stw_le_p(response + 2, SCRD_RESPONSE_HEADER_LEN);
    memcpy(response + 4, request + 4, sizeof(uint32_t));
    if (!e->ool_out_addr || response_size > e->ool_out_size ||
        !sep_dma(s, e->ool_out_addr, response, response_size, true)) {
        fprintf(stderr, "sep(%s): scrd tag %u cmd 0x%02x cannot write %u-byte "
                "OOL reply (dva 0x%" PRIx64 " size 0x%x); no reply\n",
                s->role, frame_tag(m), command, response_size,
                e->ool_out_addr, e->ool_out_size);
        return;
    }

    sep_send_raw(s, frame(SEP_EP_CREDENTIALS, frame_tag(m),
                          response_size & 0xff, response_size >> 8, 0));
    fprintf(stderr, "sep(%s): scrd v1 cmd 0x%02x seq 0x%08x tag %u replied "
            "with %u-byte OOL envelope at dva 0x%" PRIx64 "\n", s->role,
            command, ldl_le_p(request + 4), frame_tag(m), response_size,
            e->ool_out_addr);
}

/*
 * The xART reply: { ep, tag, u8 status, u16 byte count } -- byte 2 is what
 * the gated sender returns as its IOReturn (ldrb w22, [msg, 2] at
 * 0xfffffff00959f4bc) and bytes 3..4 are how many bytes it copies out of the
 * OOL out-buffer (ldurh w8, [msg, 3] at 0x59f530). In our frame helper those
 * are op, param and the low byte of data.
 */
static void sep_xart_reply(DarwinSEPState *s, uint64_t req, uint8_t status, uint16_t len) {
    sep_send(s, frame_ep(req), frame_tag(req), status, len & 0xff, len >> 8);
}

// Put `len` bytes into the endpoint's OOL out-buffer and answer with that
// count. Falls back to an empty success if the buffer cannot be reached, which
// is logged because the AP will then REQUIRE-panic on the length mismatch.
static void sep_xart_reply_data(DarwinSEPState *s, uint64_t req, const void *buf, uint16_t len) {
    SEPEndpointState *e = &s->ep[frame_ep(req)];
    if (!e->ool_out_addr || len > e->ool_out_size ||
        !sep_dma(s, e->ool_out_addr, (void *)buf, len, true)) {
        fprintf(stderr, "sep(%s): xART ep %u op 0x%02x: cannot write %u bytes to OOL out "
                "(dva 0x%" PRIx64 " size 0x%x); answering empty\n", s->role, frame_ep(req),
                frame_op(req), len, e->ool_out_addr, e->ool_out_size);
        len = 0;
    }
    sep_xart_reply(s, req, XART_STATUS_OK, len);
}

static void sep_handle_xart(DarwinSEPState *s, uint64_t m) {
    uint8_t ep = frame_ep(m), op = frame_op(m);

    switch (op) {
    case XART_GET_FULL_EPOCHS: {
        // 8 x EpochSlot { u8 epoch; u8 pad[3]; }, all zero: a constant standing
        // in for SEP state, accepted because no consumer validates the values
        // (header). The length is what matters -- anything but 32 panics.
        uint8_t slots[XART_EPOCH_COUNT * XART_EPOCH_SLOT_SIZE] = { 0 };
        fprintf(stderr, "sep(%s): xART ep %u getFullEpochs: %u zero slots, %zu bytes\n",
                s->role, ep, XART_EPOCH_COUNT, sizeof(slots));
        sep_xart_reply_data(s, m, slots, sizeof(slots));
        return;
    }
    case XART_GET_EPOCH: {
        // One slot, 8 bytes, same zero constant. The slot index is byte 6 of
        // the request (sturb at 0x5a1c0c writes [this+0x30] there).
        uint8_t slot[XART_GET_EPOCH_LEN] = { 0 };
        fprintf(stderr, "sep(%s): xART ep %u getEpoch(index %u): zero slot, %zu bytes\n",
                s->role, ep, (unsigned)((m >> 48) & 0xff), sizeof(slot));
        sep_xart_reply_data(s, m, slot, sizeof(slot));
        return;
    }
    case XART_COMMIT_EPOCHS:
        // 8 x u16 Epoch in the OOL in-buffer, nothing expected back. Not
        // stored: the model has no epoch state to update. Logged so the values
        // the AP commits are on record for whoever models it.
        fprintf(stderr, "sep(%s): xART ep %u commitEpochs: %u x u16 accepted, not stored\n",
                s->role, ep, XART_EPOCH_COUNT);
        sep_dump_ool_in_len(s, ep, XART_EPOCH_COUNT * XART_EPOCH_SIZE);
        sep_xart_reply(s, m, XART_STATUS_OK, 0);
        return;
    default:
        // Status 0 with an empty payload. Enough for requests without an out
        // buffer; one that expects data will REQUIRE-panic on the length,
        // naming the next opcode to model. That is the honest failure mode.
        fprintf(stderr, "sep(%s): xART ep %u op 0x%02x param %u data 0x%08x: "
                "acknowledged without action\n",
                s->role, ep, op, frame_param(m), frame_data(m));
        sep_xart_reply(s, m, XART_STATUS_OK, 0);
        return;
    }
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
    case SEP_EP_KEYSTORE:  sep_handle_sks(s, m); break;
    case 16: case 19:      sep_handle_xart(s, m); break;
    case SEP_EP_CREDENTIALS: sep_handle_scrd(s, m); break;
    default:
        // scrd and friends: logged and left unanswered until their
        // protocols are modelled. This is the honest hole, not a guess.
        fprintf(stderr, "sep(%s): ep %u '%s' op %u tag %u param %u data 0x%08x: no handler\n",
                s->role, ep, ep_name(s, ep), frame_op(m), frame_tag(m), frame_param(m), frame_data(m));
        if (s->debug) sep_dump_ool_in(s, ep, m);
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
    const char *sks_request_debug = getenv("DARWIN_SKS_REQUEST_DEBUG");
    s->sks_request_debug = sks_request_debug && sks_request_debug[0] &&
                           sks_request_debug[0] != '0';
    const char *sks_request_debug_code =
        getenv("DARWIN_SKS_REQUEST_DEBUG_CODE");
    if (sks_request_debug_code && sks_request_debug_code[0]) {
        char *end = NULL;
        unsigned long code = strtoul(sks_request_debug_code, &end, 0);

        if (end != sks_request_debug_code && *end == '\0' && code <= 0x7f) {
            s->sks_request_debug_code_set = true;
            s->sks_request_debug_code = code;
        } else {
            fprintf(stderr, "sep(%s): ignoring invalid "
                    "DARWIN_SKS_REQUEST_DEBUG_CODE=%s (expected 0..0x7f)\n",
                    s->role, sks_request_debug_code);
        }
    }
    sep_pick_endpoints(s);
    memory_region_init_io(&s->iomem, OBJECT(s), &sep_ops, s, "darwin-sep", s->mmio_size);
    sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->iomem);
    for (int i = 0; i < 4; i++) sysbus_init_irq(SYS_BUS_DEVICE(dev), &s->irq[i]);
}

static int darwin_sep_post_load(void *opaque, int version_id)
{
    DarwinSEPState *s = opaque;

    if (s->i2a_head < 0 || s->i2a_head >= MBOX_FIFO_DEPTH ||
        s->i2a_count < 0 || s->i2a_count > MBOX_FIFO_VISIBLE ||
        s->pend_head < 0 || s->pend_head >= MBOX_PEND_DEPTH ||
        s->pend_count < 0 || s->pend_count > MBOX_PEND_DEPTH ||
        (s->status != SEP_STATUS_ROM && s->status != SEP_STATUS_TZ0)) {
        return -EINVAL;
    }
    for (unsigned i = 0; i < SEP_MAX_EPS; i++) {
        SEPEndpointState *e = &s->ep[i];

        if (e->ool_in_addr + e->ool_in_size < e->ool_in_addr ||
            e->ool_out_addr + e->ool_out_size < e->ool_out_addr) {
            return -EINVAL;
        }
    }

    /*
     * DMA is synchronous and DART is resolved again while constructing the
     * destination machine.  Only the mailbox's level signals need replay.
     */
    sep_update_irqs(s);
    return 0;
}

static const VMStateDescription vmstate_sep_msg = {
    .name = "darwin-sep/msg",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT64(msg0, SEPMsg),
        VMSTATE_UINT64(msg1, SEPMsg),
        VMSTATE_END_OF_LIST()
    },
};

static const VMStateDescription vmstate_sep_endpoint = {
    .name = "darwin-sep/endpoint",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_BOOL(advertised, SEPEndpointState),
        VMSTATE_UINT64(ool_in_addr, SEPEndpointState),
        VMSTATE_UINT64(ool_out_addr, SEPEndpointState),
        VMSTATE_UINT32(ool_in_size, SEPEndpointState),
        VMSTATE_UINT32(ool_out_size, SEPEndpointState),
        VMSTATE_END_OF_LIST()
    },
};

static const VMStateDescription vmstate_darwin_sep = {
    .name = TYPE_DARWIN_SEP,
    .version_id = 1,
    .minimum_version_id = 1,
    .post_load = darwin_sep_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32_EQUAL(mmio_size, DarwinSEPState),
        VMSTATE_VBUFFER_UINT32(misc, DarwinSEPState, 1, NULL, mmio_size),
        VMSTATE_UINT32(cpu_control, DarwinSEPState),
        VMSTATE_UINT32(cpu_status, DarwinSEPState),
        VMSTATE_UINT32(a2i_ctrl_raw, DarwinSEPState),
        VMSTATE_UINT32(i2a_ctrl_raw, DarwinSEPState),
        VMSTATE_UINT64(a2i_send0, DarwinSEPState),
        VMSTATE_STRUCT_ARRAY(i2a_fifo, DarwinSEPState, MBOX_FIFO_DEPTH, 1,
                             vmstate_sep_msg, SEPMsg),
        VMSTATE_INT32(i2a_head, DarwinSEPState),
        VMSTATE_INT32(i2a_count, DarwinSEPState),
        VMSTATE_STRUCT_ARRAY(pend_fifo, DarwinSEPState, MBOX_PEND_DEPTH, 1,
                             vmstate_sep_msg, SEPMsg),
        VMSTATE_INT32(pend_head, DarwinSEPState),
        VMSTATE_INT32(pend_count, DarwinSEPState),
        VMSTATE_BOOL(announced, DarwinSEPState),
        VMSTATE_UINT32(status, DarwinSEPState),
        VMSTATE_BOOL(os_alive, DarwinSEPState),
        VMSTATE_UINT64(shm_dva, DarwinSEPState),
        VMSTATE_UINT32(shm_size, DarwinSEPState),
        VMSTATE_UINT64(txm_dva, DarwinSEPState),
        VMSTATE_UINT64(txm_size, DarwinSEPState),
        VMSTATE_BOOL(txm_published, DarwinSEPState),
        VMSTATE_STRUCT_ARRAY(ep, DarwinSEPState, SEP_MAX_EPS, 1,
                             vmstate_sep_endpoint, SEPEndpointState),
        VMSTATE_UINT64(sks_op19_requests, DarwinSEPState),
        VMSTATE_END_OF_LIST()
    },
};

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
    dc->vmsd = &vmstate_darwin_sep;
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
