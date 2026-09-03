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
 * 0}; observed 36 bytes for its cmd 10 and 40 for cmd 25 (the developer-mode
 * query AMFI makes on every spawn). The body format is not modelled. With
 * DARWIN_SEP_SCRD_FAIL_FAST=1 every request is answered at once with length
 * 0 and a nonzero status, so ACM reports an SEP error instead of waiting
 * 5000 ms per command; the status value is a placeholder, not a modelled
 * SEP error code. Default is to stay silent and log.
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
#define SKS_NEGOTIATE  0x4d
#define SKS_SET_ENV    0x2a
#define SKS_MIGRATE_MEDIA_KEY_TO_CLASS 0x0f
#define SKS_CHECK_CLASS 0x10
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
 * docs/re/sks-op0f-media-key-migration.md.  The record itself stays opaque. */
#define SKS_MIGRATE_REQUEST_SIZE       0xb0
#define SKS_MIGRATE_VARIANT_OFF        0x4c
#define SKS_MIGRATE_FIXED_ONE_OFF      0x50
#define SKS_MIGRATE_FIXED_ZERO0_OFF    0x54
#define SKS_MIGRATE_FIXED_ZERO1_OFF    0x58
#define SKS_MIGRATE_FIXED_ZERO2_OFF    0x5c
#define SKS_MIGRATE_FIXED_U64_OFF      0x60
#define SKS_MIGRATE_FIXED_ZERO3_OFF    0x68
#define SKS_MIGRATE_TARGET_CLASS_OFF   0x6c
#define SKS_MIGRATE_FIXED_ZERO4_OFF    0x70
#define SKS_MIGRATE_FIXED_ZERO5_OFF    0x74
#define SKS_MIGRATE_RECORD_LEN_OFF     0x78
#define SKS_MIGRATE_RECORD_OFF         0x7c
#define SKS_MIGRATE_OUTPUT_CAP_OFF     0xa4
#define SKS_MIGRATE_OUTPUT_AUX_OFF     0xa8
#define SKS_MIGRATE_OUTPUT_SCALAR_OFF  0xac
#define SKS_MIGRATE_REQUEST_VARIANT    3
#define SKS_MIGRATE_RESPONSE_VARIANT   3
#define SKS_MIGRATE_TARGET_CLASS       0x0e
#define SKS_MIGRATE_REQUEST_SCALAR     0
#define SKS_MIGRATE_RESPONSE_CLASS     SKS_MIGRATE_TARGET_CLASS

/* fs_check_class emits two live-captured selector-2 request shapes.  The
 * 0x70-byte class-1 query was already accepted on remount
 * (/tmp/dvm/probe/SKS_REMOUNT_V10.stderr.log:1912-1919).  The 0x8c-byte form
 * carries the requested protection class at wire +0x60 and is the form APFS
 * uses while creating protected named streams
 * (/tmp/dvm/probe/DATA_SEED_VISIBLE.stderr.log:1573-1585). */
#define SKS_CHECK_CLASS_SHORT_REQUEST_SIZE 0x70
#define SKS_CHECK_CLASS_REQUEST_SIZE       0x8c
#define SKS_CHECK_CLASS_VARIANT_OFF        0x4c
#define SKS_CHECK_CLASS_FIXED_ONE_OFF      0x50
#define SKS_CHECK_CLASS_FIXED_ZERO0_OFF    0x54
#define SKS_CHECK_CLASS_FIXED_MAX_OFF      0x58
#define SKS_CHECK_CLASS_FIXED_ZERO1_OFF    0x5c
#define SKS_CHECK_CLASS_REQUEST_CLASS_OFF  0x60
#define SKS_CHECK_CLASS_LONG_TAG_OFF       0x64
#define SKS_CHECK_CLASS_LONG_SIZE_OFF      0x68
#define SKS_CHECK_CLASS_LONG_ZERO_OFF      0x70
#define SKS_CHECK_CLASS_LONG_TAIL_OFF      0x74
#define SKS_CHECK_CLASS_REQUEST_VARIANT    2
#define SKS_CHECK_CLASS_SHORT_CLASS        1
#define SKS_CHECK_CLASS_LONG_TAG           2
#define SKS_CHECK_CLASS_LONG_SIZE          0x1c
#define SKS_CHECK_CLASS_RESPONSE_SCALAR0_OFF 56
#define SKS_CHECK_CLASS_RESPONSE_SCALAR1_OFF 60

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

/* The final 24 bytes are identical in every 0x8c-byte request captured during
 * DATA_SEED_FIRSTERR and DATA_SEED_VISIBLE.  The u32 at +0x6c varies between
 * calls and remains deliberately opaque. */
static const uint8_t sks_check_class_long_tail[] = {
    0x01, 0x00, 0x61, 0x70, 0x66, 0x73, 0x75, 0x75,
    0x69, 0x64, 0x00, 0x00, 0x76, 0x6f, 0x6c, 0x75,
    0x6d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

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
    bool scrd_fail_fast;
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

static bool sep_sks_validate_migrate_request(DarwinSEPState *s,
                                             const uint8_t *request,
                                             uint32_t request_size)
{
    uint32_t header_body_size = 0;
    uint32_t ipc_version = 0;
    uint32_t variant = 0;
    uint32_t target_class = 0;
    uint32_t record_len = 0;
    uint32_t output_cap = 0;
    uint32_t output_scalar = 0;

    if (request_size >= SKS_IPC_V1_HEADER_SIZE) {
        header_body_size = ldl_le_p(request);
        ipc_version = ldl_le_p(request + SKS_IPC_VERSION_OFF);
    }
    if (request_size >= SKS_MIGRATE_OUTPUT_SCALAR_OFF + sizeof(uint32_t)) {
        variant = ldl_le_p(request + SKS_MIGRATE_VARIANT_OFF);
        target_class = ldl_le_p(request + SKS_MIGRATE_TARGET_CLASS_OFF);
        record_len = ldl_le_p(request + SKS_MIGRATE_RECORD_LEN_OFF);
        output_cap = ldl_le_p(request + SKS_MIGRATE_OUTPUT_CAP_OFF);
        output_scalar = ldl_le_p(request + SKS_MIGRATE_OUTPUT_SCALAR_OFF);
    }

    /* This accepts only the one statically decoded and live-captured variant.
     * In particular, do not turn another union variant or record shape into a
     * fake success: its response decoder and SEP side effects are unknown. */
    if (request_size != SKS_MIGRATE_REQUEST_SIZE ||
        header_body_size != SKS_IPC_V1_HEADER_BODY_SIZE ||
        ipc_version != SKS_IPC_VERSION_1 ||
        variant != SKS_MIGRATE_REQUEST_VARIANT ||
        target_class != SKS_MIGRATE_TARGET_CLASS ||
        record_len != SKS_WRAPPED_KEY_SIZE ||
        output_cap != SKS_MEDIA_KEY_SIZE ||
        ldl_le_p(request + SKS_MIGRATE_FIXED_ONE_OFF) != 1 ||
        ldl_le_p(request + SKS_MIGRATE_FIXED_ZERO0_OFF) != 0 ||
        ldl_le_p(request + SKS_MIGRATE_FIXED_ZERO1_OFF) != 0 ||
        ldl_le_p(request + SKS_MIGRATE_FIXED_ZERO2_OFF) != 0 ||
        ldq_le_p(request + SKS_MIGRATE_FIXED_U64_OFF) != UINT64_MAX ||
        ldl_le_p(request + SKS_MIGRATE_FIXED_ZERO3_OFF) != 0 ||
        ldl_le_p(request + SKS_MIGRATE_FIXED_ZERO4_OFF) != 0 ||
        ldl_le_p(request + SKS_MIGRATE_FIXED_ZERO5_OFF) != 0 ||
        ldl_le_p(request + SKS_MIGRATE_OUTPUT_AUX_OFF) != 0 ||
        output_scalar != SKS_MIGRATE_REQUEST_SCALAR ||
        SKS_MIGRATE_RECORD_OFF + record_len !=
            SKS_MIGRATE_OUTPUT_CAP_OFF) {
        fprintf(stderr, "sep(%s): sks op0f rejected unsupported migration "
                "shape: request %u header 0x%x version %u variant %u "
                "class %u record length %u output capacity %u output "
                "scalar %u; no reply\n",
                s->role, request_size, header_body_size, ipc_version, variant,
                target_class, record_len, output_cap, output_scalar);
        return false;
    }

    fprintf(stderr, "sep(%s): sks op0f accepted request length %u variant %u "
            "class %u, opaque record length %u, output capacity %u, output "
            "scalar %u\n",
            s->role, request_size, variant, target_class, record_len,
            output_cap, output_scalar);
    return true;
}

static bool sep_sks_validate_check_class_request(DarwinSEPState *s,
                                                 const uint8_t *request,
                                                 uint32_t request_size,
                                                 uint32_t *requested_class,
                                                 bool *echo_class)
{
    uint32_t header_body_size = 0;
    uint32_t ipc_version = 0;
    uint32_t variant = 0;
    uint32_t protection_class = 0;
    bool common_shape;
    bool short_shape;
    bool long_shape;

    if (request_size >= SKS_IPC_V1_HEADER_SIZE) {
        header_body_size = ldl_le_p(request);
        ipc_version = ldl_le_p(request + SKS_IPC_VERSION_OFF);
    }
    if (request_size >=
        SKS_CHECK_CLASS_REQUEST_CLASS_OFF + sizeof(uint32_t)) {
        variant = ldl_le_p(request + SKS_CHECK_CLASS_VARIANT_OFF);
        protection_class =
            ldl_le_p(request + SKS_CHECK_CLASS_REQUEST_CLASS_OFF);
    }

    common_shape = request_size >=
            SKS_CHECK_CLASS_REQUEST_CLASS_OFF + sizeof(uint32_t) &&
        header_body_size == SKS_IPC_V1_HEADER_BODY_SIZE &&
        ipc_version == SKS_IPC_VERSION_1 &&
        variant == SKS_CHECK_CLASS_REQUEST_VARIANT &&
        ldl_le_p(request + SKS_CHECK_CLASS_FIXED_ONE_OFF) == 1 &&
        ldl_le_p(request + SKS_CHECK_CLASS_FIXED_ZERO0_OFF) == 0 &&
        ldl_le_p(request + SKS_CHECK_CLASS_FIXED_MAX_OFF) == UINT32_MAX &&
        ldl_le_p(request + SKS_CHECK_CLASS_FIXED_ZERO1_OFF) == 0;
    short_shape = request_size == SKS_CHECK_CLASS_SHORT_REQUEST_SIZE &&
        protection_class == SKS_CHECK_CLASS_SHORT_CLASS &&
        ldl_le_p(request + SKS_CHECK_CLASS_LONG_TAG_OFF) == 0 &&
        ldl_le_p(request + SKS_CHECK_CLASS_LONG_SIZE_OFF) == 0 &&
        ldl_le_p(request + SKS_CHECK_CLASS_LONG_SIZE_OFF + 4) == 0;
    long_shape = request_size == SKS_CHECK_CLASS_REQUEST_SIZE &&
        (protection_class == 3 || protection_class == 4) &&
        ldl_le_p(request + SKS_CHECK_CLASS_LONG_TAG_OFF) ==
            SKS_CHECK_CLASS_LONG_TAG &&
        ldl_le_p(request + SKS_CHECK_CLASS_LONG_SIZE_OFF) ==
            SKS_CHECK_CLASS_LONG_SIZE &&
        ldl_le_p(request + SKS_CHECK_CLASS_LONG_ZERO_OFF) == 0 &&
        !memcmp(request + SKS_CHECK_CLASS_LONG_TAIL_OFF,
                sks_check_class_long_tail,
                sizeof(sks_check_class_long_tail));

    if (!common_shape || (!short_shape && !long_shape)) {
        fprintf(stderr, "sep(%s): sks op10 rejected unsupported check-class "
                "shape: request %u header 0x%x version %u variant %u class "
                "%u; no reply\n", s->role, request_size, header_body_size,
                ipc_version, variant, protection_class);
        return false;
    }

    *requested_class = protection_class;
    *echo_class = long_shape;
    fprintf(stderr, "sep(%s): sks op10 accepted %s request length %u "
            "variant %u class %u\n", s->role,
            long_shape ? "protected-object" : "availability", request_size,
            variant, protection_class);
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

    fprintf(stderr, "sep(%s): sks code 0x%02x id %u replied with %u-byte "
            "SHA-256-authenticated IPC v1 message\n", s->role, sks_code(m),
            frame_op(m), response_size);
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
    bool check_class_echo = false;
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

    if (s->debug) {
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
        if (!sep_sks_validate_migrate_request(s, request, request_size)) {
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
         * optional output pointer at 0xfffffff00957bbf4..0x957bc60.  APFS
         * requires it to match the requested class 14 at
         * 0xfffffff00a875598..0xa8755a4; zero is the distinct request-side
         * field captured at +0xac. */
        stl_le_p(payload + 8 + SKS_WRAPPED_KEY_SIZE,
                 SKS_MIGRATE_RESPONSE_CLASS);
        fprintf(stderr, "sep(%s): sks op0f supplies migrated record length %u "
                "and output class %u for variant %u\n", s->role,
                SKS_WRAPPED_KEY_SIZE, SKS_MIGRATE_RESPONSE_CLASS,
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

    fprintf(stderr, "sep(%s): sks code 0x%02x id %u (%s), request %u bytes\n",
            s->role, sks_code(m), frame_op(m), name, request_size);
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
    case 10:
        fprintf(stderr, "sep(%s): scrd request tag %u, %u byte body: %s\n", s->role,
                frame_tag(m), (unsigned)((m >> 16) & 0xffff),
                s->scrd_fail_fast ? "failing fast (DARWIN_SEP_SCRD_FAIL_FAST)" : "no handler");
        if (s->debug) sep_dump_ool_in(s, ep, m);
        if (s->scrd_fail_fast) {
            // {ep 10, tag, length 0, status 1}: see the header. Status 1 is a
            // placeholder for "SEP said no", not a decoded error code.
            sep_send_raw(s, frame(10, frame_tag(m), 0, 0, 1));
        }
        break;
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
    s->scrd_fail_fast = getenv("DARWIN_SEP_SCRD_FAIL_FAST") != NULL;
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
