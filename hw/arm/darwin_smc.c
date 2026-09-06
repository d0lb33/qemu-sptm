/*
 * darwin-smc: the SMC coprocessor's key endpoint.
 *
 * On iPhone17,3 / T8140 the SMC is an RTKit coprocessor (/arm-io/smc,
 * "iop,ascwrap-v6", role SMC) whose firmware exposes a key/value store on
 * RTKit endpoint 0x20.  XNU's AppleSMCKeysEndpoint personality binds the
 * RTBuddy nub "SMCEndpoint1" (kernelcache prelink info, IOProviderClass
 * RTBuddyEndpointService), and AppleSMC (com.apple.driver.AppleSMC) builds
 * everything else on it: AppleSMCInterface children for the nub's
 * smc-pmu / smc-charger / smc-power-out / smc-charger-util nodes and, above
 * AppleSMC itself, AppleSmartBatteryManager (AppleSmartBatteryManagerEmbedded,
 * IOProviderClass AppleSMC), whose AppleSmartBattery is the only class in the
 * kernelcache that derives from IOPMPowerSource besides the Dialog-PMU-era
 * AppleARMPMUPowerSource, whose "charger" nub this tree does not carry.
 *
 * Message layout.  m1n1 proxyclient/m1n1/fw/smc.py documents the M1 form
 * and the T8140 endpoint code agrees with every field we have checked:
 *
 *   request  [7:0] type   [15:12] id   [23:16] size   [31:24] write size
 *            [63:32] key as a big-endian FourCC
 *   reply    [7:0] result [15:12] id   [31:16] size   [63:32] value
 *            (values of at most four bytes travel in the message, larger
 *            ones through the shared buffer)
 *   types    0x10 READ  0x11 WRITE  0x12 GET_KEY_BY_INDEX  0x13 GET_KEY_INFO
 *            0x17 INITIALIZE  0x18 NOTIFICATION (IOP -> AP)  0x20 RW_KEY
 *
 * AppleSMCKeysEndpoint's response path checks the reply id against the
 * outstanding command ("Tag/ID of response (0x%02x) doesn't match last
 * command sent", 0xfffffff0095d30d8) and the reply's size against the
 * request ("readKeyPolled %c%c%c%c sizeMismatch sent=%d rcvd=%d",
 * 0xfffffff0095d4410).
 *
 * Shared buffer.  The reply to INITIALIZE is the physical address of the
 * SMC's shared SRAM ("PA = 0x%llx", 0xfffffff0095d3298).  The endpoint
 * accepts it only inside the nub's region-base .. region-base +
 * region-size - page (reads of the two properties at 0xfffffff0095d3430 and
 * 0xfffffff0095d34a8, the range check at 0xfffffff0095d34e0-0xfffffff0095d350c)
 * and maps it with IOMemoryDescriptor::withPhysicalAddress
 * (0xfffffff0095d351c), so the buffer must be real memory there.  The
 * T8140 tree gives the SMC region-base 0x30de00000, size 0x100000, which is
 * not DRAM in this machine; this model backs the whole region with RAM and
 * places the buffer 512 KiB into it (64 KiB aligned so the address's id
 * bits [15:12] are zero, the id of the INITIALIZE command).
 *
 * Keys.  Every key the guest asks for is logged; unknown keys are refused
 * with SMC result 0x84 (key not found) rather than invented.  The table
 * below holds only what a traced driver reads and what the reply must carry
 * for that driver to continue; each entry cites the reader.
 *
 * DARWIN_SMC_DEBUG=1 logs every endpoint message.
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qapi/error.h"
#include "migration/vmstate.h"
#include "system/memory.h"
#include "system/address-spaces.h"
#include "exec/memattrs.h"
#include "xnu/apple_dtree.h"
#include "xnu/darwin_asc.h"
#include "xnu/darwin_smc.h"

#define SMC_EP                 0x20

#define SMC_READ_KEY           0x10
#define SMC_WRITE_KEY          0x11
#define SMC_GET_KEY_BY_INDEX   0x12
#define SMC_GET_KEY_INFO       0x13
#define SMC_INITIALIZE         0x17
#define SMC_NOTIFICATION       0x18
#define SMC_RW_KEY             0x20

/* SMC result codes as used by AppleSMCFamily's kSMC* strings; the numeric
 * values match m1n1's SMCError handling and Apple's public SMC headers. */
#define SMC_OK                 0x00
#define SMC_KEY_NOT_FOUND      0x84
#define SMC_KEY_NOT_READABLE   0x85
#define SMC_KEY_NOT_WRITABLE   0x86
#define SMC_KEY_SIZE_MISMATCH  0x87

#define SMC_SHMEM_OFFSET       0x80000
#define SMC_SHMEM_SIZE         0x4000
#define SMC_MAX_KEYS           128

typedef struct {
    char key[5];
    char type[5];
    uint8_t size;
    uint8_t flags;
    bool writable;
    uint8_t data[64];
    const char *why;
} SMCKey;

/* The modelled battery.  One pack, one charger, a fixed state of charge,
 * external power attached and charging.  See smc_battery_apply(). */
typedef struct {
    uint8_t soc;        /* percent */
    bool external;      /* charger attached */
    bool charging;
} SMCBattery;

typedef struct {
    DeviceState *asc;
    SMCBattery batt;
    MemoryRegion region;
    uint64_t region_base;
    uint64_t region_size;
    uint64_t shmem;
    bool debug;
    bool initialized;
    SMCKey keys[SMC_MAX_KEYS];
    unsigned n_keys;
    uint64_t n_msgs;
    uint64_t n_unknown;
} DarwinSMC;

static DarwinSMC *g_smc;

static uint32_t fourcc(const char *s)
{
    return ((uint32_t)(uint8_t)s[0] << 24) | ((uint32_t)(uint8_t)s[1] << 16) |
           ((uint32_t)(uint8_t)s[2] << 8) | (uint8_t)s[3];
}

static void fourcc_str(uint32_t v, char *out)
{
    out[0] = v >> 24; out[1] = v >> 16; out[2] = v >> 8; out[3] = v;
    for (int i = 0; i < 4; i++) {
        if (out[i] < 0x20 || out[i] >= 0x7f) out[i] = '?';
    }
    out[4] = 0;
}

static SMCKey *smc_add(DarwinSMC *s, const char *key, const char *type, unsigned size,
                       const void *data, bool writable, const char *why)
{
    g_assert(s->n_keys < SMC_MAX_KEYS && size <= sizeof(s->keys[0].data));
    SMCKey *k = &s->keys[s->n_keys++];
    memcpy(k->key, key, 4); k->key[4] = 0;
    memcpy(k->type, type, 4); k->type[4] = 0;
    k->size = size;
    /* flags byte as m1n1 decodes it from GET_KEY_INFO: bit 7 readable,
     * bit 6 writable (Apple's SMC_FLAG_* in IOKit's SMC headers) */
    k->flags = 0x80 | (writable ? 0x40 : 0);
    k->writable = writable;
    if (data) memcpy(k->data, data, size);
    k->why = why;
    return k;
}

static SMCKey *smc_find(DarwinSMC *s, uint32_t key)
{
    for (unsigned i = 0; i < s->n_keys; i++) {
        if (fourcc(s->keys[i].key) == key) return &s->keys[i];
    }
    return NULL;
}

/*
 * Integer key data is big-endian on the wire: with #KEY answered as
 * little-endian 3 the guest logged "Number of keys on this target:
 * 50331648" (0x03000000) in probe BATT_SMC2, so AppleSMCKeysEndpoint
 * reassembles the bytes most-significant first (Apple's SMC convention).
 */
static void smc_add_u(DarwinSMC *s, const char *key, const char *type, unsigned size,
                      uint64_t value, bool writable, const char *why)
{
    uint8_t be[8];
    for (unsigned i = 0; i < size; i++) {
        be[i] = value >> (8 * (size - 1 - i));
    }
    smc_add(s, key, type, size, be, writable, why);
}


/*
 * Battery and charger keys.
 *
 * Who reads what (AppleSmartBatteryManagerEmbedded, text
 * 0xfffffff009692060-0xfffffff0096c3814, disassembly in the RE notes):
 *
 *   BPCC  AppleSmartBattery reads it as 2 bytes right after probing its key
 *         table (0xfffffff0096a8154-0xfffffff0096a81c8): packs = BPCC >> 8,
 *         chargers = BPCC & 0xff; BatteryInstalled = packs != 0
 *         (0xfffffff0096a84a0-0xfffffff0096a84f4, log "BatteryInstalled=%u
 *         packs:%d").  Without it there is no AppleSmartBatteryPack and the
 *         IOPMPowerSource says BatteryInstalled=false, which is exactly the
 *         state powerd's control.internal null dereference comes from.
 *
 *   The 20-key command table (cmd -> key pairs at 0xfffffff007758688, entry
 *   templates at 0xfffffff007757b60): AppleSmartBattery calls GET_KEY_INFO
 *   for each at start (0xfffffff0096a7fac-0xfffffff0096a8140), tolerates
 *   0x84 by renaming the key NOOP, and otherwise reads the key with the
 *   size GET_KEY_INFO reported, 1..32 bytes (0xfffffff0096a7dcc-
 *   0xfffffff0096a7de4), widening the bytes to an integer.  Entries with a
 *   property symbol publish straight to the IORegistry
 *   (0xfffffff0096b559c): CHCR -> AppleRawExternalConnected, BSFC ->
 *   FullyCharged, CH0V -> AppleRawBatteryVoltage, CHAS ->
 *   ChargerConfiguration, B0BL -> BootVoltage, BCFW ->
 *   SkipperNEIgnoreAtCritical, BMDA -> ManufacturerData, BMSN -> serial
 *   data; B0AC becomes InstantAmperage (0xfffffff0096b5c44-0xfffffff0096b5c70)
 *   and CHCE drives IOPMPowerSource external-connected
 *   (0xfffffff0096b5bf0-0xfffffff0096b5c1c).
 *
 * Meanings and widths follow the same keys in Linux's upstream
 * drivers/power/supply/macsmc-power.c (Apple silicon SMC firmware, which
 * shares this key namespace): B0AV voltage mV u16, B0AC current mA s16
 * (negative discharging), B0CT cycle count u16, B0TE minutes to empty u16
 * (0xffff = unknown), B0TF minutes to full, B0RM/B0FC/B0DC remaining /
 * full / design capacity mAh u16, B0AT temperature K*10 u16, BUIC UI state
 * of charge percent u8, CHCE charger present flag, CHCC charge capable
 * flag, CHSC system charging flag, BSFC fully charged flag, CHNC u64
 * no-charge reasons (0 = charging allowed), BCF0 u8 critical flags (0 = no
 * emergency), BMSN/BMDN/BMDT serial, model, manufacture date strings, BNCB
 * cell count u8.  Keys the T8140 drivers request whose meaning has no such
 * reference (CHAS, B0BL, CH0V, BCFW, D2xx, WAxx...) are either left absent
 * (0x84, which the readers tolerate) or, when the driver's own property
 * name explains them, given the value that name implies and noted.
 */
static void smc_set_u(DarwinSMC *s, const char *key, uint64_t value)
{
    SMCKey *k = smc_find(s, fourcc(key));
    g_assert(k);
    for (unsigned i = 0; i < k->size; i++) {
        k->data[i] = value >> (8 * (k->size - 1 - i));
    }
}

/* Physical constants of the modelled pack: an iPhone-class single cell. */
#define BATT_DESIGN_MAH   3561
#define BATT_FULL_MAH     3400
#define BATT_VOLTAGE_MV   4120

static void smc_battery_apply(DarwinSMC *s)
{
    const SMCBattery *b = &s->batt;
    bool full = b->soc >= 100;
    bool charging = b->external && b->charging && !full;
    int16_t current_ma = charging ? 480 : (b->external ? 0 : -350);
    unsigned remaining = BATT_FULL_MAH * b->soc / 100;

    smc_set_u(s, "BPCC", 0x0100 | (b->external ? 1 : 0));
    smc_set_u(s, "B0AV", BATT_VOLTAGE_MV);
    smc_set_u(s, "B0AC", (uint16_t)current_ma);
    smc_set_u(s, "B0CT", 12);
    smc_set_u(s, "B0TE", charging || b->external ? 0xffff : 60 * 8 * b->soc / 100);
    smc_set_u(s, "B0TF", charging ? 60 * (100 - b->soc) / 60 + 1 : 0xffff);
    smc_set_u(s, "B0RM", remaining);
    smc_set_u(s, "B0FC", BATT_FULL_MAH);
    smc_set_u(s, "B0DC", BATT_DESIGN_MAH);
    smc_set_u(s, "B0AT", 2982);          /* 25.1 C */
    smc_set_u(s, "BUIC", b->soc);
    smc_set_u(s, "BRSC", b->soc);
    smc_set_u(s, "CHCE", b->external);
    smc_set_u(s, "CHCC", b->external);
    smc_set_u(s, "CHCR", b->external);
    smc_set_u(s, "CHSC", charging);
    smc_set_u(s, "BSFC", full);
    smc_set_u(s, "CHNC", full ? 1 : 0);  /* macsmc-power CHNC_BATTERY_FULL is bit 0 */
    smc_set_u(s, "BCF0", 0);
    smc_set_u(s, "CH0V", b->external ? 5000 : 0);
    smc_set_u(s, "B0BL", BATT_VOLTAGE_MV);
}

static void smc_populate_battery(DarwinSMC *s)
{
    static const char serial[16] = "DVMBATT000000001";
    static const char model[16] = "darwin-vm";
    static const char mfg[4] = "3405";   /* macsmc-power: YYMM, year offset 1992 */

    smc_add_u(s, "BPCC", "ui16", 2, 0, false, "AppleSmartBattery pack/charger count");
    /* the command-table keys, in the order AppleSmartBattery probes them */
    smc_add_u(s, "B0AV", "ui16", 2, 0, false, "AppleSmartBattery cmd 0x09 voltage");
    smc_add_u(s, "B0AC", "si16", 2, 0, false, "AppleSmartBattery cmd 0x0a InstantAmperage");
    smc_add(s, "BMSN", "ch8*", 16, serial, false, "AppleSmartBattery cmd 0x76 serial");
    smc_add_u(s, "BCF0", "ui8 ", 1, 0, false, "AppleSmartBattery cmd 0x400 critical flags");
    smc_add_u(s, "CHCC", "flag", 1, 0, false, "AppleSmartBattery cmd 0x200 charge capable");
    smc_add_u(s, "CHCE", "flag", 1, 0, false, "AppleSmartBattery cmd 0x100 charger present");
    smc_add_u(s, "CHCR", "flag", 1, 0, false, "AppleSmartBattery cmd 0x1700 AppleRawExternalConnected");
    smc_add_u(s, "CHSC", "flag", 1, 0, false, "AppleSmartBattery cmd 0x01 system charging");
    smc_add_u(s, "CH0V", "ui16", 2, 0, false, "AppleSmartBattery cmd 0xe00 AppleRawBatteryVoltage");
    smc_add_u(s, "BSFC", "flag", 1, 0, false, "AppleSmartBattery cmd 0x300 FullyCharged");
    smc_add_u(s, "CHNC", "ui64", 8, 0, false, "AppleSmartBattery cmd 0x1600 no-charge reasons");
    smc_add_u(s, "B0BL", "ui16", 2, 0, false, "AppleSmartBattery cmd 0x1500 BootVoltage");
    smc_add_u(s, "B0CT", "ui16", 2, 0, false, "AppleSmartBattery cmd 0x17 cycle count");
    smc_add_u(s, "B0TE", "ui16", 2, 0, false, "AppleSmartBattery cmd 0x12 time to empty");
    /* pack-level keys with macsmc-power semantics, for AppleSmartBatteryPack */
    smc_add_u(s, "B0TF", "ui16", 2, 0, false, "time to full (macsmc-power)");
    smc_add_u(s, "B0RM", "ui16", 2, 0, false, "remaining capacity mAh (macsmc-power)");
    smc_add_u(s, "B0FC", "ui16", 2, 0, false, "full charge capacity mAh (macsmc-power)");
    smc_add_u(s, "B0DC", "ui16", 2, 0, false, "design capacity mAh (macsmc-power)");
    smc_add_u(s, "B0AT", "ui16", 2, 0, false, "temperature K*10 (macsmc-power)");
    smc_add_u(s, "BUIC", "ui8 ", 1, 0, false, "UI state of charge % (macsmc-power)");
    smc_add_u(s, "BRSC", "ui8 ", 1, 0, false, "raw state of charge % (pack key list 0xfffffff0077585a8)");
    smc_add_u(s, "BNCB", "ui8 ", 1, 1, false, "cell count (macsmc-power)");
    smc_add(s, "BMDN", "ch8*", 16, model, false, "model name (macsmc-power)");
    smc_add(s, "BMDT", "ch8*", 4, mfg, false, "manufacture date (macsmc-power)");
    /* AppleSmartBatteryPack shutdown-data check (0xfffffff0096998e8-
     * 0xfffffff009699984): read 'UQd'+pack as 2 bytes (falls back to UPOF),
     * any nonzero flag means shutdown data exists; then write 1 to
     * 'UB'+pack+'C' to clear it.  No shutdown data is pending here. */
    smc_add_u(s, "UQd0", "ui16", 2, 0, false, "AppleSmartBatteryPack shutdown data flags");
    smc_add_u(s, "UB0C", "ui8 ", 1, 0, true, "AppleSmartBatteryPack shutdown data clear");

    s->batt.soc = 80;
    s->batt.external = true;
    s->batt.charging = true;
    const char *env = getenv("DARWIN_SMC_BATTERY");
    if (env) {
        /* soc[,ext][,charging]  e.g. DARWIN_SMC_BATTERY=55,0,0 */
        int soc = 80, ext = 1, chg = 1;
        sscanf(env, "%d,%d,%d", &soc, &ext, &chg);
        s->batt.soc = MIN(MAX(soc, 0), 100);
        s->batt.external = ext != 0;
        s->batt.charging = chg != 0;
    }
    smc_battery_apply(s);
}

static void smc_populate(DarwinSMC *s)
{
    uint32_t u32;
    uint8_t rev[6] = { 1, 0, 0, 0, 0, 0 };
    uint8_t zeros[32] = { 0 };

    /* AppleSMCFamily::smcGetVersWithSMC reads REV, smcPublishVersion reads
     * $Num (strings at 0xfffffff007727808+; readers at 0xfffffff0095cef7c and
     * 0xfffffff0095cf1a0).  The values are a virtual-SMC identity. */
    smc_add(s, "REV ", "{rev", 6, rev, false, "AppleSMCFamily::smcGetVersWithSMC");
    u32 = 1;
    smc_add(s, "$Num", "ui8 ", 1, &u32, false, "AppleSMCFamily::smcPublishVersion");
    /* AppleSMCKeysEndpoint::_smcInitKeyTableCache reads the key count
     * (0xfffffff0095d3834, "%s: Number of keys on this target: %d") and then
     * enumerates keys by index. #KEY is patched after the table is final. */
    smc_add_u(s, "#KEY", "ui32", 4, 0, false, "AppleSMCKeysEndpoint::_smcInitKeyTableCache");

    /*
     * AppleSMC::start and AppleSMCKeysEndpoint, transfer sizes from the
     * call sites (tools output keysizes.py over 0xfffffff0095c67c0-0xfffffff0095f1d04):
     *   CLKH  8-byte write of the AP clock ("ERROR: smcWriteKey CLKH failed", 0xfffffff0095c99c4)
     *   WKTP  1-byte wake type ("writing WKTP=%d")
     *   NTAP  1-byte write enabling notifications ("NTAP result", 0xfffffff0095d660c);
     *         refusing it produced "Unable to enable notification interface"
     *   RGEN  1 byte, read at 0xfffffff0095cf8d0 with 0x84 tolerated
     *   aDC#  4 bytes, ADC channel count (0xfffffff0095c8574); zero channels
     *   LGPE / LGDE / LGWT  SMC log control (1, 32, 8 bytes)
     *   MBSE / MBSW / MESS  panic-flow keys (4, 8, 1 bytes; "MESS key not present")
     * Values are the neutral ones: no ADC channels, log disabled, nothing
     * pending.  The guest writes CLKH/WKTP/NTAP/LGxx; those are stored.
     */
    smc_add_u(s, "CLKH", "ui64", 8, 0, true, "AppleSMC::start clock write");
    smc_add_u(s, "WKTP", "ui8 ", 1, 0, true, "AppleSMC wake type");
    smc_add_u(s, "NTAP", "flag", 1, 0, true, "AppleSMCKeysEndpoint notification enable");
    smc_add_u(s, "RGEN", "ui8 ", 1, 0, false, "AppleSMC reset generation");
    smc_add_u(s, "aDC#", "ui32", 4, 0, false, "AppleSMC ADC channel count");
    smc_add_u(s, "LGPE", "flag", 1, 0, true, "AppleSMC log enable");
    smc_add(s, "LGDE", "hex_", 32, zeros, true, "AppleSMC log descriptor");
    smc_add_u(s, "LGWT", "ui64", 8, 0, true, "AppleSMC log watermark");
    smc_add_u(s, "MBSE", "ui32", 4, 0, true, "AppleSMC panic begin");
    smc_add_u(s, "MBSW", "ui64", 8, 0, false, "AppleSMC panic status");
    smc_add_u(s, "MESS", "ui8 ", 1, 0, false, "AppleSMC panic message");

    smc_populate_battery(s);

    smc_add_u(s, "#KEY", "ui32", 4, 0, false, NULL);   /* placeholder, replaced below */
    s->n_keys--;
    {
        SMCKey *k = smc_find(s, fourcc("#KEY"));
        uint32_t n = s->n_keys;
        for (unsigned i = 0; i < 4; i++) k->data[i] = n >> (8 * (3 - i));
    }
}

static void smc_reply(DarwinSMC *s, uint64_t msg)
{
    if (s->debug) {
        fprintf(stderr, "smc: IOP -> AP 0x%016" PRIx64 "\n", msg);
    }
    darwin_asc_send(s->asc, SMC_EP, msg);
}

static bool smc_shmem_rw(DarwinSMC *s, void *buf, unsigned len, bool write)
{
    if (len > SMC_SHMEM_SIZE) return false;
    MemTxResult r = write ?
        address_space_write(&address_space_memory, s->shmem, MEMTXATTRS_UNSPECIFIED, buf, len) :
        address_space_read(&address_space_memory, s->shmem, MEMTXATTRS_UNSPECIFIED, buf, len);
    return r == MEMTX_OK;
}

static bool smc_handle(void *opaque, uint8_t ep, uint64_t msg)
{
    DarwinSMC *s = opaque;
    if (ep != SMC_EP) return false;
    s->n_msgs++;

    unsigned type = msg & 0xff;
    unsigned id = (msg >> 12) & 0xf;
    unsigned size = (msg >> 16) & 0xff;
    unsigned wsize = (msg >> 24) & 0xff;
    uint32_t key = msg >> 32;
    char name[5];
    fourcc_str(key, name);
    uint64_t reply = (uint64_t)id << 12;

    if (s->debug) {
        fprintf(stderr, "smc: AP -> IOP 0x%016" PRIx64 " type 0x%02x id %u size %u wsize %u key %s\n",
                msg, type, id, size, wsize, name);
    }

    switch (type) {
    case SMC_INITIALIZE:
        s->initialized = true;
        fprintf(stderr, "smc: INITIALIZE; shared buffer at 0x%" PRIx64 " (%u keys)\n",
                s->shmem, s->n_keys);
        smc_reply(s, s->shmem);
        return true;

    case SMC_READ_KEY: {
        SMCKey *k = smc_find(s, key);
        if (!k) {
            s->n_unknown++;
            fprintf(stderr, "smc: READ %s size %u: key not modelled (0x84)\n", name, size);
            smc_reply(s, reply | SMC_KEY_NOT_FOUND);
            return true;
        }
        /* The request size is the caller's buffer, not the key size: the
         * battery pack reads every key with an 8-byte buffer, and
         * AppleSMCKeysEndpoint's polled reader only complains when the
         * reply is larger than what it sent ("readKeyPolled %c%c%c%c
         * sizeMismatch sent=%d rcvd=%d" is reached from the cmp at
         * 0xfffffff0095d43cc, b.hs skips it) and copies the reply's own
         * size from the message or the shared buffer (0xfffffff0095d441c-
         * 0xfffffff0095d44bc).  So a larger request is served with the
         * key's size; a smaller one is a real mismatch. */
        if (size < k->size) {
            fprintf(stderr, "smc: READ %s asked %u bytes, key is %u (0x87)\n", name, size, k->size);
            smc_reply(s, reply | SMC_KEY_SIZE_MISMATCH);
            return true;
        }
        if (s->debug) {
            fprintf(stderr, "smc: READ %s (%s) ->", name, k->type);
            for (unsigned i = 0; i < k->size; i++) fprintf(stderr, " %02x", k->data[i]);
            fprintf(stderr, "\n");
        }
        reply |= (uint64_t)k->size << 16;
        if (k->size <= 4) {
            uint32_t v = 0;
            memcpy(&v, k->data, k->size);
            reply |= (uint64_t)v << 32;
        } else if (!smc_shmem_rw(s, k->data, k->size, true)) {
            smc_reply(s, reply | SMC_KEY_NOT_READABLE);
            return true;
        }
        smc_reply(s, reply | SMC_OK);
        return true;
    }

    case SMC_WRITE_KEY: {
        SMCKey *k = smc_find(s, key);
        uint8_t buf[64] = { 0 };
        if (size <= sizeof(buf)) {
            smc_shmem_rw(s, buf, size, false);
        }
        fprintf(stderr, "smc: WRITE %s size %u:", name, size);
        for (unsigned i = 0; i < size && i < 16; i++) fprintf(stderr, " %02x", buf[i]);
        if (!k) {
            s->n_unknown++;
            fprintf(stderr, " (key not modelled, 0x84)\n");
            smc_reply(s, reply | SMC_KEY_NOT_FOUND);
            return true;
        }
        if (!k->writable) {
            fprintf(stderr, " (read-only, 0x86)\n");
            smc_reply(s, reply | SMC_KEY_NOT_WRITABLE);
            return true;
        }
        if (size != k->size) {
            fprintf(stderr, " (size mismatch, key is %u, 0x87)\n", k->size);
            smc_reply(s, reply | SMC_KEY_SIZE_MISMATCH);
            return true;
        }
        memcpy(k->data, buf, size);
        fprintf(stderr, " stored\n");
        smc_reply(s, reply | SMC_OK);
        return true;
    }

    case SMC_GET_KEY_BY_INDEX: {
        uint32_t index = key;
        if (index >= s->n_keys) {
            smc_reply(s, reply | SMC_KEY_NOT_FOUND);
            return true;
        }
        /* m1n1 decodes the value's little-endian bytes as the key text. */
        uint32_t v;
        memcpy(&v, s->keys[index].key, 4);
        smc_reply(s, reply | ((uint64_t)v << 32) | SMC_OK);
        return true;
    }

    case SMC_GET_KEY_INFO: {
        SMCKey *k = smc_find(s, key);
        if (!k) {
            s->n_unknown++;
            fprintf(stderr, "smc: GET_KEY_INFO %s: key not modelled (0x84)\n", name);
            smc_reply(s, reply | SMC_KEY_NOT_FOUND);
            return true;
        }
        /* m1n1 get_key_info: 6 bytes {size u8, type[4], flags u8} in shmem. */
        uint8_t info[6];
        info[0] = k->size;
        memcpy(info + 1, k->type, 4);
        info[5] = k->flags;
        smc_shmem_rw(s, info, sizeof(info), true);
        smc_reply(s, reply | ((uint64_t)6 << 16) | SMC_OK);
        return true;
    }

    case SMC_RW_KEY: {
        s->n_unknown++;
        fprintf(stderr, "smc: RW_KEY %s rsize %u wsize %u: not modelled (0x84)\n", name, size, wsize);
        smc_reply(s, reply | SMC_KEY_NOT_FOUND);
        return true;
    }

    default:
        fprintf(stderr, "smc: unknown message type 0x%02x (0x%016" PRIx64 ")\n", type, msg);
        smc_reply(s, reply | SMC_KEY_NOT_FOUND);
        return true;
    }
}

static const DarwinASCOps smc_asc_ops = {
    .handle = smc_handle,
};

static const VMStateDescription vmstate_darwin_smc_key = {
    .name = "darwin-smc/key",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT8_ARRAY(data, SMCKey, 64),
        VMSTATE_END_OF_LIST()
    },
};

static const VMStateDescription vmstate_darwin_smc = {
    .name = "darwin-smc",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_BOOL(initialized, DarwinSMC),
        VMSTATE_UINT64(n_msgs, DarwinSMC),
        VMSTATE_UINT64(n_unknown, DarwinSMC),
        VMSTATE_STRUCT_ARRAY(keys, DarwinSMC, SMC_MAX_KEYS, 1, vmstate_darwin_smc_key, SMCKey),
        VMSTATE_UINT8(batt.soc, DarwinSMC),
        VMSTATE_BOOL(batt.external, DarwinSMC),
        VMSTATE_BOOL(batt.charging, DarwinSMC),
        VMSTATE_END_OF_LIST()
    },
};

DeviceState *darwin_smc_create(struct dtree_node *dt_root, uint64_t iobase, DeviceState *aic)
{
    struct dtree_node *smc = adt_find_node(dt_root, "arm-io/smc");
    if (!smc || !adt_get_prop_val(smc, "compatible")) {
        return NULL;
    }
    struct dtree_node *nub = adt_find_node(dt_root, "arm-io/smc/iop-smc-nub");
    uint64_t *rb = nub ? adt_get_prop_val(nub, "region-base") : NULL;
    uint64_t *rs = nub ? adt_get_prop_val(nub, "region-size") : NULL;
    if (!rb || !rs || !*rb || *rs < SMC_SHMEM_OFFSET + SMC_SHMEM_SIZE) {
        fprintf(stderr, "darwin-smc: iop-smc-nub has no usable region-base/region-size; "
                "leaving the SMC as a bare RTKit mailbox\n");
        return NULL;
    }

    DarwinSMC *s = g_new0(DarwinSMC, 1);
    g_smc = s;
    s->debug = getenv("DARWIN_SMC_DEBUG") != NULL;
    s->region_base = *rb;
    s->region_size = *rs;
    s->shmem = s->region_base + SMC_SHMEM_OFFSET;

    /* The firmware region is not DRAM on this machine; give it real memory
     * so the shared buffer the endpoint maps by physical address is backed. */
    memory_region_init_ram(&s->region, NULL, "darwin-smc.region", s->region_size, &error_fatal);
    memory_region_add_subregion(get_system_memory(), s->region_base, &s->region);

    smc_populate(s);

    static const uint8_t smc_eps[] = { SMC_EP };
    s->asc = darwin_asc_create(smc, iobase, aic, smc_eps, ARRAY_SIZE(smc_eps), &smc_asc_ops, s);
    g_assert(vmstate_register(NULL, 0, &vmstate_darwin_smc, s) == 0);
    fprintf(stderr, "darwin-smc: key endpoint 0x%02x, firmware region 0x%" PRIx64 "+0x%" PRIx64
            ", shared buffer 0x%" PRIx64 ", %u keys\n", SMC_EP, s->region_base, s->region_size,
            s->shmem, s->n_keys);
    return s->asc;
}
