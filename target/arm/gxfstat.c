/*
 * gxfstat.c - see include/xnu/gxfstat.h. Measurement scaffolding for the
 * HVF-acceleration study; counts guest events that would be VM exits under
 * Hypervisor.framework. Not part of the emulated machine.
 */
#include "qemu/osdep.h"
#include "xnu/gxfstat.h"

#include <pthread.h>
#include <time.h>

uint64_t gxfstat_genter;
bool gxfstat_enabled = true;
uint64_t gxfstat_gexit;
uint64_t gxfstat_sysreg_rd;
uint64_t gxfstat_sysreg_wr;
uint64_t gxfstat_mmio_rd;
uint64_t gxfstat_mmio_wr;
uint64_t gxfstat_exc[GXFSTAT_NEXC];
uint64_t gxfstat_genter_el[4];
uint64_t gxfstat_gexit_el[4];
uint64_t gxfstat_sysreg_el[4];

static double gxfstat_t0;

/*
 * Per-register histogram. Open addressing keyed on the ARMCPRegInfo .name
 * pointer (a static string, so the pointer is a stable identity). Sized well
 * above the ~300 entries in apple_sysregs[] so it never fills.
 */
#define GXFSTAT_NREG 2048
static struct {
    const char *name;
    uint64_t rd, wr;
} gxfstat_regtab[GXFSTAT_NREG];

void gxfstat_note_sysreg(const char *name, int el, int is_write)
{
    if (!gxfstat_enabled) {
        return;
    }
    uintptr_t h = ((uintptr_t)name >> 4) & (GXFSTAT_NREG - 1);

    gxfstat_sysreg_el[el & 3]++;
    if (is_write) {
        gxfstat_sysreg_wr++;
    } else {
        gxfstat_sysreg_rd++;
    }

    for (int i = 0; i < GXFSTAT_NREG; i++) {
        int j = (h + i) & (GXFSTAT_NREG - 1);
        if (gxfstat_regtab[j].name == NULL) {
            gxfstat_regtab[j].name = name;
        }
        if (gxfstat_regtab[j].name == name) {
            if (is_write) {
                gxfstat_regtab[j].wr++;
            } else {
                gxfstat_regtab[j].rd++;
            }
            return;
        }
    }
}

static void gxfstat_dump_regs(void)
{
    int idx[GXFSTAT_NREG], n = 0;

    for (int i = 0; i < GXFSTAT_NREG; i++) {
        if (gxfstat_regtab[i].name) {
            idx[n++] = i;
        }
    }
    /* insertion sort by total, descending; n is small */
    for (int i = 1; i < n; i++) {
        int k = idx[i], j = i - 1;
        uint64_t kv = gxfstat_regtab[k].rd + gxfstat_regtab[k].wr;
        while (j >= 0 &&
               gxfstat_regtab[idx[j]].rd + gxfstat_regtab[idx[j]].wr < kv) {
            idx[j + 1] = idx[j];
            j--;
        }
        idx[j + 1] = k;
    }
    for (int i = 0; i < n && i < 25; i++) {
        int k = idx[i];
        fprintf(stderr, "gxfstat reg %-24s rd=%llu wr=%llu\n",
                gxfstat_regtab[k].name,
                (unsigned long long)gxfstat_regtab[k].rd,
                (unsigned long long)gxfstat_regtab[k].wr);
    }
    fprintf(stderr, "gxfstat reg: %d distinct Apple IMP-DEF registers touched\n", n);
    fflush(stderr);
}

static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

void gxfstat_dump(const char *why)
{
    char excbuf[512];
    int n = 0;
    excbuf[0] = '\0';
    for (int i = 0; i < GXFSTAT_NEXC; i++) {
        if (gxfstat_exc[i] && n < (int)sizeof(excbuf) - 32) {
            n += snprintf(excbuf + n, sizeof(excbuf) - n, " e%d=%llu",
                          i, (unsigned long long)gxfstat_exc[i]);
        }
    }
    fprintf(stderr,
            "gxfstat %s t=%.3f genter=%llu gexit=%llu sysrd=%llu syswr=%llu "
            "mmiord=%llu mmiowr=%llu "
            "genterEL=%llu/%llu/%llu/%llu gexitEL=%llu/%llu/%llu/%llu "
            "sysEL=%llu/%llu/%llu/%llu exc:%s\n",
            why, now_s() - gxfstat_t0,
            (unsigned long long)gxfstat_genter,
            (unsigned long long)gxfstat_gexit,
            (unsigned long long)gxfstat_sysreg_rd,
            (unsigned long long)gxfstat_sysreg_wr,
            (unsigned long long)gxfstat_mmio_rd,
            (unsigned long long)gxfstat_mmio_wr,
            (unsigned long long)gxfstat_genter_el[0],
            (unsigned long long)gxfstat_genter_el[1],
            (unsigned long long)gxfstat_genter_el[2],
            (unsigned long long)gxfstat_genter_el[3],
            (unsigned long long)gxfstat_gexit_el[0],
            (unsigned long long)gxfstat_gexit_el[1],
            (unsigned long long)gxfstat_gexit_el[2],
            (unsigned long long)gxfstat_gexit_el[3],
            (unsigned long long)gxfstat_sysreg_el[0],
            (unsigned long long)gxfstat_sysreg_el[1],
            (unsigned long long)gxfstat_sysreg_el[2],
            (unsigned long long)gxfstat_sysreg_el[3],
            excbuf);
    fflush(stderr);
}

static void gxfstat_atexit(void)
{
    gxfstat_dump("final");
    gxfstat_dump_regs();
}

static void *gxfstat_thread(void *unused)
{
    for (;;) {
        struct timespec req = { .tv_sec = 1, .tv_nsec = 0 };
        nanosleep(&req, NULL);
        gxfstat_dump("tick");
    }
    return NULL;
}

void gxfstat_start(void)
{
    static bool started;
    if (started || !gxfstat_enabled) {
        return;
    }
    started = true;
    const char *e = getenv("DARWIN_GXFSTAT");
    pthread_t th;

    gxfstat_t0 = now_s();
    atexit(gxfstat_atexit);
    if (e && e[0] == '0') {
        return;                 /* counters still run; no periodic line */
    }
    pthread_create(&th, NULL, gxfstat_thread, NULL);
    pthread_detach(th);
}
