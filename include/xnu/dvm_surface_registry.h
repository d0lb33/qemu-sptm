#ifndef DVM_SURFACE_REGISTRY_H
#define DVM_SURFACE_REGISTRY_H
/* DVM-owned experimental ABI, not Apple register semantics. Kernel-only third
 * DT aperture, +0x100 length/begin, +0x108 first-page byte offset, +0x110 page,
 * +0x118 commit (read: new ID), +0x120 retire ID, +0x128 status, +0x130 poison,
 * +0x138 read-only registry version (1).
 * Set offset BEFORE begin. Pages must come from a prepared caller descriptor.
 * The model publishes a 64-byte LE header: magic, version, session[16], ID,
 * byte length, first-page offset, page count; then LE64 DRAM file offsets.
 * Retirement requires a host-created 32-byte tombstone: session[16], ID, magic.
 * IDs never repeat in a VM. Host mappings must disappear BEFORE the tombstone.
 * Client death/host loss without this handshake leaks pinned pages; no recovery
 * or checkpoint support is implied. Byte spans and mapped page spans differ.
 */
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#define DVM_SURFACE_MAGIC UINT64_C(0x31524753564d44)
#define DVM_SURFACE_RETIRED_MAGIC UINT64_C(0x31544552564d44)
#define DVM_SURFACE_VERSION 1
#define DVM_SURFACE_PAGE 16384u
#define DVM_SURFACE_DRAM_BASE UINT64_C(0x10000000000)
#define DVM_SURFACE_DRAM_BYTES UINT64_C(0x300000000)
#define DVM_SURFACE_SLOTS 64u
#define DVM_SURFACE_MAX_BYTES (64u * 1024u * 1024u)
#define DVM_SURFACE_MAX_PAGES (DVM_SURFACE_MAX_BYTES / DVM_SURFACE_PAGE + 1u)
#define DVM_SURFACE_TOTAL_BYTES (256u * 1024u * 1024u)
#define DVM_SURFACE_LEGACY_OWNER (DVM_SURFACE_SLOTS + 1u)
enum {
    DVM_SURFACE_OK, DVM_SURFACE_ARGUMENT, DVM_SURFACE_BUSY,
    DVM_SURFACE_CAPACITY, DVM_SURFACE_RANGE, DVM_SURFACE_ALIAS,
    DVM_SURFACE_IO, DVM_SURFACE_STALE, DVM_SURFACE_POISONED
};
typedef struct DVMSurfaceRecord {
    uint64_t id, length, offset;
    uint32_t count, expected;
    bool active;
    uint64_t pages[DVM_SURFACE_MAX_PAGES]; /* aligned physical addresses */
} DVMSurfaceRecord;
typedef struct DVMSurfaceRegistry {
    DVMSurfaceRecord records[DVM_SURFACE_SLOTS];
    uint8_t owners[DVM_SURFACE_DRAM_BYTES / DVM_SURFACE_PAGE];
    uint64_t next_id, last_id, active_bytes, next_offset;
    unsigned pending, status;
    bool poisoned;
} DVMSurfaceRegistry;
static inline void dvm_surface_abort(DVMSurfaceRegistry *s)
{
    if (s->pending) {
        DVMSurfaceRecord *r = &s->records[s->pending - 1];
        for (unsigned i = 0; i < r->count; i++) {
            s->owners[(r->pages[i] - DVM_SURFACE_DRAM_BASE) / DVM_SURFACE_PAGE] = 0;
        }
        memset(r, 0, sizeof(*r));
        s->pending = 0;
    }
}
static inline unsigned dvm_surface_begin(DVMSurfaceRegistry *s, uint64_t length)
{
    dvm_surface_abort(s);
    s->last_id = 0;
    if (s->poisoned) {
        return s->status = DVM_SURFACE_POISONED;
    }
    if (!length || length > DVM_SURFACE_MAX_BYTES || s->next_offset >= DVM_SURFACE_PAGE) {
        return s->status = DVM_SURFACE_ARGUMENT;
    }
    uint32_t count = (length + s->next_offset + DVM_SURFACE_PAGE - 1) / DVM_SURFACE_PAGE;
    if (s->active_bytes + (uint64_t)count * DVM_SURFACE_PAGE > DVM_SURFACE_TOTAL_BYTES || s->next_id == UINT32_MAX) {
        return s->status = DVM_SURFACE_CAPACITY;
    }
    for (unsigned i = 0; i < DVM_SURFACE_SLOTS; i++) {
        if (!s->records[i].active) {
            DVMSurfaceRecord *r = &s->records[i];
            memset(r, 0, sizeof(*r));
            r->id = ++s->next_id;
            r->length = length;
            r->offset = s->next_offset;
            r->expected = count;
            s->pending = i + 1;
            return s->status = DVM_SURFACE_OK;
        }
    }
    return s->status = DVM_SURFACE_CAPACITY;
}
static inline unsigned dvm_surface_page(DVMSurfaceRegistry *s, uint64_t page)
{
    if (s->status) {
        return s->status;
    }
    if (!s->pending) {
        return s->status = DVM_SURFACE_ARGUMENT;
    }
    DVMSurfaceRecord *r = &s->records[s->pending - 1];
    if (r->count == r->expected || (page & (DVM_SURFACE_PAGE - 1)) ||
        page < DVM_SURFACE_DRAM_BASE || page >= DVM_SURFACE_DRAM_BASE + DVM_SURFACE_DRAM_BYTES) {
        return s->status = DVM_SURFACE_RANGE;
    }
    unsigned index = (page - DVM_SURFACE_DRAM_BASE) / DVM_SURFACE_PAGE;
    if (s->owners[index]) {
        return s->status = DVM_SURFACE_ALIAS;
    }
    s->owners[index] = s->pending;
    r->pages[r->count++] = page;
    return DVM_SURFACE_OK;
}
static inline DVMSurfaceRecord *dvm_surface_ready(DVMSurfaceRegistry *s)
{
    if (s->status) {
        return NULL;
    }
    if (!s->pending || s->records[s->pending - 1].count != s->records[s->pending - 1].expected) {
        s->status = DVM_SURFACE_ARGUMENT;
        return NULL;
    }
    return &s->records[s->pending - 1];
}
static inline void dvm_surface_activate(DVMSurfaceRegistry *s)
{
    DVMSurfaceRecord *r = dvm_surface_ready(s);
    if (!r) {
        return;
    }
    r->active = true;
    s->active_bytes += (uint64_t)r->count * DVM_SURFACE_PAGE;
    s->last_id = r->id;
    s->pending = 0;
}
static inline DVMSurfaceRecord *dvm_surface_find(DVMSurfaceRegistry *s, uint64_t id)
{
    for (unsigned i = 0; i < DVM_SURFACE_SLOTS; i++) {
        if (s->records[i].active && s->records[i].id == id) {
            return &s->records[i];
        }
    }
    return NULL;
}
/* Call only after the actual host retirement record was validated. */
static inline unsigned dvm_surface_retire(DVMSurfaceRegistry *s, uint64_t id)
{
    DVMSurfaceRecord *r = dvm_surface_find(s, id);
    if (!r || !id) {
        return s->status = DVM_SURFACE_STALE;
    }
    for (unsigned i = 0; i < r->count; i++) {
        s->owners[(r->pages[i] - DVM_SURFACE_DRAM_BASE) / DVM_SURFACE_PAGE] = 0;
    }
    s->active_bytes -= (uint64_t)r->count * DVM_SURFACE_PAGE;
    memset(r, 0, sizeof(*r));
    return s->status = DVM_SURFACE_OK;
}
#endif
