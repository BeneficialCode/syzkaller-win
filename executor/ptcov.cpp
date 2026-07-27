// ptcov.cpp - see ptcov.h

#include "ptcov.h"

#include <intel-pt.h>
#include <stdlib.h>
#include <string.h>

// Phase timing uses the TSC directly: it is an x86 instruction, so it costs nothing in
// portability and avoids pulling a clock API into this file.
#if defined(_MSC_VER)
#include <intrin.h>
#define PTCOV_TSC() __rdtsc()
#elif defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
#include <x86intrin.h>
#define PTCOV_TSC() __rdtsc()
#else
#define PTCOV_TSC() 0
#endif

// Only the normalized-PC encoding constants are wanted here; PTCOV_ENCODING_ONLY skips the
// IOCTL half of that header so this file stays free of any OS dependency.
#define PTCOV_ENCODING_ONLY
// Flat path, not "../include/...": this is the executor's own mirror of the ptrace tree,
// and syzkaller compiles executor sources from the repository root. Re-copying these files
// from D:\src\cpp\ptrace overwrites this line, so check it afterwards.
#include "ptcov_ioctl.h"

struct ptcov_decoder {
    const ptcov_module*             mods;
    uint32_t                        nmods;
    struct pt_image*                image;
    struct pt_image_section_cache*  iscache;   // NULL when every module uses the callback
    int                             last_error;
    uint32_t                        unmapped;
    uint32_t                        sections;  // cached sections added
};

// libipt asks for instruction bytes at an IP. Serve them from the loaded-image snapshot,
// honouring the page validity map and never crossing into an invalid page: returning fewer
// bytes than asked for is legal and lets libipt fail cleanly at the boundary rather than
// decoding recycled memory as instructions.
static int ptcov_read_memory(uint8_t* buffer, size_t size, const struct pt_asid* asid,
                             uint64_t ip, void* context)
{
    (void)asid;
    ptcov_decoder* dec = (ptcov_decoder*)context;

    for (uint32_t i = 0; i < dec->nmods; i++) {
        const ptcov_module* m = &dec->mods[i];
        if (ip < m->base || ip >= m->base + m->size)
            continue;

        uint32_t off = (uint32_t)(ip - m->base);
        uint32_t page = off / PTCOV_PAGE_SIZE;
        if (m->pagemap && !m->pagemap[page]) {
            dec->unmapped++;
            return -pte_nomap;
        }

        // Clamp to the end of this page, then to the end of the image. Stopping at the page
        // boundary keeps us from silently reading across into a page the map rejects.
        uint32_t page_end = (page + 1) * PTCOV_PAGE_SIZE;
        uint32_t avail = page_end - off;
        if (m->base + page_end > m->base + m->size)
            avail = m->size - off;
        if (avail > size)
            avail = (uint32_t)size;

        memcpy(buffer, m->bytes + off, avail);
        return (int)avail;
    }

    dec->unmapped++;
    return -pte_nomap;
}

// Add one cached section per maximal run of valid pages.
//
// Splitting on the page map rather than adding the whole image as a single section keeps the
// benefit of the validity information: an address in a freed discardable section maps to no
// section at all, so the decoder fails fast instead of disassembling recycled memory into
// plausible-looking garbage.
static int ptcov_add_cached_module(ptcov_decoder* dec, const ptcov_module* m)
{
    uint32_t npages = (m->size + PTCOV_PAGE_SIZE - 1) / PTCOV_PAGE_SIZE;

    if (!m->pagemap) {
        int isid = pt_iscache_add_file(dec->iscache, m->image_path, 0, m->size, m->base);
        if (isid < 0)
            return isid;
        dec->sections++;
        return pt_image_add_cached(dec->image, dec->iscache, isid, NULL);
    }

    for (uint32_t p = 0; p < npages;) {
        if (!m->pagemap[p]) {
            p++;
            continue;
        }
        uint32_t start = p;
        while (p < npages && m->pagemap[p])
            p++;
        uint64_t off = (uint64_t)start * PTCOV_PAGE_SIZE;
        uint64_t len = (uint64_t)(p - start) * PTCOV_PAGE_SIZE;
        if (off + len > m->size)
            len = m->size - off;

        int isid = pt_iscache_add_file(dec->iscache, m->image_path, off, len, m->base + off);
        if (isid < 0)
            return isid;
        dec->sections++;
        int errcode = pt_image_add_cached(dec->image, dec->iscache, isid, NULL);
        if (errcode < 0)
            return errcode;
    }
    return 0;
}

ptcov_decoder* ptcov_create(const ptcov_module* mods, uint32_t nmods)
{
    if (!mods || !nmods)
        return NULL;

    ptcov_decoder* dec = (ptcov_decoder*)calloc(1, sizeof(*dec));
    if (!dec)
        return NULL;

    dec->mods = mods;
    dec->nmods = nmods;

    // One image reused for the process lifetime; rebuilding it per program would mean
    // re-reading megabytes of driver text on every execution.
    dec->image = pt_image_alloc("ptcov");
    if (!dec->image) {
        free(dec);
        return NULL;
    }

    int need_callback = 0;
    for (uint32_t i = 0; i < nmods; i++) {
        if (mods[i].image_path)
            continue;
        need_callback = 1;
        break;
    }

    int any_cached = 0;
    for (uint32_t i = 0; i < nmods; i++) {
        if (!mods[i].image_path)
            continue;
        if (!dec->iscache) {
            dec->iscache = pt_iscache_alloc(NULL);
            if (!dec->iscache) {
                ptcov_destroy(dec);
                return NULL;
            }
        }
        if (ptcov_add_cached_module(dec, &mods[i]) < 0) {
            ptcov_destroy(dec);
            return NULL;
        }
        any_cached = 1;
    }

    // The callback is a whole-image fallback, so only install it when some module has no
    // file. It would otherwise also be consulted for gaps between cached sections, defeating
    // the fail-fast behaviour those gaps exist to provide.
    if (need_callback && !any_cached) {
        if (pt_image_set_callback(dec->image, ptcov_read_memory, dec) < 0) {
            ptcov_destroy(dec);
            return NULL;
        }
    } else if (need_callback) {
        ptcov_destroy(dec);
        return NULL;   // mixing file-backed and callback modules is not supported
    }
    return dec;
}

void ptcov_destroy(ptcov_decoder* dec)
{
    if (!dec)
        return;
    if (dec->image)
        pt_image_free(dec->image);
    if (dec->iscache)
        pt_iscache_free(dec->iscache);
    free(dec);
}

const char* ptcov_last_error(const ptcov_decoder* dec)
{
    if (!dec || !dec->last_error)
        return "none";
    return pt_errstr(pt_errcode(dec->last_error));
}

static uint32_t ptcov_normalize(const ptcov_decoder* dec, uint64_t va, int* found)
{
    for (uint32_t i = 0; i < dec->nmods; i++) {
        const ptcov_module* m = &dec->mods[i];
        if (va >= m->base && va < m->base + m->size) {
            *found = 1;
            uint32_t off = (uint32_t)(va - m->base);
            return (m->index << PTCOV_MODULE_SHIFT) | (off & PTCOV_OFFSET_MASK);
        }
    }
    *found = 0;
    return 0;
}

int ptcov_decode(ptcov_decoder* dec, const uint8_t* buf, size_t len,
                 const uint64_t* boundaries, uint32_t nboundaries,
                 ptcov_emit_fn emit, void* ctx, ptcov_stats* stats)
{
    if (!dec || !buf || !emit)
        return -1;

    ptcov_stats st;
    memset(&st, 0, sizeof(st));
    dec->unmapped = 0;

    if (!len) {
        if (stats)
            *stats = st;
        return 0;
    }

    struct pt_config config;
    memset(&config, 0, sizeof(config));
    config.size = sizeof(config);
    config.begin = (uint8_t*)buf;
    config.end = (uint8_t*)buf + len;
    // cpu left zeroed: decode to spec, matching ptxed's default so results are comparable.

    uint64_t t_begin = PTCOV_TSC();

    struct pt_block_decoder* ptdec = pt_blk_alloc_decoder(&config);
    if (!ptdec) {
        dec->last_error = -pte_nomem;
        return -1;
    }
    if (pt_blk_set_image(ptdec, dec->image) < 0) {
        pt_blk_free_decoder(ptdec);
        dec->last_error = -pte_internal;
        return -1;
    }

    st.tsc_setup = PTCOV_TSC() - t_begin;

    uint32_t call_index = 0;
    uint64_t sync = 0;

    // Structure mirrors ptxed's decode_block(): sync, then alternate between draining events
    // and pulling blocks, and on error try to re-sync but bail if we made no progress.
    for (;;) {
        uint64_t t_sync = PTCOV_TSC();
        int status = pt_blk_sync_forward(ptdec);
        st.tsc_sync += PTCOV_TSC() - t_sync;
        if (status < 0) {
            if (status == -pte_eos)
                break;
            dec->last_error = status;
            st.sync_errors++;

            uint64_t new_sync = 0;
            if (pt_blk_get_offset(ptdec, &new_sync) < 0 || new_sync <= sync)
                break;
            sync = new_sync;
            st.resyncs++;
            continue;
        }

        uint64_t t_loop = PTCOV_TSC();
        for (;;) {
            while (status & pts_event_pending) {
                struct pt_event event;
                status = pt_blk_event(ptdec, &event, sizeof(event));
                if (status < 0)
                    break;
                if (event.type == ptev_enabled)
                    st.enabled++;
                else if (event.type == ptev_disabled)
                    st.disabled++;
            }
            if (status < 0)
                break;

            if (status & pts_eos) {
                status = -pte_eos;
                break;
            }

            struct pt_block block;
            memset(&block, 0, sizeof(block));
            status = pt_blk_next(ptdec, &block, sizeof(block));
            if (status < 0)
                break;

            // Attribute to a call slice by where we are in the trace stream. This is why the
            // whole program is decoded in one pass instead of once per call: a per-slice
            // decoder would need a PSB inside every slice.
            if (nboundaries) {
                uint64_t off = 0;
                if (pt_blk_get_offset(ptdec, &off) >= 0) {
                    while (call_index < nboundaries && off > boundaries[call_index])
                        call_index++;
                }
            }

            st.raw_blocks++;
            if (block.ninsn == 0)
                st.empty_blocks++;

            int found = 0;
            uint32_t norm = ptcov_normalize(dec, block.ip, &found);
            if (found) {
                st.blocks++;
                st.insns += block.ninsn;
                emit(ctx, (int)call_index, norm, block.ip);
            } else {
                st.dropped_blocks++;
            }
        }

        st.tsc_loop += PTCOV_TSC() - t_loop;

        if (status == -pte_eos)
            break;

        dec->last_error = status;
        st.decode_errors++;

        uint64_t new_sync = 0;
        if (pt_blk_get_offset(ptdec, &new_sync) < 0 || new_sync <= sync)
            break;
        sync = new_sync;
        st.resyncs++;
    }

    uint64_t t_free = PTCOV_TSC();
    pt_blk_free_decoder(ptdec);
    st.tsc_teardown = PTCOV_TSC() - t_free;
    st.tsc_total = PTCOV_TSC() - t_begin;
    st.unmapped = dec->unmapped;
    if (stats)
        *stats = st;
    return 0;
}
