// ptcov.h - Intel PT trace -> coverage PCs.
//
// Turns a raw Intel PT buffer into the normalized basic-block PCs that syzkaller's coverage
// machinery consumes, optionally sliced per syscall.
//
// Deliberately free of any Windows or syzkaller dependency so the exact same code can be
// driven three ways: offline from files by ptcovtest (which is how it gets validated against
// ptxed), inside syz-executor via executor/cover_pt.h, and by any future host-side tool.
//
// Normalized PC encoding (see include/ptcov_ioctl.h):
//     norm_pc = (module_index << PTCOV_MODULE_SHIFT) | (va - module_base)
// A raw VA is useless as a coverage identifier because KASLR moves every module on each boot,
// so a corpus keyed on VAs stops being portable across reboots.

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PTCOV_PAGE_SIZE 4096

// One traced module's bytes, as read out of kernel memory.
typedef struct ptcov_module {
    uint64_t       base;      // runtime load address
    uint32_t       size;      // SizeOfImage
    uint32_t       index;     // module index used when normalizing PCs

    // Path to a file holding the loaded image, laid out exactly as in memory (offset 0 ==
    // `base`). PREFERRED over `bytes`: libipt only enables its block cache for sections added
    // through an image-section cache, which is both markedly faster and the configuration
    // ptxed uses - so cross-validating against ptxed is only meaningful this way.
    // The caller writes this file once (e.g. right after dumping the image) and keeps it.
    const char*    image_path;

    // Fallback used only when image_path is NULL: `size` bytes of the loaded image, served
    // to libipt through a read callback. Correct, but no block cache.
    const uint8_t* bytes;
    // One byte per PTCOV_PAGE_SIZE page, non-zero = this page holds valid code.
    //
    // A page must be marked invalid both when it could not be read AND when it belongs to a
    // discardable section: those are freed after load, so the memory still reads fine but
    // holds whatever now occupies it. Handing that to the decoder as if it were code produces
    // a long run of bogus instructions. Building this map is the caller's job because only it
    // knows the PE section table.
    const uint8_t* pagemap;
} ptcov_module;

typedef struct ptcov_decoder ptcov_decoder;

// Called once per decoded basic block. `call_index` is the slice the block fell into, or 0
// when decoding without boundaries.
typedef void (*ptcov_emit_fn)(void* ctx, int call_index, uint32_t norm_pc, uint64_t va);

typedef struct ptcov_stats {
    // Every successful pt_blk_next, including blocks we do not emit. Kept separate from
    // `blocks` so this can be compared directly against ptxed's --stat:blocks.
    uint32_t raw_blocks;
    uint32_t empty_blocks;    // raw blocks with ninsn == 0
    uint32_t dropped_blocks;  // raw blocks whose ip fell outside every known module
    uint32_t blocks;          // basic blocks emitted
    uint32_t insns;           // instructions covered by those blocks
    uint32_t enabled;         // tracing-enabled events (TIP.PGE)
    uint32_t disabled;        // tracing-disabled events (TIP.PGD)
    uint32_t sync_errors;     // failures to find a sync point
    uint32_t decode_errors;   // decode failures after a successful sync
    uint32_t unmapped;        // reads that fell outside any valid module page
    uint32_t resyncs;         // successful re-syncs after an error

    // Raw TSC deltas per phase, so a caller can tell fixed per-decode overhead apart from
    // work that scales with trace length. Left in cycles rather than converted here to keep
    // this file free of any timing API; the caller knows its own TSC rate.
    uint64_t tsc_setup;       // pt_blk_alloc_decoder + pt_blk_set_image
    uint64_t tsc_sync;        // all pt_blk_sync_forward calls
    uint64_t tsc_loop;        // the event/block decode loop
    uint64_t tsc_teardown;    // pt_blk_free_decoder
    uint64_t tsc_total;       // whole ptcov_decode call
} ptcov_stats;

// `mods` must stay alive for the decoder's lifetime.
ptcov_decoder* ptcov_create(const ptcov_module* mods, uint32_t nmods);
void ptcov_destroy(ptcov_decoder* dec);

// Decode [buf, buf+len).
//
// `boundaries` holds `nboundaries` monotonically increasing byte offsets into the trace,
// as returned by PTCOV_SNAPSHOT at each syscall boundary. A block whose trace offset is
// below boundaries[0] belongs to call 0, below boundaries[1] to call 1, and so on. Pass
// nboundaries == 0 to attribute everything to call 0.
//
// Returns 0 on success (including a trace that simply ended), negative on hard failure.
int ptcov_decode(ptcov_decoder* dec, const uint8_t* buf, size_t len,
                 const uint64_t* boundaries, uint32_t nboundaries,
                 ptcov_emit_fn emit, void* ctx, ptcov_stats* stats);

// Human-readable name for the last libipt error, for diagnostics.
const char* ptcov_last_error(const ptcov_decoder* dec);

#ifdef __cplusplus
}
#endif
