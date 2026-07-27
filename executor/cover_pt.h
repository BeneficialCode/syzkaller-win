// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Intel PT backed coverage for Windows, replacing nocover.h.
//
// Where KCOV hands the executor a ready-made array of basic block PCs, here the hardware hands
// us a compressed branch trace that has to be decoded first. The shape of this file follows
// from one decision: cover_collect() writes its result in EXACTLY the kcov layout
// (count, then PCs, with data_offset == sizeof(uint64) and pc_offset == 0), so that
// write_coverage_signal(), hash(), dedup(), write_output() and write_extra_output() in
// executor.cc are reused verbatim. Nothing above this file knows PT exists.
//
// Coverage is attributed PER CALL: every cover_reset rewinds the hardware write pointer to the
// start of the ToPA buffer and resumes tracing, and the matching cover_collect pauses tracing
// and decodes exactly what that one syscall produced.
//
// Rewinding per call rather than slicing one growing buffer is not an arbitrary choice. libipt
// can only start decoding at a PSB, and MEASURED ON THIS HARDWARE, re-enabling TraceEn does NOT
// emit one: PSBs appear only at the periodic PSBFreq interval, about every 2 KB. Slices of a
// shared buffer are therefore not independently decodable - captured with 8 boundaries, slice 0
// decoded to 1610 blocks and slices 1..7 to nothing at all, with no reported error. After a
// rewind, though, offset 0 always holds a PSB (verified: 4/4 slices, 0 sync errors,
// ~700 blocks each), so each call's buffer is a self-contained trace.
//
// What that costs is the `extra` channel. There is one PT buffer per CPU, so rewinding for each
// call discards whatever accumulated between calls; extra_cov therefore always reports size 0
// here. Nothing is silently misattributed, and background coverage is meant to come from
// tracing the OTHER CPUs instead, which needs its own buffers.
//
// Configuration: the traced module's name is read from a file named "syz-pt-target" sitting
// next to the executor binary (the same convention syz-cover-bitmap already uses), or from the
// SYZ_PT_TARGET environment variable, which takes precedence.

#pragma once

#include <winioctl.h> // CTL_CODE, for ptcov_ioctl.h

#include "ptcov.h"
#include "ptcov_ioctl.h"

// Mirrors kCoverSize: the same 2 MB worth of PCs the Linux executor gives KCOV.
// One BELOW kCoverSize, not equal to it. execute_call treats cov.size >= kCoverSize as a fatal
// "too much cover", so a count that lands exactly on the cap kills the executor. Measured: with
// ntoskrnl as the traced module that happens after a few thousand programs, because a single
// syscall there really can produce more than 256K basic blocks. Truncating instead of dying is
// also what KCOV does when it reaches the end of its mmap.
static const uint32 kPtMaxPCs = (uint32)kCoverSize - 1;
// Per-CPU ToPA size. With the IP filter narrowed to one module and only branch packets
// enabled, a program's trace is normally single-digit KB, so this is generous.
static const uint32 kPtTraceSize = 4 << 20;

// argv[0], stashed by os_init so cover_open can find files next to the executor.
static const char* g_pt_argv0 = NULL;

struct pt_state {
	HANDLE dev;
	uint32 cpu;
	bool active; // START_TRACE succeeded

	char module[PTCOV_MODULE_NAME_MAX];
	uint64 image_base;
	uint32 image_size;
	uint8* image_bytes;
	uint8* pagemap;

	ptcov_module mod;
	ptcov_decoder* dec;

	uint8* trace; // user-mode VA of the ToPA buffer, mapped by the driver

	// One hardware buffer serves every thread in this process, so two calls that overlap in
	// time cannot be told apart in it. Async calls (Props.Async) and calls that outlive their
	// timeout both produce that overlap. `inflight` counts calls between reset and collect;
	// `taint` latches once it ever exceeds one and clears when the last one finishes. A tainted
	// window reports no coverage at all: attributing one call's blocks to another would feed
	// the fuzzer a signal that is not merely incomplete but wrong.
	CRITICAL_SECTION lock;
	uint32 inflight;
	bool taint;

	uint64 overflows; // ToPA filled up and tracing stopped
	uint64 unattributed; // calls dropped because their window was shared
	uint64 truncations; // calls with more blocks than the cover buffer holds
};

static pt_state g_pt;

// ------------------------------------------------------------------------------------------
// Driver plumbing
// ------------------------------------------------------------------------------------------

static bool pt_ioctl(DWORD code, void* in, DWORD inLen, void* out, DWORD outLen, DWORD* ret)
{
	DWORD n = 0;
	if (!DeviceIoControl(g_pt.dev, code, in, inLen, out, outLen, &n, NULL))
		return false;
	if (ret)
		*ret = n;
	return true;
}

static void pt_snapshot(uint32 flags, PTCOV_SNAPSHOT_RES* res)
{
	PTCOV_SNAPSHOT_REQ req;
	memset(&req, 0, sizeof(req));
	req.CpuId = g_pt.cpu;
	req.Flags = flags;
	memset(res, 0, sizeof(*res));
	if (!pt_ioctl(IOCTL_PTCOV_SNAPSHOT, &req, sizeof(req), res, sizeof(*res), NULL))
		failmsg("PTCOV_SNAPSHOT failed", "cpu=%u flags=0x%x err=%u", g_pt.cpu, flags, GetLastError());
}

// Read the traced module's name from SYZ_PT_TARGET, else from a "syz-pt-target" file next to
// the executor binary.
static void pt_read_target_name(char* out, size_t out_size)
{
	const char* env = getenv("SYZ_PT_TARGET");
	if (env && env[0]) {
		strncpy(out, env, out_size - 1);
		out[out_size - 1] = 0;
		return;
	}
	char path[1024] = {0};
	const char* base = g_pt_argv0 ? g_pt_argv0 : "";
	const char* sep = strrchr(base, '\\');
	if (!sep)
		sep = strrchr(base, '/');
	// A bare "syz-executor.exe" with no directory is legitimate, so fall back to the current
	// directory rather than computing a negative length off a NULL separator - the equivalent
	// code for syz-cover-bitmap in executor.cc has exactly that latent bug.
	size_t dirlen = sep ? (size_t)(sep - base) + 1 : 0;
	if (dirlen >= sizeof(path) - 32)
		fail("executor path is too long to locate syz-pt-target");
	memcpy(path, base, dirlen);
	strncat(path, "syz-pt-target", sizeof(path) - dirlen - 1);

	FILE* f = fopen(path, "rb");
	if (!f)
		failmsg("coverage is enabled but no PT target module is configured",
			"set SYZ_PT_TARGET or create %s", path);
	if (!fgets(out, (int)out_size, f))
		out[0] = 0;
	fclose(f);
	// Strip trailing whitespace/newlines left by an editor.
	for (size_t i = strlen(out); i > 0 && (unsigned char)out[i - 1] <= ' '; i--)
		out[i - 1] = 0;
	if (!out[0])
		failmsg("PT target module file is empty", "path=%s", path);
}

// Pull the whole loaded image out of kernel memory, plus a per-page validity map.
//
// Reading the LOADED bytes rather than the on-disk PE is not optional: measured on this target,
// ntoskrnl has 7153 bytes of loader-rewritten code across 2924 sites (retpoline / import
// optimization) that no relocation explains, and feeding the decoder disk bytes desynchronizes
// it there. Small third-party drivers may show none of that, but the decoder must not depend on
// which case it got.
static void pt_load_image()
{
	const uint32 kPage = 4096;
	uint32 npages = (g_pt.image_size + kPage - 1) / kPage;
	// VirtualAlloc, not malloc: executor.cc poisons malloc/calloc to keep the executor's memory
	// behaviour deterministic. VirtualAlloc also hands back zeroed pages, which the page map
	// relies on.
	g_pt.image_bytes = (uint8*)VirtualAlloc(NULL, g_pt.image_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	g_pt.pagemap = (uint8*)VirtualAlloc(NULL, npages, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!g_pt.image_bytes || !g_pt.pagemap)
		fail("out of memory reading the traced module image");

	uint32 okPages = 0;
	for (uint32 off = 0; off < g_pt.image_size;) {
		uint32 len = g_pt.image_size - off;
		if (len > PTCOV_READ_CODE_MAX_CHUNK)
			len = PTCOV_READ_CODE_MAX_CHUNK;
		PTCOV_READ_CODE_REQ req;
		memset(&req, 0, sizeof(req));
		req.Va = g_pt.image_base + off;
		req.Length = len;
		if (pt_ioctl(IOCTL_PTCOV_READ_CODE, &req, sizeof(req), g_pt.image_bytes + off, len, NULL)) {
			for (uint32 p = off / kPage; p < (off + len + kPage - 1) / kPage; p++) {
				if (p < npages && !g_pt.pagemap[p]) {
					g_pt.pagemap[p] = 1;
					okPages++;
				}
			}
			off += len;
			continue;
		}
		// A chunk straddling readable and freed pages fails as a whole; retry page by page so
		// the readable part is not thrown away with the rest.
		for (uint32 p = off; p < off + len; p += kPage) {
			uint32 plen = (off + len - p) < kPage ? (off + len - p) : kPage;
			req.Va = g_pt.image_base + p;
			req.Length = plen;
			if (pt_ioctl(IOCTL_PTCOV_READ_CODE, &req, sizeof(req), g_pt.image_bytes + p, plen, NULL)) {
				g_pt.pagemap[p / kPage] = 1;
				okPages++;
			}
		}
		off += len;
	}
	if (!okPages)
		failmsg("could not read any of the traced module", "module=%s", g_pt.module);

	// Discardable sections (INIT and friends) are freed after load, so their pages usually READ
	// fine but hold whatever was recycled into them. Marking them invalid keeps the decoder from
	// disassembling unrelated data if it ever wanders there; that code is never executed again,
	// so nothing real is lost.
	uint32 masked = 0;
	if (g_pt.image_size > 0x40) {
		uint32 e_lfanew = *(uint32*)(g_pt.image_bytes + 0x3C);
		if (e_lfanew + 4 + 20 + 2 < g_pt.image_size &&
		    memcmp(g_pt.image_bytes + e_lfanew, "PE\0\0", 4) == 0) {
			uint8* coff = g_pt.image_bytes + e_lfanew + 4;
			uint16 nsec = *(uint16*)(coff + 2);
			uint16 optsz = *(uint16*)(coff + 16);
			uint8* sec = coff + 20 + optsz;
			for (uint16 i = 0; i < nsec; i++) {
				uint8* s = sec + i * 40;
				if ((uint32)(s + 40 - g_pt.image_bytes) > g_pt.image_size)
					break;
				uint32 vsize = *(uint32*)(s + 8);
				uint32 vaddr = *(uint32*)(s + 12);
				uint32 chars = *(uint32*)(s + 36);
				if (!(chars & 0x02000000)) // IMAGE_SCN_MEM_DISCARDABLE
					continue;
				for (uint32 off = vaddr; off < vaddr + vsize; off += kPage) {
					uint32 p = off / kPage;
					if (p < npages && g_pt.pagemap[p]) {
						g_pt.pagemap[p] = 0;
						masked++;
					}
				}
			}
		}
	}
	debug("pt: image %s base=0x%llx size=0x%x pages=%u/%u (masked %u discardable)\n",
	      g_pt.module, (unsigned long long)g_pt.image_base, g_pt.image_size,
	      okPages - masked, npages, masked);
}

static void pt_start_trace()
{
	PT_USER_REQ req;
	memset(&req, 0, sizeof(req));
	req.kCpuAffinity = (KAFFINITY)1 << g_pt.cpu;
	req.TraceSize = kPtTraceSize;
	// No CYC/MTC/TSC: timing packets cost 5-20x the trace volume and coverage has no use for
	// them. Branch packets + ToPA + RET compression is what the decoder needs.
	req.OptsMask = PTCOV_RECOMMENDED_OPTS;
	req.ProcessId = GetCurrentProcessId();
	req.bTraceKernel = TRUE;
	req.bTraceUser = FALSE;
	req.IpFiltering.NumOfRanges = 1;
	req.IpFiltering.Ranges[0].pStartVa = (PVOID)(ULONG_PTR)g_pt.image_base;
	req.IpFiltering.Ranges[0].pEndVa = (PVOID)(ULONG_PTR)(g_pt.image_base + g_pt.image_size);
	req.IpFiltering.Ranges[0].bStopTrace = FALSE;

	PVOID bufs[64];
	memset(bufs, 0, sizeof(bufs));
	DWORD ret = 0;
	if (!pt_ioctl(IOCTL_WINIPT_START_TRACE, &req, sizeof(req), bufs, sizeof(bufs), &ret))
		failmsg("WINIPT_START_TRACE failed", "cpu=%u err=%u", g_pt.cpu, GetLastError());
	if (!bufs[0])
		fail("START_TRACE returned no user-mode buffer address");
	g_pt.trace = (uint8*)bufs[0];
	g_pt.active = true;
}

// ------------------------------------------------------------------------------------------
// The cover_* interface executor.cc expects
// ------------------------------------------------------------------------------------------

static void cover_open(cover_t* cov, bool extra)
{
	if (!flag_coverage)
		return;
	// Called once per thread plus once for extra_cov, but there is a single device, a single
	// CPU and a single trace buffer behind all of them.
	if (g_pt.dev)
		return;

	InitializeCriticalSection(&g_pt.lock);

	g_pt.dev = CreateFileA(PTCOV_DEVICE_PATH_UM, GENERIC_READ | GENERIC_WRITE,
			       0, NULL, OPEN_EXISTING, 0, NULL);
	if (g_pt.dev == INVALID_HANDLE_VALUE)
		failmsg("cannot open the Intel PT device", "path=%s err=%u (is ptrace.sys loaded, and "
			"is the executor running elevated?)", PTCOV_DEVICE_PATH_UM, GetLastError());

	// The driver traces per CPU, so pinning is what turns that into per-process attribution.
	// CPU 0 is left to the OS, sshd and syz-fuzzer.
	SYSTEM_INFO si;
	GetSystemInfo(&si);
	uint32 usable = si.dwNumberOfProcessors > 1 ? si.dwNumberOfProcessors - 1 : 1;
	g_pt.cpu = 1 + (uint32)(procid % usable);
	DWORD_PTR mask = (DWORD_PTR)1 << g_pt.cpu;
	if (!SetProcessAffinityMask(GetCurrentProcess(), mask) ||
	    !SetThreadAffinityMask(GetCurrentThread(), mask))
		failmsg("cannot pin to the traced CPU", "cpu=%u err=%u", g_pt.cpu, GetLastError());

	PTCOV_ATTACH_REQ att;
	memset(&att, 0, sizeof(att));
	att.CpuId = g_pt.cpu;
	if (!pt_ioctl(IOCTL_PTCOV_ATTACH, &att, sizeof(att), &att, sizeof(att), NULL))
		failmsg("PTCOV_ATTACH failed", "cpu=%u err=%u (another process may own this CPU)",
			g_pt.cpu, GetLastError());

	pt_read_target_name(g_pt.module, sizeof(g_pt.module));

	PTCOV_MODULE_INFO mi;
	memset(&mi, 0, sizeof(mi));
	strncpy(mi.Name, g_pt.module, sizeof(mi.Name) - 1);
	if (!pt_ioctl(IOCTL_PTCOV_QUERY_MODULE, &mi, sizeof(mi), &mi, sizeof(mi), NULL))
		failmsg("PTCOV_QUERY_MODULE failed", "module=%s err=%u", g_pt.module, GetLastError());
	g_pt.image_base = mi.ImageBase;
	g_pt.image_size = mi.ImageSize;

	pt_load_image();

	g_pt.mod.base = g_pt.image_base;
	g_pt.mod.size = g_pt.image_size;
	g_pt.mod.index = 0;
	g_pt.mod.bytes = g_pt.image_bytes;
	g_pt.mod.pagemap = g_pt.pagemap;
	// Callback-backed image on purpose. The file-backed cached path is measurably faster, but
	// libipt's block cache makes block boundaries depend on whether an address has been decoded
	// before: the first program to reach new code gets a different block split than later ones.
	// That is precisely the flaky signal that makes a corpus grow without bound.
	g_pt.mod.image_path = NULL;
	g_pt.dec = ptcov_create(&g_pt.mod, 1);
	if (!g_pt.dec)
		fail("ptcov_create failed");

	pt_start_trace();
}

static void cover_mmap(cover_t* cov)
{
	if (cov->data != NULL)
		return;
	// Plain heap, not a mapping: unlike KCOV nothing outside this process writes here, we fill
	// it ourselves from the decoder.
	uint32 bytes = (uint32)((kPtMaxPCs + 1) * sizeof(uint64));
	cov->data = (char*)VirtualAlloc(NULL, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!cov->data)
		fail("failed to allocate the coverage buffer");
	cov->data_end = cov->data + bytes;
	cov->mmap_alloc_size = bytes;
	// The kcov layout: [0] is the count, the PCs follow. Keeping this exact is what lets
	// write_coverage_signal be reused unchanged.
	cov->data_offset = sizeof(uint64);
	cov->pc_offset = 0;
	cov->size = 0;
}

static void cover_protect(cover_t* cov)
{
}

static void cover_unprotect(cover_t* cov)
{
}

static void cover_enable(cover_t* cov, bool collect_comps, bool extra)
{
	if (collect_comps)
		fail("comparison tracing is not available from Intel PT");
	// Tracing is started once in cover_open; each call's window is delimited by cover_reset
	// (rewind + resume) and cover_collect (pause), so there is nothing to enable per thread.
}

static void cover_reset(cover_t* cov)
{
	cov->size = 0;
	// extra_cov shares the one hardware buffer with the per-call channel and would only
	// re-report what a call already reported; see the file comment.
	if (cov == &extra_cov || !g_pt.active)
		return;

	EnterCriticalSection(&g_pt.lock);
	if (g_pt.inflight > 0) {
		// Another call is still running, so from here on the buffer holds both.
		g_pt.taint = true;
	}
	g_pt.inflight++;
	if (!g_pt.taint) {
		PTCOV_SNAPSHOT_RES res;
		// REWIND is what makes this call's trace start with a PSB, and therefore what makes it
		// decodable on its own.
		pt_snapshot(PTCOV_SNAP_PAUSE | PTCOV_SNAP_REWIND | PTCOV_SNAP_RESUME, &res);
		if (!(res.StatusBits & PTCOV_STATUS_TRACE_EN))
			fail("PT did not resume after a rewind; RTIT_CTL.TraceEn stayed clear");
	}
	LeaveCriticalSection(&g_pt.lock);
}

struct pt_emit_ctx {
	uint64* pcs;
	uint32 count;
	bool truncated;
};

static void pt_emit(void* ctx, int call_index, uint32 norm_pc, uint64 va)
{
	pt_emit_ctx* c = (pt_emit_ctx*)ctx;
	if (c->count >= kPtMaxPCs) {
		c->truncated = true;
		return;
	}
	c->pcs[c->count++] = norm_pc;
}

static void cover_collect(cover_t* cov)
{
	cov->size = 0;
	if (cov == &extra_cov || !g_pt.active)
		return;

	EnterCriticalSection(&g_pt.lock);
	if (g_pt.inflight > 0)
		g_pt.inflight--;
	// Still someone running means this call's window was shared with theirs, even if the
	// overlap only started after our own reset.
	bool shared = g_pt.taint || g_pt.inflight > 0;

	PTCOV_SNAPSHOT_RES res;
	// PAUSE without RESUME: tracing stays off while we read the buffer, so nothing can append
	// to the range we are about to decode. The next cover_reset turns it back on.
	pt_snapshot(shared && g_pt.inflight > 0 ? PTCOV_SNAP_PAUSE | PTCOV_SNAP_RESUME
						: PTCOV_SNAP_PAUSE,
		    &res);

	if (res.StatusBits & PTCOV_STATUS_ERROR)
		fail("RTIT_STATUS.Error is set: the PT configuration was rejected");

	bool stopped = (res.StatusBits & PTCOV_STATUS_STOPPED) != 0;
	uint64 end_off = res.ByteOffset;

	if (shared) {
		g_pt.unattributed++;
		debug("pt: call %llu ran overlapped, dropping its coverage\n",
		      (unsigned long long)g_pt.unattributed);
	} else if (stopped) {
		// The ToPA filled and the hardware stopped generating. Everything past that point is
		// missing, so drop this call rather than report a truncated trace as if it were
		// complete: a subset of the real blocks is indistinguishable from a different code
		// path, which is exactly the kind of signal that makes a corpus grow without bound.
		g_pt.overflows++;
		debug("pt: buffer overflow #%llu, dropping this call's coverage\n",
		      (unsigned long long)g_pt.overflows);
	} else if (end_off > 0) {
		pt_emit_ctx ctx;
		ctx.pcs = (uint64*)(cov->data + cov->data_offset);
		ctx.count = 0;
		ctx.truncated = false;
		ptcov_stats st;
		memset(&st, 0, sizeof(st));
		ptcov_decode(g_pt.dec, g_pt.trace, (size_t)end_off, NULL, 0, pt_emit, &ctx, &st);
		cov->size = ctx.count;
		*(uint64*)cov->data = ctx.count;
		if (ctx.truncated) {
			g_pt.truncations++;
			debug("pt: call produced over %u blocks, truncated (#%llu)\n",
			      kPtMaxPCs, (unsigned long long)g_pt.truncations);
		}
		if (st.decode_errors || st.sync_errors)
			debug("pt: decode errors=%u sync=%u unmapped=%u\n",
			      st.decode_errors, st.sync_errors, st.unmapped);
	}

	if (g_pt.inflight == 0)
		g_pt.taint = false;
	// A ToPA stop latches RTIT_STATUS.Stopped and tracing cannot be re-enabled until it is
	// cleared, which only a rewind does. Do it here rather than leaving it for the next
	// cover_reset so an overflow cannot wedge tracing for the rest of the program.
	if (stopped)
		pt_snapshot(PTCOV_SNAP_PAUSE | PTCOV_SNAP_REWIND, &res);
	LeaveCriticalSection(&g_pt.lock);
}

// Intel PT gives us basic block starts, so an edge is the usual xor of two consecutive block
// PCs - the same model KCOV's trace-pc mode uses.
static bool use_cover_edges(uint64 pc)
{
	return true;
}
