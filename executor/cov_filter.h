// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#if SYZ_EXECUTOR_USES_SHMEM && !GOOS_windows
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

struct cov_filter_t {
	uint32 pcstart;
	uint32 pcsize;
	uint8 bitmap[];
};

static cov_filter_t* cov_filter;

static void init_coverage_filter(char* filename)
{
	int f = open(filename, O_RDONLY);
	if (f < 0) {
		// We don't fail here because we don't know yet if we should use coverage filter or not.
		// We will receive the flag only in execute flags and will fail in coverage_filter if necessary.
		debug("bitmap is not found, coverage filter disabled\n");
		return;
	}
	struct stat st;
	if (fstat(f, &st))
		fail("faied to stat coverage filter");
	// A random address for bitmap. Don't corrupt output_data.
	void* preferred = (void*)0x110f230000ull;
	cov_filter = (cov_filter_t*)mmap(preferred, st.st_size, PROT_READ, MAP_PRIVATE, f, 0);
	if (cov_filter != preferred)
		failmsg("failed to mmap coverage filter bitmap", "want=%p, got=%p", preferred, cov_filter);
	if ((uint32)st.st_size != sizeof(uint32) * 2 + ((cov_filter->pcsize >> 4) / 8 + 1))
		fail("bad coverage filter bitmap size");
	close(f);
}

static bool coverage_filter(uint64 pc)
{
	if (!flag_coverage_filter)
		return true;
	if (cov_filter == NULL)
		fail("coverage filter was enabled but bitmap initialization failed");
	// Prevent out of bound while searching bitmap.
	uint32 pc32 = (uint32)(pc & 0xffffffff);
	if (pc32 < cov_filter->pcstart || pc32 > cov_filter->pcstart + cov_filter->pcsize)
		return false;
	// For minimizing the size of bitmap, the lowest 4-bit will be dropped.
	pc32 -= cov_filter->pcstart;
	pc32 = pc32 >> 4;
	uint32 idx = pc32 / 8;
	uint32 shift = pc32 % 8;
	return (cov_filter->bitmap[idx] & (1 << shift)) > 0;
}

#elif SYZ_EXECUTOR_USES_SHMEM && GOOS_windows
// The coverage filter is not ported to Windows yet. It is deliberately a stub rather than a
// build error, because enabling shmem must not depend on the filter: the bitmap format is keyed
// on the uint32 PC space, and on Windows that space is being redefined as (module, offset), so
// porting it before the PC encoding settles would just have to be redone.
//
// syz-manager/covfilter.go rejects the option explicitly for this target, so a user asking for
// a filter gets an error there rather than silently unfiltered coverage here.
static void init_coverage_filter(char* filename)
{
}

static bool coverage_filter(uint64 pc)
{
	if (flag_coverage_filter)
		fail("coverage filter is not supported on windows");
	return true;
}

#else
static void init_coverage_filter(char* filename)
{
}
#endif
