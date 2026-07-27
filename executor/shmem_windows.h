// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Attaching to the manager's shared memory on Windows.
//
// Everywhere else the executor inherits two file descriptors (kInFd/kOutFd) and mmaps them.
// That is not available here: os/exec refuses cmd.ExtraFiles on Windows, so pkg/ipc creates
// pagefile-backed NAMED sections instead and passes their names on our command line as
// "-in <name> -out <name>". We open them by name.

#pragma once

// Note: GetCurrentProcessId() rather than _getpid(). Including <process.h> here breaks the
// build with "C2733: vsnprintf: cannot overload functions with extern C linkage", because it is
// pulled in after the executor has already declared the printf family. windows.h is already
// included by executor_windows.h and gives us what we need.

static HANDLE shmem_in_handle = NULL;
static HANDLE shmem_out_handle = NULL;
// Remembered from argv so mmap_output can attach when it is called later from main().
static const char* shmem_out_name = NULL;

// Parse the section names out of argv. Absent names are not an error here; the caller decides
// whether it needed them, so that non-exec modes (version, runtest) keep working unchanged.
static void shmem_parse_args(int argc, char** argv, const char** in_name, const char** out_name)
{
	*in_name = NULL;
	*out_name = NULL;
	for (int i = 1; i + 1 < argc; i++) {
		if (strcmp(argv[i], "-in") == 0)
			*in_name = argv[i + 1];
		else if (strcmp(argv[i], "-out") == 0)
			*out_name = argv[i + 1];
	}
}

static HANDLE shmem_open(const char* name, DWORD access)
{
	HANDLE h = OpenFileMappingA(access, FALSE, name);
	if (h == NULL)
		failmsg("failed to open shared memory section", "name=%s, err=%u", name, GetLastError());
	return h;
}

// Map the whole input region read-only and hand back the view.
//
// The caller repoints input_data at this rather than copying: the serialized program stream is
// self-terminating, so its length is not known up front, and copying all of kMaxInput on every
// execution would dominate the cost of the whole path.
static char* shmem_map_input(const char* name, int size)
{
	shmem_in_handle = shmem_open(name, FILE_MAP_READ);
	void* addr = MapViewOfFile(shmem_in_handle, FILE_MAP_READ, 0, 0, size);
	if (addr == NULL)
		failmsg("failed to map input region", "name=%s, err=%u", name, GetLastError());
	return (char*)addr;
}

// Map the output region read-write, preferring the same address the POSIX build uses so that
// debugging output and crash dumps look alike across targets. Windows may refuse a specific
// base, in which case any address will do: unlike the Linux build we never need to hand the
// address to another process.
static uint32* shmem_map_output(const char* name, int size)
{
	shmem_out_handle = shmem_open(name, FILE_MAP_ALL_ACCESS);
	void* want = (void*)(kOutputBase + (1 << 20) * (uint64)(GetCurrentProcessId() % 128));
	void* addr = MapViewOfFileEx(shmem_out_handle, FILE_MAP_ALL_ACCESS, 0, 0, size, want);
	if (addr == NULL)
		addr = MapViewOfFile(shmem_out_handle, FILE_MAP_ALL_ACCESS, 0, 0, size);
	if (addr == NULL)
		failmsg("failed to map output region", "name=%s, err=%u", name, GetLastError());
	return (uint32*)addr;
}
