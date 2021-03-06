// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

#include <direct.h> // for _chdir
#include <io.h> // for mktemp
#include <windows.h>
#include <fltUser.h>
#include <string>
#include <memory>

#if SYZ_EXECUTOR || SYZ_HANDLE_SEGV
static void install_segv_handler()
{
}

#define NONFAILING(...) \
	([&]() { __try { __VA_ARGS__; } __except (EXCEPTION_EXECUTE_HANDLER) { return false; } return true; }())
#endif

#if SYZ_EXECUTOR || SYZ_THREADED || SYZ_REPEAT && SYZ_EXECUTOR_USES_FORK_SERVER
static uint64 current_time_ms()
{
	return GetTickCount64();
}
#endif

#if SYZ_EXECUTOR || SYZ_THREADED || SYZ_REPEAT && SYZ_EXECUTOR_USES_FORK_SERVER
static void sleep_ms(uint64 ms)
{
	Sleep(ms);
}
#endif

#if SYZ_EXECUTOR || SYZ_THREADED
static void thread_start(void* (*fn)(void*), void* arg)
{
	HANDLE th = CreateThread(NULL, 128 << 10, (LPTHREAD_START_ROUTINE)fn, arg, 0, NULL);
	if (th == NULL)
		exitf("CreateThread failed");
}

struct event_t {
	CRITICAL_SECTION cs;
	CONDITION_VARIABLE cv;
	int state;
};

static void event_init(event_t* ev)
{
	InitializeCriticalSection(&ev->cs);
	InitializeConditionVariable(&ev->cv);
	ev->state = 0;
}

static void event_reset(event_t* ev)
{
	ev->state = 0;
}

static void event_set(event_t* ev)
{
	EnterCriticalSection(&ev->cs);
	if (ev->state)
		fail("event already set");
	ev->state = 1;
	LeaveCriticalSection(&ev->cs);
	WakeAllConditionVariable(&ev->cv);
}

static void event_wait(event_t* ev)
{
	EnterCriticalSection(&ev->cs);
	while (!ev->state)
		SleepConditionVariableCS(&ev->cv, &ev->cs, INFINITE);
	LeaveCriticalSection(&ev->cs);
}

static int event_isset(event_t* ev)
{
	EnterCriticalSection(&ev->cs);
	int res = ev->state;
	LeaveCriticalSection(&ev->cs);
	return res;
}

static int event_timedwait(event_t* ev, uint64 timeout_ms)
{
	EnterCriticalSection(&ev->cs);
	uint64 start = current_time_ms();
	for (;;) {
		if (ev->state)
			break;
		uint64 now = current_time_ms();
		if (now - start > timeout_ms)
			break;
		SleepConditionVariableCS(&ev->cv, &ev->cs, timeout_ms - (now - start));
	}
	int res = ev->state;
	LeaveCriticalSection(&ev->cs);
	return res;
}
#endif

#if SYZ_EXECUTOR || SYZ_SANDBOX_NONE
static void loop();
static int do_sandbox_none(void)
{
	loop();
	return 0;
}
#endif

static void use_temporary_dir(void)
{
	char tmpdir_template[] = "./syzkaller.XXXXXX";
	char* tmpdir = mktemp(tmpdir_template);

	CreateDirectory(tmpdir, NULL);
	_chdir(tmpdir);
}

#if SYZ_EXECUTOR || __NR_syz_opendevice
static HANDLE syz_opendevice(const char* symLinkName)
{
	char name[MAX_PATH] = {0};

	sprintf(name, "\\\\.\\%s", symLinkName);
	HANDLE hDevice = ::CreateFileA(name, GENERIC_READ | GENERIC_WRITE, 0,
				       NULL, OPEN_EXISTING, 0, NULL);

	if (hDevice == INVALID_HANDLE_VALUE) {
		return hDevice;
	}

	return hDevice;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_ioctl
static bool syz_ioctl(HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize,
		  LPVOID lpOutBuffer, DWORD nOutBufferSize)
{
	DWORD bytes = 0;
	return ::DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize,
			       lpOutBuffer, nOutBufferSize, &bytes, NULL);
}
#endif

std::wstring StringToWstring(const std::string& str)
{
	int len = MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, nullptr, 0);
	len += 1;
	std::unique_ptr<wchar_t[]> buffer = std::make_unique<wchar_t[]>(len);
	memset(buffer.get(), 0, sizeof(wchar_t) * len);
	MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.size(), buffer.get(), len);
	std::wstring wstr(buffer.get());
	return wstr;
}

#if SYZ_EXECUTOR || __NR_syz_openport
static HANDLE syz_openport(const char* portName)
{
	HANDLE hPort = INVALID_HANDLE_VALUE;
	std::string name = portName;
	std::wstring wname = StringToWstring(name);


	auto hr = ::FilterConnectCommunicationPort(wname.c_str(), 0, nullptr, 0, nullptr, &hPort);
	if (FAILED(hr)) {
		return INVALID_HANDLE_VALUE;
	}

	return hPort;
}
#endif