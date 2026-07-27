// ptcov_ioctl.h - Coverage extensions to the WindowsIntelPTrace driver.
//
// Shared verbatim between the driver (ptrace.sys) and its user-mode clients, notably
// syzkaller's syz-executor.exe. Keep it self-contained: clients must NOT include common.h,
// which drags in the unfinished ipt.sys reimplementation and does not compile as C++.
//
// Everything here lives in the 0xA20..0xA2F function-code range, reserved for the coverage
// extensions so it can never collide with the original IOCTL_WINIPT_* codes (0xA01..0xA14).

#pragma once

// ---------------------------------------------------------------------------------------
// Normalized PC encoding
//
// Deliberately placed before the platform guard below: it is pure arithmetic with no header
// dependency, so the decoder (ptcov, which is intentionally OS-agnostic) can use it by
// defining PTCOV_ENCODING_ONLY without dragging in ntddk.h or windows.h.
//
// A raw kernel VA is useless as a coverage identifier: KASLR moves every module on each
// boot, so a corpus keyed on VAs stops being portable across reboots. Coverage PCs are
// therefore normalized to (module index, offset within module):
//
//     norm_pc = (module_index << PTCOV_MODULE_SHIFT) | (va - module_base)
//
// 6 bits of module index and 26 bits of offset: 64 modules of up to 64 MB each. ntoskrnl.exe
// is ~17 MB and third-party drivers are well under 4 MB, so the offset field is generous,
// and 64 modules covers a target plus everything it calls into.
//
// The module table itself is enumerated once by syz-fuzzer and distributed to both the
// executor and the manager, so the two sides can never disagree about an index.
// ---------------------------------------------------------------------------------------

#define PTCOV_MAX_MODULES       64
#define PTCOV_MODULE_SHIFT      26
#define PTCOV_OFFSET_MASK       0x03FFFFFFu
#define PTCOV_MAX_MODULE_SIZE   (1u << PTCOV_MODULE_SHIFT)

#if !defined(CTL_CODE) && !defined(PTCOV_ENCODING_ONLY)
#error "include <ntddk.h> (driver) or <windows.h>/<winioctl.h> before this header, or define PTCOV_ENCODING_ONLY"
#endif

#ifdef CTL_CODE

// ---------------------------------------------------------------------------------------
// Device
// ---------------------------------------------------------------------------------------

#define PTCOV_DEVICE_NAME_KM    L"\\Device\\WindowsIntelPTrace"
#define PTCOV_SYMLINK_NAME_KM   L"\\DosDevices\\WindowsIntelPTrace"
#define PTCOV_DEVICE_PATH_UM    "\\\\.\\WindowsIntelPTrace"
#define PTCOV_DEVICE_PATH_UM_W  L"\\\\.\\WindowsIntelPTrace"

// =========================================================================================
// Shared subset of the original WindowsIntelPT interface
//
// Moved here out of ptrace\common.h so that user-mode clients never have to include that
// header: it declares anonymous members of named struct types, which MSVC accepts in C but
// rejects in C++, and it drags in the unfinished ipt.sys reimplementation.
//
// Layout is byte-for-byte identical to the original; only DWORD/QWORD were spelled out as
// ULONG32/ULONG64 so this header does not depend on ntstrsafe.h having been included first.
// =========================================================================================

#define INTEL_PT_PMI_EVENT_NAME L"IntelPtPmiEvt"    // name of the buffer-full sync event

// PT_USER_REQ.OptsMask bits
#define PT_TRACE_CYC_PCKS_MASK          (1 << 0)    // CYC packets
#define PT_TRACE_MTC_PCKS_MASK          (1 << 1)    // MTC packets
#define PT_TRACE_TSC_PCKS_MASK          (1 << 2)    // TSC packets
#define PT_TRACE_BRANCH_PCKS_MASK       (1 << 3)    // COFI packets: FUP/TIP/TIP.PGE/TIP.PGD/TNT/MODE
#define PT_ENABLE_TOPA_MASK             (1 << 4)    // Table of Physical Addresses output
#define PT_ENABLE_RET_COMPRESSION_MASK  (1 << 5)    // RET compression

// Coverage tracing wants branch packets, ToPA output and RET compression, and explicitly
// does NOT want CYC/MTC/TSC: timing packets cost 5-20x the trace volume and buy nothing.
#define PTCOV_RECOMMENDED_OPTS \
    (PT_TRACE_BRANCH_PCKS_MASK | PT_ENABLE_TOPA_MASK | PT_ENABLE_RET_COMPRESSION_MASK)

typedef struct _INTEL_PT_CAPABILITIES {
    UINT16 bCr3Filtering : 1;           // [0]  IA32_RTIT_CTL.CR3Filter can be set
    UINT16 bConfPsbAndCycSupported : 1; // [1]  configurable PSB and cycle-accurate mode
    UINT16 bIpFiltering : 1;            // [2]  IP filtering and TraceStop supported
    UINT16 bMtcSupport : 1;             // [3]  IA32_RTIT_CTL.MTCEn can be set
    UINT16 bPtWriteSupport : 1;         // [4]  PTWRITE supported
    UINT16 bPETSupport : 1;             // [5]  Power Event Trace supported
    UINT16 bVmxSupport : 1;             // [6]  Intel PT usable in VMX operation
    UINT16 bTopaOutput : 1;             // [7]  ToPA output scheme supported
    UINT16 bTopaMultipleEntries : 1;    // [8]  ToPA tables can hold multiple entries
    UINT16 bSingleRangeSupport : 1;     // [9]  single-range output supported
    UINT16 bTransportOutputSupport : 1; // [10] output to Trace Transport Subsystem
    UINT16 bIpPcksAreLip : 1;           // [11] IP payloads are LIP rather than RIP
    SHORT  numOfAddrRanges;             // number of ADDRn_CFG ranges for IP filtering
    SHORT  mtcPeriodBmp;                // bitmap of supported MTC period encodings
    SHORT  cycThresholdBmp;             // bitmap of supported cycle threshold values
    SHORT  psbFreqBmp;                  // bitmap of supported PSB frequency encodings
} INTEL_PT_CAPABILITIES, *PINTEL_PT_CAPABILITIES;

typedef struct _PT_TRACE_IP_FILTERING {
    ULONG32 NumOfRanges;
    struct {
        PVOID   pStartVa;
        PVOID   pEndVa;
        BOOLEAN bStopTrace;             // TRUE => ADDRn_CFG = 2 (TraceStop) instead of 1 (FilterEn)
    } Ranges[4];
} PT_TRACE_IP_FILTERING, *PPT_TRACE_IP_FILTERING;

typedef struct _PT_USER_REQ {
    KAFFINITY             kCpuAffinity; // target CPU affinity mask
    ULONG32               TraceSize;    // trace buffer size in bytes
    ULONG32               OptsMask;     // PT_TRACE_*_MASK bits
    ULONG32               ProcessId;    // target process id (0 means every process)
    PT_TRACE_IP_FILTERING IpFiltering;  // IP ranges to trace, if any
    BOOLEAN               bTraceUser;   // trace ring 3
    BOOLEAN               bTraceKernel; // trace ring 0
} PT_USER_REQ, *PPT_USER_REQ;

typedef enum _PT_TRACE_STATE {
    PT_TRACE_STATE_ERROR = -1,
    PT_TRACE_STATE_STOPPED,
    PT_TRACE_STATE_PAUSED,
    PT_TRACE_STATE_RUNNING
} PT_TRACE_STATE, *PPT_TRACE_STATE;

typedef struct _PT_TRACE_DETAILS {
    ULONG32               TargetProcId;
    ULONG32               CpuId;
    ULONG32               TraceBuffSize;
    ULONG64               TotalNumberOfPackets;
    PT_TRACE_IP_FILTERING IpFiltering;
    PT_TRACE_STATE        CurrentTraceState;
} PT_TRACE_DETAILS, *PPT_TRACE_DETAILS;

typedef VOID(*PMI_USER_CALLBACK_ROUTINE)(ULONG32 CpuId, PVOID pBuffer, ULONG64 BufferSize);

typedef struct _PT_PMI_USER_CALLBACK {
    KAFFINITY                 kCpuAffinity; // CPUs this callback applies to
    PMI_USER_CALLBACK_ROUTINE pAddress;     // user-mode routine
    ULONG32                   ThreadId;     // thread to run it on
} PT_PMI_USER_CALLBACK, *PPT_PMI_USER_CALLBACK;

// Original IOCTLs. Note these pass FILE_EXECUTE (0x20) / FILE_READ_DATA (1) into CTL_CODE's
// 2-bit Access field, so the value spills into the DeviceType bits and the resulting codes
// are not what the arguments suggest. Preserved exactly as-is for compatibility.
#define IOCTL_WINIPT_CHECKSUPPORT         CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA01, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_WINIPT_START_TRACE          CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA03, METHOD_BUFFERED, FILE_EXECUTE)
#define IOCTL_WINIPT_PAUSE_TRACE          CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA05, METHOD_BUFFERED, FILE_EXECUTE)
#define IOCTL_WINIPT_RESUME_TRACE         CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA07, METHOD_BUFFERED, FILE_EXECUTE)
#define IOCTL_WINIPT_CLEAR_TRACE          CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA09, METHOD_BUFFERED, FILE_EXECUTE)
#define IOCTL_WINIPT_GET_TRACE_DETAILS    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA0B, METHOD_BUFFERED, FILE_READ_DATA | FILE_EXECUTE)
#define IOCTL_WINIPT_DO_KERNELDRV_TRACE   CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA0C, METHOD_BUFFERED, FILE_EXECUTE)
#define IOCTL_WINIPT_ALLOC_BUFFERS        CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA0D, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_WINIPT_FREE_BUFFERS         CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA0F, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_WINIPT_REGISTER_PMI_ROUTINE CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA12, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_WINIPT_FREE_PMI_ROUTINE     CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA14, METHOD_BUFFERED, FILE_WRITE_DATA)

// ---------------------------------------------------------------------------------------
// IOCTL codes
// ---------------------------------------------------------------------------------------

// Look up a loaded kernel module by name; returns its runtime base and size.
#define IOCTL_PTCOV_QUERY_MODULE  CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA20, METHOD_BUFFERED,   FILE_READ_DATA)
// Copy raw bytes out of kernel memory, restricted to a loaded module's image range.
#define IOCTL_PTCOV_READ_CODE     CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA21, METHOD_OUT_DIRECT, FILE_READ_DATA)
// Read the exact trace write position of the calling CPU (optionally pausing/resuming).
#define IOCTL_PTCOV_SNAPSHOT      CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA22, METHOD_BUFFERED,   FILE_WRITE_DATA)
// Claim / release exclusive ownership of one CPU's tracing state.
#define IOCTL_PTCOV_ATTACH        CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA23, METHOD_BUFFERED,   FILE_WRITE_DATA)
#define IOCTL_PTCOV_DETACH        CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA24, METHOD_BUFFERED,   FILE_WRITE_DATA)

// These codes validate their own buffers per IOCTL and are exempt from the driver's legacy
// blanket "inputLen >= 8 && outputLen != 0" gate.
#define PTCOV_IS_COVERAGE_IOCTL(c)      \
    ((c) == IOCTL_PTCOV_QUERY_MODULE || \
     (c) == IOCTL_PTCOV_READ_CODE    || \
     (c) == IOCTL_PTCOV_SNAPSHOT     || \
     (c) == IOCTL_PTCOV_ATTACH       || \
     (c) == IOCTL_PTCOV_DETACH)

// ---------------------------------------------------------------------------------------
// IOCTL_PTCOV_QUERY_MODULE
// ---------------------------------------------------------------------------------------

#define PTCOV_MODULE_NAME_MAX   64
#define PTCOV_MODULE_PATH_MAX   256

typedef struct _PTCOV_MODULE_INFO {
    // In: base name to look up, case-insensitive, NUL-terminated ("victim.sys").
    // Out: echoed back unchanged.
    CHAR    Name[PTCOV_MODULE_NAME_MAX];
    ULONG64 ImageBase;                          // Out: runtime load address
    ULONG32 ImageSize;                          // Out: SizeOfImage
    ULONG32 Reserved;
    CHAR    FullPath[PTCOV_MODULE_PATH_MAX];    // Out: "\SystemRoot\System32\drivers\..."
} PTCOV_MODULE_INFO, *PPTCOV_MODULE_INFO;

// ---------------------------------------------------------------------------------------
// IOCTL_PTCOV_READ_CODE
//
// Input buffer is the request; output buffer receives Length raw bytes.
//
// Why read from memory instead of just mapping the .sys file from disk: on Windows 10 20H1+
// the loader rewrites call sites in loaded kernel modules (retpoline / import optimization),
// which changes instruction lengths. Hotpatch prologues and third-party hooking engines do
// the same, and IMAGE_SCN_MEM_DISCARDABLE sections are freed after load. Feeding libipt the
// on-disk bytes therefore desynchronizes the decoder in ways that are extremely hard to
// diagnose after the fact.
// ---------------------------------------------------------------------------------------

#define PTCOV_READ_CODE_MAX_CHUNK  (64 * 1024)

typedef struct _PTCOV_READ_CODE_REQ {
    ULONG64 Va;             // In: kernel VA, must lie inside a loaded module
    ULONG32 Length;         // In: bytes to copy, <= PTCOV_READ_CODE_MAX_CHUNK
    ULONG32 Reserved;
} PTCOV_READ_CODE_REQ, *PPTCOV_READ_CODE_REQ;

// ---------------------------------------------------------------------------------------
// IOCTL_PTCOV_SNAPSHOT
//
// Returns the byte offset at which Intel PT will write next, which is what slices one
// continuous trace into per-syscall ranges.
//
// PTCOV_SNAP_PAUSE is not optional for an accurate reading: the SDM only guarantees that
// buffered packets have reached memory, and that IA32_RTIT_OUTPUT_MASK_PTRS is
// architecturally accurate, once TraceEn is clear. Reading the offset while tracing is live
// yields a stale value. Pass PAUSE|RESUME to take a reading at a call boundary in a single
// kernel transition.
//
// ByteOffset is a direct index into the user-mapped buffer. That holds because
// AllocAndSetTopa builds every ToPA entry at the fixed 4 KB size, in PFN order, from one
// MDL, and MapTracePhysBufToUserVa maps that same MDL - so ToPA entry order, MDL PFN order
// and user VA page order all coincide. Do not introduce variable-size ToPA entries.
// ---------------------------------------------------------------------------------------

#define PTCOV_SNAP_PAUSE    0x1     // clear TraceEn before reading (required for accuracy)
#define PTCOV_SNAP_RESUME   0x2     // set TraceEn again before returning
#define PTCOV_SNAP_REWIND   0x4     // reset the write position to the head of the ToPA

// RTIT_STATUS bits reported back in PTCOV_SNAPSHOT_RES.StatusBits
#define PTCOV_STATUS_FILTER_EN  0x01
#define PTCOV_STATUS_CONTEXT_EN 0x02
#define PTCOV_STATUS_TRIGGER_EN 0x04
#define PTCOV_STATUS_ERROR      0x08
#define PTCOV_STATUS_STOPPED    0x10
// Not from RTIT_STATUS: sampled from RTIT_CTL.TraceEn AFTER any rewind/resume this call
// performed. Everything else here is read before the rewind, so without this there is no way
// for a client to tell "tracing is running again" from "tracing silently stayed off".
#define PTCOV_STATUS_TRACE_EN   0x20

typedef struct _PTCOV_SNAPSHOT_REQ {
    ULONG32 CpuId;          // In: must be the CPU the calling thread is pinned to
    ULONG32 Flags;          // In: PTCOV_SNAP_*
} PTCOV_SNAPSHOT_REQ, *PPTCOV_SNAPSHOT_REQ;

typedef struct _PTCOV_SNAPSHOT_RES {
    // Out: the write position IN EFFECT WHEN THIS CALL RETURNS, i.e. after any requested
    // rewind. So with PTCOV_SNAP_REWIND this is 0, and a caller can always use it directly
    // as the start of the next range without special-casing the rewind.
    ULONG64 ByteOffset;
    // Out: the position before the rewind, so nothing is lost. Equals ByteOffset when no
    // rewind was requested. Useful for spotting how full the buffer got.
    ULONG64 PrevByteOffset;
    ULONG32 TopaEntry;      // Out: MaskOrTableOffset, after any rewind
    ULONG32 StatusBits;     // Out: PTCOV_STATUS_*, sampled before the rewind clears them
    ULONG64 PacketByteCnt;  // Out: RTIT_STATUS.PacketByteCnt, sampled before the rewind
} PTCOV_SNAPSHOT_RES, *PPTCOV_SNAPSHOT_RES;

// ---------------------------------------------------------------------------------------
// IOCTL_PTCOV_ATTACH / IOCTL_PTCOV_DETACH
//
// Records the calling process as the exclusive owner of one CPU's tracing state. syzkaller
// runs one executor process per CPU, each pinned, and the driver's original design kept the
// "current" affinity in a single global - so the last START_TRACE silently stole the state
// of every other process. Ownership makes that a clean STATUS_DEVICE_BUSY instead.
// ---------------------------------------------------------------------------------------

typedef struct _PTCOV_ATTACH_REQ {
    ULONG32 CpuId;          // In: CPU to claim / release
    ULONG32 Flags;          // In: reserved, must be 0
} PTCOV_ATTACH_REQ, *PPTCOV_ATTACH_REQ;

#endif /* CTL_CODE */
