// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package host

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/google/syzkaller/pkg/log"
)

// Windows coverage comes from Intel PT rather than from kcov, so what has to be probed is the
// PT driver rather than a /sys file. Nothing else in Check's feature list has a Windows
// implementation yet, so those stay at the default "support is not implemented in syzkaller".
//
// Note this runs on the target machine (syz-fuzzer and syz-execprog both call Check there),
// which is the only place the device exists.
func init() {
	checkFeature[FeatureCoverage] = checkPtCoverage
	// Coverage is attributed per call, so the Extra channel always comes back empty (there is
	// one PT buffer per CPU and rewinding it for each call discards whatever fell between
	// calls). Keep the feature enabled anyway: the executor only routes coverage at all when
	// the manager asks for it, and turning this off costs nothing but confuses the machine
	// check output. Background coverage is M7's job, from the other CPUs.
	checkFeature[FeatureExtraCoverage] = checkPtCoverage
	machineModulesInfo = collectPtModules
}

const ptDevicePath = `\\.\WindowsIntelPTrace`

func checkPtCoverage() string {
	path, err := windows.UTF16PtrFromString(ptDevicePath)
	if err != nil {
		return fmt.Sprintf("bad Intel PT device path %v: %v", ptDevicePath, err)
	}
	h, err := windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		// The device ACL is SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_R, so a non-elevated session
		// gets ERROR_ACCESS_DENIED here rather than ERROR_FILE_NOT_FOUND. Both mean no
		// coverage, but they need very different fixes, so keep the distinction.
		switch err {
		case windows.ERROR_FILE_NOT_FOUND, windows.ERROR_PATH_NOT_FOUND:
			return fmt.Sprintf("%v is not present (is ptrace.sys loaded?)", ptDevicePath)
		case windows.ERROR_ACCESS_DENIED:
			return fmt.Sprintf("%v is admin-only and this process is not elevated", ptDevicePath)
		}
		return fmt.Sprintf("failed to open %v: %v", ptDevicePath, err)
	}
	windows.CloseHandle(h)
	return ""
}

// ---------------------------------------------------------------------------------------------
// Loaded kernel module enumeration
//
// The coverage PC encoding is (module_index << 26) | offset, so both sides have to agree on
// which module got which index. They cannot enumerate independently: a driver load or unload
// between the two enumerations would shift every index and silently relabel the whole corpus.
// So this list, produced here on the target, is the single source of truth - it goes to the
// manager through rpctype.ConnectArgs.Modules and becomes the index space for the whole run.
//
// The traced module is placed FIRST because the executor pins it to index 0: IP filtering
// restricts the hardware to that one image, so nothing else can contribute a PC yet. Multiple
// simultaneously traced ranges need a real index table shipped to the executor, which is M7.
// ---------------------------------------------------------------------------------------------

const systemModuleInformation = 11

// RTL_PROCESS_MODULE_INFORMATION
type rtlProcessModuleInformation struct {
	Section          uintptr
	MappedBase       uintptr
	ImageBase        uintptr
	ImageSize        uint32
	Flags            uint32
	LoadOrderIndex   uint16
	InitOrderIndex   uint16
	LoadCount        uint16
	OffsetToFileName uint16
	FullPathName     [256]byte
}

// collectPtModules returns the modules that make up the coverage PC index space - which is ONLY
// the traced ones, not every loaded driver.
//
// That is not a shortcut. A normalized PC is (module_index << 26) | offset, so the index field
// holds 64 values, while a normal Windows install has a couple of hundred drivers loaded (222 on
// this target). Indexing all of them cannot work. It would also be pointless: IP filtering
// confines the hardware to the traced image, so no other module can contribute a single PC.
//
// This list is the only consumer-visible module list (it goes to the manager through
// rpctype.ConnectArgs.Modules and is used solely by pkg/cover), so keeping it to the traced set
// keeps one side owning the index space - the property that stops a driver load between two
// independent enumerations from silently relabelling the whole corpus.
func collectPtModules() ([]KernelModule, error) {
	target := ptTargetModule()
	if target == "" {
		// Coverage is not configured. Report nothing rather than a list nobody can index.
		return nil, nil
	}
	modules, err := enumKernelModules()
	if err != nil {
		return nil, err
	}
	for _, mod := range modules {
		if strings.EqualFold(mod.Name, target) {
			return []KernelModule{mod}, nil
		}
	}
	// Configured to trace something that is not loaded. The executor fails with a clearer
	// message than anything that could be produced here, so do not fail machine info over it.
	log.Logf(0, "traced module %v is not among the %v loaded kernel modules", target, len(modules))
	return nil, nil
}

// ptTargetModule mirrors cover_pt.h's lookup so the index the executor uses for its single
// traced module matches index 0 here. Keep the two in sync.
func ptTargetModule() string {
	if v := os.Getenv("SYZ_PT_TARGET"); v != "" {
		return strings.TrimSpace(v)
	}
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(exe), "syz-pt-target"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// Declared here rather than taken from x/sys/windows: the vendored version of that package
// predates its NtQuerySystemInformation wrapper, and bumping it to pull in one function would
// churn a dependency the rest of the tree shares.
var (
	modntdll                     = windows.NewLazySystemDLL("ntdll.dll")
	procNtQuerySystemInformation = modntdll.NewProc("NtQuerySystemInformation")
)

const statusInfoLengthMismatch = 0xC0000004

func ntQuerySystemInformation(class uint32, buf []byte, need *uint32) uint32 {
	st, _, _ := procNtQuerySystemInformation.Call(uintptr(class),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(need)))
	return uint32(st)
}

func enumKernelModules() ([]KernelModule, error) {
	// The required size is not stable between the query and the read - a driver can load in
	// between - so grow and retry rather than trusting the first answer.
	size := 64 << 10
	for try := 0; try < 8; try++ {
		buf := make([]byte, size)
		var need uint32
		st := ntQuerySystemInformation(systemModuleInformation, buf, &need)
		if st == statusInfoLengthMismatch {
			if int(need) <= size {
				need = uint32(size * 2)
			}
			size = int(need) + (16 << 10)
			continue
		}
		if st != 0 {
			return nil, fmt.Errorf("NtQuerySystemInformation(SystemModuleInformation) = %#x", st)
		}
		return parseKernelModules(buf)
	}
	return nil, fmt.Errorf("the kernel module list kept growing across 8 attempts")
}

func parseKernelModules(buf []byte) ([]KernelModule, error) {
	const hdr = int(unsafe.Sizeof(uintptr(0)))
	if len(buf) < hdr {
		return nil, fmt.Errorf("module list buffer is too short")
	}
	count := int(*(*uintptr)(unsafe.Pointer(&buf[0])))
	entry := int(unsafe.Sizeof(rtlProcessModuleInformation{}))
	if count < 0 || hdr+count*entry > len(buf) {
		return nil, fmt.Errorf("module list claims %v entries but the buffer holds %v bytes",
			count, len(buf))
	}
	modules := make([]KernelModule, 0, count)
	for i := 0; i < count; i++ {
		m := (*rtlProcessModuleInformation)(unsafe.Pointer(&buf[hdr+i*entry]))
		full := m.FullPathName[:]
		if n := bytes.IndexByte(full, 0); n >= 0 {
			full = full[:n]
		}
		// OffsetToFileName indexes into FullPathName, which is why the base name is taken from
		// there rather than by splitting on a separator: the path uses the native
		// "\SystemRoot\..." form, not a drive-letter path.
		name := string(full)
		if int(m.OffsetToFileName) < len(full) {
			name = string(full[m.OffsetToFileName:])
		}
		if name == "" {
			continue
		}
		modules = append(modules, KernelModule{
			Name: name,
			Addr: uint64(m.ImageBase),
			Size: uint64(m.ImageSize),
		})
	}
	return modules, nil
}
