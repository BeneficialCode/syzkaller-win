// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package osutil

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	PROCESS_ALL_ACCESS = 0x001f0fff
)

// ProcessTempDir create a new temp dir in where and returns its path and unique index.
// It alse cleans up old, unused temp dirs after dead process
func ProcessTempDir(where string) (string, error) {
	for i := 0; i < 1e3; i++ {
		path := filepath.Join(where, fmt.Sprintf("instance-%v", i))
		pidfile := filepath.Join(path, ".pid")
		err := os.Mkdir(path, DefaultDirPerm)
		if os.IsExist(err) {
			// Try to clean up.
			if cleanupTempDir(path, pidfile) {
				i--
			}
			continue
		}
		if err != nil {
			return "", err
		}
		if err := WriteFile(pidfile, []byte(strconv.Itoa(syscall.Getpid()))); err != nil {
			return "", err
		}
		return path, nil
	}
	return "", fmt.Errorf("too many live instance")
}

func cleanupTempDir(path, pidfile string) bool {
	data, err := ioutil.ReadFile(pidfile)
	if err == nil && len(data) > 0 {
		pid, err := strconv.Atoi(string(data))
		if err == nil && pid > 1 {
			handle, err := syscall.OpenProcess(PROCESS_ALL_ACCESS, false, uint32(pid))
			if err != nil {
				return false
			}
			defer syscall.CloseHandle(handle)
			if err := syscall.TerminateProcess(handle, 0); err == syscall.ESRCH {
				if os.Remove(pidfile) == nil {
					return os.RemoveAll(path) == nil
				}
			}
		}
	}
	return false
}

func HandleInterrupts(shutdown chan struct{}) {
}

func RemoveAll(dir string) error {
	return os.RemoveAll(dir)
}

func SystemMemorySize() uint64 {
	return 0
}

func LongPipe() (io.ReadCloser, io.WriteCloser, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to create pipe: %v", err)
	}
	prolongPipe(r, w)
	return r, w, err
}

func prolongPipe(r, w *os.File) {
}

// shmemSeq keeps section names unique within this process; the pid alone is not enough because
// one manager creates two mappings per executor and several executors at once.
var shmemSeq uint64

// CreateMemMappedFile creates a shared memory region the executor can attach to.
//
// Pagefile-backed (CreateFileMapping with INVALID_HANDLE_VALUE) rather than file-backed: no
// disk I/O, nothing to clean up if we crash, and none of the FILE_FLAG_DELETE_ON_CLOSE
// subtleties. The "Local\" namespace needs no privilege and is visible to any process in the
// same session, which the executor is, since syz-fuzzer spawns it directly.
func CreateMemMappedFile(size int) (*SharedMem, error) {
	if size <= 0 {
		return nil, fmt.Errorf("bad shared memory size %v", size)
	}
	name := fmt.Sprintf(`Local\syz-%v-%v`, os.Getpid(), atomic.AddUint64(&shmemSeq, 1))
	namep, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFileMapping(windows.InvalidHandle, nil, windows.PAGE_READWRITE,
		uint32(uint64(size)>>32), uint32(uint64(size)&0xffffffff), namep)
	if err != nil {
		return nil, fmt.Errorf("CreateFileMapping(%v, %v bytes) failed: %v", name, size, err)
	}
	addr, err := windows.MapViewOfFile(h, windows.FILE_MAP_WRITE, 0, 0, uintptr(size))
	if err != nil {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("MapViewOfFile(%v) failed: %v", name, err)
	}
	sm := &SharedMem{
		Name:   name,
		handle: uintptr(h),
	}
	// unsafe.Slice would be clearer but needs language version 1.17; go.mod still says 1.16.
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&sm.Mem))
	hdr.Data = addr
	hdr.Len = size
	hdr.Cap = size
	return sm, nil
}

// CloseMemMappedFile destroys a mapping created by CreateMemMappedFile.
func CloseMemMappedFile(sm *SharedMem) error {
	if sm == nil {
		return nil
	}
	var err1, err2 error
	if len(sm.Mem) != 0 {
		hdr := (*reflect.SliceHeader)(unsafe.Pointer(&sm.Mem))
		err1 = windows.UnmapViewOfFile(hdr.Data)
		sm.Mem = nil
	}
	if sm.handle != 0 {
		err2 = windows.CloseHandle(windows.Handle(sm.handle))
		sm.handle = 0
	}
	switch {
	case err1 != nil:
		return err1
	case err2 != nil:
		return err2
	}
	return nil
}

func ProcessExitStatus(ps *os.ProcessState) int {
	return ps.Sys().(syscall.WaitStatus).ExitStatus()
}

func Sandbox(cmd *exec.Cmd, user, net bool) error {
	return nil
}

func SandboxChown(file string) error {
	return nil
}

func setPdeathsig(cmd *exec.Cmd, hardKill bool) {
}

func killPgroup(cmd *exec.Cmd) {
}
