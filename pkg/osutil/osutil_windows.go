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
	"strconv"
	"syscall"
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

func CreateMemMappedFile(size int) (f *os.File, mem []byte, err error) {
	return nil, nil, fmt.Errorf("CreateMemMappedFile is not implemented")
}

func CloseMemMappedFile(f *os.File, mem []byte) error {
	return fmt.Errorf("CloseMemMappedFile is not implemented")
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
