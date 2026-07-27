// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package osutil

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// openExisting attaches to an already-created named section.
//
// OpenFileMapping is not in the vendored x/sys/windows, but CreateFileMapping with an existing
// name returns a handle to that same section (it sets ERROR_ALREADY_EXISTS, which the generated
// wrapper does not surface because the handle is valid). That is enough to exercise the name
// lookup, which is what matters here.
func openExisting(t *testing.T, name string, size int) (windows.Handle, uintptr) {
	t.Helper()
	namep, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFileMapping(windows.InvalidHandle, nil, windows.PAGE_READWRITE,
		0, uint32(size), namep)
	// The wrapper reports ERROR_ALREADY_EXISTS as an error even though the handle it returns is
	// valid and refers to the existing section - which is exactly the case we want here.
	// (Production code treats it as fatal on purpose: it asks for a NEW section.)
	if err != nil && err != windows.ERROR_ALREADY_EXISTS {
		t.Fatalf("cannot attach to section %q: %v", name, err)
	}
	if h == 0 {
		t.Fatalf("cannot attach to section %q: null handle", name)
	}
	addr, err := windows.MapViewOfFile(h, windows.FILE_MAP_WRITE, 0, 0, uintptr(size))
	if err != nil {
		windows.CloseHandle(h)
		t.Fatalf("MapViewOfFile: %v", err)
	}
	return h, addr
}

// The whole point of the Windows mechanism is that a different process attaches BY NAME, so the
// name must resolve and the contents must genuinely be shared. Doing the second attach from the
// same process still exercises both, and catches a wrong name or namespace.
func TestSharedMemAttachByName(t *testing.T) {
	const size = 64 << 10
	sm, err := CreateMemMappedFile(size)
	if err != nil {
		t.Fatalf("CreateMemMappedFile: %v", err)
	}
	defer CloseMemMappedFile(sm)

	if sm.Name == "" {
		t.Fatal("Name is empty; the executor would have no way to attach")
	}
	if sm.File != nil {
		t.Error("File must be nil on Windows: there is no descriptor to inherit, and setting " +
			"cmd.ExtraFiles would make os/exec fail outright")
	}

	h, addr := openExisting(t, sm.Name, size)
	defer windows.CloseHandle(h)
	defer windows.UnmapViewOfFile(addr)

	// Both directions must be visible: manager->executor carries the program, and
	// executor->manager carries the replies.
	sm.Mem[0] = 0xAB
	sm.Mem[size-1] = 0xCD
	second := (*[size]byte)(unsafe.Pointer(addr))
	if second[0] != 0xAB || second[size-1] != 0xCD {
		t.Errorf("creator's writes are not visible through the second view: got %#x/%#x",
			second[0], second[size-1])
	}
	second[1] = 0xEF
	if sm.Mem[1] != 0xEF {
		t.Errorf("second view's writes are not visible to the creator: got %#x", sm.Mem[1])
	}
}

// Closing must actually release the section, otherwise a name left over from a previous executor
// could still be attached to and would hand back stale replies.
func TestSharedMemReleasedOnClose(t *testing.T) {
	const size = 4096
	sm, err := CreateMemMappedFile(size)
	if err != nil {
		t.Fatalf("CreateMemMappedFile: %v", err)
	}
	name := sm.Name
	sm.Mem[0] = 0x5A
	if err := CloseMemMappedFile(sm); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Re-creating under the same name must yield a fresh, zeroed section. If the old one were
	// still alive we would see the byte written above.
	h, addr := openExisting(t, name, size)
	defer windows.CloseHandle(h)
	defer windows.UnmapViewOfFile(addr)
	if got := (*[size]byte)(unsafe.Pointer(addr))[0]; got != 0 {
		t.Errorf("section %q survived close: byte 0 is %#x, want 0", name, got)
	}
}
