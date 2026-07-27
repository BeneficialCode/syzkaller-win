// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package osutil

import (
	"testing"
)

// A round trip through the mapping. Trivial, but this is the first thing that breaks if the
// SliceHeader construction is wrong, and a bad slice header fails in ways that are very hard to
// attribute later.
func TestSharedMemRoundTrip(t *testing.T) {
	const size = 1 << 20
	sm, err := CreateMemMappedFile(size)
	if err != nil {
		t.Fatalf("CreateMemMappedFile: %v", err)
	}
	defer CloseMemMappedFile(sm)

	if len(sm.Mem) != size {
		t.Fatalf("len(Mem) = %v, want %v", len(sm.Mem), size)
	}
	if cap(sm.Mem) != size {
		t.Fatalf("cap(Mem) = %v, want %v", cap(sm.Mem), size)
	}

	// Touch the first, last and a middle byte: a mapping that is short by a page only shows up
	// at the far end.
	for _, off := range []int{0, size / 2, size - 1} {
		sm.Mem[off] = byte(off & 0xff)
	}
	for _, off := range []int{0, size / 2, size - 1} {
		if got, want := sm.Mem[off], byte(off&0xff); got != want {
			t.Errorf("Mem[%v] = %v, want %v", off, got, want)
		}
	}
	// The region must start out zeroed; the executor relies on that when it reads a reply count
	// out of a region no program has written yet.
	if sm.Mem[size/4] != 0 {
		t.Errorf("Mem[%v] = %v, want a zero-filled region", size/4, sm.Mem[size/4])
	}
}

// Two mappings must not alias each other.
func TestSharedMemDistinct(t *testing.T) {
	const size = 4096
	a, err := CreateMemMappedFile(size)
	if err != nil {
		t.Fatalf("CreateMemMappedFile: %v", err)
	}
	defer CloseMemMappedFile(a)
	b, err := CreateMemMappedFile(size)
	if err != nil {
		t.Fatalf("CreateMemMappedFile: %v", err)
	}
	defer CloseMemMappedFile(b)

	a.Mem[0] = 0x11
	b.Mem[0] = 0x22
	if a.Mem[0] != 0x11 {
		t.Errorf("the two regions alias each other")
	}
	if a.Name != "" && a.Name == b.Name {
		t.Errorf("both regions got the same name %q", a.Name)
	}
}

func TestSharedMemBadSize(t *testing.T) {
	if _, err := CreateMemMappedFile(0); err == nil {
		t.Errorf("CreateMemMappedFile(0) succeeded, want an error")
	}
}

// Closing must be idempotent: Env.Close can run after a failed setup that already released
// part of the state.
func TestSharedMemDoubleClose(t *testing.T) {
	sm, err := CreateMemMappedFile(4096)
	if err != nil {
		t.Fatalf("CreateMemMappedFile: %v", err)
	}
	if err := CloseMemMappedFile(sm); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := CloseMemMappedFile(sm); err != nil {
		t.Errorf("second close: %v", err)
	}
	if err := CloseMemMappedFile(nil); err != nil {
		t.Errorf("close(nil): %v", err)
	}
}
