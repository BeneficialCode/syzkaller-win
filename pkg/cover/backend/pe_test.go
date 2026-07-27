// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package backend

import (
	"bytes"
	"debug/pe"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestEnumeratePEFunctions runs the .pdata enumeration over a real image when one is available.
// The counts it prints are meant to be compared against the XED-based ptbb tool, which walks the
// same .pdata with a completely independent disassembler; agreement on function count and rough
// agreement on block count is what says the recursive descent is not quietly broken.
func TestEnumeratePEFunctions(t *testing.T) {
	path := os.Getenv("SYZ_PE_TEST_IMAGE")
	if path == "" {
		t.Skip("set SYZ_PE_TEST_IMAGE to a PE image to run this")
	}
	funcs, err := enumeratePEFunctions(path)
	if err != nil {
		t.Fatal(err)
	}
	blocks, named := 0, 0
	for _, fn := range funcs {
		blocks += len(fn.blocks)
		if len(fn.blocks) == 0 {
			t.Fatalf("function %v [%#x,%#x) survived with no basic blocks", fn.name, fn.start, fn.end)
		}
		if fn.blocks[0] != fn.start {
			t.Errorf("function %v: first block is %#x, want the entry %#x",
				fn.name, fn.blocks[0], fn.start)
		}
		for i, b := range fn.blocks {
			if b < fn.start || b >= fn.end {
				t.Errorf("function %v: block %#x is outside [%#x,%#x)", fn.name, b, fn.start, fn.end)
			}
			if i > 0 && b <= fn.blocks[i-1] {
				t.Errorf("function %v: blocks are not strictly increasing at %v", fn.name, i)
			}
		}
		if !strings.HasPrefix(fn.name, "sub_") && !strings.HasPrefix(fn.name, "gap_") {
			named++
		}
		if os.Getenv("SYZ_PE_FIND_RVA") != "" {
			if want, err := strconv.ParseUint(os.Getenv("SYZ_PE_FIND_RVA"), 0, 32); err == nil {
				if uint32(want) >= fn.start && uint32(want) < fn.end {
					t.Logf("RVA %#x is inside %v [%#x,%#x) with %v blocks",
						want, fn.name, fn.start, fn.end, len(fn.blocks))
				}
			}
		}
	}
	t.Logf("%v: %v functions, %v basic blocks, %v with an exported name",
		path, len(funcs), blocks, named)
}

// TestDumpPELayout writes the RVA-laid-out image and the block list so the exact same bytes can
// be handed to the XED-based ptbb tool. Comparing two independent disassemblers on identical
// input is the only way to tell a recursive-descent bug from a layout bug.
func TestDumpPELayout(t *testing.T) {
	path := os.Getenv("SYZ_PE_TEST_IMAGE")
	out := os.Getenv("SYZ_PE_DUMP_TO")
	if path == "" || out == "" {
		t.Skip("set SYZ_PE_TEST_IMAGE and SYZ_PE_DUMP_TO to run this")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := pe.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	oh := f.OptionalHeader.(*pe.OptionalHeader64)
	img, err := layoutPEImage(f, raw, oh.SizeOfImage)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, img.data, 0600); err != nil {
		t.Fatal(err)
	}
	funcs, err := enumeratePEFunctions(path)
	if err != nil {
		t.Fatal(err)
	}
	buf := new(bytes.Buffer)
	for _, fn := range funcs {
		for _, b := range fn.blocks {
			fmt.Fprintf(buf, "%016X\n", oh.ImageBase+uint64(b))
		}
	}
	if err := os.WriteFile(out+".blocks", buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %v (%v bytes, ImageBase %#x) and %v.blocks (%v lines)",
		out, len(img.data), oh.ImageBase, out, len(funcs))
}

// TestPEExportRVA prints one export's RVA. Used to calibrate an external symbol dumper (dbh.exe
// loads a module at its own base, so its addresses have to be turned back into RVAs).
func TestPEExportRVA(t *testing.T) {
	path := os.Getenv("SYZ_PE_TEST_IMAGE")
	want := os.Getenv("SYZ_PE_EXPORT")
	if path == "" || want == "" {
		t.Skip("set SYZ_PE_TEST_IMAGE and SYZ_PE_EXPORT to run this")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := pe.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	oh := f.OptionalHeader.(*pe.OptionalHeader64)
	img, err := layoutPEImage(f, raw, oh.SizeOfImage)
	if err != nil {
		t.Fatal(err)
	}
	names := peExportNames(f, oh, img)
	for rva, name := range names {
		if name == want {
			t.Logf("%v is at RVA %#x (ImageBase %#x)", name, rva, oh.ImageBase)
			return
		}
	}
	shown := 0
	for rva, name := range names {
		t.Logf("sample export: %v at %#x", name, rva)
		if shown++; shown >= 5 {
			break
		}
	}
	t.Fatalf("%v is not among the %v exports of %v", want, len(names), path)
}
