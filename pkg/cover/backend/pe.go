// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Coverage backend for Windows PE images, driven by Intel PT rather than by instrumentation.
//
// Everything here follows from one constraint: the targets are closed-source binary drivers.
// There is no source, usually no PDB, and no compiler-inserted coverage callbacks. So the two
// things a coverage report needs - a denominator (what could have been covered) and names - both
// have to be recovered from the image itself.
//
// The denominator comes from .pdata. On x64 PE, IMAGE_DIRECTORY_ENTRY_EXCEPTION holds an array
// of RUNTIME_FUNCTION{BeginAddress, EndAddress, UnwindInfoAddress}, and it is MANDATORY for SEH
// unwinding - so every non-leaf-inlined function in a driver appears there with exact start and
// end RVAs, with no PDB, no exports and no symbols involved. Recursive-descent disassembly
// inside each of those ranges then yields the basic block starts, which is the same unit Intel PT
// reports. That is the whole trick that makes "coverage for a stripped Windows driver" possible.
//
// PCs here live in the NORMALIZED space the executor emits: (module_index << 26) | offset. A raw
// VA would be useless as a coverage identifier because KASLR moves every module on each boot, so
// a corpus keyed on VAs would stop being portable across reboots. Since both sides use the same
// encoding, RestorePC is the identity - and unlike the DWARF backend there is no
// PreviousInstructionPC adjustment either, because PT reports the block's first instruction
// directly instead of the return address of a coverage callback.
package backend

import (
	"bufio"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/sys/targets"
	"golang.org/x/arch/x86/x86asm"
)

// Must match PTCOV_MODULE_SHIFT / PTCOV_OFFSET_MASK in include/ptcov_ioctl.h.
const (
	peModuleShift = 26
	peOffsetMask  = (1 << peModuleShift) - 1
	peMaxModules  = 1 << (32 - peModuleShift)
)

func makePE(target *targets.Target, objDir, srcDir, buildDir string,
	moduleObj []string, hostModules []host.KernelModule) (*Impl, error) {
	modules, err := discoverModulesPE(objDir, moduleObj, hostModules)
	if err != nil {
		return nil, err
	}
	var symbols []*Symbol
	var units []*CompileUnit
	for _, mod := range modules {
		if mod.index >= peMaxModules {
			return nil, fmt.Errorf("module %v has index %v, but the normalized PC encoding only "+
				"has room for %v modules", mod.Name, mod.index, peMaxModules)
		}
		funcs, err := enumeratePEFunctions(mod.Path)
		if err != nil {
			// A module we cannot read contributes no denominator, but the run should not die:
			// a fuzz target with 300 loaded drivers will always have some whose file is not on
			// the host, and only the traced one actually matters.
			log.Logf(0, "coverage: skipping module %v: %v", mod.Name, err)
			continue
		}
		unit := &CompileUnit{
			ObjectUnit: ObjectUnit{Name: mod.Name},
			Path:       mod.Path,
			Module:     mod.Module,
		}
		for _, fn := range funcs {
			sym := &Symbol{
				ObjectUnit: ObjectUnit{
					Name: fn.name,
					PCs:  normalizePCs(mod.index, fn.blocks),
				},
				Module: mod.Module,
				Unit:   unit,
				Start:  normalizePC(mod.index, fn.start),
				End:    normalizePC(mod.index, fn.end),
				// Nothing further to symbolize: the name is already final, whether it came
				// from an export or from the .pdata-derived sub_<rva> fallback.
				Symbolized: true,
			}
			symbols = append(symbols, sym)
			unit.PCs = append(unit.PCs, sym.PCs...)
		}
		log.Logf(0, "coverage: module %v (index %v) -> %v functions, %v basic blocks from %v",
			mod.Name, mod.index, len(funcs), len(unit.PCs), mod.Path)
		units = append(units, unit)
	}
	if len(symbols) == 0 {
		return nil, fmt.Errorf("no PE module with a .pdata section was found in %v; coverage "+
			"needs the traced driver's image on the host", objDir)
	}
	// findSymbol binary-searches on End.
	sort.Slice(symbols, func(i, j int) bool { return symbols[i].End < symbols[j].End })
	return &Impl{
		Units:   units,
		Symbols: symbols,
		// Identity: the executor already normalized, and PT gives block starts rather than
		// return addresses.
		RestorePC: func(pc uint32) uint64 { return uint64(pc) },
		Symbolize: func(pcs map[*Module][]uint64) ([]Frame, error) {
			// Line-level symbolization would need a PDB with line info, which closed-source
			// drivers do not ship. The function-level view in pkg/cover/report_binary.go is
			// built straight from Symbols instead.
			return nil, nil
		},
	}, nil
}

func normalizePC(index uint32, rva uint32) uint64 {
	return uint64(index)<<peModuleShift | uint64(rva&peOffsetMask)
}

func normalizePCs(index uint32, rvas []uint32) []uint64 {
	out := make([]uint64, len(rvas))
	for i, rva := range rvas {
		out[i] = normalizePC(index, rva)
	}
	return out
}

// peModule pairs the shared Module description with the index the executor assigned it.
type peModule struct {
	*Module
	index uint32
}

// discoverModulesPE maps the modules the target reported onto image files on the host.
//
// The index is the POSITION IN hostModules, not something derived here: that slice came from the
// target machine (pkg/host/features_windows.go) precisely so that one side owns the index space.
func discoverModulesPE(objDir string, moduleObj []string, hostModules []host.KernelModule) (
	[]peModule, error) {
	if len(hostModules) == 0 {
		return nil, fmt.Errorf("the target reported no kernel modules, so coverage has no " +
			"module index space to work in")
	}
	dirs := append([]string{objDir}, moduleObj...)
	files := locatePEFiles(dirs)
	var modules []peModule
	for i, mod := range hostModules {
		path := files[strings.ToLower(mod.Name)]
		if path == "" {
			continue
		}
		modules = append(modules, peModule{
			Module: &Module{
				Name: mod.Name,
				Path: path,
				Addr: mod.Addr,
			},
			index: uint32(i),
		})
	}
	if len(modules) == 0 {
		names := make([]string, 0, 4)
		for _, mod := range hostModules[:min(4, len(hostModules))] {
			names = append(names, mod.Name)
		}
		return nil, fmt.Errorf("none of the %v modules the target reported (%v...) has an image "+
			"in %v; copy the traced driver's binary there", len(hostModules), strings.Join(names, ", "), dirs)
	}
	return modules, nil
}

func locatePEFiles(dirs []string) map[string]string {
	files := make(map[string]string)
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			log.Logf(1, "coverage: cannot list %v: %v", dir, err)
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			// Match on the file name as the target reports it, i.e. "ntoskrnl.exe" or
			// "ptrace.sys". Order of dirs is priority, so do not overwrite.
			name := strings.ToLower(e.Name())
			if files[name] == "" {
				files[name] = filepath.Join(dir, e.Name())
			}
		}
	}
	return files
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ---------------------------------------------------------------------------------------------
// .pdata + recursive descent
// ---------------------------------------------------------------------------------------------

type peFunction struct {
	name   string
	start  uint32 // RVA
	end    uint32 // RVA, exclusive
	blocks []uint32
}

type peImage struct {
	// Image laid out by RVA, so an RVA indexes directly. Not the raw file: file offsets are
	// not RVAs, and using one for the other is the classic way to get a decoder that produces
	// plausible garbage.
	data  []byte
	valid []bool // per byte: inside an initialized, executable, non-discardable section
}

func enumeratePEFunctions(path string) ([]peFunction, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	f, err := pe.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	oh, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		return nil, fmt.Errorf("not a PE32+ image (coverage is amd64 only)")
	}
	img, err := layoutPEImage(f, raw, oh.SizeOfImage)
	if err != nil {
		return nil, err
	}
	pdata := oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXCEPTION]
	if pdata.VirtualAddress == 0 || pdata.Size == 0 {
		return nil, fmt.Errorf("no exception directory (.pdata); a stripped image without it " +
			"cannot be enumerated this way")
	}
	names := peExportNames(f, oh, img)
	// A sidecar overrides exports where both know a name, because it is the richer source: the
	// export table only covers the handful of entry points a module publishes.
	for rva, name := range loadPESymbolSidecar(path) {
		names[rva] = name
	}
	var funcs []peFunction
	skipped := 0
	const entrySize = 12
	for off := uint32(0); off+entrySize <= pdata.Size; off += entrySize {
		rec := img.slice(pdata.VirtualAddress+off, entrySize)
		if rec == nil {
			break
		}
		begin := binary.LittleEndian.Uint32(rec[0:4])
		end := binary.LittleEndian.Uint32(rec[4:8])
		if end <= begin {
			continue
		}
		// Chained/duplicate entries and entries pointing at data are both real. Skipping them
		// only shrinks the denominator; keeping them would feed the disassembler non-code.
		if !img.executable(begin, end) {
			continue
		}
		name := names[begin]
		if name == "" {
			// The designed baseline, not a failure mode: a third-party driver has no PDB and
			// exports almost nothing, so most functions are only ever known by their RVA.
			name = fmt.Sprintf("sub_%x", begin)
		}
		blocks := basicBlocks(img, begin, end)
		if len(blocks) == 0 {
			// Nothing decodable at the entry, so this .pdata entry does not describe reachable
			// code (tiny alignment stubs and entries pointing at data both look like this).
			// It contributes no denominator and would only show up as permanently uncovered.
			skipped++
			continue
		}
		funcs = append(funcs, peFunction{
			name:   name,
			start:  begin,
			end:    end,
			blocks: blocks,
		})
	}
	if len(funcs) == 0 {
		return nil, fmt.Errorf(".pdata holds %v bytes but no usable code ranges", pdata.Size)
	}
	if skipped != 0 {
		log.Logf(1, "coverage: %v: skipped %v .pdata entries with no decodable code",
			filepath.Base(path), skipped)
	}
	// .pdata can list the same range twice (identical COMDAT folding leaves duplicates).
	sort.Slice(funcs, func(i, j int) bool { return funcs[i].start < funcs[j].start })
	out := funcs[:0]
	for i, fn := range funcs {
		if i > 0 && fn.start == funcs[i-1].start {
			continue
		}
		out = append(out, fn)
	}
	return append(out, pdataGapFunctions(img, out)...), nil
}

// pdataGapFunctions covers the executable bytes that no .pdata entry claims.
//
// x64 requires unwind data only for functions that can be unwound through, so a hand-written leaf
// stub that never faults and never touches the stack can legitimately be absent. Measured on the
// target's ntoskrnl: one such 69-byte hole between entries ending at 0x475f7f and starting at
// 0x475fc4, and the fuzzer really does execute it - those were the only PCs the report could not
// attribute to any function. Without this they would stay permanently outside the denominator and
// keep tripping the "outside every known function" warning for a benign reason.
//
// There is no entry point to start from, so descend from the first byte of the gap. That is a
// guess, which is why a gap only becomes a function if something decodes there at all.
// trimPadding strips the int3 / nop / zero runs compilers put between functions.
func trimPadding(img *peImage, begin, end uint32) (uint32, uint32) {
	isPad := func(rva uint32) bool {
		b := img.slice(rva, 1)
		if b == nil {
			return false
		}
		switch b[0] {
		case 0xCC, 0x90, 0x00:
			return true
		}
		return false
	}
	for begin < end && isPad(begin) {
		begin++
	}
	for end > begin && isPad(end-1) {
		end--
	}
	return begin, end
}

func pdataGapFunctions(img *peImage, funcs []peFunction) []peFunction {
	// Alignment padding between functions must be rejected on CONTENT, not just on length. A run
	// of int3 decodes perfectly well and would otherwise become a "function" of its own: with a
	// length test alone this produced 15212 gap functions on ntoskrnl, inflating the denominator
	// by 15756 blocks of padding. Skipping pure padding leaves only the real holes.
	const minGap = 8
	var gaps []peFunction
	for i := 1; i < len(funcs); i++ {
		begin, end := funcs[i-1].end, funcs[i].start
		if end < begin+minGap || !img.executable(begin, end) {
			continue
		}
		begin, end = trimPadding(img, begin, end)
		if end < begin+minGap {
			continue
		}
		blocks := basicBlocks(img, begin, end)
		if len(blocks) == 0 {
			continue
		}
		gaps = append(gaps, peFunction{
			// Named apart from sub_ so it is obvious in a report that the boundaries here were
			// inferred from a hole rather than read out of .pdata.
			name:   fmt.Sprintf("gap_%x", begin),
			start:  begin,
			end:    end,
			blocks: blocks,
		})
	}
	return gaps
}

func layoutPEImage(f *pe.File, raw []byte, sizeOfImage uint32) (*peImage, error) {
	if sizeOfImage == 0 || sizeOfImage > 512<<20 {
		return nil, fmt.Errorf("implausible SizeOfImage %v", sizeOfImage)
	}
	img := &peImage{
		data:  make([]byte, sizeOfImage),
		valid: make([]bool, sizeOfImage),
	}
	// Headers, so the export/exception directories are readable even when they sit before the
	// first section.
	if n := len(raw); n > 0 {
		hdr := uint32(4096)
		if hdr > sizeOfImage {
			hdr = sizeOfImage
		}
		if int(hdr) > n {
			hdr = uint32(n)
		}
		copy(img.data[:hdr], raw[:hdr])
		for i := uint32(0); i < hdr; i++ {
			img.valid[i] = true
		}
	}
	for _, s := range f.Sections {
		if s.VirtualAddress >= sizeOfImage {
			continue
		}
		size := s.VirtualSize
		if s.VirtualAddress+size > sizeOfImage {
			size = sizeOfImage - s.VirtualAddress
		}
		if s.Offset != 0 && s.Size != 0 {
			n := s.Size
			if n > size {
				n = size
			}
			if int(s.Offset)+int(n) <= len(raw) {
				copy(img.data[s.VirtualAddress:s.VirtualAddress+n], raw[s.Offset:s.Offset+n])
			}
		}
		// IMAGE_SCN_MEM_EXECUTE and not IMAGE_SCN_MEM_DISCARDABLE. Discardable sections (INIT
		// and friends) are freed right after load, so they can never be executed again and
		// counting them would only inflate the denominator with code that is unreachable by
		// construction.
		const (
			scnMemExecute     = 0x20000000
			scnMemDiscardable = 0x02000000
			scnCntCode        = 0x00000020
		)
		exec := s.Characteristics&(scnMemExecute|scnCntCode) != 0 &&
			s.Characteristics&scnMemDiscardable == 0
		if !exec {
			continue
		}
		for i := s.VirtualAddress; i < s.VirtualAddress+size; i++ {
			img.valid[i] = true
		}
	}
	return img, nil
}

func (img *peImage) slice(rva, size uint32) []byte {
	if size == 0 || uint64(rva)+uint64(size) > uint64(len(img.data)) {
		return nil
	}
	return img.data[rva : rva+size]
}

func (img *peImage) executable(begin, end uint32) bool {
	if begin >= uint32(len(img.valid)) || end > uint32(len(img.valid)) || end <= begin {
		return false
	}
	return img.valid[begin] && img.valid[end-1]
}

// basicBlocks does a recursive descent over [start, end) and returns the sorted, deduplicated
// RVAs that can be the first instruction of a basic block.
//
// A block starts at the function entry, at the target of any direct branch, and at the
// instruction after any branch, call or return. Indirect targets cannot be found this way, which
// is fine and expected: measured against real traces, about 9% of the blocks Intel PT reports are
// indirect targets that no static analysis found. That makes this a LOWER BOUND on the
// denominator, never a filter on the numerator - a decoded PC is never discarded for being
// absent here.
//
// A candidate is only accepted once the walk has actually DECODED an instruction at it. Without
// that check, a branch target computed from an instruction that turns out to be inline data (a
// jump table is the usual case) gets recorded as a block start even though nothing there is code.
// Cross-checked against XED over ntoskrnl.exe: confirming candidates this way took the count of
// reported block starts that are not real instruction boundaries from 2 to 0 out of ~594k.
func basicBlocks(img *peImage, start, end uint32) []uint32 {
	code := img.slice(start, end-start)
	if code == nil {
		return nil
	}
	// Where a block could begin, and where an instruction provably does begin. A block start is
	// the intersection: claimed by the control flow AND confirmed by a successful decode.
	candidates := map[uint32]bool{start: true}
	decoded := make(map[uint32]bool)
	queue := []uint32{start}
	walked := make(map[uint32]bool)
	for len(queue) > 0 {
		pc := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if walked[pc] || pc < start || pc >= end {
			continue
		}
		for pc >= start && pc < end {
			if walked[pc] {
				break
			}
			walked[pc] = true
			inst, err := x86asm.Decode(code[pc-start:], 64)
			if err != nil {
				// Data in the middle of a function. Stop this path; other paths and other
				// functions are unaffected.
				break
			}
			decoded[pc] = true
			next := pc + uint32(inst.Len)
			if target, ok := directBranchTarget(inst, pc, next); ok && target >= start && target < end {
				candidates[target] = true
				queue = append(queue, target)
			}
			switch inst.Op {
			case x86asm.JMP:
				// Unconditional: whatever follows is only reachable as somebody else's target,
				// so do not fall through into it.
				goto done
			case x86asm.RET, x86asm.IRET, x86asm.IRETD, x86asm.IRETQ, x86asm.UD2, x86asm.HLT:
				goto done
			case x86asm.CALL:
				// The instruction after a call is a block start: libipt ends a block at the
				// call, so the return lands at the head of a new one.
				if next < end {
					candidates[next] = true
				}
			default:
				if isConditionalBranch(inst.Op) && next < end {
					candidates[next] = true
				}
			}
			pc = next
			continue
		done:
			break
		}
	}
	out := make([]uint32, 0, len(candidates))
	for pc := range candidates {
		if decoded[pc] {
			out = append(out, pc)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// directBranchTarget returns the RVA a direct jmp/jcc/call points at.
func directBranchTarget(inst x86asm.Inst, pc, next uint32) (uint32, bool) {
	switch inst.Op {
	case x86asm.JMP, x86asm.CALL:
	default:
		if !isConditionalBranch(inst.Op) {
			return 0, false
		}
	}
	if len(inst.Args) == 0 {
		return 0, false
	}
	rel, ok := inst.Args[0].(x86asm.Rel)
	if !ok {
		return 0, false
	}
	target := int64(next) + int64(rel)
	if target < 0 {
		return 0, false
	}
	return uint32(target), true
}

func isConditionalBranch(op x86asm.Op) bool {
	switch op {
	case x86asm.JA, x86asm.JAE, x86asm.JB, x86asm.JBE, x86asm.JCXZ, x86asm.JE, x86asm.JECXZ,
		x86asm.JG, x86asm.JGE, x86asm.JL, x86asm.JLE, x86asm.JNE, x86asm.JNO, x86asm.JNP,
		x86asm.JNS, x86asm.JO, x86asm.JP, x86asm.JRCXZ, x86asm.JS,
		x86asm.LOOP, x86asm.LOOPE, x86asm.LOOPNE:
		return true
	}
	return false
}

// ---------------------------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------------------------

// peExportNames maps a function's entry RVA to its exported name. This covers the handful of
// entry points a driver exports; everything else falls back to sub_<rva>.
func peExportNames(f *pe.File, oh *pe.OptionalHeader64, img *peImage) map[uint32]string {
	names := make(map[uint32]string)
	dir := oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
	if dir.VirtualAddress == 0 || dir.Size < 40 {
		return names
	}
	d := img.slice(dir.VirtualAddress, 40)
	if d == nil {
		return names
	}
	numNames := binary.LittleEndian.Uint32(d[24:28])
	addrTable := binary.LittleEndian.Uint32(d[28:32])
	nameTable := binary.LittleEndian.Uint32(d[32:36])
	ordTable := binary.LittleEndian.Uint32(d[36:40])
	base := binary.LittleEndian.Uint32(d[16:20])
	numFuncs := binary.LittleEndian.Uint32(d[20:24])
	_ = base
	for i := uint32(0); i < numNames; i++ {
		nameRVAb := img.slice(nameTable+i*4, 4)
		ordb := img.slice(ordTable+i*2, 2)
		if nameRVAb == nil || ordb == nil {
			break
		}
		ord := uint32(binary.LittleEndian.Uint16(ordb))
		if ord >= numFuncs {
			continue
		}
		fnb := img.slice(addrTable+ord*4, 4)
		if fnb == nil {
			continue
		}
		fnRVA := binary.LittleEndian.Uint32(fnb)
		// A forwarder's "address" points inside the export directory rather than at code.
		if fnRVA >= dir.VirtualAddress && fnRVA < dir.VirtualAddress+dir.Size {
			continue
		}
		if name := img.cstring(binary.LittleEndian.Uint32(nameRVAb)); name != "" {
			names[fnRVA] = name
		}
	}
	return names
}

// loadPESymbolSidecar reads "<image>.syms", a file of "<hex-rva> <name>" lines, if it exists.
//
// This exists because the interesting targets are third-party drivers with no PDB, where
// sub_<rva> is the normal outcome rather than a failure - but a name from anywhere else (a public
// PDB, a vendor header, an IDA export, a .map file) is strictly better when it is available. A
// plain text file keeps that door open without making the manager depend on Windows-only symbol
// tooling; syz-manager frequently runs on Linux while the target is Windows.
//
// Produce one for a module with a public PDB using the Debugging Tools' dbh.exe, which loads a
// 64-bit image at 0x1000000, so subtract that from the addresses it prints:
//
//	dbh -s:"srv*C:\Symbols*https://msdl.microsoft.com/download/symbols" module.sys enum *
//
// It prints "index address : name"; keep the name and turn the address into an RVA.
func loadPESymbolSidecar(imagePath string) map[uint32]string {
	names := make(map[uint32]string)
	f, err := os.Open(imagePath + ".syms")
	if err != nil {
		return names
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	bad := 0
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		rva, err := strconv.ParseUint(strings.TrimPrefix(fields[0], "0x"), 16, 32)
		if err != nil {
			bad++
			continue
		}
		names[uint32(rva)] = fields[1]
	}
	log.Logf(1, "coverage: %v.syms provided %v symbol names (%v unparsable lines)",
		filepath.Base(imagePath), len(names), bad)
	return names
}

func (img *peImage) cstring(rva uint32) string {
	if rva >= uint32(len(img.data)) {
		return ""
	}
	buf := img.data[rva:]
	if len(buf) > 512 {
		buf = buf[:512]
	}
	for i, c := range buf {
		if c == 0 {
			return string(buf[:i])
		}
	}
	return ""
}
