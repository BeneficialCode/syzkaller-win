// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package cover

import (
	"fmt"
	"html/template"
	"io"
	"sort"
)

// Function-level coverage for targets with no source code.
//
// The rest of this package renders file -> line -> program, reading the source text off disk. For
// a closed-source binary driver there is no source text to render and no line table to map to, so
// rather than inventing line numbers this walks the symbols the PE backend recovered from .pdata
// and reports coverage per function - which is the unit somebody fuzzing a binary blob can
// actually act on.
//
// Two numbers per function, deliberately kept apart:
//
//   - covered/total against the STATIC block list from recursive descent. That list is a lower
//     bound: direct branches are all found, indirect ones cannot be, so total understates reality.
//   - "+N indirect": covered PCs that landed inside the function but were not in the static list.
//     Measured on real traces this is around 9% of blocks. Folding them into the first number
//     would produce percentages above 100 and hide the distinction; dropping them would throw
//     away real coverage.

type binFunc struct {
	Name       string
	Start      uint64
	Size       uint64
	Total      int
	Covered    int
	Indirect   int
	ProgCount  int
	ExampleIdx int
}

type binModule struct {
	Name       string
	Path       string
	Funcs      []*binFunc
	Total      int
	Covered    int
	Indirect   int
	CoveredFns int
}

func (m *binModule) Percent() string { return percentOf(m.Covered, m.Total) }
func (f *binFunc) Percent() string   { return percentOf(f.Covered, f.Total) }

func percentOf(covered, total int) string {
	if total == 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f%%", 100*float64(covered)/float64(total))
}

func (rg *ReportGenerator) prepareBinaryReport(progs []Prog) ([]*binModule, int, []uint64, error) {
	if len(rg.Symbols) == 0 {
		return nil, 0, nil, fmt.Errorf("no symbols were recovered from the traced module's image")
	}
	// Which programs cover each PC. Needed so a function can be traced back to an example
	// program, the same way the source view links a line to one.
	progPCs := make(map[uint64]map[int]bool)
	for i, prog := range progs {
		for _, pc := range prog.PCs {
			if progPCs[pc] == nil {
				progPCs[pc] = make(map[int]bool)
			}
			progPCs[pc][i] = true
		}
	}
	if len(progPCs) == 0 {
		return nil, 0, nil, fmt.Errorf("no coverage collected so far")
	}
	byModule := make(map[string]*binModule)
	var order []*binModule
	// Sorted symbol starts, so a covered PC can be charged to the function containing it.
	for _, sym := range rg.Symbols {
		name := sym.Module.Name
		mod := byModule[name]
		if mod == nil {
			mod = &binModule{Name: name, Path: sym.Unit.Path}
			byModule[name] = mod
			order = append(order, mod)
		}
		static := make(map[uint64]bool, len(sym.PCs))
		for _, pc := range sym.PCs {
			static[pc] = true
		}
		fn := &binFunc{
			Name:       sym.Name,
			Start:      sym.Start,
			Size:       sym.End - sym.Start,
			Total:      len(static),
			ExampleIdx: -1,
		}
		covering := make(map[int]bool)
		for pc, progs := range progPCs {
			if pc < sym.Start || pc >= sym.End {
				continue
			}
			if static[pc] {
				fn.Covered++
			} else {
				fn.Indirect++
			}
			for idx := range progs {
				covering[idx] = true
			}
		}
		fn.ProgCount = len(covering)
		for idx := range covering {
			if fn.ExampleIdx == -1 || len(progs[idx].Data) < len(progs[fn.ExampleIdx].Data) {
				fn.ExampleIdx = idx
			}
		}
		mod.Funcs = append(mod.Funcs, fn)
		mod.Total += fn.Total
		mod.Covered += fn.Covered
		mod.Indirect += fn.Indirect
		if fn.Covered+fn.Indirect > 0 {
			mod.CoveredFns++
		}
	}
	// Charge anything left over. A handful of these are expected - a .pdata hole whose gap was
	// too small or too data-like to reconstruct - but a large count means the module index space
	// disagrees between the two sides, or the host's image is not the one actually running. Both
	// of those invalidate the whole report, so make the number visible either way.
	unattributed := 0
	var examples []uint64
	for pc := range progPCs {
		if rg.findSymbol(pc) == nil {
			unattributed++
			if len(examples) < 8 {
				examples = append(examples, pc)
			}
		}
	}
	sort.Slice(examples, func(i, j int) bool { return examples[i] < examples[j] })
	for _, mod := range order {
		// Most-covered first: with tens of thousands of functions, the interesting ones are the
		// ones the fuzzer is actually reaching.
		sort.Slice(mod.Funcs, func(i, j int) bool {
			a, b := mod.Funcs[i], mod.Funcs[j]
			if (a.Covered+a.Indirect > 0) != (b.Covered+b.Indirect > 0) {
				return a.Covered+a.Indirect > 0
			}
			if a.Covered != b.Covered {
				return a.Covered > b.Covered
			}
			return a.Start < b.Start
		})
	}
	sort.Slice(order, func(i, j int) bool { return order[i].Covered > order[j].Covered })
	return order, unattributed, examples, nil
}

// DoBinaryHTML renders the function-level view. It is what /cover serves for a target whose
// coverage comes from Intel PT rather than from source instrumentation.
func (rg *ReportGenerator) DoBinaryHTML(w io.Writer, progs []Prog, coverFilter map[uint32]uint32) error {
	modules, unattributed, examples, err := rg.prepareBinaryReport(progs)
	if err != nil {
		return err
	}
	// A full function list for ntoskrnl is ~37k rows, which no browser enjoys. Uncovered
	// functions carry no information beyond their count, so cap them.
	const maxUncovered = 200
	type modView struct {
		*binModule
		Shown       []*binFunc
		HiddenUncov int
		TotalFuncs  int
	}
	views := make([]*modView, 0, len(modules))
	for _, mod := range modules {
		v := &modView{binModule: mod, TotalFuncs: len(mod.Funcs)}
		uncov := 0
		for _, fn := range mod.Funcs {
			if fn.Covered+fn.Indirect == 0 {
				uncov++
				if uncov > maxUncovered {
					continue
				}
			}
			v.Shown = append(v.Shown, fn)
		}
		if uncov > maxUncovered {
			v.HiddenUncov = uncov - maxUncovered
		}
		views = append(views, v)
	}
	exampleText := make([]string, 0, len(examples))
	for _, pc := range examples {
		exampleText = append(exampleText, fmt.Sprintf("module %v + %#x",
			pc>>26, pc&((1<<26)-1)))
	}
	data := struct {
		Modules      []*modView
		Unattributed int
		Examples     []string
	}{views, unattributed, exampleText}
	return binaryCoverTemplate.Execute(w, data)
}

var binaryCoverTemplate = template.Must(template.New("").Parse(`
<!doctype html>
<html><head><title>syzkaller binary coverage</title>
<style>
	body { font-family: Arial, sans-serif; font-size: 13px; margin: 1em; }
	h2 { font-size: 15px; margin-bottom: 0.3em; }
	table { border-collapse: collapse; margin-bottom: 2em; }
	th, td { border: 1px solid #ccc; padding: 2px 8px; text-align: right; }
	th:first-child, td:first-child { text-align: left; font-family: monospace; }
	th { background: #eee; }
	tr.uncovered td { color: #999; }
	.note { color: #555; max-width: 60em; margin-bottom: 1.5em; }
	.warn { color: #a00; font-weight: bold; }
</style>
</head><body>
<p class="note">
Coverage recovered from Intel PT. Functions and their basic blocks come from the image's
<code>.pdata</code> exception directory plus recursive-descent disassembly, so no source and no
PDB are required; a function with no symbol is named <code>sub_&lt;rva&gt;</code>.
<b>blocks</b> is a lower bound - static analysis cannot find indirect branch targets - so
<b>indirect</b> counts covered blocks that were not in the static list rather than folding them in
and producing percentages above 100.
</p>
{{if .Unattributed}}
<p class="warn">{{.Unattributed}} covered PCs fall outside every known function. A few are normal
(a <code>.pdata</code> hole too small or too data-like to reconstruct); a large number means the
module index space disagrees between target and host, or the image on the host is not the one
running on the target. Examples: {{range .Examples}}<code>{{.}}</code> {{end}}</p>
{{end}}
{{range .Modules}}
<h2>{{.Name}} &mdash; {{.Covered}}/{{.Total}} blocks ({{.Percent}}), {{.CoveredFns}}/{{.TotalFuncs}} functions
	{{if .Indirect}}, +{{.Indirect}} indirect{{end}}</h2>
<div class="note">{{.Path}}</div>
<table>
<tr><th>function</th><th>rva</th><th>size</th><th>covered</th><th>blocks</th><th>%</th><th>indirect</th><th>progs</th></tr>
{{range .Shown}}
<tr{{if not .ProgCount}} class="uncovered"{{end}}>
	<td>{{.Name}}</td>
	<td>{{printf "%#x" .Start}}</td>
	<td>{{.Size}}</td>
	<td>{{.Covered}}</td>
	<td>{{.Total}}</td>
	<td>{{.Percent}}</td>
	<td>{{if .Indirect}}+{{.Indirect}}{{end}}</td>
	<td>{{if .ProgCount}}{{.ProgCount}}{{end}}</td>
</tr>
{{end}}
</table>
{{if .HiddenUncov}}<p class="note">{{.HiddenUncov}} further functions with no coverage are not listed.</p>{{end}}
{{end}}
</body></html>
`))

// UsesBinaryReport reports whether this generator produces the function-level view rather than
// the source view. The PE backend is the only one that leaves Frames empty while still having
// Symbols, because there is nothing to symbolize to.
func (rg *ReportGenerator) UsesBinaryReport() bool {
	return rg.target.OS == "windows"
}
