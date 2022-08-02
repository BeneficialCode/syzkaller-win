// Copyright 2015/2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"text/template"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/pkg/compiler"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/serializer"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

type SyscallData struct {
	Name     string   // syzlang中的调用名,如accept$inet
	CallName string   // 实际的syscall调用名,如accept
	NR       int32    // syscall对应的调用号,如30
	NeedCall bool     // 一个用于后续的syz-executor源码生成的标志
	Attrs    []uint64 // 存放分析syzlang所生成的SyscallAttrs数据数组
}

type Define struct {
	Name  string
	Value string
}

type ArchData struct {
	Revision   string
	ForkServer int
	Shmem      int
	GOARCH     string
	PageSize   uint64
	NumPages   uint64
	DataOffset uint64
	Calls      []SyscallData
	Defines    []Define
}

type OSData struct {
	GOOS  string
	Archs []ArchData
}

type CallPropDescription struct {
	Type string
	Name string
}

type ExecutorData struct {
	OSes      []OSData
	CallAttrs []string
	CallProps []CallPropDescription
}

var srcDir = flag.String("src", "", "path to root of syzkaller source dir")
var outDir = flag.String("out", "", "path to out dir")

func main() {
	defer tool.Init()()

	var OSList []string // [1] 将所有OS的类型名都取出来
	for OS := range targets.List {
		OSList = append(OSList, OS)
	}
	sort.Strings(OSList)
	// [2] 创建用于存储结果的结构体-data
	data := &ExecutorData{}
	for _, OS := range OSList { // [3] 解析各种OS的syzlang代码
		descriptions := ast.ParseGlob(filepath.Join(*srcDir, "sys", OS, "*.txt"), nil)
		if descriptions == nil { // [3-1] syzlang文件解析成AST树
			os.Exit(1)
		}
		constFile := compiler.DeserializeConstFile(filepath.Join(*srcDir, "sys", OS, "*.const"), nil)
		if constFile == nil { // .const 文件解析成ConstFile结构体
			os.Exit(1)
		}
		// syz-sysgen 输出结果存放目录
		osutil.MkdirAll(filepath.Join(*outDir, "sys", OS, "gen"))

		var archs []string
		for arch := range targets.List[OS] {
			archs = append(archs, arch)
		}
		sort.Strings(archs)

		var jobs []*Job // [3-2] 为每个arch创建一个Job结构体，将其添加到jobs数组中，并为数组执行排序工作
		for _, arch := range archs {
			jobs = append(jobs, &Job{
				Target:      targets.List[OS][arch],
				Unsupported: make(map[string]bool),
			})
		}
		sort.Slice(jobs, func(i, j int) bool {
			return jobs[i].Target.Arch < jobs[j].Target.Arch
		})
		var wg sync.WaitGroup // sync.WaitGroup用于等待指定数量的go routine集合执行完成
		wg.Add(len(jobs))

		for _, job := range jobs { // 遍历每个job,创建go routine 并执行这些job
			job := job
			go func() {
				defer wg.Done()
				processJob(job, descriptions, constFile)
			}()
		}
		wg.Wait()

		var syscallArchs []ArchData
		unsupported := make(map[string]int)
		for _, job := range jobs {
			if !job.OK {
				fmt.Printf("compilation of %v/%v target failed:\n", job.Target.OS, job.Target.Arch)
				for _, msg := range job.Errors {
					fmt.Print(msg)
				}
				os.Exit(1)
			}
			syscallArchs = append(syscallArchs, job.ArchData)
			for u := range job.Unsupported {
				unsupported[u]++
			}
		}
		// [3-3] 将processJob生成的job.ArchData保存到data中
		// job.ArchData即syscall属性相关的信息
		data.OSes = append(data.OSes, OSData{
			GOOS:  OS,
			Archs: syscallArchs,
		})

		for what, count := range unsupported {
			if count == len(jobs) {
				tool.Failf("%v is unsupported on all arches (typo?)", what)
			}
		}
	}
	// [4] 分别将prog.SyscallAttrs和prog.CallProps这两个结构体对应的字段名存起来
	attrs := reflect.TypeOf(prog.SyscallAttrs{})
	for i := 0; i < attrs.NumField(); i++ {
		data.CallAttrs = append(data.CallAttrs, prog.CppName(attrs.Field(i).Name))
	}

	props := prog.CallProps{}
	props.ForeachProp(func(name, _ string, value reflect.Value) {
		data.CallProps = append(data.CallProps, CallPropDescription{
			Type: value.Kind().String(),
			Name: prog.CppName(name),
		})
	})

	writeExecutorSyscalls(data)
}

type Job struct {
	Target      *targets.Target // 存放着一些关于特定OS、arch的一些常量信息
	OK          bool
	Errors      []string        // 保存错误信息的字符串集合，一条字符串代表一行报错信息
	Unsupported map[string]bool // 存放不支持的syscall集合
	ArchData    ArchData        // 存放待从worker routine返回给main函数的数据
}

func processJob(job *Job, descriptions *ast.Description, constFile *compiler.ConstFile) {
	eh := func(pos ast.Pos, msg string) { // [1] 生成一个error handler用于输出错误信息
		job.Errors = append(job.Errors, fmt.Sprintf("%v: %v\n", pos, msg))
	}
	// [2] 取出对应arch的consts字符串->整型 映射表
	consts := constFile.Arch(job.Target.Arch)
	// [3] 过滤掉自己开发人员测试使用的testOS
	if job.Target.OS == targets.TestOS {
		constInfo := compiler.ExtractConsts(descriptions, job.Target, eh)
		compiler.FabricateSyscallConsts(job.Target, constInfo, consts)
	}
	// [4] 对syzlang AST 进行编译，进一步分析AST信息
	// 这次编译提供了consts信息，因此会执行完整的编译过程
	prog := compiler.Compile(descriptions, consts, job.Target, eh)
	if prog == nil {
		return
	}
	for what := range prog.Unsupported {
		job.Unsupported[what] = true
	}
	// [5] 将分析结果，序列化为go语言源码，留待后续syz-fuzzer使用
	// 代码存在sys/<OS>/gen/<arch>.go
	sysFile := filepath.Join(*outDir, "sys", job.Target.OS, "gen", job.Target.Arch+".go")
	out := new(bytes.Buffer)
	generate(job.Target, prog, consts, out)
	rev := hash.String(out.Bytes())
	fmt.Fprintf(out, "const revision_%v = %q\n", job.Target.Arch, rev)
	writeSource(sysFile, out.Bytes())
	// 创建executor的syscall信息，并将其返回给job
	job.ArchData = generateExecutorSyscalls(job.Target, prog.Syscalls, rev)

	// Don't print warnings, they are printed in syz-check.
	job.Errors = nil
	job.OK = true
}

func generate(target *targets.Target, prg *compiler.Prog, consts map[string]uint64, out io.Writer) {
	tag := fmt.Sprintf("syz_target,syz_os_%v,syz_arch_%v", target.OS, target.Arch)
	if target.VMArch != "" {
		tag += fmt.Sprintf(" syz_target,syz_os_%v,syz_arch_%v", target.OS, target.VMArch)
	}
	fmt.Fprintf(out, "// AUTOGENERATED FILE\n")
	fmt.Fprintf(out, "// +build !codeanalysis\n")
	fmt.Fprintf(out, "// +build !syz_target %v\n\n", tag)
	fmt.Fprintf(out, "package gen\n\n")
	fmt.Fprintf(out, "import . \"github.com/google/syzkaller/prog\"\n")
	fmt.Fprintf(out, "import . \"github.com/google/syzkaller/sys/%v\"\n\n", target.OS)

	fmt.Fprintf(out, "func init() {\n")
	fmt.Fprintf(out, "\tRegisterTarget(&Target{"+
		"OS: %q, Arch: %q, Revision: revision_%v, PtrSize: %v, PageSize: %v, "+
		"NumPages: %v, DataOffset: %v, LittleEndian: %v, ExecutorUsesShmem: %v, "+
		"Syscalls: syscalls_%v, Resources: resources_%v, Consts: consts_%v}, "+
		"types_%v, InitTarget)\n}\n\n",
		target.OS, target.Arch, target.Arch, target.PtrSize, target.PageSize,
		target.NumPages, target.DataOffset, target.LittleEndian, target.ExecutorUsesShmem,
		target.Arch, target.Arch, target.Arch, target.Arch)

	fmt.Fprintf(out, "var resources_%v = ", target.Arch)
	serializer.Write(out, prg.Resources)
	fmt.Fprintf(out, "\n\n")

	fmt.Fprintf(out, "var syscalls_%v = ", target.Arch)
	serializer.Write(out, prg.Syscalls)
	fmt.Fprintf(out, "\n\n")

	fmt.Fprintf(out, "var types_%v = ", target.Arch)
	serializer.Write(out, prg.Types)
	fmt.Fprintf(out, "\n\n")

	constArr := make([]prog.ConstValue, 0, len(consts))
	for name, val := range consts {
		constArr = append(constArr, prog.ConstValue{Name: name, Value: val})
	}
	sort.Slice(constArr, func(i, j int) bool {
		return constArr[i].Name < constArr[j].Name
	})
	fmt.Fprintf(out, "var consts_%v = ", target.Arch)
	serializer.Write(out, constArr)
	fmt.Fprintf(out, "\n\n")
}

// 生成syscall信息
func generateExecutorSyscalls(target *targets.Target, syscalls []*prog.Syscall, rev string) ArchData {
	data := ArchData{ // [1] 创建ArchData结构体，该结构体最后会返回给main
		Revision:   rev,
		GOARCH:     target.Arch,
		PageSize:   target.PageSize,
		NumPages:   target.NumPages,
		DataOffset: target.DataOffset,
	}
	// 若目标OS & arch对应的target结构体，设置了对ForkServer和Shmem(共享内存的支持)
	// 则设置data中相应字段
	// 这样syz-executor便能使用这两种技术加速fuzz
	if target.ExecutorUsesForkServer {
		data.ForkServer = 1
	}
	if target.ExecutorUsesShmem {
		data.Shmem = 1
	}
	defines := make(map[string]string)
	for _, c := range syscalls { // [2] 遍历各个syscall类型的结构体
		var attrVals []uint64
		// 取出各个字段，依次存放至整型数组
		attrs := reflect.ValueOf(c.Attrs)
		last := -1
		for i := 0; i < attrs.NumField(); i++ {
			attr := attrs.Field(i)
			val := uint64(0)
			switch attr.Type().Kind() {
			case reflect.Bool:
				if attr.Bool() {
					val = 1
				}
			case reflect.Uint64:
				val = attr.Uint()
			default:
				panic("unsupported syscall attribute type")
			}
			attrVals = append(attrVals, val)
			if val != 0 {
				last = i
			}
		} // 再使用生成的attrVals数组进一步生成SyscallData结构体
		data.Calls = append(data.Calls, newSyscallData(target, c, attrVals[:last+1]))
		// Some syscalls might not be present on the compiling machine, so we
		// generate definitions for them.
		if target.SyscallNumbers && !strings.HasPrefix(c.CallName, "syz_") &&
			target.NeedSyscallDefine(c.NR) {
			defines[target.SyscallPrefix+c.CallName] = fmt.Sprintf("%d", c.NR)
		}
	}
	// [3] 将生成的data.Calls数组进行排序，并返回data变量
	sort.Slice(data.Calls, func(i, j int) bool {
		return data.Calls[i].Name < data.Calls[j].Name
	})
	// Get a sorted list of definitions.
	defineNames := []string{}
	for key := range defines {
		defineNames = append(defineNames, key)
	}
	sort.Strings(defineNames)
	for _, key := range defineNames {
		data.Defines = append(data.Defines, Define{key, defines[key]})
	}
	return data
}

func newSyscallData(target *targets.Target, sc *prog.Syscall, attrs []uint64) SyscallData {
	callName, patchCallName := target.SyscallTrampolines[sc.Name]
	if !patchCallName {
		callName = sc.CallName
	}
	return SyscallData{
		Name:     sc.Name,
		CallName: callName,
		NR:       int32(sc.NR),
		NeedCall: (!target.SyscallNumbers || strings.HasPrefix(sc.CallName, "syz_") || patchCallName) && !sc.Attrs.Disabled,
		Attrs:    attrs,
	}
}

func writeExecutorSyscalls(data *ExecutorData) {
	osutil.MkdirAll(filepath.Join(*outDir, "executor"))
	sort.Slice(data.OSes, func(i, j int) bool {
		return data.OSes[i].GOOS < data.OSes[j].GOOS
	})
	buf := new(bytes.Buffer)
	if err := defsTempl.Execute(buf, data); err != nil {
		tool.Failf("failed to execute defs template: %v", err)
	}
	// [1] 生成defs.h文件
	writeFile(filepath.Join(*outDir, "executor", "defs.h"), buf.Bytes())
	buf.Reset()
	if err := syscallsTempl.Execute(buf, data); err != nil {
		tool.Failf("failed to execute syscalls template: %v", err)
	}
	// [2] 生成syscalls.h文件
	writeFile(filepath.Join(*outDir, "executor", "syscalls.h"), buf.Bytes())
}

func writeSource(file string, data []byte) {
	if oldSrc, err := ioutil.ReadFile(file); err == nil && bytes.Equal(data, oldSrc) {
		return
	}
	writeFile(file, data)
}

func writeFile(file string, data []byte) {
	outf, err := os.Create(file)
	if err != nil {
		tool.Failf("failed to create output file: %v", err)
	}
	defer outf.Close()
	outf.Write(data)
}

var defsTempl = template.Must(template.New("").Parse(`// AUTOGENERATED FILE

struct call_attrs_t { {{range $attr := $.CallAttrs}}
	uint64_t {{$attr}};{{end}}
};

struct call_props_t { {{range $attr := $.CallProps}}
	{{$attr.Type}} {{$attr.Name}};{{end}}
};

#define read_call_props_t(var, reader) { \{{range $attr := $.CallProps}}
	(var).{{$attr.Name}} = ({{$attr.Type}})(reader); \{{end}}
}

{{range $os := $.OSes}}
#if GOOS_{{$os.GOOS}}
#define GOOS "{{$os.GOOS}}"
{{range $arch := $os.Archs}}
#if GOARCH_{{$arch.GOARCH}}
#define GOARCH "{{.GOARCH}}"
#define SYZ_REVISION "{{.Revision}}"
#define SYZ_EXECUTOR_USES_FORK_SERVER {{.ForkServer}}
#define SYZ_EXECUTOR_USES_SHMEM {{.Shmem}}
#define SYZ_PAGE_SIZE {{.PageSize}}
#define SYZ_NUM_PAGES {{.NumPages}}
#define SYZ_DATA_OFFSET {{.DataOffset}}
{{range $c := $arch.Defines}}#ifndef {{$c.Name}}
#define {{$c.Name}} {{$c.Value}}
#endif
{{end}}#endif
{{end}}
#endif
{{end}}
`))

// nolint: lll
var syscallsTempl = template.Must(template.New("").Parse(`// AUTOGENERATED FILE
// clang-format off
{{range $os := $.OSes}}
#if GOOS_{{$os.GOOS}}
{{range $arch := $os.Archs}}
#if GOARCH_{{$arch.GOARCH}}
const call_t syscalls[] = {
{{range $c := $arch.Calls}}    {"{{$c.Name}}", {{$c.NR}}{{if or $c.Attrs $c.NeedCall}}, { {{- range $attr := $c.Attrs}}{{$attr}}, {{end}}}{{end}}{{if $c.NeedCall}}, (syscall_t){{$c.CallName}}{{end}}},
{{end}}};
#endif
{{end}}
#endif
{{end}}
`))
