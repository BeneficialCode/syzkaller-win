// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"text/template"

	"github.com/google/syzkaller/pkg/compiler"
	"github.com/google/syzkaller/pkg/osutil"
)

type extractParams struct {
	AddSource      string
	DeclarePrintf  bool
	DefineGlibcUse bool // workaround for incorrect flags to clang for fuchsia.
	ExtractFromELF bool
	TargetEndian   binary.ByteOrder
}

func extract(info *compiler.ConstInfo, cc string, args []string, params *extractParams) (
	map[string]uint64, map[string]bool, error) {
	data := &CompileData{ // [1] 初始化: 声明一系列的map
		extractParams: params,
		Defines:       info.Defines,
		Includes:      info.Includes,
		Values:        info.Consts,
	}
	bin := "" // 编译生成的程序路径
	missingIncludes := make(map[string]bool)
	undeclared := make(map[string]bool) // 未定义的const，通常是自己定义的常量
	valMap := make(map[string]bool)     // 声明并初始化valMap中各个元素为true
	for _, val := range info.Consts {
		valMap[val] = true
	}
	for { // [2] 尝试将consts常量字符串与模板C代码结合，并编译结合后的代码，生成一个可执行文件
		// [2-1] 编译操作，返回结果分别为编译出的可执行文件路径/编译器标准输出/编译器错误输出
		bin1, out, err := compile(cc, args, data)
		if err == nil {
			bin = bin1
			break
		}
		// Some consts and syscall numbers are not defined on some archs.
		// Figure out from compiler output undefined consts,
		// and try to compile again without them.
		// May need to try multiple times because some severe errors terminate compilation.
		tryAgain := false
		for _, errMsg := range []string{ // [2-2] 遍历所有预先定义的错误信息，并使用正则表达式匹配
			`error: [‘']([a-zA-Z0-9_]+)[’'] undeclared`,
			`note: in expansion of macro [‘']([a-zA-Z0-9_]+)[’']`,
			`note: expanded from macro [‘']([a-zA-Z0-9_]+)[’']`,
			`error: use of undeclared identifier [‘']([a-zA-Z0-9_]+)[’']`,
		} {
			re := regexp.MustCompile(errMsg)
			matches := re.FindAllSubmatch(out, -1)
			for _, match := range matches { // [2-3] 如果匹配到了，则将出问题的常量存于undeclared中
				val := string(match[1])
				if valMap[val] && !undeclared[val] {
					undeclared[val] = true
					tryAgain = true
				}
			}
		}
		if !tryAgain {
			return nil, nil, fmt.Errorf("failed to run compiler: %v %v\n%v\n%s",
				cc, args, err, out)
		}
		data.Values = nil               // 重置编译用的consts数组
		for _, v := range info.Consts { // [2-4] 将出错的consts剔除，并将剩余没出错的consts存入编译用consts数组
			if undeclared[v] {
				continue
			}
			data.Values = append(data.Values, v)
		}
		data.Includes = nil
		for _, v := range info.Includes {
			if missingIncludes[v] {
				continue
			}
			data.Includes = append(data.Includes, v)
		}
	}
	defer os.Remove(bin) // [3] 函数退出时将新编译出的二进制文件删除

	var flagVals []uint64
	var err error
	if data.ExtractFromELF { // [4] 从编译出的二进制文件中读取数值，解析并返回
		flagVals, err = extractFromELF(bin, params.TargetEndian)
	} else {
		flagVals, err = extractFromExecutable(bin)
	}
	if err != nil {
		return nil, nil, err
	}
	if len(flagVals) != len(data.Values) {
		return nil, nil, fmt.Errorf("fetched wrong number of values %v, want != %v",
			len(flagVals), len(data.Values))
	}
	res := make(map[string]uint64)
	for i, name := range data.Values {
		res[name] = flagVals[i]
	}
	// res是const字符串与整型的映射,undeclared是未声明const字符串与bool值的映射
	return res, undeclared, nil
}

type CompileData struct {
	*extractParams
	Defines  map[string]string
	Includes []string
	Values   []string
}

func compile(cc string, args []string, data *CompileData) (string, []byte, error) {
	src := new(bytes.Buffer)                               // 创建填充好后的C代码缓冲区
	if err := srcTemplate.Execute(src, data); err != nil { // 使用传入的data对代码进行填充
		return "", nil, fmt.Errorf("failed to generate source: %v", err)
	}
	srcFile, err := osutil.TempFile("src-code") // 创建一个临时源码文件
	if err != nil {
		return "", nil, err
	}
	binFile, err := osutil.TempFile("syz-extract-bin") // 创建一个临时可执行文件
	osutil.WriteFile(srcFile, src.Bytes())
	if err != nil {
		return "", nil, err
	}
	args = append(args, []string{ // 为编译器添加额外的参数
		"-o", binFile, // 指定文件输出的路径
		"-w",
		"-Tc", srcFile, // 指定代码语言为c语言
	}...)
	if data.ExtractFromELF {
		args = append(args, "-c") // 只编译不链接
	}
	fmt.Printf("args: %s\n", args)
	// src是生成出来的源码
	// fmt.Printf("src: %v", src)
	cmd := osutil.Command(cc, args...) // 执行程序
	cmd.Stdin = src
	if out, err := cmd.CombinedOutput(); err != nil {
		os.Remove(binFile)
		return "", out, err
	}
	return binFile, nil, nil
}

func extractFromExecutable(binFile string) ([]uint64, error) {
	out, err := osutil.Command(binFile).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to run flags binary: %v\n%s", err, out)
	}
	if len(out) == 0 {
		return nil, nil
	}
	var vals []uint64
	for _, val := range strings.Split(string(out), " ") {
		n, err := strconv.ParseUint(val, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse value: %v (%v)", err, val)
		}
		vals = append(vals, n)
	}
	return vals, nil
}

func extractFromELF(binFile string, targetEndian binary.ByteOrder) ([]uint64, error) {
	f, err := os.Open(binFile)
	if err != nil {
		return nil, err
	}
	ef, err := elf.NewFile(f)
	if err != nil {
		return nil, err
	}
	for _, sec := range ef.Sections {
		if sec.Name != "syz_extract_data" {
			continue
		}
		data, err := ioutil.ReadAll(sec.Open())
		if err != nil {
			return nil, err
		}
		vals := make([]uint64, len(data)/8)
		if err := binary.Read(bytes.NewReader(data), targetEndian, &vals); err != nil {
			return nil, err
		}
		return vals, nil
	}
	return nil, fmt.Errorf("did not find syz_extract_data section")
}

// 模板C代码
var srcTemplate = template.Must(template.New("").Parse(`
{{if not .ExtractFromELF}}
#define __asm__(...)
{{end}}

{{if .DefineGlibcUse}}
#ifndef __GLIBC_USE
#	define __GLIBC_USE(X) 0
#endif
{{end}}

{{range $incl := $.Includes}}
#include <{{$incl}}>
{{end}}

{{range $name, $val := $.Defines}}
#ifndef {{$name}}
#	define {{$name}} {{$val}}
#endif
{{end}}

{{.AddSource}}

{{if .DeclarePrintf}}
int printf(const char *format, ...);
{{end}}

{{if .ExtractFromELF}}
__attribute__((section("syz_extract_data")))
unsigned long long vals[] = {
	{{range $val := $.Values}}(unsigned long long){{$val}},
	{{end}}
};
{{else}}
int main() {
	int i;
	unsigned long long vals[] = {
		{{range $val := $.Values}}(unsigned long long){{$val}},
		{{end}}
	};
	for (i = 0; i < sizeof(vals)/sizeof(vals[0]); i++) {
		if (i != 0)
			printf(" ");
		printf("%llu", vals[i]);
	}
	return 0;
}
{{end}}
`))
