// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"github.com/google/syzkaller/pkg/compiler"
)

type windows struct{}

// 初始化操作，可删除之前编译所生成的文件和配置文件
func (*windows) prepare(sourcedir string, build bool, arches []*Arch) error {
	return nil
}

// 可用于补全缺失的头文件
func (*windows) prepareArch(arch *Arch) error {
	return nil
}

// 编译并搜集常量
func (*windows) processFile(arch *Arch, info *compiler.ConstInfo) (map[string]uint64, map[string]bool, error) {
	params := &extractParams{ // [1] 准备extract参数
		DeclarePrintf: true,
		TargetEndian:  arch.target.HostEndian,
	}
	return extract(info, "cl", nil, params) // [2] 返回结果
}
