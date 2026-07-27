// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package isolated

import (
	"testing"

	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm/vmimpl"
)

func TestEscapeDoubleQuotes(t *testing.T) {
	testcases := []struct {
		inp      string
		expected string
	}{
		// Input with no quoting returns the same string.
		{
			"",
			"",
		},
		{
			"adsf",
			"adsf",
		},
		// Inputs with escaping of characters other that double
		// quotes returns the same input.
		{
			"\\$\\`\\\\\n", // \$\`\\\n
			"\\$\\`\\\\\n", // \$\`\\\n
		},
		// Input with double quote.
		{
			`"`,
			`\"`,
		},
		// Input with already escaped double quote.
		{
			`\"`,
			`\\\"`,
		},
		// Input with already escaped backtick and already
		// double quote. Should only re-escape the
		// double quote.
		{
			"\\`something\"",   // \`something"
			"\\`something\\\"", // \`something\"
		},
		// Input with already escaped backtick and already
		// escaped double quote. Should only re-escape the
		// escaped double quote.
		{
			"\\`something\\\"",     // \`something\"
			"\\`something\\\\\\\"", // \`something\\\"
		},
		{
			`touch \
    /tmp/OK
touch '/tmp/OK2'
touch "/tmp/OK3"
touch /tmp/OK4
bash -c "bash -c \"ls -al\""`,
			`touch \
    /tmp/OK
touch '/tmp/OK2'
touch \"/tmp/OK3\"
touch /tmp/OK4
bash -c \"bash -c \\\"ls -al\\\"\"`,
		},
	}
	for i, tc := range testcases {
		output := vmimpl.EscapeDoubleQuotes(tc.inp)
		if tc.expected != output {
			t.Fatalf("%v: For input %v Expected escaped string %v got %v", i+1, tc.inp, tc.expected, output)
		}
	}
}

func TestSplitTargetPort(t *testing.T) {
	tests := []struct {
		in       string
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{"192.168.2.17", "192.168.2.17", 22, false},
		{"192.168.2.17:2222", "192.168.2.17", 2222, false},
		{"host.example", "host.example", 22, false},
		{":22", "", 0, true},
		{"host:notaport", "", 0, true},
		{"host:99999", "", 0, true},
	}
	for _, test := range tests {
		host, port, err := splitTargetPort(test.in)
		if (err != nil) != test.wantErr {
			t.Errorf("splitTargetPort(%q): err=%v, wantErr=%v", test.in, err, test.wantErr)
			continue
		}
		if err != nil {
			continue
		}
		if host != test.wantHost || port != test.wantPort {
			t.Errorf("splitTargetPort(%q) = (%q, %v), want (%q, %v)",
				test.in, host, port, test.wantHost, test.wantPort)
		}
	}
}

// targetPath must use the TARGET's separator, not the host's. filepath.Join follows the host,
// which is how the original code ended up sending backslashes to a Linux target whenever the
// manager ran on Windows.
func TestTargetPath(t *testing.T) {
	tests := []struct {
		os        string
		targetDir string
		name      string
		want      string
	}{
		{targets.Windows, `C:\syzkaller`, "syz-executor.exe", `C:\syzkaller\syz-executor.exe`},
		{targets.Windows, `C:\syzkaller\`, "syz-executor.exe", `C:\syzkaller\syz-executor.exe`},
		{targets.Windows, "syzkaller", "syz-fuzzer.exe", `syzkaller\syz-fuzzer.exe`},
		{targets.Linux, "/tmp/syzkaller", "syz-executor", "/tmp/syzkaller/syz-executor"},
		{targets.Linux, "/tmp/syzkaller/", "syz-executor", "/tmp/syzkaller/syz-executor"},
	}
	for _, test := range tests {
		inst := &instance{os: test.os, cfg: &Config{TargetDir: test.targetDir}}
		if got := inst.targetPath(test.name); got != test.want {
			t.Errorf("targetPath(os=%v, dir=%q, %q) = %q, want %q",
				test.os, test.targetDir, test.name, got, test.want)
		}
	}
}

func TestToSftpPath(t *testing.T) {
	tests := []struct{ in, want string }{
		// Windows OpenSSH's sftp server roots every drive under "/", so a drive-letter path
		// without the leading slash is read as relative to the login home and the transfer
		// fails with "no such file or directory".
		{`C:\syzkaller\syz-executor.exe`, "/C:/syzkaller/syz-executor.exe"},
		{`d:/lower/case`, "/d:/lower/case"},
		{`syzkaller\a\b`, "syzkaller/a/b"},
		{"/tmp/syzkaller/x", "/tmp/syzkaller/x"},
		{"x:", "/x:"},
		{"ab:/not/a/drive", "ab:/not/a/drive"},
	}
	for _, test := range tests {
		if got := toSftpPath(test.in); got != test.want {
			t.Errorf("toSftpPath(%q) = %q, want %q", test.in, got, test.want)
		}
	}
}

func TestRebootCmd(t *testing.T) {
	win := &instance{os: targets.Windows}
	if got, want := win.rebootCmd(), "shutdown /r /t 0 /f"; got != want {
		t.Errorf("windows rebootCmd = %q, want %q", got, want)
	}
	lin := &instance{os: targets.Linux}
	if got, want := lin.rebootCmd(), "reboot"; got != want {
		t.Errorf("linux rebootCmd = %q, want %q", got, want)
	}
}

// BatchMode must always be present: without it ssh sits at a password prompt forever, which in
// an unattended run is indistinguishable from a hung target. vmimpl's own sshArgs has it
// commented out in this tree, which is why isolated appends it itself.
func TestSSHArgsForceBatchMode(t *testing.T) {
	inst := &instance{os: targets.Windows}
	args := inst.sshArgs(vmimpl.SSHArgs(false, "", 22))
	found := false
	for i, a := range args {
		if a == "-o" && i+1 < len(args) && args[i+1] == "BatchMode=yes" {
			found = true
		}
	}
	if !found {
		t.Errorf("BatchMode=yes missing from ssh args: %q", args)
	}
}

func TestCtorValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     string
		wantErr bool
	}{
		{"ok", `{"targets": ["192.168.2.17"], "target_dir": "C:/syzkaller"}`, false},
		{"no targets", `{"target_dir": "C:/syzkaller"}`, true},
		{"no target_dir", `{"targets": ["192.168.2.17"]}`, true},
		{"bad target port", `{"targets": ["192.168.2.17:nope"], "target_dir": "C:/syz"}`, true},
		// pstore reads a Linux sysfs file; accepting it silently on Windows would leave the
		// user believing crash logs were configured when nothing collects them.
		{"pstore rejected", `{"targets": ["1.2.3.4"], "target_dir": "C:/syz", "pstore": true}`, true},
		{"usb rejected", `{"targets": ["1.2.3.4"], "target_dir": "C:/syz", "usb_device_num": ["1-1"]}`, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			env := &vmimpl.Env{
				OS:     targets.Windows,
				Arch:   targets.AMD64,
				Config: []byte(test.cfg),
			}
			if _, err := ctor(env); (err != nil) != test.wantErr {
				t.Fatalf("ctor: err=%v, wantErr=%v", err, test.wantErr)
			}
		})
	}
}

// A minimal Windows config must still know where dumps land and which debugger analyzes them.
func TestCtorWindowsDefaults(t *testing.T) {
	env := &vmimpl.Env{
		OS:     targets.Windows,
		Arch:   targets.AMD64,
		Config: []byte(`{"targets": ["192.168.2.17"], "target_dir": "C:/syzkaller"}`),
	}
	pool, err := ctor(env)
	if err != nil {
		t.Fatal(err)
	}
	cfg := pool.(*Pool).cfg
	if cfg.MinidumpDir != defaultMinidumpDir {
		t.Errorf("MinidumpDir = %q, want %q", cfg.MinidumpDir, defaultMinidumpDir)
	}
	if cfg.KdPath != "kd.exe" {
		t.Errorf("KdPath = %q, want kd.exe", cfg.KdPath)
	}
	if cfg.Host != "127.0.0.1" {
		t.Errorf("Host = %q, want 127.0.0.1", cfg.Host)
	}
	if pool.Count() != 1 {
		t.Errorf("Count = %v, want 1", pool.Count())
	}
}
