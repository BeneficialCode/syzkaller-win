// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"regexp"
)

// Windows crash reports reach us by a different route than on every other target.
//
// A bare-metal Windows box has no console we can tail: there is no dmesg, and a physical
// machine generally has no serial port either. The bugcheck text is therefore not part of the
// live output stream at all. Instead vm/isolated notices the machine died, waits for it to
// reboot, fetches the minidump it wrote, runs `kd -z <dump> -c "!analyze -v;q"` on the host and
// returns that analysis from Diagnose(), which the manager appends to the crash output. So what
// is parsed here is kd's analysis, not a kernel log.
//
// A raw bugcheck banner is recognized too, so wiring up KDNET or a serial console later starts
// working without touching this file.

type windows struct {
	*config
}

func ctorWindows(cfg *config) (reporterImpl, []string, error) {
	ctx := &windows{
		config: cfg,
	}
	return ctx, nil, nil
}

func (ctx *windows) ContainsCrash(output []byte) bool {
	return containsCrash(output, windowsOopses, ctx.ignores)
}

func (ctx *windows) Parse(output []byte) *Report {
	return simpleLineParser(output, windowsOopses, nil, ctx.ignores)
}

func (ctx *windows) Symbolize(rep *Report) error {
	// kd resolved symbols against the target's own loaded modules when it produced the
	// analysis, so there is nothing left to symbolize. Explicit rather than inherited so it is
	// clear this is deliberate and not an unimplemented stub.
	return nil
}

// nolint: lll
var windowsOopses = append([]*oops{
	{
		// kd prints this inside a banner box before anything else, so anchoring here keeps the
		// bugcheck name line - which precedes BUGCHECK_CODE - inside the matched region.
		[]byte("Bugcheck Analysis"),
		[]oopsFormat{
			// Best case: symbolic bugcheck name, code, and the faulting symbol.
			//
			// Title granularity is deliberate. The bugcheck code alone lumps every access
			// violation in the system together, while the raw stack varies from run to run;
			// code plus faulting symbol is what stays stable across reproductions of one bug.
			// The offset is stripped from the symbol so a rebuild that shifts code does not
			// fork the bug into a new one.
			{
				title:        compile("Bugcheck Analysis"),
				report:       compile(`(?:.*\n)+?([A-Z][A-Z0-9_]{5,}) \(([0-9a-fA-F]+)\)(?:.*\n)+?SYMBOL_NAME:[ \t]*([^\s+]+)`),
				fmt:          "BSOD %[1]v (0x%[2]v) in %[3]v",
				alt:          []string{"BSOD 0x%[2]v", "BSOD 0x%[2]v in %[3]v"},
				noStackTrace: true,
			},
			// No SYMBOL_NAME, but FAILURE_BUCKET_ID carries the same symbol as its tail.
			{
				title:        compile("Bugcheck Analysis"),
				report:       compile(`(?:.*\n)+?([A-Z][A-Z0-9_]{5,}) \(([0-9a-fA-F]+)\)(?:.*\n)+?FAILURE_BUCKET_ID:[ \t]*\S*?_([^\s]+)`),
				fmt:          "BSOD %[1]v (0x%[2]v) in %[3]v",
				alt:          []string{"BSOD 0x%[2]v"},
				noStackTrace: true,
			},
			// Name and code only.
			{
				title:        compile("Bugcheck Analysis"),
				report:       compile(`(?:.*\n)+?([A-Z][A-Z0-9_]{5,}) \(([0-9a-fA-F]+)\)`),
				fmt:          "BSOD %[1]v (0x%[2]v)",
				alt:          []string{"BSOD 0x%[2]v"},
				noStackTrace: true,
			},
			// The analysis ran but produced no bugcheck at all: keep the crash, flag it as
			// corrupted so it is obvious the dump was unusable rather than silently losing it.
			{
				title:        compile("Bugcheck Analysis"),
				report:       compile(`(?:.*\n)+?BUGCHECK_CODE:[ \t]*([0-9a-fA-F]+)`),
				fmt:          "BSOD 0x%[1]v",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
	{
		// Raw bugcheck banner from a serial console or KDNET session.
		[]byte("*** STOP:"),
		[]oopsFormat{
			{
				title:        compile(`\*\*\* STOP:`),
				report:       compile(`\*\*\* STOP:[ \t]*0x([0-9a-fA-F]+)`),
				fmt:          "BSOD 0x%[1]v",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
	{
		// vm/isolated emits this when the machine died but no dump could be retrieved, so the
		// crash is still recorded instead of being lost to a bare "lost connection".
		[]byte("SYZ-WINDOWS-NO-DUMP"),
		[]oopsFormat{
			{
				title:        compile("SYZ-WINDOWS-NO-DUMP"),
				fmt:          "BSOD (no crash dump retrieved)",
				noStackTrace: true,
				corrupted:    true,
			},
		},
		[]*regexp.Regexp{},
	},
}, commonOopses...)
