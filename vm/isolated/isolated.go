// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package isolated drives a machine that syzkaller does not create or destroy: it is already
// running, reachable over ssh, and stays that way. That makes it the right backend for a
// bare-metal target, which is what Intel PT forces on us - no hypervisor virtualizes PT, so a
// VM backend cannot be used at all.
//
// Most of this file was commented out in this fork and what remained assumed a Linux target.
// It is now Windows-aware throughout; see the notes on Copy (scp truncation) and Diagnose
// (there is no console on a physical Windows box) which are the two places where Windows needs
// a genuinely different approach rather than different syntax.
package isolated

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm/vmimpl"
)

const (
	pstoreConsoleFile = "/sys/fs/pstore/console-ramoops-0"

	// Emitted into the crash output when the machine clearly died but no dump could be
	// retrieved, so pkg/report still records a crash instead of the manager only seeing
	// "lost connection to test machine" and discarding everything.
	noDumpMarker = "SYZ-WINDOWS-NO-DUMP"

	defaultMinidumpDir = `C:\Windows\Minidump`
	remoteDumpName     = "syz-crash.dmp"
)

func init() {
	vmimpl.Register("isolated", ctor, false)
}

type Config struct {
	Host          string   `json:"host"`           // host ip addr
	Targets       []string `json:"targets"`        // target machines: (hostname|ip)(:port)?
	TargetDir     string   `json:"target_dir"`     // directory to copy/run on target
	TargetReboot  bool     `json:"target_reboot"`  // reboot target on repair
	USBDevNums    []string `json:"usb_device_num"` // /sys/bus/usb/devices/
	StartupScript string   `json:"startup_script"` // script to execute after each startup
	Pstore        bool     `json:"pstore"`         // use crashlogs from pstore (linux only)

	// --- Windows targets -----------------------------------------------------------------

	// Host-side command that hard power-cycles the target, e.g. an IPMI call or a smart plug
	// CLI. "{{TARGET}}" is replaced with the target address.
	//
	// This is not optional in practice for unattended runs: a hard hang leaves neither ssh nor
	// a kernel debugger reachable, and a physical machine has no equivalent of "vmrun reset".
	PowerCycleCmd string `json:"power_cycle_cmd"`
	// Where the target writes crash dumps. Configure "Small memory dump" in Startup and
	// Recovery, together with AutoReboot, or a bugcheck simply parks the machine on the blue
	// screen and nothing here can recover it.
	MinidumpDir string `json:"minidump_dir"`
	// Host-side kd.exe (or cdb.exe) used to analyze the fetched dump.
	KdPath string `json:"kd_path"`
	// Optional symbol path passed to kd -y, e.g.
	// "srv*C:\Symbols*https://msdl.microsoft.com/download/symbols;D:\drivers\pdb".
	SymbolPath string `json:"symbol_path"`
}

type Pool struct {
	env *vmimpl.Env
	cfg *Config
}

type instance struct {
	cfg         *Config
	os          string
	targetAddr  string
	targetPort  int
	index       int
	closed      chan bool
	debug       bool
	sshUser     string
	sshKey      string
	forwardPort int
	workdir     string
	// Base names of everything Copy() put on the target, so Close() can kill them again.
	copied []string
}

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	cfg := &Config{}
	if err := config.LoadData(env.Config, cfg); err != nil {
		return nil, err
	}
	if cfg.Host == "" {
		cfg.Host = "127.0.0.1"
	}
	if len(cfg.Targets) == 0 {
		return nil, fmt.Errorf("config param targets is empty")
	}
	if cfg.TargetDir == "" {
		return nil, fmt.Errorf("config param target_dir is empty")
	}
	for _, target := range cfg.Targets {
		if _, _, err := splitTargetPort(target); err != nil {
			return nil, fmt.Errorf("bad target %q: %v", target, err)
		}
	}
	if len(cfg.USBDevNums) > 0 && len(cfg.USBDevNums) != len(cfg.Targets) {
		return nil, fmt.Errorf("the number of targets and the number of usb_device_num must match")
	}
	if env.OS == targets.Windows {
		if cfg.Pstore {
			return nil, fmt.Errorf("pstore is a linux-only option")
		}
		if len(cfg.USBDevNums) > 0 {
			return nil, fmt.Errorf("usb_device_num is a linux-only option; use power_cycle_cmd")
		}
		if cfg.MinidumpDir == "" {
			cfg.MinidumpDir = defaultMinidumpDir
		}
		if cfg.KdPath == "" {
			cfg.KdPath = "kd.exe"
		}
		if cfg.PowerCycleCmd == "" {
			log.Logf(0, "isolated: power_cycle_cmd is not set; a hard hang will need manual "+
				"intervention because ssh and the kernel debugger are both unreachable then")
		}
	}
	if env.Debug && len(cfg.Targets) > 1 {
		log.Logf(0, "limiting number of targets from %v to 1 in debug mode", len(cfg.Targets))
		cfg.Targets = cfg.Targets[:1]
		if len(cfg.USBDevNums) > 1 {
			cfg.USBDevNums = cfg.USBDevNums[:1]
		}
	}
	return &Pool{
		cfg: cfg,
		env: env,
	}, nil
}

func (pool *Pool) Count() int {
	return len(pool.cfg.Targets)
}

func (pool *Pool) Create(workdir string, index int) (vmimpl.Instance, error) {
	targetAddr, targetPort, _ := splitTargetPort(pool.cfg.Targets[index])
	inst := &instance{
		cfg:        pool.cfg,
		os:         pool.env.OS,
		targetAddr: targetAddr,
		targetPort: targetPort,
		index:      index,
		closed:     make(chan bool),
		debug:      pool.env.Debug,
		sshUser:    pool.env.SSHUser,
		sshKey:     pool.env.SSHKey,
		workdir:    workdir,
	}
	closeInst := inst
	defer func() {
		if closeInst != nil {
			closeInst.Close()
		}
	}()
	if err := inst.repair(); err != nil {
		return nil, fmt.Errorf("repair failed: %v", err)
	}

	dir := inst.cfg.TargetDir
	if inst.isWindows() {
		// No remount: a Windows system volume is already writable, and there is no equivalent
		// of a read-only rootfs to deal with.
		inst.ssh(fmt.Sprintf(`if not exist "%v" mkdir "%v"`, dir, dir))
		// Orphans from a previous manager run: they still hold their images locked, so the
		// del below would leave those files behind, and they are still talking to an RPC
		// port that no longer belongs to them.
		inst.ssh(killRemote("syz-fuzzer.exe") + " & " + killRemote("syz-executor.exe"))
		// Leftovers from the previous run. 2>nul because del complains on an empty directory.
		inst.ssh(fmt.Sprintf(`del /q /f "%v\*" 2>nul`, dir))
	} else {
		inst.ssh("mount -o remount,rw /")
		inst.ssh("mkdir -p '" + dir + "'")
		// path.Join, not filepath.Join: filepath follows the HOST separator, so on a Windows
		// host it produced backslashes in commands sent to a Linux target.
		inst.ssh("rm -rf '" + path.Join(dir, "*") + "'")
		if inst.cfg.Pstore {
			inst.ssh(fmt.Sprintf("rm %v", pstoreConsoleFile))
		}
	}

	closeInst = nil
	return inst, nil
}

func (inst *instance) isWindows() bool {
	return inst.os == targets.Windows
}

// sshArgs builds ssh/scp/sftp arguments with BatchMode forced on.
//
// vmimpl.sshArgs has BatchMode commented out in this fork. Without it ssh will sit at a
// password or passphrase prompt forever instead of failing, which in an unattended fuzzing run
// looks exactly like a hung target.
func (inst *instance) sshArgs(base []string) []string {
	return append(base, "-o", "BatchMode=yes")
}

func (inst *instance) Forward(port int) (string, error) {
	if inst.forwardPort != 0 {
		return "", fmt.Errorf("isolated: Forward port already set")
	}
	if port == 0 {
		return "", fmt.Errorf("isolated: Forward port is zero")
	}
	inst.forwardPort = port
	return fmt.Sprintf(inst.cfg.Host+":%v", port), nil
}

func (inst *instance) ssh(command string) error {
	if inst.debug {
		log.Logf(0, "executing ssh %+v", command)
	}

	rpipe, wpipe, err := osutil.LongPipe()
	if err != nil {
		return err
	}
	defer rpipe.Close()

	args := append(inst.sshArgs(vmimpl.SSHArgs(inst.debug, inst.sshKey, inst.targetPort)),
		inst.sshUser+"@"+inst.targetAddr, command)
	if inst.debug {
		log.Logf(0, "running command: ssh %#v", args)
	}
	cmd := osutil.Command("ssh", args...)
	cmd.Stdout = wpipe
	cmd.Stderr = wpipe
	if err := cmd.Start(); err != nil {
		wpipe.Close()
		return err
	}
	wpipe.Close()

	done := make(chan bool)
	go func() {
		select {
		case <-time.After(time.Second * 30):
			if inst.debug {
				log.Logf(0, "ssh hanged")
			}
			cmd.Process.Kill()
		case <-done:
		}
	}()
	if err := cmd.Wait(); err != nil {
		close(done)
		out, _ := ioutil.ReadAll(rpipe)
		if inst.debug {
			log.Logf(0, "ssh failed: %v\n%s", err, out)
		}
		return fmt.Errorf("ssh %+v failed: %v\n%s", args, err, out)
	}
	close(done)
	if inst.debug {
		log.Logf(0, "ssh returned")
	}
	return nil
}

// sshOutput runs a command and returns its combined output.
func (inst *instance) sshOutput(command string) ([]byte, error) {
	args := append(inst.sshArgs(vmimpl.SSHArgs(inst.debug, inst.sshKey, inst.targetPort)),
		inst.sshUser+"@"+inst.targetAddr, command)
	if inst.debug {
		log.Logf(0, "running command: ssh %#v", args)
	}
	return osutil.RunCmd(2*time.Minute, "", "ssh", args...)
}

func (inst *instance) waitForSSH(timeout time.Duration) error {
	return vmimpl.WaitForSSH(inst.debug, timeout, inst.targetAddr, inst.sshKey, inst.sshUser,
		inst.os, inst.targetPort, nil)
}

func (inst *instance) rebootCmd() string {
	if inst.isWindows() {
		return "shutdown /r /t 0 /f"
	}
	return "reboot"
}

func (inst *instance) waitForReboot(timeoutSec int) error {
	probe := "pwd"
	if inst.isWindows() {
		probe = "cd"
	}
	start := time.Now()
	for {
		if !vmimpl.SleepInterruptible(time.Second) {
			return fmt.Errorf("shutdown in progress")
		}
		// Once the probe fails the machine has started going down.
		if err := inst.ssh(probe); err != nil {
			return nil
		}
		if time.Since(start).Seconds() > float64(timeoutSec) {
			break
		}
	}
	return fmt.Errorf("isolated: the machine did not reboot on repair")
}

func (inst *instance) waitRebootAndSSH(rebootTimeoutSec int, sshTimeout time.Duration) error {
	if err := inst.waitForReboot(rebootTimeoutSec); err != nil {
		log.Logf(2, "isolated: machine did not reboot")
		return err
	}
	log.Logf(2, "isolated: rebooted, waiting for it to come back")
	if err := inst.waitForSSH(sshTimeout); err != nil {
		log.Logf(2, "isolated: machine did not come back")
		return err
	}
	log.Logf(2, "isolated: reboot succeeded")
	return nil
}

// powerCycle runs the configured host-side out-of-band power command.
func (inst *instance) powerCycle() error {
	if inst.cfg.PowerCycleCmd == "" {
		return fmt.Errorf("power_cycle_cmd is not configured")
	}
	cmdline := strings.ReplaceAll(inst.cfg.PowerCycleCmd, "{{TARGET}}", inst.targetAddr)
	log.Logf(0, "isolated: power cycling %v", inst.targetAddr)
	var out []byte
	var err error
	if runtime.GOOS == "windows" {
		out, err = osutil.RunCmd(5*time.Minute, "", "cmd", "/c", cmdline)
	} else {
		out, err = osutil.RunCmd(5*time.Minute, "", "sh", "-c", cmdline)
	}
	if err != nil {
		return fmt.Errorf("power_cycle_cmd failed: %v\n%s", err, out)
	}
	return nil
}

func (inst *instance) repair() error {
	log.Logf(2, "isolated: trying to ssh")
	if err := inst.waitForSSH(30 * time.Minute); err != nil {
		log.Logf(2, "isolated: ssh failed")
		// A hard hang takes ssh down with it, so the only way back is out-of-band power.
		if inst.cfg.PowerCycleCmd == "" {
			return fmt.Errorf("SSH failed and power_cycle_cmd is not configured: %v", err)
		}
		if err := inst.powerCycle(); err != nil {
			return err
		}
		if err := inst.waitForSSH(30 * time.Minute); err != nil {
			return fmt.Errorf("SSH failed after a power cycle: %v", err)
		}
	}
	if inst.cfg.TargetReboot {
		if len(inst.cfg.USBDevNums) > 0 {
			log.Logf(2, "isolated: trying to reboot by USB authorization")
			usbAuth := fmt.Sprintf("/sys/bus/usb/devices/%v/authorized", inst.cfg.USBDevNums[inst.index])
			if err := ioutil.WriteFile(usbAuth, []byte("0"), 0); err != nil {
				log.Logf(2, "isolated: failed to turn off the device")
				return err
			}
			if err := ioutil.WriteFile(usbAuth, []byte("1"), 0); err != nil {
				log.Logf(2, "isolated: failed to turn on the device")
				return err
			}
		} else {
			log.Logf(2, "isolated: ssh succeeded, rebooting")
			inst.ssh(inst.rebootCmd()) // the command will not return cleanly, ignore the error
			if err := inst.waitRebootAndSSH(5*60, 30*time.Minute); err != nil {
				return fmt.Errorf("waitRebootAndSSH failed: %v", err)
			}
		}
	}
	if inst.cfg.StartupScript != "" {
		log.Logf(2, "isolated: executing startup_script")
		if err := inst.runStartupScript(); err != nil {
			return err
		}
		log.Logf(2, "isolated: done executing startup_script")
	}
	return nil
}

func (inst *instance) runStartupScript() error {
	contents, err := ioutil.ReadFile(inst.cfg.StartupScript)
	if err != nil {
		return fmt.Errorf("unable to read startup_script: %v", err)
	}
	if !inst.isWindows() {
		c := string(contents)
		if err := inst.ssh(fmt.Sprintf("bash -c \"%v\"", vmimpl.EscapeDoubleQuotes(c))); err != nil {
			return fmt.Errorf("failed to execute startup_script: %v", err)
		}
		return nil
	}
	// cmd.exe has no reliable way to take a multi-line script on a command line, and quoting a
	// whole script through ssh into cmd is a losing game. Run it a line at a time instead; a
	// startup script here is a short list of independent commands (sc start ptrace, etc.).
	for _, line := range strings.Split(string(contents), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "::") ||
			strings.HasPrefix(strings.ToLower(line), "rem ") {
			continue
		}
		if err := inst.ssh(line); err != nil {
			return fmt.Errorf("startup_script line %q failed: %v", line, err)
		}
	}
	return nil
}

func (inst *instance) Close() {
	// Killing the ssh client does not kill what it started on a Windows target: there is no
	// controlling terminal and no SIGHUP, so syz-fuzzer.exe outlives the instance, keeps its
	// RPC connection to the manager, and keeps a lock on its own image. Left alone these
	// accumulate one per instance restart. Do this before closing inst.closed so ssh() is
	// still usable.
	if inst.isWindows() {
		for _, base := range inst.copied {
			inst.ssh(killRemote(base))
		}
	}
	close(inst.closed)
}

// killRemote builds a command that kills a copied binary and every per-proc copy of it.
//
// The name Copy() put on the target is not the name that ends up running: ipc.MakeEnv hardlinks
// the executor to "<base>.<procid>" so a crash can be traced back to a proc, and that link is
// made on the target, so Copy() never sees it. Killing only "<base>" therefore leaves the
// executors alive. The IMAGENAME filter takes the suffixed copies; /T on the plain name takes
// anything spawned beneath it. Failures are silent because "nothing matched" is the normal case.
func killRemote(base string) string {
	return fmt.Sprintf(`taskkill /F /T /IM "%v" 2>nul & taskkill /F /T /FI "IMAGENAME eq %v.*" 2>nul`,
		base, base)
}

// targetPath joins a file name onto TargetDir using the TARGET's separator.
func (inst *instance) targetPath(name string) string {
	if inst.isWindows() {
		return strings.TrimRight(inst.cfg.TargetDir, `\/`) + `\` + name
	}
	return path.Join(inst.cfg.TargetDir, name)
}

// toSftpPath converts a target path to the form sftp expects: always forward slashes, and a
// leading slash in front of a Windows drive letter.
//
// The leading slash is not cosmetic. Windows OpenSSH's sftp server presents drives under a
// single unix-like root, so "C:/syzfuzz/x.exe" is parsed as relative to the login home and the
// put fails; "/C:/syzfuzz/x.exe" is the absolute form it accepts.
func toSftpPath(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	if len(p) >= 2 && p[1] == ':' && isDriveLetter(p[0]) {
		p = "/" + p
	}
	return p
}

func isDriveLetter(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	base := filepath.Base(hostSrc)
	vmDst := inst.targetPath(base)

	// Kill whatever is still holding the destination open before overwriting it. Windows
	// takes a mandatory lock on a running image, so leftovers from the previous instance
	// make the transfer fail with "dest open ...: Failure" - and because Create() runs the
	// same cleanup through "del", that fails silently too and the instance loops forever
	// re-copying and never fuzzing.
	if inst.isWindows() {
		inst.ssh(killRemote(base) + fmt.Sprintf(` & del /f /q "%v" 2>nul`, vmDst))
	} else {
		inst.ssh("pkill -9 '" + base + "'; rm -f '" + vmDst + "'")
	}

	// sftp, not scp, and this is not a style preference.
	//
	// Windows OpenSSH's scp silently truncates a transfer at 204800 bytes and still exits 0.
	// Verified on this setup: a 1.86 MB minidump and a 17 MB image both arrived as exactly
	// 200 KiB with no error reported anywhere. syz-executor.exe and syz-fuzzer.exe are well
	// past that, so scp would deliver a corrupt binary and the only symptom would be the
	// target failing in bizarre ways. sftp transfers the same files intact.
	batch := fmt.Sprintf("put %q %q\nquit\n", filepath.ToSlash(hostSrc), toSftpPath(vmDst))
	args := append(inst.sshArgs(vmimpl.SCPArgs(inst.debug, inst.sshKey, inst.targetPort)),
		"-b", "-", inst.sshUser+"@"+inst.targetAddr)
	if inst.debug {
		log.Logf(0, "running command: sftp %#v <<< %q", args, batch)
	}
	cmd := osutil.Command("sftp", args...)
	cmd.Stdin = strings.NewReader(batch)
	out, err := osutil.Run(3*time.Minute, cmd)
	if err != nil {
		return "", fmt.Errorf("sftp put failed: %v\n%s", err, out)
	}

	// Verify the size landed. A silent short write is exactly the failure mode that motivated
	// dropping scp, so do not take a zero exit status as proof.
	local, err := os.Stat(hostSrc)
	if err != nil {
		return "", err
	}
	remote, err := inst.remoteFileSize(vmDst)
	if err != nil {
		log.Logf(0, "isolated: cannot verify the size of %v: %v", vmDst, err)
	} else if remote != local.Size() {
		return "", fmt.Errorf("copy of %v is truncated: %v bytes on the target, %v expected",
			vmDst, remote, local.Size())
	}
	inst.copied = append(inst.copied, base)
	return vmDst, nil
}

func (inst *instance) remoteFileSize(p string) (int64, error) {
	var cmd string
	if inst.isWindows() {
		cmd = fmt.Sprintf(`powershell -NoProfile -Command "(Get-Item -LiteralPath '%v').Length"`, p)
	} else {
		cmd = fmt.Sprintf("stat -c %%s '%v'", p)
	}
	out, err := inst.sshOutput(cmd)
	if err != nil {
		return 0, fmt.Errorf("%v\n%s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if n, err := strconv.ParseInt(line, 10, 64); err == nil {
			return n, nil
		}
	}
	return 0, fmt.Errorf("no size in output: %q", out)
}

func (inst *instance) Run(timeout time.Duration, stop <-chan bool, command string) (
	<-chan []byte, <-chan error, error) {
	// There is no console stream here, for two independent reasons.
	//
	// A physical Windows box has nothing to tail: no dmesg, and generally no serial port
	// either. Crash information comes from Diagnose() instead, which fetches the minidump the
	// machine wrote and analyzes it on the host.
	//
	// And vmimpl.OpenRemoteConsole does not exist in this tree: it is commented out in
	// vm/vmimpl/console.go because the console machinery is built on termios and there is no
	// console_windows.go, so it cannot compile on a Windows host at all. Since this fork only
	// targets Windows, carrying a Linux console branch would just be dead code that breaks the
	// build.
	rpipe, wpipe, err := osutil.LongPipe()
	if err != nil {
		return nil, nil, err
	}

	args := vmimpl.SSHArgsForward(inst.debug, inst.sshKey, inst.targetPort, inst.forwardPort)
	if inst.cfg.Pstore || inst.isWindows() {
		// On Windows this is not an option. A VM backend notices a dead machine through the
		// serial console; a physical Windows box has no console here, so this ssh stream is
		// the only liveness signal there is. Without keepalives the client sits on a dead
		// connection and the crash is only noticed when the manager's 5 minute no-output
		// timeout expires - measured at exactly that on a real bugcheck. With them the stream
		// ends about 30s after the machine goes down, which is also 4.5 minutes less fuzzing
		// time lost per crash.
		args = append(args, "-o", "ServerAliveInterval=6")
		args = append(args, "-o", "ServerAliveCountMax=5")
	}
	args = inst.sshArgs(args)
	if inst.isWindows() {
		// "exec" is a POSIX shell builtin; cmd.exe needs "cd /d" to change drive as well.
		args = append(args, inst.sshUser+"@"+inst.targetAddr,
			fmt.Sprintf(`cd /d "%v" && %v`, inst.cfg.TargetDir, command))
	} else {
		args = append(args, inst.sshUser+"@"+inst.targetAddr,
			"cd "+inst.cfg.TargetDir+" && exec "+command)
	}
	if inst.debug {
		log.Logf(0, "running command: ssh %#v", args)
	}
	cmd := osutil.Command("ssh", args...)
	cmd.Stdout = wpipe
	cmd.Stderr = wpipe
	if err := cmd.Start(); err != nil {
		rpipe.Close()
		wpipe.Close()
		return nil, nil, err
	}
	wpipe.Close()

	var tee io.Writer
	if inst.debug {
		tee = os.Stdout
	}
	merger := vmimpl.NewOutputMerger(tee)
	merger.Add("ssh", rpipe)

	return vmimpl.Multiplex(cmd, merger, nil, timeout, stop, inst.closed, inst.debug)
}

func (inst *instance) Diagnose(rep *report.Report) ([]byte, bool) {
	if inst.isWindows() {
		return inst.diagnoseWindows()
	}
	if !inst.cfg.Pstore {
		return nil, false
	}
	// TODO: kernel may not reboot after some errors.
	// E.g. if panic_on_warn is not set, or some errors don't trigger reboot at all
	// (e.g. LOCKDEP overflows).
	log.Logf(2, "waiting for crashed DUT to come back up")
	if err := inst.waitRebootAndSSH(5*60, 30*time.Minute); err != nil {
		return []byte(fmt.Sprintf("unable to SSH into DUT after reboot: %v", err)), false
	}
	log.Logf(2, "reading contents of pstore")
	contents, err := inst.readPstoreContents()
	if err != nil {
		return []byte(fmt.Sprintf("Diagnose failed: %v\n", err)), false
	}
	return contents, false
}

// diagnoseWindows recovers a bugcheck from a physical Windows target.
//
// The sequence exists because there is nothing to tail while the machine is dying: it
// bugchecks, writes a dump, and (with AutoReboot set) restarts. So we wait for it to come back,
// pull the newest dump, and let kd explain it on the host. pkg/report parses that analysis.
func (inst *instance) diagnoseWindows() ([]byte, bool) {
	buf := new(bytes.Buffer)

	log.Logf(1, "isolated: waiting for the target to come back after a bugcheck")
	if err := inst.waitForSSH(20 * time.Minute); err != nil {
		// It may be hung rather than rebooting; a power cycle is the only way to find out.
		fmt.Fprintf(buf, "target did not come back on its own: %v\n", err)
		if inst.cfg.PowerCycleCmd != "" {
			if err := inst.powerCycle(); err != nil {
				fmt.Fprintf(buf, "power cycle failed: %v\n", err)
				fmt.Fprintf(buf, "%v\n", noDumpMarker)
				return buf.Bytes(), false
			}
			if err := inst.waitForSSH(20 * time.Minute); err != nil {
				fmt.Fprintf(buf, "target did not come back after a power cycle: %v\n", err)
				fmt.Fprintf(buf, "%v\n", noDumpMarker)
				return buf.Bytes(), false
			}
		} else {
			fmt.Fprintf(buf, "power_cycle_cmd is not configured, cannot recover\n")
			fmt.Fprintf(buf, "%v\n", noDumpMarker)
			return buf.Bytes(), false
		}
	}

	dump, err := inst.fetchNewestMinidump()
	if err != nil {
		fmt.Fprintf(buf, "could not retrieve a crash dump: %v\n", err)
		fmt.Fprintf(buf, "check that Startup and Recovery is configured to write a small "+
			"memory dump to %v and that AutoReboot is enabled\n", inst.cfg.MinidumpDir)
		fmt.Fprintf(buf, "%v\n", noDumpMarker)
		return buf.Bytes(), false
	}

	analysis, err := inst.analyzeDump(dump)
	if err != nil {
		fmt.Fprintf(buf, "kd failed to analyze %v: %v\n", dump, err)
		fmt.Fprintf(buf, "%v\n", noDumpMarker)
		return buf.Bytes(), false
	}
	buf.Write(analysis)
	return buf.Bytes(), false
}

// fetchNewestMinidump copies the most recent dump off the target and returns its host path.
func (inst *instance) fetchNewestMinidump() (string, error) {
	// /o-d sorts newest first, /b prints bare names.
	out, err := inst.sshOutput(fmt.Sprintf(`dir /b /o-d "%v\*.dmp"`, inst.cfg.MinidumpDir))
	if err != nil {
		return "", fmt.Errorf("cannot list %v: %v\n%s", inst.cfg.MinidumpDir, err, out)
	}
	var name string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if strings.HasSuffix(strings.ToLower(line), ".dmp") {
			name = line
			break
		}
	}
	if name == "" {
		return "", fmt.Errorf("no .dmp files in %v", inst.cfg.MinidumpDir)
	}

	// Copy it into the ssh user's home first. Fetching straight from an absolute path under
	// C:\Windows through sftp is unreliable, while a plain relative name from the home
	// directory works, and the copy also takes it out of the way of the next crash.
	remote := remoteDumpName
	if out, err := inst.sshOutput(fmt.Sprintf(`copy /y "%v\%v" %v`,
		inst.cfg.MinidumpDir, name, remote)); err != nil {
		return "", fmt.Errorf("cannot stage %v: %v\n%s", name, err, out)
	}

	local := filepath.Join(inst.workdir, "crash.dmp")
	batch := fmt.Sprintf("get %q %q\nquit\n", remote, filepath.ToSlash(local))
	args := append(inst.sshArgs(vmimpl.SCPArgs(inst.debug, inst.sshKey, inst.targetPort)),
		"-b", "-", inst.sshUser+"@"+inst.targetAddr)
	cmd := osutil.Command("sftp", args...)
	cmd.Stdin = strings.NewReader(batch)
	if out, err := osutil.Run(5*time.Minute, cmd); err != nil {
		return "", fmt.Errorf("sftp get failed: %v\n%s", err, out)
	}
	st, err := os.Stat(local)
	if err != nil {
		return "", err
	}
	if st.Size() == 0 {
		return "", fmt.Errorf("fetched dump %v is empty", local)
	}
	log.Logf(1, "isolated: fetched crash dump %v (%v bytes)", name, st.Size())

	// Remove it from the target so the next crash is not confused with this one.
	inst.ssh(fmt.Sprintf(`del /q /f "%v\%v"`, inst.cfg.MinidumpDir, name))
	return local, nil
}

func (inst *instance) analyzeDump(dumpPath string) ([]byte, error) {
	args := []string{"-z", dumpPath}
	if inst.cfg.SymbolPath != "" {
		args = append(args, "-y", inst.cfg.SymbolPath)
	}
	args = append(args, "-c", "!analyze -v; q")
	if inst.debug {
		log.Logf(0, "running %v %#v", inst.cfg.KdPath, args)
	}
	// Symbol server downloads on a first crash can be slow.
	out, err := osutil.RunCmd(15*time.Minute, "", inst.cfg.KdPath, args...)
	if err != nil && len(out) == 0 {
		return nil, err
	}
	// kd exits non-zero in some situations even after printing a usable analysis, so keep the
	// output whenever there is any.
	return out, nil
}

func (inst *instance) readPstoreContents() ([]byte, error) {
	log.Logf(0, "reading pstore contents")
	args := append(inst.sshArgs(vmimpl.SSHArgs(inst.debug, inst.sshKey, inst.targetPort)),
		inst.sshUser+"@"+inst.targetAddr, "cat "+pstoreConsoleFile+" && rm "+pstoreConsoleFile)
	if inst.debug {
		log.Logf(0, "running command: ssh %#v", args)
	}
	var stdout, stderr bytes.Buffer
	cmd := osutil.Command("ssh", args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("unable to read pstore file: %v: %v", err, stderr.String())
	}
	return stdout.Bytes(), nil
}

func splitTargetPort(addr string) (string, int, error) {
	target := addr
	port := 22
	if colonPos := strings.Index(addr, ":"); colonPos != -1 {
		p, err := strconv.ParseUint(addr[colonPos+1:], 10, 16)
		if err != nil {
			return "", 0, err
		}
		target = addr[:colonPos]
		port = int(p)
	}
	if target == "" {
		return "", 0, fmt.Errorf("target is empty")
	}
	return target, port, nil
}
