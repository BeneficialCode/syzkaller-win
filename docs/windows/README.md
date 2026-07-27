# Windows

`Windows` support is very raw and preliminary (read, non-working).

There is a [closed-source port at Microsoft](https://github.com/dwizzzle/Presentations/blob/master/David%20Weston%20-%20Keeping%20Windows%20Secure%20-%20Bluehat%20IL%202019.pdf).

There is a more complete
[closed-source Windows port](https://www.slideshare.net/AnthonyLAOUHINETSUEI/wsl-reloaded)
done by [Fritz](https://twitter.com/anarcheuz) and [zer0mem](https://twitter.com/zer0mem).
The port has found 6 bugs including
[CVE-2018-8441](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8441).

Also, BSoDs in WSL: [1](https://twitter.com/yoavalon/status/1102563655743406082), [2](https://twitter.com/NetanelBenSimon/status/1102563950221316096).
See [BUGS ON THE WINDSHIELD: FUZZING THE WINDOWS KERNEL](https://www.offensivecon.org/speakers/2020/netanel-ben-simon-yoav-alon.html) presentation.

To update descriptions run (assumes `cl` cross-compiler is in PATH):
```
syz-extract -os=windows
syz-sysgen
```

`sys/windows/windows.txt` was auto-extracted from windows headers with `tools/syz-declextract`.

### Prerequisites

Generated sources must exist before anything builds. On a Windows checkout with
`core.autocrlf=true` this fails unless `.gitattributes` keeps `sys/**/*.txt` as LF, because
`syz-sysgen`'s parser does not strip CR and reports every value as a `bad integer "2\r"`:

```
go install ./sys/syz-sysgen && syz-sysgen
```

That writes `sys/*/gen/*.go`, `executor/defs.h` and `executor/syscalls.h`. Re-run it after
changing anything in `sys/targets/targets.go`, and rebuild the Go binaries too: whether the
executor uses shared memory is decided at compile time from `defs.h`, while the manager decides
it at run time from `targets.go`, and a mismatch shows up as the executor demanding shared
memory section names that nobody created.

### Go binaries

```
make fuzzer execprog stress TARGETOS=windows
```

### Executor

The `-D` target defines are not optional. Without them `GOOS_windows` is 0, the
`#if !GOOS_windows` guard around `<unistd.h>` in `executor.cc` does not apply, and the build
fails immediately on a missing POSIX header.

Coverage additionally needs libipt, built as a STATIC library (`-DBUILD_SHARED_LIBS=OFF`)
because only one file is copied to the target machine, and compiled with `/Dpt_export=` so its
headers do not declare everything `__declspec(dllimport)`:

```
set LIBIPT=D:\src\cpp\libipt
cl /nologo /EHsc /O2 /MT ^
   /DGOOS_windows=1 /DGOARCH_amd64=1 /DHOSTGOOS_windows=1 /Dpt_export= ^
   /I"%LIBIPT%\libipt\include" /I"%LIBIPT%\build\libipt\include" ^
   executor\executor.cc executor\ptcov.cpp ^
   /Fobin\windows_amd64\ /Febin\windows_amd64\syz-executor.exe ^
   /link /LIBPATH:"%LIBIPT%\build\lib\Release" ^
   kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ^
   ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib winmm.lib rpcrt4.lib Crypt32.lib ^
   imm32.lib Urlmon.lib Winscard.lib Opengl32.lib Mpr.lib Ws2_32.lib Bcrypt.lib Ncrypt.lib ^
   Synchronization.lib Rpcns4.lib Mswsock.lib Mincore.lib Msimg32.lib lz32.lib libipt.lib
```

### Coverage setup

Coverage comes from Intel PT and needs, on the TARGET machine:

* `ptrace.sys` loaded, and the executor running elevated (the device ACL is admin-only).
* A CPU with IP filtering, i.e. Skylake or newer. Broadwell has Intel PT but reports zero
  address ranges, which makes the trace volume unmanageable. Check with `ptcaps.exe`.
* No hypervisor: `bcdedit /set hypervisorlaunchtype off`, and VBS / memory integrity disabled.
  Nothing virtualizes Intel PT, so a VM cannot be used at all.
* The traced module named in a `syz-pt-target` file next to the executor, or in the
  `SYZ_PT_TARGET` environment variable. Prefer the environment variable (`setx /M SYZ_PT_TARGET
  ntoskrnl.exe`): the isolated backend wipes `target_dir` when it creates an instance, so a file
  placed there does not survive.

And on the HOST, in the directory `kernel_obj` points at:

* The traced module's PE image, named exactly as the target reports it (`ntoskrnl.exe`,
  `mydriver.sys`). Copy it off the target rather than using a local copy - a different build has
  different function boundaries. Coverage recovers functions and basic blocks from this image's
  `.pdata` exception directory, which x64 makes mandatory for SEH, so no PDB and no source are
  needed.
* Optionally `<image>.syms`, one `<hex rva> <name>` per line, to replace the default `sub_<rva>`
  names. Anything can produce it - a public PDB, a vendor header, an IDA export, a `.map` file.
  For a module with symbols on the Microsoft server, `dbh.exe` from the Debugging Tools works;
  it loads a 64-bit image at `0x1000000`, so subtract that from the addresses it prints, and note
  that `enum *` returns nothing so it has to be driven one prefix at a time (`enum A*`, `enum B*`,
  ...).

`/cover` then serves a module -> function table rather than the source view, because there is no
source to render. `syz-cover` can recompute the same report offline from a `/rawcover` dump, but
needs `-pt_module <name>`: a coverage PC is `(module_index << 26) | offset`, and offline there is no
target to ask which module got index 0.

To run `syz-stress`:
```
bin\windows_amd64\syz-stress.exe -executor c:\full\path\to\bin\windows_amd64\syz-executor.exe
```

## Running against a physical machine (`isolated`)

Coverage rules out every VM backend, `vmware` included: no hypervisor virtualizes Intel PT, so
inside a guest `CPUID.14H` reports nothing and tracing cannot start. The target has to be a
separate physical machine that syzkaller does not create or destroy, which is what the
`isolated` backend is for.

Set up on the TARGET:

 - OpenSSH Server with key auth, and set the default shell to cmd.exe. PowerShell as the
   default shell breaks output parsing:
```
New-ItemProperty -Path HKLM:\SOFTWARE\OpenSSH -Name DefaultShell ^
    -Value C:\Windows\System32\cmd.exe -PropertyType String -Force
```
 - The ssh account must be an administrator. `\Device\WindowsIntelPTrace` is admin-only, and a
   Windows OpenSSH session for an admin account is already elevated, so no UAC prompt.
 - `sc config ptrace start= auto`. A bugcheck reboot is routine, and a `demand` service does not
   come back by itself, so coverage silently disappears after the first crash.
 - In `sysdm.cpl -> Advanced -> Startup and Recovery`: **enable** automatic restart (the
   opposite of the VM advice above — nothing can reach a bare-metal machine parked on a blue
   screen) and select a small memory dump, which lands in `C:\Windows\Minidump`.
 - Disable sleep and hibernate, or the target vanishes mid-run:
```
powercfg -change -standby-timeout-ac 0
powercfg /hibernate off
```
   On a laptop also set the lid-close action to "do nothing".

On the HOST, `kd.exe` from the Windows SDK Debugging Tools analyzes the fetched dumps.

```
{
	"name": "windows",
	"target": "windows/amd64",
	"http": "127.0.0.1:20000",
	"workdir": "yourpath/syzkaller-win/bin/workdir",
	"syzkaller": "yourpath/syzkaller-win",
	"sshkey": "C:/Users/youruser/.ssh/id_rsa",
	"ssh_user": "youruser",
	"cover": false,
	"kernel_obj": "yourpath/ptobj",
	"procs": 1,
	"type": "isolated",
	"vm": {
		"targets": ["192.168.2.17"],
		"target_dir": "C:\\syzfuzz",
		"minidump_dir": "C:\\Windows\\Minidump",
		"kd_path": "C:/Program Files (x86)/Windows Kits/10/Debuggers/x64/kd.exe",
		"power_cycle_cmd": "your-smart-plug-cli reset {{TARGET}}"
	}
}
```

`procs` is capped by the target's core count: coverage pins one executor per CPU and leaves
CPU 0 for the OS, so `procs <= NumCPU-1`.

`kernel_obj` is where the traced module's PE image goes (see Coverage setup above); it is only
read when `cover` is true.

`power_cycle_cmd` is optional but strongly recommended for unattended runs. A hard hang (as
opposed to a bugcheck) leaves neither ssh nor a kernel debugger reachable, and without it the
run stops until somebody presses the power button.

There is no serial console here, so a crash is only visible as the ssh stream dying and is only
described by `kd -z <dump> -c "!analyze -v"` run on the host after the machine reboots. Expect
roughly 80 seconds from bugcheck to a titled crash in `workdir/crashes`.
