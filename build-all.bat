@echo off
rem Build everything needed for a windows/amd64 run, all stamped with the same git revision.
rem
rem This exists because syz-fuzzer refuses to run against a syz-executor built from a different
rem revision, and the failure - "machine check failed: mismatching fuzzer/executor git revisions"
rem - names two hashes and nothing about which binary is stale. Building any one of the three
rem alone is therefore a trap, and rebuilding them one at a time from memory reliably misses one.
rem
rem Everything here is a plain build; nothing is copied to the target. The manager copies
rem syz-fuzzer.exe and syz-executor.exe there itself on each run.
rem
rem   build-all.bat            build Go binaries and the executor
rem   build-all.bat gen        also regenerate sys/*/gen and executor/defs.h first
rem
rem Set LIBIPT if libipt is not at D:\src\cpp\libipt; see build-executor.bat.

setlocal enabledelayedexpansion
cd /d "%~dp0"

rem Match the Makefile: a dirty tree gets a "+" so a binary is never labelled as a clean commit
rem it was not actually built from.
for /f %%r in ('git rev-parse HEAD') do set REV=%%r
if "%REV%"=="" (
	echo [!] cannot determine the git revision - is this a git checkout?
	exit /b 1
)
for /f "delims=" %%d in ('git diff --shortstat') do set DIRTY=%%d
if not "%DIRTY%"=="" set REV=%REV%+
for /f "delims=" %%d in ('git log -n 1 --format^="%%cd" --date^=format:%%Y%%m%%d-%%H%%M%%S') do set REVDATE=%%d

set LDFLAGS=-s -w -X github.com/google/syzkaller/prog.GitRevision=%REV% -X github.com/google/syzkaller/prog.gitRevisionDate=%REVDATE%

echo === revision %REV%

if /i "%~1"=="gen" (
	echo === generating descriptions
	rem Writes sys/*/gen/*.go, executor/defs.h and executor/syscalls.h, all gitignored. Needed
	rem after touching sys/*.txt or sys/targets/targets.go - and note that whether the executor
	rem uses shared memory is decided at compile time from defs.h but at run time from
	rem targets.go, so a half-regenerated tree fails in a way that looks like a logic bug.
	go run ./sys/syz-sysgen || exit /b 1
)

rem Host side: these run on this machine.
echo === syz-manager
go build -ldflags="%LDFLAGS%" -o bin\syz-manager.exe ./syz-manager || exit /b 1
echo === syz-cover
go build -ldflags="%LDFLAGS%" -o bin\syz-cover.exe ./tools/syz-cover || exit /b 1

rem Target side: these are copied to the target machine.
echo === syz-fuzzer
go build -ldflags="%LDFLAGS%" -o bin\windows_amd64\syz-fuzzer.exe ./syz-fuzzer || exit /b 1
echo === syz-execprog
go build -ldflags="%LDFLAGS%" -o bin\windows_amd64\syz-execprog.exe ./tools/syz-execprog || exit /b 1
echo === syz-stress
go build -ldflags="%LDFLAGS%" -o bin\windows_amd64\syz-stress.exe ./tools/syz-stress || exit /b 1

echo === syz-executor
rem Explicit path: this environment has NoDefaultCurrentDirectoryInExePath set, so cmd does not
rem find a batch file by bare name even when it sits in the current directory.
call "%~dp0build-executor.bat"
if errorlevel 1 exit /b 1

rem The executor is built by a separate compiler through a separate script, so confirm it really
rem carries this revision rather than trusting that the build ran. This is exactly the mismatch
rem the whole script exists to prevent, so it is worth one extra check.
set EXEREV=
for /f "tokens=4" %%v in ('bin\windows_amd64\syz-executor.exe version') do set EXEREV=%%v
if not "%EXEREV%"=="%REV%" (
	echo [!] syz-executor reports revision "%EXEREV%" but this build is "%REV%"
	echo [!] syz-fuzzer will refuse to run against it
	exit /b 1
)

echo.
echo All binaries built at %REV%
exit /b 0
