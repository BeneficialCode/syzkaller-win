@echo off
rem Build syz-executor.exe for windows/amd64.
rem
rem The GOOS/GOARCH/HOSTGOOS defines are not optional: without them GOOS_windows is 0 and the
rem build stops on <unistd.h>. libipt must be a STATIC library built with -DBUILD_SHARED_LIBS=OFF,
rem and /Dpt_export= keeps its headers from declaring everything __declspec(dllimport).
rem /MT so the target machine needs no VC runtime.

setlocal
if "%LIBIPT%"=="" set LIBIPT=D:\src\cpp\libipt
if "%VSDEV%"=="" set VSDEV=C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat

rem syz-fuzzer refuses to run against an executor whose revision differs from its own, and
rem executor.cc falls back to a hardcoded revision when GIT_REVISION is not defined. Leaving it
rem out makes every manager run die with "mismatching fuzzer/executor git revisions".
for /f %%r in ('git rev-parse HEAD') do set REV=%%r
if "%REV%"=="" (
	echo cannot determine the git revision
	exit /b 1
)

call "%VSDEV%" >nul 2>&1
if errorlevel 1 (
	echo cannot find vcvars64.bat at "%VSDEV%"
	exit /b 1
)

if not exist bin\windows_amd64 mkdir bin\windows_amd64

cl /nologo /EHsc /O2 /MT ^
	/DGOOS_windows=1 /DGOARCH_amd64=1 /DHOSTGOOS_windows=1 /Dpt_export= ^
	/DGIT_REVISION#\"%REV%\" ^
	/I"%LIBIPT%\libipt\include" /I"%LIBIPT%\build\libipt\include" ^
	executor\executor.cc executor\ptcov.cpp ^
	/Fobin\windows_amd64\ /Febin\windows_amd64\syz-executor.exe ^
	/link /LIBPATH:"%LIBIPT%\build\lib\Release" ^
	kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ^
	ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib winmm.lib rpcrt4.lib Crypt32.lib ^
	imm32.lib Urlmon.lib Winscard.lib Opengl32.lib Mpr.lib Ws2_32.lib Bcrypt.lib Ncrypt.lib ^
	Synchronization.lib Rpcns4.lib Mswsock.lib Mincore.lib Msimg32.lib lz32.lib libipt.lib
exit /b %errorlevel%
