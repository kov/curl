@echo off
rem Run abi_msvc.py with MSVC for x64 on the PATH; see abi_msvc.py.
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64 >nul || exit /b 1
rem MSYS2 python3 reads POSIX paths: run it from the checkout's root.
cd /d "%~dp0..\.." || exit /b 1
python3 inventory/measure/abi_msvc.py %*
