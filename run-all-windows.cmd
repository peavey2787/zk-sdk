@echo off
setlocal EnableExtensions
cd /d "%~dp0"
rem usage: run-all-windows.cmd [fast|full]   (default: fast)
where cargo >nul 2>nul || (echo FAIL: Cargo toolchain not installed & exit /b 1)
where python >nul 2>nul || (echo FAIL: Python 3 not installed & exit /b 1)
python scripts\run_all.py %~1
exit /b %errorlevel%
