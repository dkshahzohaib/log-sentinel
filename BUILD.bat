@echo off
REM ===============================================================
REM  Build a portable LogSentinel.exe using PyInstaller.
REM  Run this once and you get dist\LogSentinel.exe — no Python
REM  required on the machines you ship to.
REM ===============================================================

setlocal enableextensions
title Log Sentinel — Building...
cd /d "%~dp0"

REM ---- Verify Python ---------------------------------------------
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [!] Python not found. Install from https://www.python.org/downloads/
    pause
    exit /b 1
)

echo.
echo Installing/upgrading PyInstaller...
python -m pip install --upgrade pyinstaller
if %errorlevel% neq 0 (
    echo [!] pip install failed.
    pause
    exit /b 1
)

echo.
echo ============================================================
echo   Building portable LogSentinel.exe — please wait (1–3 min).
echo ============================================================
echo.

REM Clean previous build artifacts
if exist build rmdir /s /q build
if exist dist  rmdir /s /q dist

python -m PyInstaller --clean LogSentinel.spec
if %errorlevel% neq 0 (
    echo.
    echo [!] PyInstaller build failed. See output above.
    pause
    exit /b 1
)

echo.
echo ============================================================
echo   BUILD SUCCESS
echo   Your portable build is at:  dist\LogSentinel.exe
echo   Size: (run dir dist\LogSentinel.exe to check)
echo ============================================================
echo.
echo Next steps:
echo    1. Test it: double-click dist\LogSentinel.exe
echo    2. For full power: right-click → Run as administrator
echo    3. Copy LogSentinel.exe to a USB stick, ship it anywhere.
echo.

pause
