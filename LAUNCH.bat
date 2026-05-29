@echo off
REM =====================================================================
REM  Log Sentinel — one-click launcher
REM
REM  • Checks if Python is installed; offers to install it if not
REM  • Launches the GUI app
REM  • Right-click "Run as administrator" for full Security log visibility
REM =====================================================================

setlocal enableextensions
title Log Sentinel — Launching...
cd /d "%~dp0"

REM ---- Check Python ---------------------------------------------------
where python >nul 2>nul
if %errorlevel% equ 0 goto :launch

echo.
echo  Python is not installed.
echo.
echo  Log Sentinel needs Python (a free, safe runtime — same one used by
echo  NASA, YouTube and Instagram). It's about 30 MB and takes one minute
echo  to install.
echo.
choice /c YN /m "  Open the official download page now? "
if errorlevel 2 goto :no_python

start "" "https://www.python.org/downloads/windows/"
echo.
echo  When the installer opens:
echo    1.  IMPORTANT: tick "Add python.exe to PATH" at the bottom of the window.
echo    2.  Click "Install Now" and wait for it to finish.
echo    3.  Re-run LAUNCH.bat (this file).
echo.
pause
exit /b

:no_python
echo.
echo  Cannot launch without Python. Aborting.
echo.
pause
exit /b 1

:launch
REM ---- Detect admin ---------------------------------------------------
net session >nul 2>nul
if %errorlevel% equ 0 (
    set "ADMIN_NOTE=Running as Administrator (full power)"
) else (
    set "ADMIN_NOTE=Not Administrator — Security log will be limited"
)

echo.
echo  ============================================================
echo    LOG SENTINEL
echo    %ADMIN_NOTE%
echo  ============================================================
echo.
echo  Starting GUI...

REM ---- Run the app ----------------------------------------------------
start "" pythonw app.py
if %errorlevel% neq 0 (
    REM Fallback to python.exe with console (so user sees errors)
    python app.py
    pause
)

exit /b 0
