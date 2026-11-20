@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title SecureScan AI - Installation
echo ============================================================
echo   SecureScan AI - Windows installation
echo ============================================================
echo.

set "PYCMD="
where py >nul 2>nul
if not errorlevel 1 set "PYCMD=py -3"
if not defined PYCMD (
    where python >nul 2>nul
    if not errorlevel 1 set "PYCMD=python"
)
if not defined PYCMD goto :nopython

%PYCMD% -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)"
if errorlevel 1 goto :oldpython
echo [1/6] Python found:
%PYCMD% --version

if exist ".venv\Scripts\python.exe" (
    echo [2/6] Virtual environment already exists.
) else (
    echo [2/6] Creating virtual environment...
    %PYCMD% -m venv .venv
    if errorlevel 1 goto :fail
)

echo [3/6] Installing dependencies (this can take a few minutes)...
".venv\Scripts\python.exe" -m pip install --upgrade pip >nul 2>nul
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto :fail

if exist ".env" (
    echo [4/6] Keeping your existing .env settings.
) else (
    echo [4/6] Creating .env from .env.example...
    copy /y ".env.example" ".env" >nul
)

echo [5/6] Preparing the database...
".venv\Scripts\python.exe" -m app.cli init-db
if errorlevel 1 goto :fail

echo [6/6] Create the first administrator account.
echo       Choose a strong password of at least 12 characters with letters and numbers.
echo.
".venv\Scripts\python.exe" -m app.cli init-admin
if errorlevel 1 goto :fail

echo.
echo ============================================================
echo   Installation finished.
echo.
echo   1. Double-click  start_server.bat  to start SecureScan AI.
echo   2. Open http://127.0.0.1:8000 in your browser and sign in.
echo   3. To use the Android app, double-click allow_phone_access.bat
echo      (right-click, Run as administrator) - see README.md.
echo ============================================================
pause
exit /b 0

:nopython
echo [ERROR] Python was not found.
echo         Install Python 3.11 or newer from https://www.python.org/downloads/
echo         and tick "Add python.exe to PATH" in the installer, then run this file again.
pause
exit /b 1

:oldpython
echo [ERROR] Python 3.11 or newer is required. Your version is:
%PYCMD% --version
echo         Install a newer version from https://www.python.org/downloads/ and run this file again.
pause
exit /b 1

:fail
echo.
echo [ERROR] Installation stopped because a step failed. Read the messages above.
echo         See docs\TROUBLESHOOTING.md for help.
pause
exit /b 1
