@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo SecureScan AI is not installed.
    pause
    exit /b 1
)
set "PORT=8000"
for /f %%p in ('".venv\Scripts\python.exe" -m app.cli show-port') do set "PORT=%%p"
set "FOUND="
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":%PORT% " ^| findstr LISTENING') do (
    set "FOUND=1"
    echo Stopping process %%a listening on port %PORT%...
    taskkill /PID %%a /F >nul 2>nul
)
if not defined FOUND echo No SecureScan AI server is listening on port %PORT%.
pause
