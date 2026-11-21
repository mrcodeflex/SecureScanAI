@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title SecureScan AI server
if not exist ".venv\Scripts\python.exe" (
    echo SecureScan AI is not installed yet. Run install_windows.bat first.
    pause
    exit /b 1
)
if not exist ".env" copy /y ".env.example" ".env" >nul
echo Starting SecureScan AI... (close this window or press Ctrl+C to stop)
".venv\Scripts\python.exe" -m app.cli serve
echo.
echo The server has stopped. If this was unexpected, read the messages above.
pause
