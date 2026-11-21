@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"
title SecureScan AI - allow phone access
if not exist ".venv\Scripts\python.exe" (
    echo Run install_windows.bat first.
    pause
    exit /b 1
)
net session >nul 2>&1
if errorlevel 1 (
    echo This needs administrator rights to add a Windows Firewall rule.
    echo Right-click this file and choose "Run as administrator".
    pause
    exit /b 1
)
echo This lets phones on your PRIVATE Wi-Fi network connect to SecureScan AI.
echo It will:
echo   - change .env so the server listens on your network (plain HTTP, trusted LAN only)
echo   - add a Windows Firewall rule for the Private network profile and local subnet only
echo Do not do this on a public or shared network.
echo.
set /p CONFIRM=Continue? (Y/N): 
if /i not "!CONFIRM!"=="Y" (
    echo Cancelled.
    pause
    exit /b 0
)
".venv\Scripts\python.exe" -m app.cli enable-lan
set "PORT=8000"
for /f %%p in ('".venv\Scripts\python.exe" -m app.cli show-port') do set "PORT=%%p"
netsh advfirewall firewall delete rule name="SecureScan AI (private network)" >nul 2>&1
netsh advfirewall firewall add rule name="SecureScan AI (private network)" dir=in action=allow protocol=TCP localport=%PORT% profile=private remoteip=localsubnet
if errorlevel 1 (
    echo [ERROR] The firewall rule could not be added.
    pause
    exit /b 1
)
echo.
echo Done. Restart the server (stop_server.bat, then start_server.bat).
echo Then run:  ipconfig   and look for the "IPv4 Address" of your Wi-Fi adapter.
echo In the Android app enter:  http://YOUR-IPV4-ADDRESS:%PORT%
echo Make sure Windows marks your Wi-Fi network as "Private" (Settings > Network).
pause
