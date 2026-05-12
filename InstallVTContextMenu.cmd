@echo off
setlocal

set "PowerShellExe=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%PowerShellExe%" set "PowerShellExe=powershell.exe"

pushd "%~dp0" >nul
"%PowerShellExe%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0InstallVTContextMenu.ps1" %*
set "ExitCode=%ERRORLEVEL%"
popd >nul

echo.
if "%ExitCode%"=="0" (
    echo VanishTotal context menu setup finished.
) else (
    echo VanishTotal context menu setup failed with exit code %ExitCode%.
)

echo.
pause
exit /b %ExitCode%
