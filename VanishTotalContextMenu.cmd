@echo off
setlocal EnableExtensions

set "PowerShellExe=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%PowerShellExe%" set "PowerShellExe=powershell.exe"
set "ContextMenuScript=%~dp0VanishTotalContextMenu.ps1"

if not exist "%ContextMenuScript%" (
    echo Could not find VanishTotalContextMenu.ps1 next to this file.
    echo.
    pause
    exit /b 1
)

if not "%~1"=="" (
    set "ActionArgs=%*"
    goto RunAction
)

:Menu
cls
echo VanishTotal Context Menu
echo.
echo 1. Install context menu
echo 2. Uninstall context menu
echo 3. Exit
echo.
choice /C 123 /N /M "Choose an option [1-3]: "

if errorlevel 3 exit /b 0
if errorlevel 2 (
    set "ActionArgs=-Uninstall"
    goto RunAction
)
if errorlevel 1 (
    set "ActionArgs="
    goto RunAction
)

:RunAction
pushd "%~dp0" >nul
"%PowerShellExe%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%ContextMenuScript%" %ActionArgs%
set "ExitCode=%ERRORLEVEL%"
popd >nul

echo.
if "%ExitCode%"=="0" (
    echo VanishTotal context menu action finished.
) else (
    echo VanishTotal context menu action failed with exit code %ExitCode%.
)

echo.
pause
exit /b %ExitCode%
