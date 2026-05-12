#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Uninstall,

    [string]$PowerShellPath,

    [string]$ScriptPath
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$installerRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($installerRoot)) {
    $installerRoot = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
}

if ([string]::IsNullOrWhiteSpace($ScriptPath)) {
    $ScriptPath = Join-Path -Path $installerRoot -ChildPath 'VanishTotal.ps1'
}

$contextMenuKey = 'Software\Classes\*\shell\VanishTotal'
$legacyContextMenuKey = 'Software\Classes\*\shell\Scan with VanishTotal'

function Get-PwshVersion {
    param(
        [Parameter(Mandatory)]
        [string]$CandidatePath
    )

    try {
        $output = & $CandidatePath -NoLogo -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' 2>$null
        $versionText = ($output | Select-Object -First 1)
        if ([string]::IsNullOrWhiteSpace($versionText)) {
            return $null
        }

        return [version]$versionText
    }
    catch {
        return $null
    }
}

function Resolve-PwshPath {
    param(
        [AllowNull()]
        [string]$RequestedPath
    )

    $candidates = [System.Collections.Generic.List[string]]::new()

    if (-not [string]::IsNullOrWhiteSpace($RequestedPath)) {
        $candidates.Add($RequestedPath)
    }

    $command = Get-Command -Name 'pwsh.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($command -and $command.Source) {
        $candidates.Add($command.Source)
    }

    if ($PSHOME) {
        $candidates.Add((Join-Path -Path $PSHOME -ChildPath 'pwsh.exe'))
    }

    $programFiles = [Environment]::GetFolderPath('ProgramFiles')
    if (-not [string]::IsNullOrWhiteSpace($programFiles)) {
        $candidates.Add((Join-Path -Path $programFiles -ChildPath 'PowerShell\7\pwsh.exe'))
    }

    $programFilesX86 = [Environment]::GetFolderPath('ProgramFilesX86')
    if (-not [string]::IsNullOrWhiteSpace($programFilesX86)) {
        $candidates.Add((Join-Path -Path $programFilesX86 -ChildPath 'PowerShell\7\pwsh.exe'))
    }

    if ($env:LOCALAPPDATA) {
        $candidates.Add((Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Microsoft\WindowsApps\pwsh.exe'))
    }

    foreach ($candidate in ($candidates | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            continue
        }

        $resolved = (Resolve-Path -LiteralPath $candidate).ProviderPath
        $version = Get-PwshVersion -CandidatePath $resolved
        if ($version -and $version -ge [version]'7.0') {
            return $resolved
        }
    }

    throw 'PowerShell 7 was not found. Install PowerShell 7, or rerun this installer with -PowerShellPath pointing to pwsh.exe.'
}

function Remove-ContextMenu {
    $root = [Microsoft.Win32.Registry]::CurrentUser
    $root.DeleteSubKeyTree($contextMenuKey, $false)
    $root.DeleteSubKeyTree($legacyContextMenuKey, $false)
}

function Set-RegistryString {
    param(
        [Parameter(Mandatory)]
        [Microsoft.Win32.RegistryKey]$Key,

        [AllowEmptyString()]
        [string]$Name,

        [AllowEmptyString()]
        [string]$Value
    )

    $Key.SetValue($Name, $Value, [Microsoft.Win32.RegistryValueKind]::String)
}

function New-RegistryCommand {
    param(
        [Parameter(Mandatory)]
        [string]$PwshPath,

        [Parameter(Mandatory)]
        [string]$VanishTotalPath,

        [switch]$UploadUnknownFiles
    )

    $parts = @(
        ('"{0}"' -f $PwshPath),
        '-NoLogo',
        '-NoProfile',
        '-ExecutionPolicy',
        'Bypass',
        '-File',
        ('"{0}"' -f $VanishTotalPath),
        '-Path',
        '"%1"'
    )

    if ($UploadUnknownFiles) {
        $parts += '-UploadUnknownFiles'
    }

    return ($parts -join ' ')
}

function Set-ContextMenu {
    param(
        [Parameter(Mandatory)]
        [string]$PwshPath,

        [Parameter(Mandatory)]
        [string]$VanishTotalPath
    )

    Remove-ContextMenu

    $root = [Microsoft.Win32.Registry]::CurrentUser
    $menuKey = $root.CreateSubKey($contextMenuKey)
    if ($null -eq $menuKey) {
        throw "Could not create registry key HKCU:\$contextMenuKey"
    }

    try {
        Set-RegistryString -Key $menuKey -Name 'MUIVerb' -Value 'Scan with VanishTotal'
        Set-RegistryString -Key $menuKey -Name 'Icon' -Value $PwshPath
        Set-RegistryString -Key $menuKey -Name 'SubCommands' -Value ''
    }
    finally {
        $menuKey.Close()
    }

    $normalKey = $root.CreateSubKey("$contextMenuKey\shell\01_LookupOnly")
    $normalCommandKey = $root.CreateSubKey("$contextMenuKey\shell\01_LookupOnly\command")
    $uploadKey = $root.CreateSubKey("$contextMenuKey\shell\02_UploadIfUnknown")
    $uploadCommandKey = $root.CreateSubKey("$contextMenuKey\shell\02_UploadIfUnknown\command")

    try {
        Set-RegistryString -Key $normalKey -Name 'MUIVerb' -Value 'Normal scan'
        Set-RegistryString -Key $normalKey -Name 'Icon' -Value $PwshPath
        Set-RegistryString -Key $normalCommandKey -Name '' -Value (New-RegistryCommand -PwshPath $PwshPath -VanishTotalPath $VanishTotalPath)

        Set-RegistryString -Key $uploadKey -Name 'MUIVerb' -Value 'Scan and upload if unknown'
        Set-RegistryString -Key $uploadKey -Name 'Icon' -Value $PwshPath
        Set-RegistryString -Key $uploadCommandKey -Name '' -Value (New-RegistryCommand -PwshPath $PwshPath -VanishTotalPath $VanishTotalPath -UploadUnknownFiles)
    }
    finally {
        foreach ($key in @($normalKey, $normalCommandKey, $uploadKey, $uploadCommandKey)) {
            if ($null -ne $key) {
                $key.Close()
            }
        }
    }
}

try {
    if ($Uninstall) {
        if ($PSCmdlet.ShouldProcess('current user Explorer context menu', 'Remove VanishTotal entries')) {
            Remove-ContextMenu
            Write-Host 'Removed VanishTotal from the current user Explorer context menu.'
        }

        return
    }

    if (-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) {
        throw "VanishTotal.ps1 was not found: $ScriptPath"
    }

    $resolvedScriptPath = (Resolve-Path -LiteralPath $ScriptPath).ProviderPath
    $modulePath = Join-Path -Path (Split-Path -Path $resolvedScriptPath -Parent) -ChildPath 'VanishTotal.Core.psm1'
    if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
        throw "VanishTotal.Core.psm1 was not found next to the script: $modulePath"
    }

    $resolvedPwshPath = Resolve-PwshPath -RequestedPath $PowerShellPath

    foreach ($path in @($resolvedScriptPath, $modulePath)) {
        Unblock-File -LiteralPath $path -ErrorAction SilentlyContinue
    }

    if ($PSCmdlet.ShouldProcess('current user Explorer context menu', 'Install VanishTotal entries')) {
        Set-ContextMenu -PwshPath $resolvedPwshPath -VanishTotalPath $resolvedScriptPath
        Write-Host 'Installed VanishTotal for the current user Explorer context menu.'
        Write-Host "PowerShell 7: $resolvedPwshPath"
        Write-Host "Script:       $resolvedScriptPath"
        Write-Host 'On Windows 11, the entry may appear under Show more options.'
    }
}
catch {
    Write-Error $_
    exit 1
}
