#requires -Version 7.0
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName = $true)]
    [Alias('FullName')]
    [ValidateNotNullOrEmpty()]
    [string]$Path,

    [string]$ApiKey = $env:VT_API_KEY,

    [switch]$UploadUnknownFiles,

    [switch]$StoreApiKey,

    [switch]$NoPause,

    [switch]$NoColor,

    [string]$JsonReportPath,

    [ValidateRange(1, 300)]
    [int]$TimeoutSec = 30,

    [ValidateRange(0, 10)]
    [int]$MaxRetries = 3,

    [ValidateRange(1, 60)]
    [int]$PollIntervalSec = 10,

    [ValidateRange(30, 7200)]
    [int]$AnalysisTimeoutSec = 900
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:ModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'VanishTotal.Core.psm1'

$script:UseColor = -not $NoColor

$script:Colors = @{
    Header     = '38;2;0;160;150'
    Text       = '38;2;240;240;240'
    Muted      = '38;2;170;170;170'
    Good       = '38;2;0;180;100'
    Warn       = '38;2;255;185;60'
    Bad        = '38;2;255;90;90'
    Info       = '38;2;90;160;255'
    Neutral    = '38;2;200;200;200'
}

function Write-Ansi {
    param(
        [AllowNull()]
        [string]$Text,

        [string]$Code = $script:Colors.Text
    )

    if ($script:UseColor) {
        Write-Host ("`e[{0}m{1}`e[0m" -f $Code, $Text)
    }
    else {
        Write-Host $Text
    }
}

function Write-Section {
    param(
        [Parameter(Mandatory)]
        [string]$Title
    )

    $width = 72
    $line = '=' * $width
    Write-Host ''
    Write-Ansi $line $script:Colors.Header
    Write-Ansi $Title.ToUpperInvariant() $script:Colors.Header
    Write-Ansi $line $script:Colors.Header
}

function Write-KeyValue {
    param(
        [Parameter(Mandatory)]
        [string]$Key,

        [AllowNull()]
        [object]$Value,

        [string]$Color = $script:Colors.Text
    )

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return
    }

    Write-Ansi ('{0,-22} {1}' -f ($Key + ':'), $Value) $Color
}

function Get-CategoryColor {
    param(
        [AllowNull()]
        [string]$Category
    )

    switch ($Category) {
        'malicious'  { $script:Colors.Bad; break }
        'suspicious' { $script:Colors.Warn; break }
        'harmless'   { $script:Colors.Good; break }
        'undetected' { $script:Colors.Info; break }
        default      { $script:Colors.Neutral; break }
    }
}

function Format-Classification {
    param(
        [AllowNull()]
        [string]$Category
    )

    switch ($Category) {
        'malicious'        { 'Malicious'; break }
        'suspicious'       { 'Suspicious'; break }
        'harmless'         { 'Clean'; break }
        'undetected'       { 'No detection'; break }
        'type-unsupported' { 'Unsupported'; break }
        'timeout'          { 'Timeout'; break }
        'confirmed-timeout' { 'Timeout'; break }
        'failure'          { 'Failed'; break }
        default            { 'Unknown'; break }
    }
}

function Get-SeverityExitCode {
    param(
        [AllowNull()]
        [string]$Severity
    )

    switch ($Severity) {
        'Clean'      { 0; break }
        'Low'        { 0; break }
        'Review'     { 2; break }
        'Suspicious' { 3; break }
        'Malicious'  { 4; break }
        default      { 1; break }
    }
}

function ConvertFrom-UnixTime {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($Value -is [int] -or $Value -is [long]) {
        return [DateTimeOffset]::FromUnixTimeSeconds([int64]$Value).LocalDateTime
    }

    return $null
}

function Write-DangerBar {
    param(
        [Parameter(Mandatory)]
        [double]$Percent,

        [Parameter(Mandatory)]
        [string]$VerdictText,

        [Parameter(Mandatory)]
        [string]$Detail,

        [Parameter(Mandatory)]
        [string]$Action
    )

    $Percent = [math]::Min([math]::Max($Percent, 0), 100)
    $filled = [int][math]::Round(40 * ($Percent / 100))
    $empty = 40 - $filled
    $bar = ('#' * $filled) + ('-' * $empty)

    $color = if ($Percent -ge 80) {
        $script:Colors.Bad
    }
    elseif ($Percent -ge 55) {
        $script:Colors.Warn
    }
    elseif ($Percent -ge 35) {
        $script:Colors.Warn
    }
    else {
        $script:Colors.Good
    }

    Write-Host ''
    Write-Ansi ('Danger score: {0}%' -f $Percent) $color
    Write-Ansi $bar $color
    Write-KeyValue -Key 'Verdict' -Value $VerdictText -Color $script:Colors.Text
    Write-KeyValue -Key 'Detail' -Value $Detail -Color $script:Colors.Muted
    Write-KeyValue -Key 'Recommended action' -Value $Action -Color $script:Colors.Text
}

function Write-JsonReport {
    param(
        [Parameter(Mandatory)]
        [object]$ReportObject,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $resolvedOutput = $OutputPath
    if (-not [IO.Path]::IsPathRooted($resolvedOutput)) {
        $resolvedOutput = Join-Path -Path (Get-Location) -ChildPath $resolvedOutput
    }

    $parent = Split-Path -Path $resolvedOutput -Parent
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $ReportObject | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $resolvedOutput -Encoding utf8
    Write-KeyValue -Key 'JSON report' -Value $resolvedOutput -Color $script:Colors.Info
}

function Invoke-PauseIfNeeded {
    param(
        [switch]$NoPause
    )

    if (-not $NoPause) {
        Write-Host ''
        [void](Read-Host 'Press Enter to close')
    }
}

$exitCode = 1

try {
    Import-Module -Name $script:ModulePath -Force

    if ([string]::IsNullOrWhiteSpace($ApiKey)) {
        $secureApiKey = Read-Host 'Enter your VirusTotal API key' -AsSecureString
        $ApiKey = ConvertFrom-SecureStringToPlainText -SecureString $secureApiKey
        if ([string]::IsNullOrWhiteSpace($ApiKey)) {
            throw 'No VirusTotal API key was provided. Set VT_API_KEY or pass -ApiKey.'
        }
    }

    if ($StoreApiKey) {
        [Environment]::SetEnvironmentVariable('VT_API_KEY', $ApiKey, 'User')
        Write-Ansi 'Stored VT_API_KEY for the current Windows user.' $script:Colors.Muted
    }

    $resolvedPath = (Resolve-Path -LiteralPath $Path).Path
    $file = Get-Item -LiteralPath $resolvedPath -ErrorAction Stop
    if ($file.PSIsContainer) {
        throw "Path is a directory, not a file: $resolvedPath"
    }

    $client = New-VTClient -ApiKey $ApiKey -TimeoutSec $TimeoutSec -MaxRetries $MaxRetries
    $riskModel = Get-VTDefaultRiskModel

    Write-Section 'VanishTotal'
    Write-KeyValue -Key 'Target file' -Value $resolvedPath
    Write-KeyValue -Key 'Upload policy' -Value ($(if ($UploadUnknownFiles) { 'Upload unknown files when no VT report exists' } else { 'Lookup only; unknown files are not uploaded' })) -Color $(if ($UploadUnknownFiles) { $script:Colors.Warn } else { $script:Colors.Good })

    $lookupParams = @{
        FilePath              = $resolvedPath
        Client                = $client
        UploadUnknownFiles    = $UploadUnknownFiles
        PollIntervalSec       = $PollIntervalSec
        AnalysisTimeoutSec    = $AnalysisTimeoutSec
    }

    if ($UploadUnknownFiles) {
        if ($PSCmdlet.ShouldProcess($resolvedPath, 'Upload file to VirusTotal if no existing report is available')) {
            $lookup = Get-VTFileReport @lookupParams
        }
        else {
            throw 'Upload was not approved.'
        }
    }
    else {
        $lookup = Get-VTFileReport @lookupParams
    }

    if ($lookup.Status -eq 'NotFound') {
        Write-Section 'No Existing VirusTotal Report'
        Write-KeyValue -Key 'SHA256' -Value $lookup.Hash
        Write-Ansi 'VirusTotal has no existing report for this file. The file was not uploaded because -UploadUnknownFiles was not supplied.' $script:Colors.Warn

        $structured = New-VTStructuredReport -TargetPath $resolvedPath -Lookup $lookup -Report $null -Attributes $null -Assessments @() -Risk $null
        if ($JsonReportPath) {
            Write-JsonReport -ReportObject $structured -OutputPath $JsonReportPath
        }

        $exitCode = 2
        return
    }

    $report = $lookup.Report
    $data = Get-VTPropertyValue -InputObject $report -Name 'data'
    $attributes = Get-VTPropertyValue -InputObject $data -Name 'attributes'
    if ($null -eq $attributes) {
        throw 'VirusTotal response did not include file attributes.'
    }

    $assessments = @(ConvertTo-VTEngineAssessments -Attributes $attributes -RiskModel $riskModel)
    $risk = Measure-VTRisk -Attributes $attributes -Assessments $assessments -FilePath $resolvedPath -RiskModel $riskModel
    $structuredReport = New-VTStructuredReport -TargetPath $resolvedPath -Lookup $lookup -Report $report -Attributes $attributes -Assessments $assessments -Risk $risk

    Write-Section 'File Details'
    $fileName = Get-VTPropertyValue -InputObject $attributes -Name 'meaningful_name'
    if (-not $fileName) {
        $fileName = Split-Path -Path $resolvedPath -Leaf
    }

    Write-KeyValue -Key 'Name' -Value $fileName
    Write-KeyValue -Key 'Size' -Value ('{0:N0} bytes' -f (Get-VTPropertyValue -InputObject $attributes -Name 'size'))
    Write-KeyValue -Key 'Type' -Value (Get-VTPropertyValue -InputObject $attributes -Name 'type_description')
    Write-KeyValue -Key 'Magic' -Value (Get-VTPropertyValue -InputObject $attributes -Name 'magic')
    Write-KeyValue -Key 'SHA256' -Value (Get-VTPropertyValue -InputObject $attributes -Name 'sha256')
    Write-KeyValue -Key 'SHA1' -Value (Get-VTPropertyValue -InputObject $attributes -Name 'sha1')
    Write-KeyValue -Key 'MD5' -Value (Get-VTPropertyValue -InputObject $attributes -Name 'md5')
    Write-KeyValue -Key 'vhash' -Value (Get-VTPropertyValue -InputObject $attributes -Name 'vhash')
    Write-KeyValue -Key 'tlsh' -Value (Get-VTPropertyValue -InputObject $attributes -Name 'tlsh')
    Write-KeyValue -Key 'Times submitted' -Value (Get-VTPropertyValue -InputObject $attributes -Name 'times_submitted')
    Write-KeyValue -Key 'First seen' -Value (ConvertFrom-UnixTime -Value (Get-VTPropertyValue -InputObject $attributes -Name 'first_submission_date'))
    Write-KeyValue -Key 'Last seen' -Value (ConvertFrom-UnixTime -Value (Get-VTPropertyValue -InputObject $attributes -Name 'last_submission_date'))

    Write-Section 'Engine Verdicts'

    if ($assessments.Count -eq 0) {
        Write-Ansi 'VirusTotal did not return per-engine verdicts for this file.' $script:Colors.Warn
    }
    else {
        Write-Ansi ('{0,-28} {1,-20} {2}' -f 'Engine', 'Classification', 'Result') $script:Colors.Muted
        Write-Ansi ('{0,-28} {1,-20} {2}' -f ('-' * 26), ('-' * 18), ('-' * 30)) $script:Colors.Muted

        foreach ($assessment in $assessments | Sort-Object Engine) {
            $classification = Format-Classification -Category $assessment.EffectiveCategory

            $resultText = if ([string]::IsNullOrWhiteSpace($assessment.Result)) {
                $classification
            }
            else {
                $assessment.Result
            }

            $line = '{0,-28} {1,-20} {2}' -f $assessment.Engine, $classification, $resultText
            Write-Ansi $line (Get-CategoryColor -Category $assessment.EffectiveCategory)
        }
    }

    Write-Section 'Detection Summary'
    Write-KeyValue -Key 'Malicious' -Value $risk.AdjustedStats.malicious -Color $script:Colors.Bad
    Write-KeyValue -Key 'Suspicious' -Value $risk.AdjustedStats.suspicious -Color $script:Colors.Warn
    Write-KeyValue -Key 'Clean' -Value $risk.AdjustedStats.harmless -Color $script:Colors.Good
    Write-KeyValue -Key 'No detection' -Value $risk.AdjustedStats.undetected -Color $script:Colors.Info

    $unavailable = $risk.AdjustedStats.unsupported + $risk.AdjustedStats.timeout + $risk.AdjustedStats.failure + $risk.AdjustedStats.unknown
    if ($unavailable -gt 0) {
        Write-KeyValue -Key 'Unavailable' -Value $unavailable -Color $script:Colors.Muted
    }

    Write-DangerBar -Percent $risk.DangerScorePercent -VerdictText $risk.VerdictText -Detail $risk.VerdictDetail -Action $risk.RecommendedAction

    Write-Section 'VirusTotal Link'
    Write-KeyValue -Key 'GUI report' -Value $structuredReport.Lookup.GuiUrl -Color $script:Colors.Info

    if ($JsonReportPath) {
        Write-Section 'Report Export'
        Write-JsonReport -ReportObject $structuredReport -OutputPath $JsonReportPath
    }

    Write-Section 'End of Report'
    $exitCode = Get-SeverityExitCode -Severity $risk.Severity
}
catch {
    Write-Host ''
    Write-Ansi ("Error: {0}" -f $_.Exception.Message) $script:Colors.Bad
    $exitCode = 1
}
finally {
    Invoke-PauseIfNeeded -NoPause:$NoPause
    exit $exitCode
}
