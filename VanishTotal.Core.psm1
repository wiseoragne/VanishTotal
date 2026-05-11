Set-StrictMode -Version 3.0

$script:VTApiBaseUri = 'https://www.virustotal.com/api/v3'

$script:DefaultEngineWeights = [ordered]@{
    # Calibrated May 2026 from recent AV-TEST business results, AV-Comparatives
    # enterprise malware/real-world tests, and enterprise governance constraints.
    # These weights model detection-confidence contribution, not product preference.
    'Microsoft'             = 10
    'BitDefender'           = 10
    'ESET'                  = 10
    'ESET-NOD32'            = 10
    'Avast'                 = 10
    'AVG'                   = 9
    'GData'                 = 9
    'G DATA'                = 9
    'WithSecure'            = 9
    'F-Secure'              = 9
    'Norton'                = 9
    'Symantec'              = 9
    'Kaspersky'             = 8
    'Trellix'               = 8
    'McAfee'                = 8
    'FireEye'               = 8
    'Sophos'                = 8
    'CrowdStrike'           = 8
    'Cisco'                 = 8
    'Elastic'               = 8
    'Rapid7'                = 8
    'VIPRE'                 = 8
    'AhnLab-V3'             = 8
    'AhnLab'                = 8
    'TrendMicro'            = 8
    'Trend Micro'           = 8
    'SentinelOne'           = 8
    'Paloalto'              = 8
    'Palo Alto Networks'    = 8
    'Fortinet'              = 8
    'BitDefenderTheta'      = 8
    'BitDefenderFalx'       = 8
    'K7AntiVirus'           = 7
    'K7'                    = 7
    'Avira'                 = 7
    'Malwarebytes'          = 7
    'Qualys'                = 7
    'Seqrite'               = 7
    'MicroWorld-eScan'      = 7
    'eScan'                 = 7
    'Acronis'               = 7
    'HP'                    = 7
    'Cylance'               = 6
    'BlackBerry'            = 6
    'CheckPoint'            = 6
    'Check Point'           = 6
    'DrWeb'                 = 6
    'Emsisoft'              = 6
    'Zillya'                = 5
    'Comodo'                = 5
    'Xcitium'               = 5
    'ClamAV'                = 4
    'Jiangmin'              = 4
    'Rising'                = 4
    'Antiy-AVL'             = 4
    'VBA32'                 = 4
    'Bkav'                  = 4
    'MaxSecure'             = 4
    'Cyren'                 = 3
}

function ConvertFrom-SecureStringToPlainText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [SecureString]$SecureString
    )

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        if ($bstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
}

function Get-VTPropertyValue {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name
    )

    process {
        if ($null -eq $InputObject) {
            return $null
        }

        if ($InputObject -is [System.Collections.IDictionary]) {
            if ($InputObject.Contains($Name)) {
                return $InputObject[$Name]
            }

            return $null
        }

        $property = $InputObject.PSObject.Properties[$Name]
        if ($null -ne $property) {
            return $property.Value
        }

        return $null
    }
}

function New-VTClient {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ApiKey,

        [ValidateRange(1, 300)]
        [int]$TimeoutSec = 30,

        [ValidateRange(0, 10)]
        [int]$MaxRetries = 3,

        [string]$ApiBaseUri = $script:VTApiBaseUri
    )

    [PSCustomObject]@{
        ApiKey     = $ApiKey
        TimeoutSec = $TimeoutSec
        MaxRetries = $MaxRetries
        ApiBaseUri = $ApiBaseUri.TrimEnd('/')
        UserAgent  = 'VanishTotal/2.0 PowerShell'
    }
}

function Get-VTHttpStatusCode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $responseProperty = $ErrorRecord.Exception.PSObject.Properties['Response']
    if ($null -eq $responseProperty) {
        return $null
    }

    $response = $responseProperty.Value
    if ($null -eq $response) {
        return $null
    }

    $statusCode = $response.StatusCode
    if ($null -eq $statusCode) {
        return $null
    }

    if ($statusCode.PSObject.Properties['value__']) {
        return [int]$statusCode.value__
    }

    try {
        return [int]$statusCode
    }
    catch {
        return $null
    }
}

function Get-VTRetryDelaySeconds {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,

        [Parameter(Mandatory)]
        [int]$Attempt
    )

    $responseProperty = $ErrorRecord.Exception.PSObject.Properties['Response']
    $response = if ($null -ne $responseProperty) { $responseProperty.Value } else { $null }
    if ($null -ne $response -and $null -ne $response.Headers) {
        try {
            $retryAfter = $response.Headers.RetryAfter
            if ($null -ne $retryAfter) {
                if ($retryAfter.Delta.HasValue) {
                    return [math]::Max(1, [int][math]::Ceiling($retryAfter.Delta.Value.TotalSeconds))
                }

                if ($retryAfter.Date.HasValue) {
                    $seconds = ($retryAfter.Date.Value - [DateTimeOffset]::UtcNow).TotalSeconds
                    return [math]::Max(1, [int][math]::Ceiling($seconds))
                }
            }
        }
        catch {
            # Fall back to exponential backoff below.
        }
    }

    return [math]::Min(60, [math]::Pow(2, $Attempt))
}

function Invoke-VTRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('GET', 'POST')]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter(Mandatory)]
        [pscustomobject]$Client,

        [AllowNull()]
        [object]$Body,

        [AllowNull()]
        [hashtable]$Form
    )

    $headers = @{
        'x-apikey'   = $Client.ApiKey
        'User-Agent' = $Client.UserAgent
    }

    $params = @{
        Method      = $Method
        Uri         = $Uri
        Headers     = $headers
        TimeoutSec  = $Client.TimeoutSec
        ErrorAction = 'Stop'
    }

    if ($PSBoundParameters.ContainsKey('Body') -and $null -ne $Body) {
        $params['Body'] = $Body
        $params['ContentType'] = 'application/json'
    }

    if ($PSBoundParameters.ContainsKey('Form') -and $null -ne $Form) {
        $params['Form'] = $Form
    }

    for ($attempt = 0; $attempt -le $Client.MaxRetries; $attempt++) {
        try {
            return Invoke-RestMethod @params
        }
        catch {
            $statusCode = Get-VTHttpStatusCode -ErrorRecord $_
            $canRetry = ($null -eq $statusCode) -or ($statusCode -in @(429, 500, 502, 503, 504))
            if ($attempt -lt $Client.MaxRetries -and $canRetry) {
                $delay = Get-VTRetryDelaySeconds -ErrorRecord $_ -Attempt ($attempt + 1)
                $statusText = if ($null -eq $statusCode) { 'a transient network error' } else { "HTTP $statusCode" }
                Write-Verbose "VirusTotal returned $statusText. Retrying in $delay second(s)."
                Start-Sleep -Seconds $delay
                continue
            }

            throw
        }
    }
}

function Get-VTDefaultRiskModel {
    [CmdletBinding()]
    param()

    $engineWeights = [ordered]@{}
    foreach ($key in $script:DefaultEngineWeights.Keys) {
        $engineWeights[$key] = $script:DefaultEngineWeights[$key]
    }

    [PSCustomObject]@{
        EngineWeights            = $engineWeights
        DefaultEngineWeight      = 2
        Tier1WeightThreshold     = 9
        SuspiciousKeywordPattern = '(?i)(\bsuspicious\b|\bheur(istic)?\b|\bgeneric\b|\bgen[:._-]|\bml\b|machine.?learning|riskware|risk.?tool|pua|pup|potentially.?unwanted|\bunwanted\b|adware|grayware|hack.?tool|not-a-virus|unsafe|packed|obfuscat|low.?confidence|confidence[:= ]+low|low.?score|score[:= ]+[0-5]?\d\b|possible|variant|cloud)'
        AmbiguousMaliciousKeywordPattern = '(?i)(\bsuspicious\b|riskware|risk.?tool|pua|pup|potentially.?unwanted|\bunwanted\b|adware|grayware|hack.?tool|not-a-virus|unsafe|low.?confidence|confidence[:= ]+low|low.?score|score[:= ]+[0-5]?\d\b|possible)'
        MaliciousKeywordPattern  = '(?i)(\bmalicious\b|ransom|trojan|worm|virus|backdoor|rootkit|stealer|keylogger|banker|botnet|spyware|dropper|loader|exploit|miner|cryptor|infostealer|\brat\b|wiper)'
    }
}

function Get-VTEngineWeight {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Engine,

        [Parameter(Mandatory)]
        [pscustomobject]$RiskModel
    )

    $weights = $RiskModel.EngineWeights
    if ($weights.Contains($Engine)) {
        return [int]$weights[$Engine]
    }

    foreach ($key in $weights.Keys | Sort-Object { ([string]$_).Length } -Descending) {
        if ($Engine.StartsWith([string]$key, [StringComparison]::OrdinalIgnoreCase)) {
            return [int]$weights[$key]
        }
    }

    return [int]$RiskModel.DefaultEngineWeight
}

function Get-VTDetectionAssessment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Engine,

        [Parameter(Mandatory)]
        [object]$Result,

        [Parameter(Mandatory)]
        [pscustomobject]$RiskModel
    )

    $rawCategory = [string](Get-VTPropertyValue -InputObject $Result -Name 'category')
    $rawCategory = $rawCategory.Trim().ToLowerInvariant()
    $resultText = [string](Get-VTPropertyValue -InputObject $Result -Name 'result')
    $method = [string](Get-VTPropertyValue -InputObject $Result -Name 'method')
    $engineVersion = [string](Get-VTPropertyValue -InputObject $Result -Name 'engine_version')
    $engineUpdate = [string](Get-VTPropertyValue -InputObject $Result -Name 'engine_update')

    $hasMaliciousKeyword = $false
    $hasSuspiciousKeyword = $false
    $hasAmbiguousMaliciousKeyword = $false

    if (-not [string]::IsNullOrWhiteSpace($resultText)) {
        $hasMaliciousKeyword = $resultText -match $RiskModel.MaliciousKeywordPattern
        $hasSuspiciousKeyword = $resultText -match $RiskModel.SuspiciousKeywordPattern
        $hasAmbiguousMaliciousKeyword = $resultText -match $RiskModel.AmbiguousMaliciousKeywordPattern
    }

    $effectiveCategory = if ($rawCategory) { $rawCategory } else { 'unknown' }
    $confidence = 'None'
    $reason = 'VirusTotal category'

    switch ($rawCategory) {
        'malicious' {
            if ($hasMaliciousKeyword) {
                $effectiveCategory = 'malicious'
                $confidence = 'High'
                $reason = 'VT malicious category with malware-family wording'
            }
            elseif ($hasAmbiguousMaliciousKeyword) {
                $effectiveCategory = 'suspicious'
                $confidence = 'Medium'
                $reason = 'Detection name uses PUA, tool, or low-confidence wording'
            }
            else {
                $effectiveCategory = 'malicious'
                $confidence = 'Medium'
                $reason = 'VT malicious category'
            }
        }
        'suspicious' {
            $effectiveCategory = 'suspicious'
            $confidence = 'Medium'
            $reason = 'VT suspicious category'
        }
        { $_ -in @('harmless', 'undetected') } {
            if ($hasMaliciousKeyword) {
                $effectiveCategory = 'suspicious'
                $confidence = 'Medium'
                $reason = 'Non-malicious category included malware wording'
            }
            elseif ($hasSuspiciousKeyword) {
                $effectiveCategory = 'suspicious'
                $confidence = 'Low'
                $reason = 'Non-malicious category included suspicious wording'
            }
            else {
                $effectiveCategory = $rawCategory
                $confidence = 'None'
            }
        }
        default {
            if ($hasMaliciousKeyword) {
                $effectiveCategory = 'malicious'
                $confidence = 'Medium'
                $reason = 'Detection text included malware wording'
            }
            elseif ($hasSuspiciousKeyword) {
                $effectiveCategory = 'suspicious'
                $confidence = 'Low'
                $reason = 'Detection text included suspicious wording'
            }
            elseif (-not $rawCategory) {
                $effectiveCategory = 'unknown'
                $reason = 'No VT category provided'
            }
        }
    }

    [PSCustomObject]@{
        Engine            = $Engine
        RawCategory       = $rawCategory
        EffectiveCategory = $effectiveCategory
        Result            = $resultText
        Method            = $method
        EngineVersion     = $engineVersion
        EngineUpdate      = $engineUpdate
        Confidence        = $confidence
        Reason            = $reason
        Weight            = Get-VTEngineWeight -Engine $Engine -RiskModel $RiskModel
    }
}

function ConvertTo-VTEngineAssessments {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Attributes,

        [Parameter(Mandatory)]
        [pscustomobject]$RiskModel
    )

    $results = Get-VTPropertyValue -InputObject $Attributes -Name 'last_analysis_results'
    if ($null -eq $results) {
        return @()
    }

    $items = if ($results -is [System.Collections.IDictionary]) {
        foreach ($key in $results.Keys) {
            [PSCustomObject]@{
                Name  = [string]$key
                Value = $results[$key]
            }
        }
    }
    else {
        $results.PSObject.Properties
    }

    foreach ($item in $items | Sort-Object Name) {
        Get-VTDetectionAssessment -Engine $item.Name -Result $item.Value -RiskModel $RiskModel
    }
}

function Get-VTThreatFamilyCandidate {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$DetectionName
    )

    if ([string]::IsNullOrWhiteSpace($DetectionName)) {
        return $null
    }

    $ignore = @{
        'adware' = $true; 'agent' = $true; 'application' = $true; 'cloud' = $true
        'confidence' = $true; 'detected' = $true; 'file' = $true; 'gen' = $true
        'generic' = $true; 'grayware' = $true; 'heur' = $true; 'heuristic' = $true
        'malware' = $true; 'ml' = $true; 'msil' = $true; 'packed' = $true
        'possible' = $true; 'program' = $true; 'pua' = $true; 'pup' = $true
        'riskware' = $true; 'score' = $true; 'suspicious' = $true; 'trojan' = $true
        'unsafe' = $true; 'variant' = $true; 'virus' = $true; 'win32' = $true
        'win64' = $true; 'worm' = $true; 'w32' = $true; 'w64' = $true
    }

    $clean = [regex]::Replace($DetectionName.ToLowerInvariant(), '[^a-z0-9]+', ' ')
    foreach ($token in $clean.Split(' ', [StringSplitOptions]::RemoveEmptyEntries)) {
        if ($token.Length -lt 4) {
            continue
        }

        if ($token -match '^\d+$') {
            continue
        }

        if ($ignore.ContainsKey($token)) {
            continue
        }

        return (Get-Culture).TextInfo.ToTitleCase($token)
    }

    return $null
}

function Get-VTFileTypeRiskBonus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Attributes,

        [Parameter(Mandatory)]
        [string]$FilePath
    )

    $typeDescription = [string](Get-VTPropertyValue -InputObject $Attributes -Name 'type_description')
    $magic = [string](Get-VTPropertyValue -InputObject $Attributes -Name 'magic')
    $extension = [IO.Path]::GetExtension($FilePath).TrimStart('.').ToLowerInvariant()
    $combined = "$typeDescription $magic $extension".ToLowerInvariant()

    if ($combined -match '\b(exe|scr|com|cpl|dll|sys|drv|efi|pe32|executable)\b') {
        return 0.10
    }

    if ($combined -match '\b(ps1|psm1|bat|cmd|vbs|vbe|js|jse|wsf|hta|lnk|script|powershell|javascript|batch)\b') {
        return 0.12
    }

    if ($combined -match '\b(doc|docm|xls|xlsm|ppt|pptm|rtf|pdf|office|word|excel|macro|document)\b') {
        return 0.06
    }

    if ($combined -match '\b(zip|rar|7z|tar|gz|archive|iso|img)\b') {
        return 0.04
    }

    return 0.0
}

function Measure-VTRisk {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Attributes,

        [Parameter(Mandatory)]
        [object[]]$Assessments,

        [Parameter(Mandatory)]
        [string]$FilePath,

        [Parameter(Mandatory)]
        [pscustomobject]$RiskModel
    )

    $adjustedStats = [ordered]@{
        malicious   = 0
        suspicious  = 0
        harmless    = 0
        undetected  = 0
        unsupported = 0
        timeout     = 0
        failure     = 0
        unknown     = 0
    }

    $weightedTotal = 0.0
    $weightedMalicious = 0.0
    $weightedSuspicious = 0.0
    $weightedHarmlessOffset = 0.0
    $tier1MaliciousWeight = 0.0
    $tier1SuspiciousWeight = 0.0
    $familyCounts = @{}

    foreach ($assessment in $Assessments) {
        $category = [string]$assessment.EffectiveCategory
        $weight = [double]$assessment.Weight

        switch ($category) {
            'malicious' {
                $adjustedStats.malicious++
                $weightedTotal += $weight
                $weightedMalicious += $weight
                if ($weight -ge $RiskModel.Tier1WeightThreshold) {
                    $tier1MaliciousWeight += $weight
                }

                $family = Get-VTThreatFamilyCandidate -DetectionName $assessment.Result
                if ($family) {
                    if (-not $familyCounts.ContainsKey($family)) {
                        $familyCounts[$family] = 0
                    }
                    $familyCounts[$family]++
                }
            }
            'suspicious' {
                $adjustedStats.suspicious++
                $weightedTotal += $weight
                $weightedSuspicious += ($weight * 0.55)
                if ($weight -ge $RiskModel.Tier1WeightThreshold) {
                    $tier1SuspiciousWeight += $weight
                }

                $family = Get-VTThreatFamilyCandidate -DetectionName $assessment.Result
                if ($family) {
                    if (-not $familyCounts.ContainsKey($family)) {
                        $familyCounts[$family] = 0
                    }
                    $familyCounts[$family]++
                }
            }
            'harmless' {
                $adjustedStats.harmless++
                $weightedTotal += $weight
                $weightedHarmlessOffset += ($weight * 0.08)
            }
            'undetected' {
                $adjustedStats.undetected++
                $weightedTotal += $weight
            }
            'type-unsupported' {
                $adjustedStats.unsupported++
            }
            { $_ -in @('timeout', 'confirmed-timeout') } {
                $adjustedStats.timeout++
            }
            'failure' {
                $adjustedStats.failure++
            }
            default {
                $adjustedStats.unknown++
            }
        }
    }

    $score = 0.0
    $baseScore = 0.0
    if ($weightedTotal -gt 0) {
        $baseScore = ($weightedMalicious + $weightedSuspicious - $weightedHarmlessOffset) / $weightedTotal
        if ($baseScore -lt 0) {
            $baseScore = 0
        }

        $maxAgreement = 0
        if ($familyCounts.Count -gt 0) {
            $maxAgreement = [int](($familyCounts.Values | Measure-Object -Maximum).Maximum)
        }

        $consensusMultiplier = 1.0
        if ($maxAgreement -gt 1) {
            $consensusMultiplier += [math]::Min($maxAgreement - 1, 6) * 0.03
        }

        $reputationMultiplier = 1.0
        $timesSubmitted = Get-VTPropertyValue -InputObject $Attributes -Name 'times_submitted'
        if ($timesSubmitted -is [int] -or $timesSubmitted -is [long]) {
            if ($timesSubmitted -lt 3) {
                $reputationMultiplier *= 1.12
            }
            elseif ($timesSubmitted -gt 1000) {
                $reputationMultiplier *= 0.82
            }
            elseif ($timesSubmitted -gt 100) {
                $reputationMultiplier *= 0.90
            }
        }

        $firstSeen = Get-VTPropertyValue -InputObject $Attributes -Name 'first_submission_date'
        if (($firstSeen -is [int] -or $firstSeen -is [long]) -and $firstSeen -gt 0) {
            $firstSeenUtc = [DateTimeOffset]::FromUnixTimeSeconds([int64]$firstSeen)
            if ($firstSeenUtc -gt [DateTimeOffset]::UtcNow.AddDays(-14)) {
                $reputationMultiplier *= 1.08
            }
            elseif ($firstSeenUtc -lt [DateTimeOffset]::UtcNow.AddDays(-365) -and $adjustedStats.malicious -eq 0) {
                $reputationMultiplier *= 0.92
            }
        }

        $fileTypeBonus = Get-VTFileTypeRiskBonus -Attributes $Attributes -FilePath $FilePath

        $score = ($baseScore * $consensusMultiplier * $reputationMultiplier) + $fileTypeBonus

        if ($adjustedStats.malicious -eq 0 -and $adjustedStats.suspicious -eq 0) {
            $score = [math]::Min($score, 0.18)
        }
        elseif ($adjustedStats.malicious -eq 0) {
            $score = [math]::Min($score, 0.45)
        }
        elseif ($adjustedStats.malicious -eq 1) {
            $score = [math]::Min($score, 0.50)
        }
        elseif ($adjustedStats.malicious -eq 2) {
            $score = [math]::Min($score, 0.65)
        }

        if ($adjustedStats.malicious -ge 5) {
            $score = [math]::Max($score, 0.70)
        }

        if ($adjustedStats.malicious -ge 10) {
            $score = [math]::Max($score, 0.85)
        }

        if ($tier1MaliciousWeight -gt 0) {
            $score = [math]::Max($score, 0.55)
        }
        elseif ($tier1SuspiciousWeight -gt 0) {
            $score = [math]::Max($score, 0.35)
        }

        if ($tier1MaliciousWeight -eq 0 -and $adjustedStats.malicious -ge 3) {
            $score = [math]::Min($score, 0.82)
        }
    }

    $score = [math]::Min([math]::Max($score, 0), 1)
    $danger = [math]::Round($score * 100, 2)

    $verdictText = 'No engine data'
    $severity = 'Unknown'
    $recommendedAction = 'No automated decision. Re-run when VirusTotal provides analysis data.'
    $verdictDetail = 'VirusTotal did not provide usable engine results for this file.'

    if ($weightedTotal -gt 0) {
        if ($danger -lt 15) {
            $severity = 'Clean'
            $verdictText = 'Very likely clean'
            $recommendedAction = 'Allow under normal controls and keep standard endpoint monitoring.'
            $verdictDetail = 'No meaningful detection consensus was found.'
        }
        elseif ($danger -lt 35) {
            $severity = 'Low'
            $verdictText = 'Low risk'
            $recommendedAction = 'Allow only if the source, signer, and business need are expected.'
            $verdictDetail = 'Minor risk indicators exist, but engine consensus is weak.'
        }
        elseif ($danger -lt 55) {
            $severity = 'Review'
            $verdictText = 'Manual review recommended'
            $recommendedAction = 'Triage manually before deployment or execution.'
            $verdictDetail = 'Signals are mixed or keyword-based suspicious indicators were found.'
        }
        elseif ($danger -lt 80) {
            $severity = 'Suspicious'
            $verdictText = 'Suspicious - contain and investigate'
            $recommendedAction = 'Quarantine or block pending sandboxing, signature validation, and source verification.'
            $verdictDetail = 'Multiple or higher-weight suspicious signals were found.'
        }
        else {
            $severity = 'Malicious'
            $verdictText = 'High confidence malicious'
            $recommendedAction = 'Block the hash, isolate affected hosts, and start incident-response handling.'
            $verdictDetail = 'Strong weighted detection consensus indicates malware.'
        }
    }

    [PSCustomObject]@{
        DangerScorePercent    = $danger
        BaseScorePercent      = [math]::Round($baseScore * 100, 2)
        Severity              = $severity
        VerdictText           = $verdictText
        VerdictDetail         = $verdictDetail
        RecommendedAction     = $recommendedAction
        AdjustedStats         = [PSCustomObject]$adjustedStats
        WeightedTotal         = [math]::Round($weightedTotal, 2)
        WeightedMalicious     = [math]::Round($weightedMalicious, 2)
        WeightedSuspicious    = [math]::Round($weightedSuspicious, 2)
        Tier1MaliciousWeight  = [math]::Round($tier1MaliciousWeight, 2)
        Tier1SuspiciousWeight = [math]::Round($tier1SuspiciousWeight, 2)
        FamilyConsensus       = [PSCustomObject]$familyCounts
    }
}

function Get-VTFileReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,

        [Parameter(Mandatory)]
        [pscustomobject]$Client,

        [switch]$UploadUnknownFiles,

        [ValidateRange(1, 60)]
        [int]$PollIntervalSec = 10,

        [ValidateRange(30, 7200)]
        [int]$AnalysisTimeoutSec = 900
    )

    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) {
        throw "File not found or not a regular file: $FilePath"
    }

    $file = Get-Item -LiteralPath $FilePath -ErrorAction Stop
    $hash = Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256
    $fileId = $hash.Hash.ToLowerInvariant()
    $fileUri = "$($Client.ApiBaseUri)/files/$fileId"

    try {
        $report = Invoke-VTRequest -Method GET -Uri $fileUri -Client $Client
        return [PSCustomObject]@{
            Status     = 'Found'
            Uploaded   = $false
            Report     = $report
            Hash       = $fileId
            File       = $file
            AnalysisId = $null
        }
    }
    catch {
        $statusCode = Get-VTHttpStatusCode -ErrorRecord $_
        if ($statusCode -ne 404) {
            throw
        }
    }

    if (-not $UploadUnknownFiles) {
        return [PSCustomObject]@{
            Status     = 'NotFound'
            Uploaded   = $false
            Report     = $null
            Hash       = $fileId
            File       = $file
            AnalysisId = $null
        }
    }

    if ($file.Length -gt 650MB) {
        throw "File exceeds VirusTotal's 650 MB upload limit. Hash lookup was attempted first, but the file cannot be uploaded."
    }

    if ($file.Length -gt 200MB) {
        Write-Warning 'VirusTotal accepts uploads up to 650 MB, but files over 200 MB are often bundles and may produce engine timeouts. Consider extracting and scanning the inner files when possible.'
    }

    $uploadUri = "$($Client.ApiBaseUri)/files"
    if ($file.Length -gt 32MB) {
        $uploadUrlResult = Invoke-VTRequest -Method GET -Uri "$($Client.ApiBaseUri)/files/upload_url" -Client $Client
        $uploadUri = [string](Get-VTPropertyValue -InputObject $uploadUrlResult -Name 'data')
        if ([string]::IsNullOrWhiteSpace($uploadUri)) {
            throw 'VirusTotal did not return an upload URL for the large file.'
        }
    }

    $uploadResult = Invoke-VTRequest -Method POST -Uri $uploadUri -Client $Client -Form @{ file = $file }
    $uploadData = Get-VTPropertyValue -InputObject $uploadResult -Name 'data'
    $analysisId = [string](Get-VTPropertyValue -InputObject $uploadData -Name 'id')
    if ([string]::IsNullOrWhiteSpace($analysisId)) {
        throw 'VirusTotal upload completed, but no analysis ID was returned.'
    }

    $analysisUri = "$($Client.ApiBaseUri)/analyses/$analysisId"
    $timer = [Diagnostics.Stopwatch]::StartNew()
    do {
        Start-Sleep -Seconds $PollIntervalSec
        $analysis = Invoke-VTRequest -Method GET -Uri $analysisUri -Client $Client
        $analysisData = Get-VTPropertyValue -InputObject $analysis -Name 'data'
        $analysisAttributes = Get-VTPropertyValue -InputObject $analysisData -Name 'attributes'
        $status = [string](Get-VTPropertyValue -InputObject $analysisAttributes -Name 'status')
        Write-Verbose "VirusTotal analysis status: $status"

        if ($status -eq 'completed') {
            break
        }

        if ($timer.Elapsed.TotalSeconds -gt $AnalysisTimeoutSec) {
            throw "Timed out waiting for VirusTotal analysis after $AnalysisTimeoutSec seconds. Analysis ID: $analysisId"
        }
    } while ($true)

    $report = Invoke-VTRequest -Method GET -Uri $fileUri -Client $Client
    [PSCustomObject]@{
        Status     = 'Uploaded'
        Uploaded   = $true
        Report     = $report
        Hash       = $fileId
        File       = $file
        AnalysisId = $analysisId
    }
}

function New-VTStructuredReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TargetPath,

        [Parameter(Mandatory)]
        [object]$Lookup,

        [AllowNull()]
        [object]$Report,

        [AllowNull()]
        [object]$Attributes,

        [AllowNull()]
        [object[]]$Assessments,

        [AllowNull()]
        [object]$Risk
    )

    $data = Get-VTPropertyValue -InputObject $Report -Name 'data'
    $reportId = [string](Get-VTPropertyValue -InputObject $data -Name 'id')
    $sha256 = if ($Attributes) { [string](Get-VTPropertyValue -InputObject $Attributes -Name 'sha256') } else { [string]$Lookup.Hash }
    $guiUrl = if ($sha256) { "https://www.virustotal.com/gui/file/$sha256" } else { $null }

    [PSCustomObject]@{
        GeneratedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        TargetPath     = $TargetPath
        Lookup         = [PSCustomObject]@{
            Status     = $Lookup.Status
            Uploaded   = $Lookup.Uploaded
            Hash       = $Lookup.Hash
            AnalysisId = $Lookup.AnalysisId
            ReportId   = $reportId
            GuiUrl     = $guiUrl
        }
        File           = [PSCustomObject]@{
            Name            = if ($Attributes) { Get-VTPropertyValue -InputObject $Attributes -Name 'meaningful_name' } else { [IO.Path]::GetFileName($TargetPath) }
            Size            = if ($Attributes) { Get-VTPropertyValue -InputObject $Attributes -Name 'size' } else { $Lookup.File.Length }
            TypeDescription = if ($Attributes) { Get-VTPropertyValue -InputObject $Attributes -Name 'type_description' } else { $null }
            Magic           = if ($Attributes) { Get-VTPropertyValue -InputObject $Attributes -Name 'magic' } else { $null }
            Sha256          = $sha256
            Sha1            = if ($Attributes) { Get-VTPropertyValue -InputObject $Attributes -Name 'sha1' } else { $null }
            Md5             = if ($Attributes) { Get-VTPropertyValue -InputObject $Attributes -Name 'md5' } else { $null }
            VHash           = if ($Attributes) { Get-VTPropertyValue -InputObject $Attributes -Name 'vhash' } else { $null }
            TLSH            = if ($Attributes) { Get-VTPropertyValue -InputObject $Attributes -Name 'tlsh' } else { $null }
            TimesSubmitted  = if ($Attributes) { Get-VTPropertyValue -InputObject $Attributes -Name 'times_submitted' } else { $null }
        }
        RawStats       = if ($Attributes) { Get-VTPropertyValue -InputObject $Attributes -Name 'last_analysis_stats' } else { $null }
        AdjustedStats  = if ($Risk) { $Risk.AdjustedStats } else { $null }
        Risk           = if ($Risk) {
            [PSCustomObject]@{
                DangerScorePercent = $Risk.DangerScorePercent
                BaseScorePercent   = $Risk.BaseScorePercent
                Severity           = $Risk.Severity
                VerdictText        = $Risk.VerdictText
                VerdictDetail      = $Risk.VerdictDetail
                RecommendedAction  = $Risk.RecommendedAction
            }
        }
        else {
            $null
        }
        Engines        = if ($Assessments) {
            $Assessments | Select-Object Engine, RawCategory, EffectiveCategory, Result, Method, Confidence, Reason, Weight, EngineVersion, EngineUpdate
        }
        else {
            @()
        }
    }
}

Export-ModuleMember -Function @(
    'ConvertFrom-SecureStringToPlainText',
    'ConvertTo-VTEngineAssessments',
    'Get-VTDefaultRiskModel',
    'Get-VTFileReport',
    'Get-VTPropertyValue',
    'Measure-VTRisk',
    'New-VTClient',
    'New-VTStructuredReport'
)
