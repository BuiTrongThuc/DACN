[CmdletBinding()]
param(
    [string]$Root = '',
    [string]$CaseId = ''
)

$ErrorActionPreference = 'Stop'
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
if (-not $Root) {
    $Root = Join-Path $scriptDir '..'
}

$metadataPath = Join-Path $Root 'metadata\cases.jsonl'
$sigmaOutPath = Join-Path $Root 'metadata\sigma-results.jsonl'

if (-not (Test-Path $metadataPath)) {
    throw "Missing metadata/cases.jsonl at $metadataPath. Run collect_windows_logs.ps1 first."
}

$sigmaRules = @(
    @{
        RuleId = 'sigma-win-security-audit-log-cleared-1102'
        File = 'Security.evtx'
        EventIds = @(1102, 4719)
        Keywords = @()
    },
    @{
        RuleId = 'sigma-win-security-encoded-process-4688'
        File = 'Security.evtx'
        EventIds = @(4688)
        Keywords = @('-EncodedCommand', 'FromBase64String', 'schtasks /create')
    },
    @{
        RuleId = 'sigma-win-security-persistence-or-privilege'
        File = 'Security.evtx'
        EventIds = @(4698, 4720, 4728, 4732, 4756)
        Keywords = @()
    },
    @{
        RuleId = 'sigma-win-powershell-encoded-scriptblock-4104'
        File = 'PowerShell.evtx'
        EventIds = @(4104)
        Keywords = @('-EncodedCommand', 'FromBase64String', 'WindowStyle Hidden')
    },
    @{
        RuleId = 'sigma-win-powershell-scheduled-task-4104'
        File = 'PowerShell.evtx'
        EventIds = @(4104)
        Keywords = @('schtasks /create', 'GlobalBanAtomicUpdater')
    },
    @{
        RuleId = 'sigma-win-powershell-log-clear-4104'
        File = 'PowerShell.evtx'
        EventIds = @(4104)
        Keywords = @('wevtutil cl', 'Clear-EventLog', 'auditpol /clear')
    },
    @{
        RuleId = 'sigma-win-powershell-ingress-transfer-4104'
        File = 'PowerShell.evtx'
        EventIds = @(4104)
        Keywords = @('Invoke-WebRequest', 'bitsadmin /transfer')
    },
    @{
        RuleId = 'sigma-win-powershell-credential-search-4104'
        File = 'PowerShell.evtx'
        EventIds = @(4104)
        Keywords = @('findstr /si password', 'HKLM\SAM')
    },
    @{
        RuleId = 'sigma-win-sysmon-process-creation-1'
        File = 'Sysmon.evtx'
        EventIds = @(1)
        Keywords = @('-EncodedCommand', 'FromBase64String', 'certutil -urlcache', 'bitsadmin /transfer')
    },
    @{
        RuleId = 'sigma-win-defender-detection-1116-1117'
        File = 'Defender.evtx'
        EventIds = @(1116, 1117)
        Keywords = @()
    }
)

$cases = @()
foreach ($line in Get-Content $metadataPath -Encoding UTF8) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    $c = $line | ConvertFrom-Json
    if (-not $CaseId -or $c.case_id -eq $CaseId) {
        $cases += $c
    }
}

if ($cases.Count -eq 0) {
    throw "No matching cases found in $metadataPath"
}

$existingResults = [ordered]@{}
if (Test-Path $sigmaOutPath) {
    foreach ($line in Get-Content $sigmaOutPath -Encoding UTF8) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try {
            $obj = $line | ConvertFrom-Json
            $existingResults[$obj.case_id] = $line
        } catch {}
    }
}

foreach ($c in $cases) {
    $relPath = if ($c.artifact_path) { $c.artifact_path } else { $c.log_path }
    $artifactDir = Join-Path $Root $relPath

    $matchedRules = @()
    $totalMatches = 0

    foreach ($rule in $sigmaRules) {
        $evtxPath = Join-Path $artifactDir $rule.File
        if (-not (Test-Path $evtxPath)) { continue }

        try {
            $filter = @{ Path = $evtxPath; Id = $rule.EventIds }
            $events = @(Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue)
            foreach ($ev in $events) {
                $xmlText = $ev.ToXml()
                $isMatch = $false
                if ($rule.Keywords.Count -eq 0) {
                    $isMatch = $true
                } else {
                    foreach ($kw in $rule.Keywords) {
                        if ($xmlText.IndexOf($kw, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                            $isMatch = $true
                            break
                        }
                    }
                }
                if ($isMatch) {
                    $totalMatches++
                    if ($matchedRules -notcontains $rule.RuleId) {
                        $matchedRules += $rule.RuleId
                    }
                }
            }
        } catch {
            # Ignore empty query errors from Get-WinEvent
        }
    }

    $predicted = ($totalMatches -gt 0)
    $primaryRule = if ($matchedRules.Count -gt 0) { $matchedRules -join ';' } else { 'none' }
    $resultObj = [ordered]@{
        case_id = $c.case_id
        predicted_detected = [bool]$predicted
        rule_id = $primaryRule
        match_count = [int]$totalMatches
        evaluated_utc = (Get-Date).ToUniversalTime().ToString('o')
    }
    $jsonLine = $resultObj | ConvertTo-Json -Compress
    $existingResults[$c.case_id] = $jsonLine
    Write-Host ("Sigma [{0}]: predicted_detected={1}, match_count={2}, rule_id={3}" -f $c.case_id, $predicted, $totalMatches, $primaryRule)
}

$outLines = @($existingResults.Values)
$outLines | Set-Content -Encoding UTF8 -Path $sigmaOutPath
Write-Host "Sigma results saved to: $sigmaOutPath"
