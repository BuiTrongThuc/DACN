[CmdletBinding()]
param(
    [string]$Root = '',
    [string]$ExportDir = ''
)

$ErrorActionPreference = 'Stop'
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
if (-not $Root) {
    $Root = Join-Path $scriptDir '..'
}
if (-not $ExportDir) {
    $ExportDir = Join-Path $Root 'redteam-export'
}

$metadataPath = Join-Path $Root 'metadata\cases.jsonl'
if (-not (Test-Path $metadataPath)) {
    throw "Missing metadata/cases.jsonl. Run collect_windows_logs.ps1 or copy metadata/cases.example.jsonl and fill real values."
}

$envPath = Join-Path $Root 'metadata\environment.json'
$envData = $null
if (Test-Path $envPath) {
    $envData = Get-Content $envPath -Raw -Encoding UTF8 | ConvertFrom-Json
} else {
    Write-Warning "Missing metadata/environment.json. Run .\scripts\preflight.ps1 before final handoff."
}

$caseIds = [ordered]@{}
$baselineCount = 0
$atomicCount = 0
$failedTests = @()
$missingFiles = @()
$lineNumber = 0

foreach ($line in Get-Content $metadataPath -Encoding UTF8) {
    $lineNumber++
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    try {
        $case = $line | ConvertFrom-Json
    } catch {
        throw "Invalid JSON at metadata/cases.jsonl:$lineNumber"
    }
    foreach ($field in @('case_id', 'expected_detected')) {
        if ($null -eq $case.$field) {
            throw "Missing '$field' at metadata/cases.jsonl:$lineNumber"
        }
    }
    if ($caseIds.Contains($case.case_id)) {
        throw "Duplicate case_id '$($case.case_id)'"
    }
    $caseIds[$case.case_id] = $case

    $kindVal = if ($case.kind) { $case.kind } elseif ($case.log_path -like 'baseline/*') { 'baseline' } else { 'atomic' }
    if ($kindVal -eq 'baseline') { $baselineCount++ } else { $atomicCount++ }
    if ($case.status -and $case.status -ne 'completed') {
        $failedTests += "$($case.case_id) ($($case.technique_id): $($case.status))"
    }

    $relPath = if ($case.artifact_path) { $case.artifact_path } elseif ($case.log_path) { Join-Path 'artifacts' $case.log_path } else { "artifacts/$kindVal/$($case.case_id)" }
    $artifactPath = Join-Path $Root $relPath
    if (-not (Test-Path $artifactPath)) {
        $altPath = if ($case.log_path) { Join-Path $Root $case.log_path } else { $artifactPath }
        if (Test-Path $altPath) {
            $artifactPath = $altPath
        } else {
            throw "Missing artifacts for '$($case.case_id)': $artifactPath"
        }
    }
    $evtxFiles = @(Get-ChildItem $artifactPath -Filter '*.evtx' -File -ErrorAction SilentlyContinue)
    if ($evtxFiles.Count -eq 0) {
        throw "No EVTX files for '$($case.case_id)' in $artifactPath"
    }
    foreach ($expectedEvtx in @('Security.evtx', 'Sysmon.evtx', 'PowerShell.evtx', 'Defender.evtx')) {
        if (-not (Test-Path (Join-Path $artifactPath $expectedEvtx))) {
            $missingFiles += "$($case.case_id)/$expectedEvtx"
        }
    }

    $caseHashCsv = Join-Path $Root "artifacts\hashes\$($case.case_id).csv"
    if (-not (Test-Path $caseHashCsv)) {
        $altHashCsv = Join-Path $Root "hashes\$($case.case_id).csv"
        if (-not (Test-Path $altHashCsv)) {
            throw "Missing SHA256 hash file for '$($case.case_id)': $caseHashCsv"
        }
    }
}

$hashFiles = @(Get-ChildItem (Join-Path $Root 'artifacts\hashes') -Filter '*.csv' -File -ErrorAction SilentlyContinue)
if (-not $hashFiles) {
    throw 'No SHA256 hash files found under artifacts/hashes.'
}

# Build redteam-export/ handoff structure per docs/RED_TEAM_HANDOFF.md Section 7
New-Item -ItemType Directory -Force -Path (Join-Path $ExportDir 'baseline'), (Join-Path $ExportDir 'atomic'), (Join-Path $ExportDir 'metadata'), (Join-Path $ExportDir 'hashes') | Out-Null

foreach ($case in $caseIds.Values) {
    $kindVal = if ($case.kind) { $case.kind } elseif ($case.log_path -like 'baseline/*') { 'baseline' } else { 'atomic' }
    $relPath = if ($case.artifact_path) { $case.artifact_path } else { Join-Path 'artifacts' $case.log_path }
    $srcDir = Join-Path $Root $relPath
    $dstDir = Join-Path $ExportDir "$kindVal\$($case.case_id)"
    New-Item -ItemType Directory -Force -Path $dstDir | Out-Null
    Copy-Item -Path (Join-Path $srcDir '*') -Destination $dstDir -Force -ErrorAction SilentlyContinue
}

Copy-Item -Path (Join-Path $Root 'artifacts\hashes\*.csv') -Destination (Join-Path $ExportDir 'hashes') -Force -ErrorAction SilentlyContinue
Copy-Item -Path $metadataPath -Destination (Join-Path $ExportDir 'metadata\cases.jsonl') -Force

$sigmaPath = Join-Path $Root 'metadata\sigma-results.jsonl'
if (Test-Path $sigmaPath) {
    Copy-Item -Path $sigmaPath -Destination (Join-Path $ExportDir 'metadata\sigma-results.jsonl') -Force
    $sigmaLines = @(Get-Content $sigmaPath -Encoding UTF8 | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    Write-Host "Sigma results file found: $($sigmaLines.Count) case record(s)."
} else {
    Write-Warning "Chua co metadata/sigma-results.jsonl. Hay chay .\scripts\run_sigma_on_evtx.ps1 truoc khi ban giao."
}

if ($envPath -and (Test-Path $envPath)) {
    Copy-Item -Path $envPath -Destination (Join-Path $ExportDir 'metadata\environment.json') -Force
}

$winVer = if ($envData -and $envData.windows) { "$($envData.windows.Caption) ($($envData.windows.Version), Build $($envData.windows.BuildNumber))" } else { [System.Environment]::OSVersion.VersionString }
$sysmonInfo = if ($envData -and $envData.sysmon) { "$($envData.sysmon) (Version: $($envData.sysmon_version))" } else { 'Not installed / Not detected' }
$psVer = if ($envData -and $envData.powershell) { $envData.powershell } else { $PSVersionTable.PSVersion.ToString() }
$tzInfo = if ($envData -and $envData.timezone) { $envData.timezone } else { (Get-TimeZone).Id }
$availChannels = if ($envData -and $envData.channels) {
    (($envData.channels | Where-Object { $_.exists -and $_.enabled } | ForEach-Object { $_.name }) -join ', ')
} else { 'Unknown' }

$readmeLines = @(
    "=== RED TEAM WINDOWS EVTX HANDOFF PACKAGE ===",
    "Generated UTC      : $((Get-Date).ToUniversalTime().ToString('o'))",
    "Host / User        : $env:COMPUTERNAME / $env:USERDOMAIN\$env:USERNAME",
    "Windows Version    : $winVer",
    "Sysmon Version/Cfg : $sysmonInfo",
    "PowerShell Version : $psVer",
    "Timezone           : $tzInfo",
    "Available Channels : $availChannels",
    "Total Cases        : $($caseIds.Count) (Baseline: $baselineCount, Atomic: $atomicCount)",
    "Failed Tests       : $(if ($failedTests.Count -gt 0) { $failedTests -join '; ' } else { 'None' })",
    "Missing EVTX Files : $(if ($missingFiles.Count -gt 0) { $missingFiles -join ', ' } else { 'None' })"
)
$readmeLines | Set-Content -Encoding UTF8 -Path (Join-Path $ExportDir 'README.txt')

if ($baselineCount -lt 3) {
    Write-Warning "Hien co $baselineCount case baseline (yeu cau toi thieu 3 ngay baseline binh thuong, khuyen nghi 7 ngay)."
}

Write-Host "Handoff valid: $($caseIds.Count) cases (baseline: $baselineCount, atomic: $atomicCount), $($hashFiles.Count) hash files."
Write-Host "Export package ready at: $ExportDir (including README.txt, baseline/, atomic/, metadata/, hashes/)"
