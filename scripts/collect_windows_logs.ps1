[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$CaseId,

    [ValidateSet('baseline', 'atomic')]
    [string]$Kind = 'atomic',

    [string]$OutputRoot = '',

    [string]$MetadataPath = '',

    [string]$TechniqueId = $null,

    [string]$TestName = $null,

    [string]$StartUtc = $null,

    [string]$EndUtc = $null,

    [string]$Status = 'completed'
)

$ErrorActionPreference = 'Stop'
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
$projectRoot = Split-Path -Parent $scriptDir
if (-not $OutputRoot) {
    $OutputRoot = Join-Path $projectRoot 'artifacts'
}
if (-not $MetadataPath) {
    $MetadataPath = Join-Path $projectRoot 'metadata\cases.jsonl'
}

$destination = Join-Path $OutputRoot (Join-Path $Kind $CaseId)
$rootKindDest = Join-Path $projectRoot (Join-Path $Kind $CaseId)
New-Item -ItemType Directory -Force -Path $destination, $rootKindDest | Out-Null

if ($Kind -eq 'baseline' -and (-not $StartUtc)) {
    $StartUtc = (Get-Date).AddSeconds(-1).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $benignCmd = "`$OutputEncoding = [System.Text.UTF8Encoding]::new(`$false); [Console]::OutputEncoding = `$OutputEncoding; Get-Date | Out-Null; Get-Service | Select-Object -First 5 | Out-Null; Get-Process | Select-Object -First 5 | Out-Null; Write-Output 'Normal workstation activity for $CaseId'"
    & powershell.exe -NoProfile -NonInteractive -Command $benignCmd | Out-Null
    Start-Sleep -Milliseconds 600
    $EndUtc = (Get-Date).AddSeconds(1).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
}

$collectionStartUtc = if ($StartUtc) { $StartUtc } else { (Get-Date).AddMinutes(-5).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ') }
$collectionEndUtc = if ($EndUtc) { $EndUtc } else { (Get-Date).AddSeconds(2).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ') }

$qStart = ([datetime]::Parse($collectionStartUtc)).ToUniversalTime().AddSeconds(-1).ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
$qEnd = ([datetime]::Parse($collectionEndUtc)).ToUniversalTime().AddSeconds(1).ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
$xpathQuery = "/q:*[System[TimeCreated[@SystemTime>='$qStart' and @SystemTime<='$qEnd']]]"

$channels = @(
    @{ Name = 'Security'; File = 'Security.evtx' },
    @{ Name = 'Microsoft-Windows-Sysmon/Operational'; File = 'Sysmon.evtx' },
    @{ Name = 'Microsoft-Windows-PowerShell/Operational'; File = 'PowerShell.evtx' },
    @{ Name = 'Microsoft-Windows-Windows Defender/Operational'; File = 'Defender.evtx' }
)

$exported = @()
$failed = @()
foreach ($channel in $channels) {
    $path = Join-Path $destination $channel.File
    try {
        if (Test-Path $path) {
            Remove-Item -Path $path -Force -ErrorAction SilentlyContinue
        }
        & wevtutil.exe epl $channel.Name $path $xpathQuery 2>$null
        if ($LASTEXITCODE -eq 0 -and (Test-Path $path)) {
            $exported += $channel.Name
            Copy-Item -Path $path -Destination (Join-Path $rootKindDest $channel.File) -Force
        } else {
            $failed += $channel.Name
        }
    } catch {
        $failed += $channel.Name
    }
}

$hashPath = Join-Path $OutputRoot (Join-Path 'hashes' "$CaseId.csv")
$rootHashDir = Join-Path $projectRoot 'hashes'
New-Item -ItemType Directory -Force -Path (Split-Path $hashPath -Parent), $rootHashDir | Out-Null

$evtxFiles = @(Get-ChildItem -Path $destination -Filter '*.evtx' -File -ErrorAction SilentlyContinue)
if ($evtxFiles.Count -gt 0) {
    $evtxFiles |
        Get-FileHash -Algorithm SHA256 |
        Export-Csv -NoTypeInformation -Encoding UTF8 -Path $hashPath
    Copy-Item -Path $hashPath -Destination (Join-Path $rootHashDir "$CaseId.csv") -Force
}

$manifest = [ordered]@{
    case_id = $CaseId
    kind = $Kind
    status = $Status
    host = $env:COMPUTERNAME
    username = "$env:USERDOMAIN\$env:USERNAME"
    start_utc = $collectionStartUtc
    end_utc = $collectionEndUtc
    exported_channels = $exported
    failed_channels = $failed
    hash_csv = "hashes/$CaseId.csv"
}
$manifestJson = $manifest | ConvertTo-Json -Depth 3
$manifestJson | Set-Content -Encoding UTF8 (Join-Path $destination 'collection-manifest.json')
$manifestJson | Set-Content -Encoding UTF8 (Join-Path $rootKindDest 'collection-manifest.json')

# Update or append case entry in metadata/cases.jsonl
$metaDir = Split-Path $MetadataPath -Parent
New-Item -ItemType Directory -Force -Path $metaDir | Out-Null

$expectedDetected = ($Kind -eq 'atomic' -and $Status -eq 'completed')
$caseEntry = [ordered]@{
    case_id = $CaseId
    expected_detected = [bool]$expectedDetected
    technique_id = if ($TechniqueId) { $TechniqueId } else { $null }
    test_name = if ($TestName) { $TestName } else { $null }
    host = $env:COMPUTERNAME
    username = "$env:USERDOMAIN\$env:USERNAME"
    start_utc = $collectionStartUtc
    end_utc = $collectionEndUtc
    kind = $Kind
    status = $Status
    log_path = "$Kind/$CaseId"
    artifact_path = "artifacts/$Kind/$CaseId"
}
$caseJsonLine = $caseEntry | ConvertTo-Json -Compress

$existingLines = @()
$updated = $false
if (Test-Path $MetadataPath) {
    foreach ($line in Get-Content $MetadataPath -Encoding UTF8) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try {
            $parsed = $line | ConvertFrom-Json
            if ($parsed.case_id -eq $CaseId) {
                $existingLines += $caseJsonLine
                $updated = $true
            } else {
                $existingLines += $line
            }
        } catch {
            $existingLines += $line
        }
    }
}
if (-not $updated) {
    $existingLines += $caseJsonLine
}
$existingLines | Set-Content -Encoding UTF8 -Path $MetadataPath

Write-Host "Collected case: $CaseId ($Kind)"
Write-Host "Output EVTX   : $destination ($($exported.Count)/4 channels exported)"
Write-Host "SHA256 Hashes : $hashPath"
Write-Host "Metadata JSONL: $MetadataPath"
if ($failed.Count -gt 0) {
    Write-Warning ("Unavailable channels: " + ($failed -join ', '))
}
