[CmdletBinding()]
param(
    [string]$Root = (Join-Path $PSScriptRoot '..')
)

$ErrorActionPreference = 'Stop'
$metadataPath = Join-Path $Root 'metadata\cases.jsonl'
if (-not (Test-Path $metadataPath)) {
    throw "Missing metadata/cases.jsonl. Copy the example and fill real values."
}

$caseIds = @{}
$lineNumber = 0
foreach ($line in Get-Content $metadataPath) {
    $lineNumber++
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    try {
        $case = $line | ConvertFrom-Json
    } catch {
        throw "Invalid JSON at metadata/cases.jsonl:$lineNumber"
    }
    foreach ($field in @('case_id', 'expected_detected', 'kind', 'artifact_path')) {
        if ($null -eq $case.$field) {
            throw "Missing '$field' at metadata/cases.jsonl:$lineNumber"
        }
    }
    if ($caseIds.ContainsKey($case.case_id)) {
        throw "Duplicate case_id '$($case.case_id)'"
    }
    $caseIds[$case.case_id] = $case
    $artifactPath = Join-Path $Root $case.artifact_path
    if (-not (Test-Path $artifactPath)) {
        throw "Missing artifacts for '$($case.case_id)': $artifactPath"
    }
    if (-not (Get-ChildItem $artifactPath -Filter '*.evtx' -File)) {
        throw "No EVTX files for '$($case.case_id)'"
    }
}

$hashFiles = Get-ChildItem (Join-Path $Root 'artifacts\hashes') -Filter '*.csv' -File -ErrorAction SilentlyContinue
if (-not $hashFiles) {
    throw 'No SHA256 hash files found under artifacts/hashes.'
}

Write-Host "Handoff valid: $($caseIds.Count) cases, $($hashFiles.Count) hash files."
