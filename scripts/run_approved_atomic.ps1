[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$CaseId,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^T[0-9]{4}(\.[0-9]{3})?$')]
    [string]$TechniqueId,

    [int[]]$TestNumbers = @(1),

    [Parameter(Mandatory = $true)]
    [switch]$Approved,

    [string]$OutputRoot = (Join-Path $PSScriptRoot '..\artifacts')
)

$ErrorActionPreference = 'Stop'
if (-not $Approved) {
    throw 'Pass -Approved only after the supervisor has approved this exact test.'
}

if (-not (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue)) {
    throw 'Invoke-AtomicTest is not available. Install and import Invoke-AtomicRedTeam first.'
}

$caseRoot = Join-Path $OutputRoot (Join-Path 'atomic' $CaseId)
New-Item -ItemType Directory -Force -Path $caseRoot | Out-Null
$startUtc = (Get-Date).ToUniversalTime().ToString('o')
$status = 'failed'
$errorMessage = $null
try {
    & Invoke-AtomicTest $TechniqueId -TestNumbers $TestNumbers
    if ($LASTEXITCODE -eq 0) {
        $status = 'completed'
    }
} catch {
    $errorMessage = $_.Exception.Message
}
$endUtc = (Get-Date).ToUniversalTime().ToString('o')

$collector = Join-Path $PSScriptRoot 'collect_windows_logs.ps1'
& $collector -CaseId $CaseId -Kind atomic -OutputRoot $OutputRoot

$run = [ordered]@{
    case_id = $CaseId
    technique_id = $TechniqueId
    test_numbers = @($TestNumbers)
    status = $status
    start_utc = $startUtc
    end_utc = $endUtc
    host = $env:COMPUTERNAME
    username = "$env:USERDOMAIN\\$env:USERNAME"
    approved = [bool]$Approved
    error = $errorMessage
}
$run | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 (Join-Path $caseRoot 'atomic-run.json')
if ($errorMessage) {
    Write-Warning "Atomic test failed: $errorMessage"
}
Write-Host "Atomic case recorded: $CaseId ($status)"
