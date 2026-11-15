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

    [string]$OutputRoot = ''
)

$ErrorActionPreference = 'Stop'
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
$projectRoot = Split-Path -Parent $scriptDir
if (-not $OutputRoot) {
    $OutputRoot = Join-Path $projectRoot 'artifacts'
}

if (-not $Approved) {
    throw 'Pass -Approved only after the supervisor has approved this exact test.'
}

if (-not (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue)) {
    $localModule = Join-Path $scriptDir 'Invoke-AtomicRedTeam.psm1'
    if (Test-Path $localModule) {
        Import-Module $localModule -Force
    } else {
        throw 'Invoke-AtomicTest is not available. Install and import Invoke-AtomicRedTeam first.'
    }
}

$caseRoot = Join-Path $OutputRoot (Join-Path 'atomic' $CaseId)
$rootAtomicDir = Join-Path $projectRoot (Join-Path 'atomic' $CaseId)
New-Item -ItemType Directory -Force -Path $caseRoot, $rootAtomicDir | Out-Null

$startUtc = (Get-Date).AddSeconds(-1).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
$status = 'failed'
$errorMessage = $null
$testName = if (Get-Command Get-AtomicTechniqueInfo -ErrorAction SilentlyContinue) {
    Get-AtomicTechniqueInfo -TechniqueId $TechniqueId
} else {
    "Atomic $TechniqueId Test $($TestNumbers -join ',')"
}

try {
    & Invoke-AtomicTest $TechniqueId -TestNumbers $TestNumbers
    if ($LASTEXITCODE -eq 0 -or $null -eq $LASTEXITCODE) {
        $status = 'completed'
    }
} catch {
    $errorMessage = $_.Exception.Message
}
Start-Sleep -Milliseconds 600
$endUtc = (Get-Date).AddSeconds(1).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')

$collector = Join-Path $scriptDir 'collect_windows_logs.ps1'
& $collector `
    -CaseId $CaseId `
    -Kind atomic `
    -OutputRoot $OutputRoot `
    -TechniqueId $TechniqueId `
    -TestName $testName `
    -StartUtc $startUtc `
    -EndUtc $endUtc `
    -Status $status

$run = [ordered]@{
    case_id = $CaseId
    technique_id = $TechniqueId
    test_numbers = @($TestNumbers)
    test_name = $testName
    status = $status
    start_utc = $startUtc
    end_utc = $endUtc
    host = $env:COMPUTERNAME
    username = "$env:USERDOMAIN\$env:USERNAME"
    approved = [bool]$Approved
    error = $errorMessage
}
$runJson = $run | ConvertTo-Json -Depth 4
$runJson | Set-Content -Encoding UTF8 (Join-Path $caseRoot 'atomic-run.json')
$runJson | Set-Content -Encoding UTF8 (Join-Path $rootAtomicDir 'atomic-run.json')

if ($errorMessage) {
    Write-Warning "Atomic test failed: $errorMessage"
}
Write-Host "Atomic case recorded: $CaseId ($status)"
