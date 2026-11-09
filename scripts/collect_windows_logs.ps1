[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$CaseId,

    [ValidateSet('baseline', 'atomic')]
    [string]$Kind = 'atomic',

    [string]$OutputRoot = (Join-Path $PSScriptRoot '..\artifacts')
)

$ErrorActionPreference = 'Stop'
$destination = Join-Path $OutputRoot (Join-Path $Kind $CaseId)
New-Item -ItemType Directory -Force -Path $destination | Out-Null
$startUtc = (Get-Date).ToUniversalTime().ToString('o')

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
        & wevtutil.exe epl $channel.Name $path
        if ($LASTEXITCODE -eq 0) {
            $exported += $channel.Name
        } else {
            $failed += $channel.Name
        }
    } catch {
        $failed += $channel.Name
    }
}

$hashPath = Join-Path $OutputRoot (Join-Path 'hashes' "$CaseId.csv")
New-Item -ItemType Directory -Force -Path (Split-Path $hashPath) | Out-Null
Get-ChildItem -Path $destination -Filter '*.evtx' |
    Get-FileHash -Algorithm SHA256 |
    Export-Csv -NoTypeInformation -Path $hashPath

$manifest = [ordered]@{
    case_id = $CaseId
    kind = $Kind
    host = $env:COMPUTERNAME
    username = "$env:USERDOMAIN\\$env:USERNAME"
    start_utc = $startUtc
    end_utc = (Get-Date).ToUniversalTime().ToString('o')
    exported_channels = $exported
    failed_channels = $failed
}
$manifest | ConvertTo-Json -Depth 3 | Set-Content -Encoding UTF8 (Join-Path $destination 'collection-manifest.json')

Write-Host "Collected case: $CaseId"
Write-Host "Output: $destination"
if ($failed.Count -gt 0) {
    Write-Warning ("Unavailable channels: " + ($failed -join ', '))
}
