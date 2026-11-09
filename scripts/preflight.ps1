[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $PSScriptRoot '..\metadata\environment.json')
)

$ErrorActionPreference = 'Stop'
$channels = @(
    'Security',
    'Microsoft-Windows-Sysmon/Operational',
    'Microsoft-Windows-PowerShell/Operational',
    'Microsoft-Windows-Windows Defender/Operational'
)

$channelStatus = foreach ($channel in $channels) {
    try {
        $log = Get-WinEvent -ListLog $channel -ErrorAction Stop
        [ordered]@{
            name = $channel
            exists = $true
            enabled = [bool]$log.IsEnabled
            record_count = [int64]$log.RecordCount
            maximum_size_bytes = [int64]$log.MaximumSizeInBytes
        }
    } catch {
        [ordered]@{
            name = $channel
            exists = $false
            enabled = $false
            record_count = 0
            maximum_size_bytes = 0
            error = $_.Exception.Message
        }
    }
}

$sysmonPath = $null
try {
    $sysmonPath = (Get-CimInstance Win32_Service -Filter "Name='Sysmon'" -ErrorAction Stop).PathName
} catch {
    $sysmonPath = $null
}

$environment = [ordered]@{
    collected_utc = (Get-Date).ToUniversalTime().ToString('o')
    host = $env:COMPUTERNAME
    user = "$env:USERDOMAIN\\$env:USERNAME"
    windows = (Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber)
    powershell = $PSVersionTable.PSVersion.ToString()
    sysmon = $sysmonPath
    channels = @($channelStatus)
}

$parent = Split-Path $OutputPath -Parent
New-Item -ItemType Directory -Force -Path $parent | Out-Null
$environment | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 $OutputPath
$environment | ConvertTo-Json -Depth 5
Write-Host "Preflight report: $OutputPath"
