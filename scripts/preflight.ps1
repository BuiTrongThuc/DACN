[CmdletBinding()]
param(
    [string]$OutputPath = '',
    [string]$SnapshotNote = ''
)

$ErrorActionPreference = 'Stop'
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
if (-not $OutputPath) {
    $OutputPath = Join-Path $scriptDir '..\metadata\environment.json'
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

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

$sysmonService = $null
$sysmonVersion = $null
try {
    $svc = Get-CimInstance Win32_Service -Filter "Name='Sysmon' OR Name='Sysmon64'" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($svc) {
        $sysmonService = $svc.PathName
        $exePath = ($svc.PathName -replace '^"([^"]+)".*$', '$1').Trim()
        if (Test-Path $exePath) {
            $sysmonVersion = (Get-Item $exePath).VersionInfo.FileVersion
        }
    }
} catch {
    $sysmonService = $null
}

$osInfo = Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber

$environment = [ordered]@{
    collected_utc = (Get-Date).ToUniversalTime().ToString('o')
    snapshot_verified = if ($SnapshotNote) { $SnapshotNote } else { 'Verify VM snapshot created prior to testing' }
    host = $env:COMPUTERNAME
    user = "$env:USERDOMAIN\$env:USERNAME"
    is_elevated_admin = $isElevated
    windows = $osInfo
    powershell = $PSVersionTable.PSVersion.ToString()
    sysmon = $sysmonService
    sysmon_version = $sysmonVersion
    timezone = (Get-TimeZone).Id
    channels = @($channelStatus)
}

$parent = Split-Path $OutputPath -Parent
New-Item -ItemType Directory -Force -Path $parent | Out-Null
$environment | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 $OutputPath
$environment | ConvertTo-Json -Depth 5
Write-Host "Preflight report saved to: $OutputPath"

$unavailable = @($channelStatus | Where-Object { -not $_.exists -or -not $_.enabled })
if (-not $isElevated) {
    Write-Warning "PowerShell dang chay KHONG co quyen Administrator. Kenh 'Security' can Run as Administrator de kiem tra va xuat EVTX."
}
if (-not $sysmonService) {
    Write-Warning "Sysmon chua duoc cai dat (Microsoft-Windows-Sysmon/Operational khong kha dung). Hay cai Sysmon (sysmon64.exe -accepteula -i) truoc khi thu baseline."
}
if ($unavailable.Count -gt 0) {
    Write-Warning ("Cac kenh chua san sang (" + $unavailable.Count + "/4): " + (($unavailable | ForEach-Object { $_.name }) -join ', '))
} else {
    Write-Host "Tat ca 4 kenh (Security, Sysmon, PowerShell, Defender) deu KHA DUNG va ENABLED."
}
