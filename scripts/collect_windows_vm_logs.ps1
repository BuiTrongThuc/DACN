<#
.SYNOPSIS
    Thu thap Windows Event Log (Security, Sysmon, PowerShell) tu may ao Windows
    ra dinh dang XML chuan cua GlobalBan de xay dung Baseline hoac Test (Atomic Red Team).

.EXAMPLE
    .\scripts\collect_windows_vm_logs.ps1 -OutputPath .\datasets\vm_baseline.xml -HoursBack 168
    .\scripts\collect_windows_vm_logs.ps1 -OutputPath .\datasets\vm_test_atomic.xml -HoursBack 24
#>
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\datasets\windows_vm_export.xml",

    [Parameter(Mandatory = $false)]
    [int]$HoursBack = 168,

    [Parameter(Mandatory = $false)]
    [int]$MaxEventsPerChannel = 5000
)

$ErrorActionPreference = "Stop"
$StartTime = (Get-Date).AddHours(-$HoursBack)

$Channels = @(
    @{
        LogName = "Security"
        Ids     = @(1102, 4624, 4625, 4634, 4647, 4648, 4663, 4672, 4688, 4698, 4702, 4704, 4719, 4720, 4728, 4732, 4756, 5156)
    },
    @{
        LogName = "System"
        Ids     = @(7045)
    },
    @{
        LogName = "Microsoft-Windows-Sysmon/Operational"
        Ids     = @(1, 3, 11, 12, 13, 14)
    },
    @{
        LogName = "Microsoft-Windows-PowerShell/Operational"
        Ids     = @(4103, 4104)
    }
)

$XmlFragments = New-Object System.Collections.Generic.List[string]

foreach ($Channel in $Channels) {
    $LogName = $Channel.LogName
    $Ids = $Channel.Ids
    try {
        $Events = Get-WinEvent -FilterHashtable @{
            LogName   = $LogName
            Id        = $Ids
            StartTime = $StartTime
        } -MaxEvents $MaxEventsPerChannel -ErrorAction Stop | Sort-Object TimeCreated

        foreach ($Evt in $Events) {
            $XmlFragments.Add($Evt.ToXml())
        }
        Write-Host "[OK] Collected $($Events.Count) events from $LogName"
    }
    catch {
        Write-Warning "Skipped or no matching events in channel '$LogName': $($_.Exception.Message)"
    }
}

$OutDir = Split-Path -Parent $OutputPath
if ($OutDir -and -not (Test-Path $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
}

$Content = "<Events>`n" + ($XmlFragments -join "`n") + "`n</Events>`n"
[System.IO.File]::WriteAllText($OutputPath, $Content, [System.Text.Encoding]::UTF8)
Write-Host "[DONE] Wrote $($XmlFragments.Count) total Windows events to $OutputPath"

