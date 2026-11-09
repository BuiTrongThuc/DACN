# Red Team Windows Collector

This repository is for authorized collection on an isolated Windows VM. It is separate from the detection project so the Red Team can clone it on the test machine.

## Clone and open in VS Code

```powershell
git clone <GITHUB_URL>
cd redteam-windows-collector
code .
```

Open a PowerShell terminal in VS Code. Run only tests approved by the project supervisor. Do not run this repository on production systems.

## Red Team workflow

Run the environment check before collecting data:

```powershell
.\scripts\preflight.ps1
```

Collect baseline snapshots for several normal days. Before each approved
Atomic Red Team test, use a unique case ID and record the technique and test
number. The wrapper requires an explicit approval flag, records UTC times, and
collects the EVTX files after the test:

```powershell
.\scripts\run_approved_atomic.ps1 `
	-CaseId atomic-T1059-001-test-01 `
	-TechniqueId T1059.001 `
	-TestNumbers 1 `
	-Approved
```

Only use the exact technique and test number approved by the supervisor.

## Collect Windows logs

Open PowerShell with the permissions required by the event channels:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\collect_windows_logs.ps1 -CaseId baseline-day-01 -Kind baseline
```

After an approved Atomic Red Team test:

```powershell
.\scripts\collect_windows_logs.ps1 -CaseId atomic-T1059-001-test-01 -Kind atomic
```

The script exports EVTX files and SHA256 hashes under `artifacts/`. It does not execute an attack and does not change Windows audit policy.

## Record cases

Copy `metadata/cases.example.jsonl` to `metadata/cases.jsonl` and replace the example values with real values. Copy `metadata/sigma-results.example.jsonl` to `metadata/sigma-results.jsonl` and record Sigma results for the same case IDs. Record one line per baseline or Atomic Red Team case. Do not record passwords, tokens, private keys, or full command secrets.

After all cases and hashes are present, validate the handoff:

```powershell
.\scripts\validate_handoff.ps1
```

Send the other team:

- `artifacts/baseline/<case-id>/*.evtx`
- `artifacts/atomic/<case-id>/*.evtx`
- `artifacts/hashes/*.csv`
- `metadata/cases.jsonl`
- Windows, Sysmon and PowerShell versions
- The approved Atomic test ID and its start/end times
- Sigma results using the same case IDs

EVTX and real metadata are ignored by Git. Transfer them separately through the agreed secure channel; do not commit them to GitHub.
