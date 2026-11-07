# GlobalBan operations

## Safe defaults

Keep `actions.dry_run: true` and require explicit approval for every live
action. `--dry-run` is an additional command-line override. The AI advisory
can recommend a response, but it cannot execute an unregistered command or
bypass `PolicyGuard`, `PolicyGate`, the allowlist, or the firewall adapter.

## Windows event collection

Run PowerShell as Administrator only when the selected channel requires it.
GlobalBan reads events; it does not change audit policy, install Sysmon, or
change Defender settings.

1. Enable the required audit subcategories in a disposable Windows VM using
   the organization's approved policy management process.
2. Install and configure Sysmon using a reviewed ruleset. Confirm that
   `Microsoft-Windows-Sysmon/Operational` contains events before replaying data.
3. Confirm Defender Operational logging is enabled and that the configured
   channel exists:

   ```powershell
   Get-WinEvent -ListLog Security,System,Microsoft-Windows-PowerShell/Operational
   ```

4. Set `ingestion.source: windows_event_log` and keep a small
   `poll_interval_seconds` such as `5`.
5. Start with:

   ```powershell
   globalban --config config/config.yaml --dry-run
   ```

Channel names and event availability vary by Windows edition, provider,
configured audit policy, Sysmon rules, and Defender settings. Treat missing
channels as an environment issue, not as evidence that no threat exists.

## Fixture replay

The checked-in fixture is synthetic and safe:

```powershell
py -m pytest tests/test_windows_fixture.py
globalban-evaluate --labels datasets/windows_eval_labels.jsonl `
  --output evaluation-report.json
```

The evaluation report contains the exact labels, predictions, confusion
matrix, precision, recall, F1, and false-positive rate. Do not report these
sample metrics as production performance; replace the sample cases with
independently reviewed labels before making a claim.
The accompanying `datasets/windows_eval_metadata.json` records the schema
version, source, filter, label policy, and production-representative status.

## Dataset handling

AD-GEN and WinLOLBIN-GT are local reference sources, not automatic ground
truth. Keep only the small checked-in samples and metadata in Git. Store
complete downloads outside the repository or in an approved artifact store;
use Git LFS only after repository owners approve storage and licensing.

- Never commit real logs, credentials, or unmasked host/network identifiers.
- Preserve the upstream license and citation beside any redistributed sample.
- Record dataset version, acquisition date, filter, and label policy in the
  evaluation report.
- Remove temporary conversions and generated CSVs before publishing a branch.

## Approval and rollback

Live operation requires a reviewed firewall template, appropriate Windows or
Linux privileges, and an operator approval. Use the configured rollback command
only after checking the audit record and confirming that the address should be
released. Keep audit JSONL append-only and protect it from untrusted users.

## Agent runtime

`AgentRuntime` uses a plan-first flow. It selects only names from the trusted
allowlist, does not execute by default, and reports an explicit failure when a
handler has not been wired. Enabling execution does not bypass approval for
tools marked as approval-required. Automatic source changes and Git commits are
not enabled; they require a reviewed sandbox and an explicit future policy.
When an `AuditLogger` is supplied, the runtime records `agent.plan` and
`agent.tool_call` entries, including approval state and tool result.
