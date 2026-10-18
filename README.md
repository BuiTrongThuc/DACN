# GlobalBan

GlobalBan is a defensive SSH and Windows behavior monitor. It parses failed
login events, reads Windows Event Log channels through PowerShell, correlates
security events into explainable behavior sequences, maintains a small local
baseline, and can optionally request an AI advisory through a privacy-filtering
proxy.

## Requirements

- Python 3.10 or newer
- PyYAML

## Setup

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -e ".[dev]"
Copy-Item .env.example .env
Copy-Item config\config.example.yaml config\config.yaml
```

On Linux/macOS, activate the environment with `source .venv/bin/activate`.

On Windows 11, use `py -m venv .venv` and
`.venv\\Scripts\\Activate.ps1`. The Windows Event Log source uses the built-in
`powershell.exe`; no extra Windows event package is required.

## Configure and run

Edit `config/config.yaml` and set `ingestion.log_path` to the SSH
authentication log (`/var/log/auth.log` or `/var/log/secure` on many Linux
systems). Start in dry-run mode first:

```powershell
globalban --config config/config.yaml --dry-run
```

The monitor only takes action on failed SSH authentication attempts. It
aggregates each source IP over the configured time window and applies the
threshold and allowlist policy. Actual firewall changes are disabled by
default. To enable them, configure a firewall command for your operating
system, set `actions.dry_run: false`, and run with the required privileges.
Review the command and test it on a disposable system before enabling it.

Windows Security Event 4625 XML records are also accepted by the ingestion
parser. When the configured failure threshold is crossed, the optional AI
client receives only the masked network and aggregate counts through the
Ubuntu egress proxy; the raw Windows log is never sent to the API.

Configuration secrets can be supplied through environment variables; see
`.env.example`. The application does not load `.env` automatically, so export
those variables in your shell or use your process manager's secret mechanism.
WhatsApp notifications and the optional AI explanation are disabled unless
configured.

## Windows event monitoring

To read live Windows channels, configure:

```yaml
ingestion:
	source: windows_event_log
	poll_interval_seconds: 5
	log_names:
		- Security
		- System
		- Microsoft-Windows-PowerShell/Operational
		- Microsoft-Windows-Sysmon/Operational
		- Microsoft-Windows-Windows Defender/Operational
```

Run from an elevated PowerShell when the configured channel requires it:

```powershell
globalban --config config/config.yaml --dry-run
```

The adapter uses `Get-WinEvent` and does not enable audit policy, install
Sysmon, or modify Windows. Configure those separately and deliberately. Event
availability depends on Windows edition, provider configuration, audit policy,
Sysmon rules, and Defender settings.

For a safe fixture replay, use `datasets/windows_events.xmll`. It contains
documentation IPs and synthetic events only; it does not execute commands or
perform a real attack. The replay regression test is in
`tests/test_windows_fixture.py`.

## Detection pipeline

The implemented pipeline is:

```text
Windows Event Log or fixture file
	-> normalized WindowsEvent
	-> duplicate filtering and time-window correlation
	-> rule-based sequence score and local frequency baseline
	-> auditable RiskCandidate
	-> optional Gemini advisory through the Ubuntu egress proxy
	-> existing dry-run policy/action path for SSH IP candidates
```

The current sequence detector has explainable rules for login/process,
privilege/process, persistence, audit-log changes, malware alerts, and selected
PowerShell/Sysmon command indicators. The baseline is a warm-up frequency
baseline stored in `globalban-baseline.json`; it is not a trained ML model and
the project does not claim precision, recall, or F1 results without labelled
data.

The AI receives normalized, allowlisted evidence only. It returns severity,
confidence, evidence, hypotheses, optional MITRE ATT&CK references, missing
data, and human-reviewed recommendations. It cannot execute commands, change
firewall policy, or decide to block an address.

## Twelve-tool agent mapping

The project keeps the requested twelve tools as trusted Python contracts rather
than twelve independent services. Their current mapping is:

1. Log ingestion/parser: `ingestion/parser.py`, `ingestion/windows_source.py`
2. Process monitor: `detection/process_monitor.py`
3. Security collector: `ingestion/windows_source.py`
4. Behavioral context: `detection/context.py`
5. Anomaly engine: `detection/aggregator.py`, `detection/baseline.py`, `detection/sequence.py`
6. Threat intelligence: `threat_intel.py`, disabled unless explicitly configured
7. Privacy proxy: `proxy.py`, `privacy/`
8. AI decision engine: `ai/client.py`, `ai/schemas.py`
9. Policy gate: `policy/gate.py`, `policy/guard.py`
10. Action enforcer: `actions/enforcer.py`, dry-run action adapter
11. Audit/rollback: `audit/logger.py`, `audit/rollback.py`
12. Evaluation/reporting: `evaluation/metrics.py`

`agent/tools.py` exposes an allowlisted catalog and rejects unregistered tools;
approval-gated tools cannot run without explicit approval. The catalog is ready
for a provider-specific function-calling loop, but the current AI client remains
advisory and does not let an LLM execute arbitrary functions.

## Atomic-EVTX evaluation data

The external [Atomic-EVTX dataset](https://github.com/arniki/atomic-evtx)
reports 1,064 Windows 10 attack scenarios across initial access, execution,
credential access, privilege escalation, persistence, discovery, defense
evasion, lateral movement, collection, command and control, exfiltration, and
impact. The project keeps only metadata in
`datasets/atomic_evtx_manifest.json`; raw EVTX/JSON is not copied into this
repository because it is large and the source does not expose a clear license.

Download it separately, then load the attack catalog:

```powershell
python -c "from globalban.evaluation.atomic_catalog import load_atomic_catalog; print(len(load_atomic_catalog(r'C:\\path\\full_list_of_attacks_simulated.csv')))"
```

Use the unfiltered logs to test parsing, `atomic_removed` to reduce generator
artifacts, and `atomic_and_tools_removed` to test behavior-based detection
without relying on obvious tool names. Do not claim model accuracy until the
logs are converted to labels and evaluated with the metrics module.

## Ubuntu egress proxy

The repository includes a standalone allowlist proxy for API requests. It
accepts only `POST /v1/chat/completions`, rejects extra fields and unmasked IPs,
then forwards the validated request to the configured upstream API. On Ubuntu:

```bash
python -m pip install -e .
GLOBALBAN_PROXY_BIND=0.0.0.0 \
GLOBALBAN_PROXY_PORT=8080 \
GLOBALBAN_PROXY_UPSTREAM=https://generativelanguage.googleapis.com/v1beta/openai \
globalban-proxy
```

Keep the port restricted with the Ubuntu firewall and set the client API base
URL to `http://192.168.52.131:8080/v1`. The default bind address is
`127.0.0.1`; expose it on the LAN only when the firewall permits trusted
clients. The default upstream is Gemini's OpenAI-compatible endpoint and the
default model in the example is `gemini-2.5-flash`. Set the key only in the
Ubuntu environment, never in YAML or source:

```bash
export GLOBALBAN_AI_API_KEY='YOUR_NEW_GEMINI_KEY'
```

This proxy filters JSON API bodies, but it is not a transparent HTTPS MITM for
arbitrary applications.

## Run tests

```powershell
py -m pytest
```

## Desktop app

On Windows, launch the dashboard from the activated virtual environment:

```powershell
globalban-app
```

The app starts the existing monitor in dry-run mode, streams its high-signal
events, and keeps the backend logic unchanged. It does not grant the AI admin
rights or execute firewall actions from the GUI.

## Project layout

- `src/globalban/ingestion`: SSH log parsing and file tailing
- `src/globalban/detection`: failed-attempt aggregation
- `src/globalban/detection/baseline.py`: local explainable event baseline
- `src/globalban/detection/sequence.py`: Windows sequence correlation and risk candidates
- `src/globalban/detection/process_monitor.py`: process observations and ancestry
- `src/globalban/detection/context.py`: time-window entity context
- `src/globalban/policy`: safe-to-block policy checks
- `src/globalban/policy/gate.py`: approval and rate gates
- `src/globalban/actions`: firewall action adapter
- `src/globalban/actions/enforcer.py`: policy-gated action boundary
- `src/globalban/privacy`: outbound data filtering and IP masking
- `src/globalban/threat_intel.py`: optional threat-intelligence adapter
- `src/globalban/agent/tools.py`: allowlisted twelve-tool registry
- `src/globalban/evaluation/metrics.py`: labeled detection metrics
- `src/globalban/ai`: optional OpenAI-compatible explanation client
- `src/globalban/ingestion/windows_source.py`: PowerShell Windows Event Log adapter
- `src/globalban/audit`: JSON-lines audit log
- `src/globalban/audit/rollback.py`: TTL-backed rollback records
- `src/globalban/notifications`: optional WhatsApp notification
- `datasets/`: small illustrative SSH examples and evaluation records
- `tests/`: unit tests

GlobalBan is a learning and defensive administration project, not a substitute
for a properly managed firewall, intrusion prevention system, or incident
response process. Validate policy and backups before enabling automatic
blocking.
