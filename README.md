# GlobalBan

GlobalBan is a small defensive SSH log monitor. It parses failed-login events,
groups attempts by source IP, checks local policy, and can optionally block
offenders and send WhatsApp alerts.

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

Configuration secrets can be supplied through environment variables; see
`.env.example`. The application does not load `.env` automatically, so export
those variables in your shell or use your process manager's secret mechanism.
WhatsApp notifications and the optional AI explanation are disabled unless
configured.

## Run tests

```powershell
py -m pytest
```

## Project layout

- `src/globalban/ingestion`: SSH log parsing and file tailing
- `src/globalban/detection`: failed-attempt aggregation
- `src/globalban/policy`: safe-to-block policy checks
- `src/globalban/actions`: firewall action adapter
- `src/globalban/privacy`: outbound data filtering and IP masking
- `src/globalban/ai`: optional OpenAI-compatible explanation client
- `src/globalban/audit`: JSON-lines audit log
- `src/globalban/notifications`: optional WhatsApp notification
- `datasets/`: small illustrative SSH examples and evaluation records
- `tests/`: unit tests

GlobalBan is a learning and defensive administration project, not a substitute
for a properly managed firewall, intrusion prevention system, or incident
response process. Validate policy and backups before enabling automatic
blocking.
