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
`.env.example`. The application loads `.env` from the current directory or
repository root when variables are not already set, or you can use your
process manager's secret mechanism. WhatsApp notifications and the optional AI
explanation are disabled unless configured.

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

Windows authentication events also use a persistent 24-hour behavior detector.
It covers fast brute force, slow-and-low attempts, periodic automation, password
spraying, nonexistent-user enumeration, distributed attacks against one user,
and successful login after repeated failures. Results are emitted as the same
explainable risk candidates used by the existing policy and audit pipeline.
The state file is configured by `detection.behavior_state_path`. The detector
does not bypass the allowlist, dry-run mode, approval gate, or firewall action
adapter. Windows risk actions are recorded as approval-required until a
trusted operator explicitly approves them.

The AI receives normalized, allowlisted evidence only. It is called directly
using the configured external `ai.base_url`; the application does not require
or silently substitute a localhost API gateway. It returns severity,
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

## Báo cáo công việc tuần (02/11/2026 - 07/11/2026)

### Đã thực hiện

- Bổ sung giám sát Windows Event Log qua PowerShell cho các kênh Security,
  System, PowerShell, Sysmon và Windows Defender.
- Chuẩn hóa và tương quan sự kiện Windows thành các chuỗi hành vi có thể giải
  thích, kết hợp rule-based scoring với local frequency baseline.
- Bổ sung phát hiện brute force nhanh, slow-and-low, password spraying, dò user
  không tồn tại, tấn công phân tán và đăng nhập thành công sau nhiều lần thất
  bại.
- Hoàn thiện policy gate, approval gate, dry-run, audit và rollback. Hành động
  rủi ro trên Windows mặc định yêu cầu operator phê duyệt.
- Bổ sung giao diện desktop để chạy monitor ở chế độ dry-run và theo dõi sự
  kiện chính.
- Hoàn thiện AI advisory: AI chỉ nhận bằng chứng đã chuẩn hóa và allowlist,
  trả về severity, confidence, evidence, hypothesis, ATT&CK reference và
  khuyến nghị; AI không tự thực thi lệnh hoặc thay đổi firewall.
- Bổ sung egress proxy cho API AI, kiểm tra request, che IP và chặn dữ liệu
  Windows vượt giới hạn trước khi forward.
- Tích hợp AD-GEN và WinLOLBIN-GT làm nguồn dữ liệu tham khảo cục bộ cho AI
  advisory. Hệ thống tìm các mẫu tương đồng trong hai nguồn này, đưa cùng log
  đã chuẩn hóa vào AI để nhận định tình huống, bổ sung narrative/nhãn/ngữ cảnh
  MITRE ATT&CK và đề xuất hướng xử lý.
- Bổ sung tooling phục vụ chuẩn bị dữ liệu WinLOLBIN-GT và red-team simulator
  cho các kịch
  bản brute force, password spray, PowerShell, persistence, audit clearing và
  kiểm soát false positive.
- Cập nhật cấu hình, tài liệu, `.gitignore` và các bài test liên quan đến
  config, proxy, rollback và sequence detection.

### Kết quả hiện tại

- Commit chính trong tuần là `93e6d56` ngày 04/11/2026:
  `Add Windows monitoring, AI controls, and dataset tooling`.
- Pipeline hiện tại: Windows Event Log hoặc fixture -> chuẩn hóa event -> lọc
  trùng và tương quan theo cửa sổ thời gian -> sequence score/baseline ->
  `RiskCandidate` -> AI advisory tùy chọn -> policy/action path hiện có.
- Có fixture Windows tổng hợp để replay an toàn; fixture không thực thi lệnh và
  không mô phỏng tấn công thật.
- AI advisory hiện có thể tham chiếu hai nguồn dữ liệu cục bộ là AD-GEN và
  WinLOLBIN-GT. AD-GEN cung cấp narrative theo process từ Sysmon, còn
  WinLOLBIN-GT cung cấp các mẫu hành vi LOLBin đã xử lý. Hai nguồn này chỉ
  đóng vai trò dữ liệu tham khảo để AI phân tích log và nhận diện tình huống;
  chúng không thay thế evidence từ event đang phân tích. Khuyến nghị của AI
  vẫn phải đi qua policy gate, approval gate và action path hiện có.
- Bộ test dùng `pytest` và có thể chạy bằng `py -m pytest` trong Python 3.10+.

### Khó khăn và phần đang vướng

- Chưa có dữ liệu EVTX/JSON đã gắn nhãn đầy đủ để đánh giá định lượng
  precision, recall hoặc F1; hiện mới có metadata Atomic-EVTX và dữ liệu hỗ trợ
  kiểm thử.
- Baseline hiện là local frequency baseline trong giai đoạn warm-up, chưa phải
  mô hình machine learning đã huấn luyện.
- Việc đọc event thực tế phụ thuộc Windows edition, provider, audit policy,
  Sysmon rules và Defender settings; một số channel cần PowerShell nâng cao.
- Bộ WinLOLBIN-GT dung lượng lớn đang có các CSV lớn và file tạm chưa được Git
  theo dõi; cần quyết định commit trực tiếp, dùng Git LFS hay lưu ngoài
  repository.
- AD-GEN có dữ liệu LAB/REAL lớn và phụ thuộc nguồn COMISET; cần thống nhất
  phạm vi dữ liệu được phép lưu trong repository và cách quản lý license trước
  khi dùng làm benchmark hoặc phân phối lại.
- Thư mục `docs/` chưa có tài liệu vận hành riêng; hướng dẫn chính hiện nằm
  trong README.
- AI hiện chỉ ở vai trò advisory và catalog tool đã allowlist, chưa có vòng
  function-calling để AI tự gọi tool. Đây là giới hạn có chủ ý nhằm giữ
  approval gate và không cho AI tự thay đổi hệ thống.

### Hướng xử lý tiếp theo

- Chạy đầy đủ test regression và bổ sung test cho các kịch bản Windows/red-team
  còn thiếu.
- Chuyển dữ liệu đánh giá sang dạng có label, xây dựng protocol đánh giá và
  báo cáo metric có thể tái lập.
- Xác định cách quản lý dataset lớn: loại bỏ file tạm, dùng Git LFS hoặc lưu
  dataset ở kho riêng.
- Xác định chính sách lưu trữ và license cho AD-GEN, sau đó bổ sung protocol
  đánh giá narrative/ATT&CK alignment nếu dùng AD-GEN làm dữ liệu benchmark.
- Bổ sung tài liệu vận hành trong `docs/`, nhất là cách bật Windows
  audit/Sysmon/Defender và cách chạy fixture replay.
- Kiểm thử end-to-end trên máy Windows có event channel thực tế, đồng thời giữ
  mặc định dry-run và approval-required.

### Tài liệu và tham chiếu

- Hướng dẫn dự án: `README.md`
- Cấu hình mẫu: `config/config.example.yaml`
- Dữ liệu tham khảo AD-GEN: `AD-GEN/README.md`
- Dữ liệu tham khảo WinLOLBIN-GT: `datasets/WinLOLBIN-GT-dataset/README.md`
- Fixture Windows: `datasets/windows_events.xmll`
- Test fixture: `tests/test_windows_fixture.py`
- Commit công việc tuần: `93e6d56`
