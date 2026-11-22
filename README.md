# 🔴 GlobalBan — Red Team Toolkit (`redteam-toolkit`)

> **Bộ công cụ Red Team & Purple Team** mô phỏng tấn công chuẩn MITRE ATT&CK và đánh giá đối chuẩn hệ thống phòng thủ UEBA  
> Đề tài ĐACN 2026 — Phát hiện hành vi bất thường người dùng (UEBA) trên Windows bằng AI Agent

---

## 📌 Tổng quan nhánh này

Nhánh `redteam-toolkit` chứa **toàn bộ công cụ thực chiến phía Red Team** bao gồm 24 kỹ thuật MITRE ATT&CK bao quát 9 Tactics, giao diện đồ họa SOC Console, bộ kiểm chuẩn chữ ký số SHA-256 và cầu nối đánh giá Sigma vs. UEBA.

```
redteam-toolkit/
├── redteam-harness/              # 🔴 BỘ CÔNG CỤ RED TEAM HARNESS & GUI CONSOLE
│   ├── run_campaign.py           # Bộ điều phối 24 kỹ thuật ATT&CK (9 Tactics), xuất EVTX thật & băm SHA-256
│   ├── redteam_gui.py            # Giao diện SOC-style Console (PySide6) — Chạy tuần tự & Nút DỪNG khẩn cấp
│   ├── validate_handoff.py       # Kiểm chuẩn toàn vẹn gói bằng chứng SHA-256 trước khi giao Blue Team
│   ├── simulate_normal_days.py   # Sinh 5 ngày log hành vi văn phòng bình thường (Multi-day Baseline)
│   ├── bridge_evaluate.py        # Cầu nối nạp EVTX thật vào GlobalBan → Báo cáo Precision / Recall / F1
│   ├── package_for_vm.ps1        # Script đóng gói công cụ thành zip để triển khai lên máy ảo nạn nhân
│   ├── deploy_on_vm.bat          # Batch script cài đặt nhanh trên Windows 11 VM
│   └── artifacts/                # 📦 Bằng chứng thực nghiệm (Manifest, CSV SHA-256, Ground-Truth)
│       ├── baseline/             # EVTX & manifest hành vi bình thường
│       ├── atomic/               # EVTX & manifest từng đòn tấn công ATT&CK
│       ├── hashes/               # Chữ ký số SHA-256 từng file chống giả mạo
│       └── metadata/             # red_ground_truth.json & cases.jsonl
├── attack_simulator/             # Trình mô phỏng & phân tích dữ liệu Windows Event Log
├── attack_globalban_studio.py    # Giao diện Studio phân tích nâng cao (Tkinter)
├── bridge_evaluate.py            # Cầu nối đối chuẩn tại thư mục gốc
├── comparison_sigma_vs_ueba.md   # Bảng đối sánh kết quả: Luật Sigma tĩnh vs. UEBA GlobalBan
├── comparison_sigma_vs_ueba.json # Dữ liệu đối sánh JSON định lượng chi tiết
└── src/globalban/                # Các module lõi phục vụ đánh giá hành vi
    ├── ai_agent/                 # AI Agent suy luận và giải thích lệch chuẩn bằng tiếng Việt
    ├── baseline/                 # Per-(User, Host) Behavioral Profiler đa ngày
    ├── detector/                 # UEBA Anomaly Scorer (0–100) theo độ hiếm và chuỗi sự kiện
    ├── evaluation/               # Danh mục đối chứng 14 Sigma Rules
    └── ingestion/                # Trình phân tích cấu trúc Windows Security & Sysmon EVTX
```

---

## ⚔️ Danh mục 24 Kỹ thuật MITRE ATT&CK (Bao quát 9 Tactics)

| STT | Chiến thuật (Tactic) | Kỹ thuật (Technique ID) | Tên bài kiểm thử | Hành vi / Lệnh thực thi thực tế |
|:---:|---|:---:|---|---|
| **01** | **Initial Access / Baseline** | `BASELINE` | Normal Workstation Routine | Tác vụ văn phòng thông thường (`whoami`, `Get-Date`, notepad chuẩn) |
| **02** | **Discovery** | `T1082` | System Information Discovery | Chạy dồn dập `hostname`, `ver`, `systeminfo` trong < 2 giây |
| **03** | **Discovery** | `T1033` | System Owner/User Discovery | `whoami /all`, `net user`, `net localgroup` qua tiến trình ẩn |
| **04** | **Discovery** | `T1016` | System Network Config Discovery | Thu thập cấu hình card mạng & routing: `ipconfig /all`, `route print` |
| **05** | **Discovery** | `T1049` | System Network Connections | Thu thập kết nối mạng & ARP: `netstat -ano`, `arp -a` |
| **06** | **Discovery** | `T1057` | Process Discovery | Liệt kê tiến trình đang chạy: `tasklist /v`, `Get-Process` |
| **07** | **Discovery** | `T1083` | File & Directory Discovery | Quét tìm thư mục và file nhạy cảm: `dir /s /b *.txt` |
| **08** | **Discovery** | `T1087.001` | Local Account Discovery | Dò quét nhóm quản trị viên: `net localgroup administrators` |
| **09** | **Discovery** | `T1046` | Network Service Scanning | Quét cổng mạng (Port Probes: 22, 80, 443, 445, 3389, 5985) tới máy mục tiêu |
| **10** | **Execution** | `T1059.001` | PowerShell Obfuscation | Thực thi lệnh PowerShell mã hóa Base64 (`-EncodedCommand`) |
| **11** | **Execution** | `T1059.003` | Windows Command Shell | Chạy chuỗi lệnh batch/cmd nối chuỗi: `cmd.exe /c "set & cd & ver"` |
| **12** | **Persistence** | `T1053.005` | Scheduled Task | Tạo tác vụ định kỳ bằng `schtasks /create` & tự dọn dẹp |
| **13** | **Persistence** | `T1547.001` | Registry Run Keys Autostart | Cắm chốt khởi động trong Registry: `HKCU\...\Run` & tự dọn dẹp |
| **14** | **Persistence / PrivEsc**| `T1543.003` | Windows Service Creation | Đăng ký dịch vụ hệ thống bằng `sc.exe create` & dọn dẹp |
| **15** | **Defense Evasion** | `T1218.011` | Rundll32 LOLBin Execution | Lợi dụng tiến trình hệ thống hợp lệ: `rundll32.exe user32.dll,MessageBeep` |
| **16** | **Defense Evasion** | `T1105` | Ingress Tool Transfer | Dò quét tiện ích tải tệp nhị phân: `certutil.exe -v -urlcache` |
| **17** | **Defense Evasion** | `T1070.004` | Indicator Removal: File Deletion | Tạo file tạm và xóa dấu vết bằng `cmd.exe /c del /f /q` |
| **18** | **Defense Evasion** | `T1070.001` | Event Log Tampering Recon | Thăm dò can thiệp nhật ký sự kiện Windows: `wevtutil qe Security` |
| **19** | **Credential Access** | `T1110.001` | Brute Force SMB | Thử đăng nhập sai liên tiếp qua SMB IPC$ (`net use`) → Event 4625 |
| **20** | **Credential Access** | `T1110.003` | Password Spraying SMB | Thử 1 mật khẩu chung trên 5 tài khoản tới máy Blue Team → Event 4625 |
| **21** | **Lateral Movement** | `T1021.002` | SMB Admin Shares Recon | Dò quét chia sẻ file từ xa: `net view \\192.168.52.136` & kết nối IPC$ |
| **22** | **Collection** | `T1560.001` | Archive Collected Data | Gom tệp vào thư mục tạm và nén lại bằng `Compress-Archive` |
| **23** | **Command & Control** | `T1071.001` | Application Layer Protocol | Tạo xung nhịp C2 Beaconing định kỳ (HTTP/TCP) về IP mục tiêu |
| **24** | **Context Deviation** | `T1059-LotL` | Living-off-the-Land Off-Hours | Lệnh Windows chuẩn chạy ngoài giờ làm việc (UEBA bắt lệch chuẩn) |

---

## 🖥️ Giao diện Red Team Studio (PySide6)

Khởi động giao diện điều khiển thực chiến:

```powershell
python C:\redteam-harness\redteam_gui.py
```

* **24 Nút kỹ thuật:** Kích hoạt riêng lẻ từng bài kiểm thử với trạng thái trực quan (🔵 Waiting, 🟡 Running, 🟢 Done, 🔴 Failed).
* **Nút `[🚀 CHẠY TOÀN BỘ (24 BÀI)]`:** Tự động điều phối toàn bộ chiến dịch tuần tự với thời gian giãn cách Cooldown tùy chỉnh.
* **Nút `[⏹ DỪNG]`:** Ngắt khẩn cấp ngay lập tức chiến dịch đang chạy, an toàn cho hệ thống lab.
* **Bảng điều khiển tích hợp:** Nút kiểm tra toàn vẹn SHA-256 (`validate_handoff`), nạp đánh giá đối sánh Sigma vs. UEBA (`bridge_evaluate`), và mở nhanh thư mục lưu trữ `artifacts/`.

---

## 🔒 Quy chuẩn an toàn & Pháp chứng số

1. **Safe-guard bắt buộc:** Chỉ cho phép thực thi nhắm vào dải mạng lab VMware NAT `192.168.52.0/24`, yêu cầu cờ xác nhận `--approved`.
2. **Tính toàn vẹn bằng chứng (Forensic Integrity):** Mỗi tệp `.evtx` xuất ra được băm SHA-256 tức thì vào file `.csv`. Bộ kiểm chuẩn `validate_handoff.py` tự động xác thực đối chứng trước khi bàn giao Blue Team.
3. **Dọn dẹp tự động (Auto-Cleanup):** Các tác vụ tạo Scheduled Task, Registry Key, Service hay thư mục nén tạm đều được lập trình dọn dẹp sạch sẽ ngay sau khi sinh bằng chứng telemetry.
