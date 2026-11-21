# 🔴 GlobalBan — Red Team Toolkit (`redteam-toolkit`)

> **Bộ công cụ Purple Team** mô phỏng tấn công chuẩn MITRE ATT&CK và đánh giá hiệu quả hệ thống phòng thủ UEBA  
> Đề tài ĐACN 2026 — Phát hiện hành vi bất thường người dùng (UEBA) trên Windows bằng AI Agent

---

## 📌 Tổng quan nhánh này

Nhánh `redteam-toolkit` chứa **toàn bộ công cụ phía Red Team** trong mô hình Purple Team:

```
redteam-toolkit/
├── redteam-harness/          # 🔴 Bộ công cụ Red Team chính
│   ├── run_campaign.py       # Điều phối 12 kỹ thuật MITRE ATT&CK
│   ├── redteam_gui.py        # Giao diện đồ họa SOC-style (PySide6)
│   ├── validate_handoff.py   # Kiểm tra toàn vẹn SHA-256
│   ├── simulate_normal_days.py  # Sinh log baseline bình thường 5 ngày
│   ├── bridge_evaluate.py    # Đánh giá: Sigma Rules vs UEBA GlobalBan
│   └── artifacts/            # Bằng chứng thực nghiệm (EVTX manifest, hash CSV)
├── bridge_evaluate.py        # Bản chạy nhanh tại gốc repo
└── src/globalban/            # Các module UEBA cần thiết cho đánh giá
    ├── ai_agent/             # AI Agent giải thích bất thường (tiếng Việt)
    ├── baseline/             # Per-(User, Host) Behavioral Profiler
    ├── detector/             # UEBA Anomaly Scorer (thang điểm 0–100)
    ├── evaluation/           # Sigma Rules benchmark (14 luật)
    └── ingestion/            # Đọc và phân tích file EVTX
```

> 📂 **Blue Team codebase** (GlobalBan UEBA system đầy đủ) → xem nhánh [`main`](https://github.com/BuiTrongThuc/DACN/tree/main)

---

## 🚀 Bắt đầu nhanh

### 1. Yêu cầu
- Windows 10/11, Python ≥ 3.12
- `pip install PySide6`
- Mạng VMware NAT `192.168.52.0/24`

### 2. Mở giao diện đồ họa
```powershell
python C:\redteam-harness\redteam_gui.py
```

### 3. Chạy chiến dịch bằng dòng lệnh
```powershell
# Sinh baseline 5 ngày bình thường
python redteam-harness\simulate_normal_days.py

# Chạy toàn bộ 12 kỹ thuật ATT&CK
python redteam-harness\run_campaign.py --target-ip 192.168.52.136 --approved

# Kiểm tra toàn vẹn SHA-256
python redteam-harness\validate_handoff.py

# So sánh Sigma vs UEBA → xuất báo cáo
python bridge_evaluate.py
```

---

## ⚔️ 12 Kỹ thuật MITRE ATT&CK

| ID | Tên | Mô tả ngắn |
|----|-----|------------|
| — | Normal Baseline | Log bình thường 5 ngày |
| T1082 | System Info Discovery | `systeminfo`, `hostname`, `ver` |
| T1033 | User Discovery | `whoami /all`, `net user` |
| T1016/T1049 | Network Discovery | `ipconfig`, `arp -a`, `netstat` |
| T1560.001 | Archive Staging | Nén file tạm bằng `Compress-Archive` |
| T1053.005 | Scheduled Task | Tạo/xóa tác vụ `schtasks` |
| T1071.001 | C2 Beaconing | HTTP/TCP đều đặn về máy Red |
| T1110.001 | Brute Force | Thử đăng nhập nhiều lần qua SMB |
| T1110.003 | Password Spray | 1 mật khẩu × nhiều tài khoản |
| T1059.001 | Encoded PowerShell | `-EncodedCommand` Base64 |
| T1087.001 | Account Discovery | `net localgroup administrators` |
| — | Context Deviation (LotL) | Lệch chuẩn thời gian & công cụ |

---

## 🏗️ Kiến trúc lab

```
┌─────────────────────────────────────────────────┐
│           VMware NAT 192.168.52.0/24            │
│                                                 │
│  🔴 Red (192.168.52.134)   🔵 Blue (192.168.52.136) │
│  redteam-harness/   ──attack──►  Windows 11 VM  │
│  run_campaign.py              Audit Policy ✅   │
│  redteam_gui.py    ◄─EVTX──   Sysmon ✅        │
│  bridge_evaluate.py           GlobalBan (UEBA)  │
└─────────────────────────────────────────────────┘
```

---

*⚠️ Chỉ sử dụng trong môi trường lab kiểm soát. Không triển khai ra ngoài.*
