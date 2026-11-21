# 🔴 GlobalBan Red Team Harness

> **Bộ công cụ mô phỏng tấn công chuẩn MITRE ATT&CK** dành cho Purple Team Lab  
> Thuộc đề tài ĐACN 2026 — Phát hiện hành vi bất thường người dùng (UEBA) trên Windows

---

## 🎯 Mô tả tổng quan

Bộ công cụ **Red Team Harness** chạy trực tiếp trên máy Red Team (`192.168.52.134`), mô phỏng các kỹ thuật tấn công theo khung **MITRE ATT&CK** nhắm vào máy Blue Team (`192.168.52.136`), tự động thu thập bằng chứng **Windows Event Log thật (.evtx)**, tính toán mã băm **SHA-256** chống chỉnh sửa, và xuất **Ground-Truth** để đánh giá hiệu quả hệ thống phòng thủ **GlobalBan (UEBA + AI Agent)**.

```
Máy Red Team (134) ──[tấn công mô phỏng]──► Máy Blue Team (136)
        │                                           │
        │◄──────────── Log EVTX thật ───────────────┘
        │
        ▼
  artifacts/ ── Ground-Truth JSON ── SHA-256 CSV
        │
        ▼
  bridge_evaluate.py ── So sánh Sigma vs UEBA ── Báo cáo Precision/Recall/F1
```

---

## 📁 Cấu trúc thư mục

```
redteam-harness/
├── run_campaign.py           # Bộ điều phối chính — thực thi kịch bản ATT&CK, xuất EVTX + SHA256
├── redteam_gui.py            # 🖥️ Giao diện đồ họa SOC-style (PySide6) — điều khiển tấn công trực quan
├── validate_handoff.py       # Kiểm tra toàn vẹn SHA-256 trước khi bàn giao cho Blue Team
├── simulate_normal_days.py   # Sinh log hành vi bình thường 5 ngày làm cơ sở Baseline
├── bridge_evaluate.py        # Cầu nối đánh giá: nạp EVTX vào GlobalBan → Precision/Recall/F1
├── package_for_vm.ps1        # Script đóng gói toàn bộ công cụ thành file .zip để triển khai
├── deploy_on_vm.bat          # Script batch cài đặt nhanh trên máy ảo Windows
├── comparison_sigma_vs_ueba.md   # Bảng so sánh kết quả: Sigma Rules vs UEBA (Markdown)
├── comparison_sigma_vs_ueba.json # Dữ liệu so sánh dạng JSON (xuất tự động)
└── artifacts/                # 📦 Bằng chứng thực nghiệm (tự động sinh ra khi chạy)
    ├── baseline/             # Log EVTX hành vi bình thường (nhiều ngày)
    ├── atomic/               # Log EVTX của từng ca tấn công mô phỏng
    ├── hashes/               # File CSV chứa mã băm SHA-256 chống chỉnh sửa
    └── metadata/
        ├── cases.jsonl       # Danh sách tất cả ca kiểm thử (Ground-Truth registry)
        └── red_ground_truth.json  # Ground-Truth chuẩn để chấm điểm Blue Team
```

---

## ⚔️ Các kỹ thuật MITRE ATT&CK được mô phỏng

| STT | Technique ID | Tên kỹ thuật | Mô tả |
|-----|-------------|--------------|-------|
| 1 | — | **Normal Baseline** | Tạo 5 ngày log hành vi bình thường làm đường cơ sở |
| 2 | **T1082** | System Information Discovery | Thu thập thông tin hệ thống: `systeminfo`, `hostname`, `ver` |
| 3 | **T1033** | System Owner/User Discovery | Liệt kê người dùng: `whoami /all`, `net user`, `query user` |
| 4 | **T1016 / T1049** | Network Discovery | Khảo sát mạng: `ipconfig /all`, `arp -a`, `netstat -ano` |
| 5 | **T1560.001** | Archive via Utility | Nén dữ liệu tạm bằng `Compress-Archive` (PowerShell) |
| 6 | **T1053.005** | Scheduled Task | Tạo tác vụ định kỳ bằng `schtasks /create` rồi xóa |
| 7 | **T1071.001** | C2 Beaconing | Gửi kết nối HTTP/TCP đều đặn về máy Red (mô phỏng C2) |
| 8 | **T1110.001** | Brute Force | Thử đăng nhập nhiều lần qua SMB (`net use`) |
| 9 | **T1110.003** | Password Spray | Thử 1 mật khẩu với nhiều tài khoản khác nhau |
| 10 | **T1059.001** | Encoded PowerShell | Thực thi lệnh PowerShell mã hóa Base64 (`-EncodedCommand`) |
| 11 | **T1087.001** | Local Account Discovery | Liệt kê tài khoản cục bộ: `net localgroup administrators` |
| 12 | — | **Context Deviation (LotL)** | Mô phỏng lệch chuẩn thời gian và công cụ hệ thống |

---

## 🖥️ Giao diện đồ họa (Red Team GUI)

File `redteam_gui.py` cung cấp giao diện SOC-style tối màu với các tính năng:

- **12 nút kỹ thuật** — kích hoạt từng cuộc tấn công hoặc toàn bộ chiến dịch
- **Badge trạng thái thời gian thực** — 🔵 Waiting / 🟡 Running / 🟢 Done / 🔴 Failed  
- **Nhật ký hoạt động** — xuất log trực tiếp lên màn hình
- **Nút Validate Handoff** — kiểm tra SHA-256 toàn gói bằng chứng
- **Nút So sánh Sigma vs UEBA** — chạy đánh giá và xuất báo cáo

```bash
# Khởi động giao diện
python C:\redteam-harness\redteam_gui.py
```

---

## 🚀 Hướng dẫn sử dụng

### Yêu cầu môi trường
- **Hệ điều hành:** Windows 10/11 (x64)
- **Python:** >= 3.12
- **Thư viện:** `PySide6 >= 6.5`  
  ```powershell
  pip install PySide6
  ```
- **Mạng:** VMware NAT `192.168.52.0/24` — máy Red Team `192.168.52.134`, Blue Team `192.168.52.136`

### Chạy chiến dịch bằng dòng lệnh

```powershell
# 1. Tạo Baseline bình thường 5 ngày
python C:\redteam-harness\simulate_normal_days.py

# 2. Chạy toàn bộ chiến dịch tấn công (cần phê duyệt rõ ràng)
python C:\redteam-harness\run_campaign.py --target-ip 192.168.52.136 --approved

# 3. Kiểm tra toàn vẹn SHA-256 của gói bằng chứng
python C:\redteam-harness\validate_handoff.py

# 4. Đánh giá: So sánh Sigma Rules vs UEBA GlobalBan
python C:\redteam-harness\bridge_evaluate.py
```

### Chạy kỹ thuật đơn lẻ

```powershell
python C:\redteam-harness\run_campaign.py --target-ip 192.168.52.136 --approved --case T1082
python C:\redteam-harness\run_campaign.py --target-ip 192.168.52.136 --approved --case T1110.001
```

---

## 📊 Kết quả thực nghiệm

Sau khi chạy, bảng so sánh được xuất tại:
- 📄 `comparison_sigma_vs_ueba.md` — Bảng Markdown có thể đọc trực tiếp
- 📋 `comparison_sigma_vs_ueba.json` — Dữ liệu JSON cho xử lý tự động

Kết quả bao gồm:

| Chỉ số | Sigma Rules | UEBA + AI Agent (GlobalBan) |
|--------|------------|------------------------------|
| Precision | — | — |
| Recall | — | — |
| F1-Score | — | — |
| False Positive Rate | — | — |

> *Điền số liệu sau khi chạy thực nghiệm đầy đủ*

---

## 🔒 Cơ chế an toàn

- ✅ **Phải có cờ `--approved`** khi chạy dòng lệnh, hoặc tích ô phê duyệt trên GUI
- ✅ **Chỉ cho phép IP trong dải `192.168.52.*`** — không thể tấn công ra ngoài mạng lab
- ✅ **Tự động dọn dẹp** sau mỗi kỹ thuật (xóa tác vụ schtasks, file tạm, staging folder)
- ✅ **Mã hóa SHA-256** ngay sau khi xuất EVTX — phát hiện chỉnh sửa sau thực nghiệm

---

## 🏗️ Kiến trúc Purple Team Lab

```
┌─────────────────────────────────────────────────────────────┐
│                   VMware NAT 192.168.52.0/24                │
│                                                             │
│  🔴 Red Team (192.168.52.134)        🔵 Blue Team (192.168.52.136)  │
│  ┌─────────────────────┐             ┌──────────────────────┐  │
│  │  redteam-harness/   │  ──attack──►│  Windows 11 VM       │  │
│  │  run_campaign.py    │             │  Audit Policy ✅     │  │
│  │  redteam_gui.py     │◄──EVTX log─│  Sysmon ✅           │  │
│  │  bridge_evaluate.py │             │  GlobalBan (UEBA)    │  │
│  └─────────────────────┘             └──────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## 📝 Ghi chú kỹ thuật

- File `.evtx` thật được xuất bằng **`wevtutil epl`** — cần quyền Administrator
- Nếu không có quyền Admin, script tự động tạo file EVTX placeholder (4096 bytes) để không bị crash
- Máy Blue Team phải bật **Audit Policy**: Logon (4624/4625) + Process Creation (4688) + CommandLine
- Sysmon được khuyến nghị cài để ghi thêm sự kiện 1 (Process Create), 3 (Network), 11 (File Create)

---

## 👥 Thông tin đề tài

| Thông tin | Chi tiết |
|-----------|----------|
| **Tên đề tài** | Phát hiện hành vi bất thường người dùng (UEBA) trên Windows bằng AI Agent |
| **Trường** | Đại học — Khoa Công nghệ Thông tin |
| **Năm** | 2026 |
| **GitHub** | [BuiTrongThuc/DACN](https://github.com/BuiTrongThuc/DACN) |
| **Nhánh chính** | `main` (Blue Team GlobalBan) |
| **Nhánh này** | `redteam-toolkit` (Red Team Harness + GUI) |

---

*📌 Toàn bộ công cụ chỉ dùng trong môi trường lab kiểm soát. Không sử dụng ngoài phạm vi đề tài.*
