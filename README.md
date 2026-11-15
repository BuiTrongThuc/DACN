# GlobalBan Red-Team Studio, Adversary Emulation & Benchmark Suite

Dự án `attack-globalban` cung cấp bộ công cụ toàn diện cho Red Team mô phỏng tấn công, chấm điểm SIEM/UEBA và thu thập dữ liệu EVTX chuẩn pháp chứng số.

Hệ thống hoạt động với **Dual-Mode Engine**:
- **Chế độ kết nối ngoài (Linked Mode)**: Tự động phát hiện và kết nối với mã nguồn GlobalBan nếu có trên máy.
- **Chế độ độc lập (Standalone Mode)**: Tích hợp sẵn bộ máy phát hiện chuẩn (`BuiltinGlobalBanEngine` + `BuiltinUEBAEngine`) với 100% chức năng, **không bao giờ bị lỗi thiếu đường dẫn (`FileNotFoundError`)** khi chạy trên máy tính độc lập hoặc máy ảo Red Team riêng biệt.

---

## Cấu Trúc Mã Nguồn Phân Chia Theo Từng File (Modular Architecture)

Mã nguồn được phân tách khoa học vào package `attack_simulator/` theo đúng nguyên tắc Single Responsibility:

```
attack-globalban/
├── attack_globalban_studio.py    # Entry point chính (Giao diện Dark SOC Studio + CLI Batch + Interactive)
├── attack_tool.py                # Wrapper tương thích ngược cho attack_globalban_studio.py
├── attack_simulator/             # Gói module nghiệp vụ độc lập
│   ├── __init__.py               # Re-export các lớp và hàm trọng tâm
│   ├── models.py                 # Định nghĩa ScenarioSpec, MITRE ATT&CK Catalog, SimulatedRecord
│   ├── xml_utils.py              # Xây dựng và phân tích cú pháp Windows Event XML (System + EventData)
│   ├── generator.py              # Bộ sinh 6 chiến dịch tấn công, Benign, Admin Noise & UEBA 7-Day Baseline
│   ├── engine.py                 # BuiltinGlobalBanEngine & BuiltinUEBAEngine (Standalone Detectors)
│   ├── evaluator.py              # Dual-Mode Evaluation Pipeline & WinLOLBIN-GT Benchmark
│   └── gui.py                    # Giao diện đồ họa Dark Cybersecurity SOC (6 KPI Cards + 6 Tabs)
├── scripts/                      # Bộ PowerShell Toolkit thu thập EVTX & quét Sigma trên máy ảo VMware
├── tests/                        # Bộ kiểm thử tự động (Unit Tests)
└── output/                       # 7 file dữ liệu và báo cáo xuất tự động
```

---

## 8 Kịch Bản & Module Đánh Giá Được Hỗ Trợ

| Mã | Kịch bản mô phỏng | Chuỗi Event ID / Dữ liệu sinh ra | Rule GlobalBan kích hoạt |
| :-: | :--- | :--- | :--- |
| **1** | **Brute Force / Password Spraying** (`brute_force`) | $\ge 5$ sự kiện `4625`, `4771` hoặc `4776` từ cùng 1 IP trong 300s | `AUTH-FAILURE-BURST` (Level 1 & Level 2) |
| **2** | **Lệnh mã hóa / Làm rối** (`obfuscation`) | `4688` (và `4104`) có `CommandLine` chứa `-EncodedCommand`, `-enc`, `FromBase64String`, `IEX` | `OBFUSCATED-COMMAND-LINE`, `WINDOWS-4688-4104` |
| **3** | **Xâm nhập & Cắm chốt** (`persistence`) | Cùng `Computer`: `4624` (Logon) $\rightarrow$ `4688` (Process) $\rightarrow$ `4698` (Scheduled Task) hoặc `7045` (Service) | `WINDOWS-4624-4688-4698`, `WINDOWS-4624-4688-7045` |
| **4** | **Leo thang đặc quyền** (`privilege_escalation`) | `4720` (Tạo user) $\rightarrow$ `4728`/`4732`/`4756` (Thêm nhóm Admin) $\rightarrow$ `4704` (Gán quyền) | `PRIVILEGE-CHANGE` & `WINDOWS-4720-4732-4704` |
| **5** | **Xóa dấu vết** (`defense_evasion`) | `7045` / `4688` $\rightarrow$ `1102` (Xóa Security Log) hoặc `4719` (Sửa Audit Policy) | `WINDOWS-7045-1102` (và `4719`, `4688`) |
| **6** | **C2 Beaconing** (`c2_beaconing`) | $\ge 5$ sự kiện `5156` chiều ra (`Direction=%%14592`) tới cùng 1 IP Public cách đều (30s) | `C2-BEACONING` |
| **7** | **UEBA 7-Day Baseline & Atomic Red Team** | Học 7 ngày Baseline (`4624`, `4634`, `4688`, `5156`, `4104`, Sysmon `1`, `3`) & chấm lệch chuẩn giờ đăng nhập, máy lạ, tiến trình lạ, PowerShell lạ, IP/port lạ | `UEBA-BEHAVIOR-DEVIATION` |
| **8** | **WinLOLBIN-GT Dataset** | Các lệnh Living Off The Land Binaries (`rundll32`, `regsvr32`, `mshta`, `certutil`, `wmic`, ...) | `LOLBIN-ABUSE` |

---

## 7 File Dữ Liệu Chuẩn Tự Động Xuất Vào `output/`

Mỗi lần chạy mô phỏng hoặc bấm nút trên giao diện, hệ thống tự động sinh và cập nhật trọn bộ 7 file:
1. `output/simulated_windows_events.xml`: File Windows Event Viewer XML hợp nhất chứa toàn bộ các sự kiện tấn công và bình thường.
2. `output/simulated_windows_eval.jsonl`: Dữ liệu JSON Lines kèm nhãn Ground Truth (từng kỹ thuật MITRE, rule kỳ vọng, `is_malicious`, `expected_signal`).
3. `output/windows_baseline_7days.xml`: 1,078 sự kiện học thói quen bình thường của 3 người dùng (`nguyen.an`, `tran.binh`, `admin.it`) trong 7 ngày.
4. `output/ueba_profiles.json`: Hồ sơ hành vi đã lượng hóa từ `BehavioralProfileStore`.
5. `output/windows_test_atomic.xml`: 18 sự kiện kiểm thử Atomic Red Team (gồm 10 log thường ngày thứ 8 và 8 đòn tấn công lệch chuẩn).
6. `output/windows_ground_truth.json`: Nhãn chân thực cho 18 sự kiện kiểm thử UEBA.
7. `output/evaluation_report.json`: Báo cáo chi tiết các chỉ số Precision, Recall, F1, FPR, Confusion Matrix và độ phủ MITRE ATT&CK.

---

## Hướng Dẫn Chạy Ứng Dụng

### 1. Mở Giao Diện Đồ Họa Dark SOC Studio (Mặc định)
```bash
python attack_globalban_studio.py
```
*(Hoặc chạy lệnh tương thích: `python attack_tool.py --gui`)*

### 2. Chạy Tự Động Trên Dòng Lệnh (CLI Batch Mode)
```bash
python attack_globalban_studio.py --cli -c 25 -b 600 --fp-noise 30
```

### 3. Chạy Menu Tương Tác Trên Terminal
```bash
python attack_globalban_studio.py -i
```

### 4. Liệt Kê Các Kịch Bản Hỗ Trợ
```bash
python attack_globalban_studio.py --list-scenarios
```

### 5. Chạy Bộ Unit Tests
```bash
python -m unittest discover tests -v
```
*(Toàn bộ 4 test suites kiểm thử 100% metrics, chống báo giả FPR, UEBA 7-day baseline và LOLBin benchmark chạy mượt mà không phụ thuộc môi trường bên ngoài)*
