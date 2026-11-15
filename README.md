# GlobalBan Red-Team Simulator, UEBA Benchmark & EVTX Collection Toolkit

Dự án `attack-globalban` được thiết kế đồng bộ 100% với dự án **GlobalBan** (`C:\Users\PC1\globalban`), bao gồm 2 thành phần chính:
1. **Bộ Red Team EVTX Collection & Sigma Toolkit (`scripts/`)**: Thu thập dữ liệu thực nghiệm trên máy ảo Windows (Preflight, Baseline 3–7 ngày, Atomic Red Team có phê duyệt, xuất EVTX + SHA256, quét Sigma theo `case_id`, xuất XML trực tiếp qua `collect_windows_vm_logs.ps1` và kiểm tra bàn giao cho nhóm phân tích).
2. **Công cụ Giả lập Tấn công Windows XML, UEBA 7-Day Baseline & Chấm điểm GlobalBan (`attack_tool.py`)**: Sinh tự động hàng nghìn log Windows Event XML, học hồ sơ hành vi UEBA 7 ngày (`BehavioralProfileStore`), kiểm thử lệch chuẩn Atomic Red Team (`UEBA-BEHAVIOR-DEVIATION`), đánh giá `WinLOLBIN-GT` (`LOLBIN-ABUSE`) và chấm điểm Precision, Recall, F1-Score, FPR.

---

## Quy Trình 8 Bước Thu Thập Dữ Liệu Thực Nghiệm (Red Team Toolkit)

1. **Tạo Snapshot & Ghi nhận môi trường**: Tạo snapshot VM trước khi thử nghiệm; chạy [preflight.ps1](file:///c:/Users/PC1/attack-globalban/scripts/preflight.ps1) để ghi tự động `hostname`, `username`, `Windows`, `PowerShell` và `Sysmon` version vào `metadata/environment.json`.
2. **Đảm bảo 4 kênh Event Log khả dụng**: Kiểm tra `Security`, `Microsoft-Windows-Sysmon/Operational`, `Microsoft-Windows-PowerShell/Operational` và `Microsoft-Windows-Windows Defender/Operational` (mở PowerShell bằng quyền **Run as Administrator** để truy cập kênh `Security`).
3. **Thu thập Baseline bình thường (tối thiểu 3 ngày, khuyến nghị 7 ngày)**: Không chạy Atomic Red Team trong giai đoạn này; cuối mỗi ngày xuất log bằng [collect_windows_logs.ps1](file:///c:/Users/PC1/attack-globalban/scripts/collect_windows_logs.ps1) hoặc xuất XML bằng [collect_windows_vm_logs.ps1](file:///c:/Users/PC1/attack-globalban/scripts/collect_windows_vm_logs.ps1).
4. **Chỉ chạy Atomic Red Team sau khi được phê duyệt**: Sử dụng [run_approved_atomic.ps1](file:///c:/Users/PC1/attack-globalban/scripts/run_approved_atomic.ps1) kèm cờ bắt buộc `-Approved`, `-TechniqueId` và `-TestNumbers`.
5. **Quản lý theo `case_id`**: Mỗi lần chạy có `case_id` duy nhất, tự động ghi `start_utc`, `end_utc`, `host`, `username`, `status` vào `metadata/cases.jsonl` và `collection-manifest.json`.
6. **Xuất EVTX và SHA256**: Mỗi case xuất các file `.evtx` vào `artifacts/<kind>/<case_id>/` và bảng băm SHA256 vào `artifacts/hashes/<case_id>.csv`.
7. **Chạy bộ luật Sigma trên cùng các EVTX**: Chạy [run_sigma_on_evtx.ps1](file:///c:/Users/PC1/attack-globalban/scripts/run_sigma_on_evtx.ps1) để quét trực tiếp các file `.evtx` và ghi kết quả theo từng `case_id` vào `metadata/sigma-results.jsonl`.
8. **Kiểm tra & Bàn giao riêng Artifact**: Chạy [validate_handoff.ps1](file:///c:/Users/PC1/attack-globalban/scripts/validate_handoff.ps1) để xác thực tính toàn vẹn trước khi đóng gói chuyển riêng cho nhóm phân tích (`.gitignore` đã chặn commit file `.evtx` và metadata thật lên Git).

### Các Lệnh Toolkit Chuẩn

```powershell
# Bước 1 & 2: Kiểm tra môi trường và 4 kênh Event Log
.\scripts\preflight.ps1

# Bước 3, 5, 6: Thu thập Baseline hàng ngày (baseline-day-01 .. baseline-day-07)
.\scripts\collect_windows_logs.ps1 -CaseId baseline-day-01 -Kind baseline

# Bước 4, 5, 6: Chạy kỹ thuật Atomic Red Team đã được phê duyệt
.\scripts\run_approved_atomic.ps1 `
  -CaseId atomic-test-01 `
  -TechniqueId <TECHNIQUE_ID_DA_DUOC_DUYET> `
  -TestNumbers <TEST_NUMBER> `
  -Approved

# Bước 7: Chạy bộ luật Sigma trên các EVTX đã thu thập theo case_id
.\scripts\run_sigma_on_evtx.ps1

# Bước 8: Kiểm tra tính hợp lệ của toàn bộ gói bàn giao
.\scripts\validate_handoff.ps1
```

---

## Công Cụ Giả Lập Tấn Công Windows XML, UEBA & Chấm Điểm GlobalBan

Công cụ Python chuyên dụng dùng để:
1. **Sinh tự động hàng nghìn log Windows Event XML** (trộn lẫn cả log bình thường - *Benign* và các chiến dịch tấn công nhiều bước - *Multi-step Attack Campaigns* theo đúng thứ tự thời gian).
2. **Xuất đầy đủ bộ dữ liệu chuẩn của GlobalBan trong `output/`**:
   - `output/simulated_windows_eval.jsonl` & `output/simulated_windows_events.xml`: Bộ dữ liệu 6 kịch bản tấn công + Benign cho `evaluate_windows_dataset`.
   - `output/windows_baseline_7days.xml`: 7 ngày log thói quen bình thường (1,078 events của 3 Users `nguyen.an`, `tran.binh`, `admin.it` trên 3 máy `PC-01`, `PC-02`, `SRV-FILE01`).
   - `output/ueba_profiles.json`: Hồ sơ hành vi UEBA đã học và lưu trữ từ `BehavioralProfileStore`.
   - `output/windows_test_atomic.xml` & `output/windows_ground_truth.json`: Bộ kiểm thử lệch chuẩn hành vi UEBA kết hợp Atomic Red Team (tấn công 2 giờ sáng trên `PC-01`, di chuyển ngang sang `SRV-FILE01`, chạy PowerShell mã hóa từ Word và tạo Scheduled Task trên `PC-02`) cho `evaluate_ueba_dataset`.
3. **Đo lường tự động** các chỉ số **Precision, Recall, F1-Score, False Positive Rate (FPR), Rule Match Accuracy, Deviation Tag Match Rate**, Ma trận nhầm lẫn (**TP, FP, FN, TN**) trên cả 3 bộ đánh giá:
   - `evaluate_windows_dataset` (6 kịch bản chuỗi & hành vi Windows XML)
   - `evaluate_ueba_dataset` (UEBA 7-Day Baseline vs Atomic Red Team - `UEBA-BEHAVIOR-DEVIATION`)
   - `evaluate_winlolbin_dataset` (WinLOLBIN-GT - `LOLBIN-ABUSE`)

---

## Các Kịch Bản Tấn Công & Bộ Đánh Giá Được Hỗ Trợ

| Mã | Kịch bản mô phỏng | Chuỗi Event ID / Dữ liệu sinh ra | Rule GlobalBan kích hoạt |
| :-: | :--- | :--- | :--- |
| **1** | **Brute Force / Password Spraying** (`brute_force`) | $\ge 5$ sự kiện `4625`, `4771` hoặc `4776` từ cùng 1 IP trong 300s | `AUTH-FAILURE-BURST` (Level 1 & Level 2) |
| **2** | **Lệnh mã hóa / Làm rối** (`obfuscation`) | `4688` (và `4104`) có `CommandLine` chứa `-EncodedCommand`, `-enc`, `FromBase64String`, `IEX` | `OBFUSCATED-COMMAND-LINE`, `WINDOWS-4688-4104` |
| **3** | **Xâm nhập & Cắm chốt** (`persistence`) | Cùng `Computer`: `4624` (Logon) $\rightarrow$ `4688` (Process) $\rightarrow$ `4698` (Scheduled Task) hoặc `7045` (Service) | `WINDOWS-4624-4688-4698`, `WINDOWS-4624-4688-7045` |
| **4** | **Leo thang đặc quyền** (`privilege_escalation`) | `4720` (Tạo user) $\rightarrow$ `4728`/`4732`/`4756` (Thêm nhóm Admin) $\rightarrow$ `4704` (Gán quyền) | `PRIVILEGE-CHANGE` & `WINDOWS-4720-4732-4704` |
| **5** | **Xóa dấu vết** (`defense_evasion`) | `7045` / `4688` $\rightarrow$ `1102` (Xóa Security Log) hoặc `4719` (Sửa Audit Policy) | `WINDOWS-7045-1102` (và `4719`, `4688`) |
| **6** | **C2 Beaconing** (`c2_beaconing`) | $\ge 5$ sự kiện `5156` chiều ra (`Direction=%%14592`) tới cùng 1 IP Public cách đều (30s) | `C2-BEACONING` |
| **7** | **UEBA 7-Day Baseline & Atomic Red Team** | Học 7 ngày Baseline (`4624`, `4634`, `4688`, `5156`, `4104`, Sysmon `1`, `3`) & chấm lệch chuẩn giờ đăng nhập, máy lạ, tiến trình lạ, lệnh PowerShell lạ, IP/port lạ | `UEBA-BEHAVIOR-DEVIATION` |
| **8** | **WinLOLBIN-GT Dataset** | Các lệnh Living Off The Land Binaries (`rundll32`, `regsvr32`, `mshta`, `certutil`, `wmic`, ...) | `LOLBIN-ABUSE` |

---

## Hướng Dẫn Sử Dụng

### 1. Chạy Giao Diện Đồ Họa (Tkinter GUI)
```powershell
& "C:\Users\PC1\.local\bin\python3.15.exe" attack_tool.py --gui
```

### 2. Chạy Menu Tương Tác Trên Terminal (Interactive CLI)
```powershell
& "C:\Users\PC1\.local\bin\python3.15.exe" attack_tool.py --interactive
```

### 3. Chạy Trực Tiếp Qua CLI & Kiểm Thử Tự Động
```powershell
# Chạy toàn bộ kịch bản + UEBA 7-day Baseline + WinLOLBIN-GT + Bắn vào GlobalBan CLI
& "C:\Users\PC1\.local\bin\python3.15.exe" attack_tool.py --scenarios all --campaigns 25 --benign 600

# Chạy bộ Unit Tests kiểm chứng 100% Precision/Recall/F1
& "C:\Users\PC1\.local\bin\python3.15.exe" -m unittest discover -s tests -p "test_*.py" -v
```
