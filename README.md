# Công Cụ Giả Lập Tấn Công Windows XML & Chấm Điểm GlobalBan

Công cụ Python chuyên dụng dùng để:
1. **Sinh tự động hàng trăm / hàng nghìn log Windows Event XML** (trộn lẫn cả log bình thường - *Benign* và các chiến dịch tấn công nhiều bước - *Multi-step Attack Campaigns* theo đúng thứ tự thời gian).
2. **Xuất đồng thời 2 định dạng chuẩn của GlobalBan**:
   - `output/simulated_windows_eval.jsonl`: Kèm nhãn `expected_signal`, `expected_rule_ids` và ánh xạ MITRE ATT&CK đầy đủ cho hàm `evaluate_windows_dataset`.
   - `output/simulated_windows_events.xml`: Định dạng Windows Event Viewer XML (`<Events><Event>...</Event></Events>`) để đẩy trực tiếp vào `globalban.main --windows-xml` hoặc nạp vào GlobalBan Desktop Dashboard.
3. **Đo lường tự động** các chỉ số **Precision, Recall, F1-Score, False Positive Rate (FPR), Rule Match Accuracy**, Ma trận nhầm lẫn (**TP, FP, FN, TN**) và **Recall theo từng kỹ thuật MITRE ATT&CK**.

---

## 6 Kịch Bản Tấn Công Được Hỗ Trợ

| Mã | Kịch bản mô phỏng | Chuỗi Event ID sinh ra | Rule GlobalBan kích hoạt |
| :-: | :--- | :--- | :--- |
| **1** | **Brute Force / Password Spraying** (`brute_force`) | $\ge 5$ sự kiện `4625`, `4771` hoặc `4776` từ cùng 1 IP trong 300s | `AUTH-FAILURE-BURST` (Level 1 & Level 2) |
| **2** | **Lệnh mã hóa / Làm rối** (`obfuscation`) | `4688` (và `4104`) có `CommandLine` chứa `-EncodedCommand`, `-enc`, `FromBase64String`, `IEX` | `OBFUSCATED-COMMAND-LINE` |
| **3** | **Xâm nhập & Cắm chốt** (`persistence`) | Cùng `Computer`: `4624` (Logon) $\rightarrow$ `4688` (Process) $\rightarrow$ `4698` (Scheduled Task) hoặc `7045` (Service) | `WINDOWS-4624-4688-4698`, `WINDOWS-4624-4688-7045` (`logon-process-persistence`) |
| **4** | **Leo thang đặc quyền** (`privilege_escalation`) | `4720` (Tạo user) $\rightarrow$ `4728`/`4732`/`4756` (Thêm nhóm Admin) $\rightarrow$ `4704` (Gán quyền) | `PRIVILEGE-CHANGE` & `WINDOWS-4720-4732-4704` |
| **5** | **Xóa dấu vết** (`defense_evasion`) | `7045` / `4688` $\rightarrow$ `1102` (Xóa Security Log) hoặc `4719` (Sửa Audit Policy) | `WINDOWS-7045-1102` (và `4719`, `4688`) |
| **6** | **C2 Beaconing** (`c2_beaconing`) | $\ge 5$ sự kiện `5156` chiều ra (`Direction=%%14592`) tới cùng 1 IP Public cách đều (30s) | `C2-BEACONING` |

---

## Hướng Dẫn Sử Dụng

### 1. Chạy Giao Diện Đồ Họa (Tkinter GUI)
```powershell
& "C:\Users\Admin\Desktop\globalban\.venv\Scripts\python.exe" attack_tool.py --gui
```

### 2. Chạy Menu Tương Tác Trên Terminal (Interactive CLI)
```powershell
& "C:\Users\Admin\Desktop\globalban\.venv\Scripts\python.exe" attack_tool.py --interactive
```

### 3. Chạy Trực Tiếp Qua CLI (Sinh >1,000 log XML + Chấm điểm tự động)
```powershell
# Chạy toàn bộ 6 kịch bản (25 chiến dịch/kịch bản + 600 log Benign = 1,097 logs)
& "C:\Users\Admin\Desktop\globalban\.venv\Scripts\python.exe" attack_tool.py --scenarios all --campaigns 25 --benign 600

# Chỉ chọn kịch bản số 1 (Brute Force), số 3 (Persistence) và số 6 (C2 Beaconing)
& "C:\Users\Admin\Desktop\globalban\.venv\Scripts\python.exe" attack_tool.py --scenarios 1,3,6 --campaigns 30 --benign 500

# Thử nghiệm thêm nhiễu Admin (False Positive Stress Test) để quan sát sự thay đổi của FPR và Precision
& "C:\Users\Admin\Desktop\globalban\.venv\Scripts\python.exe" attack_tool.py --scenarios all --campaigns 20 --benign 500 --fp-noise 15
```

