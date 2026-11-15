# HƯỚNG DẪN SỬ DỤNG CÔNG CỤ GIẢ LẬP & GIAO DIỆN ĐỒ HỌA (`attack_tool.py`)

Tài liệu này hướng dẫn từng bước cách chạy dự án `attack-globalban` để sinh dữ liệu, chấm điểm hệ thống phòng thủ **GlobalBan**, bắn log trực tiếp vào CLI và mở **GlobalBan Dashboard**.

---

## 1. Yêu Cầu Môi Trường

- **Hệ điều hành**: Windows 10 / Windows 11 / Windows Server.
- **Python**: Python 3.11+ (trên máy hiện tại đã cài sẵn tại `C:\Users\PC1\.local\bin\python3.15.exe` — chỉ sử dụng thư viện chuẩn của Python, không cần cài thêm bất kỳ thư viện ngoài nào).
- **Thư mục dự án GlobalBan**: Đặt tại `C:\Users\PC1\globalban` (công cụ tự động nhận diện đường dẫn này mà không cần cấu hình thủ công).

---

## 2. Ba Cách Khởi Chạy Công Cụ

Mở **PowerShell** tại thư mục `c:\Users\PC1\attack-globalban`:

### Cách 1: Chạy Giao Diện Đồ Họa Trực Quan (Tkinter GUI) — *Khuyên dùng khi Demo / Báo cáo*

```powershell
& "C:\Users\PC1\.local\bin\python3.15.exe" attack_tool.py --gui
```

**Hướng dẫn thao tác trên cửa sổ GUI**:
1. **Khung "Chọn Kịch Bản Chiến Dịch Tấn Công"**:
   - Tích chọn một hoặc tất cả các kịch bản từ **1 đến 6** (Brute Force, Obfuscation, Persistence, Privilege Escalation, Defense Evasion, C2 Beaconing) cùng với **Kịch bản 7 (UEBA 7-Day Baseline & Atomic Red Team)** và **Kịch bản 8 (WinLOLBIN-GT)**.
2. **Khung "Cấu Hình Số Lượng Log Sinh Ra"**:
   - **Số chiến dịch / mỗi kịch bản**: Số lượng đợt tấn công muốn sinh cho mỗi kịch bản (mặc định: `20` hoặc `25`).
   - **Số lượng Log bình thường (Benign)**: Số sự kiện sạch trộn lẫn vào tập dữ liệu (mặc định: `600`).
   - **Nhiễu Admin (Test False Positive)**: Số lượng lệnh quản trị viên hợp lệ trộn vào để thử thách bộ lọc báo giả.
3. **3 Nút Chức Năng Chính**:
   - **Nút 1 — `1. Sinh File XML + JSONL & Chấm Điểm Tự Động`**: Sinh toàn bộ các file log trong thư mục `output/`, chạy thuật toán chấm điểm của GlobalBan và hiển thị ngay kết quả **Precision, Recall, F1-Score, FPR, Confusion Matrix** cùng danh sách cảnh báo trên bảng.
   - **Nút 2 — `2. Bắn Log XML trực tiếp vào GlobalBan CLI`**: Đẩy file `simulated_windows_events.xml` và `windows_test_atomic.xml` (kèm hồ sơ 7 ngày `windows_baseline_7days.xml`) trực tiếp vào hàm `globalban.main` để thu về các bản ghi JSON cảnh báo.
   - **Nút 3 — `3. Mở GlobalBan Dashboard (Tự Động Liên Kết & Nạp XML)`**: Tự động khởi chạy giao diện **GlobalBan - Windows Security & UEBA Monitor**, nạp sẵn hồ sơ thói quen 7 ngày của 3 người dùng (`nguyen.an`, `tran.binh`, `admin.it`), 3 máy tính (`PC-01`, `PC-02`, `SRV-FILE01`) và hiển thị trực tiếp các cảnh báo lên màn hình giám sát của Blue Team.

---

### Cách 2: Chạy Tự Động Qua Dòng Lệnh (CLI Batch Mode)

Chạy một lệnh duy nhất để sinh toàn bộ dữ liệu, chấm điểm cả 3 tập (Windows 6 kịch bản, UEBA 7-day Baseline, WinLOLBIN-GT) và xuất báo cáo ra màn hình + file JSON:

```powershell
# Chạy mặc định toàn bộ kịch bản (25 chiến dịch/kịch bản + 600 log Benign = 1,097 logs)
& "C:\Users\PC1\.local\bin\python3.15.exe" attack_tool.py

# Tuỳ chỉnh kịch bản và số lượng log (VD: chỉ chạy kịch bản 1, 3, 6 với 30 chiến dịch và 500 log Benign)
& "C:\Users\PC1\.local\bin\python3.15.exe" attack_tool.py --scenarios 1,3,6 --campaigns 30 --benign 500

# Kiểm thử thêm 30 sự kiện nhiễu Admin hợp lệ để chứng minh FPR vẫn bằng 0.00%
& "C:\Users\PC1\.local\bin\python3.15.exe" attack_tool.py --scenarios all --campaigns 25 --benign 600 --fp-noise 30

# Xem danh sách mô tả các kịch bản
& "C:\Users\PC1\.local\bin\python3.15.exe" attack_tool.py --list-scenarios
```

---

### Cách 3: Chạy Menu Tương Tác Từng Bước Trên Terminal (Interactive CLI)

```powershell
& "C:\Users\PC1\.local\bin\python3.15.exe" attack_tool.py --interactive
```
Chương trình sẽ hỏi lần lượt từng thông số trên màn hình console (chọn kịch bản nào, bao nhiêu chiến dịch, bao nhiêu log sạch, bao nhiêu nhiễu Admin) rồi thực thi tự động.

---

## 3. Ý Nghĩa Các File Được Sinh Ra Trong Thư Mục `output/`

Sau mỗi lần chạy, thư mục [output/](file:///c:/Users/PC1/attack-globalban/output) sẽ chứa 7 file chuẩn:

| Tên file trong `output/` | Ý nghĩa & Mục đích sử dụng |
| :--- | :--- |
| **[simulated_windows_events.xml](file:///c:/Users/PC1/attack-globalban/output/simulated_windows_events.xml)** | File log Windows Event XML chuẩn (`<Events><Event>...</Event></Events>`) chứa toàn bộ sự kiện của 6 kịch bản tấn công trộn lẫn với log sạch Benign, sắp xếp đúng thứ tự thời gian. Dùng để nạp vào `globalban.main --windows-xml` hoặc GlobalBan Dashboard. |
| **[simulated_windows_eval.jsonl](file:///c:/Users/PC1/attack-globalban/output/simulated_windows_eval.jsonl)** | File dữ liệu định dạng JSON Lines, mỗi dòng gồm chuỗi XML kèm nhãn Ground Truth (`is_malicious`, `expected_signal`, `expected_rule_ids`, `mitre_technique_id`). Dùng cho hàm chấm điểm `evaluate_windows_dataset`. |
| **[windows_baseline_7days.xml](file:///c:/Users/PC1/attack-globalban/output/windows_baseline_7days.xml)** | 1,078 sự kiện Windows XML mô phỏng 7 ngày làm việc bình thường của `nguyen.an` (`PC-01`), `tran.binh` (`PC-02`) và `admin.it` (`SRV-FILE01`). Dùng cho tham số `--learn-baseline`. |
| **[ueba_profiles.json](file:///c:/Users/PC1/attack-globalban/output/ueba_profiles.json)** | Hồ sơ hành vi UEBA đã được GlobalBan học từ 7 ngày Baseline (lưu giờ hoạt động quen thuộc, danh sách máy tính, tiến trình thường dùng, lệnh PowerShell, IP/Port quen thuộc). Dùng cho tham số `--profile-path`. |
| **[windows_test_atomic.xml](file:///c:/Users/PC1/attack-globalban/output/windows_test_atomic.xml)** | 18 sự kiện kiểm thử UEBA (10 sự kiện bình thường + 8 sự kiện tấn công Atomic Red Team lúc 2 giờ sáng và di chuyển ngang). |
| **[windows_ground_truth.json](file:///c:/Users/PC1/attack-globalban/output/windows_ground_truth.json)** | Nhãn chuẩn Ground Truth cho tập kiểm thử UEBA, định nghĩa rõ từng mã `atomic_test_id`, `mitre_technique_id` và danh sách nhãn lệch chuẩn `expected_deviation_tags`. |
| **[evaluation_report.json](file:///c:/Users/PC1/attack-globalban/output/evaluation_report.json)** | Báo cáo tổng hợp toàn bộ kết quả chấm điểm dưới dạng JSON để lưu trữ hoặc đưa vào phụ lục báo cáo đồ án. |

---

## 4. Cách Đọc Hiểu Các Chỉ Số Chấm Điểm Trên Báo Cáo

- **True Positive (TP)**: Số sự kiện mang tín hiệu tấn công mà GlobalBan **bắt trúng**.
- **False Positive (FP)**: Số sự kiện bình thường (log sạch / lệnh Admin hợp lệ) bị GlobalBan **báo động nhầm** (Mục tiêu lý tưởng: `FP = 0`).
- **False Negative (FN)**: Số sự kiện mang tín hiệu tấn công bị GlobalBan **bỏ lọt** (Mục tiêu lý tưởng: `FN = 0`).
- **True Negative (TN)**: Số sự kiện không phải tín hiệu cảnh báo được GlobalBan **bỏ qua đúng**.
- **Precision ($\frac{TP}{TP + FP}$)**: Độ chính xác của cảnh báo (100% nghĩa là hễ GlobalBan báo động thì chắc chắn 100% là tấn công thật, không có báo giả).
- **Recall ($\frac{TP}{TP + FN}$)**: Độ phủ phát hiện tấn công (100% nghĩa là bắt được toàn bộ 100% các đợt tấn công, không bỏ sót).
- **F1-Score**: Trung bình điều hòa giữa Precision và Recall (đạt `100.00%` / `1.0000`).
- **Rule Match Accuracy**: Tỷ lệ GlobalBan kích hoạt đúng chính xác mã Rule (`AUTH-FAILURE-BURST`, `C2-BEACONING`, `WINDOWS-4624-4688-4698`, ...) như thiết kế.
- **Deviation Tag Match Rate**: Tỷ lệ bộ phát hiện UEBA chỉ ra đúng chính xác các lý do lệch chuẩn hành vi (giờ lạ, máy lạ, tiến trình lạ, lệnh PowerShell lạ, kết nối mạng lạ).
