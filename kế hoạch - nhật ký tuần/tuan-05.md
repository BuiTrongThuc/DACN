# Báo cáo công việc tuần 05

**Thời gian:** 09/11/2026 - 15/11/2026
**Dự án:** GlobalBan - hệ thống giám sát SSH và hành vi Windows
**Người thực hiện:** Nhóm sinh viên

## 1. Công việc đã thực hiện

- **Phối hợp chuẩn bị môi trường Lab:** Phối hợp cùng nhóm Red Team thiết lập máy ảo Windows 10 độc lập (`DESKTOP-3K305I1`, địa chỉ IP `192.168.52.136`, tài khoản kiểm thử `main` và `redtest`).
- **Cấu hình Audit Policy nâng cao:** Bật tính năng Process Creation có kèm Command Line (Audit Policy: Detailed Tracking, Event ID 4688), kích hoạt PowerShell ScriptBlock Logging (Event ID 4104) và Logon/Logoff events (4624/4625).
- **Thu thập dữ liệu EVTX thực tế:** Tiến hành trích xuất log nhị phân Windows gốc gồm `Security.evtx` và `PowerShell.evtx` cho hai trạng thái:
  + Dữ liệu hoạt động bình thường (Baseline) lưu tại `data/baseline/`.
  + Dữ liệu kịch bản kiểm thử tấn công (Atomic) lưu tại `data/atomic/`.
- **Nâng cấp bộ phân tích cú pháp XML (`src/globalban/ingestion/parser.py`):**
  + Khắc phục lỗi đọc tên máy tính: bóc tách chính xác thẻ `<System><Computer>HOSTNAME</Computer></System>` dạng text node con thay vì chỉ kiểm tra attribute.
  + Chuẩn hóa việc trích xuất các trường định danh `SubjectUserName`, `TargetUserName`, `NewProcessName` và `CommandLine`.
- **Xây dựng module huấn luyện Baseline (`train_baseline.py`):**
  + Phát triển script nạp offline các tệp EVTX, phân tích cú pháp sự kiện và học hồ sơ thói quen của người dùng và máy trạm (tần suất loại sự kiện, khung giờ hoạt động, danh sách tiến trình và câu lệnh thường dùng).
  + Xuất và đóng băng hồ sơ hành vi vào tệp `globalban-baseline.json`.
- **Mở rộng nguồn tri thức RAG cục bộ (`src/globalban/ai/dataset_context.py`):**
  + Tích hợp thêm tri thức kỹ thuật tấn công từ MITRE ATT&CK Windows (`attack_techniques.csv`).
  + Tổ chức tìm kiếm độc lập trên cả 3 nguồn tri thức: AD-GEN, WinLOLBIN-GT và MITRE ATT&CK phục vụ tạo context tham khảo cho AI Agent.

## 2. Kết quả

- Bộ parser xử lý chuẩn xác 100% định danh máy tính và tài khoản từ log Windows thực tế của máy `DESKTOP-3K305I1`.
- Script `train_baseline.py` đọc và chuẩn hóa thành công 2.725 sự kiện từ `PowerShell.evtx` (725 sự kiện) và `Security.evtx` (2.000 sự kiện), tạo lập thành công hồ sơ hành vi `globalban-baseline.json` ở trạng thái đóng băng (`Frozen = True`).
- Toàn bộ 52/52 bài kiểm thử tự động (unit tests) đều vượt qua.

## 3. Khó khăn và tồn đọng

- Các tệp nhật ký nhị phân `.evtx` có dung lượng tương đối lớn (>15-18MB), lệnh `Get-WinEvent` của PowerShell dễ bị quá thời gian chờ (timeout) nếu xuất toàn bộ tệp mà không giới hạn số lượng.
- Bộ nạp dữ liệu RAG `ADGenPreprocessor` gặp lỗi giới hạn độ dài trường CSV (`field larger than field limit`) khi đọc các đoạn narrative phân tích sự cố dài trong tệp mẫu `adgen_sample.csv`.
- Chưa có script tích hợp chạy từ đầu đến cuối (End-to-End) để tự động xuất bảng so sánh hiệu năng phát hiện giữa luật tĩnh (Sigma) và mô hình chuỗi hành vi (UEBA).

## 4. Hướng phát triển tiếp theo

- Bổ sung cơ chế giới hạn số lượng sự kiện (`max_events`) và tối ưu lệnh PowerShell đọc EVTX để tránh nghẽn luồng xử lý.
- Cấu hình mở rộng giới hạn bộ nhớ đọc CSV (`csv.field_size_limit`) trong module AI dataset context.
- Xây dựng pipeline đánh giá định lượng so sánh hiệu năng phát hiện (Precision, Recall, F1-Score, FPR) giữa Sigma và UEBA kèm kích hoạt AI Agent.
- Nâng cấp giao diện desktop và xây dựng bộ lắng nghe thời gian thực để sẵn sàng kết nối khi Red Team cập nhật các đợt tấn công tiếp theo.
