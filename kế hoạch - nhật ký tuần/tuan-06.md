# Báo cáo công việc tuần 06

**Thời gian:** 16/11/2026 - 22/11/2026
**Dự án:** GlobalBan - hệ thống giám sát SSH và hành vi Windows
**Người thực hiện:** Nhóm sinh viên

## 1. Công việc đã thực hiện

- **Khắc phục triệt để các lỗi Ingestion và Baseline:**
  + *Tối ưu hóa đọc EVTX (`src/globalban/ingestion/evtx.py`):* Bổ sung tham số `max_events=2000`, nhúng trực tiếp đường dẫn xử lý vào script PowerShell tránh lỗi phân tích tham số command-line và nâng timeout lên 180 giây, loại bỏ hoàn toàn lỗi timeout khi đọc các tệp log lớn.
  + *Xử lý triệt để bộ nhớ đệm Python (`__pycache__`):* Xóa sạch các file `.pyc` cũ lưu vết lỗi thụt lề (indentation) của `WinLolbinPreprocessor`, đảm bảo các class RAG khởi tạo thông suốt.
  + *Nâng dung lượng đọc dữ liệu RAG (`src/globalban/ai/dataset_context.py`):* Thiết lập `csv.field_size_limit(10_000_000)` giải quyết lỗi tràn bộ đệm đọc các đoạn văn bản phân tích dài trong dataset AD-GEN.
  + *Sửa lỗi lưu trữ và làm mới Baseline (`src/globalban/detection/baseline.py`):* Bổ sung lưu/phục hồi cờ `frozen` vào tệp JSON; đồng thời cấu hình phương thức `fit()` tự động làm sạch (reset/clear) các counter trước khi học để tránh hiện tượng cộng dồn mẫu trùng lặp, đảm bảo dữ liệu học luôn chuẩn xác ở mức 2.725 sự kiện.
- **Xây dựng và hoàn thiện Pipeline đánh giá (`run_evaluation_pipeline.py`):**
  + Tự động nạp hồ sơ Baseline đã học từ `globalban-baseline.json`.
  + Nạp và chuẩn hóa 2.725 sự kiện kiểm thử từ `data/atomic/` (`PowerShell.evtx` và `Security.evtx`).
  + Chạy phân tích chuỗi tương quan (`SequenceCorrelator` kết hợp `BehaviorBaseline`), bắt thành công 272 cảnh báo hành vi nguy hiểm vượt ngưỡng (Score ≥ 60/100, trong đó có các cảnh báo đạt 80 - 95/100 liên quan đến thao tác can thiệp audit log và khởi tạo tiến trình bất thường).
  + Thực hiện đối chiếu định lượng tự động giữa Luật tĩnh (Sigma Rules) và Mô hình hành vi (UEBA + Correlator), xuất bảng chỉ số hiệu năng (Precision, Recall, F1-Score, FPR).
  + Tự động truy vấn tri thức đối chiếu RAG nội bộ (AD-GEN, WinLOLBIN-GT, MITRE ATT&CK) và kích hoạt AI Agent sinh khuyến nghị phòng thủ (chế độ Offline Heuristic Advisory và hỗ trợ gọi trực tiếp qua Gemini / OpenAI API).
- **Phát triển Module Giám sát Thời gian thực (`live_monitor.py`):**
  + Xây dựng engine giám sát realtime đa kênh: liên tục quét các kênh Windows Event Log trọng yếu (`Security`, `Microsoft-Windows-PowerShell/Operational`, `System`, `Microsoft-Windows-Sysmon/Operational`) với chu kỳ 5 giây, cửa sổ nhìn lại 15 giây.
  + Hiển thị cảnh báo trực quan ra màn hình console bằng mã màu ANSI: phân loại mức cảnh báo WARNING (Score 60–89) và CRITICAL (Score ≥ 90).
  + Tự động lưu vết toàn bộ sự kiện và cảnh báo phát hiện vào tệp nhật ký `globalban-live-alerts.jsonl`.
- **Nâng cấp Giao diện Desktop Dashboard (`src/globalban/app.py`):**
  + Thiết kế thêm trang giám sát chuyên biệt **"🔴 05 LIVE RED TEAM"** nổi bật trên thanh điều hướng sidebar.
  + Tích hợp cơ chế tự động cập nhật dữ liệu nền (Auto-refresh mỗi 3 giây) đọc từ file `globalban-live-alerts.jsonl`.
  + Bố trí các thẻ thống kê tổng quan trực quan: Tổng cảnh báo, Cảnh báo Critical, Cảnh báo High, Sự kiện gần nhất.
  + Bổ sung bảng nhật ký cảnh báo thời gian thực có phân loại màu sắc (đỏ đậm cho Critical, vàng cho High, xanh cho sự kiện thường) kèm thanh cuộn mượt mà.
  + Tích hợp cửa sổ bật lên (Popup modal) cảnh báo đỏ tức thì ngay khi xuất hiện hành vi tấn công mức CRITICAL.
  + Tích hợp nút bấm *"Khởi động Live Monitor"* trực tiếp từ giao diện để tự động mở tiến trình giám sát nền trong cửa sổ console riêng.
- **Tình hình phối hợp với Red Team:**
  + Đội ngũ Red Team đã thực thi xong đợt tấn công ban đầu và đã chuyển giao toàn bộ log kiểm thử để xây dựng bộ đánh giá.
  + Hiện tại Red Team đang tiếp tục cập nhật (update) các kịch bản tấn công mới và phức tạp hơn (Persistence thông qua Scheduled Tasks/Registry Run keys, Defense Evasion bằng obfuscated PowerShell, dump credential bộ nhớ LSASS).
  + Phía Blue Team đã hoàn thiện hạ tầng tiếp nhận và giao diện cảnh báo real-time, sẵn sàng nhận diện và phát tín hiệu cảnh báo tức thì ngay khi Red Team kích hoạt các payload mới.

## 2. Kết quả đạt được

- **Kết quả huấn luyện Baseline (`train_baseline.py`):**
  + Tổng số sự kiện huấn luyện: 2.725 sự kiện.
  + Định danh máy tính: `DESKTOP-3K305I1`.
  + Danh sách tài khoản: `MAIN`, `redtest`, `SYSTEM`, `LOCAL SERVICE`, `DESKTOP-3K305I1$`,...
  + Trạng thái: Đã đóng băng (`Frozen = True`), không bị ô nhiễm khi nạp log kiểm thử.
- **Bảng so sánh hiệu năng phát hiện (Sigma vs UEBA):**

```text
================================================================================
PHƯƠNG PHÁP            | PRECISION  | RECALL   | F1-SCORE  | FPR    | KẾT QUẢ
--------------------------------------------------------------------------------
Sigma Rules            | 1.00       | 1.00     | 1.00      | 0.00   | PHÁT HIỆN
UEBA + Correlator      | 1.00       | 1.00     | 1.00      | 0.00   | PHÁT HIỆN
================================================================================
```

- **Chất lượng mã nguồn:** Toàn bộ 52/52 unit tests đều vượt qua thành công (`52 passed in 0.46s`). Cú pháp toàn bộ các module mới và cập nhật đều đạt chuẩn.

## 3. Khó khăn và tồn đọng

- Mô hình AI Agent hiện chủ yếu chạy ở chế độ Offline Heuristic Advisory do cần người dùng nạp biến môi trường API Key thực tế để kết nối mô hình trực tuyến ngoài Internet.
- Cần tiếp tục theo dõi độ trễ phát hiện (detection latency) khi Red Team chạy liên tục các kịch bản real-time trên môi trường mạng máy ảo.

## 4. Kế hoạch tiếp theo (Sắp làm)

- **Đấu nối kiểm thử trực tiếp đợt cập nhật của Red Team:** Phối hợp cùng Red Team kích hoạt các kịch bản tấn công mới theo thời gian thực, đo đạc độ trễ phản hồi của module `live_monitor.py` và bảng điều khiển `app.py`.
- **Kích hoạt LLM API trực tiếp:** Thiết lập API Key (Gemini 2.5 Flash / OpenAI) để kiểm chứng khả năng AI Agent sinh báo cáo điều tra sự cố (Incident Investigation Report) hoàn chỉnh với đầy đủ MITRE ATT&CK mapping và giả thuyết tấn công.
- **Hoàn thiện cơ chế phản ứng tự động có kiểm soát (Active Mitigation):** Đấu nối module chặn tường lửa Windows Firewall (chế độ Live) dựa trên quyết định từ Policy Gate khi phát hiện rủi ro mức độ Critical, bảo đảm có audit và cơ chế rollback.
- **Hoàn thiện tài liệu và báo cáo đồ án:** Tổng hợp toàn bộ số liệu đo lường thực nghiệm, hoàn thiện các biểu đồ so sánh và tài liệu hướng dẫn vận hành cho đồ án.
