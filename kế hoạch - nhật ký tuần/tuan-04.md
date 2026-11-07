# Báo cáo công việc tuần 04

**Thời gian:** 02/11/2026 - 08/11/2026
**Dự án:** GlobalBan - hệ thống giám sát SSH và hành vi Windows
**Người thực hiện:** Nhóm sinh viên

## 1. Nội dung khắc phục

- Bổ sung metadata cho bộ `windows_eval_labels.jsonl`, gồm phiên bản schema,
  nguồn dữ liệu, chính sách gắn nhãn, bộ lọc và xác nhận đây chưa phải dữ liệu
  đại diện cho production.
- Bổ sung `AgentRuntime` theo mô hình plan-first: agent lập kế hoạch trước,
  chỉ gọi tên tool nằm trong allowlist và từ chối tool không đăng ký.
- Bổ sung audit cho từng kế hoạch và từng lần function-calling, ghi rõ tool,
  trạng thái approval, kết quả và lỗi.
- Bổ sung test cho function-calling có giới hạn quyền và test kiểm tra audit.
- Cập nhật lại phần đánh giá: kết quả sample chỉ xác nhận protocol, chưa được
  dùng để kết luận hiệu năng hệ thống.

## 2. Kết quả kiểm chứng

- Bộ test hiện tại đạt 46/46 test.
- Function-calling hợp lệ được thực thi qua `ToolRegistry`; tên tool không có
  trong allowlist bị từ chối rõ ràng.
- Mọi lần lập kế hoạch và gọi tool đều có thể truy vết trong audit JSONL.
- Công cụ đánh giá vẫn tạo được báo cáo precision, recall, F1 và
  false-positive rate từ dữ liệu có nhãn.

## 3. Phần chưa hoàn thành

- Chưa có EVTX/JSON production được review độc lập và chưa thể công bố metric
  production.
- Chưa chạy E2E trên máy Windows thật có đủ Security, PowerShell, Sysmon và
  Defender; cần hoàn thành sau khi dựng VM Windows cô lập.
- Chưa bật agent tự tạo commit hoặc tự push. Đây là giới hạn an toàn vì cần
  sandbox, diff review, allowlist thay đổi và rollback trước khi cho phép.

## 4. Hướng phát triển tiếp theo

- Dựng VM Windows có snapshot, cô lập mạng và bật từng channel có kiểm soát để
  chạy E2E red team bên ngoài dự án.
- Nối các handler đọc/điều tra tin cậy vào runtime, sau đó bổ sung handler hành
  động có approval và audit riêng.
- Mở rộng function-calling theo schema cố định, giới hạn tham số và timeout.
- Xây dựng sandbox tạo diff; chỉ cho phép tạo commit sau khi test, review và
  rollback đều đạt.
