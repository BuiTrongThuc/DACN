# Báo cáo công việc tuần 01

**Thời gian:** 14/10/2026 - 18/10/2026
**Dự án:** GlobalBan - hệ thống giám sát SSH và hành vi Windows
**Người thực hiện:** Nhóm sinh viên

## 1. Công việc đã thực hiện

- Củng cố luồng khởi động, cấu hình và xử lý sự kiện đăng nhập SSH.
- Bổ sung các thành phần nền tảng cho Windows ingestion và chuẩn hóa
  `WindowsEvent`.
- Hoàn thiện policy, action, audit và rollback theo hướng dry-run trước khi cho
  phép thay đổi firewall.
- Bổ sung test nền cho parser, aggregator, policy guard, action và rollback.

## 2. Kết quả

Nhóm đã có pipeline nền tảng từ log đầu vào đến risk candidate và action path:

```text
SSH/Windows log -> parser -> detection -> policy -> action -> audit
```

Các hành động nguy hiểm được giữ ở chế độ dry-run hoặc yêu cầu phê duyệt.

## 3. Khó khăn

- Event Windows thực tế phụ thuộc edition, provider và audit policy.
- Chưa có dữ liệu Windows có nhãn để đo precision, recall và F1.
- Cần tiếp tục kiểm tra tính tương thích giữa các nguồn log SSH và Windows.

## 4. Hướng tiếp theo

- Hoàn thiện Windows Event Log adapter và sequence detection.
- Bổ sung các tình huống đăng nhập bất thường và persistence.
- Xây dựng fixture an toàn để replay thay cho việc thử trực tiếp trên máy thật.