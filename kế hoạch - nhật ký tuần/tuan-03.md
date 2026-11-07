# Báo cáo công việc tuần 03

**Thời gian:** 02/11/2026 - 07/11/2026
**Dự án:** GlobalBan - hệ thống giám sát SSH và hành vi Windows
**Người thực hiện:** Nhóm sinh viên

## 1. Công việc đã thực hiện

- Bổ sung AI advisory với schema severity, confidence, evidence, hypothesis,
  ATT&CK reference, missing data và recommendation.
- Bổ sung privacy masking, egress proxy và giới hạn dữ liệu gửi ra ngoài.
- Tích hợp AD-GEN và WinLOLBIN-GT theo cơ chế tìm kiếm bounded local context;
  dữ liệu chỉ là tham khảo, không được xem là ground truth.
- Bổ sung catalog Atomic-EVTX và metric precision, recall, F1, false-positive
  rate.
- Tạo protocol JSONL có label, sample `datasets/windows_eval_labels.jsonl`,
  CLI `globalban-evaluate` và test tái lập.
- Tạo `AgentRuntime` theo nguyên tắc plan-first: agent chỉ gọi tool có trong
  allowlist; mặc định chỉ lập kế hoạch, còn thực thi phải bật rõ ràng và vẫn
  chịu kiểm soát approval.
- Bổ sung hướng dẫn vận hành Windows, fixture replay, dataset/license và
  approval/rollback tại `docs/OPERATIONS.md`.
- Cập nhật chính sách quản lý dataset lớn: không commit raw dataset không rõ
  license; dùng artifact store hoặc Git LFS khi được phê duyệt.

## 2. Kết quả

Đã chuyển dự án từ prototype phát hiện sang nền tảng agent có kiểm soát:

```text
log -> parser -> detector -> RiskCandidate -> AI advisory
    -> allowlisted tool plan -> policy gate -> dry-run/approved action
    -> audit/rollback -> evaluation report
```

## 3. Hạn chế và phần còn vướng

- Sample label hiện chỉ xác nhận protocol, chưa đại diện hiệu năng production.
- Cần bổ sung EVTX/JSON có label được review độc lập và metadata version/filter.
- Cần chạy E2E trên Windows thật với các channel đã bật.
- Agent runtime hiện mới điều phối tool nội bộ; các handler thực tế, vòng
  function-calling với AI và cơ chế tự tạo commit chưa được bật.

## 4. Hướng phát triển tiếp theo

- Dựng máy ảo Windows riêng, cô lập mạng và snapshot trước khi thực nghiệm
  red team; đây là môi trường thực nghiệm bên ngoài, không phải red-team test
  module trong dự án.
- Nối các handler tin cậy vào agent runtime, bổ sung audit cho từng lần gọi và
  kiểm thử function-calling có giới hạn quyền.
- Chỉ xem xét tự động tạo commit sau khi có sandbox, diff review, allowlist và
  cơ chế rollback; không cho agent tự ý đẩy thay đổi chưa kiểm tra.
