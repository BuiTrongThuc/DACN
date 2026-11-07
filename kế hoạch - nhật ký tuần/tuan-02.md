# Báo cáo công việc tuần 02

**Thời gian:** 19/10/2026 - 24/10/2026
**Dự án:** GlobalBan - hệ thống giám sát SSH và hành vi Windows
**Người thực hiện:** Nhóm sinh viên

## 1. Công việc đã thực hiện

- Bổ sung giám sát Windows Event Log qua PowerShell cho Security, System,
  PowerShell, Sysmon và Windows Defender.
- Chuẩn hóa và tương quan sự kiện theo cửa sổ thời gian, kết hợp rule-based
  scoring với local frequency baseline.
- Bổ sung phát hiện brute force nhanh, slow-and-low, password spraying, user
  không tồn tại, tấn công phân tán và đăng nhập thành công sau thất bại.
- Hoàn thiện desktop monitor ở chế độ dry-run.
- Xây dựng AI advisory và egress proxy; AI chỉ nhận evidence đã chuẩn hóa, che
  IP và giới hạn dữ liệu.
- Tích hợp AD-GEN và WinLOLBIN-GT làm dữ liệu tham khảo cục bộ cho AI phân tích
  tình huống, không coi các dataset này là ground truth.
- Bổ sung tooling chuẩn bị dữ liệu WinLOLBIN-GT và cập nhật test/config.

## 2. Kết quả

```text
Windows Event Log/fixture -> normalized event -> correlation
-> sequence score/baseline -> RiskCandidate -> AI advisory -> policy/action
```

Có fixture Windows tổng hợp để replay an toàn. Fixture không thực thi lệnh và
không mô phỏng tấn công thật. Các hành động rủi ro vẫn qua approval gate,
dry-run, audit và rollback.

## 3. Khó khăn

- Chưa có EVTX/JSON gắn nhãn đầy đủ để đánh giá định lượng.
- Baseline hiện là local frequency baseline, chưa phải mô hình machine learning.
- Dataset lớn cần được quản lý bằng artifact store hoặc Git LFS sau khi xác nhận
  license.
- Chưa có môi trường Windows riêng để thực nghiệm red team an toàn.

## 4. Hướng tiếp theo

- Xây dựng protocol đánh giá có label và báo cáo metric tái lập.
- Viết tài liệu vận hành Windows và dataset.
- Dựng máy ảo Windows cô lập để thực nghiệm red team bên ngoài dự án.
- Phát triển dần từ AI advisory sang AI agent có tool allowlist và kiểm soát
  quyền.