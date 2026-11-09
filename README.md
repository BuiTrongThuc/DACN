# Bộ thu thập dữ liệu Windows cho Red Team

Kho lưu trữ này phục vụ việc thu thập dữ liệu đã được phê duyệt trên máy ảo
Windows cô lập. Kho được tách khỏi dự án phát hiện để đội Red Team có thể sao
chép vào máy kiểm thử.

## Sao chép và mở bằng VS Code

```powershell
git clone https://github.com/BuiTrongThuc/DACN.git
cd DACN
code .
```

Mở terminal PowerShell trong VS Code. Chỉ chạy các bài kiểm thử đã được người
phụ trách dự án phê duyệt. Không chạy kho này trên hệ thống sản xuất.

## Quy trình Red Team

Chạy kiểm tra môi trường trước khi thu thập dữ liệu:

```powershell
.\scripts\preflight.ps1
```

Thu thập ảnh chụp đường cơ sở trong một vài ngày hoạt động bình thường. Trước
mỗi bài kiểm thử Atomic Red Team đã được phê duyệt, hãy dùng mã ca duy nhất và
ghi lại kỹ thuật cùng số bài kiểm thử. Bộ bao yêu cầu cờ phê duyệt rõ ràng, ghi
thời gian UTC và thu thập các tệp EVTX sau khi kiểm thử:

```powershell
.\scripts\run_approved_atomic.ps1 `
	-CaseId atomic-T1059-001-test-01 `
	-TechniqueId T1059.001 `
	-TestNumbers 1 `
	-Approved
```

Chỉ sử dụng đúng kỹ thuật và số bài kiểm thử đã được người phụ trách phê duyệt.

## Thu thập nhật ký Windows

Mở PowerShell với quyền cần thiết cho các kênh sự kiện:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\collect_windows_logs.ps1 -CaseId baseline-day-01 -Kind baseline
```

Sau một bài kiểm thử Atomic Red Team đã được phê duyệt:

```powershell
.\scripts\collect_windows_logs.ps1 -CaseId atomic-T1059-001-test-01 -Kind atomic
```

Tập lệnh xuất các tệp EVTX và mã băm SHA256 vào `artifacts/`. Tập lệnh không
thực hiện tấn công và không thay đổi chính sách kiểm tra Windows.

## Ghi nhận ca kiểm thử

Sao chép `metadata/cases.example.jsonl` thành `metadata/cases.jsonl` rồi thay
giá trị mẫu bằng giá trị thực tế. Sao chép
`metadata/sigma-results.example.jsonl` thành `metadata/sigma-results.jsonl` và
ghi kết quả Sigma cho cùng các mã ca. Ghi một dòng cho mỗi ca đường cơ sở hoặc
Atomic Red Team. Không ghi mật khẩu, token, khóa riêng tư hoặc toàn bộ bí mật
của lệnh.

Sau khi đã có đầy đủ ca kiểm thử và mã băm, hãy kiểm tra việc bàn giao:

```powershell
.\scripts\validate_handoff.ps1
```

Gửi cho đội còn lại:

- `artifacts/baseline/<case-id>/*.evtx`
- `artifacts/atomic/<case-id>/*.evtx`
- `artifacts/hashes/*.csv`
- `metadata/cases.jsonl`
- Phiên bản Windows, Sysmon và PowerShell
- Mã bài kiểm thử Atomic đã phê duyệt cùng thời gian bắt đầu/kết thúc
- Kết quả Sigma dùng cùng các mã ca

EVTX và siêu dữ liệu thực tế được Git bỏ qua. Hãy chuyển chúng riêng qua kênh
bảo mật đã thống nhất; không commit chúng lên GitHub.
