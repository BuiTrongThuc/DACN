# QUY TRÌNH THU THẬP EVTX, CHẠY ATOMIC RED TEAM & QUÉT SIGMA THỰC TẾ (`scripts/`)

Bên cạnh bộ sinh giả lập bằng Python, dự án `attack-globalban` cung cấp đầy đủ bộ **PowerShell Red Team Toolkit** nằm trong thư mục [scripts/](file:///c:/Users/PC1/attack-globalban/scripts) để thực hiện thu thập dữ liệu thực nghiệm trên máy ảo Windows (Windows VM), quét luật Sigma và đóng gói bàn giao cho nhóm phân tích (Blue Team).

---

## 1. Danh Sách Các Script Trong Thư Mục `scripts/`

| Tên file script | Chức năng chính |
| :--- | :--- |
| **[preflight.ps1](file:///c:/Users/PC1/attack-globalban/scripts/preflight.ps1)** | Kiểm tra điều kiện máy ảo trước khi thực nghiệm: ghi nhận `hostname`, `username`, phiên bản `Windows`, `PowerShell`, `Sysmon`, múi giờ và kiểm tra trạng thái khả dụng của 4 kênh Event Log (`Security`, `Sysmon`, `PowerShell`, `Defender`) vào `metadata/environment.json`. |
| **[collect_windows_logs.ps1](file:///c:/Users/PC1/attack-globalban/scripts/collect_windows_logs.ps1)** | Xuất 4 kênh Windows Event Log ra file `.evtx` theo đúng khoảng thời gian của từng `case_id`, tự động tính mã băm toàn vẹn `SHA256` lưu vào `hashes/<case_id>.csv` và ghi nhận dòng metadata vào `metadata/cases.jsonl`. |
| **[collect_windows_vm_logs.ps1](file:///c:/Users/PC1/attack-globalban/scripts/collect_windows_vm_logs.ps1)** | Xuất trực tiếp các sự kiện từ Windows Event Log (`Security`, `Sysmon`, `PowerShell`, `System`) ra định dạng file `.xml` hợp nhất để nạp thẳng vào `globalban.main --learn-baseline` hoặc `--windows-xml`. |
| **[run_approved_atomic.ps1](file:///c:/Users/PC1/attack-globalban/scripts/run_approved_atomic.ps1)** | Thực thi các bài kiểm thử **Atomic Red Team** có kiểm soát an toàn: bắt buộc phải có cờ `-Approved`, mã kỹ thuật `-TechniqueId` và số thứ tự bài test `-TestNumbers`; tự động ghi giờ bắt đầu/kết thúc UTC, chạy bài test, dọn dẹp (`Cleanup`) và gọi `collect_windows_logs.ps1` để xuất `.evtx` + `SHA256`. |
| **[Invoke-AtomicRedTeam.psm1](file:///c:/Users/PC1/attack-globalban/scripts/Invoke-AtomicRedTeam.psm1)** | Module thực thi các bài test Atomic Red Team cục bộ an toàn (có thể thu hồi/hoàn tác 100% sau khi chạy) dành cho môi trường máy ảo không cần kết nối Internet. |
| **[run_sigma_on_evtx.ps1](file:///c:/Users/PC1/attack-globalban/scripts/run_sigma_on_evtx.ps1)** | Quét cùng một bộ luật **Sigma** trực tiếp trên toàn bộ các file `.evtx` của từng `case_id` (cả `baseline` và `atomic`) và xuất kết quả phát hiện (`predicted_detected`, `rule_id`, `match_count`) vào `metadata/sigma-results.jsonl`. |
| **[validate_handoff.ps1](file:///c:/Users/PC1/attack-globalban/scripts/validate_handoff.ps1)** | Kiểm tra chéo toàn bộ tính toàn vẹn của dữ liệu (đủ tối thiểu 3–7 ngày baseline, có case atomic, khớp mã băm SHA256, không trùng lặp `case_id`, có kết quả Sigma) và tự động đóng gói thư mục `redteam-export/` kèm `README.txt` để bàn giao. |

---

## 2. Hướng Dẫn Thực Hành Quy Trình 8 Bước Chuẩn Red Team

> [!IMPORTANT]
> Mở **PowerShell bằng quyền Quản trị viên (Run as Administrator)** tại thư mục `c:\Users\PC1\attack-globalban` để Windows cho phép xuất kênh nhật ký bảo mật `Security`.

### Bước 1 & 2: Tạo Snapshot máy ảo & Kiểm tra môi trường (`preflight.ps1`)
Trước khi làm bất kỳ thao tác nào, tạo Snapshot cho máy ảo Windows, sau đó chạy lệnh:
```powershell
.\scripts\preflight.ps1
```
- **Tác dụng**: Tạo cấu trúc thư mục làm việc và xuất file `metadata/environment.json` ghi rõ cấu hình máy, phiên bản hệ điều hành, PowerShell, Sysmon và trạng thái 4 kênh log.

---

### Bước 3: Thu thập Baseline bình thường (Tối thiểu 3 ngày, khuyến nghị 7 ngày)
Trong giai đoạn thu thập Baseline, chỉ sử dụng máy ảo cho các tác vụ bình thường (soạn thảo văn bản, duyệt web, quản trị cơ bản) và **tuyệt đối không chạy Atomic Red Team**. Cuối mỗi ngày, xuất log của ngày đó với mã `case_id` riêng:
```powershell
.\scripts\collect_windows_logs.ps1 -CaseId baseline-day-01 -Kind baseline
.\scripts\collect_windows_logs.ps1 -CaseId baseline-day-02 -Kind baseline
.\scripts\collect_windows_logs.ps1 -CaseId baseline-day-03 -Kind baseline
# Tiếp tục cho tới baseline-day-07
```
- **Tác dụng**:
  - Xuất các file `Security.evtx`, `Sysmon.evtx`, `PowerShell.evtx`, `Defender.evtx` vào `baseline/<case_id>/`.
  - Tạo file băm SHA256 tại `hashes/<case_id>.csv`.
  - Ghi nhãn chuẩn `"expected_detected": false` vào `metadata/cases.jsonl`.

---

### Bước 4, 5 & 6: Chạy Atomic Red Team đã được phê duyệt & Xuất EVTX theo `case_id`
Chỉ chạy các kỹ thuật đã được người hướng dẫn phê duyệt bằng cách truyền đầy đủ `-CaseId`, `-TechniqueId`, `-TestNumbers` và cờ `-Approved`:

```powershell
# Ví dụ 1: Chạy kỹ thuật T1059.001 (PowerShell Encoded/Execution) - Bài test số 1
.\scripts\run_approved_atomic.ps1 `
  -CaseId atomic-T1059-001-test-01 `
  -TechniqueId T1059.001 `
  -TestNumbers 1 `
  -Approved

# Ví dụ 2: Chạy kỹ thuật T1053.005 (Scheduled Task Persistence) - Bài test số 1
.\scripts\run_approved_atomic.ps1 `
  -CaseId atomic-T1053-005-test-01 `
  -TechniqueId T1053.005 `
  -TestNumbers 1 `
  -Approved
```
- **Tác dụng**:
  - Tự động ghi nhận thời gian `start_utc` và `end_utc` chính xác quanh thời điểm thực thi kỹ thuật tấn công.
  - Tự động dọn dẹp (`Cleanup`) các tác vụ/file tạm sau khi test xong.
  - Xuất riêng bộ `.evtx` trong đúng khung thời gian diễn ra tấn công vào `atomic/<case_id>/`, băm `SHA256` và ghi `"expected_detected": true` vào `metadata/cases.jsonl`.

---

### Bước 7: Chạy cùng bộ luật Sigma trên toàn bộ các file EVTX (`run_sigma_on_evtx.ps1`)
Sau khi đã có đủ các case `baseline` và `atomic`, chạy bộ quét Sigma:
```powershell
.\scripts\run_sigma_on_evtx.ps1
```
- **Tác dụng**:
  - Quét trực tiếp các file `.evtx` của từng case bằng bộ luật Sigma chuẩn.
  - Xuất kết quả ra `metadata/sigma-results.jsonl` theo đúng định dạng chuẩn để so sánh với GlobalBan:
    ```json
    {"case_id":"baseline-day-01","predicted_detected":false,"rule_id":null,"match_count":0}
    {"case_id":"atomic-T1059-001-test-01","predicted_detected":true,"rule_id":"sigma-win-powershell-encoded-scriptblock-4104","match_count":5}
    ```

---

### Bước 8: Kiểm tra toàn vẹn & Đóng gói bàn giao (`validate_handoff.ps1`)
Chạy lệnh kiểm tra cuối cùng trước khi bàn giao dữ liệu cho nhóm phát hiện:
```powershell
.\scripts\validate_handoff.ps1
```
- **Tác dụng**:
  - Kiểm tra mọi `case_id` trong `cases.jsonl` đều có thư mục `.evtx` và bảng băm `hashes/<case_id>.csv` khớp 100%.
  - Tự động tổng hợp gói bàn giao hoàn chỉnh tại thư mục `redteam-export/`:
    ```text
    redteam-export/
      baseline/<case_id>/*.evtx
      atomic/<case_id>/*.evtx
      metadata/cases.jsonl
      metadata/sigma-results.jsonl
      metadata/environment.json
      hashes/*.csv
      README.txt
    ```
  - Lưu ý bảo mật: File [.gitignore](file:///c:/Users/PC1/attack-globalban/.gitignore) đã được cấu hình để **chặn không cho commit các file `.evtx` thật, file hash `.csv` và thư mục `redteam-export/` lên GitHub**, đảm bảo tuân thủ tuyệt đối quy tắc an toàn dữ liệu của Red Team.
