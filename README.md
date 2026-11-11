# GlobalBan

GlobalBan là công cụ phát hiện hành vi bất thường trên Windows theo hướng
phòng thủ và có thể giải thích. Công cụ đọc Windows Event Log qua PowerShell,
xây dựng đường cơ sở theo từng người dùng và máy, liên kết các sự kiện bảo
mật thành chuỗi hành vi, rồi tạo bằng chứng để agent giải thích vì sao một
hoạt động lệch khỏi thói quen. Phần SSH được giữ để tương thích với mã cũ,
nhưng không còn là trọng tâm đánh giá của đề tài.

## Yêu cầu

- Python 3.10 trở lên
- PyYAML

## Cài đặt

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -e ".[dev]"
Copy-Item .env.example .env
Copy-Item config\config.example.yaml config\config.yaml
```

Trên Linux/macOS, kích hoạt môi trường bằng
`source .venv/bin/activate`.

Trên Windows 11, dùng `py -m venv .venv` và
`.venv\\Scripts\\Activate.ps1`. Nguồn Windows Event Log sử dụng
`powershell.exe` tích hợp sẵn, không cần cài thêm gói sự kiện Windows.

## Cấu hình và chạy

Chỉnh sửa `config/config.yaml`, đặt `ingestion.source: windows_event_log` và
cấu hình các kênh Windows cần thu thập. Trước tiên hãy chạy ở chế độ mô
phỏng:

```powershell
globalban --config config/config.yaml --dry-run
```

Theo mặc định, thay đổi tường lửa bị vô hiệu hóa. Muốn bật, hãy cấu hình lệnh
tường lửa cho hệ điều hành, đặt `actions.dry_run: false` và chạy với quyền
phù hợp. Hãy xem lại lệnh và thử trên hệ thống tạm trước khi bật.

Bản ghi XML Windows Security Event 4625 cũng được bộ phân tích tiếp nhận. Khi
vượt ngưỡng thất bại đã cấu hình, ứng dụng AI tùy chọn chỉ nhận mạng đã che
thông tin và các số liệu tổng hợp thông qua proxy Ubuntu; nhật ký Windows thô
không bao giờ được gửi tới API.

Có thể cung cấp bí mật cấu hình qua biến môi trường; xem `.env.example`. Ứng
dụng tải `.env` từ thư mục hiện tại hoặc thư mục gốc của kho mã nếu biến chưa
được đặt. Cũng có thể dùng cơ chế quản lý bí mật của trình quản lý tiến trình.
Thông báo WhatsApp và phần giải thích AI tùy chọn bị tắt nếu chưa cấu hình.

## Giám sát sự kiện Windows

Để đọc các kênh Windows theo thời gian thực, cấu hình:

```yaml
ingestion:
	source: windows_event_log
	poll_interval_seconds: 5
	log_names:
		- Security
		- System
		- Microsoft-Windows-PowerShell/Operational
		- Microsoft-Windows-Sysmon/Operational
		- Microsoft-Windows-Windows Defender/Operational
```

Chạy từ PowerShell đã nâng quyền khi kênh được cấu hình yêu cầu:

```powershell
globalban --config config/config.yaml --dry-run
```

Bộ điều hợp sử dụng `Get-WinEvent`, không bật chính sách kiểm tra, cài Sysmon
hay thay đổi Windows. Hãy cấu hình riêng và có chủ đích. Khả năng có sẵn của
sự kiện phụ thuộc vào phiên bản Windows, cấu hình nhà cung cấp, chính sách
kiểm tra, luật Sysmon và cài đặt Defender.

Để phát lại fixture an toàn, dùng `datasets/windows_events.xmll`. File chỉ
chứa IP dùng cho tài liệu và sự kiện tổng hợp; không thực thi lệnh hay cuộc
tấn công thật. Kiểm thử hồi quy phát lại nằm trong
`tests/test_windows_fixture.py`.

## Quy trình phát hiện

Quy trình hiện được triển khai:

```text
Windows Event Log hoặc fixture
	-> WindowsEvent đã chuẩn hóa
	-> lọc trùng lặp và liên kết theo cửa sổ thời gian
	-> điểm chuỗi theo luật và đường cơ sở user/máy
	-> RiskCandidate có thể kiểm toán
	-> tư vấn Gemini tùy chọn qua proxy Ubuntu
	-> luồng chính sách/hành động mô phỏng hiện có cho ứng viên IP SSH
```

Bộ phát hiện chuỗi hiện có các luật dễ giải thích cho đăng nhập/tiến trình,
quyền hạn/tiến trình, duy trì bám trụ, thay đổi nhật ký kiểm tra, cảnh báo mã
độc hại và một số chỉ báo lệnh PowerShell/Sysmon. Đường cơ sở là đường cơ sở
tần suất theo user/máy trong giai đoạn làm nóng, được lưu tại
`globalban-baseline.json`;
đây không phải mô hình ML đã huấn luyện và dự án không tuyên bố kết quả
precision, recall hay F1 nếu chưa có dữ liệu gắn nhãn.

Các sự kiện xác thực Windows cũng dùng bộ phát hiện hành vi liên tục trong 24
giờ. Bộ phát hiện bao phủ brute force nhanh, tấn công chậm, tự động hóa định
kỳ, password spraying, dò tài khoản không tồn tại, tấn công phân tán vào một
người dùng và đăng nhập thành công sau nhiều lần thất bại. Kết quả được phát
ra dưới dạng các ứng viên rủi ro có thể giải thích giống luồng chính sách và
kiểm toán hiện có.

File trạng thái được cấu hình bằng `detection.behavior_state_path`. Bộ phát
hiện không bỏ qua danh sách cho phép, chế độ mô phỏng, cổng phê duyệt hay bộ
điều hợp hành động tường lửa. Các hành động rủi ro Windows được ghi nhận là
cần phê duyệt cho tới khi người vận hành tin cậy phê duyệt rõ ràng.

AI chỉ nhận bằng chứng đã chuẩn hóa và nằm trong danh sách cho phép. AI được
gọi trực tiếp bằng `ai.base_url` bên ngoài đã cấu hình; ứng dụng không yêu cầu
hay âm thầm thay thế bằng cổng API localhost. Kết quả gồm mức độ nghiêm
trọng, độ tin cậy, bằng chứng, giả thuyết, tham chiếu MITRE ATT&CK tùy chọn,
dữ liệu còn thiếu và khuyến nghị do con người xem xét. AI không thể thực thi
lệnh, thay đổi chính sách tường lửa hay tự quyết định chặn địa chỉ.

## Ánh xạ mười hai công cụ của tác nhân

Dự án giữ mười hai công cụ được yêu cầu dưới dạng các hợp đồng Python đáng tin
cậy thay vì mười hai dịch vụ độc lập. Ánh xạ hiện tại:

1. Tiếp nhận/phân tích nhật ký: `ingestion/parser.py`, `ingestion/windows_source.py`
2. Giám sát tiến trình: `detection/process_monitor.py`
3. Thu thập bảo mật: `ingestion/windows_source.py`
4. Ngữ cảnh hành vi: `detection/context.py`
5. Động cơ bất thường: `detection/aggregator.py`, `detection/baseline.py`, `detection/sequence.py`
6. Thông tin tình báo mối đe dọa: `threat_intel.py`, chỉ bật khi cấu hình rõ
7. Proxy riêng tư: `proxy.py`, `privacy/`
8. Động cơ quyết định AI: `ai/client.py`, `ai/schemas.py`
9. Cổng chính sách: `policy/gate.py`, `policy/guard.py`
10. Bộ thực thi hành động: `actions/enforcer.py`, bộ điều hợp mô phỏng
11. Kiểm toán/khôi phục: `audit/logger.py`, `audit/rollback.py`
12. Đánh giá/báo cáo: `evaluation/metrics.py`

`agent/tools.py` cung cấp danh mục cho phép và từ chối các công cụ chưa đăng
ký; công cụ cần phê duyệt không thể chạy nếu chưa được phê duyệt rõ ràng.
Danh mục đã sẵn sàng cho vòng gọi hàm theo từng nhà cung cấp, nhưng ứng dụng
AI hiện chỉ tư vấn và không cho LLM thực thi hàm tùy ý.

## Dữ liệu đánh giá Atomic-EVTX

Bộ dữ liệu bên ngoài [Atomic-EVTX](https://github.com/arniki/atomic-evtx)
báo cáo 1.064 kịch bản tấn công Windows 10 thuộc nhiều nhóm như truy cập ban
đầu, thực thi, truy cập thông tin xác thực, nâng quyền, duy trì bám trụ, khám
phá, né tránh phòng thủ, di chuyển ngang, thu thập, điều khiển, lấy dữ liệu và
phá hoại. Kho mã chỉ giữ siêu dữ liệu tại
`datasets/atomic_evtx_manifest.json`; không sao chép EVTX/JSON thô vì dữ liệu
lớn và nguồn không công bố giấy phép rõ ràng.

Tải riêng bộ dữ liệu, sau đó nạp danh mục tấn công:

```powershell
python -c "from globalban.evaluation.atomic_catalog import load_atomic_catalog; print(len(load_atomic_catalog(r'C:\\path\\full_list_of_attacks_simulated.csv')))"
```

Dùng nhật ký chưa lọc để kiểm tra phân tích, `atomic_removed` để giảm tạo tác
của bộ sinh và `atomic_and_tools_removed` để kiểm tra phát hiện dựa trên hành
vi mà không phụ thuộc vào tên công cụ dễ nhận biết. Không tuyên bố độ chính
xác của mô hình cho tới khi nhật ký được chuyển thành nhãn và đánh giá bằng
mô-đun chỉ số.

## Kế hoạch đo lường và so sánh Sigma

Tập đánh giá cần có hai phần: nhiều ngày log Windows bình thường để làm
baseline, và các phiên log có nhãn bất thường. Mỗi phiên nên ghi `case_id`,
thời gian, host, user, các event Windows và `expected_detected`. Chạy bộ đánh
giá bằng:

```powershell
globalban-evaluate --labels path\to\windows_eval.jsonl --output evaluation-report.json
```

Trên chính các case đó, chạy các luật Sigma tương ứng rồi ghi kết quả vào bảng
so sánh gồm true positive, false positive, false negative, precision, recall,
F1, false-positive rate và thời gian phát hiện. Hiện repo đã có parser, baseline,
detector và module metrics; chưa ghi số đo thật khi chưa có log Windows đã gắn
nhãn. Nhóm Red Team cần bàn giao sau: danh sách kỹ thuật đã chạy, thời điểm
bắt đầu/kết thúc, host/user sử dụng, log thu được và kết quả Sigma trên cùng
tập test.

## Proxy Ubuntu cho lưu lượng ra ngoài

Kho mã có proxy danh sách cho phép độc lập cho các yêu cầu API. Proxy chỉ nhận
`POST /v1/chat/completions`, từ chối trường dư thừa và IP chưa che thông tin,
sau đó chuyển tiếp yêu cầu đã kiểm tra tới API nguồn. Trên Ubuntu:

```bash
python -m pip install -e .
GLOBALBAN_PROXY_BIND=0.0.0.0 \
GLOBALBAN_PROXY_PORT=8080 \
GLOBALBAN_PROXY_UPSTREAM=https://generativelanguage.googleapis.com/v1beta/openai \
globalban-proxy
```

Giới hạn cổng bằng tường lửa Ubuntu và đặt URL cơ sở API phía máy khách là
`http://192.168.52.131:8080/v1`. Địa chỉ bind mặc định là `127.0.0.1`; chỉ
mở trong mạng LAN khi tường lửa cho phép các máy khách tin cậy. Mô hình mặc
định trong ví dụ là `gemini-2.5-flash`. Chỉ đặt khóa trong môi trường Ubuntu,
không đặt trong YAML hay mã nguồn:

```bash
export GLOBALBAN_AI_API_KEY='YOUR_NEW_GEMINI_KEY'
```

Proxy lọc nội dung JSON của API nhưng không phải HTTPS MITM trong suốt cho các
ứng dụng tùy ý.

## Chạy kiểm thử

```powershell
py -m pytest
```

## Ứng dụng máy tính

Trên Windows, khởi chạy bảng điều khiển từ môi trường ảo đã kích hoạt:

```powershell
globalban-app
```

Ứng dụng khởi chạy bộ giám sát hiện có ở chế độ mô phỏng, hiển thị các sự kiện
quan trọng và giữ nguyên logic backend. Ứng dụng không cấp quyền quản trị cho
AI hay thực thi hành động tường lửa từ giao diện.

## Cấu trúc dự án

- `src/globalban/ingestion`: phân tích và đọc nối tiếp nhật ký SSH
- `src/globalban/detection`: gom nhóm các lần thử thất bại
- `src/globalban/detection/baseline.py`: đường cơ sở sự kiện cục bộ dễ giải thích
- `src/globalban/detection/sequence.py`: liên kết chuỗi Windows và ứng viên rủi ro
- `src/globalban/detection/process_monitor.py`: quan sát tiến trình và quan hệ cha-con
- `src/globalban/detection/context.py`: ngữ cảnh thực thể theo cửa sổ thời gian
- `src/globalban/policy`: kiểm tra chính sách địa chỉ an toàn để chặn
- `src/globalban/policy/gate.py`: cổng phê duyệt và giới hạn tốc độ
- `src/globalban/actions`: bộ điều hợp hành động tường lửa
- `src/globalban/actions/enforcer.py`: ranh giới hành động theo chính sách
- `src/globalban/privacy`: lọc dữ liệu gửi đi và che IP
- `src/globalban/threat_intel.py`: bộ điều hợp tình báo mối đe dọa tùy chọn
- `src/globalban/agent/tools.py`: danh mục mười hai công cụ được cho phép
- `src/globalban/evaluation/metrics.py`: chỉ số phát hiện có nhãn
- `src/globalban/ai`: ứng dụng khách giải thích tùy chọn tương thích OpenAI
- `src/globalban/ingestion/windows_source.py`: bộ điều hợp Windows Event Log qua PowerShell
- `src/globalban/audit`: nhật ký kiểm toán dạng JSON Lines
- `src/globalban/audit/rollback.py`: bản ghi khôi phục có TTL
- `src/globalban/notifications`: thông báo WhatsApp tùy chọn
- `datasets/`: ví dụ SSH và bản ghi đánh giá minh họa nhỏ
- `tests/`: kiểm thử đơn vị

GlobalBan là dự án học tập và quản trị phòng thủ, không thay thế cho tường
lửa, hệ thống ngăn chặn xâm nhập hay quy trình ứng phó sự cố được quản lý
đúng cách. Hãy kiểm tra chính sách và bản sao lưu trước khi bật chặn tự động.
