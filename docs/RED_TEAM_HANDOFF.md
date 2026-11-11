# Huong dan Red Team thu thap du lieu Windows

Tai lieu nay danh cho thanh vien Red Team lam viec trong VS Code tren may ao Windows duoc phep kiem thu. Khong chay cac bai test tren may that, may cua nguoi khac, hoac mang san xuat.

## 1. Chuan bi may ao

1. Tao snapshot truoc khi thay doi may ao.
2. Dat ten may ro rang, vi du `WIN-RED-01`.
3. Tao mot tai khoan kiem thu rieng va ghi lai hostname, username, Windows version.
4. Bat cac kenh log can thiet:
   - Security
   - Microsoft-Windows-Sysmon/Operational
   - Microsoft-Windows-PowerShell/Operational
   - Microsoft-Windows-Windows Defender/Operational
5. Mo VS Code voi thu muc lam viec rieng, vi du `C:\redteam-work`.
6. Mo terminal PowerShell trong VS Code bang quyen phu hop.

Khong commit EVTX, token, mat khau, private key hoac file co du lieu ca nhan vao Git.

## 2. Tao thu muc ban giao

Chay trong PowerShell:

```powershell
$root = 'C:\redteam-work'
New-Item -ItemType Directory -Force -Path `
  "$root\baseline", "$root\atomic", "$root\metadata", "$root\hashes"
```

Su dung `baseline` cho log binh thuong va `atomic` cho log cua tung lan test. Moi lan test phai co mot `case_id` rieng.

## 3. Thu baseline binh thuong

Thu nhat log trong nhieu ngay khi may ao duoc su dung binh thuong. Khong chay Atomic Red Team trong khoang nay. Cuoi moi ngay hoac cuoi dot thu, mo PowerShell bang quyen phu hop va xuat cac kenh log:

```powershell
$case = 'baseline-day-01'
$dest = "C:\redteam-work\baseline\$case"
New-Item -ItemType Directory -Force -Path $dest

wevtutil epl Security "$dest\Security.evtx"
wevtutil epl Microsoft-Windows-Sysmon/Operational "$dest\Sysmon.evtx"
wevtutil epl Microsoft-Windows-PowerShell/Operational "$dest\PowerShell.evtx"
wevtutil epl Microsoft-Windows-Windows-Defender/Operational "$dest\Defender.evtx"
Get-FileHash "$dest\*.evtx" -Algorithm SHA256 |
  Export-Csv "C:\redteam-work\hashes\$case.csv" -NoTypeInformation
```

Neu khong co Sysmon hoac Defender, ghi ro trong metadata thay vi tu y dien them du lieu.

## 4. Chuan bi Atomic Red Team

Chi cai va chay trong may ao da duoc phe duyet. Trong PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
Install-Module Invoke-AtomicRedTeam -Scope CurrentUser
Import-Module Invoke-AtomicRedTeam
```

Truoc moi bai test, doc mo ta va dieu kien cua test. Chi chon test phu hop voi pham vi do an, co the hoan tac, va duoc nguoi huong dan phe duyet. Khong chay ca bo danh sach ky thuat mot cach mu quang.

Ghi thoi gian UTC truoc va sau khi chay test. Vi du voi mot test da duoc phe duyet:

```powershell
$start = (Get-Date).ToUniversalTime()
# Dat lenh Invoke-AtomicTest cu the da duoc phe duyet o day.
# Vi du: Invoke-AtomicTest <TECHNIQUE-ID> -TestNumbers <N>
$end = (Get-Date).ToUniversalTime()
```

Neu test co prereq, chay kiem tra prereq truoc. Luu lai technique ID, test number, ten test, ket qua va moi thay doi can don dep. Khong dua command nguy hiem vao file metadata; chi ghi ID va ten test.

## 5. Xuat log cho tung case

Ngay sau moi test, xuat lai log voi `case_id` rieng:

```powershell
$case = 'atomic-T1059-001-test-01'
$dest = "C:\redteam-work\atomic\$case"
New-Item -ItemType Directory -Force -Path $dest

wevtutil epl Security "$dest\Security.evtx"
wevtutil epl Microsoft-Windows-Sysmon/Operational "$dest\Sysmon.evtx"
wevtutil epl Microsoft-Windows-PowerShell/Operational "$dest\PowerShell.evtx"
wevtutil epl Microsoft-Windows-Windows-Defender/Operational "$dest\Defender.evtx"
Get-FileHash "$dest\*.evtx" -Algorithm SHA256 |
  Export-Csv "C:\redteam-work\hashes\$case.csv" -NoTypeInformation
```

Khong xoa log baseline. Neu co khoang thoi gian canh bao hoac log bi thieu, ghi ro trong metadata.

## 6. Tao metadata JSONL

Tao file `C:\redteam-work\metadata\cases.jsonl`, moi dong la mot case:

```json
{"case_id":"baseline-day-01","expected_detected":false,"technique_id":null,"test_name":null,"host":"WIN-RED-01","username":"lab-user","start_utc":"2026-11-09T08:00:00Z","end_utc":"2026-11-09T17:00:00Z","log_path":"baseline/baseline-day-01"}
{"case_id":"atomic-T1059-001-test-01","expected_detected":true,"technique_id":"T1059.001","test_name":"approved test name","host":"WIN-RED-01","username":"lab-user","start_utc":"2026-11-09T18:00:00Z","end_utc":"2026-11-09T18:05:00Z","log_path":"atomic/atomic-T1059-001-test-01"}
```

Thay gia tri vi du bang thong tin that. `expected_detected` phai duoc xac nhan dua tren viec test co thuc su chay thanh cong hay khong, khong dua vao viec detector co phat hien hay khong.

## 7. Ban giao cho nhom phat hien

Nen dong goi cac thu muc sau:

```text
redteam-export/
  baseline/<case_id>/*.evtx
  atomic/<case_id>/*.evtx
  metadata/cases.jsonl
  hashes/*.csv
  README.txt
```

`README.txt` can ghi Windows version, Sysmon version/config, PowerShell version, timezone, cac kenh log co san, test nao that bai va cac file bi thieu.

Gui kem ket qua Sigma tren cung cac `case_id`. Moi phuong phap phai tra ve mot danh sach ket qua co dang:

```json
{"case_id":"atomic-T1059-001-test-01","predicted_detected":true,"rule_id":"sigma-rule-id"}
```

Nhom phat hien se dung `cases.jsonl` lam ground truth, chay pipeline tren EVTX that, sau do tinh precision, recall, F1 va false-positive rate. Khong dung fixture `datasets/windows_events.xmll` de thay cho so lieu nay.
