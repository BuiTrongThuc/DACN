# Ke hoach ban giao de tai

## 1. Muc tieu

Xay dung va danh gia he thong phat hien hanh vi lech khoi thoi quen cua tung
nguoi dung tren tung may Windows. Agent phai giai thich bat thuong bang cac
bang chung trong log. SSH khong phai trong tam danh gia.

## 2. Trang thai da hoan thanh

- Baseline duoc phan tach theo `host + username`.
- Baseline theo doi event type, gio hoat dong, executable va command line.
- Baseline co `fit()` de hoc tu log binh thuong va `score()`/`freeze()` de
  khong bi nhiem boi log Atomic khi danh gia.
- Co bo doc EVTX offline tren may phan tich:
  `globalban.ingestion.evtx.read_evtx_events`.
- Co SequenceCorrelator va RiskCandidate voi reason giai thich.
- Agent nhan host, username, timestamp, risk score, event IDs va reasons
  trong payload da duoc allowlist.
- Co protocol metrics: precision, recall, F1, false-positive rate.
- Co collector Red Team, wrapper Atomic co `case_id`, hash va validator.
- Da kiem tra: `52 passed`, Python compile thanh cong.
- Commit hien tai: `dd97a70`.

## 3. Cach tiep tuc tren may moi

```powershell
git clone https://github.com/BuiTrongThuc/DACN.git
cd DACN
git checkout main
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m pytest -q
```

Neu can collector Red Team:

```powershell
git checkout redteam-toolkit
```

Khong commit EVTX, token, mat khau, audit nhat ky co du lieu nhay cam hoac
thong tin dinh danh may that len GitHub.

## 4. Viec Red Team phai lam

Thuc hien trong VM Windows duoc phep kiem thu, khong phai host va khong phai
may that:

1. Tao snapshot, ghi hostname, username, Windows, PowerShell va Sysmon version.
2. Dam bao Security, Sysmon, PowerShell va Defender channels kha dung.
3. Thu baseline binh thuong it nhat 3 ngay, khuyen nghi 7 ngay.
4. Chi chay Atomic Red Team sau khi co technique ID va test number duoc phe
   duyet.
5. Moi lan chay dung mot `case_id`, ghi start/end UTC, host, user, status.
6. Xuat EVTX va SHA256 cho tung case.
7. Chay cung bo luat Sigma tren cung cac EVTX va ghi ket qua theo `case_id`.
8. Chuyen rieng cac artifact EVTX va metadata cho nhom phan tich.

Dùng toolkit:

```powershell
.\scripts\preflight.ps1
.\scripts\collect_windows_logs.ps1 -CaseId baseline-day-01 -Kind baseline
.\scripts\run_approved_atomic.ps1 `
  -CaseId atomic-test-01 `
  -TechniqueId <TECHNIQUE_ID_DA_DUOC_DUYET> `
  -TestNumbers <TEST_NUMBER> `
  -Approved
.\scripts\validate_handoff.ps1
```

## 5. Viec nhom phan tich phai lam sau khi nhan du lieu

1. Kiem tra hash va manifest; loai bo case thieu EVTX hoac thieu metadata.
2. Doc EVTX bang `read_evtx_events`, sau do chuan hoa bang parser.
3. Chi dung baseline cases de goi `BehaviorBaseline.fit(...)` va dong bang
   baseline truoc khi doc atomic cases.
4. Chay detector tren baseline va atomic cases, luu `case_id`, score, reasons,
   event IDs, host va username.
5. Goi agent giai thich tu payload da allowlist; khong gui EVTX tho hoac secret.
6. Chay Sigma tren cung case va luu `case_id`, rule ID, predicted detected.
7. Dung cung ground truth de goi `compare_methods(...)`.
8. Xuat bang precision, recall, F1, false-positive rate, false-negative rate
   va detection latency.
9. Kiem tra thu cong mot so explanation de dam bao moi ket luan co bang chung.

## 6. Dieu kien duoc xem la hoan thanh

- Co it nhat 3 ngay baseline binh thuong, tot nhat 7 ngay.
- Co it nhat mot so atomic cases thanh cong va that bai duoc ghi nhan.
- Moi case co EVTX, manifest, hash va metadata hop le.
- Sigma va detector dung cung tap case va cung ground truth.
- Co bang metrics that, khong dung fixture de bao cao.
- Co it nhat mot explanation cho moi case bi danh dau va explanation chi
  dung bang chung tu log.
- Test code pass va khong co secret/log that trong Git.

## 7. Gioi han can ghi ro trong bao cao

Neu chua co EVTX va nhan tu VM, chi duoc ghi rang pipeline da san sang;
khong duoc ghi Precision, Recall, F1 hoac ket luan hieu qua nhu ket qua that.
Fixture trong `datasets/` chi dung de kiem thu hoi quy.
