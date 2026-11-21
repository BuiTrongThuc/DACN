@echo off
REM ============================================================================
REM deploy_on_vm.bat - Cài đặt tự động C:\redteam-harness trên máy ảo Blue Team
REM ============================================================================

echo [*] Dang tao thu muc C:\redteam-harness...
if not exist "C:\redteam-harness" mkdir "C:\redteam-harness"
cd /d "C:\redteam-harness"

echo [*] Dang tai goi redteam-harness-vm.zip tu Red Team (192.168.52.134)...
powershell -NoProfile -Command "Invoke-WebRequest -Uri http://192.168.52.134:8000/redteam-harness-vm.zip -OutFile harness.zip; Expand-Archive -Path harness.zip -DestinationPath C:\redteam-harness -Force; Remove-Item harness.zip -Force"

if exist "C:\redteam-harness\run_campaign.py" (
    echo [OK] Cai dat thanh cong! Thu muc lam viec hien tai: %CD%
    echo [*] Ban co the chay ngay:
    echo     python run_campaign.py --target-ip 192.168.52.136 --approved
) else (
    echo [ERROR] Khong the tai goi harness. Kiem tra ket noi den 192.168.52.134:8000!
)
