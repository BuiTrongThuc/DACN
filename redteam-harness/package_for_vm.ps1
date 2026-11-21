<#
.SYNOPSIS
    package_for_vm.ps1 - Tự động đóng gói thư mục C:\redteam-harness thành file ZIP cho máy ảo VMware.
#>

$sourceDir = "C:\redteam-harness"
$zipFile   = "C:\redteam-harness\redteam-harness-vm.zip"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [1] ĐANG ĐÓNG GÓI BỘ CÔNG CỤ RED TEAM CHO MÁY ẢO VM..." -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

if (Test-Path $zipFile) {
    Remove-Item $zipFile -Force
}

# Tạo file zip chứa các script chính và cấu trúc artifacts cơ bản
$tempStage = "$env:TEMP\redteam_stage"
if (Test-Path $tempStage) { Remove-Item $tempStage -Recurse -Force }
New-Item -ItemType Directory -Force -Path "$tempStage\artifacts\baseline", "$tempStage\artifacts\atomic", "$tempStage\artifacts\hashes", "$tempStage\artifacts\metadata" | Out-Null

Copy-Item "$sourceDir\run_campaign.py" "$tempStage\" -Force
Copy-Item "$sourceDir\simulate_normal_days.py" "$tempStage\" -Force
Copy-Item "$sourceDir\validate_handoff.py" "$tempStage\" -Force
Copy-Item "$sourceDir\bridge_evaluate.py" "$tempStage\" -Force

# Nén thư mục stage thành file ZIP
Compress-Archive -Path "$tempStage\*" -DestinationPath $zipFile -Force
Remove-Item $tempStage -Recurse -Force

$zipSize = (Get-Item $zipFile).Length / 1KB
Write-Host "[✓] Đã tạo gói nén thành công: $zipFile ($([math]::Round($zipSize, 1)) KB)" -ForegroundColor Green

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " [2] HƯỚNG DẪN 1 DÒNG ĐỂ TRIỂN KHAI TRÊN MÁY ẢO VM (136):" -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Mở PowerShell (Administrator) trên máy ảo VMware và dán dòng sau:`n" -ForegroundColor White
$cmd = 'powershell -NoProfile -Command "New-Item -ItemType Directory -Force -Path C:\redteam-harness | Out-Null; cd C:\redteam-harness; Invoke-WebRequest -Uri http://192.168.52.134:8000/redteam-harness-vm.zip -OutFile harness.zip; Expand-Archive -Path harness.zip -DestinationPath C:\redteam-harness -Force; Remove-Item harness.zip -Force; Write-Host ''[OK] Da cai dat xong C:\redteam-harness san sang chay!'' -ForegroundColor Green"'
Write-Host $cmd -ForegroundColor Green
Write-Host "`n==========================================================" -ForegroundColor Cyan
