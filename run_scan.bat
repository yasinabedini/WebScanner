@echo off
chcp 65001 > nul
color 0B

echo ╔═══════════════════════════════════════════════════════════╗
echo ║        🚀 Enterprise Web Scanner - Quick Start 🚀         ║
echo ╚═══════════════════════════════════════════════════════════╝
echo.

set /p domain="🎯 دامنه هدف را وارد کنید: "
if "%domain%"=="" (
    echo [!] دامنه نمی‌تواند خالی باشد!
    pause
    exit /b 1
)

echo.
echo نوع اسکن را انتخاب کنید:
echo [1] Quick      - سریع (فقط آسیب‌پذیری‌های Critical و High)
echo [2] Standard   - استاندارد (Critical, High, Medium)
echo [3] Comprehensive - جامع (تمام سطوح)
echo.
set /p choice="انتخاب (1-3): "

set scan_type=comprehensive
if "%choice%"=="1" set scan_type=quick
if "%choice%"=="2" set scan_type=standard
if "%choice%"=="3" set scan_type=comprehensive

echo.
set /p skip_ports="اسکن پورت انجام شود؟ (Y/N): "
set skip_flag=
if /i "%skip_ports%"=="N" set skip_flag=--skip-ports

echo.
echo ═══════════════════════════════════════════════════════════
echo شروع اسکن...
echo ═══════════════════════════════════════════════════════════
echo.

python scanner.py -d %domain% -t %scan_type% %skip_flag%

echo.
echo ═══════════════════════════════════════════════════════════
echo اسکن تکمیل شد!
echo ═══════════════════════════════════════════════════════════
pause
