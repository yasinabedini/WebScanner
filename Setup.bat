@echo off
chcp 65001 > nul
color 0A

echo ╔═══════════════════════════════════════════════════════════╗
echo ║                                                           ║
echo ║        🛡️  Enterprise Web Scanner - Setup  🛡️             ║
echo ║                                                           ║
echo ╚═══════════════════════════════════════════════════════════╝
echo.

echo [1] بررسی Python...
python --version > nul 2>&1
if %errorlevel% neq 0 (
    echo [✗] Python یافت نشد!
    echo [!] لطفاً Python 3.7+ را از python.org نصب کنید
    pause
    exit /b 1
)
echo [✓] Python نصب است

echo.
echo [2] بررسی ابزارها...
if not exist "tools\" (
    echo [✗] پوشه tools یافت نشد!
    echo [!] لطفاً ابزارها را در پوشه tools قرار دهید
    pause
    exit /b 1
)

set missing=0
if not exist "tools\subfinder.exe" (
    echo [✗] subfinder.exe یافت نشد
    set missing=1
)
if not exist "tools\httpx.exe" (
    echo [✗] httpx.exe یافت نشد
    set missing=1
)
if not exist "tools\nuclei.exe" (
    echo [✗] nuclei.exe یافت نشد
    set missing=1
)
if not exist "tools\katana.exe" (
    echo [✗] katana.exe یافت نشد
    set missing=1
)
if not exist "tools\dnsx.exe" (
    echo [✗] dnsx.exe یافت نشد
    set missing=1
)
if not exist "tools\naabu.exe" (
    echo [✗] naabu.exe یافت نشد
    set missing=1
)

if %missing%==1 (
    echo.
    echo [!] لطفاً ابزارهای گمشده را دانلود و در پوشه tools قرار دهید
    pause
    exit /b 1
)
echo [✓] تمام ابزارها موجود هستند

echo.
echo [3] بررسی Nuclei Templates...
if not exist "nuclei-templates\" (
    echo [✗] پوشه nuclei-templates یافت نشد!
    echo [!] لطفاً قالب‌های Nuclei را دانلود کنید
    pause
    exit /b 1
)
echo [✓] قالب‌های Nuclei موجود هستند

echo.
echo [4] نصب وابستگی‌های Python...
if exist "requirements.txt" (
    pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo [✗] خطا در نصب وابستگی‌ها
        pause
        exit /b 1
    )
    echo [✓] وابستگی‌ها نصب شدند
) else (
    echo [!] فایل requirements.txt یافت نشد
)

echo.
echo ╔═══════════════════════════════════════════════════════════╗
echo ║                                                           ║
echo ║              ✅ نصب با موفقیت انجام شد!                  ║
echo ║                                                           ║
echo ║  برای شروع اسکن از دستور زیر استفاده کنید:              ║
echo ║  python scanner.py -d example.com                        ║
echo ║                                                           ║
echo ║  یا از فایل run_scan.bat استفاده کنید                   ║
echo ║                                                           ║
echo ╚═══════════════════════════════════════════════════════════╝
echo.
pause
