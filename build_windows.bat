@echo off
REM Aurivo Music Player - Windows Build Script
REM Python 3.10+ ve PyInstaller gerekli

echo ================================================
echo Aurivo Music Player - Windows Build
echo ================================================
echo.

REM Sanal ortam varsa aktive et
if exist "venv\Scripts\activate.bat" (
    echo [1/5] Sanal ortam aktive ediliyor...
    call venv\Scripts\activate.bat
) else (
    echo [1/5] Sanal ortam bulunamadi, sistem Python kullanilacak
)

echo [2/5] Temel bağımlılıklar kontrol ediliyor...
pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo PyInstaller kurulu degil, kuruluyor...
    pip install pyinstaller
)

pip show PyQt5 >nul 2>&1
if errorlevel 1 (
    echo HATA: PyQt5 kurulu degil! Lutfen once 'pip install PyQt5' calistirin.
    pause
    exit /b 1
)

echo [3/5] Eski build dosyalari temizleniyor...
if exist "dist\Aurivo.exe" del /Q "dist\Aurivo.exe"
if exist "build" rmdir /S /Q "build"

echo [4/5] Windows executable olusturuluyor...
echo NOT: Whisper DAHIL DEGIL (kullanici istege bagli kuracak)
pyinstaller --clean aurivo_windows.spec

if errorlevel 1 (
    echo.
    echo HATA: Build basarisiz!
    pause
    exit /b 1
)

echo [5/5] Build tamamlandi!
echo.
echo ================================================
echo Cikti: dist\Aurivo.exe
echo Boyut: ~150-200MB (Whisper haric)
echo ================================================
echo.
echo NOT: Kullanicilar ilk kez "Otomatik Altyazi" kullandiginda
echo       Whisper otomatik indirilecek (~2.2GB)
echo.
pause
