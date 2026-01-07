@echo off
REM Aurivo Music Player - Windows Build Script (STANDARD VERSION)
REM Python 3.10+ ve PyInstaller gerekli
REM Whisper DAHIL DEGIL - Kucuk boyut (~150-200MB)

echo ================================================
echo Aurivo Music Player - Windows Build (STANDARD)
echo ================================================
echo.
echo Bu standard surumu olustururmusunuz (Whisper HARIC)
echo Boyut: ~150-200MB
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

pip show numpy >nul 2>&1
if errorlevel 1 (
    echo NumPy kurulu degil, kuruluyor...
    pip install numpy
)

pip show pybind11 >nul 2>&1
if errorlevel 1 (
    echo pybind11 kurulu degil, kuruluyor...
    pip install pybind11
)

pip show PyQt5 >nul 2>&1
if errorlevel 1 (
    echo HATA: PyQt5 kurulu degil! Lutfen once 'pip install PyQt5' calistirin.
    pause
    exit /b 1
)

echo [3/5] Eski build dosyalari temizleniyor...
if exist "dist\Aurivo-Standard.exe" del /Q "dist\Aurivo-Standard.exe"
if exist "build" rmdir /S /Q "build"

echo [4/5] Native moduller derleniyor...

REM --- C++ DSP (ctypes) ---
if exist "aurivo_dsp.dll" del /Q "aurivo_dsp.dll"

where cl >nul 2>&1
if not errorlevel 1 (
    echo  - aurivo_dsp.dll derleniyor (MSVC cl)
    cl /nologo /O2 /EHsc /LD aurivo_dsp.cpp /link /OUT:aurivo_dsp.dll
) else (
    where g++ >nul 2>&1
    if not errorlevel 1 (
        echo  - aurivo_dsp.dll derleniyor (g++)
        g++ -O3 -shared -std=c++17 -o aurivo_dsp.dll aurivo_dsp.cpp
    ) else (
        echo HATA: ne 'cl' ne de 'g++' bulundu. aurivo_dsp.dll derlenemiyor.
        echo Lutfen Visual Studio Build Tools veya MinGW-w64 kurun.
        pause
        exit /b 1
    )
)

if not exist "aurivo_dsp.dll" (
    echo HATA: aurivo_dsp.dll olusmadi.
    pause
    exit /b 1
)

REM --- subtitle_engine (pybind11) ---
echo  - subtitle_engine derleniyor (pybind11)
python setup_subtitle_engine.py build_ext --inplace
if errorlevel 1 (
    echo HATA: subtitle_engine build basarisiz!
    pause
    exit /b 1
)

REM --- viz_engine (ProjectM opsiyonel) ---
echo  - viz_engine deneniyor (opsiyonel)
python setup.py build_ext --inplace
if errorlevel 1 (
    echo UYARI: viz_engine build basarisiz (opsiyonel). Devam ediliyor...
)

echo [5/5] Windows executable olusturuluyor (STANDARD)...
echo NOT: Whisper DAHIL DEGIL - kullanici istege bagli kuracak
pyinstaller --clean aurivo_windows_standard.spec

if errorlevel 1 (
    echo.
    echo HATA: Build basarisiz!
    pause
    exit /b 1
)

echo [6/5] Build tamamlandi!
echo.
echo ================================================
echo Cikti: dist\Aurivo-Standard.exe
echo Boyut: ~150-200MB (Whisper haric)
echo ================================================
echo.
echo OZELLIKLER:
echo   + Muzik calma (tum formatlar)
echo   + Video oynatma
echo   + Manuel altyazi (.srt, .vtt)
echo   + 11 gorsellestirme modu
echo   + 10 bantli ekoulayzer
echo   + DSP efektleri
echo   - Otomatik video altyazi (Whisper yok)
echo.
echo NOT: Kullanicilar "Otomatik Altyazi" secenegini kullanamazlar.
echo      Pro versiyonu gerektigi konusunda bilgilendirilecekler.
echo.
pause
