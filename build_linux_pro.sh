#!/bin/bash
# Aurivo Music Player - Linux Build Script (PRO VERSION)
# Python 3.10+ ve PyInstaller gerekli
# Whisper DAHIL - Buyuk boyut (~2.5GB)

set -e

echo "================================================"
echo "Aurivo Music Player - Linux Build (PRO)"
echo "================================================"
echo ""
echo "Bu PRO sürümü oluşturuyorsunuz (Whisper DAHİL)"
echo "Boyut: ~2.5GB"
echo ""

# Sanal ortam varsa aktive et
if [ -d "pyqt_venv" ]; then
    echo "[1/7] Sanal ortam aktive ediliyor..."
    source pyqt_venv/bin/activate
elif [ -d "venv" ]; then
    echo "[1/7] Sanal ortam aktive ediliyor..."
    source venv/bin/activate
else
    echo "[1/7] Sanal ortam bulunamadı, sistem Python kullanılacak"
fi

echo "[2/7] Temel bağımlılıklar kontrol ediliyor..."
if ! pip show pyinstaller &> /dev/null; then
    echo "PyInstaller kurulu değil, kuruluyor..."
    pip install pyinstaller
fi

# Native derleme bağımlılıkları
if ! pip show pybind11 &> /dev/null; then
    echo "pybind11 kurulu değil, kuruluyor..."
    pip install pybind11
fi
if ! pip show numpy &> /dev/null; then
    echo "numpy kurulu değil, kuruluyor..."
    pip install numpy
fi

if ! pip show PyQt5 &> /dev/null; then
    echo "HATA: PyQt5 kurulu değil! Lütfen önce 'pip install PyQt5' çalıştırın."
    exit 1
fi

echo "[3/7] Whisper ve PyTorch kurulumu kontrol ediliyor..."
if ! pip show openai-whisper &> /dev/null; then
    echo "Whisper kurulu değil, kuruluyor... (Bu biraz zaman alabilir)"
    pip install openai-whisper
fi

if ! pip show torch &> /dev/null; then
    echo "PyTorch kurulu değil, kuruluyor... (Bu çok zaman alabilir, ~2GB)"
    pip install torch torchaudio
fi

echo "[4/7] Eski build dosyaları temizleniyor..."
rm -rf dist/aurivo-pro build/

echo "[5/7] Native modüller derleniyor..."

# 1) ctypes DSP kütüphanesi (zorunlu)
if [ -f "aurivo_dsp.cpp" ]; then
    if command -v g++ >/dev/null 2>&1; then
        echo " - aurivo_dsp.so derleniyor (g++)"
        g++ -O3 -shared -fPIC -std=c++17 -o aurivo_dsp.so aurivo_dsp.cpp
    else
        echo "HATA: g++ bulunamadı (aurivo_dsp.so derlenemiyor)" >&2
        exit 1
    fi
else
    echo "HATA: aurivo_dsp.cpp bulunamadı" >&2
    exit 1
fi

# 2) PyBind11 altyazı motoru (zorunlu)
if [ -f "setup_subtitle_engine.py" ]; then
    echo " - subtitle_engine derleniyor (pybind11)"
    python3 setup_subtitle_engine.py build_ext --inplace
else
    echo "HATA: setup_subtitle_engine.py bulunamadı" >&2
    exit 1
fi

# 3) ProjectM viz_engine (opsiyonel) - projectM dev paketleri yoksa geç
if [ -f "setup.py" ]; then
    echo " - viz_engine deneniyor (ProjectM opsiyonel)"
    if ! python3 setup.py build_ext --inplace; then
        echo "⚠ viz_engine derlenemedi (projectM headers/libs yok olabilir) - ProjectM görselleştirme devre dışı kalır"
    fi
fi

echo "[6/7] Linux executable oluşturuluyor (PRO)..."
echo "NOT: Whisper DAHİL - otomatik altyazı özelliği aktif"
pyinstaller --clean aurivo_linux_pro.spec

if [ $? -ne 0 ]; then
    echo ""
    echo "HATA: Build başarısız!"
    exit 1
fi

echo "[7/7] Build tamamlandı!"
echo ""

# Icon symlink oluştur (PyInstaller packed binary için)
echo "[+] Icon ve wrapper oluşturuluyor..."
cd dist/aurivo-pro
if [ ! -L "icons" ] && [ -d "_internal/icons" ]; then
    ln -sf _internal/icons icons
    echo "✓ icons -> _internal/icons"
fi

# DSP kütüphanesi symlink
if [ -f "_internal/aurivo_dsp.so" ] && [ ! -f "aurivo_dsp.so" ]; then
    ln -sf _internal/aurivo_dsp.so aurivo_dsp.so
    echo "✓ aurivo_dsp.so -> _internal/aurivo_dsp.so"
fi

# Desktop ve ikon dosyaları
if [ -f "_internal/aurivo.desktop" ]; then
    ln -sf _internal/aurivo.desktop aurivo.desktop
    echo "✓ aurivo.desktop symlink"
fi
if [ -f "_internal/icons/aurivo.png" ]; then
    ln -sf _internal/icons/aurivo.png aurivo.png
    echo "✓ aurivo.png (uygulama simgesi)"
elif [ -f "_internal/media-playback-start.png" ]; then
    ln -sf _internal/media-playback-start.png aurivo.png
    echo "✓ aurivo.png (uygulama simgesi - fallback)"
fi

# Launcher wrapper script oluştur
if [ -f "aurivo" ]; then
    mv aurivo aurivo.bin
    cat > aurivo << 'WRAPPER_EOF'
#!/bin/bash
# Aurivo Music Player - Launcher Script (Pro)
# GStreamer ve Qt çevre değişkenlerini ayarla

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# GStreamer plugin dizinlerini sistem yollarına ekle
export GST_PLUGIN_PATH=/usr/lib/gstreamer-1.0:${GST_PLUGIN_PATH}
export GST_PLUGIN_SYSTEM_PATH=/usr/lib/gstreamer-1.0
export GST_PLUGIN_SCANNER=/usr/lib/gstreamer-1.0/gst-plugin-scanner

# GLib şema dizini
export XDG_DATA_DIRS=/usr/share:${XDG_DATA_DIRS}

# Qt platformu
export QT_QPA_PLATFORM_PLUGIN_PATH=/usr/lib/qt/plugins/platforms

# GStreamer registry'yi yenile (ilk çalıştırmada)
if [ ! -f "$HOME/.cache/gstreamer-1.0/registry.x86_64.bin" ]; then
    echo "GStreamer registry oluşturuluyor..."
    gst-inspect-1.0 > /dev/null 2>&1
fi

# Executable'ı çalıştır
exec ./aurivo.bin "$@"
WRAPPER_EOF
    chmod +x aurivo
    echo "✓ Launcher wrapper oluşturuldu"
fi

cd ../..

echo ""
echo "================================================"
echo "Çıktı: dist/aurivo-pro/"
echo "Çalıştır: ./dist/aurivo-pro/aurivo"
echo "Boyut: ~2.5GB (Whisper dahil)"
echo "================================================"
echo ""
echo "ÖZELLİKLER:"
echo "  + Müzik çalma (tüm formatlar)"
echo "  + Video oynatma"
echo "  + Manuel altyazı (.srt, .vtt)"
echo "  + Otomatik video altyazı (Whisper AI)"
echo "  + Çoklu dil otomatik altyazı"
echo "  + 11 görselleştirme modu"
echo "  + 10 bantlı ekolayzır"
echo "  + DSP efektleri"
echo ""
echo "NOT: Kullanıcılar direkt otomatik altyazı oluşturabilir."
echo ""
