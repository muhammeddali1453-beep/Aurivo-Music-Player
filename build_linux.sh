#!/bin/bash
# Aurivo Music Player - Linux Build Script
# Python 3.10+ ve PyInstaller gerekli

set -e

echo "================================================"
echo "Aurivo Music Player - Linux Build"
echo "================================================"
echo ""

# Sanal ortam varsa aktive et
if [ -d "pyqt_venv" ]; then
    echo "[1/5] Sanal ortam aktive ediliyor..."
    source pyqt_venv/bin/activate
elif [ -d "venv" ]; then
    echo "[1/5] Sanal ortam aktive ediliyor..."
    source venv/bin/activate
else
    echo "[1/5] Sanal ortam bulunamadı, sistem Python kullanılacak"
fi

echo "[2/5] Temel bağımlılıklar kontrol ediliyor..."
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

echo "[3/6] Eski build dosyaları temizleniyor..."
rm -rf dist/aurivo build/

echo "[4/6] Native modüller derleniyor..."

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

echo "[5/6] Linux executable oluşturuluyor..."
echo "NOT: Whisper DAHİL DEĞİL (kullanıcı isteğe bağlı kuracak)"
pyinstaller --clean aurivo_linux.spec

if [ $? -ne 0 ]; then
    echo ""
    echo "HATA: Build başarısız!"
    exit 1
fi

echo "[6/6] Build tamamlandı!"
echo ""

# Icon symlink oluştur (PyInstaller packed binary için)
echo "[+] Icon ve wrapper oluşturuluyor..."
cd dist/aurivo
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
# Aurivo Music Player - Launcher Script
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
echo "Çıktı: dist/aurivo/"
echo "Çalıştır: ./dist/aurivo/aurivo"
echo "Boyut: ~150-200MB (Whisper hariç)"
echo "================================================"
echo ""
echo "NOT: Kullanıcılar ilk kez 'Otomatik Altyazı' kullandığında"
echo "     Whisper otomatik indirilecek (~2.2GB)"
echo ""

# AppImage oluşturma (opsiyonel)
read -p "AppImage oluşturmak ister misiniz? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    if command -v appimagetool &> /dev/null; then
        echo "AppImage oluşturuluyor..."
        # AppDir yapısı oluştur
        mkdir -p AppDir/usr/bin
        mkdir -p AppDir/usr/share/icons/hicolor/256x256/apps
        mkdir -p AppDir/usr/share/applications
        
        cp -r dist/aurivo/* AppDir/usr/bin/
        
        # Desktop dosyası oluştur
        cat > AppDir/usr/share/applications/aurivo.desktop << EOF
[Desktop Entry]
Type=Application
Name=Aurivo Music Player
Exec=aurivo
Icon=aurivo
Categories=Audio;Player;
EOF
        
        # AppRun oluştur
        cat > AppDir/AppRun << 'EOF'
#!/bin/bash
SELF=$(readlink -f "$0")
HERE=${SELF%/*}
export PATH="${HERE}/usr/bin/:${PATH}"
exec "${HERE}/usr/bin/aurivo" "$@"
EOF
        chmod +x AppDir/AppRun
        
        appimagetool AppDir Aurivo-x86_64.AppImage
        echo "✓ AppImage oluşturuldu: Aurivo-x86_64.AppImage"
    else
        echo "appimagetool bulunamadı. Manuel kurulum: https://github.com/AppImage/AppImageKit"
    fi
fi
