# Aurivo Music Player - Dağıtım Kılavuzu

## 🎵 Paket Stratejisi

**İki Ayrı Paket: Standard ve Pro**
- **Standard**: ~150-200MB (Whisper hariç, çoğu kullanıcı için)
- **Pro**: ~2.5GB (Whisper dahil, otomatik altyazı için)

### 🎯 Kullanıcı Kararı Akışı
```
Kullanıcı → Otomatik video altyazısı gerekli mi?
  ↓ HAYIR → Standard Edition (150MB)
  ↓ EVET  → Pro Edition (2GB)
```

### Standard Paket İçeriği
✅ Müzik çalar (tüm formatlar)
✅ Video oynatıcı
✅ 11 görselleştirme modu
✅ Manuel altyazı desteği (.srt, .vtt)
✅ Ekolayzır + DSP efektleri
✅ Kütüphane yönetimi
✅ YouTube indirme
❌ Otomatik altyazı (Whisper yok)

### Pro Paket İçeriği
✅ **Standard'daki tüm özellikler**
✅ **Otomatik video transkripsiyon (Whisper AI)**
✅ **Çoklu dil otomatik altyazı**

---

## 🪟 Windows 10/11 Build

### Gereksinimler
- Python 3.10+
- PyQt5: `pip install PyQt5`
- PyInstaller: `pip install pyinstaller`
- Native build için (en az biri):
   - Visual Studio Build Tools (MSVC `cl`)
   - veya MinGW-w64 (`g++`)

### Build Adımları
```cmd
# 1. Sanal ortam oluştur (önerilen)
python -m venv venv
venv\Scripts\activate

# 2. Bağımlılıkları kur
pip install PyQt5 mutagen numpy pyinstaller pybind11

# 3. Build çalıştır
build_windows.bat
```

**Çıktı:** `dist/Aurivo.exe` (~150-200MB)

### Test
```cmd
dist\Aurivo.exe
```

---

## 🐧 Linux Build

### Gereksinimler
- Python 3.10+
- PyQt5: `pip install PyQt5`
- PyInstaller: `pip install pyinstaller`
- (Opsiyonel) AppImage için: [appimagetool](https://github.com/AppImage/AppImageKit)

### Build Adımları - Standard Edition
```bash
# 1. Sanal ortam oluştur (önerilen)
python3 -m venv venv
source venv/bin/activate

# 2. Bağımlılıkları kur (Whisper HARİÇ)
pip install PyQt5 mutagen numpy pyinstaller

# 3. Standard build çalıştır
./build_linux_standard.sh
```

**Çıktı:** 
- `dist/aurivo-standard/aurivo` (~150-200MB)

### Build Adımları - Pro Edition
```bash
# 1. Sanal ortam kullan (yukarıdaki ile aynı)
source venv/bin/activate

# 2. Whisper ve PyTorch kur
pip install openai-whisper torch torchaudio

# 3. Pro build çalıştır
./build_linux_pro.sh
```

**Çıktı:** 
- `dist/aurivo-pro/aurivo` (~2.5GB)

### Paketleme
```bash
# Standard
cd dist
tar -czf aurivo-standard-v1.0-linux.tar.gz aurivo-standard/

# Pro
tar -czf aurivo-pro-v1.0-linux.tar.gz aurivo-pro/
```
- `Aurivo-x86_64.AppImage` (tek dosya, opsiyonel)

### Test
```bash
./dist/aurivo/aurivo
# veya
./Aurivo-x86_64.AppImage
```

---

## 📦 Dağıtım Dosyaları

### Windows
```
Aurivo-Windows-v2.0.0.zip
├── Aurivo.exe          # Ana executable
├── README.txt           # Kullanım kılavuzu
└── LICENSE.txt
```

### Linux
```
Aurivo-Linux-v2.0.0.tar.gz
├── aurivo/             # Klasör yapısı
│   ├── aurivo          # Executable
│   └── ...
└── README.txt

# veya

Aurivo-x86_64.AppImage  # Tek dosya
```

---

## 🎤 Whisper Kurulumu (Kullanıcı İçin)

Uygulama ilk kez "Otomatik Altyazı" kullanıldığında:

1. **Kontrol penceresi açılır:**
   ```
   Bu özellik 2.2GB ek indirme gerektirir.
   - PyTorch: 1.7GB
   - Whisper Model: 462MB
   
   İndirmek ister misiniz?
   ```

2. **Kabul edilirse:**
   ```bash
   # Otomatik kurulum başlar
   pip install openai-whisper
   # Model otomatik indirilir
   ```

3. **Kurulum konumu:**
   - Linux: `~/.cache/whisper/`
   - Windows: `%USERPROFILE%\.cache\whisper\`

---

## 🔧 Build Özellikleri

### Dahil OLAN Paketler
- PyQt5 (GUI)
- mutagen (metadata)
- numpy (FFT)
- subtitle_engine (C++ modülü)

### Dahil OLMAYAN Paketler (Boyut Optimizasyonu)
- ❌ whisper
- ❌ torch / torchvision
- ❌ tensorflow
- ❌ matplotlib
- ❌ pandas
- ❌ scipy

**Sonuç:** ~150MB yerine ~3GB paket boyutu önlendi!

---

## 🚀 Kullanıcıya Notlar

## 📦 Hangi Paketi İndirmeliyim?

### Aurivo Standard İndir Eğer:
- Sadece müzik dinleyecekseniz
- Video izleyeceksiniz ama altyazı gerekmiyorsa
- Manuel olarak .srt/.vtt altyazı eklemek yeterliyse
- Disk alanı sınırlıysa

### Aurivo Pro İndir Eğer:
- Videolardan otomatik altyazı oluşturacaksanız
- Çoklu dilde transkripsiyon yapacaksanız
- 2.5GB+ disk alanınız varsa

---

### İlk Çalıştırma
```
Windows Standard: Aurivo-Standard.exe'ye çift tıkla
Windows Pro:      Aurivo-Pro.exe'ye çift tıkla
Linux Standard:   ./dist/aurivo-standard/aurivo
Linux Pro:        ./dist/aurivo-pro/aurivo
```

### Standard Versiyonda Kullanım
- Müzik çalma: ✅ Tam özellikli
- Video oynatma: ✅ Tam özellikli
- Manuel altyazı: ✅ `.vtt/.srt` yükle
- Otomatik altyazı: ❌ Pro versiyonu gerekli

### Pro Versiyonda Kullanım
- Standard'daki tüm özellikler: ✅
- Otomatik altyazı: ✅ Direkt kullanılabilir
- Video menüsünden "Whisper ile Transkripsiyon" seç
- İlk çalıştırmada model indirilir (~500MB, tek seferlik)

---

## 📋 Build Kontrol Listesi

- [ ] Python 3.10+ kurulu
- [ ] PyQt5 kurulu (`pip show PyQt5`)
- [ ] PyInstaller kurulu (`pip show pyinstaller`)
- [ ] `icons/` klasörü mevcut
- [ ] `main.py` güncel
- [ ] Build script çalıştırıldı
- [ ] Executable test edildi
- [ ] Boyut kontrol edildi (~150-200MB)
- [ ] Whisper yok (excludes listesi)
- [ ] İcon düzgün görünüyor

---

## 🐛 Yaygın Sorunlar

### "PyQt5 bulunamadı"
```bash
pip install PyQt5
```

### "DLL/Library eksik" (Windows)
- Visual C++ Redistributable 2015-2022 gerekli
- İndir: https://aka.ms/vs/17/release/vc_redist.x64.exe

### "libQt5Core.so.5 eksik" (Linux)
```bash
# Debian/Ubuntu
sudo apt install libqt5multimedia5 libqt5multimediawidgets5

# Arch Linux
sudo pacman -S qt5-multimedia

# Fedora
sudo dnf install qt5-qtmultimedia
```

### Build çok uzun sürüyor
- UPX devre dışı bırak: spec dosyasında `upx=False`
- Debug modu: `--debug=all` parametresi

---

## 📞 Destek

- GitHub Issues: [Proje linki]
- Email: [İletişim]
- Wiki: [Dokümantasyon]

---

**Son Güncelleme:** 1 Ocak 2026
**Versiyon:** 1.0.0
