# Angolla Music Player - Dağıtım Kılavuzu

## 🎵 Paket Stratejisi

**Tek paket + Opsiyonel Whisper**
- Ana paket: ~150-200MB (temel özellikler)
- Whisper eklentisi: ~2.2GB (kullanıcı isteğe bağlı)

### Neler Dahil?
✅ Müzik çalar (tüm formatlar)
✅ Video oynatıcı
✅ 11 görselleştirme modu
✅ Manuel altyazı desteği
✅ Ekolayzır + DSP efektleri
✅ Kütüphane yönetimi

❌ Otomatik altyazı (Whisper) - **kullanıcı yükler**

---

## 🪟 Windows 10/11 Build

### Gereksinimler
- Python 3.10+
- PyQt5: `pip install PyQt5`
- PyInstaller: `pip install pyinstaller`

### Build Adımları
```cmd
# 1. Sanal ortam oluştur (önerilen)
python -m venv venv
venv\Scripts\activate

# 2. Bağımlılıkları kur
pip install PyQt5 mutagen numpy pyinstaller

# 3. Build çalıştır
build_windows.bat
```

**Çıktı:** `dist/Angolla.exe` (~150-200MB)

### Test
```cmd
dist\Angolla.exe
```

---

## 🐧 Linux Build

### Gereksinimler
- Python 3.10+
- PyQt5: `pip install PyQt5`
- PyInstaller: `pip install pyinstaller`
- (Opsiyonel) AppImage için: [appimagetool](https://github.com/AppImage/AppImageKit)

### Build Adımları
```bash
# 1. Sanal ortam oluştur (önerilen)
python3 -m venv venv
source venv/bin/activate

# 2. Bağımlılıkları kur
pip install PyQt5 mutagen numpy pyinstaller

# 3. Build çalıştır
./build_linux.sh
```

**Çıktı:** 
- `dist/angolla/angolla` (klasör yapısı)
- `Angolla-x86_64.AppImage` (tek dosya, opsiyonel)

### Test
```bash
./dist/angolla/angolla
# veya
./Angolla-x86_64.AppImage
```

---

## 📦 Dağıtım Dosyaları

### Windows
```
Angolla-Windows-v1.0.zip
├── Angolla.exe          # Ana executable
├── README.txt           # Kullanım kılavuzu
└── LICENSE.txt
```

### Linux
```
Angolla-Linux-v1.0.tar.gz
├── angolla/             # Klasör yapısı
│   ├── angolla          # Executable
│   └── ...
└── README.txt

# veya

Angolla-x86_64.AppImage  # Tek dosya
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

### İlk Çalıştırma
```
Windows: Angolla.exe'ye çift tıkla
Linux:   ./angolla veya AppImage'a çift tıkla
```

### Whisper Olmadan Kullanım
- Müzik çalma: ✅ Tam özellikli
- Video oynatma: ✅ Tam özellikli
- Manuel altyazı: ✅ `.vtt/.srt` yükle
- Otomatik altyazı: ❌ Whisper gerekli

### Whisper İle Kullanım
1. Video menüsünden "Otomatik Altyazı" seç
2. İlk seferde kurulum prompt'u gelir
3. Kabul et → 2.2GB indirilir (~5-10 dakika)
4. Sonraki videolarda direkt çalışır

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
