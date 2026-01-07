# 📦 GitHub Release Hazırlık Checklist

## Ön Hazırlık

- [ ] **Version numarası belirle**: Örnek: `v1.0`, `v1.1`, `v2.0`
- [ ] **Changelog hazırla**: Yeni özellikler, düzeltmeler, değişiklikler
- [ ] **Tüm testler geçiyor**: Yerel sistemde test et

### 🏗️ Build İşlemleri (İKİ VERSİYON)

#### Standard Versiyon (Altyazı HARİÇ - ~150-200MB)
- [ ] **Linux Build**: `./build_linux_standard.sh` hatasız çalışıyor
- [ ] **Windows Build**: `build_windows_standard.bat` hatasız çalışıyor (Windows'ta)
- [ ] **Paketleme**: Oluşturulan dosyaları yeniden adlandır:
  - Linux: `aurivo-standard-vX.X-linux.tar.gz`
  - Windows: `aurivo-standard-vX.X-windows.zip`

#### Pro Versiyon (Altyazı DAHİL - ~2GB+)
- [ ] **Linux Build**: `./build_linux_pro.sh` hatasız çalışıyor
- [ ] **Windows Build**: `build_windows_pro.bat` hatasız çalışıyor (Windows'ta)
- [ ] **Paketleme**: Oluşturulan dosyaları yeniden adlandır:
  - Linux: `aurivo-pro-vX.X-linux.tar.gz`
  - Windows: `aurivo-pro-vX.X-windows.zip`

- [ ] **Tüm paketler test edildi**: Her dosya açılıp çalıştırıldı

## GitHub Ayarları

### Repository Ayarları
1. GitHub'da repository oluştur: `https://github.com/KULLANICI_ADINIZ/Aurivo-Music-Player`
2. Repository ayarları:
  - **Description**: "🎵 Aurivo: güçlü, hafif ve görsel açıdan zengin müzik çalar — 11 görselleştirme modu, DSP efektleri ve video altyazı desteği"
   - **Topics**: `music-player`, `pyqt5`, `linux`, `audio-visualization`, `gstreamer`, `fft`, `dsp`
   - **Website**: (varsa)

### İlk Commit ve Push
```bash
cd /home/muhammet-dali/Aurivo-Music-Player

# Git başlat (eğer yoksa)
git init

# .gitignore ekle
cat > .gitignore << 'EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
*.egg-info/
dist/
build/
*.egg

# Virtual Environments
venv/
venv311/
pyqt_venv/
env/

# IDE
.vscode/
.idea/
*.swp
*.swo

# Config files (user-specific)
aurivo_config.json
aurivo_playlist.json
aurivo_playlists_collection.json
aurivo_playlists_collection.pkl.bak

# Build artifacts
*.tar.gz
*.zip

# Temporary files
*.bak
*.tmp
.DS_Store

# Presets (too large, optional)
presets/
pyprojectx-main/
EOF

# Dosyaları stage'e al
git add .
git commit -m "Initial commit: Aurivo Music Player v1.0"

# Remote ekle
git remote add origin https://github.com/KULLANICI_ADINIZ/Aurivo-Music-Player.git

# Push et
git branch -M main
git push -u origin main
```

## Release Oluşturma

### 1. GitHub Web Interface'den
1. Repository'ye git: `https://github.com/KULLANICI_ADINIZ/Aurivo-Music-Player`
2. Sağ tarafta **"Releases"** → **"Create a new release"**
3. **"Choose a tag"** → `v1.0` yaz (yeni tag oluştur)
4. **Release title**: `Aurivo Music Player v1.0 - İlk Kararlı Sürüm`
5. **Description**: (Aşağıdaki template'i kullan)

#### Release Description Template
```markdown
# 🎉 Aurivo Music Player v1.0

İlk kararlı sürümümüzü duyurmaktan mutluluk duyuyoruz!

---

## 📥 İNDİRME SEÇENEKLERİ / DOWNLOAD OPTIONS

### 🎵 Standard Edition (~150-200MB) - ÖNERİLEN / RECOMMENDED
**Çoğu kullanıcı için ideal** — Tüm temel özellikler dahil

#### Linux:
- **aurivo-standard-v1.0-linux.tar.gz** — Doğrudan çalıştırılabilir

#### Windows:
- **aurivo-standard-v1.0-windows.zip** — Kurulum gerektirmez

**İçerik:**
- ✅ Müzik ve video oynatma (tüm formatlar)
- ✅ 11 görselleştirme modu
- ✅ 32-band EQ + yüzlerce preset
- ✅ DSP efektleri (Compressor, Limiter, Exciter, vb.)
- ✅ Manuel altyazı (.srt, .vtt dosyaları)
- ✅ YouTube indirme
- ❌ Otomatik altyazı (AI transkripsiyon)

---

### 🚀 Pro Edition (~2GB+) - ADVANCED
**Otomatik video altyazısı isteyenler için** — Whisper AI dahil

#### Linux:
- **aurivo-pro-v1.0-linux.tar.gz** — AI modelleri dahil

#### Windows:
- **aurivo-pro-v1.0-windows.zip** — AI modelleri dahil

**Ek Özellikler:**
- ✅ **Standard'daki tüm özellikler**
- ✅ **Otomatik video transkripsiyon** (Whisper AI)
- ✅ **Çoklu dil altyazı oluşturma** (90+ dil)
- ✅ **Gerçek zamanlı altyazı üretimi**

⚠️ **Not:** Pro sürüm daha büyük boyutlu (AI modelleri nedeniyle). Sadece otomatik altyazı özelliği gerekiyorsa indirin.

---

## ✨ Özellikler

### 🎨 Görselleştirme
- 11 farklı görselleştirme modu (FFT tabanlı)
- Tam ekran desteği
- Akıcı animasyonlar

### 🎛️ Ses İşleme
- 10 bantlı ekolayzır
- 5 DSP efekti (C++ motoru)
- Crossfade desteği

### 📚 Kütüphane
- SQLite veritabanı
- Hızlı arama ve tarama
- Playlist koleksiyonları

### 🎬 Video
- Video oynatma
- Çoklu dil altyazı
- Whisper transkripsiyon (opsiyonel)

## 📥 İndirme ve Kurulum

### Sistem Gereksinimleri
- **OS**: Linux (kernel 5.0+)
- **RAM**: 512 MB minimum
- **Disk**: 250 MB

### Kurulum
```bash
# 1. Sistem bağımlılıklarını kurun
sudo pacman -S gst-plugins-base gst-plugins-good gst-plugins-bad gst-libav

# 2. Paketi indirip çıkartın
tar -xzf Aurivo-Linux-v2.0.0.tar.gz
cd aurivo

# 3. Çalıştırın
./aurivo
```

Detaylı talimatlar için [INSTALL.md](INSTALL.md) dosyasına bakın.

## 📊 Paket İçeriği
- **Boyut**: 203 MB (sıkıştırılmış), 545 MB (açılmış)
- **Python**: 3.13.11
- **PyQt5**: 5.15.11
- **Dahil Bileşenler**:
  - Ana uygulama (aurivo.bin)
  - DSP motoru (Linux: aurivo_dsp.so / Windows: aurivo_dsp.dll)
  - Subtitle engine (Linux: subtitle_engine*.so / Windows: subtitle_engine*.pyd)
  - 11 görselleştirme modu
  - Icon set (SVG)
  - Desktop integration

## 🐛 Bilinen Sorunlar
- Video oynatma bazı codec'lerde sorun yaşayabilir (gst-libav kurulumu gerekli)
- Whisper özelliği için ayrı kurulum gerekiyor (~2.2 GB)

## 🔄 Yükseltme
Bu ilk sürüm olduğu için önceki sürümden yükseltme yok.

## 🙏 Teşekkürler
Clementine, PyQt5, NumPy, GStreamer ve tüm açık kaynak topluluğuna teşekkürler!

---

**İlk defa kullanıyorsanız**: [Hızlı Başlangıç Rehberi](INSTALL.md#-i̇lk-kullanım)
**Sorun mu yaşıyorsunuz**: [Sorun Giderme](INSTALL.md#-sorun-giderme)
**Katkıda bulunun**: [CONTRIBUTING.md](CONTRIBUTING.md)
```

6. **Assets Yükleme**:
  - `Aurivo-Linux-v2.0.0.tar.gz` dosyasını sürükle-bırak (dist/ klasöründen)
   - Dosya yüklenene kadar bekle

7. **Set as latest release** işaretle
8. **Publish release** butonuna tıkla

### 2. Komut Satırından (GitHub CLI ile)
```bash
# GitHub CLI kur (eğer yoksa)
sudo pacman -S github-cli  # Arch
# sudo apt install gh  # Ubuntu

# Giriş yap
gh auth login

# Tag oluştur
git tag -a v1.0 -m "Aurivo Music Player v1.0 - İlk Kararlı Sürüm"
git push origin v1.0

# Release oluştur
gh release create v1.0 \
  dist/Aurivo-Linux-v1.0.tar.gz \
  --title "Aurivo Music Player v1.0 - İlk Kararlı Sürüm" \
  --notes-file release_notes.md
```

## Post-Release

### Release Notes Dosyası (Opsiyonel)
Eğer CLI kullanacaksanız:
```bash
cat > release_notes.md << 'EOF'
# 🎉 Aurivo Music Player v1.0

[Yukarıdaki template'i buraya kopyala]
EOF
```

### Duyuru
- [ ] README.md'de download link'ini güncelle
- [ ] Discord/Forum'da duyuru yap
- [ ] Twitter/sosyal medya paylaşımı

### Kullanıcı Dokümanları
- [ ] Wiki sayfaları oluştur
- [ ] Ekran görüntüleri ekle
- [ ] Video demo hazırla (opsiyonel)

## Sonraki Sürümler İçin

### Version Numarası Kuralı
- **Major (v2.0)**: Büyük özellik eklemeleri, API değişiklikleri
- **Minor (v1.1)**: Yeni özellikler, geriye uyumlu
- **Patch (v1.0.1)**: Hata düzeltmeleri

### Her Release için
```bash
# 1. Değişiklikleri commit'le
git add .
git commit -m "Release v1.1: [Özellik adı]"

# 2. Tag oluştur
git tag -a v1.1 -m "v1.1 release notes"

# 3. Push et
git push origin main --tags

# 4. Yeni paketi build et
./build_linux.sh
./package_linux.sh

# 5. GitHub'da yeni release oluştur
gh release create v1.1 dist/Aurivo-Linux-v1.1.tar.gz \
  --title "Aurivo v1.1" \
  --notes "Changelog..."
```

## Güvenlik

### GPG İmzalama (Önerilen)
```bash
# GPG key oluştur (eğer yoksa)
gpg --full-generate-key

# Paketi imzala
gpg --detach-sign --armor dist/Aurivo-Linux-v1.0.tar.gz

# Release'e imza dosyasını da ekle
gh release upload v1.0 dist/Aurivo-Linux-v1.0.tar.gz.asc
```

### SHA256 Checksum
```bash
# Checksum oluştur
sha256sum dist/Aurivo-Linux-v1.0.tar.gz > Aurivo-Linux-v1.0.sha256

# Release notes'a ekle
cat Aurivo-Linux-v1.0.sha256
```

## Troubleshooting

### Git push hata veriyor
```bash
# SSH key ayarla
ssh-keygen -t ed25519 -C "your_email@example.com"
cat ~/.ssh/id_ed25519.pub  # GitHub'a ekle
```

### Release asset çok büyük (>2GB)
GitHub dosya limiti 2GB. Eğer Whisper dahil paket oluşturacaksanız:
- Whisper'ı ayrı release'de dağıtın
- External hosting kullanın (Google Drive, DropBox)

### Tag silme/düzenleme
```bash
# Yerel tag'i sil
git tag -d v1.0

# Remote tag'i sil
git push origin :refs/tags/v1.0

# Yeniden oluştur
git tag -a v1.0 -m "Updated release"
git push origin v1.0
```

---

## ✅ Son Kontrol

Release yapmadan önce:
- [ ] Tüm dosyalar commit'lendi
- [ ] README.md güncel
- [ ] INSTALL.md talimatları doğru
- [ ] Paket test edildi
- [ ] Version numarası doğru
- [ ] Changelog hazır
- [ ] Git tag oluşturuldu
- [ ] Release notes yazıldı
- [ ] Asset yüklendi
- [ ] "Latest release" işaretli

**İlk release için toplam süre**: ~15-30 dakika
**Sonraki release'ler**: ~5-10 dakika

Good luck! 🚀
