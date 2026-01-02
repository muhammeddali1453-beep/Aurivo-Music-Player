# 📦 GitHub Release Hazırlık Checklist

## Ön Hazırlık

- [ ] **Version numarası belirle**: Örnek: `v1.0`, `v1.1`, `v2.0`
- [ ] **Changelog hazırla**: Yeni özellikler, düzeltmeler, değişiklikler
- [ ] **Tüm testler geçiyor**: Yerel sistemde test et
- [ ] **Build başarılı**: `./build_linux.sh` hatasız çalışıyor
- [ ] **Paket oluşturuldu**: `./package_linux.sh` ile tar.gz oluşturuldu

## GitHub Ayarları

### Repository Ayarları
1. GitHub'da repository oluştur: `https://github.com/KULLANICI_ADINIZ/Angolla-Music-Player`
2. Repository ayarları:
   - **Description**: "🎵 Clementine-inspired music player with 11 visualizations, DSP effects, and video subtitle support"
   - **Topics**: `music-player`, `pyqt5`, `linux`, `audio-visualization`, `gstreamer`, `fft`, `dsp`
   - **Website**: (varsa)

### İlk Commit ve Push
```bash
cd /home/muhammet-dali/Angolla-Music-Player

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
angolla_config.json
angolla_playlist.json
angolla_playlists_collection.json
angolla_playlists_collection.pkl.bak

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
git commit -m "Initial commit: Angolla Music Player v1.0"

# Remote ekle
git remote add origin https://github.com/KULLANICI_ADINIZ/Angolla-Music-Player.git

# Push et
git branch -M main
git push -u origin main
```

## Release Oluşturma

### 1. GitHub Web Interface'den
1. Repository'ye git: `https://github.com/KULLANICI_ADINIZ/Angolla-Music-Player`
2. Sağ tarafta **"Releases"** → **"Create a new release"**
3. **"Choose a tag"** → `v1.0` yaz (yeni tag oluştur)
4. **Release title**: `Angolla Music Player v1.0 - İlk Kararlı Sürüm`
5. **Description**: (Aşağıdaki template'i kullan)

#### Release Description Template
```markdown
# 🎉 Angolla Music Player v1.0

İlk kararlı sürümümüzü duyurmaktan mutluluk duyuyoruz!

## ✨ Özellikler

### 🎨 Görselleştirme
- 11 farklı görselleştirme modu (FFT tabanlı)
- Tam ekran desteği
- Clementine tarzı animasyonlar

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
tar -xzf Angolla-Linux-v1.0.tar.gz
cd angolla

# 3. Çalıştırın
./angolla
```

Detaylı talimatlar için [INSTALL.md](INSTALL.md) dosyasına bakın.

## 📊 Paket İçeriği
- **Boyut**: 203 MB (sıkıştırılmış), 545 MB (açılmış)
- **Python**: 3.13.11
- **PyQt5**: 5.15.11
- **Dahil Bileşenler**:
  - Ana uygulama (angolla.bin)
  - DSP motoru (angolla_dsp.so)
  - Subtitle engine (subtitle_engine.so)
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
   - `Angolla-Linux-v1.0.tar.gz` dosyasını sürükle-bırak (dist/ klasöründen)
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
git tag -a v1.0 -m "Angolla Music Player v1.0 - İlk Kararlı Sürüm"
git push origin v1.0

# Release oluştur
gh release create v1.0 \
  dist/Angolla-Linux-v1.0.tar.gz \
  --title "Angolla Music Player v1.0 - İlk Kararlı Sürüm" \
  --notes-file release_notes.md
```

## Post-Release

### Release Notes Dosyası (Opsiyonel)
Eğer CLI kullanacaksanız:
```bash
cat > release_notes.md << 'EOF'
# 🎉 Angolla Music Player v1.0

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
gh release create v1.1 dist/Angolla-Linux-v1.1.tar.gz \
  --title "Angolla v1.1" \
  --notes "Changelog..."
```

## Güvenlik

### GPG İmzalama (Önerilen)
```bash
# GPG key oluştur (eğer yoksa)
gpg --full-generate-key

# Paketi imzala
gpg --detach-sign --armor dist/Angolla-Linux-v1.0.tar.gz

# Release'e imza dosyasını da ekle
gh release upload v1.0 dist/Angolla-Linux-v1.0.tar.gz.asc
```

### SHA256 Checksum
```bash
# Checksum oluştur
sha256sum dist/Angolla-Linux-v1.0.tar.gz > Angolla-Linux-v1.0.sha256

# Release notes'a ekle
cat Angolla-Linux-v1.0.sha256
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
