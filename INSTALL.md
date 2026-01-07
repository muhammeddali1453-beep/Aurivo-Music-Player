# Aurivo Music Player - Kurulum Rehberi

## ⚠️ DİKKAT

> **Bu uygulama geliştirme aşamasındadır!**  
> Kararsız davranışlar, hatalar ve eksik özellikler bekleyebilirsiniz.  
> Lütfen karşılaştığınız sorunları [GitHub Issues](../../issues)'da bildirin.

---

## 📦 İndirme

### GitHub Releases'tan İndirme
1. [Releases sayfasına](../../releases) gidin
2. En son sürümü bulun (örn: v1.0)
3. **Assets** bölümünden `Aurivo-Linux-v1.0.tar.gz` dosyasını indirin (203 MB)

### Komut satırından indirme (opsiyonel)
```bash
wget https://github.com/KULLANICI_ADI/Aurivo-Music-Player/releases/latest/download/Aurivo-Linux-v1.0.tar.gz
```

## 🚀 Kurulum (Linux)

### 1. Sistem Gereksinimleri
Aurivo çalışmak için şu sistem paketlerine ihtiyaç duyar:

```bash
# Arch Linux / Manjaro
sudo pacman -S gst-plugins-base gst-plugins-good gst-plugins-bad gst-libav

# Ubuntu / Debian
sudo apt install gstreamer1.0-plugins-base gstreamer1.0-plugins-good \
                 gstreamer1.0-plugins-bad gstreamer1.0-libav

# Fedora
sudo dnf install gstreamer1-plugins-base gstreamer1-plugins-good \
                 gstreamer1-plugins-bad-free gstreamer1-libav
```

### 2. Paketi Çıkartma
```bash
tar -xzf Aurivo-Linux-v1.0.tar.gz
cd aurivo
```

### 3. Çalıştırma
```bash
./aurivo
```

### 4. Masaüstü Kısayolu Oluşturma (Opsiyonel)
Uygulama menüsünden başlatmak için:

```bash
# Desktop dosyasını kopyalayın
cp aurivo.desktop ~/.local/share/applications/

# Icon'u kopyalayın (Icon=aurivo)
mkdir -p ~/.local/share/icons/hicolor/48x48/apps/
cp icons/media-playback-start.png ~/.local/share/icons/hicolor/48x48/apps/aurivo.png

# Desktop veritabanını güncelleyin
update-desktop-database ~/.local/share/applications/
```

Artık uygulama menünüzde "Aurivo Music Player" görünecektir.

### 5. Sistem Geneline Kurulum (Tüm Kullanıcılar)
Tüm kullanıcılar için (menü + ikon + komut) kurmak isterseniz:

```bash
chmod +x ./install_systemwide.sh

# Binary yolunu siz verin (örn: release paketinden ./aurivo)
sudo ./install_systemwide.sh --bin ./aurivo

# Alternatif: build çıktınız farklıysa
# sudo ./install_systemwide.sh --bin ./build/aurivo_linux/aurivo
```

Kurulumdan sonra menüde görünmüyorsa oturumu kapat/aç yapın veya:

```bash
update-desktop-database /usr/local/share/applications/ || true
gtk-update-icon-cache -f /usr/local/share/icons/hicolor || true
```

## 🎵 İlk Kullanım

1. **Müzik Ekleme**: Sürükle-bırak ile dosya ekleyin veya sağ tıklayarak "Dosya Ekle" seçin
2. **Kütüphane Tarama**: Ayarlar → Kütüphane → Klasör Ekle
3. **Görselleştirme**: 11 farklı görselleştirme modu (Alt panel veya tam ekran)
4. **Ekolayzır**: Ses → Ekolayzır (10 bant ayarlanabilir)
5. **Video Oynatma**: Video dosyalarını sürükleyip bırakın
6. **Altyazı**: Video oynatırken sağ tıklayın → Altyazı Seç (otomatik transkripsiyon için Whisper kurulumu gerekir)

## 🛠️ Gelişmiş Özellikler

### Whisper Altyazı Desteği (Opsiyonel)
Otomatik video transkripsiyon için:

```bash
# Whisper kurulumu
pip install openai-whisper

# Kullanım: Video oynatırken sağ tıklayın → "Whisper ile Transkripsiyonu Oluştur"
```

### DSP Efektleri
Dahili C++ DSP motoru ile:
- Compressor
- Limiter
- Exciter
- Stereo Widener
- Bass Boost

Efektler otomatik olarak yüklenir (aurivo_dsp.so).

## ⚙️ Ayarlar ve Yapılandırma

Ayarlar otomatik olarak şurada saklanır:
- Yapılandırma: `~/.config/Aurivo/aurivo_config.json`
- Çalma listeleri: `~/.config/Aurivo/aurivo_playlist.json`
- Altyazılar: `~/.local/share/aurivo/subtitles/`

## 🐛 Sorun Giderme

### Video oynatılmıyor
```bash
# Codec desteğini kontrol edin
gst-inspect-1.0 | grep -i libav

# Eksik codec paketini kurun
sudo pacman -S gst-libav  # Arch
sudo apt install gstreamer1.0-libav  # Ubuntu
```

### Ses çıkmıyor
- Sistem ses ayarlarını kontrol edin
- Aurivo içindeki ses seviyesini kontrol edin
- Terminal'den `./aurivo` çalıştırıp hata mesajlarını kontrol edin

### Görselleştirme çalışmıyor
- NumPy kurulu olduğundan emin olun: `pip install numpy`
- OpenGL sürücülerini kontrol edin

### Desktop kısayolu görünmüyor
```bash
# XDG veritabanını manuel güncelleme
update-desktop-database ~/.local/share/applications/
gtk-update-icon-cache ~/.local/share/icons/hicolor/
```

## 📊 Sistem Gereksinimleri

| Bileşen | Minimum | Önerilen |
|---------|---------|----------|
| İşletim Sistemi | Linux (kernel 5.0+) | Linux (kernel 6.0+) |
| RAM | 512 MB | 1 GB |
| Disk Alanı | 250 MB | 300 MB |
| İşlemci | Dual-core 1.5 GHz | Quad-core 2.0 GHz |
| GPU | OpenGL 2.0 | OpenGL 3.0+ |

## 🔄 Güncelleme

Yeni sürüm için:
1. [Releases sayfasından](../../releases) yeni sürümü indirin
2. Eski klasörü silin veya yeniden adlandırın
3. Yeni paketi çıkartın
4. Ayarlarınız otomatik olarak korunur (~/.config/Aurivo/)

## 📝 Lisans

Bu yazılım [LICENSE](LICENSE) dosyasında belirtilen lisans altında dağıtılmaktadır.

## 🤝 Destek

- **Hata Bildirimi**: [GitHub Issues](../../issues)
- **Özellik İsteği**: [GitHub Discussions](../../discussions)
- **Dokümantasyon**: [Wiki](../../wiki)

## 🌟 Katkıda Bulunma

Kaynak koddan derlemek veya geliştirmeye katkıda bulunmak için [CONTRIBUTING.md](CONTRIBUTING.md) dosyasına bakın.
