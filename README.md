# 🎵 Angolla Music Player

<div align="center">

![Angolla Logo](icons/media-playback-start.png)

**Clementine'den ilham alan güçlü, hafif ve görsel açıdan zengin müzik çalar**

[![Linux](https://img.shields.io/badge/Platform-Linux-blue.svg)](https://github.com)
[![Python](https://img.shields.io/badge/Python-3.11+-green.svg)](https://python.org)
[![PyQt5](https://img.shields.io/badge/GUI-PyQt5-orange.svg)](https://riverbankcomputing.com/software/pyqt/)
[![License](https://img.shields.io/badge/License-GPL--3.0-red.svg)](LICENSE)

[📥 İndir](../../releases) | [📖 Kurulum](INSTALL.md) | [🐛 Hata Bildir](../../issues) | [💬 Tartışmalar](../../discussions)

</div>

---

## ✨ Özellikler

### 🎨 Görselleştirme
- **11 Farklı Mod**: Çizgiler, Daireler, Spektrum, Enerji Halkaları, Dalga, Pulsar, Spiral, Volcano, Işın, Çift Spektrum, Radyal Grid
- **Gerçek Zamanlı FFT Analizi**: NumPy tabanlı 96-band frekans spektrumu
- **Tam Ekran Desteği**: Ayrı pencerede veya ana ekran altında
- **Clementine Tarzı Animasyon**: Attack/release yumuşatma, cap heights

### 🎛️ Ses İşleme
- **10 Bantlı Ekolayzır**: Tam kontrol edilebilir frekans bantları
- **DSP Efektleri** (C++ motoru):
  - Compressor
  - Limiter
  - Exciter
  - Stereo Widener
  - Bass Boost
- **Crossfade**: Parçalar arası geçiş efekti

### 📚 Kütüphane Yönetimi
- **SQLite Veritabanı**: Hızlı tarama ve arama
- **Metadata Desteği**: ID3, MP4, FLAC, Vorbis
- **Sıralanabilir Tablo**: Başlık, sanatçı, albüm, süre
- **Playlist Koleksiyonları**: Çoklu playlist yönetimi

### 🎬 Video Desteği
- **Video Oynatma**: GStreamer tabanlı
- **Çoklu Dil Altyazı**: SRT, VTT formatları
- **Otomatik Transkripsiyon**: Whisper entegrasyonu (opsiyonel)
- **C++ Subtitle Engine**: pybind11 ile hızlı işleme

### 🎨 Tema Sistemi
- **7 Hazır Tema**: AURA Mavi, Gece Moru, Neon Yeşil, Gün Batımı, vb.
- **Bar Renk Modları**: Normal, RGB spektrum, Gradyan
- **Dinamik Renkler**: Tema değişimi ile otomatik uyum

## 🚀 Hızlı Başlangıç

### İndirme ve Kurulum
```bash
# 1. Son sürümü indirin
wget https://github.com/KULLANICI_ADI/Angolla-Music-Player/releases/latest/download/Angolla-Linux-v1.0.tar.gz

# 2. Sistem bağımlılıklarını kurun
sudo pacman -S gst-plugins-base gst-plugins-good gst-plugins-bad gst-libav  # Arch
# sudo apt install gstreamer1.0-plugins-* gstreamer1.0-libav  # Ubuntu

# 3. Paketi çıkartın
tar -xzf Angolla-Linux-v1.0.tar.gz
cd angolla

# 4. Çalıştırın
./angolla
```

Detaylı kurulum talimatları için [INSTALL.md](INSTALL.md) dosyasına bakın.

## 📸 Ekran Görüntüleri

### Ana Arayüz
<div align="center">
  <img src="screenshots/01-main-interface.png" alt="Ana Arayüz" width="80%">
  <p><em>Playlist yönetimi ve görselleştirme</em></p>
</div>

### Görselleştirme Modları
<div align="center">
  <img src="screenshots/02-visualization-1.png" alt="Görselleştirme 1" width="45%">
  <img src="screenshots/03-visualization-2.png" alt="Görselleştirme 2" width="45%">
  <p><em>11 farklı FFT tabanlı görselleştirme modu</em></p>
</div>

### Ekolayzır & Kütüphane
<div align="center">
  <img src="screenshots/04-equalizer.png" alt="10 Bantlı Ekolayzır" width="45%">
  <img src="screenshots/05-library-view.png" alt="Kütüphane Görünümü" width="45%">
  <p><em>10 bantlı EQ ve SQLite kütüphane yönetimi</em></p>
</div>

### Tam Ekran & Video Desteği
<div align="center">
  <img src="screenshots/07-fullscreen.png" alt="Tam Ekran Görselleştirme" width="45%">
  <img src="screenshots/08-video-subtitle.png" alt="Video + Altyazı" width="45%">
  <p><em>Tam ekran mod ve çoklu dil altyazı desteği</em></p>
</div>

## 💻 Teknik Detaylar

### Mimari
- **Tek Dosya Yapısı**: ~3000+ satır monolitik Python kodu
- **PyQt5 GUI**: QMainWindow, QMediaPlayer, QAudioProbe
- **C++ Bileşenler**:
  - `angolla_dsp.so`: Ses efektleri motoru
  - `subtitle_engine.so`: Altyazı işleme (pybind11)
- **FFT Pipeline**: QAudioProbe → NumPy → 96-band spektrum → Görselleştirme

### Ses Veri Akışı
```
QMediaPlayer → QAudioProbe → process_audio_buffer() 
  → FFT Analizi → send_visual_data() 
  → update_sound_data() (Yumuşatma) 
  → paintEvent() → Render
```

### Desteklenen Formatlar
- **Ses**: MP3, FLAC, OGG, M4A, WAV
- **Video**: MP4, MKV, AVI, WebM (GStreamer codec desteğine bağlı)
- **Altyazı**: SRT, VTT

## 🛠️ Kaynak Koddan Derleme

```bash
# 1. Repository'yi klonlayın
git clone https://github.com/KULLANICI_ADI/Angolla-Music-Player.git
cd Angolla-Music-Player

# 2. Python bağımlılıklarını kurun
pip install PyQt5 mutagen numpy soundfile Pillow

# 3. C++ modüllerini derleyin
python setup.py build_ext --inplace

# 4. Linux paketi oluşturun
./build_linux.sh

# 5. Dağıtım arşivi oluşturun
./package_linux.sh
```

Detaylar için [DISTRIBUTION.md](DISTRIBUTION.md) dosyasına bakın.

## 📋 Sistem Gereksinimleri

| Bileşen | Minimum | Önerilen |
|---------|---------|----------|
| OS | Linux (kernel 5.0+) | Linux (kernel 6.0+) |
| RAM | 512 MB | 1 GB |
| Disk | 250 MB | 300 MB |
| CPU | Dual-core 1.5 GHz | Quad-core 2.0 GHz |
| GPU | OpenGL 2.0 | OpenGL 3.0+ |

## 🤝 Katkıda Bulunma

Katkılarınızı bekliyoruz! Pull request göndermeden önce:

1. Fork edin ve branch oluşturun
2. Değişikliklerinizi test edin
3. Türkçe kod yorumları ekleyin
4. Pull request açın

Detaylar için [CONTRIBUTING.md](CONTRIBUTING.md) dosyasına bakın.

## 📝 Lisans

Bu proje GPL-3.0 lisansı altında dağıtılmaktadır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

## 🐛 Hata Bildirimi

Hata bulduysanız veya özellik önerisi yapmak istiyorsanız:
- [GitHub Issues](../../issues) üzerinden hata bildirin
- Terminal çıktısını ekleyin (`./angolla` ile çalıştırın)
- Sistem bilgilerinizi paylaşın (distro, Python versiyonu)

## 🙏 Teşekkürler

- **Clementine**: İlham kaynağı
- **PyQt5**: GUI framework
- **NumPy**: FFT analizi
- **GStreamer**: Multimedia pipeline
- **Whisper**: Otomatik transkripsiyon

---

<div align="center">

**Angolla ile müziğinizin tadını çıkarın! 🎶**

[⬆ Başa Dön](#-angolla-music-player)

</div>
