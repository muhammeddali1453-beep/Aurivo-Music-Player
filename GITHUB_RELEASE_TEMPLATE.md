# 🎉 Aurivo Music Player v1.0

İlk kararlı sürümümüzü duyurmaktan mutluluk duyuyoruz!

---

## 📥 İNDİRME / DOWNLOAD

### 🎵 Aurivo Music Player (~205MB)

#### 🐧 Linux:
- **aurivo-standard-v1.0-linux.tar.gz** — Doğrudan çalıştırılabilir

**Tüm Özellikler Dahil:**
- ✅ Müzik ve video oynatma (tüm formatlar: MP3, FLAC, OGG, M4A, WAV, MP4, MKV, AVI)
- ✅ 11 görselleştirme modu (gerçek zamanlı FFT analizi)
- ✅ 32-band EQ + yüzlerce hazır preset
- ✅ DSP efektleri (Compressor, Limiter, Exciter, Stereo Widener, Bass Boost)
- ✅ Manuel altyazı desteği (.srt, .vtt dosyaları)
- ✅ YouTube video/müzik indirme
- ✅ Kütüphane yönetimi (SQLite)
- ✅ Çoklu tema desteği
- ✅ Playlist yönetimi (sürükle-bırak)

---

## 🚀 Otomatik Altyazı (Opsiyonel)

**Otomatik video transkripsiyon** istiyorsanız, uygulamayı indirdikten sonra Whisper AI'yi kurun:

```bash
pip install openai-whisper torch
```

**Whisper ile Ek Özellikler:**
- ✅ **Otomatik video transkripsiyon** (AI tabanlı)
- ✅ **90+ dil desteği** (İngilizce, Türkçe, Fransızca, Almanca, İspanyolca, Japonca, Korece, vb.)
- ✅ **Gerçek zamanlı altyazı üretimi** (video oynatırken)
- ✅ **Altyazı dışa aktarma** (.srt, .vtt formatları)

⚠️ **Not:** Whisper + PyTorch kurulumu yaklaşık **~2GB** ek alan gerektirir.

**Uygulama otomatik algılar:** Whisper kuruluysa altyazı özellikleri aktif olur, yoksa manuel altyazı (.srt/.vtt) kullanabilirsiniz.

---

## ✨ Özellikler / Features

### 🎨 Görselleştirme
- **11 Farklı Mod**: Çizgiler, Daireler, Spektrum Çubukları, Enerji Halkaları, Dalga Formu, Pulsar, Spiral, Volcano, Işın Çakışması, Çift Spektrum, Radyal Grid
- **Gerçek Zamanlı FFT Analizi**: NumPy tabanlı 96-band frekans spektrumu
- **Tam Ekran Desteği**: Ayrı pencerede veya ana ekran altında
- **Akıcı Bar Animasyonu**: Attack/release yumuşatma, cap heights (Clementine tarzı)

### 🎛️ Ses İşleme
- **32 Bant Ekolayzır**: Yüzlerce hazır preset (Rock, Pop, Jazz, Classical, vb.)
- **DSP Efektleri** (C++ motoru ile):
  - Compressor (dinamik aralık kontrolü)
  - Limiter (pik sınırlama)
  - Exciter (harmonik zenginleştirme)
  - Stereo Widener (stereo imaj genişletme)
  - Bass Boost (bas güçlendirme)
- **Crossfade**: Parçalar arası yumuşak geçiş efekti

### 📚 Kütüphane Yönetimi
- **SQLite Veritabanı**: Hızlı tarama ve arama
- **Otomatik Metadata**: Mutagen ile tag çıkarma
- **Sıralanabilir Kolon**: Başlık, sanatçı, albüm, süre
- **Çoklu Format Desteği**: MP3, FLAC, OGG, M4A, WAV

### 🎬 Video Oynatma
- **Geniş Codec Desteği**: MP4, MKV, AVI, WebM
- **Entegre Altyazı**: .srt, .vtt dosyaları
- **Tam Ekran Modu**: Klavye kısayolları (F11)

### 📥 YouTube İndirme
- **Video/Müzik İndirme**: yt-dlp entegrasyonu
- **Format Seçimi**: MP4 (video) veya MP3 (sadece ses)
- **İlerleme Göstergesi**: Gerçek zamanlı indirme durumu

### 🎨 Tema Sistemi
- **6 Önceden Tanımlı Tema**: AURA Mavi, Karanlık Mod, Güneş, Orman, Gece, Gün Batımı
- **Özelleştirilebilir Renkler**: Renk seçici ile kendi temanızı oluşturun

---

## 🚀 Kurulum / Installation

### 🐧 Linux
```bash
# İndirin ve çıkartın
tar -xzf aurivo-standard-v1.0-linux.tar.gz
# veya
tar -xzf aurivo-pro-v1.0-linux.tar.gz

# Çalıştırın
cd aurivo-standard  # veya aurivo-pro
./aurivo
```

**Sistem Gereksinimleri:**
- Ubuntu 20.04+ / Fedora 34+ / Arch Linux (güncel)
- Python 3.10+ (dahil)
- GStreamer 1.0+ (genellikle önyüklü)

### 🪟 Windows 10/11
```cmd
1. ZIP dosyasını indirin
2. Sağ tık → "Extract All..." (Tümünü Çıkart)
3. Aurivo.exe'yi çift tıklayın
```

**Sistem Gereksinimleri:**
- Windows 10/11 (64-bit)
- Kurulum gerektirmez (portable)
- 4GB RAM (Pro için 8GB önerilir)

---

## 📝 Changelog

### ✨ Yeni Özellikler
- 🎨 11 görselleştirme modu eklendi
- 🎛️ 32-band EQ + yüzlerce preset
- 🎬 Video oynatma + altyazı desteği
- 📥 YouTube indirme entegrasyonu
- 🚀 Pro sürüm: Whisper AI otomatik altyazı (90+ dil)
- 🎨 6 tema + özelleştirilebilir renkler
- 📚 SQLite kütüphane yönetimi
- 🔊 C++ DSP motoru (5 efekt)

### 🐛 Bilinen Sorunlar
- Bazı Linux dağıtımlarında ilk başlatmada GStreamer uyarısı (görmezden gelin)
- Pro sürümde ilk altyazı oluşturma 10-30 saniye sürebilir (model yükleme)

---

## 🛠️ Geliştirici Bilgileri

**Teknoloji Stack:**
- **GUI**: PyQt5
- **Ses/Video**: QtMultimedia + GStreamer
- **DSP**: C++ (pybind11)
- **Görselleştirme**: QPainter + NumPy FFT
- **AI** (Pro): OpenAI Whisper + PyTorch
- **Database**: SQLite3

**Kaynak Kod:** Şu anda özel (yakında açık kaynak olabilir)

---

## 🤝 Katkıda Bulunma

Geri bildirimleriniz çok değerli! Lütfen:
- 🐛 Hataları [Issues](../../issues) sayfasından bildirin
- 💡 Özellik önerilerinizi [Discussions](../../discussions) bölümünde paylaşın
- ⭐ Projeyi beğendiyseniz yıldız verin!

---

## 📄 Lisans

[LICENSE](LICENSE) dosyasına bakın.

---

## 🙏 Teşekkürler

Bu projeyi mümkün kılan tüm açık kaynak katkıcılara teşekkürler!
