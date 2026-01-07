#!/bin/bash
# Hibrit Repository Kurulum Scripti
# Public release repo + Private kaynak kod repo

set -e  # Hata olursa dur

echo "🚀 Hibrit Repository Sistemi Kurulumu"
echo "======================================"
echo ""

# Renkler
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 1. Mevcut repo'yu private yap
echo -e "${BLUE}[1/5]${NC} Mevcut repository'yi private yapıyoruz..."
echo ""
echo "⚠️  Manuel İşlem Gerekli:"
echo "   1. https://github.com/muhammeddali1453-beep/Aurivo-Music-Player/settings"
echo "   2. En alta kaydır → 'Danger Zone'"
echo "   3. 'Change repository visibility' → 'Make private'"
echo "   4. Repo adını yaz: muhammeddali1453-beep/Aurivo-Music-Player"
echo "   5. 'I understand, make this repository private'"
echo ""
read -p "Private yaptın mı? (y/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ İşlem iptal edildi. Önce private yap."
    exit 1
fi

# 2. Public repo için klasör oluştur
echo -e "${BLUE}[2/5]${NC} Public release repository klasörü oluşturuluyor..."
PUBLIC_DIR="../Aurivo-Music-Player-Public"

if [ -d "$PUBLIC_DIR" ]; then
    echo "⚠️  Klasör zaten var: $PUBLIC_DIR"
    read -p "Silip yeniden oluştur? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$PUBLIC_DIR"
    else
        echo "Mevcut klasör kullanılacak."
    fi
fi

mkdir -p "$PUBLIC_DIR"
cd "$PUBLIC_DIR"

# Git init
if [ ! -d ".git" ]; then
    git init
    echo -e "${GREEN}✓${NC} Git repository başlatıldı"
fi

# 3. Public repo içeriğini oluştur
echo -e "${BLUE}[3/5]${NC} Public repository içeriği hazırlanıyor..."

# README.md (sadece release bilgisi)
cat > README.md << 'EOFREADME'
# 🎵 Aurivo Music Player

<div align="center">

![Aurivo Logo](https://raw.githubusercontent.com/muhammeddali1453-beep/Aurivo-Music-Player/main/icons/media-playback-start.png)

**Clementine'den ilham alan güçlü, hafif ve görsel açıdan zengin müzik çalar**

[![Linux](https://img.shields.io/badge/Platform-Linux-blue.svg)](https://github.com)
[![Downloads](https://img.shields.io/github/downloads/muhammeddali1453-beep/Aurivo-Music-Player/total)](https://github.com/muhammeddali1453-beep/Aurivo-Music-Player/releases)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg)](LICENSE)

[📥 İndir](../../releases) | [📖 Kurulum](INSTALL.md) | [🐛 Hata Bildir](../../issues)

</div>

---

## ✨ Özellikler

### 🎨 Görselleştirme
- **11 Farklı Mod**: Çizgiler, Daireler, Spektrum, Enerji Halkaları, Dalga, Pulsar, Spiral, Volcano, Işın, Çift Spektrum, Radyal Grid
- **Gerçek Zamanlı FFT**: NumPy tabanlı 96-band frekans spektrumu
- **Tam Ekran**: Ayrı pencerede veya ana ekran altında

### 🎛️ Ses İşleme
- **10 Bantlı Ekolayzır**: Tam kontrol edilebilir
- **DSP Efektleri**: Compressor, Limiter, Exciter, Stereo Widener, Bass Boost
- **Crossfade**: Parçalar arası geçiş

### 📚 Kütüphane
- **SQLite Veritabanı**: Hızlı tarama
- **Metadata**: ID3, MP4, FLAC, Vorbis
- **Playlist**: Çoklu playlist yönetimi

### 🎬 Video
- **Video Oynatma**: GStreamer
- **Altyazı**: SRT, VTT + otomatik transkripsiyon (Whisper)

## 📸 Ekran Görüntüleri

*(Buraya screenshots/ klasöründeki görselleri ekleyeceğiz)*

## 🚀 Hızlı Başlangıç

### İndirme
[Son sürümü indirin](../../releases/latest)

### Kurulum
Detaylı kurulum talimatları için [INSTALL.md](INSTALL.md) dosyasına bakın.

```bash
# 1. Sistem bağımlılıkları
sudo pacman -S gst-plugins-base gst-plugins-good gst-plugins-bad gst-libav

# 2. Paketi çıkart
tar -xzf Aurivo-Linux-v1.0.tar.gz
cd aurivo

# 3. Çalıştır
./aurivo
```

## 📋 Sistem Gereksinimleri

| Bileşen | Minimum | Önerilen |
|---------|---------|----------|
| OS | Linux (kernel 5.0+) | Linux (kernel 6.0+) |
| RAM | 512 MB | 1 GB |
| Disk | 250 MB | 300 MB |
| CPU | Dual-core 1.5 GHz | Quad-core 2.0 GHz |

## 🤝 Destek

- **Hata Bildirimi**: [GitHub Issues](../../issues)
- **Özellik İsteği**: [GitHub Discussions](../../discussions)

## 📝 Lisans

Bu yazılım özel lisans altında dağıtılmaktadır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

**Özet:**
- ✅ Kişisel kullanım serbest
- ✅ Binary dağıtımı serbest
- ❌ Kaynak kod kopyalama yasak
- ❌ Ticari kullanım yasak

---

<div align="center">

**Aurivo ile müziğinizin tadını çıkarın! 🎶**

Copyright © 2026 Muhammet Dali. All rights reserved.

</div>
EOFREADME

# INSTALL.md kopyala
cp ../Aurivo-Music-Player/INSTALL.md .

# LICENSE kopyala
cp ../Aurivo-Music-Player/LICENSE .

# .gitignore
cat > .gitignore << 'EOFIGNORE'
# Sadece release dosyaları
*.tar.gz
*.zip
*.dmg
*.exe

# Geçici
.DS_Store
*.tmp
EOFIGNORE

echo -e "${GREEN}✓${NC} Public repo dosyaları oluşturuldu"

# 4. Screenshots klasörü
echo -e "${BLUE}[4/5]${NC} Screenshots klasörü hazırlanıyor..."
mkdir -p screenshots
cat > screenshots/.gitkeep << 'EOF'
# Ekran görüntülerini buraya ekle
# Örnek: main-interface.png, visualization-1.png, vb.
EOF

# 5. Git commit
echo -e "${BLUE}[5/5]${NC} İlk commit yapılıyor..."
git add .
git commit -m "Initial commit: Public release repository

- README: Özellikler ve kurulum
- INSTALL: Detaylı kurulum rehberi
- LICENSE: Proprietary lisans
- Screenshots klasörü hazır"

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}✓ Hibrit Sistem Kurulumu Tamamlandı!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "📁 Dizin Yapısı:"
echo ""
echo "   Aurivo-Music-Player/ (PRIVATE)"
echo "   ├── main.py ← Kaynak kod (gizli)"
echo "   ├── DSP kodlar ← Gizli"
echo "   └── build scripts ← Gizli"
echo ""
echo "   Aurivo-Music-Player-Public/ (PUBLIC)"
echo "   ├── README.md ← Herkes görebilir"
echo "   ├── INSTALL.md ← Herkes görebilir"
echo "   ├── LICENSE ← Herkes görebilir"
echo "   └── screenshots/ ← Ekran görüntüleri"
echo ""
echo "🔧 Sonraki Adımlar:"
echo ""
echo "1. GitHub'da yeni PUBLIC repo oluştur:"
echo "   ${YELLOW}https://github.com/new${NC}"
echo "   İsim: ${YELLOW}Aurivo-Music-Player${NC} (aynı isim, ama bu public olacak)"
echo ""
echo "2. Remote ekle:"
echo "   ${YELLOW}cd $PUBLIC_DIR${NC}"
echo "   ${YELLOW}git remote add origin https://github.com/muhammeddali1453-beep/Aurivo-Music-Player.git${NC}"
echo "   ${YELLOW}git branch -M main${NC}"
echo "   ${YELLOW}git push -u origin main${NC}"
echo ""
echo "3. Ekran görüntüleri ekle:"
echo "   ${YELLOW}cp ~/Pictures/aurivo-*.png screenshots/${NC}"
echo "   ${YELLOW}git add screenshots/ && git commit -m 'Screenshots eklendi' && git push${NC}"
echo ""
echo "4. Release oluştur:"
echo "   ${YELLOW}gh release create v1.0 ~/Aurivo-Music-Player/dist/Aurivo-Linux-v1.0.tar.gz${NC}"
echo ""
echo -e "${BLUE}Not:${NC} Private repo'daki release'leri public repo'ya taşıman gerekecek."
echo ""
