# Ekran Görüntüleri Rehberi

## 📸 Hangi Ekranları Çekmeliyim?

### 1. Ana Pencere (Main Interface)
- Playlist görünümü
- Görselleştirme çalışırken
- Albüm kapağı görünümü
- **Dosya adı**: `main-interface.png`

### 2. Görselleştirme Modları (En Az 3 Farklı)
- Spektrum çubukları
- Daireler veya spiraller
- Tam ekran görselleştirme
- **Dosyalar**: `visualization-1.png`, `visualization-2.png`, vb.

### 3. Ekolayzır Penceresi
- 10 bantlı EQ açık
- **Dosya adı**: `equalizer.png`

### 4. Kütüphane/Library View
- Parça listesi
- Sıralama özellikleri
- **Dosya adı**: `library-view.png`

### 5. Video Oynatma + Altyazı (Varsa)
- Video oynatılırken
- Altyazı görünümü
- **Dosya adı**: `video-subtitle.png`

## 🎯 Ekran Görüntüsü Alma (Linux)

### Flameshot (Önerilen)
```bash
# Kurulum
sudo pacman -S flameshot  # Arch
sudo apt install flameshot  # Ubuntu

# Kullanım
flameshot gui
# Veya: Shift+PrtScr
```

### GNOME Screenshot
```bash
# Tam ekran
gnome-screenshot

# Seçili alan
gnome-screenshot -a

# Pencere
gnome-screenshot -w
```

### Spectacle (KDE)
```bash
# Kurulum
sudo pacman -S spectacle

# Kullanım
spectacle
```

## 📏 Optimal Boyutlar

- **Genişlik**: 1920px (Full HD)
- **Yükseklik**: 1080px veya daha az
- **Format**: PNG (kayıpsız) veya JPG (%90 kalite)
- **Dosya boyutu**: < 500KB (GitHub için optimize)

## 🖼️ GitHub'a Ekleme

### Yöntem 1: Screenshots Klasörü (Bu Repo)
```bash
# Ekran görüntülerini buraya kopyala
cp ~/Pictures/aurivo-*.png screenshots/

# Git'e ekle
git add screenshots/
git commit -m "Screenshots: Uygulama ekran görüntüleri eklendi"
git push
```

### Yöntem 2: README'ye Direkt Embed
1. GitHub'da Issue veya PR oluştur
2. Görseli sürükle-bırak
3. GitHub otomatik link verir:
   ```
   ![Image](https://user-images.githubusercontent.com/...)
   ```
4. Bu linki README'ye kopyala

### Yöntem 3: GitHub Releases (Büyük Görseller)
```bash
# Release'e ekran görüntüsü ekle
gh release upload v1.0 screenshots/*.png
```

## 📝 README'de Kullanım

### Tek Görsel
```markdown
![Ana Pencere](screenshots/main-interface.png)
```

### Galeri (Yan Yana)
```markdown
<div align="center">
  <img src="screenshots/visualization-1.png" width="45%">
  <img src="screenshots/visualization-2.png" width="45%">
</div>
```

### Detaylı Açıklamalı
```markdown
## Görselleştirme Modları

### Spektrum Çubukları
![Spektrum](screenshots/visualization-1.png)
*11 farklı FFT tabanlı görselleştirme modu*

### Tam Ekran Deneyimi
![Full Screen](screenshots/fullscreen-viz.png)
*Tam ekran mod ile immersive deneyim*
```

## 🎨 Görsel Optimizasyonu (Opsiyonel)

### ImageMagick ile Boyutlandırma
```bash
# Kurulum
sudo pacman -S imagemagick

# Genişliği 1920px'e küçült
mogrify -resize 1920x screenshots/*.png

# JPEG'e çevir (%90 kalite)
mogrify -format jpg -quality 90 screenshots/*.png
```

### OptiPNG ile Sıkıştırma
```bash
sudo pacman -S optipng
optipng screenshots/*.png
```

## ✅ Checklist

- [ ] En az 5 farklı ekran görüntüsü çektim
- [ ] Ana arayüz görüntüsü var
- [ ] Görselleştirme modları gösterildi
- [ ] Dosya isimleri açıklayıcı
- [ ] Boyutlar optimize edildi (< 500KB)
- [ ] Git'e eklendi ve push edildi
- [ ] README.md'de kullanıldı

## 📤 Public Repo'ya Taşıma

Hibrit sistem için:
```bash
# Screenshots'u public repo'ya kopyala
cp -r screenshots ../Aurivo-Music-Player-Public/
cd ../Aurivo-Music-Player-Public/
git add screenshots/
git commit -m "Assets: Ekran görüntüleri eklendi"
git push
```

---

**Not**: Ekran görüntülerinde kişisel bilgi (dosya yolları, kullanıcı adı) varsa blur uygula!
