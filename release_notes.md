# 🎉 Aurivo Music Player v2.0

Bu sürüm, uygulamanın **Angolla → Aurivo** yeniden markalanmasını ve 32 bant EQ için Poweramp benzeri **Hazır Ayarlar (preset)** deneyimini getirir.

## ✨ Öne Çıkanlar

### 🎛️ 32 Bant Ana EQ + Hazır Ayarlar
- Yüzlerce preset, hızlı arama
- Seçili preset için tik işareti
- EQ üzerinde seçili preset adı
- Her preset satırında mini eğri ikonları

### ⚡ Performans ve Akıcılık
- Preset listesi doldurma/ikon üretiminde optimizasyonlar
- Preset seçimi sırasında UI blokajını azaltan iyileştirmeler

### 🎨 Yeni Marka ve İkon
- Aurivo adıyla güncellenmiş uygulama simgesi
- Linux desktop entegrasyonu: `aurivo.desktop` + `aurivo.png`

### 🔁 Geriye Dönük Uyumluluk
- Eski Angolla kullanıcı verileri (ayarlar/playlist/DB) için otomatik taşıma (mevcutsa)

## 🐧 Linux Kurulum

### Çalıştır (portable)
- Arşivi açtıktan sonra `./aurivo` ile çalıştırın.

### Menüye kur (sudo’suz)
- Kullanıcı kurulumu: `./install_systemwide.sh --user --bin ./dist/aurivo/aurivo`

## 🧩 Notlar / Bilinen Noktalar
- Video/codec ve bazı medya türleri için GStreamer eklentileri gerekir (distro’ya göre paket adları değişebilir).
- Bazı sistemlerde QtWebEngine/OpenSSL uyumluluğu uyarıları görülebilir; bu durum dağıtımın OpenSSL/Qt paketleriyle ilişkilidir.

---

Sorun bildirmek ve sürüm notlarını takip etmek için GitHub Releases sayfasını kullanın.
