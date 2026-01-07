# 🎬 Aurivo TURBO Reklam Geçiş Sistemi

## Genel Bakış
Aurivo Music Player'da web platformalarında (YouTube, Spotify vb.) reklam **ultra hızlı** ve otomatik olarak geçilir. Sistem güvenli QWebChannel bridge'i üzerinden çalışır.

## 🚀 Turbo Özellikler

### ⚡ Ultra Hızlı Geçiş
- **50ms interval**: Her 50 milisaniyede reklam kontrolü (10x daha hızlı!)
- **Anında tespit**: MutationObserver ile DOM değişikliği algılama
- **Çoklu tıklama**: Skip butonuna 3 kez tıklama garantisi
- **16x hızlandırma**: Reklam videoları 16 kat hızlı oynatılır

### 🎯 Gelişmiş Tespit
- **12 farklı selector**: Tüm YouTube reklam buton türleri
- **Overlay gizleme**: Reklam katmanları otomatik gizlenir
- **Ses kontrolü**: Reklam sesi otomatik kapatılır (mute + volume 0)

### ⌨️ Klavye Kısayolları
| Kısayol | İşlem |
|---------|-------|
| **Shift+S** | Hızlı reklam geçişi |
| **Ctrl+Shift+A** | Otomatik geçişi aç/kapat |
| **Ctrl+Shift+T** | Turbo modu aç/kapat |

### 🔐 Güvenlik Özellikleri
- **QWebChannel Bridge**: Güvenli JavaScript-Python iletişimi
- **Whitelist Kontrolü**: Yalnızca tanımlı siteler erişim sağlayabilir
- **Sınırlı Metodlar**: Yalnızca izinli işlemler çalışabilir

## Teknik Yapı

### Bridge Metotları

#### `skip_ad_safe(site_name: str)`
Güvenli reklam geçiş isteği yapar.
```javascript
window.AurivoBridge.skip_ad_safe('youtube');
```

#### `seek_safe(site_name: str, seconds: int)`
0-120 saniye aralığında başlama konumu değiştirir.
```javascript
window.AurivoBridge.seek_safe('youtube', 30);
```

#### `toggle_play_safe(site_name: str, should_play: bool)`
Oynatma/durdurma kontrolü.
```javascript
window.AurivoBridge.toggle_play_safe('youtube', true);
```

#### `volume_safe(site_name: str, volume: int)`
0-100 aralığında ses kontrolü.
```javascript
window.AurivoBridge.volume_safe('youtube', 75);
```

### Whitelist Konfigürasyonu

**config.py**:
```python
# Güvenilir domainler (hassas izinler için)
TRUSTED_DOMAINS = {
    "localhost",
    "127.0.0.1",
}

# Bridge erişime izin verilen siteler
BRIDGE_ALLOWED_SITES = {
    "youtube",
    "spotify",
}
```

**Kalıcı Ayarlar** (`aurivo_settings.json`):
```json
{
  "trusted_domains": ["localhost", "127.0.0.1"],
  "bridge_allowed_sites": ["youtube", "spotify"]
}
```

## Kullanım

### Web Tarayıcıda
1. Aurivo uygulamasını başlatın
2. Web tarayıcısı bölümüne YouTube/Spotify linkini girin
3. Reklamlar otomatik olarak geçilecektir

### Demo Sayfasını Test Etme
```bash
# Tarayıcıda açın:
file:///path/to/ad_skip_demo.html
```

Demo sayfasında:
- "Reklam Göster" butonuna tıklayın
- "Reklamı Atla" veya Shift+S tuşunu kullanın
- Logları konsollarda izleyin

### Ayarları Yönetme
1. ⚙️ **Ayarlar** butonuna tıklayın
2. "Köprü İzinli Siteler" listesini düzenleyin
3. Yeni siteler ekleyin veya silin
4. "Kaydet" butonuna tıklayın

## Sorun Giderme

### Bridge Bağlantısı Çalışmıyor
**Sebep**: QWebChannel modülü yüklenemedi  
**Çözüm**:
```bash
pip install PyQt5>=5.15
```

### Reklam Geçişi Çalışmıyor
**Sebep**: Site whitelist'te değil  
**Çözüm**: Ayarlar → Köprü İzinli Siteler'e site adını ekleyin

### JavaScript Scriptleri Çalışmıyor
**Sebep**: JavaScript devre dışı  
**Çözüm**: QWebEngineSettings'de JavaScript aktif olduğundan emin olun

## Sistem Logları

Konsol çıktısında şu mesajları görebilirsiniz:

```
✓ Reklam geçiş scripti yüklendi (QWebEngineScript)
🔄 Otomatik reklam geçişi başlatıldı
✓ Reklam geçildi (Aurivo) #1
⌨️ Klavye komutu (Shift+S) tetiklendi
```

## Geliştirilmiş Özellikler

- 📊 Geçilen reklam sayısı takibi
- 🔍 Görünür olmayan butonları göz ardı etme
- 🎯 Çoklu dil desteği (selector seçenekleri)
- 🛡️ Hata yönetimi ve fallback mekanizmaları

## İlerleme Durumu

✅ **Tamamlanan**:
- QWebChannel bridge entegrasyon
- Auto-skip sistemi
- Keyboard shortcuts
- Whitelist yönetimi
- Demo sayfası
- Error handling

🔄 **Gelecekte Planlanan**:
- Daha fazla platform desteği (Twitch, Discord vb.)
- Özel selector konfigürasyonu
- İstatistik paneli
- Reklam hızlı ileri sarma

## Dosyalar

| Dosya | Amaç |
|-------|------|
| `main.py` | Ana uygulama (Bridge, script inject) |
| `config.py` | Whitelist konfigürasyonu |
| `ad_skip_demo.html` | Test ve demo sayfası |
| `aurivo_settings.json` | Kalıcı ayarlar |

## Kaynaklar

- 📚 QWebChannel: https://doc.qt.io/qt-5/qtwebchannel-index.html
- 📚 QWebEngine: https://doc.qt.io/qt-5/qtwebengine-index.html
- 🔒 Güvenlik Best Practices: https://owasp.org/

---
**Oluşturulma**: 2025-12-13  
**Durum**: ✅ Aktif ve Çalışan
