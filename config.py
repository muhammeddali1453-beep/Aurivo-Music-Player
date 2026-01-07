# Aurivo Security Configuration
# Easily manage trusted domains and bridge-allowed site list here.

# Domains considered trusted for the embedded Web tab.
# NOTE: This list is used as an allowlist. Keep it tight.
TRUSTED_DOMAINS = {
    # Google / YouTube (main + CDN)
    "youtube.com",
    "youtu.be",
    "ytimg.com",
    "googlevideo.com",
    "google.com",
    "gstatic.com",
    "googleusercontent.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",

    # Spotify
    "spotify.com",
    "scdn.co",
    "spotifycdn.com",

    # Deezer
    "deezer.com",
    "dzcdn.net",

    # SoundCloud
    "soundcloud.com",
    "sndcdn.com",

    # Mixcloud
    "mixcloud.com",
}

# Sites allowed to use BridgeSecurityController.*_safe(site_name)
BRIDGE_ALLOWED_SITES = {
    "youtube",
    "spotify",
    "youtube_music",
    "deezer",
    "soundcloud",
    "mixcloud",
}

# ═══════════════════════════════════════════════════════════════════════════
# UZAKTAN KUMANDA API GÜVENLİK AYARLARI
# ═══════════════════════════════════════════════════════════════════════════

# API sunucusu etkin mi? (True = aktif, False = devre dışı)
REMOTE_API_ENABLED = False

# API port numarası
REMOTE_API_PORT = 8765

# Dış bağlantılara açık mı? (True = 0.0.0.0, False = sadece localhost)
# DİKKAT: True yapılırsa kimlik doğrulama otomatik zorunlu olur
REMOTE_API_EXTERNAL = False

# CORS izinli originler (ek origin'ler eklenebilir)
REMOTE_API_ALLOWED_ORIGINS = {
    "http://localhost",
    "http://127.0.0.1",
    # Örnek: "http://192.168.1.100:3000",
}

# Token geçerlilik süresi (saniye)
REMOTE_API_TOKEN_EXPIRY = 3600  # 1 saat

# Maksimum başarısız giriş denemesi
REMOTE_API_MAX_FAILED_ATTEMPTS = 5

# Kilitlenme süresi (saniye)
REMOTE_API_LOCKOUT_DURATION = 300  # 5 dakika

# Rate limiting (saniye başına maksimum istek)
REMOTE_API_RATE_LIMIT = 60  # dakikada 60 istek
