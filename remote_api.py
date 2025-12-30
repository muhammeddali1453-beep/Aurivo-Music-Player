#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Angolla Music Player - Uzaktan Kumanda API Modülü
Güvenlik: Kimlik Doğrulama + CORS + CSRF Koruması
"""

import hashlib
import hmac
import secrets
import time
import json
import threading
from functools import wraps
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from typing import Optional, Callable, Dict, Any


def _mask_secret(value: Optional[str], keep: int = 4) -> str:
    """Hassas değerleri log/print çıktısında maskele."""
    if not value:
        return "<yok>"
    v = str(value)
    if len(v) <= keep * 2:
        return "<gizli>"
    return f"{v[:keep]}...{v[-keep:]}"

# ═══════════════════════════════════════════════════════════════════════════
# GÜVENLİK YAPILANDIRMASI
# ═══════════════════════════════════════════════════════════════════════════

class APISecurityConfig:
    """API güvenlik yapılandırması"""
    
    # Varsayılan ayarlar
    DEFAULT_PORT = 8765
    TOKEN_EXPIRY_SECONDS = 3600  # 1 saat
    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_DURATION = 300  # 5 dakika
    
    # CORS izinli originler (yerel bağlantılar için)
    ALLOWED_ORIGINS = {
        "http://localhost",
        "http://127.0.0.1",
        "http://localhost:8765",
        "http://127.0.0.1:8765",
    }
    
    # İzin verilen HTTP metodları
    ALLOWED_METHODS = {"GET", "POST", "OPTIONS"}
    
    # İzin verilen headerlar
    ALLOWED_HEADERS = {
        "Content-Type",
        "Authorization",
        "X-CSRF-Token",
        "X-Requested-With",
    }
    
    def __init__(self):
        self.api_key: Optional[str] = None
        self.csrf_secret: str = secrets.token_hex(32)
        self.failed_attempts: Dict[str, int] = {}
        self.lockout_times: Dict[str, float] = {}
        self.active_tokens: Dict[str, float] = {}  # token -> expiry_time
        self._lock = threading.Lock()
    
    def generate_api_key(self) -> str:
        """Yeni API anahtarı oluştur"""
        self.api_key = secrets.token_urlsafe(32)
        return self.api_key
    
    def generate_csrf_token(self) -> str:
        """CSRF token oluştur"""
        timestamp = str(int(time.time()))
        message = f"{timestamp}:{self.csrf_secret}"
        signature = hmac.new(
            self.csrf_secret.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        return f"{timestamp}:{signature}"
    
    def validate_csrf_token(self, token: str, max_age: int = 3600) -> bool:
        """CSRF token doğrula"""
        if not token or ":" not in token:
            return False
        
        try:
            timestamp_str, signature = token.rsplit(":", 1)
            timestamp = int(timestamp_str)
            
            # Token süresi kontrolü
            if time.time() - timestamp > max_age:
                return False
            
            # İmza doğrulama
            message = f"{timestamp_str}:{self.csrf_secret}"
            expected_signature = hmac.new(
                self.csrf_secret.encode(),
                message.encode(),
                hashlib.sha256
            ).hexdigest()
            
            return hmac.compare_digest(signature, expected_signature)
        except (ValueError, TypeError):
            return False
    
    def generate_session_token(self) -> str:
        """Oturum token'ı oluştur"""
        token = secrets.token_urlsafe(32)
        with self._lock:
            self.active_tokens[token] = time.time() + self.TOKEN_EXPIRY_SECONDS
        return token
    
    def validate_session_token(self, token: str) -> bool:
        """Oturum token'ını doğrula"""
        if not token:
            return False
        
        with self._lock:
            expiry = self.active_tokens.get(token)
            if expiry is None:
                return False
            if time.time() > expiry:
                del self.active_tokens[token]
                return False
            return True
    
    def revoke_session_token(self, token: str) -> None:
        """Oturum token'ını iptal et"""
        with self._lock:
            self.active_tokens.pop(token, None)
    
    def check_rate_limit(self, client_ip: str) -> bool:
        """Rate limiting kontrolü"""
        with self._lock:
            # Kilitlenme kontrolü
            lockout_time = self.lockout_times.get(client_ip, 0)
            if time.time() < lockout_time:
                return False
            
            # Başarısız deneme sayısı kontrolü
            attempts = self.failed_attempts.get(client_ip, 0)
            return attempts < self.MAX_FAILED_ATTEMPTS
    
    def record_failed_attempt(self, client_ip: str) -> None:
        """Başarısız denemeyi kaydet"""
        with self._lock:
            self.failed_attempts[client_ip] = self.failed_attempts.get(client_ip, 0) + 1
            if self.failed_attempts[client_ip] >= self.MAX_FAILED_ATTEMPTS:
                self.lockout_times[client_ip] = time.time() + self.LOCKOUT_DURATION
    
    def reset_failed_attempts(self, client_ip: str) -> None:
        """Başarısız denemeleri sıfırla"""
        with self._lock:
            self.failed_attempts.pop(client_ip, None)
            self.lockout_times.pop(client_ip, None)
    
    def cleanup_expired_tokens(self) -> None:
        """Süresi dolmuş tokenları temizle"""
        current_time = time.time()
        with self._lock:
            expired = [t for t, exp in self.active_tokens.items() if current_time > exp]
            for token in expired:
                del self.active_tokens[token]


# Global güvenlik yapılandırması
_security_config = APISecurityConfig()


# ═══════════════════════════════════════════════════════════════════════════
# CORS MİDDLEWARE
# ═══════════════════════════════════════════════════════════════════════════

def add_cors_headers(handler: 'SecureAPIHandler', origin: Optional[str] = None) -> None:
    """CORS headerlarını ekle"""
    if origin and origin in _security_config.ALLOWED_ORIGINS:
        handler.send_header("Access-Control-Allow-Origin", origin)
    else:
        # Yerel bağlantılar için varsayılan
        handler.send_header("Access-Control-Allow-Origin", "http://localhost")
    
    handler.send_header(
        "Access-Control-Allow-Methods",
        ", ".join(_security_config.ALLOWED_METHODS)
    )
    handler.send_header(
        "Access-Control-Allow-Headers",
        ", ".join(_security_config.ALLOWED_HEADERS)
    )
    handler.send_header("Access-Control-Allow-Credentials", "true")
    handler.send_header("Access-Control-Max-Age", "86400")


def validate_origin(origin: Optional[str]) -> bool:
    """Origin header'ını doğrula"""
    if not origin:
        return True  # Same-origin istekler için
    return origin in _security_config.ALLOWED_ORIGINS


# ═══════════════════════════════════════════════════════════════════════════
# GÜVENLİ API HANDLER
# ═══════════════════════════════════════════════════════════════════════════

class SecureAPIHandler(BaseHTTPRequestHandler):
    """Güvenli HTTP istek işleyici"""
    
    # Player referansı (dışarıdan atanacak)
    player = None
    
    # API endpoint'leri
    endpoints: Dict[str, Callable] = {}
    
    def log_message(self, format, *args):
        """Güvenli loglama - hassas bilgileri gizle"""
        # Varsayılan olarak loglamayı devre dışı bırak
        pass
    
    def _get_client_ip(self) -> str:
        """İstemci IP adresini al"""
        return self.client_address[0]
    
    def _send_json_response(self, data: dict, status: int = 200) -> None:
        """JSON yanıt gönder"""
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        
        # CORS headerları
        origin = self.headers.get("Origin")
        add_cors_headers(self, origin)
        
        # Güvenlik headerları
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-XSS-Protection", "1; mode=block")
        self.send_header("Content-Security-Policy", "default-src 'none'")
        
        self.end_headers()
        
        response = json.dumps(data, ensure_ascii=False)
        self.wfile.write(response.encode("utf-8"))
    
    def _send_error_response(self, message: str, status: int = 400) -> None:
        """Hata yanıtı gönder"""
        self._send_json_response({"error": message, "success": False}, status)
    
    def _authenticate(self) -> bool:
        """Kimlik doğrulama kontrolü"""
        client_ip = self._get_client_ip()
        
        # Rate limiting kontrolü
        if not _security_config.check_rate_limit(client_ip):
            self._send_error_response("Çok fazla başarısız deneme. Lütfen bekleyin.", 429)
            return False
        
        # Authorization header kontrolü
        auth_header = self.headers.get("Authorization", "")
        
        # Bearer token kontrolü
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            if _security_config.validate_session_token(token):
                _security_config.reset_failed_attempts(client_ip)
                return True
        
        # API Key kontrolü
        if auth_header.startswith("ApiKey "):
            api_key = auth_header[7:]
            if _security_config.api_key and hmac.compare_digest(api_key, _security_config.api_key):
                _security_config.reset_failed_attempts(client_ip)
                return True
        
        # Kimlik doğrulama başarısız
        _security_config.record_failed_attempt(client_ip)
        self._send_error_response("Kimlik doğrulama başarısız", 401)
        return False
    
    def _validate_csrf(self) -> bool:
        """CSRF token doğrulama (POST istekleri için)"""
        if self.command != "POST":
            return True
        
        csrf_token = self.headers.get("X-CSRF-Token", "")
        if not _security_config.validate_csrf_token(csrf_token):
            self._send_error_response("Geçersiz CSRF token", 403)
            return False
        return True
    
    def _validate_origin(self) -> bool:
        """Origin doğrulama"""
        origin = self.headers.get("Origin")
        if not validate_origin(origin):
            self._send_error_response("İzin verilmeyen origin", 403)
            return False
        return True
    
    def do_OPTIONS(self):
        """CORS preflight isteği"""
        origin = self.headers.get("Origin")
        if not validate_origin(origin):
            self.send_response(403)
            self.end_headers()
            return
        
        self.send_response(204)
        add_cors_headers(self, origin)
        self.end_headers()
    
    def do_GET(self):
        """GET isteklerini işle"""
        if not self._validate_origin():
            return
        
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        # Public endpoint'ler (kimlik doğrulama gerektirmez)
        if path == "/api/csrf-token":
            self._handle_csrf_token()
            return
        
        if path == "/api/health":
            self._handle_health_check()
            return
        
        # Korunan endpoint'ler
        if not self._authenticate():
            return
        
        # Endpoint yönlendirme
        if path == "/api/status":
            self._handle_status()
        elif path == "/api/playlist":
            self._handle_get_playlist()
        elif path == "/api/current":
            self._handle_current_track()
        elif path == "/api/volume":
            self._handle_get_volume()
        else:
            self._send_error_response("Endpoint bulunamadı", 404)
    
    def do_POST(self):
        """POST isteklerini işle"""
        if not self._validate_origin():
            return
        
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        # Login endpoint'i (sadece API key ile)
        if path == "/api/login":
            self._handle_login()
            return
        
        # Diğer POST endpoint'leri için kimlik doğrulama + CSRF
        if not self._authenticate():
            return
        
        if not self._validate_csrf():
            return
        
        # Endpoint yönlendirme
        if path == "/api/play":
            self._handle_play()
        elif path == "/api/pause":
            self._handle_pause()
        elif path == "/api/next":
            self._handle_next()
        elif path == "/api/previous":
            self._handle_previous()
        elif path == "/api/stop":
            self._handle_stop()
        elif path == "/api/volume":
            self._handle_set_volume()
        elif path == "/api/seek":
            self._handle_seek()
        elif path == "/api/logout":
            self._handle_logout()
        else:
            self._send_error_response("Endpoint bulunamadı", 404)
    
    # ═══════════════════════════════════════════════════════════════════════
    # ENDPOINT HANDLERLARİ
    # ═══════════════════════════════════════════════════════════════════════
    
    def _handle_csrf_token(self):
        """CSRF token al"""
        token = _security_config.generate_csrf_token()
        self._send_json_response({"csrf_token": token, "success": True})
    
    def _handle_health_check(self):
        """Sağlık kontrolü"""
        self._send_json_response({
            "status": "healthy",
            "service": "Angolla Remote API",
            "version": "1.0.0",
            "success": True
        })
    
    def _handle_login(self):
        """Giriş yap ve session token al"""
        client_ip = self._get_client_ip()
        
        if not _security_config.check_rate_limit(client_ip):
            self._send_error_response("Çok fazla başarısız deneme. Lütfen bekleyin.", 429)
            return
        
        auth_header = self.headers.get("Authorization", "")
        if not auth_header.startswith("ApiKey "):
            _security_config.record_failed_attempt(client_ip)
            self._send_error_response("API Key gerekli", 401)
            return
        
        api_key = auth_header[7:]
        if not _security_config.api_key or not hmac.compare_digest(api_key, _security_config.api_key):
            _security_config.record_failed_attempt(client_ip)
            self._send_error_response("Geçersiz API Key", 401)
            return
        
        _security_config.reset_failed_attempts(client_ip)
        session_token = _security_config.generate_session_token()
        csrf_token = _security_config.generate_csrf_token()
        
        self._send_json_response({
            "session_token": session_token,
            "csrf_token": csrf_token,
            "expires_in": _security_config.TOKEN_EXPIRY_SECONDS,
            "success": True
        })
    
    def _handle_logout(self):
        """Çıkış yap"""
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            _security_config.revoke_session_token(token)
        
        self._send_json_response({"message": "Çıkış yapıldı", "success": True})
    
    def _handle_status(self):
        """Oynatıcı durumunu al"""
        if not self.player:
            self._send_json_response({"status": "no_player", "success": True})
            return
        
        try:
            from PyQt5.QtMultimedia import QMediaPlayer
            state = self.player.player.state()
            state_str = {
                QMediaPlayer.StoppedState: "stopped",
                QMediaPlayer.PlayingState: "playing",
                QMediaPlayer.PausedState: "paused"
            }.get(state, "unknown")
            
            self._send_json_response({
                "state": state_str,
                "position": self.player.player.position(),
                "duration": self.player.player.duration(),
                "success": True
            })
        except Exception as e:
            self._send_error_response(f"Durum alınamadı: {str(e)}", 500)
    
    def _handle_get_playlist(self):
        """Playlist'i al"""
        if not self.player:
            self._send_json_response({"playlist": [], "success": True})
            return
        
        try:
            playlist = []
            for i in range(self.player.playlistWidget.count()):
                item = self.player.playlistWidget.item(i)
                playlist.append({
                    "index": i,
                    "title": item.text() if item else ""
                })
            
            self._send_json_response({
                "playlist": playlist,
                "current_index": self.player.playlistWidget.currentRow(),
                "success": True
            })
        except Exception as e:
            self._send_error_response(f"Playlist alınamadı: {str(e)}", 500)
    
    def _handle_current_track(self):
        """Mevcut parça bilgisi"""
        if not self.player:
            self._send_json_response({"track": None, "success": True})
            return
        
        try:
            current_item = self.player.playlistWidget.currentItem()
            self._send_json_response({
                "track": current_item.text() if current_item else None,
                "index": self.player.playlistWidget.currentRow(),
                "success": True
            })
        except Exception as e:
            self._send_error_response(f"Parça bilgisi alınamadı: {str(e)}", 500)
    
    def _handle_get_volume(self):
        """Ses seviyesini al"""
        if not self.player:
            self._send_json_response({"volume": 0, "success": True})
            return
        
        try:
            volume = self.player.volumeSlider.value()
            self._send_json_response({"volume": volume, "success": True})
        except Exception as e:
            self._send_error_response(f"Ses seviyesi alınamadı: {str(e)}", 500)
    
    def _handle_play(self):
        """Oynat"""
        if not self.player:
            self._send_error_response("Player bulunamadı", 500)
            return
        
        try:
            self.player.player.play()
            self._send_json_response({"message": "Oynatılıyor", "success": True})
        except Exception as e:
            self._send_error_response(f"Oynatma hatası: {str(e)}", 500)
    
    def _handle_pause(self):
        """Duraklat"""
        if not self.player:
            self._send_error_response("Player bulunamadı", 500)
            return
        
        try:
            self.player.player.pause()
            self._send_json_response({"message": "Duraklatıldı", "success": True})
        except Exception as e:
            self._send_error_response(f"Duraklatma hatası: {str(e)}", 500)
    
    def _handle_next(self):
        """Sonraki parça"""
        if not self.player:
            self._send_error_response("Player bulunamadı", 500)
            return
        
        try:
            self.player._next_track()
            self._send_json_response({"message": "Sonraki parçaya geçildi", "success": True})
        except Exception as e:
            self._send_error_response(f"Sonraki parça hatası: {str(e)}", 500)
    
    def _handle_previous(self):
        """Önceki parça"""
        if not self.player:
            self._send_error_response("Player bulunamadı", 500)
            return
        
        try:
            self.player._prev_track()
            self._send_json_response({"message": "Önceki parçaya geçildi", "success": True})
        except Exception as e:
            self._send_error_response(f"Önceki parça hatası: {str(e)}", 500)
    
    def _handle_stop(self):
        """Durdur"""
        if not self.player:
            self._send_error_response("Player bulunamadı", 500)
            return
        
        try:
            self.player.player.stop()
            self._send_json_response({"message": "Durduruldu", "success": True})
        except Exception as e:
            self._send_error_response(f"Durdurma hatası: {str(e)}", 500)
    
    def _handle_set_volume(self):
        """Ses seviyesini ayarla"""
        if not self.player:
            self._send_error_response("Player bulunamadı", 500)
            return
        
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            data = json.loads(body)
            
            volume = int(data.get("volume", 50))
            volume = max(0, min(100, volume))  # 0-100 arasında sınırla
            
            self.player.volumeSlider.setValue(volume)
            self._send_json_response({"volume": volume, "success": True})
        except Exception as e:
            self._send_error_response(f"Ses seviyesi ayarlanamadı: {str(e)}", 500)
    
    def _handle_seek(self):
        """Konuma atla"""
        if not self.player:
            self._send_error_response("Player bulunamadı", 500)
            return
        
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            data = json.loads(body)
            
            position = int(data.get("position", 0))
            self.player.player.setPosition(position)
            self._send_json_response({"position": position, "success": True})
        except Exception as e:
            self._send_error_response(f"Konum ayarlanamadı: {str(e)}", 500)


# ═══════════════════════════════════════════════════════════════════════════
# API SUNUCUSU
# ═══════════════════════════════════════════════════════════════════════════

class RemoteAPIServer:
    """Uzaktan kumanda API sunucusu"""
    
    def __init__(self, player=None, port: int = None, bind_address: str = "127.0.0.1"):
        """
        Args:
            player: AngollaPlayer instance
            port: API port numarası
            bind_address: Bağlanılacak adres (güvenlik için varsayılan localhost)
        """
        self.player = player
        self.port = port or _security_config.DEFAULT_PORT
        self.bind_address = bind_address
        self.server: Optional[HTTPServer] = None
        self.server_thread: Optional[threading.Thread] = None
        self._running = False
    
    def start(self, external: bool = False) -> str:
        """
        API sunucusunu başlat
        
        Args:
            external: True ise dış bağlantılara açık (0.0.0.0), 
                     False ise sadece localhost
        
        Returns:
            API anahtarı (external=True ise)
        """
        if self._running:
            print("[API] Sunucu zaten çalışıyor")
            return _security_config.api_key or ""
        
        # Dış bağlantılar için kimlik doğrulama zorunlu
        api_key = None
        if external:
            api_key = _security_config.generate_api_key()
            self.bind_address = "0.0.0.0"
            print(f"[API] ⚠️  DIŞ BAĞLANTI AÇIK - Kimlik doğrulama zorunlu")
            # Güvenlik: API anahtarını loglama (stdout/stderr dahil)
            print(f"[API] 🔑 API anahtarı oluşturuldu: {_mask_secret(api_key)}")
        else:
            self.bind_address = "127.0.0.1"
        
        # Handler'a player referansını ata
        SecureAPIHandler.player = self.player
        
        try:
            self.server = HTTPServer(
                (self.bind_address, self.port),
                SecureAPIHandler
            )
            
            self.server_thread = threading.Thread(
                target=self._run_server,
                daemon=True
            )
            self.server_thread.start()
            self._running = True
            
            print(f"[API] ✓ Sunucu başlatıldı: http://{self.bind_address}:{self.port}")
            
            return api_key or ""
            
        except Exception as e:
            print(f"[API] ✗ Sunucu başlatılamadı: {e}")
            return ""
    
    def _run_server(self):
        """Sunucu döngüsü"""
        try:
            self.server.serve_forever()
        except Exception as e:
            print(f"[API] Sunucu hatası: {e}")
        finally:
            self._running = False
    
    def stop(self):
        """Sunucuyu durdur"""
        if self.server:
            self.server.shutdown()
            self.server = None
        self._running = False
        print("[API] Sunucu durduruldu")
    
    def is_running(self) -> bool:
        """Sunucu çalışıyor mu?"""
        return self._running
    
    def get_api_key(self) -> Optional[str]:
        """Mevcut API anahtarını al"""
        return _security_config.api_key
    
    def regenerate_api_key(self) -> str:
        """Yeni API anahtarı oluştur"""
        return _security_config.generate_api_key()
    
    def add_allowed_origin(self, origin: str) -> None:
        """İzin verilen origin ekle"""
        _security_config.ALLOWED_ORIGINS.add(origin)
    
    def remove_allowed_origin(self, origin: str) -> None:
        """İzin verilen origin'i kaldır"""
        _security_config.ALLOWED_ORIGINS.discard(origin)


# ═══════════════════════════════════════════════════════════════════════════
# YARDIMCI FONKSİYONLAR
# ═══════════════════════════════════════════════════════════════════════════

def get_security_config() -> APISecurityConfig:
    """Global güvenlik yapılandırmasını al"""
    return _security_config


def create_api_server(player=None, port: int = None) -> RemoteAPIServer:
    """
    API sunucusu oluştur
    
    Örnek kullanım:
        server = create_api_server(player=window)
        api_key = server.start(external=True)  # Dış bağlantılar için
        # veya
        server.start(external=False)  # Sadece localhost
    """
    return RemoteAPIServer(player=player, port=port)


# ═══════════════════════════════════════════════════════════════════════════
# TEST / DEMO
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print("Angolla Remote API - Güvenlik Test Modu")
    print("=" * 60)
    
    # Test sunucusu başlat
    server = create_api_server()
    api_key = server.start(external=True)
    
    print("\n📋 Kullanılabilir Endpoint'ler:")
    print("  GET  /api/health      - Sağlık kontrolü (public)")
    print("  GET  /api/csrf-token  - CSRF token al (public)")
    print("  POST /api/login       - Giriş yap (API Key ile)")
    print("  GET  /api/status      - Oynatıcı durumu")
    print("  GET  /api/playlist    - Playlist listesi")
    print("  GET  /api/current     - Mevcut parça")
    print("  GET  /api/volume      - Ses seviyesi")
    print("  POST /api/play        - Oynat")
    print("  POST /api/pause       - Duraklat")
    print("  POST /api/next        - Sonraki")
    print("  POST /api/previous    - Önceki")
    print("  POST /api/stop        - Durdur")
    print("  POST /api/volume      - Ses seviyesi ayarla")
    print("  POST /api/seek        - Konuma atla")
    print("  POST /api/logout      - Çıkış yap")
    
    print("\n🔒 Kimlik Doğrulama:")
    print(f"  API Key: {_mask_secret(api_key)}")
    print("  Header: Authorization: ApiKey <key>")
    print("  veya:   Authorization: Bearer <session_token>")
    
    print("\n🛡️  CSRF Koruması:")
    print("  POST isteklerinde X-CSRF-Token header'ı gerekli")
    
    print("\n⏹️  Durdurmak için Ctrl+C")
    
    try:
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop()
        print("\n✓ Sunucu kapatıldı")
