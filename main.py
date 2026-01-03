#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Angolla Music Player - Tek Dosya, Güncel Sürüm (Sade Geçiş + Çalışan Görselleştirme)
"""
import math
import sys
import os

# ═══════════════════════════════════════════════════════════════════════════
# TERMINAL HATA FİLTRELEME (Sessiz Başlatma) - EN BAŞTA YAPILMALI
# ═══════════════════════════════════════════════════════════════════════════
os.environ["GST_DEBUG"] = "0"
os.environ["GST_DEBUG_NO_COLOR"] = "1"
os.environ["G_MESSAGES_DEBUG"] = ""
os.environ["QT_LOGGING_RULES"] = "*.debug=false;qt.qpa.*=false"
os.environ["PYTHONWARNINGS"] = "ignore"

# STDERR + STDOUT Filtreleme: GStreamer, Chromium ve MediaEvent hatalarını gizle
import re
class _FilteredOutput:
    """GStreamer, Chromium ve MediaEvent hatalarını filtreleyen output wrapper"""
    IGNORE_PATTERNS = (
        # GStreamer hataları
        'GStreamer-CRITICAL', 'GStreamer-WARNING', 'GST_IS_ELEMENT', 
        'gst_element', 'gst_', '): Gst',
        # Chromium/WebEngine hataları
        'pipeline_error', 'MediaEvent', 'batching_media_log', 
        'FFmpegDemuxer', 'no supported streams', 'Sandboxing disabled',
        # JavaScript uyarıları
        'js:', 'Uncaught', 'TrustedScript', 'Document-Policy',
        'preloaded using link preload', 'generate_204', 'cookie',
        # Güvenlik/genel hatalar
        'SecurityError', 'assertion', 'ERROR:batching', 'WARNING:',
        'libva error', 'va_openDriver', 'Could not',
        'data:', "'failed'",
    )
    # Chromium process ID formatı: [123456:123456:1229/051249.194982:ERROR:...]
    _CHROMIUM_PATTERN = re.compile(r'^\[\d+:\d+:')
    # (python:123): GStreamer formatı
    _GST_PATTERN = re.compile(r'^\(python:\d+\):')
    
    def __init__(self, stream, is_stderr=False):
        self._stream = stream
        self._is_stderr = is_stderr
    def write(self, msg):
        if not msg or not msg.strip():
            return len(msg) if msg else 0
        stripped = msg.strip()
        # Chromium PID:TID formatındaki mesajları engelle
        if self._CHROMIUM_PATTERN.match(stripped):
            return len(msg)
        # (python:xxx): GStreamer formatını engelle
        if self._GST_PATTERN.match(stripped):
            return len(msg)
        # Diğer desen eşleşmelerini kontrol et
        if any(p in msg for p in self.IGNORE_PATTERNS):
            return len(msg)
        try:
            self._stream.write(msg)
        except Exception:
            pass
        return len(msg)
    def flush(self):
        try:
            self._stream.flush()
        except Exception:
            pass
    def fileno(self):
        return self._stream.fileno()
    # stdout için gerekli ek metodlar
    def isatty(self):
        return hasattr(self._stream, 'isatty') and self._stream.isatty()
    @property
    def encoding(self):
        return getattr(self._stream, 'encoding', 'utf-8')

sys.stderr = _FilteredOutput(sys.__stderr__, is_stderr=True)
sys.stdout = _FilteredOutput(sys.__stdout__, is_stderr=False)

# Chromium sessiz mod
os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = (
    (os.environ.get("QTWEBENGINE_CHROMIUM_FLAGS", "") + 
     " --log-level=3 --disable-logging --silent-debugger-extension-api"
     " --disable-client-side-phishing-detection --disable-default-apps"
     " --disable-extensions --disable-hang-monitor --disable-popup-blocking"
     " --disable-prompt-on-repost --disable-sync --disable-translate"
     " --metrics-recording-only --no-first-run --safebrowsing-disable-auto-update")
    .strip()
)

flags = os.environ.get("QTWEBENGINE_CHROMIUM_FLAGS", "")
flag_list = flags.split() if flags else []
enable_features = set()
enable_index = None
disable_features = set()
disable_index = None
for idx, item in enumerate(flag_list):
    if item.startswith("--enable-features="):
        enable_index = idx
        enable_features.update(item.split("=", 1)[1].split(","))
        break
for idx, item in enumerate(flag_list):
    if item.startswith("--disable-features="):
        disable_index = idx
        disable_features.update(item.split("=", 1)[1].split(","))
        break
enable_features.add("WebRTCPipeWireCapturer")
enable_value = "--enable-features=" + ",".join(sorted(enable_features))
if enable_index is None:
    flag_list.append(enable_value)
else:
    flag_list[enable_index] = enable_value
disable_features.add("AudioServiceSandbox")
disable_value = "--disable-features=" + ",".join(sorted(disable_features))
if disable_index is None:
    flag_list.append(disable_value)
else:
    flag_list[disable_index] = disable_value
flag_list = [f for f in flag_list if not f.startswith("--audio-buffer-size=")]
required_flags = [
    "--force-wave-audio",
    "--disable-audio-output-resampling",
    "--disable-gpu-audio-output",
    "--disable-accelerated-video-decode",
    "--disable-gpu-memory-buffer-video-frames",
    "--audio-buffer-size=2048",
    "--disable-web-security",
    "--use-fake-ui-for-media-stream",
    "--no-sandbox",
    "--test-type",
    "--ignore-gpu-blocklist",
    "--enable-gpu-rasterization",
    "--u2f-fingerprint-check-upscale-threshold=0",
]
for flag in required_flags:
    if flag not in flag_list:
        flag_list.append(flag)
if flag_list:
    os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = " ".join(flag_list)
import json
import random
import time
import ctypes
import sqlite3
import numpy as np
from pathlib import Path
from config import TRUSTED_DOMAINS, BRIDGE_ALLOWED_SITES
import web_engine_handler
try:
    import sounddevice as sd
except ImportError:
    sd = None
try:
    import soundfile as sf
except ImportError:
    sf = None


def _build_eq_frequencies(num_bands=32, min_freq=20.0, max_freq=20000.0):
    if num_bands < 2:
        return [min_freq]
    log_min = math.log10(min_freq)
    log_max = math.log10(max_freq)
    step = (log_max - log_min) / (num_bands - 1)
    return [10 ** (log_min + step * i) for i in range(num_bands)]


def _format_eq_frequency(freq):
    if freq >= 1000.0:
        val = freq / 1000.0
        label = f"{val:.1f}"
        if label.endswith(".0"):
            label = label[:-2]
        return f"{label}kHz"
    return f"{int(round(freq))}Hz"


EQ_BAND_FREQS = _build_eq_frequencies()
EQ_BAND_LABELS = [_format_eq_frequency(freq) for freq in EQ_BAND_FREQS]


def _import_webengine():
    """Try importing QWebEngineView; fallback by adding common site-packages paths."""
    try:
        from PyQt5.QtWebEngineWidgets import QWebEngineView  # type: ignore
        return QWebEngineView
    except Exception:
        pass

    import site, glob
    candidates = set()
    # venv + user + system paths
    for p in site.getsitepackages() + [site.getusersitepackages()]:
        candidates.add(p)
    # Tüm /usr/lib/python*/site-packages dizinlerini tara (Arch 3.13 vs. için)
    for p in glob.glob("/usr/lib/python*/site-packages"):
        candidates.add(p)
    for p in candidates:
        if p and os.path.isdir(p) and p not in sys.path:
            sys.path.append(p)
            try:
                from PyQt5.QtWebEngineWidgets import QWebEngineView  # type: ignore
                return QWebEngineView
            except Exception:
                continue
    return None
from typing import Optional, Dict, Any, List
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QVBoxLayout,
    QWidget, QLabel, QHBoxLayout, QSlider, QListWidget, QSplitter,
    QAction, QStatusBar, QTreeView, QStackedWidget, QListWidgetItem,
    QMenu, QFileDialog, QMessageBox, QShortcut, QFileSystemModel,
    QDialog, QCheckBox, QGridLayout, QComboBox, QLineEdit, QDial, QFrame,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView, QListView,
    QColorDialog, QToolBar, QToolButton, QStyle, QSizePolicy, QProgressBar,
    QCompleter, QKeySequenceEdit, QActionGroup, QSpinBox, QGroupBox, QProgressDialog
)
from PyQt5.QtWidgets import QPlainTextEdit
from PyQt5.QtMultimedia import (
    QMediaPlayer, QMediaContent, QMediaPlaylist, QAudioProbe
)
from PyQt5.QtMultimediaWidgets import QVideoWidget
from PyQt5.QtCore import (
    QUrl, Qt, QTime, QDir, QModelIndex, QTimer, QByteArray,
    QSettings, QPointF, QPoint, QRectF, QRect, pyqtSignal, pyqtSlot, QEvent, QObject, QSize, QLocale,
    QStandardPaths, QStringListModel, QThread, QPropertyAnimation, QEasingCurve, QSortFilterProxyModel
)
import threading
from PyQt5.QtGui import QPolygonF
# Downloader Imports (yeni modül)
from download_dialog import DownloadDialog, DownloadWorker, resolve_yt_dlp_command
# Geriye uyumluluk: eski ad (DownloadFormatDialog) için alias
DownloadFormatDialog = DownloadDialog

from PyQt5.QtGui import (
    QPainter, QBrush, QColor, QPixmap, QKeySequence, QPen,
    QFont, QIcon, QPainterPath, QRadialGradient, QLinearGradient, QDesktopServices, QImage, QPalette,
    QCursor
)
try:
    from PyQt5.QtSvg import QSvgRenderer
except Exception:
    QSvgRenderer = None
QWebEngineView = _import_webengine()

# WebEngine ek importlar (varsa)
QWebEnginePage = None
QWebEngineProfile = None
QWebChannel = None
QWebEngineSettings = None
QWebEngineScript = None

try:
    from PyQt5.QtWebEngineWidgets import QWebEnginePage
except Exception:
    pass

try:
    from PyQt5.QtWebEngine import QWebEngineProfile
except Exception:
    try:
        from PyQt5.QtWebEngineWidgets import QWebEngineProfile
    except Exception:
        pass

try:
    from PyQt5.QtWebChannel import QWebChannel
except Exception:
    pass

import collections # Ensure collections is imported for deque

# ---------------------------------------------------------------------------
# WEB TAB GÜVENLİK YARDIMCILARI
# ---------------------------------------------------------------------------
import ipaddress
import html as _html
import os as _os


def _sanitize_url_for_log_qurl(qurl: 'QUrl') -> str:
    """Query/fragment (token vs) sızıntısını önlemek için URL'yi maskele."""
    try:
        safe = QUrl(qurl)
        safe.setQuery("")
        safe.setFragment("")
        return safe.toString()
    except Exception:
        try:
            return str(qurl)
        except Exception:
            return "<url>"


def _is_private_or_loopback_host(host: str) -> bool:
    """localhost/özel ağ/loopback IP'leri ve bariz yerel hedefleri engelle."""
    if not host:
        return True
    h = host.strip().lower().strip("[]")
    if h in {"localhost", "127.0.0.1", "0.0.0.0", "::1"}:
        return True
    try:
        ip = ipaddress.ip_address(h)
        return bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast)
    except Exception:
        return False


def _host_matches_allowlist(host: str, allowed_domains) -> bool:
    """Host == domain veya host .domain alt alanı ise izin ver."""
    if not host:
        return False
    h = host.strip().lower().rstrip(".")
    for domain in allowed_domains or []:
        d = str(domain).strip().lower().rstrip(".")
        if not d:
            continue
        if h == d or h.endswith("." + d):
            return True
    return False


def _is_allowed_web_qurl(qurl: 'QUrl') -> bool:
    """Web sekmesinde izinli URL mi? (HTTPS/WSS + domain allowlist + local engel)."""
    try:
        scheme = (qurl.scheme() or "").lower()

        # İç sayfalar (blocked mesajı vb.)
        if scheme in {"about"}:
            return True
        if scheme in {"data", "blob"}:
            # data/blob için host beklenmez
            return not qurl.host()

        # Katı şema: sadece TLS'li protokoller
        if scheme not in {"https", "wss"}:
            return False

        host = (qurl.host() or "").lower()
        if _is_private_or_loopback_host(host):
            return False

        return _host_matches_allowlist(host, TRUSTED_DOMAINS)
    except Exception:
        return False


def _blocked_html(reason: str) -> str:
    r = (reason or "").strip()
    if not r:
        r = "Bu adres güvenlik nedeniyle engellendi."
    # Güvenlik: HTML içine kullanıcı/metin basmadan önce escape et
    r = _html.escape(r, quote=True)
    return (
        "<html><body style='background:#111;color:#eee;font-family:sans-serif;'>"
        "<div style='max-width:720px;margin:48px auto;padding:16px;'>"
        "<h2 style='margin:0 0 12px 0;'>⛔ Engellendi</h2>"
        f"<div style='opacity:0.9;line-height:1.5'>{r}</div>"
        "</div></body></html>"
    )


def _looks_like_xss_payload(text: str) -> bool:
    """Çok temel XSS göstergeleri (false-positive olabilir, fail-closed).

    Not: Web sayfanın içindeki form alanlarını (POST body) göremeyiz; burada
    en azından URL/path/query üzerinden bariz payloadları engelliyoruz.
    """
    if not text:
        return False
    t = text.strip().lower()
    # bariz HTML/JS tag/handler örnekleri
    needles = (
        "<script",
        "</script",
        "javascript:",
        "vbscript:",
        "data:text/html",
        "onerror=",
        "onload=",
        "onmouseover=",
        "srcdoc=",
        "document.cookie",
    )
    if any(n in t for n in needles):
        return True
    # ham tag karakterleri (encode edilmemiş)
    if "<" in t or ">" in t:
        return True
    return False


# ---------------------------------------------------------------------------
# WEB DOWNLOAD GÜVENLİĞİ
# ---------------------------------------------------------------------------
_ALLOWED_DOWNLOAD_MIME_PREFIXES = ("image/", "audio/", "video/")

# Script/çalıştırılabilir ve riskli uzantılar (indirimi engelle)
_BLOCKED_DOWNLOAD_EXTS = {
    "exe", "msi", "bat", "cmd", "com", "scr", "pif",
    "ps1", "vbs", "js", "jse", "jar",
    "sh", "bash", "zsh", "fish",
    "py", "pyw", "rb", "pl", "php",
    "htm", "html", "xhtml", "mhtml",
    "svg",  # SVG script içerebilir
    "apk", "dmg", "pkg", "deb", "rpm", "appimage",
    "desktop",
}

# İzinli medya uzantıları (image/audio/video)
_ALLOWED_DOWNLOAD_EXTS = {
    # Images
    "jpg", "jpeg", "png", "gif", "webp", "bmp", "tiff", "tif", "ico",
    # Audio
    "mp3", "flac", "ogg", "m4a", "wav", "aac", "opus", "wma",
    # Video
    "mp4", "mkv", "webm", "avi", "mov", "m4v",
}


def _is_allowed_download(mime_type: str, suggested_name: str) -> bool:
    """Web sekmesi indirmesi için MIME+uzantı kontrolü.

    Talimat gereği hem MIME hem uzantı denetlenir.
    """
    mt = (mime_type or "").strip().lower()
    name = (suggested_name or "").strip()
    ext = _os.path.splitext(name)[1].lower().lstrip(".")

    # Uzantı yoksa veya açıkça riskliyse engelle
    if not ext:
        return False
    if ext in _BLOCKED_DOWNLOAD_EXTS:
        return False

    # MIME yoksa temkinli davran (talimata göre MIME denetimi şart)
    if not mt:
        return False

    # MIME izinli kategori değilse engelle
    if not any(mt.startswith(p) for p in _ALLOWED_DOWNLOAD_MIME_PREFIXES):
        return False

    # Uzantı izinli listede değilse engelle
    if ext not in _ALLOWED_DOWNLOAD_EXTS:
        return False

    return True


try:
    from PyQt5.QtWebEngineCore import QWebEngineUrlRequestInterceptor
except Exception:
    QWebEngineUrlRequestInterceptor = None


if QWebEngineUrlRequestInterceptor is not None:
    class AngollaWebRequestInterceptor(QWebEngineUrlRequestInterceptor):
        """Tüm alt kaynak isteklerinde HTTPS+allowlist zorunluluğu."""

        def interceptRequest(self, info):
            try:
                url = info.requestUrl()
                # XSS/zarlı payload göstergeleri URL içinde ise engelle
                try:
                    import urllib.parse
                    dec = urllib.parse.unquote_plus(url.toString())
                    if _looks_like_xss_payload(dec):
                        info.block(True)
                        return
                except Exception:
                    pass
                if not _is_allowed_web_qurl(url):
                    info.block(True)
            except Exception:
                # Güvenlikte fail-closed tercih edilir
                try:
                    info.block(True)
                except Exception:
                    pass

# ---------------------------------------------------------------------------
# C++ DSP ENGINE BRIDGE
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# PYTHON DSP ENGINE (Replaces buggy C++ implementation)
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# GLOBAL STATE MANAGER (Industrial Persistence)
# ---------------------------------------------------------------------------
class AudioManager(QObject):
    """
    Central source of truth for all Audio & DSP states.
    Survives song changes, playlist skips, and app restarts.
    """
    state_changed = pyqtSignal()
    
    def __init__(self):
        super().__init__()
        self.settings = QSettings("Angolla", "AudioSettings")
        self.lock = threading.Lock()
        
        # Default State
        self.dsp_enabled = True
        self.eq_bands = [0.0] * 32
        self.tone_bass = 0.0
        self.tone_mid = 0.0
        self.tone_treble = 0.0
        self.stereo_width = 1.0
        self.acoustic_space = 0
        self.smart_audio_enabled = True # Varsayılan olarak açık (Efektler hemen duyulsun)
        self._web_mode_activated_ts = 0.0
        self._last_web_video_count = 0
        
        self.load_state()

    def load_state(self):
        with self.lock:
            self.dsp_enabled = self.settings.value("dsp/enabled", True, type=bool)
            bands = self.settings.value("dsp/eq_bands")
            if bands and len(bands) == 32:
                self.eq_bands = [float(x) for x in bands]
            self.tone_bass = float(self.settings.value("dsp/tone_bass", 0.0))
            self.tone_mid = float(self.settings.value("dsp/tone_mid", 0.0))
            self.tone_treble = float(self.settings.value("dsp/tone_treble", 0.0))
            self.stereo_width = float(self.settings.value("dsp/stereo_width", 1.0))
            self.acoustic_space = int(self.settings.value("dsp/acoustic_space", 0))
            self.smart_audio_enabled = self.settings.value("dsp/smart_audio_enabled", True, type=bool)

    def save_state(self):
        with self.lock:
            self.settings.setValue("dsp/enabled", self.dsp_enabled)
            self.settings.setValue("dsp/eq_bands", self.eq_bands)
            self.settings.setValue("dsp/tone_bass", self.tone_bass)
            self.settings.setValue("dsp/tone_mid", self.tone_mid)
            self.settings.setValue("dsp/tone_treble", self.tone_treble)
            self.settings.setValue("dsp/stereo_width", self.stereo_width)
            self.settings.setValue("dsp/acoustic_space", self.acoustic_space)
            self.settings.setValue("dsp/smart_audio_enabled", self.smart_audio_enabled)
            self.settings.sync()

    def update_band(self, index, gain):
        if 0 <= index < 32:
            self.eq_bands[index] = gain
            self.state_changed.emit()

    def update_tone(self, bass, mid, treble):
        self.tone_bass = bass
        self.tone_mid = mid
        self.tone_treble = treble
        if (abs(bass) > 1e-3 or abs(mid) > 1e-3 or abs(treble) > 1e-3) and not self.smart_audio_enabled:
            self.smart_audio_enabled = True
        self.state_changed.emit()

    def update_stereo(self, width):
        self.stereo_width = max(0.0, min(2.0, width))
        if abs(self.stereo_width - 1.0) > 1e-3 and not self.smart_audio_enabled:
            self.smart_audio_enabled = True
        self.state_changed.emit()

    def update_acoustic_space(self, index):
        self.acoustic_space = index
        self.state_changed.emit()

    def update_master_toggle(self, enabled):
        self.smart_audio_enabled = bool(enabled)
        self.state_changed.emit()

    def reset_eq(self):
        self.eq_bands = [0.0] * 32
        self.state_changed.emit()

    def reset_tone_space(self):
        self.tone_bass = 0.0
        self.tone_mid = 0.0
        self.tone_treble = 0.0
        self.stereo_width = 1.0
        self.acoustic_space = 0
        self.state_changed.emit()

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# GLOBAL AUDIO ENGINE (Thread Isolated & Real-time DSP)
# ---------------------------------------------------------------------------
class MockMediaPlayer(QObject):
    """Mimics QMediaPlayer API for seamless integration with existing UI code"""
    positionChanged = pyqtSignal(int)
    durationChanged = pyqtSignal(int)
    stateChanged = pyqtSignal(int)
    mediaStatusChanged = pyqtSignal(int)

    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        self._volume = 70
        self._state = QMediaPlayer.StoppedState
        self._status = QMediaPlayer.NoMedia

    def state(self): return self._state
    def mediaStatus(self): return self._status
    def position(self): return self.engine.get_position_ms()
    def duration(self): return self.engine.get_duration_ms()
    def volume(self): return self._volume
    def setVolume(self, v): 
        self._volume = v
        self.engine.set_volume(v / 100.0)
    def setPosition(self, ms): self.engine.seek(ms)
    def play(self): self.engine.play()
    def pause(self): self.engine.pause()
    def stop(self): self.engine.stop()
    def setMedia(self, content):
        path = content.request().url().toLocalFile()
        self.engine.load_file(path)
    def isSeekable(self): return True
    def isAudioAvailable(self): return True

class GlobalAudioEngine(QThread):
    """
    Professional Thread-Isolated Engine using sounddevice + C++ DSP.
    Ensures 0% UI lag and high-fidelity output.
    """
    viz_data_ready = pyqtSignal(bytes, int, int, int) # raw, size, channels, rate

    def __init__(self, manager: AudioManager):
        super().__init__()
        self.mgr = manager
        self.media_player = MockMediaPlayer(self)
        self.dsp = None
        self.stream = None
        self.audio_data = None
        self.samplerate = 48000
        self.current_frame = 0
        self.running = True
        self.volume = 0.7
        self.paused = True
        self._lock = threading.Lock()
        self.ui_timer = QTimer(self)
        self.ui_timer.setInterval(100) # 10FPS UI updates
        self.ui_timer.timeout.connect(self._emit_ui_updates)
        self.ui_timer.start()
        self.web_queue = collections.deque()
        self.web_queue_samples = 0
        self.web_active = False
        self.web_channels = 2
        self.web_blocksize = 1024
        self.web_max_queue_samples = self.web_blocksize * 2 * 6
        self._web_remainder = None
        self._web_remainder_pos = 0
        self._stream_mode = "local"
        self._web_lpf_freq = 8000.0

        # Transport Fade (Pause/Resume/Stop)
        self._transport_gain = 1.0
        self._fade_active = False
        self._fade_from = 1.0
        self._fade_to = 1.0
        self._fade_pos = 0
        self._fade_len = 0
        self._fade_finish_action = None  # None | "pause" | "stop"
        self._fade_ms = 400
        self._fade_out_on_pause = False
        self._fade_in_on_resume = False
        self._fade_out_on_stop = False
        self._paused_reason = "load"

        # Async load/switch (gap-free next/prev)
        self._pending_audio_data = None
        self._pending_ready = False
        self._pending_request_id = 0
        self._ui_track_changed = False
        
        # Crossfade Variables
        self.crossfade_duration_ms = 0
        self.crossfade_buffer = None
        self.crossfade_pos = 0
        self.crossfade_active = False

        # Crossfade tuning (tek noktadan ayarlanabilir sabitler)
        # Not: Bunlar UI ayarı değildir; sadece motor içi ince ayar değerleri.
        self._crossfade_tuning = {
            "proc_tail_extra_frames": 4096,   # async switch gecikmesi için güvenli pay (~85ms @48kHz)
            "micro_ms_manual": 4.0,           # click/tık engelleme micro fade-in
            "micro_ms_auto": 8.0,
            "in_pow_manual": 0.70,            # <1 => daha hızlı yükseliş
            "in_pow_auto": 1.00,
            "out_pow_manual": 1.15,           # >1 => daha yumuşak düşüş
            "out_pow_auto": 1.00,
        }

        # Crossfade context: affects only transition curve (does not change DSP effects)
        self._crossfade_context = ""

        # Crossfade (processed tail) - old track tail is pre-processed with DSP to avoid
        # bass/eq transient "patlama" during manual next/prev at high tone settings.
        self._cf_proc_buffer = None
        self._cf_proc_ready = False
        self._cf_proc_request_id = 0
        self._cf_proc_start_frame = 0

        # Transition limiter state (smoothes crossfade peaks without "pumping")
        self._transition_limiter_gain = 1.0
        
        # Connect manager updates (thread-safe)
        self.mgr.state_changed.connect(self.sync_dsp_params)

    def run(self):
        print("✓ GlobalAudioEngine (Thread) Starting...")
        try:
            from live_dsp_bridge import LiveDSPBridge 
            self.dsp = LiveDSPBridge()
            self.sync_dsp_params()
        except Exception as e:
            print(f"❌ DSP Error in Thread: {e}")
        self.exec_()
        
        if self.stream:
            self.stream.stop()
            self.stream.close()
        print("👋 GlobalAudioEngine Stopping.")

    def _emit_ui_updates(self):
        # Track değişimi sonrası UI sinyalleri (callback thread yerine burada)
        try:
            if getattr(self, "_ui_track_changed", False):
                self._ui_track_changed = False
                self.media_player.durationChanged.emit(self.get_duration_ms())
                self.media_player._status = QMediaPlayer.LoadedMedia
                self.media_player.mediaStatusChanged.emit(self.media_player._status)
        except Exception:
            pass
        if not self.paused:
            self.media_player.positionChanged.emit(self.get_position_ms())

    @pyqtSlot()
    def sync_dsp_params(self):
        if not self.dsp: return
        with self._lock:
            self.dsp.set_dsp_enabled(self.mgr.dsp_enabled)
            self.dsp.set_eq_bands(self.mgr.eq_bands)
            self.dsp.set_tone_params(self.mgr.tone_bass, self.mgr.tone_mid, self.mgr.tone_treble)
            if hasattr(self.dsp, "set_bass_gain"):
                self.dsp.set_bass_gain(self.mgr.tone_bass)
            if hasattr(self.dsp, "set_treble_gain"):
                self.dsp.set_treble_gain(self.mgr.tone_treble)
            self.dsp.set_stereo_width(self.mgr.stereo_width)
            self.dsp.set_master_toggle(self.mgr.smart_audio_enabled)
            if hasattr(self.dsp, "set_web_lpf"):
                self.dsp.set_web_lpf(self._web_lpf_freq)

    def set_web_lpf(self, freq):
        with self._lock:
            self._web_lpf_freq = freq
            if self.dsp and hasattr(self.dsp, "set_web_lpf"):
                self.dsp.set_web_lpf(freq)

    def set_crossfade_duration(self, ms):
        self.crossfade_duration_ms = max(0, int(ms))

    def set_crossfade_context(self, reason: str):
        """UI'dan gelen parça değişim nedenine göre crossfade davranışını ayarlar."""
        try:
            self._crossfade_context = str(reason or "")
        except Exception:
            self._crossfade_context = ""

    def configure_transport_fades(self, fade_ms: int = 400, stop_fade_enabled: bool = False,
                                  fade_out_on_pause: bool = False, fade_in_on_resume: bool = False):
        """Configure pause/resume/stop fades (LOCAL playback only)."""
        with self._lock:
            self._fade_ms = max(0, int(fade_ms))
            self._fade_out_on_stop = bool(stop_fade_enabled)
            self._fade_out_on_pause = bool(fade_out_on_pause)
            self._fade_in_on_resume = bool(fade_in_on_resume)

    def _start_transport_fade_locked(self, target_gain: float, duration_ms: int, finish_action: str = None):
        try:
            dur_ms = max(0, int(duration_ms))
            if dur_ms <= 0:
                self._fade_active = False
                self._fade_from = float(target_gain)
                self._fade_to = float(target_gain)
                self._fade_pos = 0
                self._fade_len = 0
                self._fade_finish_action = None
                self._transport_gain = float(target_gain)
                return
            self._fade_active = True
            self._fade_from = float(self._transport_gain)
            self._fade_to = float(target_gain)
            self._fade_pos = 0
            self._fade_len = max(1, int((dur_ms / 1000.0) * self.samplerate))
            self._fade_finish_action = finish_action
        except Exception:
            self._fade_active = False
            self._fade_finish_action = None

    def _decode_audio_file_to_stereo(self, path: str):
        """Decode file into stereo float32 ndarray and samplerate."""
        if not sf:
            return None, None
        try:
            data, sr = sf.read(path, dtype="float32")
        except Exception:
            data, sr = self._decode_with_ffmpeg(path)
        if data is None or sr is None:
            return None, None
        if np is None:
            # NumPy yoksa güvenli dönüşüm yapamayız; mevcut davranışa bırak.
            return None, None
        try:
            data = np.asarray(data, dtype=np.float32)
            if data.ndim == 1:
                data = np.column_stack((data, data))
            elif data.shape[1] == 1:
                data = np.column_stack((data[:, 0], data[:, 0]))
            elif data.shape[1] >= 2:
                data = data[:, :2]
            return data, int(sr)
        except Exception:
            return None, None

    def _resample_stereo(self, data, sr: int, target_sr: int = 48000):
        if np is None or data is None or sr is None:
            return data, sr
        try:
            sr = int(sr)
        except Exception:
            return data, sr
        if sr <= 0 or sr == target_sr:
            return data, sr
        try:
            frames = int(data.shape[0])
            if frames <= 1:
                return data, target_sr
            duration = frames / float(sr)
            target_frames = max(1, int(round(duration * target_sr)))
            src_idx = np.linspace(0.0, frames - 1, num=frames, dtype=np.float32)
            dst_idx = np.linspace(0.0, frames - 1, num=target_frames, dtype=np.float32)
            out = np.zeros((target_frames, 2), dtype=np.float32)
            out[:, 0] = np.interp(dst_idx, src_idx, data[:, 0]).astype(np.float32)
            out[:, 1] = np.interp(dst_idx, src_idx, data[:, 1]).astype(np.float32)
            return out, target_sr
        except Exception:
            return data, sr

    def request_play_file(self, file_path: str):
        """Asynchronously decode track; switch inside audio callback to minimize gaps."""
        if not file_path:
            return
        if np is None:
            # NumPy yoksa async yol güvenilir değil.
            return

        with self._lock:
            self._pending_request_id += 1
            req_id = int(self._pending_request_id)
            self._pending_ready = False
            self._pending_audio_data = None

            # Prepare DSP-processed crossfade tail snapshot (old track)
            self._cf_proc_request_id = req_id
            self._cf_proc_ready = False
            self._cf_proc_buffer = None
            self._cf_proc_start_frame = int(self.current_frame)

            cf_tail = None
            cf_preroll = None
            cf_settings = None
            try:
                if (not self.paused) and self.crossfade_duration_ms > 0 and self.audio_data is not None:
                    cf_len = int((self.crossfade_duration_ms / 1000.0) * self.samplerate)
                    if cf_len > 0:
                        remaining = len(self.audio_data) - self.current_frame
                        # Not: switch anı async decode yüzünden birkaç blok gecikebilir.
                        # Eğer yalnızca cf_len kadar tail alırsak ve switch gecikirse,
                        # eski tail "geri sarma" gibi duyulabilir. Biraz ekstra pay bırak.
                        extra = int(getattr(self, "_crossfade_tuning", {}).get("proc_tail_extra_frames", 4096))
                        take = min(remaining, cf_len + extra)
                        if take > 0:
                            # Small warmup to prime IIR filter state (does not change effect, only avoids transient)
                            warm = min(int(0.20 * float(self.samplerate)), int(self.current_frame))
                            if warm > 0:
                                cf_preroll = self.audio_data[self.current_frame - warm : self.current_frame].copy()
                            cf_tail = self.audio_data[self.current_frame : self.current_frame + take].copy()

                            # Snapshot current DSP settings (do not touch algorithms)
                            try:
                                eq = getattr(self.mgr, "eq_bands", None)
                                eq_list = list(eq) if eq is not None else None
                            except Exception:
                                eq_list = None
                            cf_settings = {
                                "dsp_enabled": bool(getattr(self.mgr, "dsp_enabled", True)),
                                "eq_bands": eq_list,
                                "tone_bass": float(getattr(self.mgr, "tone_bass", 0.0)),
                                "tone_mid": float(getattr(self.mgr, "tone_mid", 0.0)),
                                "tone_treble": float(getattr(self.mgr, "tone_treble", 0.0)),
                                "stereo_width": float(getattr(self.mgr, "stereo_width", 1.0)),
                                "smart_audio_enabled": bool(getattr(self.mgr, "smart_audio_enabled", True)),
                                "web_lpf": float(getattr(self, "_web_lpf_freq", 8000.0)),
                                "samplerate": int(self.samplerate),
                            }
            except Exception:
                cf_tail = None
                cf_preroll = None
                cf_settings = None

        def _worker():
            try:
                # 0) Pre-process old-track crossfade tail with DSP (if we have a snapshot)
                try:
                    if cf_tail is not None and cf_settings is not None:
                        from live_dsp_bridge import LiveDSPBridge
                        dsp_cf = LiveDSPBridge()

                        # Apply same DSP settings
                        try:
                            dsp_cf.set_dsp_enabled(bool(cf_settings.get("dsp_enabled", True)))
                            if cf_settings.get("eq_bands") is not None:
                                dsp_cf.set_eq_bands(np.asarray(cf_settings["eq_bands"], dtype=np.float32))
                            dsp_cf.set_tone_params(
                                float(cf_settings.get("tone_bass", 0.0)),
                                float(cf_settings.get("tone_mid", 0.0)),
                                float(cf_settings.get("tone_treble", 0.0)),
                            )
                            if hasattr(dsp_cf, "set_bass_gain"):
                                dsp_cf.set_bass_gain(float(cf_settings.get("tone_bass", 0.0)))
                            if hasattr(dsp_cf, "set_treble_gain"):
                                dsp_cf.set_treble_gain(float(cf_settings.get("tone_treble", 0.0)))
                            dsp_cf.set_stereo_width(float(cf_settings.get("stereo_width", 1.0)))
                            dsp_cf.set_master_toggle(bool(cf_settings.get("smart_audio_enabled", True)))
                            if hasattr(dsp_cf, "set_sample_rate"):
                                dsp_cf.set_sample_rate(float(cf_settings.get("samplerate", 48000)))
                            if hasattr(dsp_cf, "set_web_lpf"):
                                dsp_cf.set_web_lpf(float(cf_settings.get("web_lpf", 8000.0)))
                        except Exception:
                            pass

                        # Warm up filter state (discard output)
                        try:
                            if cf_preroll is not None:
                                warm_buf = np.asarray(cf_preroll, dtype=np.float32).reshape(-1, 2).copy().flatten()
                                dsp_cf.process_buffer(warm_buf)
                        except Exception:
                            pass

                        # Process tail
                        tail_buf = np.asarray(cf_tail, dtype=np.float32).reshape(-1, 2).copy().flatten()
                        dsp_cf.process_buffer(tail_buf)
                        tail_proc = tail_buf.reshape(-1, 2).astype(np.float32, copy=False)

                        with self._lock:
                            if req_id == int(getattr(self, "_cf_proc_request_id", 0)):
                                self._cf_proc_buffer = tail_proc
                                self._cf_proc_ready = True
                except Exception:
                    # Fallback: no processed tail
                    pass

                data, sr = self._decode_audio_file_to_stereo(file_path)
                if data is None or sr is None:
                    return
                data, _ = self._resample_stereo(data, int(sr), target_sr=48000)
                with self._lock:
                    if req_id != self._pending_request_id:
                        return
                    self._pending_audio_data = data
                    self._pending_ready = True
            except Exception:
                return

        threading.Thread(target=_worker, daemon=True).start()

    def _switch_to_pending_if_ready_locked(self):
        """Must be called under _lock; keep it lightweight (callback-safe)."""
        if not getattr(self, "_pending_ready", False):
            return
        data = self._pending_audio_data
        if data is None:
            self._pending_ready = False
            return

        was_paused = bool(self.paused)

        # Crossfade: capture from current track at the exact cut point
        try:
            if (not was_paused) and self.crossfade_duration_ms > 0 and self.audio_data is not None:
                cf_samples = int((self.crossfade_duration_ms / 1000.0) * self.samplerate)
                if cf_samples > 0:
                    # Prefer DSP-processed tail (precomputed) to avoid bass transient/"patlama"
                    use_proc = bool(getattr(self, "_cf_proc_ready", False)) and getattr(self, "_cf_proc_buffer", None) is not None
                    if use_proc:
                        # Align precomputed tail to *actual* cut point to avoid "tekrarlanma/geri sarma" hissi.
                        start_frame = int(getattr(self, "_cf_proc_start_frame", 0) or 0)
                        offset = int(self.current_frame) - start_frame
                        if offset < 0:
                            offset = 0
                        buf = self._cf_proc_buffer
                        if offset >= len(buf):
                            # Too late; fallback to live capture
                            buf = None
                        else:
                            buf = buf[offset : offset + cf_samples]

                        if buf is None or len(buf) <= 0:
                            remaining = len(self.audio_data) - self.current_frame
                            take = min(remaining, cf_samples)
                            if take > 0:
                                self.crossfade_buffer = self.audio_data[self.current_frame : self.current_frame + take].copy()
                                self.crossfade_pos = 0
                                self.crossfade_active = True
                            else:
                                self.crossfade_active = False
                        else:
                            self.crossfade_buffer = buf
                            self.crossfade_pos = 0
                            self.crossfade_active = True
                        self._cf_proc_buffer = None
                        self._cf_proc_ready = False
                    else:
                        remaining = len(self.audio_data) - self.current_frame
                        take = min(remaining, cf_samples)
                        if take > 0:
                            self.crossfade_buffer = self.audio_data[self.current_frame : self.current_frame + take].copy()
                            self.crossfade_pos = 0
                            self.crossfade_active = True
                        else:
                            self.crossfade_active = False
                else:
                    self.crossfade_active = False
            else:
                self.crossfade_active = False
        except Exception:
            self.crossfade_active = False

        # Switch
        self.audio_data = data
        self.current_frame = 0
        self.samplerate = 48000
        self.paused = was_paused
        self._pending_audio_data = None
        self._pending_ready = False
        self._ui_track_changed = True

    def set_force_mute(self, mute: bool):
        """Phase 3: Hard mute for absolute silence."""
        with self._lock:
            if self.dsp and hasattr(self.dsp, "set_force_mute"):
                self.dsp.set_force_mute(mute)

    def _start_output_stream(self, samplerate, blocksize, callback):
        if self.stream:
            try:
                self.stream.stop()
                self.stream.close()
            except Exception:
                pass
        self.stream = sd.OutputStream(
            samplerate=samplerate,
            channels=2,
            callback=callback,
            blocksize=blocksize,
            dtype="float32",
            latency="low",
        )
        self.stream.start()

    def _ensure_web_stream(self, sample_rate):
        if sample_rate <= 0:
            sample_rate = 48000
        if self._stream_mode != "web" or self.samplerate != sample_rate or not self.stream:
            self.samplerate = sample_rate
            if self.dsp and hasattr(self.dsp, "set_sample_rate"):
                self.dsp.set_sample_rate(self.samplerate)
            self._start_output_stream(self.samplerate, self.web_blocksize, self._web_audio_callback)
            self._stream_mode = "web"

    def _clear_web_queue(self):
        self.web_queue.clear()
        self.web_queue_samples = 0
        self._web_remainder = None
        self._web_remainder_pos = 0

    def flush_web_audio(self):
        with self._lock:
            self._clear_web_queue()

    def _drop_web_samples(self, excess):
        if excess <= 0:
            return
        while excess > 0:
            if self._web_remainder is not None:
                avail = len(self._web_remainder) - self._web_remainder_pos
                drop = min(excess, avail)
                self._web_remainder_pos += drop
                self.web_queue_samples -= drop
                excess -= drop
                if self._web_remainder_pos >= len(self._web_remainder):
                    self._web_remainder = None
                    self._web_remainder_pos = 0
                continue
            if not self.web_queue:
                break
            buf = self.web_queue.popleft()
            drop = min(excess, len(buf))
            if drop < len(buf):
                self._web_remainder = buf
                self._web_remainder_pos = drop
            self.web_queue_samples -= drop
            excess -= drop

    def feed_web_audio(self, samples, sample_rate, channels):
        if samples is None:
            return
        try:
            data = np.asarray(samples, dtype=np.float32)
        except Exception:
            return
        if data.size == 0:
            return
        if channels <= 0:
            channels = 2
        frames = data.size // channels
        if frames <= 0:
            return
        data = data[: frames * channels]
        if channels == 1:
            stereo = np.empty((frames, 2), dtype=np.float32)
            stereo[:, 0] = data
            stereo[:, 1] = data
            data = stereo
        elif channels != 2:
            try:
                data = data.reshape(frames, channels)[:, :2]
            except Exception:
                return
        else:
            data = data.reshape((frames, 2))
        # Sesin hoparlöre saf aktarılması için 48kHz'e yeniden örnekle
        if sample_rate != 48000 and sample_rate > 0:
            duration = frames / float(sample_rate)
            target_frames = max(1, int(round(duration * 48000)))
            src_idx = np.linspace(0.0, frames - 1, num=frames, dtype=np.float32)
            dst_idx = np.linspace(0.0, frames - 1, num=target_frames, dtype=np.float32)
            resampled = np.zeros((target_frames, 2), dtype=np.float32)
            for ch in range(2):
                resampled[:, ch] = np.interp(dst_idx, src_idx, data[:, ch])
            data = resampled
            sample_rate = 48000

        data = np.clip(data, -1.0, 1.0)
        with self._lock:
            self.web_active = True
            self.web_channels = 2
            self._ensure_web_stream(48000)
            # Store as (frames, 2) to prevent broadcast errors
            self.web_queue.append(data)
            self.web_queue_samples += data.size
            if self.web_queue_samples > self.web_max_queue_samples:
                self._drop_web_samples(self.web_queue_samples - self.web_max_queue_samples)

    def feed_monitor_audio(self, samples, sample_rate):
        """Phase 3: High-quality monitor feeding with C++ Resampling."""
        if samples is None: return
        try:
            data = np.asarray(samples, dtype=np.float32)
        except Exception: return
        if data.size == 0: return

        with self._lock:
            self.web_active = True
            self._ensure_web_stream(48000) # Output is always 48k
            
            # Force (frames, 2)
            frames = data.size // 2
            data = data[:frames * 2].reshape((frames, 2))
            
            self.web_queue.append((data, sample_rate))
            self.web_queue_samples += data.size
            if self.web_queue_samples > self.web_max_queue_samples:
                self._drop_web_samples(self.web_queue_samples - self.web_max_queue_samples)

    def stop_web_audio(self):
        with self._lock:
            self.web_active = False
            self._clear_web_queue()
            if self._stream_mode == "web" and self.stream:
                try:
                    self.stream.stop()
                    self.stream.close()
                except Exception:
                    pass
                self.stream = None
                self._stream_mode = "local"

    def _pull_web_samples(self, needed_frames):
        """Pull stereo frames from the queue. Returns (needed_frames, 2) or None."""
        needed_samples = needed_frames * 2
        out = np.zeros((needed_frames, 2), dtype=np.float32)
        filled_samples = 0
        
        while filled_samples < needed_samples:
            if self._web_remainder is None:
                if not self.web_queue:
                    break
                entry = self.web_queue.popleft()
                # Ensure entry is a 1D interleaved array
                if isinstance(entry, tuple):
                    self._web_remainder = entry[0].flatten()
                else:
                    self._web_remainder = entry.flatten()
                self._web_remainder_pos = 0
            
            avail = len(self._web_remainder) - self._web_remainder_pos
            take = min(needed_samples - filled_samples, avail)
            
            # Write into flattened view of our stereo output
            out.flat[filled_samples:filled_samples + take] = self._web_remainder[
                self._web_remainder_pos:self._web_remainder_pos + take
            ]
            
            self._web_remainder_pos += take
            self.web_queue_samples -= take
            filled_samples += take
            
            if self._web_remainder_pos >= len(self._web_remainder):
                self._web_remainder = None
                self._web_remainder_pos = 0
                
        if filled_samples < needed_samples:
            return None
        return out

    def _web_audio_callback(self, outdata, frames, time_info, status):
        try:
            outdata.fill(0)
            if not self.web_active:
                return
            
            with self._lock:
                if not self.web_queue and self._web_remainder is None:
                    return
                
                # Pull as (frames, 2)
                buf = self._pull_web_samples(frames)
            
            if buf is None:
                return

            proc_buf = buf.flatten()
            # Map back to stereo output
            out_view = outdata
            if out_view.ndim == 1:
                if out_view.size == frames * 2:
                    out_view = out_view.reshape(frames, 2)
                else:
                    out_view[:frames] = proc_buf.reshape(frames, 2).mean(axis=1) * self.volume
                    return
            out_view[:frames] = proc_buf.reshape(frames, 2) * self.volume

            # Phase 4/6: Emit viz data with 3.0x Gain and Standard Shape
            viz_pushed = (proc_buf * 3.0).clip(-1.0, 1.0).astype(np.float32)
            self.viz_data_ready.emit(viz_pushed.tobytes(), 32, 2, self.samplerate)
        except Exception:
            pass

    def load_file(self, path):
        if not sf:
            print("❌ soundfile not found. Cannot load local files.")
            return
        
        # Crossfade Capture
        with self._lock:
            if self.crossfade_duration_ms > 0 and self.audio_data is not None and not self.paused:
                try:
                    cf_samples = int((self.crossfade_duration_ms / 1000.0) * self.samplerate)
                    if cf_samples > 0:
                        remaining = len(self.audio_data) - self.current_frame
                        take = min(remaining, cf_samples)
                        if take > 0:
                            self.crossfade_buffer = self.audio_data[self.current_frame : self.current_frame + take].copy()
                            self.crossfade_pos = 0
                            self.crossfade_active = True
                        else:
                            self.crossfade_active = False
                except Exception:
                    self.crossfade_active = False
            else:
                self.crossfade_active = False

            self.audio_data = None
            self.current_frame = 0
            self.paused = True
            self._paused_reason = "load"
            self._transport_gain = 1.0
            self._fade_active = False
            self._fade_finish_action = None

        try:
            data, sr = sf.read(path, dtype='float32')
        except Exception as e:
            data, sr = self._decode_with_ffmpeg(path)
            if data is None:
                print(f"❌ Error loading audio {path}: {e}")
                self.media_player._status = QMediaPlayer.InvalidMedia
                self.media_player.mediaStatusChanged.emit(self.media_player._status)
                return

        # Mümkünse 48kHz'e sabitle (stream restart kaynaklı ses kesilmelerini azaltır)
        try:
            if np is not None:
                data = np.asarray(data, dtype=np.float32)
                if data.ndim == 1:  # Mono -> Stereo
                    data = np.column_stack((data, data))
                elif data.shape[1] == 1:
                    data = np.column_stack((data[:, 0], data[:, 0]))
                elif data.shape[1] >= 2:
                    data = data[:, :2]

                sr = int(sr) if sr else 48000
                if sr != 48000 and sr > 0:
                    frames = int(data.shape[0])
                    duration = frames / float(sr)
                    target_frames = max(1, int(round(duration * 48000)))
                    src_idx = np.linspace(0.0, frames - 1, num=frames, dtype=np.float32)
                    dst_idx = np.linspace(0.0, frames - 1, num=target_frames, dtype=np.float32)
                    out = np.zeros((target_frames, 2), dtype=np.float32)
                    out[:, 0] = np.interp(dst_idx, src_idx, data[:, 0]).astype(np.float32)
                    out[:, 1] = np.interp(dst_idx, src_idx, data[:, 1]).astype(np.float32)
                    data = out
                self.samplerate = 48000
            else:
                # NumPy yoksa mevcut davranış: file samplerate
                self.samplerate = int(sr) if sr else 48000
        except Exception:
            self.samplerate = int(sr) if sr else 48000

        try:
            with self._lock:
                self.audio_data = data
                self.current_frame = 0
                self.paused = True

            self.media_player.durationChanged.emit(self.get_duration_ms())
            self.media_player._status = QMediaPlayer.LoadedMedia
            self.media_player.mediaStatusChanged.emit(self.media_player._status)
            print(f"🎵 Loaded: {os.path.basename(path)} ({self.samplerate}Hz)")

            # Stream'i mümkün olduğunca sabit tut: sadece yoksa başlat veya samplerate değiştiyse yeniden başlat
            need_restart = (not self.stream) or (int(getattr(self, 'samplerate', 48000)) != int(getattr(self, '_stream_samplerate', 0) or 0))
            if need_restart:
                try:
                    if self.stream:
                        self.stream.stop()
                        self.stream.close()
                except Exception:
                    pass
                if self.dsp and hasattr(self.dsp, "set_sample_rate"):
                    self.dsp.set_sample_rate(self.samplerate)
                self._start_output_stream(self.samplerate, 1024, self._audio_callback)
                self._stream_samplerate = int(self.samplerate)
            self._stream_mode = "local"
            self.web_active = False
            self._clear_web_queue()
            
        except Exception as e:
            print(f"❌ Error loading audio {path}: {e}")
            self.media_player._status = QMediaPlayer.InvalidMedia
            self.media_player.mediaStatusChanged.emit(self.media_player._status)

    def _decode_with_ffmpeg(self, input_path):
        try:
            import hashlib
            import subprocess
        except Exception:
            return None, None

        cache_dir = Path("/tmp/angolla_live_cache")
        cache_dir.mkdir(exist_ok=True)

        try:
            st = os.stat(input_path)
            key = f"{input_path}|{st.st_mtime_ns}|{st.st_size}"
        except OSError:
            key = input_path

        cache_name = hashlib.md5(key.encode("utf-8", "ignore")).hexdigest()[:12] + ".wav"
        out_path = cache_dir / cache_name

        if not out_path.exists():
            try:
                subprocess.run(
                    [
                        "ffmpeg",
                        "-y",
                        "-v",
                        "error",
                        "-i",
                        input_path,
                        "-ac",
                        "2",
                        "-ar",
                        "48000",
                        str(out_path),
                    ],
                    check=True,
                )
            except FileNotFoundError:
                print("❌ ffmpeg not found. Cannot decode this format.")
                return None, None
            except subprocess.CalledProcessError as exc:
                print(f"❌ ffmpeg decode failed: {exc}")
                return None, None

        try:
            data, sr = sf.read(str(out_path), dtype="float32")
            return data, sr
        except Exception as exc:
            print(f"❌ Decoded file read failed: {exc}")
            return None, None

    def _audio_callback(self, outdata, frames, time, status):
        # High-performance callback
        with self._lock:
            # Eğer yeni parça hazırsa, sessizliğe düşmeden hemen switch et
            try:
                self._switch_to_pending_if_ready_locked()
            except Exception:
                pass

            if self.paused or self.audio_data is None:
                outdata.fill(0)
                return

            start = self.current_frame
            end = start + frames
            
            if start >= len(self.audio_data):
                outdata.fill(0)
                self.paused = True
                self.media_player._state = QMediaPlayer.StoppedState
                self.media_player.stateChanged.emit(self.media_player._state)
                # End of Media
                self.media_player._status = QMediaPlayer.EndOfMedia
                self.media_player.mediaStatusChanged.emit(self.media_player._status)
                return

            chunk = self.audio_data[start:end]
            actual_frames = len(chunk)
            
            # Prepare buffers for C++ [L, R, L, R...]
            raw_buf = chunk.copy().flatten()
            proc_buf = raw_buf.copy()
            if self.dsp:
                self.dsp.process_buffer(proc_buf)
            
            # --- CROSSFADE (Modular) ---
            self._apply_crossfade(proc_buf, actual_frames)
            # ---------------------------

            # --- TRANSPORT FADE (Pause/Resume/Stop) ---
            self._apply_transport_fade(proc_buf, actual_frames)
            # ------------------------------------------

            # Transition limiter (crossfade overlap can create peaks at high volume)
            is_transition = False
            try:
                if self.crossfade_duration_ms > 0:
                    cf_len = int((self.crossfade_duration_ms / 1000.0) * self.samplerate)
                    if cf_len > 0 and (self.crossfade_active or self.current_frame < cf_len):
                        is_transition = True
            except Exception:
                is_transition = False

            if not is_transition:
                # Geçiş yokken limiter reset
                try:
                    self._transition_limiter_gain = 1.0
                except Exception:
                    pass

            # Apply Volume and copy to output
            out_view = outdata
            if out_view.ndim == 1:
                if out_view.size == frames * 2:
                    out_view = out_view.reshape(frames, 2)
                else:
                    mono = proc_buf.reshape(-1, 2)[:actual_frames].mean(axis=1) * self.volume
                    if is_transition and np is not None:
                        try:
                            peak = float(np.max(np.abs(mono)))
                            ceiling = 0.99
                            target = 1.0 if peak <= ceiling else (ceiling / peak)
                            g0 = float(getattr(self, "_transition_limiter_gain", 1.0))
                            # Attack: hızlı azalt, Release: yavaş toparla (pompalanma olmasın)
                            if target < g0:
                                g1 = target
                            else:
                                g1 = g0 + (target - g0) * 0.08
                            self._transition_limiter_gain = float(g1)
                            mono *= float(g1)
                        except Exception:
                            pass
                    out_view[:actual_frames] = mono
                    if actual_frames < frames:
                        out_view[actual_frames:].fill(0)
                        self.paused = True
                        self.media_player._state = QMediaPlayer.StoppedState
                        self.media_player.stateChanged.emit(self.media_player._state)
                        self.media_player._status = QMediaPlayer.EndOfMedia
                        self.media_player.mediaStatusChanged.emit(self.media_player._status)
                    self.current_frame += actual_frames
                    viz_buf = raw_buf
                    self.viz_data_ready.emit(viz_buf.tobytes(), 32, 2, self.samplerate)
                    return
            stereo = proc_buf.reshape(-1, 2)[:actual_frames] * self.volume
            if is_transition and np is not None:
                try:
                    peak = float(np.max(np.abs(stereo)))
                    ceiling = 0.99
                    target = 1.0 if peak <= ceiling else (ceiling / peak)
                    g0 = float(getattr(self, "_transition_limiter_gain", 1.0))
                    if target < g0:
                        g1 = target
                    else:
                        g1 = g0 + (target - g0) * 0.08
                    self._transition_limiter_gain = float(g1)
                    stereo *= float(g1)
                except Exception:
                    pass
            out_view[:actual_frames] = stereo
            if actual_frames < frames:
                outdata[actual_frames:].fill(0)
                self.paused = True
                self.media_player._state = QMediaPlayer.StoppedState
                self.media_player.stateChanged.emit(self.media_player._state)
                self.media_player._status = QMediaPlayer.EndOfMedia
                self.media_player.mediaStatusChanged.emit(self.media_player._status)
            
            self.current_frame += actual_frames
            
            # Emit viz data (PCM for FFT) using pre-DSP audio
            viz_buf = raw_buf
            self.viz_data_ready.emit(viz_buf.tobytes(), 32, 2, self.samplerate)

    def _apply_transport_fade(self, proc_buf, actual_frames):
        """Applies pause/resume/stop fades to the processed buffer."""
        try:
            # Fast path: constant gain
            if not self._fade_active:
                if abs(self._transport_gain - 1.0) > 1e-6:
                    proc_view = proc_buf.reshape(-1, 2)
                    proc_view *= float(self._transport_gain)
                return

            # Fade path
            proc_view = proc_buf.reshape(-1, 2)
            remaining = max(0, int(self._fade_len) - int(self._fade_pos))
            if remaining <= 0:
                self._fade_active = False
                self._transport_gain = float(self._fade_to)
                self._finish_transport_fade_if_needed()
                if abs(self._transport_gain - 1.0) > 1e-6:
                    proc_view *= float(self._transport_gain)
                return

            take = min(int(actual_frames), remaining)
            if take > 0:
                start_pos = int(self._fade_pos)
                end_pos = start_pos + take
                if self._fade_len <= 0:
                    gains = np.full((take,), float(self._fade_to), dtype=np.float32)
                else:
                    t0 = start_pos / float(self._fade_len)
                    t1 = end_pos / float(self._fade_len)
                    gains = np.linspace(
                        self._fade_from + (self._fade_to - self._fade_from) * t0,
                        self._fade_from + (self._fade_to - self._fade_from) * t1,
                        take,
                        dtype=np.float32,
                    )
                proc_view[:take] *= gains[:, np.newaxis]

            if actual_frames > take:
                # After fade ends within this block, use the target gain
                tail_gain = float(self._fade_to)
                proc_view[take:actual_frames] *= tail_gain

            self._fade_pos += int(actual_frames)
            if self._fade_pos >= self._fade_len:
                self._fade_active = False
                self._transport_gain = float(self._fade_to)
                self._finish_transport_fade_if_needed()
        except Exception:
            pass

    def _finish_transport_fade_if_needed(self):
        action = self._fade_finish_action
        if not action:
            return
        self._fade_finish_action = None
        try:
            if action == "pause":
                self.paused = True
                self._paused_reason = "user_pause"
                self.media_player._state = QMediaPlayer.PausedState
                self.media_player.stateChanged.emit(self.media_player._state)
            elif action == "stop":
                self.paused = True
                self.current_frame = 0
                self._paused_reason = "user_stop"
                self.media_player._state = QMediaPlayer.StoppedState
                self.media_player.stateChanged.emit(self.media_player._state)
        except Exception:
            pass

    def _apply_crossfade(self, proc_buf, actual_frames):
        """Applies crossfade logic to the processed buffer."""
        if self.crossfade_duration_ms <= 0:
            return

        try:
            cf_len = int((self.crossfade_duration_ms / 1000.0) * self.samplerate)
            if cf_len <= 0:
                return

            # 1) Fade In (New Track)
            # Not: Kazanç toplamı > 1 olursa algısal "ses yükselmesi" ve tepe oluşabilir.
            # Bu yüzden equal-power eğriyi kullanıp, miks bölgesinde toplam kazancı 1'e normalize edeceğiz.
            proc_view = proc_buf.reshape(-1, 2)
            ctx = (getattr(self, "_crossfade_context", "") or "").strip().lower()
            manual_ctx = ctx in ("manual_next", "manual_prev", "manual_select")

            # Not: Eski parçanın sesi "akıcı" azalmalı.
            # Bu yüzden miks eğrisini equal-power tabanlı tutuyoruz:
            # yeni_gain = sin(t*pi/2), eski_gain = cos(t*pi/2)
            # Manuel geçişte yeni biraz daha hızlı belirir (tık/ani his olmadan).
            tuning = getattr(self, "_crossfade_tuning", {}) or {}
            in_pow = float(tuning.get("in_pow_manual" if manual_ctx else "in_pow_auto", 1.0))
            out_pow = float(tuning.get("out_pow_manual" if manual_ctx else "out_pow_auto", 1.0))

            ramp_in = None
            if self.current_frame < cf_len:
                start_pos = int(self.current_frame)
                t = (np.arange(actual_frames, dtype=np.float32) + float(start_pos)) / float(cf_len)
                t = np.clip(t, 0.0, 1.0)
                base_in = np.sin(t * (np.pi / 2.0)).astype(np.float32, copy=False)
                # power-shape (manual: daha hızlı)
                try:
                    ramp_in = np.power(base_in, np.float32(in_pow)).astype(np.float32, copy=False)
                except Exception:
                    ramp_in = base_in

                # "Tık" engelleme: yeni parça başlangıcında çok kısa micro fade-in.
                # 4-8ms gibi çok kısa bir yükseliş, hem pürüzsüz yapar hem de 'akıcı crossfade' hissini bozmaz.
                try:
                    micro_ms = float(tuning.get("micro_ms_manual" if manual_ctx else "micro_ms_auto", 6.0))
                    micro_len = int((micro_ms / 1000.0) * float(self.samplerate))
                    if micro_len > 1:
                        mt = (np.arange(actual_frames, dtype=np.float32) + float(start_pos)) / float(micro_len)
                        mt = np.clip(mt, 0.0, 1.0)
                        micro_env = (0.5 - 0.5 * np.cos(np.pi * mt)).astype(np.float32, copy=False)
                        ramp_in = (ramp_in * micro_env).astype(np.float32, copy=False)
                except Exception:
                    pass
                proc_view[:actual_frames] *= ramp_in[:, np.newaxis]

            # 2) Fade Out (Old Track)
            if self.crossfade_active and self.crossfade_buffer is not None:
                cf_avail = len(self.crossfade_buffer) - self.crossfade_pos
                if cf_avail > 0:
                    mix_len = min(actual_frames, cf_avail)
                    cf_chunk = self.crossfade_buffer[self.crossfade_pos : self.crossfade_pos + mix_len]
                    
                    start_pos = int(self.crossfade_pos)
                    t = (np.arange(mix_len, dtype=np.float32) + float(start_pos)) / float(cf_len)
                    t = np.clip(t, 0.0, 1.0)
                    base_out = np.cos(t * (np.pi / 2.0)).astype(np.float32, copy=False)
                    try:
                        ramp_out = np.power(base_out, np.float32(out_pow)).astype(np.float32, copy=False)
                    except Exception:
                        ramp_out = base_out

                    # Old + New mix
                    proc_view[:mix_len] += cf_chunk * ramp_out[:, np.newaxis]

                    # Gain-bump önleme: (ramp_in + ramp_out) > 1 ise 1'e normalize et
                    try:
                        if ramp_in is None:
                            in_mix = np.zeros((mix_len,), dtype=np.float32)
                        else:
                            in_mix = ramp_in[:mix_len]
                        denom = in_mix + ramp_out
                        denom = np.maximum(1.0, denom).astype(np.float32, copy=False)
                        proc_view[:mix_len] /= denom[:, np.newaxis]
                    except Exception:
                        pass
                    
                    self.crossfade_pos += mix_len
                else:
                    self.crossfade_active = False

            # Crossfade bittiğinde manuel bağlamı temizle (bir sonraki geçişi etkilemesin)
            try:
                if self.current_frame >= cf_len and not self.crossfade_active:
                    self._crossfade_context = ""
            except Exception:
                pass
        except Exception:
            pass

    def get_position_ms(self):
        return int((self.current_frame / self.samplerate) * 1000)

    def get_duration_ms(self):
        if self.audio_data is None: return 0
        return int((len(self.audio_data) / self.samplerate) * 1000)

    def set_volume(self, v):
        self.volume = v

    def seek(self, ms):
        with self._lock:
            self.current_frame = int((ms / 1000.0) * self.samplerate)
            self.current_frame = max(0, min(self.current_frame, len(self.audio_data) if self.audio_data is not None else 0))

    def play(self):
        with self._lock:
            was_paused = bool(self.paused)
            reason = getattr(self, "_paused_reason", None)
            self.paused = False
            self._paused_reason = None
            # Only apply fade-in on resume from a user pause
            if was_paused and reason == "user_pause" and self._fade_in_on_resume and self._fade_ms > 0:
                self._transport_gain = 0.0
                self._start_transport_fade_locked(1.0, self._fade_ms, finish_action=None)
            else:
                self._transport_gain = 1.0
                self._fade_active = False
                self._fade_finish_action = None
        self.media_player._state = QMediaPlayer.PlayingState
        self.media_player.stateChanged.emit(self.media_player._state)

    def pause(self):
        with self._lock:
            if self.paused:
                return
            if self._fade_out_on_pause and self._fade_ms > 0:
                self._paused_reason = "user_pause"
                self._start_transport_fade_locked(0.0, self._fade_ms, finish_action="pause")
                return
            self.paused = True
            self._paused_reason = "user_pause"
        self.media_player._state = QMediaPlayer.PausedState
        self.media_player.stateChanged.emit(self.media_player._state)

    def stop(self):
        with self._lock:
            if (not self.paused) and self._fade_out_on_stop and self._fade_ms > 0:
                self._paused_reason = "user_stop"
                self._start_transport_fade_locked(0.0, self._fade_ms, finish_action="stop")
                return
            self.paused = True
            self._paused_reason = "user_stop"
            self.current_frame = 0
            self._transport_gain = 1.0
            self._fade_active = False
            self._fade_finish_action = None
        self.media_player._state = QMediaPlayer.StoppedState
        self.media_player.stateChanged.emit(self.media_player._state)

    def shutdown(self):
        """GlobalAudioEngine thread-safe shutdown."""
        try:
            if self.ui_timer and self.ui_timer.isActive():
                self.ui_timer.stop()
        except Exception:
            pass
        with self._lock:
            self.web_active = False
            self.paused = True
            self._clear_web_queue()
        try:
            if self.stream:
                self.stream.stop()
                self.stream.close()
        except Exception:
            pass
        self.stream = None
        self.quit()
        self.wait(2000)

    def play_file(self, file_path):
        """Compatibility slot for playlist integration"""
        if np is not None:
            try:
                self.request_play_file(file_path)
                # Eğer stream hiç başlamadıysa, hızlı bir şekilde oynatmayı başlat
                if not self.stream:
                    # Fallback: ilk parçada gecikmeyi minimize etmek için sync yükle
                    self.load_file(file_path)
            except Exception:
                self.load_file(file_path)
        else:
            self.load_file(file_path)
        self.play()

# ---------------------------------------------------------------------------
# OFFLINE DSP PROCESSOR
# ---------------------------------------------------------------------------
class OfflineDSPProcessor:
    """Processes audio files offline with DSP effects"""
    
    def __init__(self, dsp_engine):
        self.dsp = dsp_engine
        self.cache_dir = Path("/tmp/angolla_dsp_cache")
        self.cache_dir.mkdir(exist_ok=True)
        
    def _get_settings_hash(self):
        """Generate hash of current DSP settings"""
        import hashlib
        settings_str = (
            f"{self.dsp.enabled}_"
            f"{self.dsp.eq_gains.tobytes()}_"
        )
        return hashlib.md5(settings_str.encode()).hexdigest()[:8]
    
    def _get_cache_path(self, input_path):
        """Get cached file path for given input"""
        input_file = Path(input_path)
        settings_hash = self._get_settings_hash()
        cache_name = f"{input_file.stem}_{settings_hash}.wav"
        return self.cache_dir / cache_name
    
    def is_cached(self, input_path):
        """Check if processed version exists in cache"""
        cache_path = self._get_cache_path(input_path)
        return cache_path.exists()
    
    def _get_source_cache_path(self, input_path):
        """Get path for cached source WAV (decoded from M4A etc)"""
        import hashlib
        input_file = Path(input_path)
        # Hash full path to avoid collisions with same filename in different dirs
        path_hash = hashlib.md5(str(input_file).encode()).hexdigest()[:8]
        cache_name = f"source_{input_file.stem}_{path_hash}.wav"
        return self.cache_dir / cache_name

    def process_file(self, input_path, progress_callback=None):
        """Process audio file with DSP"""
        import soundfile as sf
        import subprocess
        import tempfile
        import os
        
        # Check output cache first (Already processed with current settings?)
        cache_path = self._get_cache_path(input_path)
        if cache_path.exists():
            if progress_callback: progress_callback(100)
            return str(cache_path)
        
        if progress_callback: progress_callback(5)
            
        # --- SMART SOURCE LOADING ---
        # Strategy: 
        # 1. Try direct read (WAV, FLAC, etc)
        # 2. If fail, check for "source cache" (decoded M4A->WAV)
        # 3. If no cache, convert with ffmpeg and SAVE to source cache
        
        audio = None
        sr = 48000
        
        try:
            # 1. Try direct read
            audio, sr = sf.read(input_path, dtype='float32')
        except Exception:
            # Not native format. Check source cache.
            source_cache = self._get_source_cache_path(input_path)
            
            if source_cache.exists():
                print(f"✓ Using cached source (fast load): {source_cache.name}")
                audio, sr = sf.read(source_cache, dtype='float32')
            else:
                # 3. Must convert
                print(f"⚠️ Decoding format with ffmpeg (first time only): {input_path}")
                try:
                    # Convert directly to SOURCE CACHE path
                    subprocess.run([
                        'ffmpeg', '-y', '-v', 'error', 
                        '-i', str(input_path),
                        '-ar', '48000', 
                        '-ac', '2',
                        '-f', 'wav', 
                        str(source_cache)
                    ], check=True)
                    
                    audio, sr = sf.read(source_cache, dtype='float32')
                    print(f"✓ Saved decoded source to cache: {source_cache.name}")
                    
                except Exception as e:
                    print(f"❌ Audio loading failed completely: {e}")
                    raise e
        
        # Convert mono to stereo
        if len(audio.shape) == 1:
            audio = np.column_stack((audio, audio))
        
        if progress_callback:
            progress_callback(10)
        
        # Process in chunks (smaller chunks for better limiter response)
        # 4096 samples @ 48kHz = ~85ms
        # Prevents "pumping" where a single peak dips the volume for 2 seconds
        chunk_size = 4096 
        processed_chunks = []
        
        total_samples = len(audio)
        num_chunks = (total_samples + chunk_size - 1) // chunk_size
        
        for i in range(num_chunks):
            start = i * chunk_size
            end = min(start + chunk_size, total_samples)
            chunk = audio[start:end]
            
            # Process through DSP
            processed_chunk = self.dsp.process(chunk)
            processed_chunks.append(processed_chunk)
            
            # Update progress (10% to 90%)
            if progress_callback:
                progress = 10 + int((i / num_chunks) * 80)
                progress_callback(progress)
        
        # Concatenate all chunks
        processed_audio = np.vstack(processed_chunks)
        
        if progress_callback:
            progress_callback(95)
        
        # Save to cache
        sf.write(str(cache_path), processed_audio, sr, subtype='PCM_16')
        
        if progress_callback:
            progress_callback(100)
        
        return str(cache_path)

# ---------------------------------------------------------------------------
# DSP BACKGROUND WORKER
# ---------------------------------------------------------------------------
class DSPWorker(QThread):
    finished = pyqtSignal(str, int, bool) # processed_path, position, was_playing
    
    def __init__(self, processor, file_path, position, was_playing):
        super().__init__()
        self.processor = processor
        self.file_path = file_path
        self.position = position
        self.was_playing = was_playing
        
    def run(self):
        try:
            # Process in thread without blocking UI
            result = self.processor.process_file(self.file_path)
            self.finished.emit(result, self.position, self.was_playing)
        except Exception as e:
            print(f"Worker Error: {e}")
            self.finished.emit(self.file_path, self.position, self.was_playing) # Fallback

# ---------------------------------------------------------------------------
# VISUALIZER WORKER (Offloads FFT from UI Thread)
# ---------------------------------------------------------------------------
class VisualizerWorker(QObject):
    data_ready = pyqtSignal(list, bytes) # band_vals, pcm_raw
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._prev_band_vals = None # Anti-Jitter Memory
    
    @pyqtSlot(bytes, int, int, int)
    def process_buffer(self, raw, sample_size, channels, sample_rate):
        """Perform FFT and spectrum analysis in background thread"""
        try:
            if sample_size == 8:
                dtype = np.int8
            elif sample_size == 16:
                dtype = np.int16
            elif sample_size == 32:
                dtype = np.float32
            else:
                dtype = np.int32
            
            samples = np.frombuffer(raw, dtype=dtype)
            if channels == 2:
                samples = samples.reshape(-1, 2).mean(axis=1)

            samples = samples.astype(np.float32)
            N = len(samples)
            if N < 512:
                return

            # ═══════════════════════════════════════════════════════════════
            # RESAMPLING: 44100Hz → 48000Hz (Web ses cızırtısı çözümü)
            # ═══════════════════════════════════════════════════════════════
            TARGET_RATE = 48000
            if sample_rate != TARGET_RATE and sample_rate > 0:
                duration = N / sample_rate
                target_samples = int(duration * TARGET_RATE)
                if target_samples > 0:
                    samples = np.interp(
                        np.linspace(0, duration, target_samples),
                        np.linspace(0, duration, N),
                        samples
                    ).astype(np.float32)
                    N = len(samples)

            # FFT
            effective_rate = float(TARGET_RATE if (sample_rate != TARGET_RATE and sample_rate > 0) else sample_rate)
            window = np.hanning(N)
            windowed = samples * window
            fft = np.fft.rfft(windowed, n=4096)

            magnitude = np.abs(fft)
            nyquist = effective_rate / 2.0
            min_freq = 20.0
            max_freq = min(20000.0, nyquist)

            freqs = np.fft.rfftfreq(4096, d=1.0 / effective_rate) if effective_rate > 0 else None
            if freqs is None:
                return

            start_idx = int(np.searchsorted(freqs, min_freq))
            end_idx = int(np.searchsorted(freqs, max_freq))
            if end_idx <= start_idx + 2:
                return

            freq_slice = freqs[start_idx:end_idx]
            mag_slice = magnitude[start_idx:end_idx]

            num_bars = 96
            target_freqs = np.linspace(min_freq, max_freq, num_bars)
            band_vals = np.interp(target_freqs, freq_slice, mag_slice)
            
            # Anti-Jitter Smoothing (Exponential Moving Average) - Seri tepki için alpha artırıldı
            if self._prev_band_vals is not None and len(self._prev_band_vals) == num_bars:
                alpha = 0.95 # Smoothing factor (0.95 = %95 yeni veri, %5 eski veri) - Çok daha seri
                band_vals = alpha * band_vals + (1.0 - alpha) * self._prev_band_vals
            
            self._prev_band_vals = band_vals
            self.data_ready.emit(band_vals.tolist(), raw)
        except Exception as e:
            print(f"VizWorker Error: {e}")

# ---------------------------------------------------------------------------
# EQ CURVE VISUALIZATION WIDGET (Tone_Space Fill)
# ---------------------------------------------------------------------------
class EQCurveWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.slider_positions = []
        self.baseline_y = 0
        self.peak_gain = 0.0

    def set_slider_positions(self, positions, baseline_y, peak_gain=None):
        self.slider_positions = positions
        self.baseline_y = baseline_y
        if peak_gain is not None:
            self.peak_gain = peak_gain
        self.update()

    def _blend_color(self, c1, c2, t):
        t = max(0.0, min(1.0, t))
        r = int(c1.red() + (c2.red() - c1.red()) * t)
        g = int(c1.green() + (c2.green() - c1.green()) * t)
        b = int(c1.blue() + (c2.blue() - c1.blue()) * t)
        return QColor(r, g, b)

    def _heat_color(self, gain_db):
        cold = QColor(200, 230, 255)  # ice blue
        green = QColor(70, 220, 110)
        red = QColor(255, 70, 70)

        if gain_db <= -15.0:
            return cold
        if gain_db < 0.0:
            return self._blend_color(cold, green, (gain_db + 15.0) / 15.0)
        if gain_db < 15.0:
            return self._blend_color(green, red, gain_db / 15.0)
        return red

    def paintEvent(self, event):
        if len(self.slider_positions) < 2:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        curve_path = QPainterPath()
        curve_path.moveTo(self.slider_positions[0][0], self.slider_positions[0][1])
        for i in range(len(self.slider_positions) - 1):
            x1, y1, _ = self.slider_positions[i]
            x2, y2, _ = self.slider_positions[i + 1]
            cx = (x1 + x2) / 2
            cy = (y1 + y2) / 2
            curve_path.quadTo(cx, cy, x2, y2)

        fill_path = QPainterPath(curve_path)
        last_x, _, _ = self.slider_positions[-1]
        fill_path.lineTo(last_x, self.baseline_y)
        fill_path.lineTo(self.slider_positions[0][0], self.baseline_y)
        fill_path.closeSubpath()

        heat = self._heat_color(self.peak_gain)
        top = QColor(heat)
        top.setAlpha(90)
        bottom = QColor(heat)
        bottom.setAlpha(10)
        gradient = QLinearGradient(0, self.rect().top(), 0, self.baseline_y)
        gradient.setColorAt(0.0, top)
        gradient.setColorAt(1.0, bottom)

        painter.setPen(Qt.NoPen)
        painter.setBrush(gradient)
        painter.drawPath(fill_path)

        line_color = QColor(heat)
        line_color.setAlpha(180)
        pen = QPen(line_color, 2, Qt.SolidLine)
        painter.setPen(pen)
        painter.setBrush(Qt.NoBrush)
        painter.drawPath(curve_path)


# ---------------------------------------------------------------------------
# MODERN RING KNOB
# ---------------------------------------------------------------------------
class ToneKnob(QDial):
    def __init__(self, min_val, max_val, default_val, parent=None):
        super().__init__(parent)
        self.setRange(min_val, max_val)
        self.setValue(default_val)
        self.setNotchesVisible(False)
        self.setCursor(Qt.PointingHandCursor)
        self.setFocusPolicy(Qt.WheelFocus)
        self.setWrapping(False)
        self.setSingleStep(1)
        self.setPageStep(5)
        self.setFixedSize(120, 120)
        self.setMouseTracking(True)
        self._drag_active = False
        self._drag_last_pos = None
        self._drag_value = float(default_val)
        self._wheel_accum = 0.0
        self.valueChanged.connect(self._on_value_changed)
        self._display_value = float(default_val)
        self._target_value = float(default_val)
        self._anim_timer = QTimer(self)
        self._anim_timer.setInterval(16)
        self._anim_timer.timeout.connect(self._tick_display)
        self.heat_min_value = min_val
        self.heat_warn_value = max_val
        self.heat_max_value = max_val
        self.use_heat_map = True
        self.alert_active = False

    def set_heat_map(self, min_value, warn_value, max_value):
        self.heat_min_value = min_value
        self.heat_warn_value = warn_value
        self.heat_max_value = max_value
        self.use_heat_map = True

    def disable_heat_map(self):
        self.use_heat_map = False
        self.update()

    def set_alert(self, active):
        self.alert_active = bool(active)
        self.update()

    def _tick_display(self):
        delta = self._target_value - self._display_value
        if abs(delta) < 0.1:
            self._display_value = self._target_value
            self._anim_timer.stop()
            self.update()
            return
        self._display_value += delta * 0.25
        self.update()

    def _on_value_changed(self, value):
        if self._drag_active:
            self._display_value = float(value)
            self._target_value = float(value)
            if self._anim_timer.isActive():
                self._anim_timer.stop()
            self.update()
            return
        self._target_value = float(value)
        if not self._anim_timer.isActive():
            self._anim_timer.start()

    def sync_display(self, value):
        self._display_value = float(value)
        self._target_value = float(value)
        if self._anim_timer.isActive():
            self._anim_timer.stop()
        self.update()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._drag_active = True
            self._drag_last_pos = event.pos()
            self._drag_value = float(self.value())
            self._wheel_accum = 0.0
            self.setFocus(Qt.MouseFocusReason)
            self.grabMouse()
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if not self._drag_active or self._drag_last_pos is None:
            super().mouseMoveEvent(event)
            return

        delta = self._drag_last_pos.y() - event.pos().y()
        delta += (event.pos().x() - self._drag_last_pos.x()) * 0.35

        span = max(1.0, float(self.maximum() - self.minimum()))
        sensitivity = (span / 240.0) * 5.0
        if event.modifiers() & Qt.ShiftModifier:
            sensitivity *= 0.25

        self._drag_value += delta * sensitivity
        new_value = int(round(self._drag_value))
        new_value = max(self.minimum(), min(self.maximum(), new_value))
        if new_value != self.value():
            self.setValue(new_value)

        self._drag_last_pos = event.pos()
        event.accept()

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._drag_active = False
            self._drag_last_pos = None
            self.releaseMouse()
            event.accept()
            return
        super().mouseReleaseEvent(event)

    def wheelEvent(self, event):
        delta = event.angleDelta().y()
        if delta == 0:
            delta = event.pixelDelta().y()
            if delta == 0:
                event.ignore()
                return

        # Kullanıcı İsteği #3: 10 kademeli ses yükseltme
        # Standart mouse wheel delta = 120
        # Her tıkta 10 birim artış/azalış istiyoruz.
        
        steps = 0
        if delta > 0:
            steps = 10
        else:
            steps = -10
            
        if event.modifiers() & Qt.ShiftModifier:
            steps = int(steps * 0.25) # Shift ile hassas ayar

        target = self.value() + steps
        target = max(self.minimum(), min(self.maximum(), target))
        
        if target != self.value():
            self.setValue(target)

        event.accept()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        rect = self.rect().adjusted(6, 6, -6, -6)
        c = rect.center()
        radius = min(rect.width(), rect.height()) / 2.0

        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor("#2a2a2a"))
        painter.drawEllipse(c, radius, radius)

        inner_radius = radius - 16
        painter.setBrush(QColor("#1f1f1f"))
        painter.drawEllipse(c, inner_radius, inner_radius)

        start_angle = 225 * 16
        total_span = -270 * 16
        ring_rect = QRectF(
            c.x() - radius + 5,
            c.y() - radius + 5,
            (radius - 5) * 2,
            (radius - 5) * 2
        )

        pen_base = QPen(QColor("#3a3a3a"), 8, Qt.SolidLine, Qt.RoundCap)
        painter.setPen(pen_base)
        painter.drawArc(ring_rect, start_angle, total_span)

        span = self.maximum() - self.minimum()
        val_norm = 0.0 if span == 0 else (self._display_value - self.minimum()) / span
        active_span = int(total_span * val_norm)
        pen_active = QPen(self._heat_color(self._display_value), 8, Qt.SolidLine, Qt.RoundCap)
        painter.setPen(pen_active)
        painter.drawArc(ring_rect, start_angle, active_span)

        # End-dot on ring
        angle_deg = 225.0 + (-270.0 * val_norm)
        angle_rad = math.radians(angle_deg)
        dot_r = radius - 5
        dot_x = c.x() + dot_r * math.cos(angle_rad)
        dot_y = c.y() - dot_r * math.sin(angle_rad)
        painter.setBrush(self._heat_color(self._display_value))
        painter.drawEllipse(QPointF(dot_x, dot_y), 4.2, 4.2)

        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor("#5a5a5a"))
        painter.drawEllipse(c, 6, 6)

    def _heat_color(self, value):
        if self.alert_active:
            return QColor(255, 70, 70)
        if not self.use_heat_map:
            return QColor(76, 255, 90)

        cold = QColor(200, 230, 255)
        green = QColor(70, 220, 110)
        red = QColor(255, 70, 70)

        if value <= self.heat_min_value:
            return cold
        if value < self.heat_warn_value:
            return self._blend_color(cold, green, (value - self.heat_min_value) / max(1.0, (self.heat_warn_value - self.heat_min_value)))
        t = (value - self.heat_warn_value) / max(1.0, (self.heat_max_value - self.heat_warn_value))
        return self._blend_color(green, red, min(t, 1.0))

    def _blend_color(self, c1, c2, t):
        t = max(0.0, min(1.0, t))
        r = int(c1.red() + (c2.red() - c1.red()) * t)
        g = int(c1.green() + (c2.green() - c1.green()) * t)
        b = int(c1.blue() + (c2.blue() - c1.blue()) * t)
        return QColor(r, g, b)


class ToneKnobWidget(QWidget):
    def __init__(self, title, min_val, max_val, default_val, suffix, callback, parent=None):
        super().__init__(parent)
        self.suffix = suffix
        self.callback = callback
        self.setStyleSheet("background: transparent; border: none;")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        self.title_label = QLabel(title)
        self.title_label.setAlignment(Qt.AlignCenter)
        self.title_label.setStyleSheet("color: #cfcfcf; font-size: 10px;")

        self.knob = ToneKnob(min_val, max_val, default_val)
        if self.suffix == "dB":
            self.knob.setSingleStep(5)
            self.knob.set_heat_map(-150.0, 0.0, 150.0)
        elif self.suffix == "%":
            self.knob.setSingleStep(2)
            self.knob.set_heat_map(0.0, 100.0, 200.0)
        self.knob.valueChanged.connect(self._on_value)

        self.value_label = QLabel("")
        self.value_label.setAlignment(Qt.AlignCenter)
        self.value_label.setStyleSheet("color: #9a9a9a; font-size: 9px;")

        layout.addWidget(self.title_label)
        layout.addWidget(self.knob, alignment=Qt.AlignHCenter)
        layout.addWidget(self.value_label)

        self._update_label(self.knob.value())

    def _format_value(self, value):
        if self.suffix == "dB":
            return f"{value / 10.0:+.1f} dB"
        if self.suffix == "%":
            return f"{value:.0f} %"
        return f"{value}{self.suffix}"

    def _update_label(self, value):
        self.value_label.setText(self._format_value(value))

    def _on_value(self, value):
        self._update_label(value)
        if self.callback:
            if self.suffix == "dB":
                self.callback(value / 10.0)
            elif self.suffix == "%":
                self.callback(value / 100.0)
            else:
                self.callback(value)

    def set_value(self, value):
        self.knob.blockSignals(True)
        self.knob.setValue(value)
        self.knob.blockSignals(False)
        self.knob.sync_display(value)
        self._update_label(value)

    def set_alert(self, active):
        self.knob.set_alert(active)

# ---------------------------------------------------------------------------
# EQUALIZER WINDOW (FULL PROFESSIONAL PANEL)
# ---------------------------------------------------------------------------
class PopupEqualizerWidget(QDialog):
    eq_changed_signal = pyqtSignal(list)

    def __init__(self, parent=None, manager: AudioManager = None):
        super().__init__(parent)
        self.mgr = manager
        self.setWindowTitle("Ses Efektleri")
        self.setWindowFlags(Qt.Window) # Independent window
        self.resize(1120, 620)
        
        self._updating_from_manager = False # Flag for remote sync
        
        # Connect to manager
        if self.mgr:
            self.mgr.state_changed.connect(self.sync_from_manager)
        
        # Easy Effects inspired dark UI
        self.setStyleSheet("""
            QDialog { background-color: #1c1c1c; }
            QLabel { color: #d6d6d6; font-family: 'Segoe UI', Arial; }
            QFrame { color: #2c2c2c; }
            /* 32-Band Sliders styling */
            QSlider::groove:vertical {
                background: #3a3a3a;
                width: 2px;
                border-radius: 2px;
            }
            QSlider::sub-page:vertical {
                background: transparent;
            }
            QSlider::add-page:vertical {
                background: transparent;
            }
            QSlider::handle:vertical {
                background: #35c6ff;
                border: 1px solid rgba(53, 198, 255, 0.9);
                height: 7px;
                width: 7px;
                margin: -3px -3px;
                border-radius: 4px;
            }
            QSlider::handle:vertical:hover {
                background: #eaeaea;
                border: 1px solid #35c6ff;
            }
        """)
        
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(14)
        
        # --- TOP BAR ---
        topbar_layout = QHBoxLayout()
        topbar_layout.setSpacing(10)

        btn_effects = QPushButton("Efektler")
        btn_effects.setCheckable(True)
        btn_effects.setChecked(True)
        btn_effects.setCursor(Qt.PointingHandCursor)
        btn_effects.setStyleSheet("""
            QPushButton {
                background-color: #2b2b2b;
                color: #ff8f00;
                border: 1px solid #3a3a3a;
                border-radius: 4px;
                padding: 4px 10px;
                font-weight: bold;
                font-size: 10px;
            }
            QPushButton:checked {
                background-color: #2b2b2b;
                color: #ff8f00;
            }
        """)

        btn_presets = QPushButton("Ön Ayarlar")
        btn_presets.setCursor(Qt.PointingHandCursor)
        btn_presets.setStyleSheet("""
            QPushButton {
                background-color: #242424;
                color: #bdbdbd;
                border: 1px solid #333;
                border-radius: 4px;
                padding: 4px 10px;
                font-size: 10px;
            }
            QPushButton:hover { color: #fff; }
        """)

        self.effects_checkbox = QCheckBox("Ses Efektlerini Etkinleştir")
        self.effects_checkbox.setChecked(True)
        self.effects_checkbox.setCursor(Qt.PointingHandCursor)
        self.effects_checkbox.setStyleSheet("QCheckBox { color: #d6d6d6; font-size: 10px; }")
        self.effects_checkbox.stateChanged.connect(self.toggle_dsp_enabled)

        title = QLabel("Ses Efektleri")
        title.setStyleSheet("color: #cfcfcf; font-size: 12px; font-weight: bold;")

        topbar_left = QHBoxLayout()
        topbar_left.setSpacing(8)
        topbar_left.addWidget(btn_effects)
        topbar_left.addWidget(btn_presets)
        topbar_left.addWidget(self.effects_checkbox)

        topbar_layout.addLayout(topbar_left)
        topbar_layout.addStretch()
        topbar_layout.addWidget(title)
        topbar_layout.addStretch()

        main_layout.addLayout(topbar_layout)

        content_layout = QHBoxLayout()
        content_layout.setSpacing(12)

        sidebar = QWidget()
        sidebar.setFixedWidth(190)
        sidebar.setStyleSheet("background-color: #1f1f1f; border: 1px solid #2a2a2a; border-radius: 8px;")
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(10, 10, 10, 10)
        sidebar_layout.setSpacing(10)

        plugins_label = QLabel("Eklentiler")
        plugins_label.setStyleSheet("color: #bdbdbd; font-size: 10px; font-weight: bold;")
        sidebar_layout.addWidget(plugins_label)

        self.effects_list = QListWidget()
        self.effects_list.addItem("Ekolayzır")
        self.effects_list.setCurrentRow(0)
        self.effects_list.setStyleSheet("""
            QListWidget {
                background: #1f1f1f;
                border: 1px solid #2a2a2a;
                color: #cfcfcf;
                font-size: 10px;
            }
            QListWidget::item {
                padding: 6px 8px;
            }
            QListWidget::item:selected {
                background: #2a2a2a;
                color: #fff;
                border-left: 2px solid #ff8f00;
            }
        """)
        sidebar_layout.addWidget(self.effects_list)
        sidebar_layout.addStretch()

        content_layout.addWidget(sidebar)

        self.effects_stack = QStackedWidget()
        self.effects_list.currentRowChanged.connect(self.effects_stack.setCurrentIndex)
        content_layout.addWidget(self.effects_stack, 1)

        main_layout.addLayout(content_layout, stretch=1)

        eq_page = QWidget()
        eq_page_layout = QVBoxLayout(eq_page)
        eq_page_layout.setContentsMargins(0, 0, 0, 0)
        eq_page_layout.setSpacing(12)
        
        # --- 32-BAND EQ ---
        eq_container = QWidget()
        eq_container.setStyleSheet("background-color: transparent; border: none;")
        eq_container_layout = QVBoxLayout(eq_container)
        eq_container_layout.setContentsMargins(10, 10, 10, 10)
        eq_container_layout.setSpacing(6)

        eq_header = QHBoxLayout()
        eq_title = QLabel("32-Bandlı Profesyonel Ekolayzır")
        eq_title.setStyleSheet("color: #d8d8d8; font-size: 11px; font-weight: bold;")
        eq_reset_btn = QPushButton("Sıfırla")
        eq_reset_btn.setCursor(Qt.PointingHandCursor)
        eq_reset_btn.setStyleSheet("""
            QPushButton { background-color: #2b2b2b; color: #bbb; border: 1px solid #3a3a3a; border-radius: 4px; padding: 4px 10px; }
            QPushButton:hover { background-color: #3a3a3a; color: #fff; }
        """)
        eq_reset_btn.clicked.connect(self.reset_eq)
        eq_header.addWidget(eq_title)
        eq_header.addStretch()
        eq_header.addWidget(eq_reset_btn)
        eq_container_layout.addLayout(eq_header)
        
        # EQ sliders
        eq_widget = QWidget()
        eq_widget.setStyleSheet("background: transparent;")
        eq_layout = QHBoxLayout(eq_widget)
        eq_layout.setSpacing(5)
        eq_layout.setContentsMargins(8, 8, 8, 6)
        
        self.sliders = []
        self.frequencies = list(EQ_BAND_LABELS)
        
        for i, freq in enumerate(self.frequencies):
            v_box = QVBoxLayout()
            v_box.setSpacing(3)
            
            slider = QSlider(Qt.Vertical)
            slider.setRange(-150, 150)
            slider.setValue(0)
            slider.setMinimumHeight(180)  # Taller sliders
            slider.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)
            slider.valueChanged.connect(lambda val, idx=i: self._on_slider_change(idx, val))
            slider.sliderReleased.connect(self._trigger_reprocess)
            
            freq_lbl = QLabel(freq)
            freq_lbl.setAlignment(Qt.AlignCenter)
            freq_lbl.setStyleSheet("color: #666; font-size: 8px;")
            
            v_box.addWidget(slider, alignment=Qt.AlignHCenter)
            v_box.addWidget(freq_lbl, alignment=Qt.AlignHCenter)
            eq_layout.addLayout(v_box)
            self.sliders.append(slider)

        self.eq_curve = EQCurveWidget(eq_widget)
        self.eq_curve.setGeometry(eq_widget.rect())
        self.eq_curve.lower()

        eq_visual_container = QFrame()
        eq_visual_container.setStyleSheet(
            "background-color: transparent; border: none;"
        )
        eq_visual_layout = QVBoxLayout(eq_visual_container)
        eq_visual_layout.setContentsMargins(6, 6, 6, 6)
        eq_visual_layout.addWidget(eq_widget)

        eq_container_layout.addWidget(eq_visual_container)
        eq_page_layout.addWidget(eq_container, stretch=2)

        tone_container = QFrame()
        tone_container.setStyleSheet(
            "background-color: transparent; border: none;"
        )
        tone_layout = QVBoxLayout(tone_container)
        tone_layout.setContentsMargins(16, 12, 16, 12)
        tone_layout.setSpacing(10)

        tone_title = QLabel("Tone_Space (Poweramp Modülü)")
        tone_title.setStyleSheet("color: #bfe5c8; font-weight: bold; font-size: 10px;")
        tone_layout.addWidget(tone_title)

        knob_row = QHBoxLayout()
        knob_row.setSpacing(24)
        self.tone_bass_knob = ToneKnobWidget(
            "Bas (100 Hz)", -150, 150, 0, "dB",
            lambda v: self.update_tone(bass=v)
        )
        self.tone_mid_knob = ToneKnobWidget(
            "Mid (500 Hz - 2 kHz)", -150, 150, 0, "dB",
            lambda v: self.update_tone(mid=v)
        )
        self.tone_treble_knob = ToneKnobWidget(
            "Tiz (10 kHz)", -150, 150, 0, "dB",
            lambda v: self.update_tone(treble=v)
        )
        self.stereo_knob = ToneKnobWidget(
            "Stereo Expander", 0, 200, 100, "%",
            lambda v: self.update_stereo(v)
        )
        knob_row.addWidget(self.tone_bass_knob)
        knob_row.addWidget(self.tone_mid_knob)
        knob_row.addWidget(self.tone_treble_knob)
        knob_row.addWidget(self.stereo_knob)
        knob_row.addStretch()
        tone_layout.addLayout(knob_row)

        bottom_row = QHBoxLayout()
        bottom_row.setSpacing(8)
        acoustic_label = QLabel("Akustik Mekan:")
        acoustic_label.setStyleSheet("color: #cfcfcf; font-size: 10px;")
        self.acoustic_combo = QComboBox()
        self.acoustic_combo.addItems(["Kapalı", "Oda", "Stüdyo", "Konser", "Kilise"])
        self.acoustic_combo.setCursor(Qt.PointingHandCursor)
        self.acoustic_combo.setStyleSheet("""
            QComboBox {
                background-color: #1a1a1a;
                color: #d6d6d6;
                border: 1px solid #3a3a3a;
                border-radius: 4px;
                padding: 4px 8px;
                font-size: 9px;
            }
            QComboBox::drop-down { border: none; }
        """)
        self.acoustic_combo.currentIndexChanged.connect(self.update_acoustic_space)

        self.reset_tone_btn = QPushButton("Modülü Sıfırla")
        self.reset_tone_btn.setCursor(Qt.PointingHandCursor)
        self.reset_tone_btn.setStyleSheet("""
            QPushButton { background-color: #2b2b2b; color: #bbb; border: 1px solid #3a3a3a; border-radius: 4px; padding: 4px 10px; }
            QPushButton:hover { background-color: #3a3a3a; color: #fff; }
        """)
        self.reset_tone_btn.clicked.connect(self.reset_tone_space)

        bottom_row.addWidget(acoustic_label)
        bottom_row.addWidget(self.acoustic_combo)
        bottom_row.addStretch()
        self.master_toggle_btn = QPushButton("⏻")
        self.master_toggle_btn.setCheckable(True)
        self.master_toggle_btn.setFixedSize(30, 30)
        self.master_toggle_btn.setCursor(Qt.PointingHandCursor)
        self.master_toggle_btn.setStyleSheet("""
            QPushButton {
                background-color: #1a1a1a;
                color: #e6e6e6;
                border: 1px solid #d8d8d8;
                border-radius: 4px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:checked {
                background-color: #2b3b2f;
                color: #4cff5a;
                border: 1px solid #4cff5a;
            }
        """)
        self.master_toggle_btn.toggled.connect(self.update_master_toggle)

        bottom_row.addWidget(self.reset_tone_btn)
        bottom_row.addWidget(self.master_toggle_btn)
        tone_layout.addLayout(bottom_row)

        eq_page_layout.addWidget(tone_container, stretch=1)
        
        # Footer
        footer = QLabel("Angolla DSP Engine v2.0 • 48kHz / 32-bit Float Processing")
        footer.setAlignment(Qt.AlignRight)
        footer.setStyleSheet("color: #444; font-size: 9px; margin-top: 10px;")
        eq_page_layout.addWidget(footer)

        self.effects_stack.addWidget(eq_page)
        
        # Load saved settings
        self.load_settings()

    def _on_slider_change(self, index, value):
        # 0. Sync with Manager
        gain = value / 10.0
        
        if self.mgr and not self._updating_from_manager:
            self.mgr.update_band(index, gain)
            self._update_eq_curve()

    def update_tone(self, bass=None, mid=None, treble=None):
        if not self.mgr:
            return
        b = bass if bass is not None else self.mgr.tone_bass
        m = mid if mid is not None else self.mgr.tone_mid
        t = treble if treble is not None else self.mgr.tone_treble
        self.mgr.update_tone(b, m, t)
        self._update_bass_alert()
        self._update_eq_curve()

    def update_stereo(self, width):
        if self.mgr:
            self.mgr.update_stereo(width)

    def update_acoustic_space(self, index):
        if self.mgr:
            self.mgr.update_acoustic_space(index)

    def update_master_toggle(self, enabled):
        if self.mgr:
            self.mgr.update_master_toggle(enabled)
            self._update_bass_alert()
            self._update_eq_curve()

    def reset_tone_space(self):
        if self.mgr:
            self.mgr.reset_tone_space()
            self._update_bass_alert()

    def _update_eq_curve(self):
        if not hasattr(self, "eq_curve"):
            return
        if not self.mgr:
            return
        self.eq_curve.show()

        positions = []
        peak_gain = -999.0
        if len(self.sliders) > 0:
            first_slider = self.sliders[0]
            baseline_y = first_slider.geometry().top() + first_slider.height() // 2
        else:
            baseline_y = 0
        tone_scale = 1.0 if self.mgr.smart_audio_enabled else 0.0

        for i, slider in enumerate(self.sliders):
            freq = EQ_BAND_FREQS[i]
            log_f = math.log10(freq)

            gain = slider.value() / 10.0
            if tone_scale > 0.0:
                bass_dist = log_f - 2.0
                gain += self.mgr.tone_bass * tone_scale * math.exp(-0.5 * (bass_dist / 0.45) ** 2)

                mid_dist = log_f - 3.0
                gain += self.mgr.tone_mid * tone_scale * math.exp(-0.5 * (mid_dist / 0.55) ** 2)

                treble_dist = log_f - 4.0
                gain += self.mgr.tone_treble * tone_scale * math.exp(-0.5 * (treble_dist / 0.45) ** 2)

            slider_center_x = slider.geometry().center().x()
            slider_height = slider.height()
            val_norm = (gain * 10.0 + 150.0) / 300.0
            val_norm = max(0.0, min(1.0, val_norm))
            slider_y = slider.geometry().top() + slider_height * (1 - val_norm)
            if gain > peak_gain:
                peak_gain = gain
            positions.append((slider_center_x, slider_y, gain))

        if peak_gain < -900.0:
            peak_gain = 0.0
        self.eq_curve.set_slider_positions(positions, baseline_y, peak_gain=peak_gain)
        self.eq_curve.setGeometry(self.eq_curve.parent().rect())
        
    def _update_bass_alert(self):
        if not self.mgr:
            return
        if not hasattr(self, "tone_bass_knob"):
            return
        alert_active = self.mgr.smart_audio_enabled and self.mgr.tone_bass >= 10.0
        self.tone_bass_knob.set_alert(alert_active)

    
    def _trigger_reprocess(self):
        """Trigger reprocessing of audio from parent"""
        if hasattr(self.parent(), 'process_current_track_offline'):
             # Debounce: wait 200ms
             QTimer.singleShot(200, self.parent().process_current_track_offline)
    
    def sync_from_manager(self):
        """Manager informs us a state changed elsewhere (or initial load)"""
        if not self.mgr: return
        self._updating_from_manager = True
        
        # Sync Effects Toggle
        self.effects_checkbox.blockSignals(True)
        self.effects_checkbox.setChecked(self.mgr.dsp_enabled)
        self.effects_checkbox.blockSignals(False)
        
        # Sync Sliders
        for i, gain in enumerate(self.mgr.eq_bands):
            val = int(gain * 10.0)
            self.sliders[i].blockSignals(True)
            self.sliders[i].setValue(val)
            self.sliders[i].blockSignals(False)

        self.tone_bass_knob.set_value(int(self.mgr.tone_bass * 10.0))
        self.tone_mid_knob.set_value(int(self.mgr.tone_mid * 10.0))
        self.tone_treble_knob.set_value(int(self.mgr.tone_treble * 10.0))
        self.stereo_knob.set_value(int(self.mgr.stereo_width * 100.0))

        self.acoustic_combo.blockSignals(True)
        self.acoustic_combo.setCurrentIndex(self.mgr.acoustic_space)
        self.acoustic_combo.blockSignals(False)

        self.master_toggle_btn.blockSignals(True)
        self.master_toggle_btn.setChecked(self.mgr.smart_audio_enabled)
        self.master_toggle_btn.blockSignals(False)

        knobs_enabled = self.mgr.smart_audio_enabled
        self.tone_bass_knob.setEnabled(knobs_enabled)
        self.tone_mid_knob.setEnabled(knobs_enabled)
        self.tone_treble_knob.setEnabled(knobs_enabled)
        self.stereo_knob.setEnabled(knobs_enabled)
        self.acoustic_combo.setEnabled(knobs_enabled)
        self.reset_tone_btn.setEnabled(knobs_enabled)

        self._update_bass_alert()
        self._update_eq_curve()
        self._updating_from_manager = False
    
    def toggle_dsp_enabled(self):
        """Toggle master DSP on/off"""
        if self.mgr:
            self.mgr.dsp_enabled = self.effects_checkbox.isChecked()
            self.mgr.state_changed.emit()
            
        # UI update will follow via state_changed -> sync_from_manager

    def reset_eq(self):
        """Reset EQ to flat."""
        if self.mgr:
            self.mgr.reset_eq()
            print("✓ EQ Sıfırlandı")

    def save_settings(self):
        """Handled by AudioManager automatically"""
        if self.mgr:
            self.mgr.save_state()

    def load_settings(self):
        """Handled by AudioManager automatically. Just initial sync."""
        self.sync_from_manager()
        self._update_eq_curve()

    def closeEvent(self, event):
        self.save_settings()
        super().closeEvent(event)
    
    def showEvent(self, event):
        # Optional: Reload or ensure sync on show? 
        # Usually load once is enough, but auto-sync is handled by valueChanged
        self._update_eq_curve()
        super().showEvent(event)


try:
    from PyQt5.QtWebEngineCore import QWebEngineSettings
except Exception:
    pass

try:
    from PyQt5.QtWebEngineCore import QWebEngineScript
except Exception:
    try:
        from PyQt5.QtWebEngineWidgets import QWebEngineScript
    except Exception:
        QWebEngineScript = None

# YENİ: Pencerenin devasa boyutlara ulaşmasını engelleyen özel Web Görünümü
if QWebEngineView:
    class ConstrainedWebEngineView(QWebEngineView):
        """
        Web içeriğinin ana pencereyi zorla büyütmesini engelleyen özel QWebEngineView.
        sizeHint() metodunu geçersiz kılarak boyut kontrolünü layout'a bırakır.
        """
        def sizeHint(self):
            # Geçersiz bir boyut döndürerek, web görünümünün kendi içeriğine göre
            # pencere boyutunu dikte etmesini engelliyoruz.
            return QSize(100, 100)
            
        def minimumSizeHint(self):
            return QSize(0, 0)
else:
    ConstrainedWebEngineView = None

# ProjectM entegrasyonu
try:
    from projectm_visualizer import ProjectMVisualizer
    HAS_PROJECTM = True
    print("✓ ProjectM visualizer yüklendi")
except ImportError as e:
    HAS_PROJECTM = False
    print(f"⚠ ProjectM yüklenemedi: {e}")


class SettingsManager:
    """JSON tabanlı ayar kalıcılığı"""
    def __init__(self, path=os.path.join(os.path.dirname(__file__), 'angolla_settings.json')):
        self.path = path
        self.data = {
            'trusted_domains': list(TRUSTED_DOMAINS),
            'bridge_allowed_sites': list(BRIDGE_ALLOWED_SITES),
        }
        self.load()
    def load(self):
        try:
            if os.path.exists(self.path):
                with open(self.path, 'r', encoding='utf-8') as f:
                    obj = json.load(f)
                    if isinstance(obj, dict):
                        self.data.update(obj)
        except Exception as e:
            print(f"Ayar yükleme hatası: {e}")
    def save(self):
        try:
            with open(self.path, 'w', encoding='utf-8') as f:
                json.dump(self.data, f, ensure_ascii=False, indent=2)
            print("✓ Ayarlar kaydedildi (JSON)")
        except Exception as e:
            print(f"Ayar kaydetme hatası: {e}")
    def get_trusted_domains(self):
        return set(self.data.get('trusted_domains', []))
    def get_bridge_allowed_sites(self):
        return set(self.data.get('bridge_allowed_sites', []))
    def set_trusted_domains(self, domains):
        self.data['trusted_domains'] = sorted(set(domains))
    def set_bridge_allowed_sites(self, sites):
        self.data['bridge_allowed_sites'] = sorted(set(sites))

class SettingsDialog(QDialog):
    def __init__(self, manager: SettingsManager, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Angolla\nGuvenlik Ayarları")
        self.resize(480, 650)  # Standart pencere boyutu
        self.manager = manager
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Güvenilir Domainler"))
        self.domains_list = QListWidget()
        for d in sorted(self.manager.get_trusted_domains()):
            self.domains_list.addItem(d)
        layout.addWidget(self.domains_list)
        self.domains_edit = QLineEdit()
        self.domains_edit.setPlaceholderText("domain ekle (ör. localhost)")
        layout.addWidget(self.domains_edit)
        btn_add_domain = QPushButton("Ekle")
        btn_del_domain = QPushButton("Sil")
        h1 = QHBoxLayout()
        h1.addWidget(btn_add_domain)
        h1.addWidget(btn_del_domain)
        layout.addLayout(h1)
        layout.addWidget(QLabel("Köprü İzinli Siteler"))
        self.sites_list = QListWidget()
        for s in sorted(self.manager.get_bridge_allowed_sites()):
            self.sites_list.addItem(s)
        layout.addWidget(self.sites_list)
        self.sites_edit = QLineEdit()
        self.sites_edit.setPlaceholderText("site ekle (ör. youtube)")
        layout.addWidget(self.sites_edit)
        btn_add_site = QPushButton("Ekle")
        btn_del_site = QPushButton("Sil")
        h2 = QHBoxLayout()
        h2.addWidget(btn_add_site)
        h2.addWidget(btn_del_site)
        layout.addLayout(h2)
        btns = QHBoxLayout()
        btn_ok = QPushButton("Kaydet")
        btn_cancel = QPushButton("İptal")
        btns.addWidget(btn_ok)
        btns.addWidget(btn_cancel)
        layout.addLayout(btns)
        btn_add_domain.clicked.connect(self._add_domain)
        btn_del_domain.clicked.connect(self._del_domain)
        btn_add_site.clicked.connect(self._add_site)
        btn_del_site.clicked.connect(self._del_site)
        btn_ok.clicked.connect(self._save)
        btn_cancel.clicked.connect(self.reject)
    def _add_domain(self):
        text = self.domains_edit.text().strip().lower()
        if text:
            self.domains_list.addItem(text)
            self.domains_edit.clear()
    def _del_domain(self):
        for item in self.domains_list.selectedItems():
            self.domains_list.takeItem(self.domains_list.row(item))
    def _add_site(self):
        text = self.sites_edit.text().strip().lower()
        if text:
            self.sites_list.addItem(text)
            self.sites_edit.clear()
    def _del_site(self):
        for item in self.sites_list.selectedItems():
            self.sites_list.takeItem(self.sites_list.row(item))
    def _save(self):
        domains = [self.domains_list.item(i).text() for i in range(self.domains_list.count())]
        sites = [self.sites_list.item(i).text() for i in range(self.sites_list.count())]
        self.manager.set_trusted_domains(domains)
        self.manager.set_bridge_allowed_sites(sites)
        self.manager.save()
        self.accept()

class DownloadProgressDialog(QDialog):
    """Modal ilerleme/log penceresi: worker'dan gelen satırları gösterir ve iptal eder."""
    def __init__(self, worker, parent=None):
        super().__init__(parent)
        self.worker = worker
        self.setWindowTitle("İndirme - İlerleme")
        self.setModal(True)  # Modal penceresi
        self.resize(640, 320)

        layout = QVBoxLayout(self)
        self.log = QPlainTextEdit(self)
        self.log.setReadOnly(True)
        layout.addWidget(self.log)

        h = QHBoxLayout()
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setRange(0, 0)  # belirsiz ilerleme
        h.addWidget(self.progress_bar)
        self.cancel_btn = QPushButton("İptal", self)
        h.addWidget(self.cancel_btn)
        layout.addLayout(h)

        # Bağlantılar
        self.worker.progress_sig.connect(self._append_line)
        self.worker.finished_sig.connect(self._on_finished)
        self.cancel_btn.clicked.connect(self._on_cancel)

    def _append_line(self, line: str):
        try:
            self.log.appendPlainText(line)
        except Exception:
            pass

    def _on_finished(self, success: bool, message: str):
        """İndirme tamamlandığında dialogu kapat."""
        try:
            if success:
                self.log.appendPlainText(f"\n✓ {message}")
            else:
                self.log.appendPlainText(f"\n✗ {message}")
            # Dialog'u kapat
            self.accept()
        except Exception:
            pass

    def _on_cancel(self):
        self.cancel_btn.setEnabled(False)
        try:
            self.worker.terminate_download()
        except Exception:
            pass

# ---------------------------------------------------------------------------
# GÖMÜLÜ WEB TABANI GÜVENLİK KÖPRÜSÜ (BRIDGE)
# ---------------------------------------------------------------------------
class BridgeSecurityController(QObject):
    """QWebChannel üzerinden güvenli, sınırlı API sağlar."""
    
    # Sinyaller
    ad_skip_requested = pyqtSignal(str)
    web_audio_data = pyqtSignal(list)  # Web sesini visualizer'a gönder
    web_playback_state = pyqtSignal(bool, bool, bool, bool, int)  # paused, ended, loading, ad_active, video_count
    video_playing = pyqtSignal(bool)  # video/stream playing state
    web_audio_pcm = pyqtSignal(list, int, int)  # PCM float list, sample_rate, channels
    
    @pyqtSlot(list)
    def send_web_audio(self, audio_data: list):
        """Web platformlarından ses verisi alır."""
        if isinstance(audio_data, list) and len(audio_data) > 0:
            self.web_audio_data.emit(audio_data)

    @pyqtSlot(list, int, int)
    def send_web_audio_pcm(self, samples: list, sample_rate: int, channels: int):
        if isinstance(samples, list) and len(samples) > 0:
            self.web_audio_pcm.emit(samples, int(sample_rate), int(channels))

    @pyqtSlot(bool, bool, bool, bool, int)
    def report_playback_state(self, paused: bool, ended: bool, loading: bool, ad_active: bool, video_count: int = 0):
        """Web oynatma durumunu UI tarafına iletir."""
        self.web_playback_state.emit(bool(paused), bool(ended), bool(loading), bool(ad_active), int(video_count))

    @pyqtSlot(bool)
    def report_video_playing(self, playing: bool):
        """Video oynuyor mu? (mutation/loopback sinyali)."""
        self.video_playing.emit(bool(playing))

    @pyqtSlot(bool)
    def on_youtube_play(self, playing: bool):
        """YouTube play/pause olayını UI tarafına iletir."""
        self.video_playing.emit(bool(playing))
    
    @pyqtSlot(str)
    def skip_ad_safe(self, site_name: str):
        """Güvenli reklam geçiş isteği."""
        allowed = set(BRIDGE_ALLOWED_SITES)
        if not isinstance(site_name, str):
            return
        site = site_name.strip().lower()
        if site not in allowed:
            # Katı doğrulama: sadece izinli siteler
            return
        # Güvenli işlem: dahili mantık tetiklenebilir
        print(f"✓ Güvenli skip_ad tetiklendi: {site}")
        self.ad_skip_requested.emit(site)
    
    @pyqtSlot(str, int)
    def seek_safe(self, site_name: str, seconds: int):
        """Güvenli seek işlemi (0-120 saniye)."""
        allowed = set(BRIDGE_ALLOWED_SITES)
        if not isinstance(site_name, str):
            return
        site = site_name.strip().lower()
        if site not in allowed or not isinstance(seconds, int) or seconds < 0 or seconds > 120:
            return
        print(f"✓ Seek tetiklendi: {site} -> {seconds}s")
    
    @pyqtSlot(str, bool)
    def toggle_play_safe(self, site_name: str, should_play: bool):
        """Güvenli oynatma/durdurma."""
        allowed = set(BRIDGE_ALLOWED_SITES)
        if not isinstance(site_name, str):
            return
        site = site_name.strip().lower()
        if site not in allowed:
            return
        status = "oynatma" if should_play else "durdurma"
        print(f"✓ {status} tetiklendi: {site}")
    
    @pyqtSlot(str, int)
    def volume_safe(self, site_name: str, volume: int):
        """Güvenli ses kontrolü (0-100)."""
        allowed = set(BRIDGE_ALLOWED_SITES)
        if not isinstance(site_name, str):
            return
        site = site_name.strip().lower()
        if site not in allowed or not isinstance(volume, int) or volume < 0 or volume > 100:
            return
        print(f"✓ Ses kontrol: {site} -> {volume}%")

# ---------------------------------------------------------------------------
# ÖZEL GÜVENLİ WEB SAYFASI
# ---------------------------------------------------------------------------
if QWebEnginePage is not None:
    class AngollaWebPage(QWebEnginePage):
        """QWebEnginePage üzerinde güvenlik kısıtlamaları uygular."""
        def __init__(self, profile, parent=None):
            super().__init__(profile, parent)
            s = self.settings()
            # Hassas ve riskli özellikleri kapat
            try:
                s.setAttribute(QWebEngineSettings.JavascriptEnabled, True)
                s.setAttribute(QWebEngineSettings.LocalStorageEnabled, True)
                s.setAttribute(QWebEngineSettings.XSSAuditingEnabled, True)
                # HTTP/mixed content gibi güvensiz içerikleri engelle
                s.setAttribute(QWebEngineSettings.AllowRunningInsecureContent, False)
                # Clipboard erişimi riskli; kapat
                s.setAttribute(QWebEngineSettings.JavascriptCanAccessClipboard, False)
                # Local (file/qrc) içeriklerin dosya/remote erişimini kapat
                if hasattr(QWebEngineSettings, "LocalContentCanAccessFileUrls"):
                    s.setAttribute(QWebEngineSettings.LocalContentCanAccessFileUrls, False)
                if hasattr(QWebEngineSettings, "LocalContentCanAccessRemoteUrls"):
                    s.setAttribute(QWebEngineSettings.LocalContentCanAccessRemoteUrls, False)
                # FIX: Enable Full Screen Support for YouTube player
                s.setAttribute(QWebEngineSettings.FullScreenSupportEnabled, True)
                s.setAttribute(QWebEngineSettings.WebGLEnabled, True)
                s.setAttribute(QWebEngineSettings.Accelerated2dCanvasEnabled, True)
                # Require explicit user gesture to block autoplay/hover previews
                s.setAttribute(QWebEngineSettings.PlaybackRequiresUserGesture, True)
            except Exception:
                pass

        def _show_blocked(self, reason: str):
            try:
                self.setHtml(_blocked_html(reason), QUrl("about:blank"))
            except Exception:
                pass

        def acceptNavigationRequest(self, url, nav_type, isMainFrame):
            """
            Web sekmesinde yalnızca allowlist domain + HTTPS/WSS kabul et.
            Yerel ağ/localhost/file erişimlerini engelle.
            """
            try:
                # Ana-frame data/blob navigasyonlarını (XSS vektörü) engelle
                try:
                    scheme = (url.scheme() or "").lower()
                    if isMainFrame and scheme in {"data", "blob"}:
                        self._show_blocked("Şüpheli içerik (data/blob) engellendi.")
                        print(f"⛔ GÜVENLİK: Web sekmesi data/blob engellendi: {_sanitize_url_for_log_qurl(url)}")
                        return False
                except Exception:
                    pass

                # URL üzerinde temel XSS filtresi (GET/link)
                try:
                    import urllib.parse
                    dec = urllib.parse.unquote_plus(url.toString())
                    if _looks_like_xss_payload(dec):
                        if isMainFrame:
                            self._show_blocked("Şüpheli içerik algılandı ve engellendi.")
                        print(f"⛔ GÜVENLİK: XSS şüpheli URL engellendi: {_sanitize_url_for_log_qurl(url)}")
                        return False
                except Exception:
                    pass

                if not _is_allowed_web_qurl(url):
                    safe_url = _sanitize_url_for_log_qurl(url)
                    if isMainFrame:
                        self._show_blocked("Bu adres güvenlik nedeniyle engellendi.")
                    print(f"⛔ GÜVENLİK: Web sekmesi URL engellendi: {safe_url}")
                    return False
            except Exception:
                pass
            return super().acceptNavigationRequest(url, nav_type, isMainFrame)

        def certificateError(self, error):
            """
            SSL/TLS Sertifika hatalarını yönetir.
            Güvenlik için geçersiz sertifikaları (süresi dolmuş, güvenilmez otorite vb.) reddeder.
            Bu, Man-in-the-Middle (Ortadaki Adam) saldırılarını engeller.
            """
            print(f"⛔ GÜVENLİK: Sertifika hatası reddedildi: {error.url().toString()} - Hata: {error.error()}")
            return False  # False = Sertifikayı reddet ve yüklemeyi durdur (En güvenli seçenek)

        def createWindow(self, _type):
            """
            Pop-up pencerelerini (örn. Google Login) yeni pencere yerine
            mevcut görünümde açar. Bu, kontrolsüz pencere boyutlanmasını engeller.
            """
            return self

        def javaScriptConsoleMessage(self, level, message, lineNumber, sourceID):
            return super().javaScriptConsoleMessage(level, message, lineNumber, sourceID)

        def featurePermissionRequested(self, securityOrigin, feature):
            # Güvenilir olmayan kaynaklardan gelen hassas izinleri reddet
            try:
                trusted_hosts = set(TRUSTED_DOMAINS)
                host = securityOrigin.host().lower()

                # Tam ekran isteğini tüm siteler için kabul et (YouTube uyarısını engellemek için)
                if feature == QWebEnginePage.FullScreen:
                    decision = QWebEnginePage.PermissionGrantedByUser
                # Diğer izinlerde sadece güvenilir hostlara izin ver
                elif host in trusted_hosts and feature not in (
                    QWebEnginePage.MediaAudioCapture,
                    QWebEnginePage.MediaVideoCapture,
                    QWebEnginePage.Geolocation,
                ):
                    decision = QWebEnginePage.PermissionGrantedByUser
                else:
                    decision = QWebEnginePage.PermissionDeniedByUser

                self.setFeaturePermission(securityOrigin, feature, decision)
            except Exception:
                pass

else:
    class AngollaWebPage(object):
        """WebEngine kullanılamadığında fallback sınıf."""
        def __init__(self, profile=None, parent=None):
            pass


# Basit çoklu dil sözlüğü (en, tr, es, fr, de, ar)
TRANSLATIONS = {
    "en": {
        "library": "Library",
        "files": "Files",
        "playlists": "Playlists",
        "internet": "Internet",
        "devices": "Devices",
        "song_info": "Song Info",
        "artist_info": "Artist Info",
        "shuffle_on": "Shuffle (On)",
        "shuffle_off": "Shuffle (Off)",
        "repeat_off": "Repeat (Off)",
        "repeat_list": "Repeat (List)",
        "repeat_one": "Repeat (One)",
        "save_playlist": "Save Playlist",
        "load_playlist": "Load Saved Playlist",
        "refresh_playlist": "Refresh Playlist",
        "open_folder": "Open Folder",
        "refresh_library": "Refresh Library",
        "volume": "Volume",
        "search": "Search...",
        "internet_header": "Internet",
        "back": "Back",
        "forward": "Forward",
        "lang": "Language",
        "share_success_title": "Share Successful",
        "share_success_body": "'{artist} - {title}' copied for sharing (simulation)!",
        "share_error_title": "Share Error",
        "share_error_body": "No track is playing.",
        "menu_file": "File",
        "menu_view": "View",
        "menu_tools": "Tools",
        "menu_help": "Help",
        "menu_add_files": "Add Files...",
        "menu_add_folder": "Add Folder...",
        "menu_exit": "Exit",
        "menu_open_visual": "Open Visualization Window",
        "menu_theme": "Theme",
        "menu_scan_library": "Scan Library",
        "menu_prefs": "Preferences",
        "menu_about": "About",
    },
    "tr": {
        "library": "Kütüphane",
        "files": "Dosyalar",
        "playlists": "Playlistler",
        "internet": "Internet",
        "devices": "Cihazlar",
        "song_info": "Şarkı Bilgisi",
        "artist_info": "Sanatçı Bilgisi",
        "shuffle_on": "Karıştır (On)",
        "shuffle_off": "Karıştır (Off)",
        "repeat_off": "Tekrar (Kapalı)",
        "repeat_list": "Tekrar (Liste)",
        "repeat_one": "Tekrar (Tek)",
        "save_playlist": "Çalma Listesini Kaydet",
        "load_playlist": "Kaydedilmiş Listeyi Yükle",
        "refresh_playlist": "Listeyi Yenile",
        "open_folder": "Klasörü Aç",
        "refresh_library": "Kütüphaneyi Güncelle",
        "volume": "Ses",
        "search": "Ara...",
        "internet_header": "Internet",
        "back": "Geri",
        "forward": "İleri",
        "lang": "Dil",
        "share_success_title": "Paylaşım Başarılı",
        "share_success_body": "'{artist} - {title}' paylaşım için kopyalandı (simülasyon)!",
        "share_error_title": "Paylaşım Hatası",
        "share_error_body": "Şu an oynatılan bir parça yok.",
        "menu_file": "Dosya",
        "menu_view": "Görünüm",
        "menu_tools": "Araçlar",
        "menu_help": "Yardım",
        "menu_add_files": "Dosya(lar) Ekle...",
        "menu_add_folder": "Klasör Ekle...",
        "menu_exit": "Çıkış",
        "menu_open_visual": "Görselleştirme Penceresini Aç",
        "menu_theme": "Tema",
        "menu_scan_library": "Kütüphaneyi Tara",
        "menu_prefs": "Tercihler",
        "menu_about": "Hakkında",
    },
    "es": {
        "library": "Biblioteca",
        "files": "Archivos",
        "playlists": "Listas",
        "internet": "Internet",
        "devices": "Dispositivos",
        "song_info": "Info de Canción",
        "artist_info": "Info de Artista",
        "shuffle_on": "Aleatorio (On)",
        "shuffle_off": "Aleatorio (Off)",
        "repeat_off": "Repetir (Off)",
        "repeat_list": "Repetir (Lista)",
        "repeat_one": "Repetir (Una)",
        "save_playlist": "Guardar Lista",
        "load_playlist": "Cargar Lista",
        "refresh_playlist": "Actualizar Lista",
        "open_folder": "Abrir Carpeta",
        "refresh_library": "Actualizar Biblioteca",
        "volume": "Volumen",
        "search": "Buscar...",
        "internet_header": "Internet",
        "back": "Atrás",
        "forward": "Adelante",
        "lang": "Idioma",
        "share_success_title": "Compartido",
        "share_success_body": "'{artist} - {title}' copiado para compartir (simulación)!",
        "share_error_title": "Error",
        "share_error_body": "No hay pista en reproducción.",
        "menu_file": "Archivo",
        "menu_view": "Vista",
        "menu_tools": "Herramientas",
        "menu_help": "Ayuda",
        "menu_add_files": "Agregar archivos...",
        "menu_add_folder": "Agregar carpeta...",
        "menu_exit": "Salir",
        "menu_open_visual": "Abrir ventana de visualización",
        "menu_theme": "Tema",
        "menu_scan_library": "Escanear biblioteca",
        "menu_prefs": "Preferencias",
        "menu_about": "Acerca de",
    },
    "fr": {
        "library": "Bibliothèque",
        "files": "Fichiers",
        "playlists": "Playlists",
        "internet": "Internet",
        "devices": "Appareils",
        "song_info": "Info Chanson",
        "artist_info": "Info Artiste",
        "shuffle_on": "Aléatoire (On)",
        "shuffle_off": "Aléatoire (Off)",
        "repeat_off": "Répéter (Off)",
        "repeat_list": "Répéter (Liste)",
        "repeat_one": "Répéter (Une)",
        "save_playlist": "Sauver Playlist",
        "load_playlist": "Charger Playlist",
        "refresh_playlist": "Rafraîchir Playlist",
        "open_folder": "Ouvrir Dossier",
        "refresh_library": "Rafraîchir Bibliothèque",
        "volume": "Volume",
        "search": "Rechercher...",
        "internet_header": "Internet",
        "back": "Précédent",
        "forward": "Suivant",
        "lang": "Langue",
        "share_success_title": "Partage Réussi",
        "share_success_body": "'{artist} - {title}' copié pour partage (simulation)!",
        "share_error_title": "Erreur de partage",
        "share_error_body": "Aucune piste en lecture.",
        "menu_file": "Fichier",
        "menu_view": "Affichage",
        "menu_tools": "Outils",
        "menu_help": "Aide",
        "menu_add_files": "Ajouter des fichiers...",
        "menu_add_folder": "Ajouter un dossier...",
        "menu_exit": "Quitter",
        "menu_open_visual": "Ouvrir la fenêtre de visualisation",
        "menu_theme": "Thème",
        "menu_scan_library": "Analyser la bibliothèque",
        "menu_prefs": "Préférences",
        "menu_about": "À propos",
    },
    "de": {
        "library": "Bibliothek",
        "files": "Dateien",
        "playlists": "Playlisten",
        "internet": "Internet",
        "devices": "Geräte",
        "song_info": "Song Info",
        "artist_info": "Künstler Info",
        "shuffle_on": "Zufall (An)",
        "shuffle_off": "Zufall (Aus)",
        "repeat_off": "Wiederholen (Aus)",
        "repeat_list": "Wiederholen (Liste)",
        "repeat_one": "Wiederholen (Einzeln)",
        "save_playlist": "Playlist Speichern",
        "load_playlist": "Playlist Laden",
        "refresh_playlist": "Playlist Aktualisieren",
        "open_folder": "Ordner Öffnen",
        "refresh_library": "Bibliothek Aktualisieren",
        "volume": "Lautstärke",
        "search": "Suchen...",
        "internet_header": "Internet",
        "back": "Zurück",
        "forward": "Vorwärts",
        "lang": "Sprache",
        "share_success_title": "Erfolg",
        "share_success_body": "'{artist} - {title}' zum Teilen kopiert (Simulation)!",
        "share_error_title": "Fehler",
        "share_error_body": "Keine Titel werden abgespielt.",
        "menu_file": "Datei",
        "menu_view": "Ansicht",
        "menu_tools": "Werkzeuge",
        "menu_help": "Hilfe",
        "menu_add_files": "Dateien hinzufügen...",
        "menu_add_folder": "Ordner hinzufügen...",
        "menu_exit": "Beenden",
        "menu_open_visual": "Visualisierungsfenster öffnen",
        "menu_theme": "Thema",
        "menu_scan_library": "Bibliothek scannen",
        "menu_prefs": "Einstellungen",
        "menu_about": "Über",
    },
    "ar": {
        "library": "المكتبة",
        "files": "الملفات",
        "playlists": "قوائم التشغيل",
        "internet": "إنترنت",
        "devices": "الأجهزة",
        "song_info": "معلومات الأغنية",
        "artist_info": "معلومات الفنان",
        "shuffle_on": "عشوائي (تشغيل)",
        "shuffle_off": "عشوائي (إيقاف)",
        "repeat_off": "تكرار (إيقاف)",
        "repeat_list": "تكرار (قائمة)",
        "repeat_one": "تكرار (واحدة)",
        "save_playlist": "حفظ القائمة",
        "load_playlist": "تحميل القائمة",
        "refresh_playlist": "تحديث القائمة",
        "open_folder": "فتح المجلد",
        "refresh_library": "تحديث المكتبة",
        "volume": "الصوت",
        "search": "بحث...",
        "internet_header": "إنترنت",
        "back": "رجوع",
        "forward": "تقدم",
        "lang": "اللغة",
        "share_success_title": "تمت المشاركة",
        "share_success_body": "تم نسخ '{artist} - {title}' للمشاركة (محاكاة)!",
        "share_error_title": "خطأ في المشاركة",
        "share_error_body": "لا يوجد أي مقطع يعمل الآن.",
        "menu_file": "ملف",
        "menu_view": "عرض",
        "menu_tools": "أدوات",
        "menu_help": "مساعدة",
        "menu_add_files": "إضافة ملفات...",
        "menu_add_folder": "إضافة مجلد...",
        "menu_exit": "خروج",
        "menu_open_visual": "فتح نافذة التصور",
        "menu_theme": "السمة",
        "menu_scan_library": "فحص المكتبة",
        "menu_prefs": "التفضيلات",
        "menu_about": "حول البرنامج",
    },
}

# Ek araçlar
import webbrowser
import urllib.parse
import urllib.request
from secure_storage import (
    atomic_write_json,
    load_json_file,
    migrate_pickle_config_to_json,
    migrate_pickle_playlist_to_json,
)
import collections
import threading

# İsteğe bağlı ek kütüphaneler (NumPy zaten en başta import edildi)

try:
    from mutagen import File as MutagenFile
    from mutagen.id3 import ID3
    from mutagen.mp4 import MP4
except Exception:
    MutagenFile = None
    ID3 = None
    MP4 = None
    print("Uyarı: Mutagen yüklenemedi. Etiket/kapak okuma sınırlı olacak.")

try:
    from PIL import Image  # type: ignore
    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False
    Image = None  # type: ignore
    print("Uyarı: Pillow bulunamadı. Kapak rengi çıkarma çalışmayacak.")

try:
    import sounddevice as sd  # type: ignore
    SD_AVAILABLE = True
except Exception:
    sd = None
    SD_AVAILABLE = False

# Sabitler
PLAYLIST_FILE = "angolla_playlist.json"
CONFIG_FILE = "angolla_config.json"
DB_FILE = "angolla_library.db"
SETTINGS_KEY = "AngollaPlayer/Settings"


# ---------------------------------------------------------------------------
# KÜTÜPHANE YÖNETİCİSİ
# ---------------------------------------------------------------------------

class LibraryManager:
    """SQLite üzerinde parça bilgilerini tutan basit kütüphane yöneticisi."""

    def __init__(self, db_file=DB_FILE):
        self.db_file = db_file
        self.conn = None
        self._connect_db()

    def _connect_db(self):
        self.conn = sqlite3.connect(self.db_file)
        self.cursor = self.conn.cursor()
        self._setup_db()

    def _setup_db(self):
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS tracks (
                id INTEGER PRIMARY KEY,
                path TEXT UNIQUE,
                title TEXT,
                artist TEXT,
                album TEXT,
                duration INTEGER,
                last_scanned REAL
            )
        """)
        self.conn.commit()

    def add_track(self, path: str, tags: Dict[str, Any]):
        if not self.conn:
            self._connect_db()
        try:
            self.cursor.execute("""
                INSERT OR REPLACE INTO tracks
                (path, title, artist, album, duration, last_scanned)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                path,
                tags.get("title", os.path.basename(path)),
                tags.get("artist", "Bilinmeyen Sanatçı"),
                tags.get("album", "Bilinmeyen Albüm"),
                tags.get("duration", 0),
                time.time()
            ))
            self.conn.commit()
        except Exception as e:
            print(f"Veritabanı hatası (add_track): {e}")

    def get_all_tracks(self):
        if not self.conn:
            self._connect_db()
        self.cursor.execute(
            "SELECT path, title, artist, album, duration "
            "FROM tracks ORDER BY artist, album, title"
        )
        return self.cursor.fetchall()

    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None


# ---------------------------------------------------------------------------
# KÜTÜPHANE TABLOSU
# ---------------------------------------------------------------------------

class LibraryTableWidget(QTableWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setColumnCount(4)
        self.setHorizontalHeaderLabels(["Başlık", "Sanatçı", "Albüm", "Süre"])
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setSortingEnabled(True)

    def load_tracks(self, tracks: List):
        self.setRowCount(len(tracks))
        for row, track in enumerate(tracks):
            path, title, artist, album, duration = track
            self.setItem(row, 0, QTableWidgetItem(title))
            self.setItem(row, 1, QTableWidgetItem(artist))
            self.setItem(row, 2, QTableWidgetItem(album))
            time_str = QTime(0, 0).addMSecs(duration).toString("mm:ss")
            duration_item = QTableWidgetItem(time_str)
            duration_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.setItem(row, 3, duration_item)
            for col in range(self.columnCount()):
                self.item(row, col).setData(Qt.UserRole, path)

    def get_selected_paths(self):
        rows = set(idx.row() for idx in self.selectionModel().selectedRows())
        paths = []
        for r in rows:
            item = self.item(r, 0)
            if item:
                p = item.data(Qt.UserRole)
                if p:
                    paths.append(p)
        return paths


# ---------------------------------------------------------------------------
# ÖZEL ARAMA KUTUSU (Enter Tuşu Düzeltmesi)
# ---------------------------------------------------------------------------





# ---------------------------------------------------------------------------
# EKOLAYZIR
# ---------------------------------------------------------------------------

class EqualizerWidget(QWidget):
    eq_changed_signal = pyqtSignal(list)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.frequencies = list(EQ_BAND_LABELS)
        self.sliders = []
        self.labels = []
        self.initial_value = 50
        self._init_ui()

    def _init_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

        for i, freq in enumerate(self.frequencies):
            v_layout = QVBoxLayout()
            val_label = QLabel("0 dB")
            val_label.setAlignment(Qt.AlignCenter)
            self.labels.append(val_label)

            slider = QSlider(Qt.Vertical)
            slider.setRange(0, 100)
            slider.setValue(self.initial_value)
            slider.setMinimumHeight(120)
            slider.setObjectName(f"eq_slider_{i}")
            # Doğrudan slider'ın sender() ile bağla (lambda'da sorun yaratmamak için)
            slider.valueChanged.connect(self._update_label)
            slider.valueChanged.connect(
                lambda: self.eq_changed_signal.emit(self.get_gains())
            )
            self.sliders.append(slider)

            freq_label = QLabel(freq)
            freq_label.setAlignment(Qt.AlignCenter)

            v_layout.addWidget(val_label)
            v_layout.addWidget(slider)
            v_layout.addWidget(freq_label)
            layout.addLayout(v_layout)

        self.setLayout(layout)

    def _update_label(self, value):
        # Uyumluluk: bazen lambda ile label parametresi de gönderiliyor
        db = (value - 50) / 5
        sender = self.sender()
        try:
            # Eğer çağıran widget doğrudan bağlı ise index ile bul
            label = self.labels[self.sliders.index(sender)]
        except Exception:
            # Fallback: eğer lambda ile label iletildiyse, kullan
            try:
                # ikinci argüman olarak gönderilen label varsa onu kullan
                # (PyQt lambda bağlantılarında bu değer doğrudan burada bulunmaz,
                #  ama bu yapı koruyucu kod sağlar.)
                label = None
            except Exception:
                label = None
        if label is not None:
            label.setText(f"{db:+.1f} dB")

    def get_gains(self):
        gains = []
        for s in self.sliders:
            gain = float(s.value() / 10.0)
            gains.append(gain)
        return gains

    def set_gains(self, gains: List[float]):
        if len(gains) != len(self.sliders):
            return
        for s, gain in zip(self.sliders, gains):
            val = int(gain * 10)
            s.setValue(val)


# ---------------------------------------------------------------------------
# PARÇA BİLGİ PANELİ
# ---------------------------------------------------------------------------

class AnimatedCoverLabel(QLabel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._base_pixmap = None
        self._anim = None
        self._target_size = None
        self.setScaledContents(False)
        self.setAlignment(Qt.AlignCenter)

    def set_cover_pixmap(self, pixmap):
        if pixmap is None or pixmap.isNull():
            self._base_pixmap = None
            super().setPixmap(QPixmap())
            self.setText("")
            parent = self.parentWidget()
            if parent is not None and hasattr(parent, "sync_label"):
                parent.sync_label()
            return

        self._base_pixmap = QPixmap(pixmap)
        parent = self.parentWidget()
        if parent is not None and hasattr(parent, "sync_label"):
            parent.sync_label()
        self._apply_scaled_pixmap()
        self._start_slide_animation()

    def set_target_size(self, size):
        self._target_size = QSize(size)
        if self._base_pixmap is not None and not self._base_pixmap.isNull():
            self._apply_scaled_pixmap()

    def scaled_size_for_width(self, width):
        if self._base_pixmap is None or self._base_pixmap.isNull():
            return QSize(width, 0)
        if self._base_pixmap.width() <= 0:
            return QSize(width, 0)
        height = int(width * (self._base_pixmap.height() / self._base_pixmap.width()))
        return QSize(width, max(1, height))

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self._base_pixmap is not None and not self._base_pixmap.isNull():
            self._apply_scaled_pixmap()

    def _apply_scaled_pixmap(self):
        if self._base_pixmap is None or self._base_pixmap.isNull():
            return
        target = self._target_size or self.size()
        scaled = self._base_pixmap.scaled(
            target, Qt.KeepAspectRatio, Qt.SmoothTransformation
        )
        super().setPixmap(scaled)

    def _start_slide_animation(self):
        parent = self.parentWidget()
        if parent is not None:
            end_y = max(0, parent.height() - self.height())
            start_y = parent.height()
        else:
            end_y = 0
            start_y = self.height()
        if self._anim is not None:
            self._anim.stop()
        self.move(0, start_y)
        self._anim = QPropertyAnimation(self, b"pos", self)
        self._anim.setDuration(1200)
        self._anim.setStartValue(QPoint(0, start_y))
        self._anim.setEndValue(QPoint(0, end_y))
        self._anim.setEasingCurve(QEasingCurve.InOutQuint)
        self._anim.start()


class AlbumArtHolder(QWidget):
    def __init__(self, label: AnimatedCoverLabel, parent=None):
        super().__init__(parent)
        self._label = label
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.sync_label()

    def sync_label(self):
        width = self.width()
        if width <= 0:
            return
        target = self._label.scaled_size_for_width(width)
        self.setMinimumHeight(target.height())
        self.setMaximumHeight(target.height())
        parent = self.parentWidget()
        if parent is not None:
            parent.setMinimumHeight(target.height())
            parent.setMaximumHeight(target.height())
        self._label.set_target_size(target)
        self._label.setGeometry(0, self.height() - target.height(), width, target.height())

class InfoDisplayWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedWidth(220)
        self.setStyleSheet(
            "background-color: #1E1E1E; border: 1px solid #444444; border-radius: 6px;"
        )
        self._album_art_visible = True
        self._external_album_label = None
        self._init_ui()

    def _init_ui(self):
        # Düzen: başlık/artist/album üstte, albüm kapağı sağ-alt köşede
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(10, 10, 10, 10)

        self.titleLabel = QLabel("Başlık: -")
        self.artistLabel = QLabel("Sanatçı: -")
        self.albumLabel = QLabel("Albüm: -")

        self.titleLabel.setStyleSheet("font-weight: bold; color: #40C4FF;")
        self.artistLabel.setStyleSheet("color: #CCCCCC;")
        self.albumLabel.setStyleSheet("color: #AAAAAA;")

        main_layout.addWidget(self.titleLabel)
        main_layout.addWidget(self.artistLabel)
        main_layout.addWidget(self.albumLabel)
        main_layout.addStretch(1)

        # Albüm kapağı artık dışa taşındı; ana uygulama tarafından yerleştirilecek.

        self.setLayout(main_layout)

    def set_album_art_visibility(self, visible: bool):
        self._album_art_visible = visible
        # Eğer dışsal bir album label atandıysa, onun görünürlüğünü ayarla
        if self._external_album_label is not None:
            self._external_album_label.setVisible(visible)
        self.update()

    def update_info(self, title: str, artist: str, album: str,
                    path: Optional[str] = None):
        self.titleLabel.setText(f"Başlık: {title}")
        self.artistLabel.setText(f"Sanatçı: {artist}")
        self.albumLabel.setText(f"Albüm: {album}")

        if not self._album_art_visible:
            if self._external_album_label is not None:
                if hasattr(self._external_album_label, "set_cover_pixmap"):
                    self._external_album_label.set_cover_pixmap(None)
                else:
                    self._external_album_label.setText("")
                    self._external_album_label.setPixmap(QPixmap())
            return

        cover_data = None

        if path and MutagenFile is not None and os.path.exists(path):
            try:
                audio = MutagenFile(path)
                if audio and audio.tags:
                    if ID3 and isinstance(audio.tags, ID3):
                        for key in audio.tags.keys():
                            if key.startswith("APIC"):
                                apic = audio.tags[key]
                                if hasattr(apic, "data") and isinstance(apic.data, bytes):
                                    cover_data = apic.data
                                    break
                    elif MP4 and isinstance(audio, MP4):
                        covr = audio.tags.get("covr")
                        if covr and isinstance(covr, list) and len(covr) > 0:
                            data = covr[0]
                            if isinstance(data, bytes):
                                cover_data = data
            except Exception:
                pass

        if cover_data:
            pix = QPixmap()
            if pix.loadFromData(QByteArray(cover_data)):
                if self._external_album_label is not None:
                    if hasattr(self._external_album_label, "set_cover_pixmap"):
                        self._external_album_label.set_cover_pixmap(pix)
                    else:
                        target = self._external_album_label.size()
                        self._external_album_label.setPixmap(
                            pix.scaled(target, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                        )
                return

        if path:
            folder = os.path.dirname(path)
            for name in ("cover.jpg", "folder.jpg", "album.png"):
                p = os.path.join(folder, name)
                if os.path.exists(p):
                    pix = QPixmap(p)
                    if self._external_album_label is not None:
                        if hasattr(self._external_album_label, "set_cover_pixmap"):
                            self._external_album_label.set_cover_pixmap(pix)
                        else:
                            target = self._external_album_label.size()
                            self._external_album_label.setPixmap(
                                pix.scaled(target, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                            )
                        return

        if self._external_album_label is not None:
            if hasattr(self._external_album_label, "set_cover_pixmap"):
                self._external_album_label.set_cover_pixmap(None)
            else:
                self._external_album_label.setText("")
                self._external_album_label.setPixmap(QPixmap())

    def clear_info(self):
        self.titleLabel.setText("Başlık: -")
        self.artistLabel.setText("Sanatçı: -")
        self.albumLabel.setText("Albüm: -")
        if self._album_art_visible and self._external_album_label is not None:
            if hasattr(self._external_album_label, "set_cover_pixmap"):
                self._external_album_label.set_cover_pixmap(None)
            else:
                self._external_album_label.setText("")
                self._external_album_label.setPixmap(QPixmap())

    def set_external_album_label(self, label: QLabel):
        """Assign an external QLabel (created by AngollaPlayer) to show album art."""
        self._external_album_label = label
        # Apply current visibility (respect the size already set by AngollaPlayer)
        if label is not None:
            label.setVisible(self._album_art_visible)

    @staticmethod
    def extract_dominant_color(path: str) -> QColor:
        """Albüm kapağından ortalama renk çıkar (fallback: mavi ton)."""
        try:
            img = QImage(path)
            if img.isNull():
                return QColor("#40C4FF")
            # Küçültüp hızlı ortalama al
            img = img.scaled(50, 50, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            r = g = b = 0
            count = img.width() * img.height()
            for x in range(img.width()):
                for y in range(img.height()):
                    c = QColor(img.pixel(x, y))
                    r += c.red()
                    g += c.green()
                    b += c.blue()
            return QColor(int(r / count), int(g / count), int(b / count))
        except Exception:
            return QColor("#40C4FF")


# ---------------------------------------------------------------------------
# SEEK SLIDER
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# DYNAMIC GRADIENT SLIDER (Video Seek + Aura)
# ---------------------------------------------------------------------------
class GradientSlider(QSlider):
    def __init__(self, orientation=Qt.Horizontal, parent=None):
        super().__init__(orientation, parent)
        self.setFixedHeight(20)  # Daha geniş ve net
        self.shift = 0.0
        self._aura_speed = 1.0
        self._aura_base_hue_f = None  # 0..1 (HSV hue fraction)
        self._aura_saturation_f = 0.8
        self._aura_value_f = 1.0
        self._aura_span_f = 0.20
        self._anim_timer = QTimer(self)
        self._anim_timer.setInterval(50)  # Daha akıcı animasyon (100ms -> 50ms)
        self._anim_timer.timeout.connect(self._animate_gradient)
        self._anim_timer.start()
        self._is_seeking = False  # Drag state tracking
        
        # Mouse tracking aktif
        self.setMouseTracking(True)

    def set_aura_speed(self, speed: float):
        """Aura akış hızını ayarla (1.0 = normal)."""
        try:
            self._aura_speed = max(0.0, float(speed))
        except Exception:
            self._aura_speed = 1.0

    def set_aura_base_color(self, base_color: QColor):
        """Tema ile uyumlu aura üretmek için taban renk ata."""
        try:
            if base_color is None or not isinstance(base_color, QColor):
                self._aura_base_hue_f = None
                return

            h, s, v, _ = base_color.getHsv()
            if h < 0:
                self._aura_base_hue_f = None
                return

            self._aura_base_hue_f = (float(h) % 360.0) / 360.0
            self._aura_saturation_f = max(0.45, min(1.0, float(s) / 255.0 if s >= 0 else 0.8))
            self._aura_value_f = max(0.75, min(1.0, float(v) / 255.0 if v >= 0 else 1.0))
        except Exception:
            self._aura_base_hue_f = None

    def _animate_gradient(self):
        self.shift += 0.03 * float(self._aura_speed)  # Daha hızlı animasyon
        if self.shift > 1.0:
            self.shift -= 1.0
        self.update()

    def mousePressEvent(self, event):
        """Etkileşimli Süre Çubuğu: Tıklanan yere anında atla"""
        if event.button() == Qt.LeftButton:
            self._is_seeking = True
            val = QStyle.sliderValueFromPosition(
                self.minimum(), self.maximum(), 
                event.x(), self.width()
            )
            self.setValue(val)
            self.sliderMoved.emit(val)
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        """Mouse drag: Sürekli güncelleme"""
        if self._is_seeking and event.buttons() & Qt.LeftButton:
            val = QStyle.sliderValueFromPosition(
                self.minimum(), self.maximum(), 
                event.x(), self.width()
            )
            self.setValue(val)
            self.sliderMoved.emit(val)
            event.accept()
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        """Mouse release: Seeking tamamlandı"""
        if event.button() == Qt.LeftButton and self._is_seeking:
            self._is_seeking = False
            val = QStyle.sliderValueFromPosition(
                self.minimum(), self.maximum(), 
                event.x(), self.width()
            )
            self.setValue(val)
            self.sliderMoved.emit(val)
            self.sliderReleased.emit()
            event.accept()
            return
        super().mouseReleaseEvent(event)

    def wheelEvent(self, event):
        if self.maximum() <= self.minimum():
            event.ignore()
            return

        delta = event.angleDelta().y()
        if delta == 0:
            delta = event.pixelDelta().y()
        if delta == 0:
            event.ignore()
            return

        step = 10
        if delta < 0:
            step = -step
        new_val = max(self.minimum(), min(self.maximum(), self.value() + step))
        if new_val != self.value():
            self.setValue(new_val)
            self.sliderMoved.emit(new_val)
            self.sliderReleased.emit()
        event.accept()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        rect = self.rect()
        
        # 1. Groove (Kanal) - Daha geniş ve estetik
        groove_rect = rect.adjusted(0, 5, 0, -5)
        
        # Groove gradient (koyu -> daha koyu)
        groove_grad = QLinearGradient(groove_rect.topLeft(), groove_rect.bottomLeft())
        groove_grad.setColorAt(0.0, QColor(38, 50, 56, 240))
        groove_grad.setColorAt(1.0, QColor(26, 35, 39, 250))
        painter.setBrush(QBrush(groove_grad))
        painter.setPen(QPen(QColor(85, 85, 85, 120), 1))
        painter.drawRoundedRect(groove_rect, 4, 4)  # Daha yuvarlatılmış
        
        # 2. Progress Aura Gradient - Çok daha parlak ve akıcı
        if self.maximum() > 0:
            ratio = self.value() / self.maximum()
        else:
            ratio = 0
            
        width = max(0, min(rect.width(), int(rect.width() * ratio)))
        progress_rect = groove_rect.adjusted(0, 0, width - rect.width(), 0)
        
        if width > 0:
            # Çok renkli gradient aura (tema bazlı veya rainbow)
            grad = QLinearGradient(progress_rect.topLeft(), progress_rect.topRight())
            
            if self._aura_base_hue_f is not None:
                # Tema bazlı renkler
                base = self._aura_base_hue_f
                # Çoklu renk durağı (daha zengin gradient)
                grad.setColorAt(0.0, QColor.fromHsvF((base + self.shift) % 1.0, self._aura_saturation_f, self._aura_value_f))
                grad.setColorAt(0.5, QColor.fromHsvF((base + self.shift + self._aura_span_f * 0.5) % 1.0, self._aura_saturation_f * 0.9, self._aura_value_f))
                grad.setColorAt(1.0, QColor.fromHsvF((base + self.shift + self._aura_span_f) % 1.0, self._aura_saturation_f, self._aura_value_f * 0.95))
            else:
                # Neon rainbow (varsayılan)
                grad.setColorAt(0.0, QColor.fromHsvF((0.50 + self.shift) % 1.0, 0.85, 1.0))  # Cyan
                grad.setColorAt(0.33, QColor.fromHsvF((0.60 + self.shift) % 1.0, 0.80, 1.0))  # Mavi
                grad.setColorAt(0.67, QColor.fromHsvF((0.75 + self.shift) % 1.0, 0.85, 0.95))  # Mor
                grad.setColorAt(1.0, QColor.fromHsvF((0.85 + self.shift) % 1.0, 0.80, 1.0))  # Pembe
            
            painter.setBrush(QBrush(grad))
            painter.setPen(Qt.NoPen)
            painter.drawRoundedRect(progress_rect, 4, 4)
        
        # 3. Animasyonlu Nokta (Handle) - Daha büyük ve parlak
        def _draw_dot(x_pos):
            dot_pos = QPointF(x_pos, groove_rect.center().y())
            
            # Glow efekti
            glow = QRadialGradient(dot_pos, 9)
            if self._aura_base_hue_f is not None:
                base_col = QColor.fromHsvF(self._aura_base_hue_f, self._aura_saturation_f, self._aura_value_f)
                glow.setColorAt(0, QColor(base_col.red(), base_col.green(), base_col.blue(), 220))
                glow.setColorAt(1, QColor(base_col.red(), base_col.green(), base_col.blue(), 0))
            else:
                glow.setColorAt(0, QColor(76, 255, 220, 220))
                glow.setColorAt(1, QColor(76, 255, 220, 0))
            
            painter.setBrush(QBrush(glow))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(dot_pos, 9, 9)
            
            # İç nokta (beyaz parlak)
            painter.setBrush(QColor(255, 255, 255, 240))
            painter.drawEllipse(dot_pos, 4, 4)
            
            # Çok küçük merkez parlama
            painter.setBrush(QColor(255, 255, 255))
            painter.drawEllipse(dot_pos, 2, 2)

        # 4. Handle (Sadece progress pozisyonunda)
        progress_x = groove_rect.left() + groove_rect.width() * ratio
        _draw_dot(progress_x)

# ---------------------------------------------------------------------------
# VIDEO DISPLAY WIDGET (Flip & Transform Support)
# ---------------------------------------------------------------------------
from PyQt5.QtWidgets import QGraphicsView, QGraphicsScene
from PyQt5.QtMultimediaWidgets import QGraphicsVideoItem
from PyQt5.QtCore import QSizeF

class VideoDisplayWidget(QGraphicsView):
    frameRendered = pyqtSignal()
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)
        self.video_item = QGraphicsVideoItem()
        self.scene.addItem(self.video_item)
        
        # Set aspect ratio mode to keep aspect ratio (prevents distortion)
        self.video_item.setAspectRatioMode(Qt.KeepAspectRatio)
        
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setStyleSheet("background-color: black; border: none;")
        self.setFocusPolicy(Qt.StrongFocus)
        
        # Rotation State
        self.current_rotation = 0
        
        # Scale Mode State
        # 0: Fill (KeepAspectRatioByExpanding - Fill Screen)
        # 1: Original (No scale)
        # 2: Fit (KeepAspectRatio - Entire Video Visible) - DEFAULT
        self.scale_mode = 2  
        
        # Orijin noktasını item'in ortası yap (başlangıçta)
        self.video_item.setTransformOriginPoint(self.width()/2, self.height()/2)
        
        # Enable Mouse Tracking for Fullscreen
        self.setMouseTracking(True)
        self.viewport().setMouseTracking(True)
        
        # Ensure the view fills the container
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        # Video fullscreen state
        self.video_fullscreen = False

        # Hide controls timer
        self.hide_controls_timer = QTimer(self)
        self.hide_controls_timer.setInterval(5000)  # 5 seconds
        self.hide_controls_timer.timeout.connect(self.hide_video_controls)

        # Controls widget (to be shown/hidden)
        self.controls_widget = None

    def resizeEvent(self, event):
        """Pencere boyutu değişince videoyu yeniden sığdır."""
        super().resizeEvent(event)
        self._update_video_transform()

    def showEvent(self, event):
        super().showEvent(event)
        QTimer.singleShot(50, self._update_video_transform)

    def set_scale_mode(self, mode):
        """
        0: Fit (Fill Screen - Default)
        1: 1:1 (Original Size)
        2: Fit (Entire Video Visible)
        """
        self.scale_mode = mode
        if mode == 0:
            self.video_item.setAspectRatioMode(Qt.KeepAspectRatioByExpanding)
        elif mode == 1:
            self.video_item.setAspectRatioMode(Qt.KeepAspectRatio)
            # Reset transform to identity (1:1)
            self.resetTransform()
        elif mode == 2:
            self.video_item.setAspectRatioMode(Qt.KeepAspectRatio)
        
        self._update_video_transform()

    def zoom_in(self):
        self.scale(1.1, 1.1)

    def zoom_out(self):
        self.scale(0.9, 0.9)

    def contextMenuEvent(self, event):
        menu = QMenu(self)
        menu.setStyleSheet("""
            QMenu { background-color: #2A2A2A; color: white; border: 1px solid #444; }
            QMenu::item { padding: 5px 20px; }
            QMenu::item:selected { background-color: #40C4FF; color: black; }
        """)
        
        title = QAction("Video Yönü", self)
        title.setEnabled(False)
        menu.addAction(title)
        menu.addSeparator()
        
        rotate_right = QAction("↪️ Sağa Çevir (90°)", self)
        rotate_right.triggered.connect(lambda: self.rotate_video(90))
        menu.addAction(rotate_right)
        
        rotate_left = QAction("↩️ Sola Çevir (90°)", self)
        rotate_left.triggered.connect(lambda: self.rotate_video(-90))
        menu.addAction(rotate_left)
        
        rotate_180 = QAction("🔄 Ters Çevir (180°)", self)
        rotate_180.triggered.connect(lambda: self.rotate_video(180))
        menu.addAction(rotate_180)
        
        reset = QAction("⏹️ Sıfırla (Normal)", self)
        reset.triggered.connect(lambda: self.rotate_video(0, absolute=True))
        menu.addAction(reset)
        
        menu.exec_(event.globalPos())

    def mouseDoubleClickEvent(self, event):
        try:
            w = self.window()
            if hasattr(w, "_toggle_video_fullscreen"):
                w._toggle_video_fullscreen()
                event.accept()
                return
        except Exception:
            pass
        super().mouseDoubleClickEvent(event)

    def keyPressEvent(self, event):
        try:
            if event.key() == Qt.Key_Escape:
                w = self.window()
                if hasattr(w, "_exit_video_fullscreen"):
                    w._exit_video_fullscreen()
                    event.accept()
                    return
            if event.key() == Qt.Key_F11:
                w = self.window()
                if hasattr(w, "_toggle_video_fullscreen"):
                    w._toggle_video_fullscreen()
                    event.accept()
                    return
        except Exception:
            pass
        super().keyPressEvent(event)

    def mouseMoveEvent(self, event):
        super().mouseMoveEvent(event)
        if self.video_fullscreen:
            # Show controls on mouse move
            self.show_video_controls()
            # Restart hide timer
            self.hide_controls_timer.start()

    def show_video_controls(self):
        """Show video controls with smooth animation"""
        if not hasattr(self, 'controls_widget') or not self.controls_widget:
            return

        if self.controls_widget.isVisible():
            return  # Already visible

        # Stop any ongoing animation
        if hasattr(self, '_controls_anim') and self._controls_anim:
            self._controls_anim.stop()

        # Create slide-in animation from bottom
        self._controls_anim = QPropertyAnimation(self.controls_widget, b"pos", self)
        self._controls_anim.setDuration(300)  # 300ms smooth
        self._controls_anim.setEasingCurve(QEasingCurve.InOutQuad)
        start_pos = QPoint(self.controls_widget.x(), self.parent().height())
        end_pos = QPoint(self.controls_widget.x(), self.parent().height() - self.controls_widget.height())
        self._controls_anim.setStartValue(start_pos)
        self._controls_anim.setEndValue(end_pos)

        self.controls_widget.show()
        self._controls_anim.start()

    def hide_video_controls(self):
        """Hide video controls with smooth animation"""
        if not hasattr(self, 'controls_widget') or not self.controls_widget:
            return

        if not self.controls_widget.isVisible():
            return  # Already hidden

        # Stop any ongoing animation
        if hasattr(self, '_controls_anim') and self._controls_anim:
            self._controls_anim.stop()

        # Create slide-out animation to bottom
        self._controls_anim = QPropertyAnimation(self.controls_widget, b"pos", self)
        self._controls_anim.setDuration(300)  # 300ms smooth
        self._controls_anim.setEasingCurve(QEasingCurve.InOutQuad)
        start_pos = self.controls_widget.pos()
        end_pos = QPoint(self.controls_widget.x(), self.parent().height())
        self._controls_anim.setStartValue(start_pos)
        self._controls_anim.setEndValue(end_pos)
        self._controls_anim.finished.connect(lambda: self.controls_widget.hide())
        self._controls_anim.start()

    def paintEvent(self, event):
        super().paintEvent(event)
        try:
            self.frameRendered.emit()
        except Exception:
            pass

    def rotate_video(self, angle, absolute=False):
        if absolute:
            self.current_rotation = angle
        else:
            self.current_rotation = (self.current_rotation + angle) % 360
        self._update_video_transform()
        
        # Kullanıcıya bilgi ver (Status bar erişimi varsa)
        parent = self.window()
        if hasattr(parent, "statusBar"):
            parent.statusBar().showMessage(f"Video Döndürüldü: {self.current_rotation}°", 2000)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._update_video_transform()

    def _update_video_transform(self):
        if not self.video_item:
            return
            
        rect = self.viewport().rect()
        view_w = rect.width()
        view_h = rect.height()
        
        if view_w <= 0 or view_h <= 0:
            return

        # 90 veya 270 derece dönüşte boyutları takas etmemiz gerekir
        if self.current_rotation in [90, 270]:
            target_w = view_h
            target_h = view_w
        else:
            target_w = view_w
            target_h = view_h
            
        self.video_item.setSize(QSizeF(target_w, target_h))
        self.video_item.setPos(0, 0)
        
        # Dönüş merkezini ayarla
        center = QPointF(target_w / 2, target_h / 2)
        self.video_item.setTransformOriginPoint(center)
        self.video_item.setRotation(self.current_rotation)
        
        # Sahneye ve View'e göre ortala
        self.scene.setSceneRect(0, 0, target_w, target_h)
        
        # Ölçekleme moduna göre sığdır
        if self.scale_mode == 0:
            # Fill Screen
            self.fitInView(self.video_item, Qt.KeepAspectRatioByExpanding)
        elif self.scale_mode == 1:
            # 1:1 modunda fitInView çağırma, sadece ortala
            pass
        else:
            # Fit (Entire Video Visible)
            self.fitInView(self.video_item, Qt.KeepAspectRatio)
            
        self.centerOn(self.video_item)

# ---------------------------------------------------------------------------
# SEEK SLIDER (Existing wrapper)
# ---------------------------------------------------------------------------
class SeekSlider(QSlider):
    def wheelEvent(self, event):
        delta = event.angleDelta().y()
        step = 5000
        if delta > 0:
            new_position = self.value() + step
        else:
            new_position = self.value() - step
        new_position = max(0, min(new_position, self.maximum()))
        self.setValue(new_position)
        self.sliderReleased.emit()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            pos = event.pos().x()
            slider_width = self.width()
            if slider_width > 0:
                value = int(
                    (self.maximum() - self.minimum()) *
                    (pos / slider_width) + self.minimum()
                )
                self.setValue(value)
                self.sliderReleased.emit()
                event.accept()
                return
        super().mousePressEvent(event)

    def paintEvent(self, event):
        # Varsayılan çizimi bırakarak sadece handle çizimini kullanıyoruz;
        # ancak ilerleme için alt arka plan rengini stil ile ayarlıyoruz (yapılandırma ana uygulamada yapılır).
        super().paintEvent(event)


# ---------------------------------------------------------------------------
# ÇALMA LİSTESİ WIDGET
# ---------------------------------------------------------------------------

class PlaylistListWidget(QListWidget):
    def __init__(self, parent=None, player=None):
        super().__init__(parent)
        self.player = player
        self.setAcceptDrops(True)
        self.setDragEnabled(True)
        self.setDropIndicatorShown(True)
        self.setDragDropMode(QListWidget.InternalMove)
        self.setSelectionMode(QListWidget.ExtendedSelection)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragMoveEvent(event)

    def dropEvent(self, event):
        if event.mimeData().hasUrls():
            file_paths = []
            for url in event.mimeData().urls():
                if url.isLocalFile():
                    file_paths.append(url.toLocalFile())
            if file_paths and self.player:
                self.player._add_files_to_playlist(file_paths)
                event.acceptProposedAction()
        elif event.source() == self and event.dropAction() == Qt.MoveAction:
            super().dropEvent(event)
            if self.player:
                self.player.update_playlist_order_after_drag()
            event.acceptProposedAction()
        else:
            super().dropEvent(event)

    def contextMenuEvent(self, event):
        """Çalma listesi sağ tık menüsü."""
        menu = QMenu(self)
        
        # Seçili öğeleri al
        selected_items = self.selectedItems()
        
        if selected_items:
            # YouTube'da ara
            youtube_action = QAction("🔍 YouTube'da Ara", self)
            youtube_action.triggered.connect(self._search_youtube)
            menu.addAction(youtube_action)
            
            # Seçili ögeleri ara
            search_action = QAction("🔎 Seçili Ögeleri Ara", self)
            search_action.triggered.connect(self._search_selected)
            menu.addAction(search_action)
            
            # Bluetooth paylaş
            bluetooth_action = QAction("📱 Bluetooth'a Paylaş", self)
            bluetooth_action.triggered.connect(self._share_bluetooth)
            menu.addAction(bluetooth_action)
            
            menu.addSeparator()
        
        # Çalma listesini temizle (her zaman available)
        clear_action = QAction("🗑️ Çalma Listesini Temizle", self)
        clear_action.triggered.connect(self._clear_playlist)
        menu.addAction(clear_action)
        
        menu.exec_(self.mapToGlobal(event.pos()))
    
    def _search_youtube(self):
        """Seçili şarkıları YouTube'da ara."""
        selected_items = self.selectedItems()
        if selected_items:
            item = selected_items[0]
            text = item.text()
            import webbrowser
            query = urllib.parse.quote(text)
            webbrowser.open(f"https://www.youtube.com/results?search_query={query}")
    
    def _search_selected(self):
        """Seçili ögeleri ara."""
        selected_items = self.selectedItems()
        if selected_items:
            item = selected_items[0]
            text = item.text()
            import webbrowser
            query = urllib.parse.quote(text)
            webbrowser.open(f"https://www.google.com/search?q={query}")
    
    def _share_bluetooth(self):
        """Bluetooth'a paylaş (stub)."""
        from PyQt5.QtWidgets import QMessageBox
        QMessageBox.information(
            self, "Bluetooth Paylaşımı",
            "Bu özellik yakında mevcut olacak.\n\n" +
            "Şarkıları Bluetooth cihazlarına gönderebileceksiniz."
        )
    
    def _clear_playlist(self):
        """Çalma listesini temizle."""
        from PyQt5.QtWidgets import QMessageBox
        reply = QMessageBox.question(
            self, "Emin misiniz?",
            "Çalma listesini temizlemek istiyor musunuz?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.clear()
            if self.player:
                self.player.playlist.clear()

    def _update_video_transform(self):
        """Video boyut/döndürme güncelleme."""
        if not self.scene or not self.video_item:
            return
            
        # Eğer Scale Mode 1 (Original) ise otomatik fit yapma
        if hasattr(self, 'scale_mode') and self.scale_mode == 1:
            return

        # Döndürme varsa manuel fit gerekebilir
        # Şimdilik basitçe fitInView çağırıyoruz
        keep_mode = Qt.KeepAspectRatioByExpanding if getattr(self, 'scale_mode', 0) == 0 else Qt.KeepAspectRatio
        self.fitInView(self.video_item, keep_mode)


# ---------------------------------------------------------------------------
# GERÇEK ZAMANLI SPEKTRUM ANALİZÖRÜ WIDGET
# ---------------------------------------------------------------------------

class RealTimeSpectrumWidget(QWidget):
    """
    Çalınan müziğin frekans spektrumunu (FFT) gerçek zamanlı olarak gösterir.
    Müzik verisi (chunk) dışarıdan 'update_visualization' metodu aracılığıyla alınacaktır.
    """
    def __init__(self, parent=None, sample_rate=44100, fft_size=2048):
        super().__init__(parent)
        self.sample_rate = sample_rate
        self.fft_size = fft_size
        
        # Sinyal penceresi (Hanning)
        if np is not None:
            self.window = np.hanning(self.fft_size)
        else:
            self.window = None
        
        # Spektrum bar'ları için veri
        self.num_bars = 64
        self.bar_heights = [0.0] * self.num_bars
        self.frequencies = []
        
        # Frekans aralıkları (Hz cinsinden)
        if np is not None:
            self.frequencies = np.fft.rfftfreq(self.fft_size, 1.0 / self.sample_rate)
            # Pozitif frekansları logaritmik gruplara böl
            self._setup_frequency_bands()
        
        # Renkler
        self.bg_color = QColor(20, 20, 30)
        self.bar_color = QColor(0, 200, 255)
        self.peak_color = QColor(255, 100, 100)
        
        # Peak tracker (tepeler)
        self.peaks = [0.0] * self.num_bars
        self.peak_fall_rate = 0.02
        
        # Yumuşatma (smoothing)
        self.smoothing_factor = 0.7
        
        # Widget ayarları
        self.setMinimumHeight(150)
        self.setMinimumWidth(400)
        
        # Güncelleme timer'ı (60 FPS)
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.update)
        self.update_timer.start(16)  # ~60 FPS
    
    def _setup_frequency_bands(self):
        """Logaritmik frekans bantlarını ayarlar."""
        if np is None:
            return
        
        # 20 Hz - 20 kHz arası logaritmik dağılım
        min_freq = 20
        max_freq = min(20000, self.sample_rate / 2)
        
        # Logaritmik ölçekte frekans bantları
        self.freq_bands = np.logspace(
            np.log10(min_freq),
            np.log10(max_freq),
            self.num_bars + 1
        )
    
    def update_visualization(self, audio_chunk_data):
        """
        Dışarıdan (ses çalma motorundan) gelen ham ses bloğunu işler.
        
        :param audio_chunk_data: NumPy dizisi formatında gelen ses verisi
        """
        if np is None or audio_chunk_data is None:
            return
        
        if len(audio_chunk_data) == 0:
            return
        
        # 1. Ham ses verisini float tipine çevir ve normalize et
        audio_data = audio_chunk_data.astype(np.float32)
        audio_data = audio_data / (np.max(np.abs(audio_data)) + 1e-9)
        
        # 2. FFT boyutuna göre veri boyutunu ayarla
        if len(audio_data) < self.fft_size:
            # Pad with zeros
            audio_data = np.pad(audio_data, (0, self.fft_size - len(audio_data)))
        elif len(audio_data) > self.fft_size:
            # Crop to fft_size
            audio_data = audio_data[:self.fft_size]
        
        # 3. Hanning penceresini uygula
        if self.window is not None:
            audio_data = audio_data * self.window
        
        # 4. FFT hesapla
        fft_result = np.fft.rfft(audio_data)
        
        # 5. Yalnızca pozitif frekansları al ve magnitude hesapla
        magnitude = np.abs(fft_result)
        
        # 6. Logaritmik ölçekte (dB) dönüştür
        # Sıfır bölme hatası için epsilon ekle
        magnitude_db = 20 * np.log10(magnitude + 1e-10)
        
        # 7. Normalize et (0-1 arası)
        min_db = -80
        max_db = 0
        magnitude_db = np.clip(magnitude_db, min_db, max_db)
        magnitude_normalized = (magnitude_db - min_db) / (max_db - min_db)
        
        # 8. Frekans bantlarına göre grupla
        self._update_bars(magnitude_normalized)
    
    def _update_bars(self, magnitude_array):
        """Magnitude array'ini bar yüksekliklerine dönüştürür."""
        if np is None or not hasattr(self, 'freq_bands'):
            return
        
        for i in range(self.num_bars):
            # Her frekans bandı için ortalama magnitude
            freq_start = self.freq_bands[i]
            freq_end = self.freq_bands[i + 1]
            
            # Frekans indekslerini bul
            freq_indices = np.where(
                (self.frequencies >= freq_start) & 
                (self.frequencies < freq_end)
            )[0]
            
            if len(freq_indices) > 0:
                # Bu banttaki ortalama magnitude
                avg_magnitude = np.mean(magnitude_array[freq_indices])
                
                # Yumuşatma (smoothing)
                self.bar_heights[i] = (
                    self.smoothing_factor * self.bar_heights[i] +
                    (1 - self.smoothing_factor) * avg_magnitude
                )
                
                # Peak güncelle
                if self.bar_heights[i] > self.peaks[i]:
                    self.peaks[i] = self.bar_heights[i]
                else:
                    # Peak yavaşça düşsün
                    self.peaks[i] = max(0, self.peaks[i] - self.peak_fall_rate)
    
    def paintEvent(self, event):
        """Spektrum bar'larını çizer."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        w = self.width()
        h = self.height()
        
        # Arka plan
        painter.fillRect(0, 0, w, h, self.bg_color)
        
        if not self.bar_heights:
            painter.end()
            return
        
        # Bar genişliği ve spacing (profesyonel ince görünüm)
        bar_width = 2.0
        total_bar_space = bar_width * self.num_bars
        spacing = 0.0
        if self.num_bars > 1 and w > total_bar_space:
            spacing = (w - total_bar_space) / (self.num_bars - 1)
        
        for i, height in enumerate(self.bar_heights):
            x = i * (bar_width + spacing)
            bar_h = height * h * 0.9  # 90% yükseklik kullan
            
            # Bar rengi (yüksekliğe göre gradient)
            hue = int(200 - height * 100)  # Mavi -> Kırmızı
            color = QColor.fromHsv(hue, 255, 255)
            
            # Bar çiz
            painter.fillRect(
                int(x), int(h - bar_h),
                int(bar_width), int(bar_h),
                color
            )
            
            # Peak göstergesi
            peak_y = h - (self.peaks[i] * h * 0.9)
            painter.fillRect(
                int(x), int(peak_y - 2),
                int(bar_width), 2,
                self.peak_color
            )
        
        # Frekans etiketleri (alt kısımda)
        painter.setPen(QColor(150, 150, 150))
        painter.setFont(QFont("Arial", 8))
        
        # Sadece birkaç frekans etiketi göster
        for i in [0, self.num_bars // 4, self.num_bars // 2, 3 * self.num_bars // 4, self.num_bars - 1]:
            if hasattr(self, 'freq_bands') and i < len(self.freq_bands):
                freq = self.freq_bands[i]
                x = i * (bar_width + spacing)
                if freq < 1000:
                    label = f"{int(freq)}Hz"
                else:
                    label = f"{freq/1000:.1f}kHz"
                painter.drawText(int(x), h - 5, label)
        
        painter.end()


# ---------------------------------------------------------------------------
# GÖRSELLEŞTİRME WIDGET - YARDIMCI SINIFLAR
# ---------------------------------------------------------------------------

class EnergyPulse:
    """Bass vuruşunda merkezden yayılan halka efekti"""
    def __init__(self, x, y, max_radius, color, lifetime=1.0):
        self.x = x
        self.y = y
        self.radius = 0.0
        self.max_radius = max_radius
        self.color = color
        self.lifetime = lifetime
        self.age = 0.0
        self.alive = True
    
    def update(self, dt):
        """Frame update - halka genişler ve kaybolur"""
        self.age += dt
        progress = self.age / self.lifetime
        
        if progress >= 1.0:
            self.alive = False
            return
        
        # Ease-out animasyon
        self.radius = self.max_radius * (1.0 - (1.0 - progress) ** 2)
    
    def get_alpha(self):
        """Fade out efekti"""
        progress = self.age / self.lifetime
        return int(255 * (1.0 - progress))


class SwirlParticle:
    """3D swirl/galaxy modu için dönen parçacık"""
    def __init__(self, angle, distance, color, speed=1.0):
        self.angle = angle  # Radyan
        self.distance = distance  # Merkezden uzaklık
        self.color = color
        self.speed = speed
        self.z = 0.0  # Derinlik (3D efekti için)
        self.size = 3.0
    
    def update(self, dt, angular_velocity, bass_intensity):
        """Döner ve bass ile titreşir"""
        self.angle += angular_velocity * self.speed * dt
        # Bass ile pulsating
        self.size = 3.0 + bass_intensity * 5.0
        # Z ekseni salınım (3D efekti)
        if np is not None:
            self.z = float(np.sin(self.angle * 2) * 50)
        else:
            self.z = 0.0


# ---------------------------------------------------------------------------
# PROJECTM SES VERİSİ BESLEME FONKSİYONU
# ---------------------------------------------------------------------------

def send_audio_to_projectm(vis_window, audio_data):
    """ProjectM widget'ına PCM ses verisi besle"""
    if vis_window and hasattr(vis_window, 'is_projectm') and vis_window.is_projectm:
        if hasattr(vis_window.visualizationWidget, 'consume_audio_data'):
            try:
                vis_window.visualizationWidget.consume_audio_data(audio_data)
            except Exception as e:
                pass  # Sessizce devam et


# ---------------------------------------------------------------------------
# GÖRSELLEŞTİRME WIDGET
# ---------------------------------------------------------------------------

class AnimatedVisualizationWidget(QWidget):
    # 🎚️ VİZÜEL YÜKSEKLIK ÖLÇEK FAKTÖRÜ (0.0-1.0)
    # Çubukların maksimum yüksekliğini kontrol eder
    VISUAL_SCALE = 1.0  # %100 yükseklik (eski: 0.25 - çok küçüktü)
    # Angolla bar analyzer parametreleri (orijinal kColumnWidth, roof sayısı vb.)
    CLEM_COLUMN_WIDTH = 4
    CLEM_NUM_ROOFS = 16
    CLEM_ROOF_VELOCITY_REDUCTION = 32
    
    def __init__(self, parent=None, initial_mode="Çizgiler", show_full_visual=True):
        super().__init__(parent)
        self.setMouseTracking(True)

        self.show_full_visual = show_full_visual
        self.vis_mode = initial_mode

        self.line_count = 60
        self.sound_intensity = 0.0

        # ESKİ SMOOTHING DEĞİŞKENLERİ
        self.band_data = [0.0] * 10
        self.band_smoothing = [0.0] * 10

        # 🔥 KRİTİK ONARIM 1: self.fft_bars değişkenini doğru sınıfta başlatıyoruz!
        self.fft_bars = []
        # Bar cap (tepe) değerleri
        self.bar_caps = []

        self.primary_color = QColor("#40C4FF")
        self.background_color = QColor("#2A2A2A")
        
        # Renkleri cache'le - titreşim engellemek için
        self._cached_bar_color = QColor("#40C4FF")
        self._cached_bar_color.setAlpha(230)
        self._cached_cap_color = QColor(94, 226, 255, 255)
        self.bar_color_mode = "NORMAL"  # NORMAL | RGB | GRADYAN
        self.bar_style_mode = "solid_with_cap"
        self.psychedelic_mode = False  # 🌈 Psychedelic Colors mode

        # 🎆 GÖRSELLEŞTİRME KONFİG (Tercihlerden gelir)
        self.vis_sensitivity = 50  # 1-100 (default 50)
        self.vis_color_intensity = 75  # 1-100 (default 75)
        self.vis_density = 60  # 1-100 (default 60)

        self.particles = []
        self._initialize_particles()

        # 🎇 YENİ MOD VERİLERİ
        self.energy_pulses = []  # Pulse Explosion için
        self.swirl_particles = []  # 3D Swirl için
        self.tunnel_offset = 0.0  # Tunnel animasyonu
        self.bass_intensity = 0.0  # Bass analizi
        self.mid_intensity = 0.0   # Mid analizi
        self.treble_intensity = 0.0  # Treble analizi
        self.waveform_data = []  # Circular Waveform için
        # Angolla bar analyzer durum önbelleği
        self._clem_state = None
        self._clem_turbine_state = None
        self._clem_boom_state = None
        self._clem_block_state = None

        self.fps = 60
        self.animation_timer = QTimer(self)
        self.animation_timer.timeout.connect(self.update_animation)
        self.set_fps(self.fps)

        self.last_update_time = time.time()
        self.bar_phase = random.uniform(0.0, 1000.0)
        self.rainbow_phase = 0.0  # Spektrum için gökkuşağı kayması (ana görsel)
        self.status_rainbow_phase = 0.0  # Alt ritim çubukları için daha yavaş aura
        self._visualizer_paused = False
        self._visualizer_fade = False



    # ------------------------------------------------------------------#
    # LOGGING & CLEANUP
    # ------------------------------------------------------------------#

    def set_vis_mode(self, mode: str):
        self.vis_mode = mode
        # Mod tabanlı stil/renk presetleri
        self._apply_mode_preset(mode)
        if mode == "Çizgiler":
            self._initialize_particles(reset_only=True)
        self.update()
        # Ana oynatıcıya haber ver (auto-cycle için)
        parent = self.parent()
        if isinstance(parent, VisualizationWindow):
            parent = parent.player
        if isinstance(parent, AngollaPlayer):
            parent._on_visual_mode_changed_external(mode)

    def set_vis_config(self, sensitivity: int, color_intensity: int, density: int):
        """Görselleştirme yapılandırmasını ayarla."""
        self.vis_sensitivity = max(1, min(100, sensitivity))
        self.vis_color_intensity = max(1, min(100, color_intensity))
        self.vis_density = max(1, min(100, density))
        self.update()

    def _initialize_particles(self, reset_only=False):
        if np is None:
            self.particles = []
            return

        if reset_only and self.particles:
            return

        self.particles = []
        for _ in range(self.line_count):
            self.particles.append({
                "pos": QPointF(random.uniform(0.1, 0.9),
                               random.uniform(0.1, 0.9)),
                "prev_pos": QPointF(random.uniform(0.1, 0.9),
                                    random.uniform(0.1, 0.9)),
                "vel": QPointF(0, 0),
            })

    def set_fps(self, fps: int):
        self.fps = fps
        if self.fps > 0:
            # 60 FPS = 16ms interval (seri ve akıcı animasyon)
            self.animation_timer.start(16)
        else:
            self.animation_timer.stop()

    def set_color_theme(self, primary_hex: str, background_hex: str = "#2A2A2A"):
        self.primary_color = QColor(primary_hex)
        self.background_color = QColor(background_hex)
        # Renkleri cache'le - her çerçevede yeniden oluşturmamak için
        self._cached_bar_color = QColor(primary_hex)
        self._cached_bar_color.setAlpha(230)
        self._cached_cap_color = QColor(primary_hex)
        self._cached_cap_color.setRgb(
            min(self._cached_bar_color.red() + 30, 255),
            min(self._cached_bar_color.green() + 30, 255),
            min(self._cached_bar_color.blue() + 30, 255),
            255
        )
        # Tema değiştiğinde Angolla cache'lerini yenile
        self._clem_state = None
        self._clem_turbine_state = None
        self._clem_boom_state = None
        self._clem_block_state = None
        self.update()

    def set_visualizer_paused(self, paused: bool, fade: bool = True):
        self._visualizer_paused = bool(paused)
        self._visualizer_fade = bool(fade) if self._visualizer_paused else False

    def reset_visualizer(self):
        count = len(self.band_smoothing) if self.band_smoothing else 96
        self.band_smoothing = [0.0] * count
        self.smooth_bands = [0.0] * count
        self.bar_caps = [0.0] * count
        self.sound_intensity = 0.0
        self.bass_intensity = 0.0
        self.mid_intensity = 0.0
        self.treble_intensity = 0.0
        self.energy_pulses = []
        self.update()

    def _fade_visual_state(self):
        decay = 0.92
        self.band_smoothing = [v * decay for v in self.band_smoothing]
        if hasattr(self, "smooth_bands"):
            self.smooth_bands = [v * decay for v in self.smooth_bands]
        else:
            self.smooth_bands = [v * decay for v in self.band_smoothing]
        if hasattr(self, "bar_caps"):
            self.bar_caps = [v * decay for v in self.bar_caps]
        else:
            self.bar_caps = [0.0] * len(self.band_smoothing)
        self.sound_intensity *= decay
        self.bass_intensity *= decay
        self.mid_intensity *= decay
        self.treble_intensity *= decay
        if max(self.band_smoothing) < 1e-3 and self.sound_intensity < 1e-3:
            self.reset_visualizer()
            self._visualizer_fade = False

    # ------------------------------------------------------------------#
    # SES VERİSİ GÜNCELLEME (ASIL ÖNEMLİ KISIM)
    # ------------------------------------------------------------------#

    def update_sound_data(self, intensity: float, band_data: list):
        """
        FFT verisini alır, dB dönüşümü ve Angolla-tarzı smoothing uygular.
        
        İyileştirmeler:
        1. dB ölçeğine dönüşüm (20 * log10)
        2. RMS tabanlı auto-gain normalizasyon
        3. Adaptif ölçekleme (son 30 frame ortalaması)
        4. Angolla attack/release (hızlı yükseliş, yavaş düşüş)
        5. Maksimum değer sınırlama (clamp)
        6. Optimize edilmiş performans
        """
        import math
        from collections import deque

        if self._visualizer_paused:
            return

        # 🎆 Sensitivity parametresini intensity'ye uygula
        sens_factor = self.vis_sensitivity / 50.0  # 50 = normal (1.0), 100 = 2x, 1 = 0.02
        intensity *= sens_factor

        if not band_data:
            band_data = [0.0] * 96

        # 96 bar'a standardize et
        NUM_DISPLAY_BARS = 96
        if len(band_data) > NUM_DISPLAY_BARS:
            band_data = band_data[:NUM_DISPLAY_BARS]
        elif len(band_data) < NUM_DISPLAY_BARS:
            band_data = band_data + [0.0] * (NUM_DISPLAY_BARS - len(band_data))

        # ========== 1. dB DÖNÜŞÜMÜ ==========
        # Ham FFT değerlerini dB ölçeğine dönüştür: 20 * log10(abs(value))
        # Negatif sonsuz değerleri -80 dB'de sınırla
        db_data = []
        for val in band_data:
            abs_val = abs(float(val))
            if abs_val > 1e-10:  # Sıfıra çok yakın değerleri engelle
                db = 20.0 * math.log10(abs_val)
                db = max(db, -80.0)  # -80 dB altına düşme
            else:
                db = -80.0
            db_data.append(db)
        
        # ========== 2. RMS TABANLI AUTO-GAIN NORMALİZASYON ==========
        # RMS (Root Mean Square) hesapla - ortalama enerji seviyesi
        if db_data:
            # dB değerlerini linear'a geri dönüştür (10^(dB/20))
            linear_vals = [10.0 ** (db / 20.0) for db in db_data]
            rms = math.sqrt(sum(v * v for v in linear_vals) / len(linear_vals))
            
            # ========== 3. ADAPTİF ÖLÇEKLENDİRME (Angolla Gain Auto-Normalization) ==========
            # Son 30 frame'in RMS ortalamasını tut
            if not hasattr(self, 'rms_history'):
                self.rms_history = deque(maxlen=30)  # Son 30 frame
            
            self.rms_history.append(rms)
            
            # Hedef yükseklik: Son 30 frame'in ortalaması
            if len(self.rms_history) > 0:
                avg_rms = sum(self.rms_history) / len(self.rms_history)
            else:
                avg_rms = rms
            
            # Adaptif gain hesapla
            # avg_rms düşükse → daha fazla gain
            # avg_rms yüksekse → daha az gain
            if avg_rms > 1e-10:
                target_level = 0.5  # Hedef görselleştirme seviyesi (dengeli - titreşim azaltıldı)
                adaptive_gain = target_level / avg_rms
                
                # Ani patlamaları sınırla (smooth transition)
                # Maksimum değişim: 2x yukarı, 0.5x aşağı (yumuşak geçiş)
                if not hasattr(self, 'prev_gain'):
                    self.prev_gain = 1.0
                
                max_gain_change = 1.2  # Frame başına maksimum %20 değişim
                if adaptive_gain > self.prev_gain * max_gain_change:
                    adaptive_gain = self.prev_gain * max_gain_change
                elif adaptive_gain < self.prev_gain / max_gain_change:
                    adaptive_gain = self.prev_gain / max_gain_change
                
                self.prev_gain = adaptive_gain
                
                # Toplam gain'i makul sınırlar içinde tut (eski: 8.0)
                adaptive_gain = max(0.1, min(15.0, adaptive_gain))
            else:
                adaptive_gain = 1.0
            
            # Normalize edilmiş değerler (0-1 arası)
            normalized = []
            for val in linear_vals:
                norm_val = val * adaptive_gain
                
                # ========== ANİ PATLAMALARDA CLAMP ==========
                # Adaptif gain'e rağmen çok yüksek değerleri sınırla
                # Soft clipping: logaritmik sıkıştırma
                if norm_val > 0.9:
                    # 0.9-1.0 arası yumuşak sıkıştırma
                    excess = norm_val - 0.9
                    norm_val = 0.9 + (excess * 0.5)  # %50 sıkıştırma
                
                # 0-1 arası kesin clamp ve VISUAL_SCALE uygula
                norm_val = max(0.0, min(1.0, norm_val)) * self.VISUAL_SCALE
                normalized.append(norm_val)
        else:
            normalized = [0.0] * NUM_DISPLAY_BARS
        
        clean = normalized
        n = len(clean)
        
        # İlk karede eski değer yoksa oluştur
        if not hasattr(self, "smooth_bands") or len(self.smooth_bands) != n:
            self.smooth_bands = [0.0] * n

        # Per-bar peak caps (Angolla style)
        if not hasattr(self, "bar_caps") or len(self.bar_caps) != n:
            self.bar_caps = [0.0] * n

        # ========== 4. ANGOLLA TARZI SMOOTHING (Seri Hareket Ayarları) ==========
        parent = self.parent()
        if isinstance(parent, VisualizationWindow):
            parent = parent.player
        is_web = isinstance(parent, AngollaPlayer) and getattr(parent, "search_mode", "") == "web"

        # Attack: hızlı yükseliş (Web için çok daha seri: 0.85)
        # Release: kontrollü düşüş (Web için daha hızlı: 0.45)
        ATTACK = 0.96 if is_web else 0.85
        RELEASE = 0.65 if is_web else 0.50
        
        out = [0.0] * n
        
        for i in range(n):
            prev = self.smooth_bands[i]
            new = clean[i]
            
            # Hesaplama: yükseldiğinde ATTACK, düştüğünde RELEASE kullan
            if new > prev:
                v = prev + (new - prev) * ATTACK
            else:
                v = prev + (new - prev) * RELEASE
            
            # ========== 5. MAKSIMUM DEĞER SINIRLA (CLAMP) ==========
            v = max(0.0, min(1.0, v))  # 0-1 arası tut
            
            out[i] = v

            # Caps: Çubuk başı çizgileri (Angolla style peaks)
            cap_val = self.bar_caps[i]
            if v > cap_val:
                # Cap yükselişi - anlık (daha zıplayan)
                cap_attack = 1.0
                cap_val = cap_val + (v - cap_val) * cap_attack
            else:
                # Cap düşüşü - daha hızlı sekme efekti
                cap_fall = 0.03 if is_web else 0.02
                cap_val = max(0.0, cap_val - cap_fall)
            
            # Cap'i de clamp'la
            cap_val = max(0.0, min(1.0, cap_val))
            self.bar_caps[i] = cap_val

        self.smooth_bands = out
        self.band_smoothing = out  # çizimlerde bunu kullanıyoruz

        # Genel ses yoğunluğunu da yumuşat (Daha seri tepki için ALPHA artırıldı)
        ALPHA = 0.30  # %30 yeni veri, %70 eski veri (daha seri)
        self.sound_intensity = (
            self.sound_intensity * (1.0 - ALPHA) + intensity * ALPHA
        )
        # Intensity'yi de clamp'la
        self.sound_intensity = max(0.0, min(1.0, self.sound_intensity))

        # 🎵 BASS / MID / TREBLE ANALİZİ (Yeni modlar için)
        self._analyze_frequency_ranges(clean)

        # Yeniden çiz
        self.update()

    def _analyze_frequency_ranges(self, band_data):
        """
        FFT bantlarını bass/mid/treble'a ayırır.
        - Bass: 0-10 (20Hz-250Hz)
        - Mid: 10-40 (250Hz-2kHz)
        - Treble: 40-96 (2kHz-20kHz)
        """
        if len(band_data) < 96:
            self.bass_intensity = 0.0
            self.mid_intensity = 0.0
            self.treble_intensity = 0.0
            return
        
        bass_bands = band_data[0:10]
        mid_bands = band_data[10:40]
        treble_bands = band_data[40:96]
        
        # Ortalama al
        self.bass_intensity = sum(bass_bands) / len(bass_bands) if bass_bands else 0.0
        self.mid_intensity = sum(mid_bands) / len(mid_bands) if mid_bands else 0.0
        self.treble_intensity = sum(treble_bands) / len(treble_bands) if treble_bands else 0.0
        
        # Sensitivity uygula
        sens_factor = self.vis_sensitivity / 50.0
        self.bass_intensity *= sens_factor
        self.mid_intensity *= sens_factor
        self.treble_intensity *= sens_factor
        
        # 0-1 aralığında tut
        self.bass_intensity = max(0.0, min(1.0, self.bass_intensity))
        self.mid_intensity = max(0.0, min(1.0, self.mid_intensity))
        self.treble_intensity = max(0.0, min(1.0, self.treble_intensity))
        
        # Pulse Explosion için bass tetikleyici
        if self.bass_intensity > 0.6 and len(self.energy_pulses) < 3:
            self._spawn_energy_pulse()


    def _apply_force(self, magnitude: float):
        """Parçacıklara rastgele yönlü kuvvet uygular (çizgi modu için)."""
        if not self.particles:
            return

        for p in self.particles:
            angle = random.uniform(0.0, 6.28318)  # ~2π
            if np is not None:
                fx = float(np.cos(angle)) * magnitude
                fy = float(np.sin(angle)) * magnitude
            else:
                fx = random.uniform(-1, 1) * magnitude
                fy = random.uniform(-1, 1) * magnitude

            p["vel"] = QPointF(
                p["vel"].x() + fx,
                p["vel"].y() + fy
            )

    # ------------------------------------------------------------------#
    # ANİMASYON
    # ------------------------------------------------------------------#

    def update_animation(self):
        current_time = time.time()
        dt = current_time - self.last_update_time
        self.last_update_time = current_time

        if dt <= 0:
            return

        if self._visualizer_paused:
            if self._visualizer_fade:
                self._fade_visual_state()
            self.update()
            return

        w, h = self.width(), self.height()
        if w <= 0 or h <= 0:
            return

        self.bar_phase += dt * 3.0
        self.rainbow_phase = (self.rainbow_phase + dt * 200.0) % 360.0  # Çok hızlı RGB klavye efekti
        # Alt ritim çubukları için daha yavaş ve akıcı renk akışı
        self.status_rainbow_phase = (self.status_rainbow_phase + dt * 30.0) % 360.0

        intensity_factor = self.sound_intensity * 0.7 + 0.3
        speed_factor = dt * 120.0

        if self.vis_mode == "Çizgiler" and self.particles and self.show_full_visual:
            # Ses yoğunluğuna göre parçacıklara kuvvet uygula
            force_magnitude = self.sound_intensity * 0.02
            self._apply_force(force_magnitude)
            
            for p in self.particles:
                p["prev_pos"] = QPointF(p["pos"].x(), p["pos"].y())

                p["vel"] = QPointF(
                    p["vel"].x() * 0.93,
                    p["vel"].y() * 0.93
                )

                cx, cy = 0.5, 0.5
                pull_x = (cx - p["pos"].x()) * 0.001 * (1.0 - self.sound_intensity)
                pull_y = (cy - p["pos"].y()) * 0.001 * (1.0 - self.sound_intensity)
                p["vel"] = QPointF(
                    p["vel"].x() + pull_x,
                    p["vel"].y() + pull_y
                )

                p["pos"] = QPointF(
                    p["pos"].x() + p["vel"].x() * speed_factor * intensity_factor,
                    p["pos"].y() + p["vel"].y() * speed_factor * intensity_factor,
                )

                p["pos"] = QPointF(
                    max(0.01, min(0.99, p["pos"].x())),
                    max(0.01, min(0.99, p["pos"].y())),
                )

        self.update()

    # ------------------------------------------------------------------#
    # ÇİZİM
    # ------------------------------------------------------------------#

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()

        painter.fillRect(self.rect(), self.background_color)

        if not self.band_smoothing:
            painter.end()
            return

        display_data = self.band_smoothing

        if not self.show_full_visual:
            self._draw_status_bars(painter, w, h, display_data)
            painter.end()
            return

        effective_mode = self.vis_mode

        if effective_mode == "Çizgiler":
            self._draw_lines_mode(painter, w, h)
        elif effective_mode == "Daireler":
            self._draw_circles_mode(painter, w, h, display_data)
        elif effective_mode == "Spektrum Çubukları":
            self._draw_spectrum_mode(painter, w, h, display_data)
        elif effective_mode == "Angolla Analyzer":
            self._draw_angolla_bar_analyzer(painter, w, h, display_data)
        elif effective_mode == "Angolla Turbine":
            self._draw_angolla_turbine(painter, w, h, display_data)
        elif effective_mode == "Angolla Boom":
            self._draw_angolla_boom(painter, w, h, display_data)
        elif effective_mode == "Angolla Block":
            self._draw_angolla_block(painter, w, h, display_data)
        elif effective_mode == "Enerji Halkaları":
            self._draw_energy_rings_mode(painter, w, h, display_data)
        elif effective_mode == "Dalga Formu":
            self._draw_waveform_mode(painter, w, h, display_data)
        elif effective_mode == "Pulsar":
            self._draw_pulsar_mode(painter, w, h, display_data)
        elif effective_mode == "Spiral":
            self._draw_spiral_mode(painter, w, h, display_data)
        elif effective_mode == "Volcano":
            self._draw_volcano_mode(painter, w, h, display_data)
        elif effective_mode == "Işın Çakışması":
            self._draw_beam_collision_mode(painter, w, h, display_data)
        elif effective_mode == "Çift Spektrum":
            self._draw_dual_spectrum_mode(painter, w, h, display_data)
        elif effective_mode == "Radyal Izgara":
            self._draw_radial_grid_mode(painter, w, h, display_data)
        elif effective_mode == "Parıltı Dalgası":
            self._draw_shimmer_wave_mode(painter, w, h, display_data)
        elif effective_mode == "Neon Aura":
            self._draw_neon_aura_mode(painter, w, h, display_data)
        elif effective_mode == "Kristal Spektrum":
            self._draw_crystal_spectrum_mode(painter, w, h, display_data)
        elif effective_mode == "İnferno":
            self._draw_inferno_mode(painter, w, h, display_data)
        elif effective_mode == "Aurora":
            self._draw_aurora_mode(painter, w, h, display_data)
        elif effective_mode == "3D Çubuklar":
            self._draw_bars3d_mode(painter, w, h, display_data)
        elif effective_mode == "Çiçek":
            self._draw_flower_mode(painter, w, h, display_data)
        elif effective_mode == "Gelişmiş Dalga":
            self._draw_waveform_advanced_mode(painter, w, h, display_data)
        elif effective_mode == "Energy Ring":
            self._draw_energy_ring_mode(painter, w, h, display_data)
        elif effective_mode == "Circular Waveform":
            self._draw_circular_waveform(painter, w, h, display_data)
        elif effective_mode == "3D Swirl":
            self._draw_3d_swirl_mode(painter, w, h, display_data)
        elif effective_mode == "Pulse Explosion":
            self._draw_pulse_explosion(painter, w, h, display_data)
        elif effective_mode == "Tunnel Mode":
            self._draw_tunnel_mode(painter, w, h, display_data)
        elif effective_mode == "Winamp Retro":
            self._draw_winamp_retro(painter, w, h, display_data)
        elif effective_mode == "Milkdrop Pulse":
            self._draw_milkdrop_pulse(painter, w, h, display_data)
        elif effective_mode == "Starfield Bass":
            self._draw_starfield_bass(painter, w, h, display_data)
        elif effective_mode == "Plasma Flow":
            self._draw_plasma_flow(painter, w, h, display_data)
        elif effective_mode == "Grid Warp":
            self._draw_grid_warp(painter, w, h, display_data)
        elif effective_mode == "Particle Rain":
            self._draw_particle_rain(painter, w, h, display_data)
        elif effective_mode == "Hex Pulse":
            self._draw_hex_pulse(painter, w, h, display_data)
        elif effective_mode == "Neon Horizon":
            self._draw_neon_horizon(painter, w, h, display_data)
        elif effective_mode == "Spectrum Tunnel":
            self._draw_spectrum_tunnel(painter, w, h, display_data)
        elif effective_mode == "Wave Orbit":
            self._draw_wave_orbit(painter, w, h, display_data)
        elif effective_mode == "Ayna":  # 🪞 YENİ: Ayna (Mirror) modu
            self._draw_mirror_mode(painter, w, h, display_data)

        painter.end()

    def _apply_mode_preset(self, mode: str):
        """Mod bazlı küçük stil dokunuşları."""
        # 🌈 Gökkuşağı Aura modları - RGB renk döngüsü (VARSAYILAN)
        # Tüm modlarda varsayılan olarak RGB modu aktif
        self.bar_color_mode = "RGB"  # Varsayılan rainbow efekti
        
        if mode in ("Winamp Retro", "Spectrum Tunnel", "Wave Orbit", "Ayna"):
            self.bar_style_mode = "glass"
        elif mode in ("Milkdrop Pulse", "Hex Pulse"):
            self.bar_style_mode = "luminous"
        elif mode in ("Starfield Bass", "Particle Rain"):
            self.bar_style_mode = "thin_caps"
        elif mode == "Plasma Flow":
            self.bar_style_mode = "gradient"
        elif mode == "Grid Warp":
            self.bar_style_mode = "pixel"
        elif mode == "Neon Horizon":
            self.bar_style_mode = "glass"
        elif mode == "Spektrum Çubukları":  # Default mode için de RGB aktif
            self.bar_style_mode = "solid_with_cap"
        elif mode == "Angolla Analyzer":
            self.bar_style_mode = "solid_with_cap"
            # Angolla barlar için tek renk döngüsü (orijinal tarza yakın)
            if self.bar_color_mode == "NORMAL":
                self.bar_color_mode = "RGB"
            self._clem_state = None  # Renk/ölçek yeniden hesaplansın
        elif mode == "Angolla Turbine":
            self.bar_style_mode = "solid_with_cap"
            if self.bar_color_mode == "NORMAL":
                self.bar_color_mode = "RGB"
            self._clem_turbine_state = None
        elif mode == "Angolla Boom":
            self.bar_style_mode = "solid_with_cap"
            if self.bar_color_mode == "NORMAL":
                self.bar_color_mode = "RGB"
            self._clem_boom_state = None
        elif mode == "Angolla Block":
            self.bar_style_mode = "solid_with_cap"
            if self.bar_color_mode == "NORMAL":
                self.bar_color_mode = "RGB"
            self._clem_block_state = None

    def _ensure_angolla_state(self, w: int, h: int, band_count: int):
        """
        Angolla Bar Analyzer için durum (roof, gradient, mapper) önbelleği.
        Orijinal kColumnWidth, roof düşüş hızı ve log ölçeklemeyi uygular.
        """
        if w <= 0 or h <= 0 or band_count <= 0:
            return None

        fg = QColor(self.primary_color)
        bg = QColor(self.background_color)
        key = (w, h, band_count, fg.rgb(), bg.rgb(), bool(self.psychedelic_mode))

        if self._clem_state and self._clem_state.get("key") == key:
            return self._clem_state

        max_down = -max(1, h // 50)
        max_up = max(1, h // 25)
        # Log ölçek (Angolla baranalyzer ile aynı yaklaşım)
        F = (h - 2) / (math.log10(255) * 1.0) if h > 2 else 1.0
        lvl_mapper = [int(F * math.log10(x + 1)) for x in range(256)]

        bar_positions = [0] * band_count
        roof_positions = [h - 5] * band_count
        roof_velocity = [self.CLEM_ROOF_VELOCITY_REDUCTION] * band_count
        roof_mem = [[] for _ in range(band_count)]

        # Roof için gradient (fg -> bg)
        if self.CLEM_NUM_ROOFS > 1:
            dr = (bg.red() - fg.red()) / float(self.CLEM_NUM_ROOFS - 1)
            dg = (bg.green() - fg.green()) / float(self.CLEM_NUM_ROOFS - 1)
            db = (bg.blue() - fg.blue()) / float(self.CLEM_NUM_ROOFS - 1)
        else:
            dr = dg = db = 0.0
        roof_colors = [
            QColor(
                fg.red() + int(dr * i),
                fg.green() + int(dg * i),
                fg.blue() + int(db * i),
                255,
            )
            for i in range(self.CLEM_NUM_ROOFS)
        ]

        # Bar gradient renkleri
        bar_base_color = QColor(fg)
        bar_base_color.setAlpha(230)
        bar_top_color = QColor(
            min(fg.red() + 40, 255),
            min(fg.green() + 40, 255),
            min(fg.blue() + 40, 255),
            255,
        )

        self._clem_state = {
            "key": key,
            "lvl_mapper": lvl_mapper,
            "bar_positions": bar_positions,
            "roof_positions": roof_positions,
            "roof_velocity": roof_velocity,
            "roof_mem": roof_mem,
            "roof_colors": roof_colors,
            "bar_base_color": bar_base_color,
            "bar_top_color": bar_top_color,
            "max_down": max_down,
            "max_up": max_up,
            "count": band_count,
            "size": (w, h),
        }
        return self._clem_state

    def _draw_angolla_bar_analyzer(self, painter, w, h, data):
        """
        Angolla Bar Analyzer portu:
        - Log ölçekli amplitude → yükseklik eşlemesi (lvl_mapper)
        - Roof/peak çizgileri ve düşüş hızı
        - Motion blur için roof geçmişi
        - Gradient barlar ve tek renkli (veya psychedelic) döngü
        """
        if not data:
            return

        state = self._ensure_angolla_state(w, h, len(data))
        if not state:
            return

        count = state["count"]
        step = w / max(count, 1)
        gap = max(1, int(step * 0.15))
        bar_w = max(2, int(step - gap))
        max_h = h - 2

        painter.setRenderHint(QPainter.Antialiasing, True)

        # Psychedelic açıkken bar rengi frame bazında döner
        use_psychedelic = self.psychedelic_mode or (
            self.bar_color_mode in ("RGB", "GRADYAN")
        )
        if use_psychedelic:
            hue = int(self.rainbow_phase % 360)
            base_color = QColor.fromHsv(hue, 240, 255, 220)
            top_color = QColor.fromHsv(hue, 200, 255, 255)
            roof_colors = [
                QColor.fromHsv(
                    hue,
                    180,
                    255 - int((i / max(self.CLEM_NUM_ROOFS - 1, 1)) * 120),
                    255,
                )
                for i in range(self.CLEM_NUM_ROOFS)
            ]
        else:
            base_color = state["bar_base_color"]
            top_color = state["bar_top_color"]
            roof_colors = state["roof_colors"]

        for i in range(count):
            v = max(0.0, min(1.0, data[i]))
            idx = min(255, int(v * 255))
            y2 = state["lvl_mapper"][idx]
            y2 = max(1, min(max_h, y2))

            change = y2 - state["bar_positions"][i]
            if change < state["max_down"]:
                y2 = state["bar_positions"][i] + state["max_down"]

            # Roof güncelle
            if y2 > state["roof_positions"][i]:
                state["roof_positions"][i] = y2
                state["roof_velocity"][i] = 1

            state["bar_positions"][i] = y2

            x = int(i * step)

            # Roof geçmişini çiz (motion blur etkisi)
            mem = state["roof_mem"][i]
            if mem:
                for c, mem_y in enumerate(mem):
                    if c >= self.CLEM_NUM_ROOFS:
                        break
                    color = roof_colors[self.CLEM_NUM_ROOFS - 1 - c]
                    painter.fillRect(int(x), int(mem_y), int(bar_w), 1, color)

            # Bar gradient
            grad = QLinearGradient(0, h - y2, 0, h)
            grad.setColorAt(0.0, top_color)
            grad.setColorAt(1.0, base_color)
            painter.fillRect(int(x), int(h - y2), int(bar_w), int(y2), grad)

            # Peak cap (roof)
            cap_y = h - state["roof_positions"][i] - 2
            cap_color = QColor(top_color)
            cap_color.setAlpha(255)
            painter.fillRect(int(x), int(cap_y), int(bar_w), 2, cap_color)

            mem.append(h - state["roof_positions"][i] - 2)
            if len(mem) > self.CLEM_NUM_ROOFS:
                mem.pop(0)

        # Roof düşüş hızı (orijinaldeki roofVelocity mantığı)
        for i in range(count):
            if state["roof_velocity"][i] != 0:
                if state["roof_velocity"][i] > self.CLEM_ROOF_VELOCITY_REDUCTION:
                    state["roof_positions"][i] -= (
                        state["roof_velocity"][i] - self.CLEM_ROOF_VELOCITY_REDUCTION
                    ) / 20.0

                if state["roof_positions"][i] < 0:
                    state["roof_positions"][i] = 0
                    state["roof_velocity"][i] = 0
                else:
                    state["roof_velocity"][i] += 1

    def _ensure_angolla_turbine_state(self, w: int, h: int, band_count: int):
        if w <= 0 or h <= 0 or band_count <= 0:
            return None
        fg = QColor(self.primary_color)
        bg = QColor(self.background_color)
        key = (w, h, band_count, fg.rgb(), bg.rgb(), bool(self.psychedelic_mode))
        if self._clem_turbine_state and self._clem_turbine_state.get("key") == key:
            return self._clem_turbine_state

        hd2 = h // 2
        F = (h - 2) / (math.log10(255) * 1.0) if h > 2 else 1.0
        cw = max(3, int(w / max(1, band_count * 1.1)))
        gap = 1
        bar_h = [0.0] * band_count
        peak_h = [0.0] * band_count
        peak_speed = [0.01] * band_count

        base_color = QColor(fg)
        base_color.setAlpha(230)
        top_color = QColor(
            min(fg.red() + 40, 255),
            min(fg.green() + 40, 255),
            min(fg.blue() + 40, 255),
            255,
        )
        midlight = QColor(bg).lighter(180)

        self._clem_turbine_state = {
            "key": key,
            "hd2": hd2,
            "F": F,
            "cw": cw,
            "gap": gap,
            "bar_h": bar_h,
            "peak_h": peak_h,
            "peak_speed": peak_speed,
            "base_color": base_color,
            "top_color": top_color,
            "midlight": midlight,
        }
        return self._clem_turbine_state

    def _draw_angolla_turbine(self, painter, w, h, data):
        """
        Angolla Turbine: merkezden yukarı/aşağı simetrik barlar + tepe çizgileri.
        """
        state = self._ensure_angolla_turbine_state(w, h, len(data))
        if not state:
            return

        hd2 = state["hd2"]
        kMaxHeight = max(1, hd2 - 1)
        cw = state["cw"]
        gap = state["gap"]
        step = cw + gap
        F = state["F"]

        use_psychedelic = self.psychedelic_mode or (
            self.bar_color_mode in ("RGB", "GRADYAN")
        )
        if use_psychedelic:
            hue = int(self.rainbow_phase % 360)
            base_color = QColor.fromHsv(hue, 240, 255, 220)
            top_color = QColor.fromHsv(hue, 180, 255, 255)
            midlight = QColor.fromHsv(hue, 180, 255, 200)
        else:
            base_color = state["base_color"]
            top_color = state["top_color"]
            midlight = state["midlight"]

        for i, v in enumerate(data):
            v = max(0.0, min(1.0, v))
            h_val = 0.0
            if v > 0.0:
                h_val = math.log10(v * 256.0) * F * 0.5
            if h_val > kMaxHeight:
                h_val = float(kMaxHeight)

            if h_val > state["bar_h"][i]:
                state["bar_h"][i] = h_val
                if h_val > state["peak_h"][i]:
                    state["peak_h"][i] = h_val
                    state["peak_speed"][i] = 0.01
            else:
                if state["bar_h"][i] > 0.0:
                    state["bar_h"][i] = max(0.0, state["bar_h"][i] - 1.4)
                if state["peak_h"][i] > 0.0:
                    state["peak_h"][i] -= state["peak_speed"][i]
                    state["peak_speed"][i] *= 1.12
                    state["peak_h"][i] = max(
                        0.0, max(state["bar_h"][i], state["peak_h"][i])
                    )

            x = int(i * step)
            y_top = int(hd2 - state["bar_h"][i])
            bar_h_px = int(state["bar_h"][i])

            grad = QLinearGradient(0, y_top, 0, hd2)
            grad.setColorAt(0.0, top_color)
            grad.setColorAt(1.0, base_color)
            painter.fillRect(x + gap // 2, y_top, cw, bar_h_px, grad)
            painter.fillRect(x + gap // 2, hd2, cw, bar_h_px, grad)

            painter.setPen(base_color)
            if bar_h_px > 0:
                painter.drawRect(x, y_top, cw, bar_h_px * 2)

            painter.setPen(midlight)
            peak_y_top = int(hd2 - state["peak_h"][i])
            peak_y_bottom = int(hd2 + state["peak_h"][i])
            painter.drawLine(x, peak_y_top, x + cw, peak_y_top)
            painter.drawLine(x, peak_y_bottom, x + cw, peak_y_bottom)

    def _ensure_angolla_boom_state(self, w: int, h: int, band_count: int):
        if w <= 0 or h <= 0 or band_count <= 0:
            return None
        fg = QColor(self.primary_color)
        bg = QColor(self.background_color)
        key = (w, h, band_count, fg.rgb(), bg.rgb(), bool(self.psychedelic_mode))
        if self._clem_boom_state and self._clem_boom_state.get("key") == key:
            return self._clem_boom_state

        HEIGHT = h - 2
        cw = max(3, int(w / max(1, band_count * 1.1)))
        gap = 1
        F = HEIGHT / (math.log10(256) * 1.1) if HEIGHT > 0 else 1.0
        bar_h = [0.0] * band_count
        peak_h = [0.0] * band_count
        peak_speed = [0.01] * band_count

        base_color = QColor(fg)
        base_color.setAlpha(230)
        top_color = QColor(
            min(fg.red() + 40, 255),
            min(fg.green() + 40, 255),
            min(fg.blue() + 40, 255),
            255,
        )
        midlight = QColor(bg).lighter(180)

        self._clem_boom_state = {
            "key": key,
            "HEIGHT": HEIGHT,
            "cw": cw,
            "gap": gap,
            "F": F,
            "bar_h": bar_h,
            "peak_h": peak_h,
            "peak_speed": peak_speed,
            "base_color": base_color,
            "top_color": top_color,
            "midlight": midlight,
        }
        return self._clem_boom_state

    def _draw_angolla_boom(self, painter, w, h, data):
        """
        Angolla Boom: alt hizalı barlar + tepe çizgisi.
        """
        state = self._ensure_angolla_boom_state(w, h, len(data))
        if not state:
            return

        HEIGHT = state["HEIGHT"]
        cw = state["cw"]
        gap = state["gap"]
        step = cw + gap
        F = state["F"]

        use_psychedelic = self.psychedelic_mode or (
            self.bar_color_mode in ("RGB", "GRADYAN")
        )
        if use_psychedelic:
            hue = int(self.rainbow_phase % 360)
            base_color = QColor.fromHsv(hue, 240, 255, 220)
            top_color = QColor.fromHsv(hue, 180, 255, 255)
            midlight = QColor.fromHsv(hue, 160, 255, 200)
        else:
            base_color = state["base_color"]
            top_color = state["top_color"]
            midlight = state["midlight"]

        for i, v in enumerate(data):
            v = max(0.0, min(1.0, v))
            h_val = 0.0
            if v > 0.0:
                h_val = math.log10(v * 256.0) * F
            h_val = min(h_val, float(HEIGHT))

            if h_val > state["bar_h"][i]:
                state["bar_h"][i] = h_val
                if h_val > state["peak_h"][i]:
                    state["peak_h"][i] = h_val
                    state["peak_speed"][i] = 0.01
            else:
                if state["bar_h"][i] > 0.0:
                    state["bar_h"][i] = max(0.0, state["bar_h"][i] - 1.27)
                if state["peak_h"][i] > 0.0:
                    state["peak_h"][i] -= state["peak_speed"][i]
                    state["peak_speed"][i] *= 1.103
                    if state["peak_h"][i] < state["bar_h"][i]:
                        state["peak_h"][i] = state["bar_h"][i]
                    state["peak_h"][i] = max(0.0, state["peak_h"][i])

            x = int(i * step)
            bar_h_px = int(state["bar_h"][i])
            y = h - bar_h_px

            grad = QLinearGradient(0, y, 0, h)
            grad.setColorAt(0.0, top_color)
            grad.setColorAt(1.0, base_color)
            painter.fillRect(x + gap // 2, y, cw, bar_h_px, grad)

            painter.setPen(base_color)
            if bar_h_px > 0:
                painter.drawRect(x, y, cw, bar_h_px)

            peak_y = int(h - state["peak_h"][i])
            painter.setPen(midlight)
            painter.drawLine(x, peak_y, x + cw, peak_y)

    def _ensure_angolla_block_state(self, w: int, h: int, band_count: int):
        if w <= 0 or h <= 0 or band_count <= 0:
            return None
        fg = QColor(self.primary_color)
        bg = QColor(self.background_color)
        key = (w, h, band_count, fg.rgb(), bg.rgb(), bool(self.psychedelic_mode))
        if self._clem_block_state and self._clem_block_state.get("key") == key:
            return self._clem_block_state

        block_h = max(3, int(h / 40))  # hedef 30-40 satır
        rows = max(8, min(80, h // block_h))
        block_w = max(4, int(w / max(8, band_count)))
        gap = 1

        PRE = 1.0
        PRO = 1.0
        SCL = math.log10(PRE + PRO + rows)
        thresholds = [1.0 - math.log10(PRE + z) / SCL for z in range(rows)]
        thresholds.append(0.0)

        fade = [[0.0 for _ in range(rows)] for _ in range(band_count)]

        self._clem_block_state = {
            "key": key,
            "rows": rows,
            "block_w": block_w,
            "block_h": block_h,
            "gap": gap,
            "thresholds": thresholds,
            "fade": fade,
            "fg": fg,
            "bg": bg,
        }
        return self._clem_block_state

    def _draw_angolla_block(self, painter, w, h, data):
        """
        Angolla Block Analyzer: grid üzerinde bar blokları (basitleştirilmiş).
        """
        state = self._ensure_angolla_block_state(w, h, len(data))
        if not state:
            return

        rows = state["rows"]
        block_w = state["block_w"]
        block_h = state["block_h"]
        gap = state["gap"]
        thresholds = state["thresholds"]
        fade = state["fade"]

        use_psychedelic = self.psychedelic_mode or (
            self.bar_color_mode in ("RGB", "GRADYAN")
        )

        for i, v in enumerate(data):
            v = max(0.0, min(1.0, v))
            # Yüksekliği log ölçekle
            if v > 0.0:
                scaled = math.log10(v * 256.0) / math.log10(256.0)
            else:
                scaled = 0.0
            active_row = 0
            for r in range(rows):
                if scaled >= thresholds[r]:
                    active_row = r
                    break
            for r in range(rows):
                # aktif veya fade
                if r >= active_row:
                    fade[i][r] = 1.0
                else:
                    fade[i][r] *= 0.90

                if fade[i][r] < 0.02:
                    continue

                alpha = int(60 + fade[i][r] * 195)
                if use_psychedelic:
                    hue = int((self.rainbow_phase + (i * 10) + r * 4) % 360)
                    color = QColor.fromHsv(hue, 220, 255, alpha)
                else:
                    color = QColor(state["fg"])
                    color.setAlpha(alpha)

                x = int(i * (block_w + gap))
                y = int(h - (r + 1) * (block_h + gap))
                painter.fillRect(x, y, block_w, block_h, color)
    def _draw_lines_mode(self, painter, w, h):
        """Çizgiler modu - parçacık sistemi ile dinamik hareket."""
        if not self.particles:
            return
        
        r, g, b, _ = self.primary_color.getRgb()
        
        # Parçacıklar arasında çizgiler ve dinamik renkler
        for i, p in enumerate(self.particles):
            sx = int(p["prev_pos"].x() * w)
            sy = int(p["prev_pos"].y() * h)
            ex = int(p["pos"].x() * w)
            ey = int(p["pos"].y() * h)

            # Hız-temelli renk (spektrum)
            speed = (p["vel"].x() ** 2 + p["vel"].y() ** 2) ** 0.5
            hue = (speed * 100 + i * (360 / len(self.particles))) % 360
            color = QColor.fromHsv(int(hue), 200, 255, int(80 + 150 * self.sound_intensity))
            
            alpha = int(120 + 135 * self.sound_intensity)
            thickness = 1 + int(self.sound_intensity * 4)
            
            pen = QPen(color, thickness)
            pen.setCapStyle(Qt.RoundCap)
            painter.setPen(pen)
            painter.drawLine(sx, sy, ex, ey)

    def _draw_circles_mode(self, painter, w, h, data):
        """Daireler modu - merkez etrafında pulsating halkalar."""
        if not data:
            return

        cx, cy = w // 2, h // 2
        max_r = min(w, h) // 2

        bass = data[0] * 0.8 + (data[1] * 0.2 if len(data) > 1 else 0.0)
        base_r = max_r * 0.15
        cur_r = base_r + max_r * 0.7 * bass

        # Merkez halka - gradient efekti
        painter.setPen(QPen(QColor.fromHsv(int(self.bar_phase * 2) % 360, 255, 255), 3))
        painter.setBrush(QBrush(QColor(
            self.primary_color.red(),
            self.primary_color.green(),
            self.primary_color.blue(),
            60,
        )))
        painter.drawEllipse(int(cx - cur_r), int(cy - cur_r),
                            int(cur_r * 2), int(cur_r * 2))

        # Spektrum noktaları - renkli ve dinamik
        band_count = len(data)
        for i in range(band_count):
            angle = i * (360 / band_count)
            factor = 1.0 - (i / band_count) * 0.5
            dist = max_r * 0.75 * factor
            if np is not None:
                x = cx + int(dist * np.cos(np.deg2rad(angle)))
                y = cy + int(dist * np.sin(np.deg2rad(angle)))
            else:
                x, y = cx, cy
            
            size = 12 + data[i] * 40 * self.sound_intensity
            alpha = int(120 + data[i] * 135)
            
            # Spektrum renk - angle-temelli
            hue = (angle + self.bar_phase) % 360
            color = QColor.fromHsv(int(hue), 255, 255, alpha)
            
            painter.setPen(Qt.NoPen)
            painter.setBrush(QBrush(color))
            painter.drawEllipse(int(x - size / 2),
                                int(y - size / 2),
                                int(size), int(size))

    def _draw_spectrum_mode(self, painter, w, h, data):
        """
        Angolla Tarzı Spektrum Çubukları - Gerçek FFT Tabanlı Görselleştirme
        
        ÖZELLİKLER:
        - 96 bantlı logaritmik frekans spektrumu (20Hz-20kHz)
        - Smooth attack/release ile yumuşak animasyon
        - Per-bar peak caps (Angolla tarzı tepeler)
        - Gradient HSV renklendirme (bass: mavi → treble: kırmızı)
        - Anti-aliasing ile pürüzsüz çizim
        - EQ kazançlarına duyarlı
        """
        if not data or len(data) == 0:
            return
        
        count = len(data)
        bar_w = max(2, w / count)  # Minimum 2px genişlik
        gap = max(1, int(bar_w * 0.15))  # Çubuklar arası boşluk
        actual_bar_w = bar_w - gap
        
        max_h = h * 0.90  # Üstte %10 boşluk bırak
        
        # Anti-aliasing aktif
        painter.setRenderHint(QPainter.Antialiasing, True)
        
        # Eğer bar_color_mode ayarlanmışsa kullan
        use_gradient = (self.bar_color_mode == "RGB" or self.bar_color_mode == "GRADYAN")
        
        for i in range(count):
            v = data[i]  # Zaten VISUAL_SCALE uygulanmış
            
            # Çubuk yüksekliği - sensitivity etkisi azaltıldı (VISUAL_SCALE için)
            sens_multiplier = 0.9 + (self.vis_sensitivity / 100.0) * 0.3  # 0.9-1.2 arası
            bar_h = int(v * max_h * sens_multiplier)
            bar_h = max(1, min(bar_h, int(max_h)))  # Sınırlar içinde tut
            
            x = int(i * bar_w)
            y = h - bar_h
            
            # Renk hesaplama
            # 🌈 PSYCHEDELIC COLORS (Angolla tarzı) - TEK RENK DÖNGÜSÜ
            if getattr(self, 'psychedelic_mode', False) or use_gradient:
                # Kullanıcı isteği: "Herbir ritim çubuğu için değil, hepsi bir renk efekti olsun"
                # Yani tüm çubuklar AYNI anda AYNI rengi alarak döngüye girsin.
                
                rainbow_offset = self.rainbow_phase # Zamanla değişen açı (0-360)
                
                # Tüm çubuklar aynı hue değerini alır (Uniform Color Cycle)
                hue = rainbow_offset % 360
                
                saturation = int(0.95 * 255)
                # Parse göre parlaklık değişimi (opsiyonel derinlik)
                value = int((0.75 + v * 0.25) * 255)
                alpha = int(180 + v * 75)
                bar_color = QColor.fromHsv(int(hue), saturation, value, alpha)
                
                # Yüksekliğe göre parlaklık
                base_value = 75 + (v * 25)
                value = int((base_value / 100.0) * 255)
                value = min(255, value)
                
                # Alpha: yüksekliğe göre opaklık
                alpha = int(160 + v * 95)
                
                bar_color = QColor.fromHsv(int(hue), saturation, value, alpha)
            else:
                # Normal mod: Tema rengi kullan
                bar_color = QColor(self._cached_bar_color)
                # Yüksekliğe göre alpha ayarla
                alpha = int(160 + v * 95)
                bar_color.setAlpha(alpha)
            
            # Çubuk çiz - yuvarlatılmış köşeler
            painter.setPen(Qt.NoPen)
            painter.setBrush(QBrush(bar_color))
            
            if actual_bar_w >= 4:
                # Geniş çubuklar: rounded rect
                painter.drawRoundedRect(
                    int(x + gap/2), y, 
                    int(actual_bar_w), bar_h,
                    2, 2  # Köşe yuvarlatma
                )
            else:
                # İnce çubuklar: basit rect
                painter.drawRect(int(x + gap/2), y, int(actual_bar_w), bar_h)
            
            # Peak cap (Angolla tarzı tepe çizgisi)
            if hasattr(self, 'bar_caps') and i < len(self.bar_caps):
                cap_val = self.bar_caps[i]
                cap_h = int(cap_val * max_h * sens_multiplier)
                
                if cap_h > 3:  # Minimum görünür yükseklik
                    cap_y = h - cap_h - 2  # 2px yukarıda
                    cap_thickness = 3
                    
                    # Cap rengi: Bar renginden daha parlak
                    if use_gradient:
                        cap_color = QColor.fromHsv(int(hue), saturation // 2, 255, 255)
                    else:
                        cap_color = QColor(self._cached_cap_color)
                    
                    painter.setBrush(QBrush(cap_color))
                    painter.drawRect(
                        int(x + gap/2), cap_y,
                        int(actual_bar_w), cap_thickness
                    )
            
            # Parlama efekti - çubuğun tepesinde (isteğe bağlı)
            if bar_h > 10 and self.vis_color_intensity > 50:
                glow_h = min(5, bar_h // 3)
                glow_alpha = int((self.vis_color_intensity - 50) * 2.5)  # 0-125
                
                if use_gradient:
                    glow_color = QColor.fromHsv(int(hue), saturation // 3, 255, glow_alpha)
                else:
                    glow_color = QColor(bar_color)
                    glow_color.setAlpha(glow_alpha)
                
                painter.setBrush(QBrush(glow_color))
                painter.drawRect(
                    int(x + gap/2), y,
                    int(actual_bar_w), glow_h
                )

    def _draw_energy_rings_mode(self, painter, w, h, data):
        """Enerji Halkaları - konsantrik halkalar spektrum göstergesi."""
        cx, cy = w // 2, h // 2
        max_r = min(w, h) // 2 * 0.85
        count = len(data)
        
        for i in range(count):
            v = data[i]
            base = max_r * (1 - (i / count) * 0.7)
            offset = max_r * 0.15 * v * self.sound_intensity
            cur_r = base + offset
            alpha = int(70 + v * 185)
            
            # Spektrum renk - frequency-temelli
            hue = (i / count * 360 + self.bar_phase) % 360
            color = QColor.fromHsv(int(hue), 255, 255, alpha)
            
            pen_width = 2 + v * 5
            pen = QPen(color, pen_width)
            pen.setCapStyle(Qt.RoundCap)
            
            painter.setPen(pen)
            painter.setBrush(Qt.NoBrush)
            painter.drawEllipse(int(cx - cur_r), int(cy - cur_r),
                                int(cur_r * 2), int(cur_r * 2))
            
            # İç halka - daha dim
            inner_color = QColor.fromHsv(int(hue), 255, 200, int(alpha * 0.3))
            inner_pen = QPen(inner_color, 1)
            painter.setPen(inner_pen)
            painter.drawEllipse(int(cx - cur_r * 0.8), int(cy - cur_r * 0.8),
                               int(cur_r * 1.6), int(cur_r * 1.6))

    def _draw_waveform_mode(self, painter, w, h, data):
        """Dalga formu görselleştirmesi - spektrum barlarının dalga şeklinde animasyonu."""
        if not data or len(data) == 0:
            return
        
        # NumPy gerekli
        if np is None:
            # NumPy yoksa basit bar göster
            self._draw_spectrum_mode(painter, w, h, data)
            return
        
        cx, cy = w // 2, h // 2
        count = len(data)
        
        # Zaman tabanlı faz
        phase = self.bar_phase * 0.05
        
        painter.setPen(Qt.NoPen)
        
        for i in range(count):
            # Normalize indeks
            t = i / max(count - 1, 1)
            
            # Sinüs dalgası - yükseklik ve X pozisyonu
            wave_x = w * t
            
            # Temel yükseklik: FFT veri
            base_height = data[i] * h * 0.4
            
            # Dalga animasyonu - zaman tabanlı
            wave_offset = np.sin(t * 4 * np.pi + phase) * 30
            
            # Y konumu (merkez etrafında)
            wave_y = cy + wave_offset
            
            # Yarıçap/boyut - FFT veriye bağlı
            radius = 4 + data[i] * 20
            alpha = int(100 + data[i] * 155)
            
            # Renk - spektrum
            hue = (t * 360) % 360
            color = QColor.fromHsv(int(hue), 255, 255, alpha)
            
            painter.setBrush(QBrush(color))
            painter.drawEllipse(int(wave_x - radius), int(wave_y - radius),
                               int(radius * 2), int(radius * 2))
            
            # Alt dalga - simetrik
            if i % 3 == 0:  # Her 3. noktada bağlantı çizgisi
                if i < count - 1:
                    next_t = (i + 1) / count
                    next_wave_x = w * next_t
                    next_wave_y = cy + (np.sin(next_t * 4 * np.pi + phase) * 30)
                    
                    color.setAlpha(50)
                    painter.setPen(QPen(color, 2))
                    painter.drawLine(int(wave_x), int(wave_y), int(next_wave_x), int(next_wave_y))
                    painter.setPen(Qt.NoPen)

    def _draw_pulsar_mode(self, painter, w, h, data):
        """Pulsar modu - merkezden dışarı doğru pulsating ışınlar."""
        if not data:
            return
        
        cx, cy = w // 2, h // 2
        count = len(data)
        max_r = min(w, h) // 2 * 0.8
        
        for i in range(count):
            v = data[i]
            angle = i * (360 / count)
            
            # Merkezden dışarı doğru ışın
            length = max_r * (0.3 + v * 0.7)
            
            if np is not None:
                end_x = cx + int(length * np.cos(np.deg2rad(angle)))
                end_y = cy + int(length * np.sin(np.deg2rad(angle)))
            else:
                end_x, end_y = cx, cy
            
            # Spektrum renk
            hue = (angle + self.bar_phase) % 360
            color = QColor.fromHsv(int(hue), 255, 255, int(150 + v * 105))
            
            thickness = 2 + v * 8
            pen = QPen(color, thickness)
            pen.setCapStyle(Qt.RoundCap)
            
            painter.setPen(pen)
            painter.drawLine(int(cx), int(cy), int(end_x), int(end_y))

    def _draw_spiral_mode(self, painter, w, h, data):
        """Spiral modu - spektrum verisi spiral şeklinde."""
        if not data:
            return
        
        cx, cy = w // 2, h // 2
        count = len(data)
        max_r = min(w, h) // 2 * 0.85
        
        if np is None:
            # NumPy yoksa basit daireler çiz
            for i in range(count):
                v = data[i]
                radius = max_r * (i / count) * (0.3 + v * 0.7)
                hue = (i / count * 360) % 360
                color = QColor.fromHsv(int(hue), 255, 255, int(100 + v * 155))
                painter.setPen(QPen(color, 2))
                painter.setBrush(Qt.NoBrush)
                painter.drawEllipse(int(cx - radius), int(cy - radius), int(radius * 2), int(radius * 2))
            return
        
        # Spiral - her bar başında bir nokta
        for i in range(count):
            v = data[i]
            t = i / count
            
            # Spiral radiusu: dışa doğru gidiyor
            radius = max_r * t * (0.4 + v * 0.6)
            
            # Spiral angle: dönüyor
            angle = t * 720 + self.bar_phase  # 2 tam dönüş
            
            x = cx + int(radius * np.cos(np.deg2rad(angle)))
            y = cy + int(radius * np.sin(np.deg2rad(angle)))
            
            # Spektrum renk
            hue = (angle) % 360
            color = QColor.fromHsv(int(hue), 255, 255, int(120 + v * 135))
            
            size = 4 + v * 16
            painter.setPen(Qt.NoPen)
            painter.setBrush(QBrush(color))
            painter.drawEllipse(int(x - size / 2), int(y - size / 2), int(size), int(size))

    def _draw_volcano_mode(self, painter, w, h, data):
        """Volcano modu - merkezden patlayan parçacıklar."""
        if not data:
            return
        
        cx, cy = w // 2, h // 2
        count = len(data)
        max_h = h * 0.45
        
        if np is None:
            # NumPy yoksa basit bar çiz
            self._draw_spectrum_mode(painter, w, h, data)
            return
        
        for i in range(count):
            v = data[i]
            angle = i * (360 / count)
            
            # Yükseklik - FFT veri
            height = max_h * v * (0.5 + self.sound_intensity * 0.5)
            
            # Parçacıkları merkezden dışarı çıkart
            for j in range(5):  # Her bar'dan 5 parçacık
                offset_angle = angle + (j - 2) * 15  # Biraz açısallık
                particle_dist = height * (j / 5)
                
                x = cx + int(particle_dist * np.cos(np.deg2rad(offset_angle)))
                y = cy - int(particle_dist * np.sin(np.deg2rad(offset_angle)))  # Yukarı çıkıyor
                
                # Spektrum renk + yükseklik tabanlı alpha
                hue = (angle + self.bar_phase) % 360
                alpha = int(200 * (1 - j / 5))  # Yukarı gittikçe şeffaflık
                color = QColor.fromHsv(int(hue), 255, 255, alpha)
                
                size = 6 * (1 - j / 5)
                painter.setPen(Qt.NoPen)
                painter.setBrush(QBrush(color))
                painter.drawEllipse(int(x - size / 2), int(y - size / 2), int(size), int(size))

    def _draw_beam_collision_mode(self, painter, w, h, data):
        """Işın Çakışması: merkezden çıkan kalın ışınların çarpıştığı efekt."""
        if not data:
            return
        cx, cy = w // 2, h // 2
        count = len(data)
        max_len = min(w, h) * 0.6

        for i in range(count):
            v = data[i]
            angle = (i / count) * 360 + (self.bar_phase * 0.5)
            length = max_len * (0.2 + v * 0.8)

            if np is not None:
                ex = cx + int(length * np.cos(np.deg2rad(angle)))
                ey = cy + int(length * np.sin(np.deg2rad(angle)))
            else:
                ex, ey = cx, cy

            hue = (angle) % 360
            color = QColor.fromHsv(int(hue), 200, 255, int(120 + v * 135))
            pen = QPen(color, 4 + v * 10)
            pen.setCapStyle(Qt.FlatCap)
            painter.setPen(pen)
            painter.drawLine(cx, cy, ex, ey)

        # Çarpışma noktalarında parlama
        for i in range(3):
            t = (self.bar_phase * 0.2 + i) % 1.0
            idx = int(t * count)
            val = data[idx]
            hue = (idx / max(1, count) * 360) % 360
            glow = QColor.fromHsv(int(hue), 255, 255, int(180 + val * 75))
            painter.setBrush(QBrush(glow))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(cx - 6, cy - 6, 12, 12)

    def _draw_dual_spectrum_mode(self, painter, w, h, data):
        """Çift Spektrum: yukarı ve aşağı simetrik spektrum çubukları."""
        count = len(data)
        if count == 0:
            return
        bar_w = w / count
        mid = h // 2
        for i in range(count):
            v = data[i]
            bar_h = int(v * (h * 0.45) * (0.6 + self.sound_intensity * 0.6))
            x = int(i * bar_w)

            hue = (i / count * 360) % 360
            color_top = QColor.fromHsv(int(hue), 220, 255, int(140 + v * 115))
            color_bot = QColor.fromHsv((int(hue) + 180) % 360, 220, 255, int(140 + v * 115))

            painter.setBrush(QBrush(color_top))
            painter.setPen(Qt.NoPen)
            painter.drawRect(x + 1, mid - bar_h, int(bar_w) - 2, bar_h)

            painter.setBrush(QBrush(color_bot))
            painter.drawRect(x + 1, mid + 1, int(bar_w) - 2, bar_h)

    def _draw_radial_grid_mode(self, painter, w, h, data):
        """Radyal Izgara: merkezden dışa doğru ızgara + radyal çubuklar."""
        if not data:
            return
        cx, cy = w // 2, h // 2
        max_r = min(w, h) // 2 * 0.9
        count = len(data)

        # Izgara halkaları
        rings = 6
        for r in range(1, rings + 1):
            rr = (r / rings) * max_r
            alpha = int(30 + (r / rings) * 100)
            color = QColor(200, 200, 200, alpha)
            painter.setPen(QPen(color, 1))
            painter.setBrush(Qt.NoBrush)
            painter.drawEllipse(int(cx - rr), int(cy - rr), int(rr * 2), int(rr * 2))

        # Radyal çubuklar
        for i in range(count):
            v = data[i]
            angle = (i / count) * 360 + self.bar_phase
            length = max_r * (0.15 + v * 0.85)
            if np is not None:
                ex = cx + int(length * np.cos(np.deg2rad(angle)))
                ey = cy + int(length * np.sin(np.deg2rad(angle)))
            else:
                ex, ey = cx, cy
            hue = (i / count * 360) % 360
            color = QColor.fromHsv(int(hue), 200, 255, int(110 + v * 120))
            pen = QPen(color, 2)
            pen.setCapStyle(Qt.RoundCap)
            painter.setPen(pen)
            painter.drawLine(cx, cy, ex, ey)

    def _draw_shimmer_wave_mode(self, painter, w, h, data):
        """Parıltı Dalgası: dalgalı çizgiler + şimmer parçacıkları."""
        if not data:
            return
        cx, cy = w // 2, h // 2
        max_r = min(w, h) // 2 * 0.7
        count = len(data)

        # Dalgalı çizgiler
        path = QPainterPath()
        for i in range(count):
            v = data[i] * max_r
            angle = (i / count) * 2 * 3.14159
            if np is not None:
                x = cx + int((max_r * 0.3 + v) * np.cos(angle))
                y = cy + int((max_r * 0.3 + v) * np.sin(angle))
            else:
                x = cx + int((max_r * 0.3 + v) * (1 if i % 2 else -1))
                y = cy + int((max_r * 0.3 + v) * (1 if (i // 2) % 2 else -1))
            if i == 0:
                path.moveTo(x, y)
            else:
                path.lineTo(x, y)

        # Ana dalga çizgisi
        hue = int((self.bar_phase / 360) * 360) % 360
        color = QColor.fromHsv(hue, 200, 255, 180)
        pen = QPen(color, 2)
        pen.setCapStyle(Qt.RoundCap)
        painter.setPen(pen)
        painter.drawPath(path)

        # Şimmer parçacıkları
        num_particles = max(5, int(count * 0.3))
        for i in range(num_particles):
            angle = (i / num_particles) * 2 * 3.14159 + self.bar_phase * 0.01
            intensity = data[int((i / num_particles) * (count - 1))] if count > 0 else 0
            r = max_r * 0.2 + intensity * max_r * 0.5
            if np is not None:
                px = cx + int(r * np.cos(angle))
                py = cy + int(r * np.sin(angle))
            else:
                px = cx + int(r)
                py = cy
            size = int(2 + intensity * 6)
            glow_color = QColor.fromHsv(hue, 100, 255, int(100 * intensity))
            painter.setBrush(glow_color)
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(int(px - size/2), int(py - size/2), size, size)

    def _draw_neon_aura_mode(self, painter, w, h, data):
        """Neon Aura: parlayan halkalar + neon renkler."""
        if not data:
            return
        cx, cy = w // 2, h // 2
        max_r = min(w, h) // 2 * 0.8
        count = len(data)

        # Konsantrik parlayan halkalar
        num_rings = 6
        for ring in range(num_rings):
            ring_data = data[int(ring * count / num_rings):int((ring + 1) * count / num_rings)]
            if not ring_data:
                continue
            avg_intensity = sum(ring_data) / len(ring_data)
            
            # Halka çapı
            r = max_r * ((ring + 1) / num_rings)
            
            # Neon rengi (mor/pembe -> mavi -> turkuaz)
            hue = (ring * 60 + self.bar_phase * 0.5) % 360
            color = QColor.fromHsv(int(hue), 255, 255, int(150 + avg_intensity * 100))
            
            # Parlama (glow) efekti
            painter.setPen(QPen(color, 2))
            painter.setBrush(Qt.NoBrush)
            painter.drawEllipse(int(cx - r), int(cy - r), int(r * 2), int(r * 2))
            
            # Daha açık renkle iç halka
            glow_color = QColor.fromHsv(int(hue), 150, 255, int(80 + avg_intensity * 50))
            painter.setPen(QPen(glow_color, 1))
            painter.drawEllipse(int(cx - r * 0.95), int(cy - r * 0.95), int(r * 1.9), int(r * 1.9))

    def _draw_crystal_spectrum_mode(self, painter, w, h, data):
        """Kristal Spektrum: geometrik kaleidoskop + spektrum çubukları."""
        if not data:
            return
        cx, cy = w // 2, h // 2
        max_r = min(w, h) // 2 * 0.85
        count = len(data)

        # Geometrik bölümler (kaleidoskop efekti)
        num_segments = 12
        for seg in range(num_segments):
            angle1 = (seg / num_segments) * 360
            angle2 = ((seg + 1) / num_segments) * 360
            
            # Bölümdeki veri ortalaması
            seg_data = data[int(seg * count / num_segments):int((seg + 1) * count / num_segments)]
            if not seg_data:
                continue
            avg_v = sum(seg_data) / len(seg_data)
            
            # Radyal çizgiler
            if np is not None:
                x1 = cx + int(max_r * np.cos(np.deg2rad(angle1)))
                y1 = cy + int(max_r * np.sin(np.deg2rad(angle1)))
                x2 = cx + int(max_r * np.cos(np.deg2rad(angle2)))
                y2 = cy + int(max_r * np.sin(np.deg2rad(angle2)))
            else:
                x1 = cx + int(max_r * (1 if seg % 2 else -1))
                y1 = cy + int(max_r * (1 if (seg // 2) % 2 else -1))
                x2 = cx
                y2 = cy
            
            # Çubuklar
            hue = (angle1 + self.bar_phase * 0.5) % 360
            color = QColor.fromHsv(int(hue), 200, 255, int(120 + avg_v * 120))
            pen = QPen(color, 3)
            pen.setCapStyle(Qt.RoundCap)
            painter.setPen(pen)
            
            # İçten dışa çizgiler (spektrum)
            inner_r = max_r * 0.2
            if np is not None:
                ix1 = cx + int(inner_r * np.cos(np.deg2rad(angle1)))
                iy1 = cy + int(inner_r * np.sin(np.deg2rad(angle1)))
                ix2 = cx + int(inner_r * np.cos(np.deg2rad(angle2)))
                iy2 = cy + int(inner_r * np.sin(np.deg2rad(angle2)))
            else:
                ix1 = cx + int(inner_r)
                iy1 = cy
                ix2 = cx
                iy2 = cy + int(inner_r)
            
            outer_r = inner_r + (max_r - inner_r) * avg_v
            if np is not None:
                ox1 = cx + int(outer_r * np.cos(np.deg2rad(angle1)))
                oy1 = cy + int(outer_r * np.sin(np.deg2rad(angle1)))
                ox2 = cx + int(outer_r * np.cos(np.deg2rad(angle2)))
                oy2 = cy + int(outer_r * np.sin(np.deg2rad(angle2)))
            else:
                ox1 = cx + int(outer_r)
                oy1 = cy
                ox2 = cx
                oy2 = cy + int(outer_r)
            
            painter.drawLine(int(ix1), int(iy1), int(ox1), int(oy1))
            painter.drawLine(int(ix2), int(iy2), int(ox2), int(oy2))

    def _draw_inferno_mode(self, painter, w, h, data):
        """İnferno: Ateş gibi parçacıklar + gradient sahne."""
        if not data:
            return
        cx, cy = w // 2, h // 2
        max_r = min(w, h) // 2 * 0.8
        count = len(data)

        # Arka plan gradient (koyu -> turuncu)
        gradient = QRadialGradient(cx, cy, max_r)
        gradient.setColorAt(0, QColor(255, 100, 0, 50))
        gradient.setColorAt(1, QColor(0, 0, 0, 200))
        painter.fillRect(0, 0, w, h, gradient)

        # Ateş gibi parçacıklar
        for i in range(count):
            v = data[i]
            angle = (i / count) * 360 + self.bar_phase
            r = max_r * (0.2 + v * 0.8)
            
            if np is not None:
                x = cx + int(r * np.cos(np.deg2rad(angle)))
                y = cy + int(r * np.sin(np.deg2rad(angle)))
            else:
                x = cx + int(r)
                y = cy

            # Renk: sarı -> turuncu -> kırmızı (sıcaklığa göre)
            intensity_color = int(v * 60)  # 0-60 hue (sarı-kırmızı)
            color = QColor.fromHsv(40 - intensity_color, 255, int(200 + v * 55), int(150 + v * 105))
            
            size = int(3 + v * 12)
            painter.setBrush(color)
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(int(x - size/2), int(y - size/2), size, size)

    def _draw_aurora_mode(self, painter, w, h, data):
        """Aurora: Şimal ışıkları tarzı dalgalı renkler."""
        if not data:
            return
        cx, cy = w // 2, h // 2
        count = len(data)

        # Arka plan koyu
        painter.fillRect(0, 0, w, h, QColor(10, 20, 40, 255))

        # Dalgalı Aurora çizgileri
        num_waves = 8
        for wave in range(num_waves):
            path = QPainterPath()
            wave_offset = (wave / num_waves) * h
            
            for x in range(0, w, 5):
                frac = x / max(1, w)
                idx = int(frac * (count - 1))
                v = data[idx] if idx < len(data) else 0
                
                # Dalgalı Y pozisyonu
                y = cy + (v - 0.5) * h * 0.4 + wave_offset - h/2
                
                if x == 0:
                    path.moveTo(x, int(y))
                else:
                    path.lineTo(x, int(y))

            # Aurora renkleri (mavi-yeşil-mor)
            hue = (wave * 45 + self.bar_phase * 0.3) % 360
            color = QColor.fromHsv(int(hue), 200, 200, int(100 + (wave / num_waves) * 100))
            pen = QPen(color, 3)
            pen.setCapStyle(Qt.RoundCap)
            painter.setPen(pen)
            painter.drawPath(path)

    def _draw_bars3d_mode(self, painter, w, h, data):
        """3D Çubuklar: İzometrik görünümlü spektrum çubukları."""
        if not data:
            return
        
        count = len(data)
        bar_width = 2.0
        spacing = 0.0
        if count > 1:
            total = bar_width * count
            if w > total:
                spacing = (w - total) / (count - 1)
        
        # Perspektif için Z derinliği
        depth = h * 0.3
        
        for i in range(count):
            v = data[i]
            x = i * (bar_width + spacing)
            bar_height = v * (h - depth)
            
            hue = (i / count * 360) % 360
            base_color = QColor.fromHsv(int(hue), 200, 255, int(180 + v * 75))
            
            # Ön yüz (en parlak)
            painter.fillRect(int(x), int(h - bar_height), int(bar_width), int(bar_height), base_color)
            
            # Sağ yüz (perspektif - biraz karanlık)
            dark_color = QColor.fromHsv(int(hue), 200, 200, int(150 + v * 60))
            points_right = [
                QPointF(int(x + bar_width), int(h - bar_height)),
                QPointF(int(x + bar_width + depth * 0.3), int(h - bar_height - depth * 0.2)),
                QPointF(int(x + bar_width + depth * 0.3), int(h - depth * 0.2)),
                QPointF(int(x + bar_width), int(h))
            ]
            painter.setBrush(dark_color)
            painter.setPen(Qt.NoPen)
            painter.drawPolygon(points_right)
            
            # Üst yüz (hafif açı - en parlak)
            top_color = QColor.fromHsv(int(hue), 150, 255, int(200 + v * 55))
            points_top = [
                QPointF(int(x), int(h - bar_height)),
                QPointF(int(x + depth * 0.3), int(h - bar_height - depth * 0.2)),
                QPointF(int(x + bar_width + depth * 0.3), int(h - bar_height - depth * 0.2)),
                QPointF(int(x + bar_width), int(h - bar_height))
            ]
            painter.setBrush(top_color)
            painter.drawPolygon(points_top)

    def _draw_flower_mode(self, painter, w, h, data):
        """Çiçek: Merkezi açan çiçek tarzı görselleştirme."""
        if not data:
            return
        cx, cy = w // 2, h // 2
        count = len(data)
        max_r = min(w, h) // 2 * 0.75

        # Arka plan
        painter.fillRect(0, 0, w, h, QColor(15, 15, 25, 255))

        # Yapraklar (petals)
        num_petals = count // 8 if count > 0 else 12
        for petal in range(num_petals):
            angle = (petal / max(1, num_petals)) * 360
            
            # Bu yapraktaki ortalama değer
            petal_data = data[int(petal * count / num_petals):int((petal + 1) * count / num_petals)]
            avg_v = sum(petal_data) / len(petal_data) if petal_data else 0
            
            petal_length = max_r * (0.3 + avg_v * 0.7)
            
            if np is not None:
                px = cx + int(petal_length * np.cos(np.deg2rad(angle)))
                py = cy + int(petal_length * np.sin(np.deg2rad(angle)))
            else:
                px = cx + int(petal_length)
                py = cy

            # Yaprak rengi
            hue = (angle + self.bar_phase * 0.2) % 360
            color = QColor.fromHsv(int(hue), 220, 255, int(130 + avg_v * 125))
            
            # Glow effect (açık renk)
            glow_color = QColor.fromHsv(int(hue), 150, 255, int(80 + avg_v * 80))
            pen_glow = QPen(glow_color, 4)
            painter.setPen(pen_glow)
            painter.drawLine(cx, cy, px, py)
            
            # Ana çizgi (daha kalın)
            pen_main = QPen(color, 2)
            painter.setPen(pen_main)
            painter.drawLine(cx, cy, px, py)
            
            # Yaprak ucu (daire)
            size = int(4 + avg_v * 10)
            painter.setBrush(color)
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(int(px - size/2), int(py - size/2), size, size)

    def _draw_waveform_advanced_mode(self, painter, w, h, data):
        """Gelişmiş Dalga Formu: Stéréo-benzeri parlak dalgalar."""
        if not data:
            return
        
        count = len(data)
        mid_y = h // 2
        
        # Arka plan (koyu gradient)
        gradient = QLinearGradient(0, 0, 0, h)
        gradient.setColorAt(0, QColor(20, 20, 40))
        gradient.setColorAt(0.5, QColor(10, 10, 30))
        gradient.setColorAt(1, QColor(20, 20, 40))
        painter.fillRect(0, 0, w, h, gradient)

        # İki dalga (üst + alt = stereo tarzı)
        for offset in [-1, 1]:  # Üst (-1) ve alt (+1)
            path = QPainterPath()
            
            for i in range(count):
                v = data[i]
                x = (i / max(1, count - 1)) * w
                
                # Dalga yüksekliği
                y_offset = v * (mid_y * 0.8) * offset
                y = mid_y + y_offset
                
                if i == 0:
                    path.moveTo(x, y)
                else:
                    path.cubicTo(path.currentPosition().x(), path.currentPosition().y(), x, y, x, y)

            # Renk (offset'e göre farklı)
            if offset == -1:
                color = QColor(100, 200, 255, 180)  # Mavi-cyan üst
            else:
                color = QColor(255, 100, 200, 180)  # Pembe-magenta alt

            pen = QPen(color, 2.5)
            pen.setCapStyle(Qt.RoundCap)
            painter.setPen(pen)
            painter.drawPath(path)

        # Merkez çizgisi
        painter.setPen(QPen(QColor(200, 200, 200, 100), 1))
        painter.drawLine(0, mid_y, w, mid_y)

    def _draw_status_bars(self, painter, w, h, display_data):
        """
        Angolla tarzı ritim çubukları - basit ve temiz.
        Tüm ekran alanını dolduruyor. Sağ kenarı garantile.
        """
        if not display_data or w <= 0 or h <= 0:
            return

        # Eğer stil Angolla seçildiyse aynı bar analyzer portunu kullan
        style_mode = getattr(self, "bar_style_mode", "")
        if style_mode == "angolla":
            self._draw_angolla_bar_analyzer(painter, w, h, display_data)
            return
        if style_mode == "turbin":
            self._draw_angolla_turbine(painter, w, h, display_data)
            return
        if style_mode == "boom":
            self._draw_angolla_boom(painter, w, h, display_data)
            return
        if style_mode == "block":
            self._draw_angolla_block(painter, w, h, display_data)
            return

        # Gösterilecek bar sayısı - update_sound_data ile senkronize et
        NUM_BARS = len(display_data)
        raw = list(display_data)[:NUM_BARS]
        
        if len(raw) == 0:
            return

        # Yumuşatma (flicker engellemek için)
        SMOOTH_FACTOR = 0.7
        if not hasattr(self, "bar_smooth_values"):
            self.bar_smooth_values = [0.0] * NUM_BARS
        else:
            # Eğer bar sayısı değiştiyse önceki array'i uzat
            if len(self.bar_smooth_values) < NUM_BARS:
                self.bar_smooth_values += [0.0] * (NUM_BARS - len(self.bar_smooth_values))
        
        smoothed_bars = []
        for i in range(NUM_BARS):
            raw_val = raw[i] if i < len(raw) else 0.0
            smoothed = self.bar_smooth_values[i] * SMOOTH_FACTOR + raw_val * (1.0 - SMOOTH_FACTOR)
            smoothed_bars.append(smoothed)
        
        self.bar_smooth_values = smoothed_bars[:]

        # Çubuk boyutu - ekranı tam olarak dolduracak şekilde hesapla,
        # ama küçük bir boşluk bırak (gap) -> çubuklar ayrı görünsün
        band_area = float(w) / NUM_BARS
        gap = min(2, max(0, int(band_area * 0.25)))
        bar_height_max = h * 0.9
        bottom_margin = h * 0.1

        left_color = QColor(120, 40, 255)
        right_color = QColor(255, 120, 40)
        
        # Çubuk stil modu (solid / striped / dots)
        bar_style = getattr(self, 'bar_style_mode', 'solid')
        
        painter.setPen(Qt.NoPen)

        for i in range(NUM_BARS):
            # Normalize değeri al (zaten VISUAL_SCALE uygulanmış)
            val = max(0.0, min(1.0, smoothed_bars[i]))
            
            # Bass boost - hafif (VISUAL_SCALE sonrası için uyarlandı)
            bass_mul = 1.0 + (1.0 - min(i, NUM_BARS * 0.3) / (NUM_BARS * 0.3)) * 0.1
            
            # Ses şiddeti etkisi - minimal (VISUAL_SCALE zaten uygulandı)
            intensity_mul = 0.8 + self.sound_intensity * 0.4  # 0.8-1.2 arası
            
            # Nihai yükseklik
            height = int(val * bar_height_max * intensity_mul * bass_mul)
            height = max(3, min(int(bar_height_max), height))
            
            # Cap yüksekliği (çubuk başı çizgisinin konumu)
            cap_val = self.bar_caps[i] if i < len(self.bar_caps) else 0.0
            cap_height = int(cap_val * bar_height_max * intensity_mul * bass_mul)
            cap_height = max(0, min(int(bar_height_max), cap_height))
            
            # Pozisyon - tüm çubukları dahil et, sağ kenarı kaçırma
            x_start = i * band_area
            x_end = (i + 1) * band_area
            x = int(round(x_start))
            next_x = w if i == NUM_BARS - 1 else int(round(x_end))
            raw_w = max(1, next_x - x)
            effective_gap = min(gap, max(0, raw_w - 1))
            draw_w = max(1, raw_w - effective_gap)
            y = int(h - bottom_margin - height)
            cap_y = int(h - bottom_margin - cap_height)

            t = i / max(1, NUM_BARS - 1)
            base = QColor(
                int(left_color.red() + (right_color.red() - left_color.red()) * t),
                int(left_color.green() + (right_color.green() - left_color.green()) * t),
                int(left_color.blue() + (right_color.blue() - left_color.blue()) * t),
            )
            bar_color = QColor(base)
            bar_color.setAlpha(int(180 + val * 75))
            cap_color = QColor(base)
            cap_color.setAlpha(255)

            # Çubuk stilü uygula
            self._draw_bar_style(
                painter, x + effective_gap // 2, y, draw_w, height,
                bar_style, bar_color, cap_color, cap_y, i, NUM_BARS
            )

    def _draw_bar_style(self, painter, x, y, w, h, style, color, cap_color, cap_y=None, i=0, count=1):
        """Çubuk stiline göre çiz. Cap_y cap konumunu gösterir."""
        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(color))
        
        if style == "striped":
            # Yatay çizgiler
            line_height = 2
            gap_height = 2
            for yy in range(y, y + h, line_height + gap_height):
                painter.drawRect(x, yy, w, line_height)
        elif style == "dots":
            # Nokta deseni
            dot_size = 3
            for xx in range(x, x + w, dot_size + 2):
                for yy in range(y, y + h, dot_size + 2):
                    painter.drawEllipse(xx, yy, dot_size, dot_size)
        elif style == "solid_with_cap":
            # Düz çubuk + başında cap çizgisi
            painter.drawRect(x, y, w, h)
            # Cap çizgisi - ince (çubuk kalınlığı kadar) ve şeffaf
            cap_line_color = QColor(color)
            cap_line_color.setAlpha(255)  # Tamamen opak
            painter.setPen(QPen(cap_line_color, 1))  # İnce çizgi (1px)
            if cap_y is not None:
                painter.drawLine(x, cap_y, x + w, cap_y)
            else:
                painter.drawLine(x, y, x + w, y)
            painter.setPen(Qt.NoPen)
        elif style == "glass":
            grad = QLinearGradient(x, y, x, y + h)
            grad.setColorAt(0.0, QColor(color).lighter(140))
            grad.setColorAt(0.5, QColor(color))
            grad.setColorAt(1.0, QColor(color).darker(140))
            painter.setBrush(QBrush(grad))
            painter.drawRoundedRect(x, y, w, h, 2, 2)
        elif style == "outline":
            pen = QPen(color, max(1, w // 6))
            painter.setPen(pen)
            painter.setBrush(Qt.NoBrush)
            painter.drawRoundedRect(x, y, w, h, 1, 1)
            painter.setPen(Qt.NoPen)
        elif style == "gradient":
            grad = QLinearGradient(x, y, x + w, y + h)
            grad.setColorAt(0.0, QColor(color).lighter(120))
            grad.setColorAt(1.0, QColor(color).darker(120))
            painter.setBrush(QBrush(grad))
            painter.drawRect(x, y, w, h)
        elif style == "rounded":
            painter.drawRoundedRect(x, y, w, h, 3, 3)
        elif style == "capsule":
            painter.drawRoundedRect(x, y, w, h, h * 0.4, h * 0.4)
        elif style == "hollow":
            pen = QPen(color, 2)
            painter.setPen(pen)
            painter.setBrush(Qt.NoBrush)
            painter.drawRect(x, y, w, h)
            painter.setPen(Qt.NoPen)
        elif style == "pixel":
            for yy in range(y, y + h, 3):
                painter.drawRect(x, yy, w, 2)
        elif style == "tri_step":
            step = max(2, h // 6)
            cur_y = y + h
            width = w
            while cur_y > y:
                painter.drawRect(x, cur_y - step, width, step)
                cur_y -= step
                width = max(1, int(width * 0.92))
        elif style == "luminous":
            glow = QColor(color)
            glow.setAlpha(120)
            painter.setBrush(QBrush(glow))
            painter.drawRoundedRect(x - 2, y - 2, w + 4, h + 4, 3, 3)
            painter.setBrush(QBrush(color))
            painter.drawRoundedRect(x, y, w, h, 3, 3)
        elif style == "neon_glow":
            # Neon parlama efekti - dış kayıtşık glow
            glow_size = max(2, int(w * 0.4))
            glow_color = QColor(color)
            glow_color.setAlpha(60)  # Şeffaf glow
            painter.setBrush(QBrush(glow_color))
            painter.drawRoundedRect(x - glow_size, y - glow_size, 
                                   w + glow_size * 2, h + glow_size * 2, 4, 4)
            # Ana çubuk - parlak renk
            painter.setBrush(QBrush(color))
            painter.drawRoundedRect(x, y, w, h, 2, 2)
        elif style == "turbin":
            # Türbin - Dönen spiral efekt
            angle = (self.bar_phase * 5 + i * 10) % 360  # Rotasyon
            painter.save()
            painter.translate(x + w//2, y + h//2)
            painter.rotate(angle)
            painter.drawRect(-w//2, -h//2, w, h)
            painter.restore()
        elif style == "boom":
            # Boom Çözümleyici - Bass vurgulu patlayıcı efekt
            # Bass frekanslarına (ilk çubuklar) özel vurgu
            bass_boost = 1.0 + (1.0 - i / count) * 0.5  # Düşük frekans boost
            boosted_h = int(h * bass_boost)
            
            # Ana çubuk
            painter.drawRect(x, y, w, boosted_h)
            
            # Patlama efekti - bass için ekstra glow
            if i < count * 0.3:  # İlk %30 (bass bölgesi)
                glow = QColor(color)
                glow.setAlpha(80)
                painter.setBrush(QBrush(glow))
                glow_h = min(10, h // 10)
                painter.drawRect(x - 1, y - glow_h, w + 2, glow_h)
        else:  # solid (varsayılan)
            # Düz çubuk
            painter.drawRect(x, y, w, h)

    def _show_bar_context_menu(self, point):
        """Çubuklar için sağ tıklama menüsü - renk ve stil seçenekleri."""
        menu = QMenu(self)
        
        # Renk seçenekleri alt menüsü
        color_menu = QMenu("🎨 Renk Seç", self)
        
        # Hazır renkler - daha fazla seçenek
        colors = {
            "AURA Mavi": "#40C4FF",
            "Zümrüt Yeşil": "#00E676",
            "Güneş Turuncusu": "#FF9800",
            "Kırmızı Ateş": "#FF1744",
            "Mor Gece": "#7C4DFF",
            "Pembe": "#FF69B4",
            "Cyan": "#00BCD4",
            "Kehribar": "#FFC107",
            "Lime": "#C6FF00",
        }
        
        for color_name, color_hex in colors.items():
            act = QAction(color_name, self)
            act.triggered.connect(
                lambda checked=False, ch=color_hex: self._set_bar_color(ch)
            )
            color_menu.addAction(act)
        
        menu.addMenu(color_menu)

        # Stil seçenekleri alt menüsü
        style_menu = QMenu("📊 Çubuk Stili", self)
        
        styles = [
            "solid", "solid_with_cap", "glass", "rounded", "capsule",
            "neon_glow", "luminous", "pixel", "striped", "dots", "hollow",
            "outline", "gradient", "tri_step", "turbin", "boom", "block", "angolla"
        ]
        style_names = {
            "solid": "⬜ Klasik Düz",
            "solid_with_cap": "📍 Çubuk Başlı",
            "glass": "💎 Cam Parlak",
            "rounded": "🔵 Yuvarlatılmış",
            "capsule": "💊 Kapsül",
            "neon_glow": "✨ Neon Işık",
            "luminous": "💫 Parlayan",
            "pixel": "🎨 Piksel Retro",
            "striped": "📏 Yatay Çizgiler",
            "dots": "⚪ Noktalar",
            "hollow": "⬛ İçi Boş",
            "outline": "📐 Kontur",
            "gradient": "🌈 Gradyan",
            "tri_step": "🔺 Üçlü Adım",
            "turbin": "🌀 Türbin",
            "boom": "💥 Boom",
            "block": "🧱 Block Analyzer",
            "angolla": "🎵 Angolla (roof + blur)"
        }
        
        for style in styles:
            act = QAction(style_names.get(style, style), self)
            act.setCheckable(True)
            act.setChecked(style == getattr(self, 'bar_style_mode', 'solid'))
            act.triggered.connect(
                lambda checked=False, s=style: self._set_bar_style(s)
            )
            style_menu.addAction(act)
        
        menu.addMenu(style_menu)
        
        # 🌈 Psychedelic Colors seçeneği (RGB rainbow mode)
        menu.addSeparator()
        psychedelic_act = QAction("🌈 Psychedelic Colors", self)
        psychedelic_act.setCheckable(True)
        psychedelic_act.setChecked(self.bar_color_mode == "RGB")
        psychedelic_act.triggered.connect(self._toggle_psychedelic_mode)
        menu.addAction(psychedelic_act)
        
        menu.exec_(self.mapToGlobal(point))

    def _set_bar_color(self, color_hex: str):
        """Çubuk rengini ayarla - hex renk veya özel modlar (RGB, GRADYAN)."""
        # Özel modlar
        if color_hex == "RGB":
            # RGB Işıklar modu - her bar farklı renk (spektrum)
            self.bar_color_mode = "RGB"
            if hasattr(self, 'parent_player'):
                self.parent_player.config_data['bar_color'] = "RGB"
                self.parent_player.save_config()
            self.update()
            return
        elif color_hex == "GRADYAN":
            # Neon Gradyan modu - mavi-cyan-yeşil-sarı-kırmızı
            self.bar_color_mode = "GRADYAN"
            if hasattr(self, 'parent_player'):
                self.parent_player.config_data['bar_color'] = "GRADYAN"
                self.parent_player.save_config()
            self.update()
            return
        
        # Normal hex renk
        self.bar_color_mode = "NORMAL"
        color = QColor(color_hex)
        self._cached_bar_color = QColor(color_hex)
        self._cached_bar_color.setAlpha(230)
        self._cached_cap_color = QColor(color)
        self._cached_cap_color.setRgb(
            min(color.red() + 30, 255),
            min(color.green() + 30, 255),
            min(color.blue() + 30, 255),
            255
        )
        
        # Config'e kaydet
        if hasattr(self, 'parent_player'):
            self.parent_player.config_data['bar_color'] = color_hex
            self.parent_player.save_config()
        
        self.update()

    def _set_auto_bar_color(self):
        """Albüm kapağından otomatik renk algıla - MP3 içindeki embedded art dahil."""
        if not hasattr(self, 'parent_player'):
            print("⚠️ parent_player bulunamadı - varsayılan renk kullanılıyor")
            self._set_bar_color("#40C4FF")
            return
        
        current_path = self.parent_player.current_file_path
        if not current_path:
            print("⚠️ Şu an çalan dosya yok - varsayılan renk")
            self._set_bar_color("#40C4FF")
            return
        if not PIL_AVAILABLE:
            print("⚠️ PIL/Pillow kütüphanesi yüklü değil - varsayılan renk")
            self._set_bar_color("#40C4FF")
            return

        # Albüm kapağından baskın rengi al
        try:
            from collections import Counter
            import os
            from io import BytesIO
            
            cover_image = None
            
            # 1. ÖNCELİKLE: MP3/M4A dosyasının içindeki embedded albüm kapağını kontrol et
            try:
                from mutagen import File as MutagenFile
                from mutagen.id3 import ID3, APIC
                from mutagen.mp4 import MP4
                
                audio = MutagenFile(current_path)
                
                if audio is not None:
                    # MP3 dosyası (ID3 tags)
                    if hasattr(audio, 'tags') and audio.tags:
                        for tag in audio.tags.values():
                            if isinstance(tag, APIC):  # ID3 APIC frame (albüm kapağı)
                                print(f"📸 MP3 içindeki gömülü albüm kapağı bulundu")
                                cover_image = Image.open(BytesIO(tag.data))
                                break
                    
                    # M4A/MP4 dosyası
                    if cover_image is None and isinstance(audio, MP4):
                        if 'covr' in audio.tags:
                            print(f"📸 M4A içindeki gömülü albüm kapağı bulundu")
                            cover_image = Image.open(BytesIO(audio.tags['covr'][0]))
            except Exception as e:
                print(f"⚠️ Embedded art okuma hatası: {e}")
            
            # 2. Embedded bulunamadıysa klasördeki dosyaları kontrol et
            if cover_image is None:
                folder = os.path.dirname(current_path)
                cover_path = None
                for name in ("cover.jpg", "folder.jpg", "cover.png", "album.png"):
                    p = os.path.join(folder, name)
                    if os.path.exists(p):
                        cover_path = p
                        break
                
                if cover_path:
                    print(f"📸 Klasörde albüm kapağı bulundu: {os.path.basename(cover_path)}")
                    cover_image = Image.open(cover_path)
                else:
                    print(f"⚠️ {folder} klasöründe albüm kapağı bulunamadı")
            
            # Rengi analiz et
            if cover_image:
                # Küçült ve RGB'ye çevir
                cover_image = cover_image.convert('RGB')
                cover_image.thumbnail((50, 50))  # Hızlı işlem için küçült
                
                # Pikselleri al ve en sık rengi bul
                pixels = list(cover_image.getdata())
                
                # Çok koyu ve beyaza yakın renkleri filtrele
                filtered_pixels = []
                for r, g, b in pixels:
                    # Parlaklık kontrolü (HSV V değeri)
                    brightness = max(r, g, b) / 255.0
                    # Çok koyu (brightness < 0.2) veya çok açık (brightness > 0.95) renkleri atla
                    if 0.2 < brightness < 0.95:
                        # Saturation kontrolü - gri tonları atla
                        min_rgb = min(r, g, b)
                        max_rgb = max(r, g, b)
                        if max_rgb > 0:
                            saturation = (max_rgb - min_rgb) / max_rgb
                            if saturation > 0.15:  # Minimum %15 saturation
                                filtered_pixels.append((r, g, b))
                
                # Filtrelenmiş pikseller yoksa orijinal pikselleri kullan
                if not filtered_pixels:
                    filtered_pixels = pixels
                
                # Renkleri grupla (performans için)
                reduced = [(r // 32 * 32, g // 32 * 32, b // 32 * 32) for r, g, b in filtered_pixels]
                color_count = Counter(reduced)
                
                if color_count:
                    most_common = color_count.most_common(1)[0][0]
                    r, g, b = most_common
                    
                    # Rengi biraz parlatıp vibrant yap
                    # HSV'ye çevir, V ve S'i artır
                    from colorsys import rgb_to_hsv, hsv_to_rgb
                    h, s, v = rgb_to_hsv(r/255.0, g/255.0, b/255.0)
                    
                    # Saturation'ı artır (daha canlı)
                    s = min(1.0, s * 1.3)
                    # Value'yu artır (daha parlak)
                    v = min(1.0, max(0.5, v * 1.2))
                    
                    r, g, b = hsv_to_rgb(h, s, v)
                    r, g, b = int(r * 255), int(g * 255), int(b * 255)
                    
                    # Rengi hex'e çevir
                    color_hex = f"#{r:02x}{g:02x}{b:02x}"
                    print(f"🎨 Algılanan renk (iyileştirilmiş): {color_hex}")
                    self._set_bar_color(color_hex)
                    return
                    
        except Exception as e:
            print(f"❌ Renk algılama hatası: {e}")
            pass
        
        # Fallback: varsayılan renk
        print("⚠️ Varsayılan renk kullanılıyor")
        self._set_bar_color("#40C4FF")

    def _set_bar_style(self, style: str):
        """Çubuk stilini ayarla ve config'e kaydet."""
        self.bar_style_mode = style
        if hasattr(self, 'parent_player'):
            self.parent_player.config_data['bar_style'] = style
            self.parent_player.save_config()
        self.update()

    def _toggle_psychedelic_mode(self):
        """🌈 Psychedelic Colors modunu aç/kapat (RGB rainbow cycling)"""
        # Psychedelic mode = RGB color mode (zaten mevcut ve çalışıyor)
        if self.bar_color_mode == "RGB":
            # Kapat - normal moda dön
            self.bar_color_mode = "NORMAL"
            self.psychedelic_mode = False
            print(f"🌈 Psychedelic Colors: KAPALI")
        else:
            # Aç - RGB rainbow moduna geç
            self.bar_color_mode = "RGB"
            self.psychedelic_mode = True
            print(f"🌈 Psychedelic Colors: AÇIK (RGB Mode)")
        self.update()

    # ------------------------------------------------------------------#
    # 🎇 YENİ GELİŞMİŞ GÖRSELLEŞTİRME MODLARI (Angolla Tarzı)
    # ------------------------------------------------------------------#

    def _spawn_energy_pulse(self):
        """Bass vuruşunda yeni enerji halkası oluştur"""
        w, h = self.width(), self.height()
        cx, cy = w // 2, h // 2
        max_r = min(w, h) // 2
        
        # Bass yoğunluğuna göre renk (turuncu/kırmızı)
        hue = int(20 - self.bass_intensity * 20)  # 20° (turuncu) → 0° (kırmızı)
        color = QColor.fromHsv(hue, 255, 255, 200)
        
        pulse = EnergyPulse(cx, cy, max_r * 0.8, color, lifetime=1.2)
        self.energy_pulses.append(pulse)

    def _draw_energy_ring_mode(self, painter, w, h, data):
        """
        Energy Ring / Energy Flower
        - FFT bantlarını merkezden dışa halka şeklinde çizer
        - Ses yoğunluğuna göre renk ve boyut değişir
        - Bass vuruşlarında pulsating efekt
        """
        if not data:
            return
        
        cx, cy = w // 2, h // 2
        max_r = min(w, h) // 2 * 0.85
        count = len(data)
        
        # Arka plan gradient (koyu)
        gradient = QRadialGradient(cx, cy, max_r)
        gradient.setColorAt(0, QColor(20, 10, 30, 255))
        gradient.setColorAt(1, QColor(5, 5, 15, 255))
        painter.fillRect(0, 0, w, h, gradient)
        
        # Ana enerji halkası - FFT değerlerine göre titreşen
        num_petals = min(count, 64)  # Maksimum 64 petal
        
        for i in range(num_petals):
            v = data[int(i * len(data) / num_petals)] if data else 0.0
            angle = (i / num_petals) * 360 + self.bar_phase * 0.5
            
            # Dinamik radius - bass ile pulse
            base_r = max_r * 0.3
            extended_r = base_r + (v * max_r * 0.5) + (self.bass_intensity * max_r * 0.1)
            
            if np is not None:
                px = cx + int(extended_r * np.cos(np.deg2rad(angle)))
                py = cy + int(extended_r * np.sin(np.deg2rad(angle)))
            else:
                px = cx + int(extended_r)
                py = cy
            
            # Renk: Bass (turuncu) → Mid (pembe) → Treble (mor)
            if i < num_petals // 3:
                hue = int(20 + v * 20)  # Turuncu-sarı
            elif i < 2 * num_petals // 3:
                hue = int(320 + v * 20)  # Pembe-magenta
            else:
                hue = int(260 + v * 20)  # Mor-mavi
            
            saturation = int(200 + self.vis_color_intensity * 0.55)
            value = int(180 + v * 75)
            alpha = int(150 + v * 105)
            
            color = QColor.fromHsv(hue, saturation, value, alpha)
            
            # Petal çiz (daire)
            size = int(5 + v * 15 + self.sound_intensity * 5)
            painter.setBrush(QBrush(color))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(int(px - size/2), int(py - size/2), size, size)
            
            # Glow efekti
            glow_size = size + 4
            glow_color = QColor(color)
            glow_color.setAlpha(alpha // 3)
            painter.setBrush(QBrush(glow_color))
            painter.drawEllipse(int(px - glow_size/2), int(py - glow_size/2), glow_size, glow_size)
        
        # Merkez parlak nokta
        center_size = int(10 + self.bass_intensity * 30)
        center_color = QColor.fromHsv(30, 255, 255, 220)
        painter.setBrush(QBrush(center_color))
        painter.drawEllipse(int(cx - center_size/2), int(cy - center_size/2), center_size, center_size)

    def _draw_circular_waveform(self, painter, w, h, data):
        """
        Circular Waveform (Halka Dalga Formu)
        - Ses sinyalinin dalga formunu dairesel biçimde çizer
        - Merkez 0 → dış halka amplitude
        - Smooth çizim + glow efekti
        """
        if not data or len(data) < 2:
            return
        
        cx, cy = w // 2, h // 2
        base_r = min(w, h) // 2 * 0.4
        max_r = min(w, h) // 2 * 0.8
        count = len(data)
        
        # Arka plan
        painter.fillRect(0, 0, w, h, QColor(10, 10, 20, 255))
        
        # Dairesel dalga path oluştur
        path = QPainterPath()
        
        for i in range(count + 1):  # +1 ile tam çember kapat
            idx = i % count
            v = data[idx]
            angle = (i / count) * 360
            
            # Radius: base + amplitude
            r = base_r + (v * (max_r - base_r))
            
            if np is not None:
                x = cx + int(r * np.cos(np.deg2rad(angle)))
                y = cy + int(r * np.sin(np.deg2rad(angle)))
            else:
                x = cx + int(r)
                y = cy
            
            if i == 0:
                path.moveTo(x, y)
            else:
                path.lineTo(x, y)
        
        path.closeSubpath()
        
        # Çizgi rengi - gradient (mavi-cyan-yeşil)
        hue = int((self.bar_phase * 0.3) % 360)
        
        # Outer glow (kalın, şeffaf)
        glow_color = QColor.fromHsv(hue, 200, 200, 80)
        painter.setPen(QPen(glow_color, 8))
        painter.setBrush(Qt.NoBrush)
        painter.drawPath(path)
        
        # Main line (orta kalınlık, parlak)
        main_color = QColor.fromHsv(hue, 255, 255, 220)
        painter.setPen(QPen(main_color, 3))
        painter.drawPath(path)
        
        # Inner highlight (ince, çok parlak)
        highlight_color = QColor.fromHsv(hue, 150, 255, 255)
        painter.setPen(QPen(highlight_color, 1))
        painter.drawPath(path)
        
        # Merkez referans dairesi
        painter.setPen(QPen(QColor(100, 100, 150, 100), 1))
        painter.setBrush(Qt.NoBrush)
        painter.drawEllipse(int(cx - base_r), int(cy - base_r), int(base_r * 2), int(base_r * 2))

    def _draw_3d_swirl_mode(self, painter, w, h, data):
        """
        3D Swirl / Galaxy Mode
        - FFT verilerine göre dönen parçacık sistemi
        - Parçacıkların rengi bass + mid + treble'a göre değişir
        - 3D derinlik efekti (Z-axis simulation)
        """
        if not data:
            return
        
        cx, cy = w // 2, h // 2
        max_r = min(w, h) // 2 * 0.9
        
        # Arka plan (koyu, space-like)
        painter.fillRect(0, 0, w, h, QColor(5, 5, 15, 255))
        
        # Swirl parçacıklarını başlat (ilk kez)
        if not self.swirl_particles or len(self.swirl_particles) < 100:
            self.swirl_particles = []
            num_particles = int(100 + self.vis_density * 2)  # 100-300 arası
            
            for i in range(num_particles):
                angle = random.uniform(0, 6.28318)  # 2π
                distance = random.uniform(0.1, 0.9) * max_r
                speed = random.uniform(0.5, 1.5)
                
                # Renk: position-temelli
                hue = (i / num_particles * 360) % 360
                color = QColor.fromHsv(int(hue), 200, 255, 200)
                
                particle = SwirlParticle(angle, distance, color, speed)
                self.swirl_particles.append(particle)
        
        # Parçacıkları güncelle ve çiz
        dt = 1.0 / max(self.fps, 1)
        angular_velocity = 2.0 + self.sound_intensity * 3.0  # Hız ses ile artar
        
        # Z-depth sorting için liste
        particles_with_depth = []
        
        for particle in self.swirl_particles:
            particle.update(dt, angular_velocity, self.bass_intensity)
            
            # 3D pozisyon hesapla
            if np is not None:
                x = cx + int(particle.distance * np.cos(particle.angle))
                y = cy + int(particle.distance * np.sin(particle.angle))
            else:
                x = cx + int(particle.distance)
                y = cy
            
            # Z-depth için scale (yakın = büyük, uzak = küçük)
            z_scale = 1.0 + particle.z / 100.0  # -0.5 to 1.5
            
            particles_with_depth.append((particle.z, x, y, particle.size * z_scale, particle.color))
        
        # Z-depth'e göre sırala (uzaktan yakına = depth-buffer simulation)
        particles_with_depth.sort(key=lambda p: p[0])
        
        for z, x, y, size, color in particles_with_depth:
            # Renk modifikasyonu: bass/mid/treble yoğunluğuna göre
            base_hue = color.hue()
            
            # Bass bölgesine turuncu/kırmızı ekle
            if self.bass_intensity > 0.5:
                color = QColor.fromHsv(int(20), 255, int(200 + self.bass_intensity * 55), color.alpha())
            # Mid bölgesine mavi ekle
            elif self.mid_intensity > 0.5:
                color = QColor.fromHsv(int(200), 255, int(180 + self.mid_intensity * 75), color.alpha())
            # Treble bölgesine mor ekle
            elif self.treble_intensity > 0.5:
                color = QColor.fromHsv(int(280), 255, int(180 + self.treble_intensity * 75), color.alpha())
            
            # Parçacık çiz
            painter.setBrush(QBrush(color))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(int(x - size/2), int(y - size/2), int(size), int(size))
        
        # Merkez glow (galaxy core)
        core_size = int(15 + self.sound_intensity * 20)
        core_color = QColor.fromHsv(40, 200, 255, 180)
        painter.setBrush(QBrush(core_color))
        painter.drawEllipse(int(cx - core_size/2), int(cy - core_size/2), core_size, core_size)

    def _draw_pulse_explosion(self, painter, w, h, data):
        """
        Pulse Explosion
        - Her bass vuruşunda merkezden dışarı kaybolan halkalar
        - Overlay blend + glow efekti
        - Müzik ritmine senkronize
        """
        if not data:
            return
        
        cx, cy = w // 2, h // 2
        
        # Arka plan
        painter.fillRect(0, 0, w, h, QColor(10, 5, 15, 255))
        
        # Pulseları güncelle
        dt = 1.0 / max(self.fps, 1)
        alive_pulses = []
        
        for pulse in self.energy_pulses:
            pulse.update(dt)
            if pulse.alive:
                alive_pulses.append(pulse)
        
        self.energy_pulses = alive_pulses
        
        # Pulseları çiz (eskiden yeniye = inside-out)
        for pulse in self.energy_pulses:
            alpha = pulse.get_alpha()
            color = QColor(pulse.color)
            color.setAlpha(alpha)
            
            # Outer glow
            glow_color = QColor(color)
            glow_color.setAlpha(alpha // 2)
            painter.setPen(QPen(glow_color, 8))
            painter.setBrush(Qt.NoBrush)
            painter.drawEllipse(
                int(pulse.x - pulse.radius),
                int(pulse.y - pulse.radius),
                int(pulse.radius * 2),
                int(pulse.radius * 2)
            )
            
            # Main ring
            painter.setPen(QPen(color, 3))
            painter.drawEllipse(
                int(pulse.x - pulse.radius),
                int(pulse.y - pulse.radius),
                int(pulse.radius * 2),
                int(pulse.radius * 2)
            )
        
        # Merkez reaktor (bass pulsating)
        reactor_size = int(20 + self.bass_intensity * 40)
        reactor_color = QColor.fromHsv(10, 255, 255, int(180 + self.bass_intensity * 75))
        
        # Glow layers
        for layer in range(3, 0, -1):
            glow_size = reactor_size + layer * 10
            glow_alpha = int(60 / layer)
            glow = QColor(reactor_color)
            glow.setAlpha(glow_alpha)
            painter.setBrush(QBrush(glow))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(
                int(cx - glow_size/2),
                int(cy - glow_size/2),
                glow_size, glow_size
            )
        
        # Core
        painter.setBrush(QBrush(reactor_color))
        painter.drawEllipse(
            int(cx - reactor_size/2),
            int(cy - reactor_size/2),
            reactor_size, reactor_size
        )
        
        # FFT bar çizelgeleri (ince çizgiler merkezden)
        if len(data) > 0:
            num_rays = min(len(data), 48)
            max_ray_len = min(w, h) // 2 * 0.6
            
            for i in range(num_rays):
                v = data[int(i * len(data) / num_rays)]
                angle = (i / num_rays) * 360 + self.bar_phase * 0.3
                ray_len = v * max_ray_len
                
                if np is not None:
                    ex = cx + int(ray_len * np.cos(np.deg2rad(angle)))
                    ey = cy + int(ray_len * np.sin(np.deg2rad(angle)))
                else:
                    ex = cx + int(ray_len)
                    ey = cy
                
                # Renk: bass/mid/treble
                if i < num_rays // 3:
                    hue = 20  # Turuncu (bass)
                elif i < 2 * num_rays // 3:
                    hue = 320  # Pembe (mid)
                else:
                    hue = 260  # Mor (treble)
                
                ray_color = QColor.fromHsv(hue, 255, int(200 + v * 55), int(100 + v * 100))
                painter.setPen(QPen(ray_color, 1))
                painter.drawLine(cx, cy, ex, ey)

    def _draw_tunnel_mode(self, painter, w, h, data):
        """
        Tunnel Mode (Tünel Efekti)
        - FFT değerleri tünelin duvar distortion'unu belirler
        - Perspektif efekti ile içeri doğru akan tünel
        - Renk gradient + motion blur simulasyonu
        """
        if not data:
            return
        
        cx, cy = w // 2, h // 2
        max_r = min(w, h) // 2
        
        # Arka plan (koyu)
        painter.fillRect(0, 0, w, h, QColor(0, 0, 10, 255))
        
        # Tünel animasyonu offset (sürekli ilerliyor)
        self.tunnel_offset += (0.5 + self.sound_intensity * 2.0) / max(self.fps, 1)
        if self.tunnel_offset > 1.0:
            self.tunnel_offset -= 1.0
        
        # Konsantrik tünel halkaları (perspektif: uzak = küçük)
        num_rings = 20
        
        for ring_idx in range(num_rings):
            # Perspektif scale (uzak = 0.1, yakın = 1.0)
            progress = (ring_idx / num_rings + self.tunnel_offset) % 1.0
            scale = 0.1 + progress * 0.9
            
            # Halka boyutu
            ring_r = max_r * scale
            
            # FFT distortion: her halka FFT band'ine göre titreşir
            band_idx = int(ring_idx * len(data) / num_rings) % len(data)
            distortion = data[band_idx] * 20  # Maksimum 20px distortion
            
            # Renk: depth-temelli gradient (uzak = mavi, yakın = kırmızı)
            hue = int(220 - progress * 220)  # 220° (mavi) → 0° (kırmızı)
            saturation = int(200 + self.vis_color_intensity * 0.55)
            value = int(100 + progress * 155)
            alpha = int(80 + progress * 120)
            
            ring_color = QColor.fromHsv(hue, saturation, value, alpha)
            
            # Halka çiz (distortion ile)
            num_segments = 64
            path = QPainterPath()
            
            for seg in range(num_segments + 1):
                angle = (seg / num_segments) * 360
                
                # Segment bazlı distortion (FFT'ye göre dalgalı)
                seg_band = int(seg * len(data) / num_segments) % len(data)
                seg_distortion = data[seg_band] * distortion
                
                r = ring_r + seg_distortion
                
                if np is not None:
                    x = cx + int(r * np.cos(np.deg2rad(angle)))
                    y = cy + int(r * np.sin(np.deg2rad(angle)))
                else:
                    x = cx + int(r)
                    y = cy
                
                if seg == 0:
                    path.moveTo(x, y)
                else:
                    path.lineTo(x, y)
            
            path.closeSubpath()
            
            # Çiz (anti-aliasing)
            painter.setPen(QPen(ring_color, 2))
            painter.setBrush(Qt.NoBrush)
            painter.drawPath(path)

    def _draw_winamp_retro(self, painter, w, h, data):
        painter.fillRect(0, 0, w, h, QColor(8, 10, 26))
        bar_count = len(data)
        bar_w = max(2, w // max(1, bar_count))
        for i, v in enumerate(data):
            hue = (i / max(1, bar_count) * 360 + self.bar_phase * 4) % 360
            c = QColor.fromHsv(int(hue), 255, 255)
            painter.setBrush(QBrush(c))
            painter.setPen(Qt.NoPen)
            h_val = int(v * h * 0.85)
            x = i * bar_w
            painter.drawRect(x, h - h_val, bar_w - 1, h_val)
            glow = QColor(c)
            glow.setAlpha(80)
            painter.fillRect(x, h - h_val - 4, bar_w - 1, 4, glow)

    def _draw_milkdrop_pulse(self, painter, w, h, data):
        painter.fillRect(self.rect(), QColor(12, 12, 18))
        num = len(data)
        if num == 0:
            return
        cx, cy = w // 2, h // 2
        painter.setPen(Qt.NoPen)
        for i, v in enumerate(data):
            angle = (i / num) * 360 + self.bar_phase * 3
            radius = (min(w, h) * 0.3) + v * (min(w, h) * 0.2)
            x = cx + radius * np.cos(np.deg2rad(angle))
            y = cy + radius * np.sin(np.deg2rad(angle))
            size = 6 + v * 26
            hue = (angle + self.bar_phase * 20) % 360
            c = QColor.fromHsv(int(hue), 255, 255, 200)
            painter.setBrush(QBrush(c))
            painter.drawEllipse(QPointF(x, y), size, size)

    def _draw_starfield_bass(self, painter, w, h, data):
        painter.fillRect(self.rect(), QColor(5, 5, 10))
        star_count = 200
        bass = data[0] if data else 0.0
        painter.setPen(Qt.NoPen)
        for i in range(star_count):
            t = (i / star_count)
            depth = (t * 0.8 + 0.2)
            speed = (1.0 / depth) * 2.0
            x = (np.sin(self.bar_phase * speed + i) * 0.5 + 0.5) * w
            y = (np.cos(self.bar_phase * speed + i * 1.3) * 0.5 + 0.5) * h
            size = 1 + depth * 2 + bass * 4
            alpha = int(80 + depth * 120 + bass * 80)
            painter.setBrush(QColor(160, 200, 255, alpha))
            painter.drawEllipse(QPointF(x, y), size, size)

    def _draw_plasma_flow(self, painter, w, h, data):
        import math
        painter.fillRect(self.rect(), QColor(6, 10, 20))
        step = 12
        t = self.bar_phase * 0.08
        for y in range(0, h, step):
            for x in range(0, w, step):
                v = math.sin(x * 0.02 + t) + math.sin(y * 0.02 - t)
                idx = int(abs(v * 12)) % max(1, len(data))
                val = data[idx] if data else 0.0
                hue = int((v * 120 + self.bar_phase * 5) % 360)
                c = QColor.fromHsv(hue, 255, int(120 + val * 120))
                painter.fillRect(x, y, step, step, c)

    def _draw_grid_warp(self, painter, w, h, data):
        painter.fillRect(self.rect(), QColor(8, 8, 12))
        cols = 18
        rows = 10
        t = self.bar_phase * 0.12
        for i in range(rows):
            for j in range(cols):
                idx = (i * cols + j) % max(1, len(data))
                v = data[idx] if data else 0.0
                cx = (j + 0.5) / cols
                cy = (i + 0.5) / rows
                offset = np.sin((cx + cy + t) * 6.28) * 0.05
                x = (cx + offset) * w
                y = (cy - offset) * h
                size = 6 + v * 16
                painter.setBrush(QColor(70, 130, 250, 200))
                painter.setPen(Qt.NoPen)
                painter.drawRoundedRect(int(x - size/2), int(y - size/2), int(size), int(size), 2, 2)

    def _draw_particle_rain(self, painter, w, h, data):
        painter.fillRect(self.rect(), QColor(4, 6, 12))
        count = 120
        bass = data[0] if data else 0.0
        for i in range(count):
            t = self.bar_phase * 0.4 + i
            x = (np.sin(t * 1.3) * 0.5 + 0.5) * w
            y = ((t * 30) % h)
            size = 2 + (i % 5) + bass * 8
            alpha = 120 + int(bass * 100)
            painter.setBrush(QColor(90, 200, 255, alpha))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(QPointF(x, y), size, size * 0.6)

    def _draw_hex_pulse(self, painter, w, h, data):
        painter.fillRect(self.rect(), QColor(10, 8, 18))
        cx, cy = w // 2, h // 2
        rings = 6
        for r in range(rings):
            radius = (r + 1) * min(w, h) * 0.07
            idx = min(len(data) - 1, r * 4) if data else 0
            val = data[idx] if data else 0.0
            hue = (self.bar_phase * 3 + r * 40) % 360
            pen = QPen(QColor.fromHsv(int(hue), 255, 255, 180))
            pen.setWidth(2)
            painter.setPen(pen)
            for i in range(6):
                angle1 = np.deg2rad(60 * i + self.bar_phase * 2)
                angle2 = np.deg2rad(60 * (i + 1) + self.bar_phase * 2)
                x1 = cx + radius * (1 + val * 0.5) * np.cos(angle1)
                y1 = cy + radius * (1 + val * 0.5) * np.sin(angle1)
                x2 = cx + radius * (1 + val * 0.5) * np.cos(angle2)
                y2 = cy + radius * (1 + val * 0.5) * np.sin(angle2)
                painter.drawLine(QPointF(x1, y1), QPointF(x2, y2))

    def _draw_neon_horizon(self, painter, w, h, data):
        painter.fillRect(self.rect(), QColor(4, 4, 10))
        horizon = int(h * 0.65)
        painter.fillRect(0, horizon, w, h - horizon, QColor(8, 12, 30))
        bar_count = len(data)
        if bar_count == 0:
            return
        bar_w = max(2, w // bar_count)
        for i, v in enumerate(data):
            hue = (200 + i * 2) % 360
            c = QColor.fromHsv(int(hue), 255, 255, 220)
            h_val = int(v * h * 0.4)
            x = i * bar_w
            y = horizon - h_val
            painter.fillRect(x, y, bar_w - 1, h_val, c)
            ref = QColor(c)
            ref.setAlpha(80)
            painter.fillRect(x, horizon, bar_w - 1, min(h_val, h - horizon), ref)

    def _draw_spectrum_tunnel(self, painter, w, h, data):
        painter.fillRect(self.rect(), QColor(8, 10, 18))
        num = len(data)
        if num == 0:
            return
        cx, cy = w // 2, h // 2
        painter.setPen(Qt.NoPen)
        for i, v in enumerate(data):
            depth = (i / num)
            r = (1 - depth) * min(w, h) * 0.45
            hue = (i * 4 + self.bar_phase * 5) % 360
            c = QColor.fromHsv(int(hue), 255, int(100 + v * 155))
            size = 10 + v * 40
            angle = (self.bar_phase * 10 + i * 12) % 360
            x = cx + r * np.cos(np.deg2rad(angle))
            y = cy + r * np.sin(np.deg2rad(angle))
            painter.setBrush(c)
            painter.drawEllipse(QPointF(x, y), size * (1 - depth), size * 0.5 * (1 - depth))

    def _draw_wave_orbit(self, painter, w, h, data):
        painter.fillRect(self.rect(), QColor(6, 8, 16))
        cx, cy = w // 2, h // 2
        radius = min(w, h) * 0.35
        band_count = len(data)
        if band_count == 0:
            return
        painter.setPen(Qt.NoPen)
        for i in range(band_count):
            angle = (i / band_count) * 360 + self.bar_phase * 2
            amp = data[i] if data else 0.0
            r = radius + amp * radius * 0.35
            x = cx + r * np.cos(np.deg2rad(angle))
            y = cy + r * np.sin(np.deg2rad(angle))
            hue = (angle + amp * 200) % 360
            size = 8 + amp * 24
            painter.setBrush(QColor.fromHsv(int(hue), 255, 255, 210))
            painter.drawEllipse(QPointF(x, y), size, size)
        
        # Merkez vortex (tünelin merkezi)
        vortex_size = int(10 + self.sound_intensity * 30)
        vortex_color = QColor.fromHsv(0, 255, 255, 200)
        
        painter.setBrush(QBrush(vortex_color))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(
            int(cx - vortex_size/2),
            int(cy - vortex_size/2),
            vortex_size, vortex_size
        )

    def _draw_mirror_mode(self, painter, w, h, data):
        """🪞 AYNA - Ortadan ince çubuklar (merkez odaklı spektrum)"""
        painter.fillRect(self.rect(), QColor(8, 8, 10))
        
        if not data or len(data) == 0:
            return
        
        count = len(data)
        
        # İnce çubuklar için parametreler
        bar_w = max(1, w / count * 0.4)  # İnce çubuklar (0.4 = %40 genişlik)
        gap = max(1, int(bar_w * 0.3))  # Aralarında daha fazla boşluk
        actual_bar_w = max(1, bar_w - gap)
        
        # Çubuklar orta kısımda (yükseklik olarak ortalanmış)
        max_bar_h = h * 0.6  # Maksimum %60 yükseklik
        center_y = h // 2  # Dikey merkez
        
        # Çubuklar yatay olarak merkezde
        total_width = count * bar_w
        start_x = (w - total_width) / 2  # Yatay merkez
        
        painter.setRenderHint(QPainter.Antialiasing, True)
        
        for i in range(count):
            v = data[i]
            
            # Çubuk yüksekliği - merkezden yukarı/aşağı büyür
            bar_h = int(v * max_bar_h)
            bar_h = max(2, min(bar_h, int(max_bar_h)))
            
            # Pozisyon - merkezden başlayarak sağa/sola
            x = int(start_x + i * bar_w)
            
            # Gökkuşağı renk (pozisyon bazlı + animasyon)
            position_offset = (i / max(count - 1, 1)) * 360
            hue = (self.rainbow_phase + position_offset) % 360
            saturation = int(0.95 * 255)
            value = int((0.75 + v * 0.25) * 255)
            alpha = int(200 + v * 55)
            
            bar_color = QColor.fromHsv(int(hue), saturation, value, alpha)
            
            painter.setPen(Qt.NoPen)
            painter.setBrush(QBrush(bar_color))
            
            # Çubuk merkezden yukarı/aşağı simetrik büyür
            y_top = center_y - bar_h // 2
            
            # İnce rounded rect çubuklar
            if actual_bar_w >= 3:
                painter.drawRoundedRect(
                    int(x + gap/2), y_top,
                    int(actual_bar_w), bar_h,
                    1, 1  # Hafif yuvarlatma
                )
            else:
                painter.drawRect(int(x + gap/2), y_top, int(actual_bar_w), bar_h)

    def mousePressEvent(self, event):
        if event.button() == Qt.RightButton:
            if self.show_full_visual:
                self._show_context_menu(event.pos())
            else:
                # Status bars (alt) için renk/stil menüsü
                self._show_bar_context_menu(event.pos())
        super().mousePressEvent(event)

    def _show_context_menu(self, point):
        menu = QMenu(self)
        app = QApplication.instance()
        from_main = next(
            (w for w in app.topLevelWidgets() if isinstance(w, AngollaPlayer)),
            None
        )
        favorites = set(from_main.vis_favorites) if from_main else set()
        auto_cycle_on = bool(from_main.vis_auto_cycle) if from_main else False

        fps_menu = QMenu("⚙️ Animasyon Hızı (FPS)", self)
        for val in [15, 30, 60]:
            a = QAction(f"{val} FPS", self)
            a.setCheckable(True)
            a.setChecked(val == self.fps)
            a.triggered.connect(lambda checked=False, f=val: self.set_fps(f))
            fps_menu.addAction(a)
        menu.addMenu(fps_menu)

        mode_menu = QMenu("🎆 Görselleştirme Modu", self)
        modes = from_main.vis_modes if from_main else [
            "Çizgiler", "Daireler", "Spektrum Çubukları"
        ]
        # Favorileri üste, geri kalan alfabetik
        if from_main:
            favs = [m for m in modes if m in favorites]
            rest = [m for m in modes if m not in favorites]
            modes = favs + rest
        for m in modes:
            action = QAction(m, self)
            action.setCheckable(True)
            action.setChecked(m == self.vis_mode)
            if from_main:
                action.triggered.connect(
                    lambda checked=False, mode=m:
                    from_main.set_visualization_mode(mode)
                )
            else:
                action.triggered.connect(
                    lambda checked=False, mode=m: self.set_vis_mode(mode)
                )
            mode_menu.addAction(action)
        menu.addMenu(mode_menu)

        # Favori toggle
        fav_act = QAction("⭐ Bu modu favori yap", self)
        fav_act.setCheckable(True)
        fav_act.setChecked(self.vis_mode in favorites)
        if from_main:
            fav_act.triggered.connect(
                lambda checked=False, mode=self.vis_mode: from_main.toggle_visual_favorite(mode)
            )
        menu.addAction(fav_act)

        # Otomatik geçiş
        auto_act = QAction("▶ Otomatik Geçiş (10 sn)", self)
        auto_act.setCheckable(True)
        auto_act.setChecked(auto_cycle_on)
        if from_main:
            auto_act.triggered.connect(from_main.toggle_visual_auto_cycle)
        menu.addAction(auto_act)

        menu.exec_(self.mapToGlobal(point))


# ---------------------------------------------------------------------------
# GÖRSELLEŞTİRME PENCERESİ
# ---------------------------------------------------------------------------

class VisualizationWindow(QMainWindow):
    def __init__(self, player):
        super().__init__()
        self.setWindowTitle("Angolla Görselleştirme")
        self.resize(800, 600)

        self.player = player

        # ProjectM mi yoksa built-in mi?
        if HAS_PROJECTM and getattr(player, 'use_projectm', False):
            self.visualizationWidget = ProjectMVisualizer(parent=self)
            self.is_projectm = True
        else:
            # AnimatedVisualizationWidget (tam ekran - eski sistem)
            self.visualizationWidget = AnimatedVisualizationWidget(
                parent=self,
                initial_mode=player.vis_mode,
                show_full_visual=True
            )
            self.visualizationWidget.set_fps(30)
            self.is_projectm = False
        
        self.setCentralWidget(self.visualizationWidget)

        # Tema rengini uygula
        theme_colors = self.player.themes[self.player.theme]
        primary_color = theme_colors[0]
        bg_color = theme_colors[2]
        
        # Görselleştirme rengi ve modu (ProjectM için geçersiz)
        if not self.is_projectm:
            self.visualizationWidget.set_color_theme(primary_color, bg_color)
            self.visualizationWidget.set_vis_mode(player.vis_mode)
        
        # Pencere arka planı
        self.setStyleSheet(f"""
            QMainWindow {{
                background-color: {bg_color};
            }}
        """)

    def closeEvent(self, event):
        self.player._vis_window_closed()
        super().closeEvent(event)

# ---------------------------------------------------------------------------
# ANA OYUNCU
# ---------------------------------------------------------------------------

class AngollaPlayer(QMainWindow):

    class _VideoOnlyProxyModel(QSortFilterProxyModel):
        """Video panelinde sadece klasörler + video dosyalarını göster."""

        def __init__(self, exts: set, parent=None):
            super().__init__(parent)
            self._exts = {str(e).lower() for e in (exts or set())}

        def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
            try:
                src = self.sourceModel()
                if src is None:
                    return False
                idx = src.index(source_row, 0, source_parent)
                if not idx.isValid():
                    return False
                # Klasörler her zaman görünsün
                try:
                    if src.isDir(idx):
                        return True
                except Exception:
                    pass
                # Dosyalarda sadece video uzantılarına izin ver
                path = ""
                try:
                    path = src.filePath(idx)
                except Exception:
                    return False
                ext = os.path.splitext(path)[1].lower()
                return ext in self._exts
            except Exception:
                return False
    
    # Signal to bridge QAudioProbe (Main Thread) -> VisualizerWorker (Worker Thread)
    video_audio_ready = pyqtSignal(bytes, int, int, int)

    @pyqtSlot(bool, bool, bool, bool, int)
    def _on_web_playback_state(self, paused, ended, loading, ad_active, video_count=0):
        """QWebChannel üzerinden gelen oynatma durumu sinyali."""
        self._last_web_video_count = video_count
        self._last_ad_active = ad_active
        if self.search_mode != "web":
            return
        now = time.time()
        playing = not (paused or ended or ad_active) and video_count > 0
        if loading and not paused and not ended and not ad_active and video_count > 0:
            playing = True
        self._web_playing = playing

        if self._web_playing:
            self._web_playback_last_active_ts = now
            self._set_visualizer_paused(False, fade=False)
            return
        last_active = getattr(self, "_web_playback_last_active_ts", 0.0)
        hold_secs = getattr(self, "_web_playback_hold_secs", 1.2)
        if last_active and (now - last_active) < hold_secs:
            return
        self._set_visualizer_paused(True, fade=True)

    @pyqtSlot(list)
    def _process_web_audio(self, band_vals):
        """QWebChannel üzerinden gelen 96-band spektrum verisi."""
        if self.search_mode != "web":
            return
        # Web listen-only: spektrum verisini işleme
        return
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Angolla Music Player - Angolla Tarzı (Gelişmiş)")
        self.setGeometry(100, 100, 1200, 820)
        self.vis_modes = self._build_visual_modes()
        self.vis_favorites = []
        self.vis_auto_cycle = False
        self.vis_auto_interval = 10000  # ms
        self._vis_auto_index = 0
        self.vis_auto_timer = QTimer(self)
        self.vis_auto_timer.timeout.connect(self._cycle_visual_mode)
        self.lang = self._detect_language()

        self.lang = self._detect_language()

        # AUDIO ARCHITECTURE (Isolated & Persistent)
        self.audio_manager = AudioManager()
        self.audio_engine = GlobalAudioEngine(self.audio_manager)
        self.audio_engine.start() # Dedicated Thread for Playback + DSP
        try:
            self.audio_engine.setPriority(QThread.HighPriority)
        except Exception:
            pass
        
        # Redundant offline processing removed for industrial stability
        self.dsp_auto_process = False 

        # Forward compatibility for visualizer
        self.mediaPlayer = self.audio_engine.media_player # Alias for probe etc
        self.playlist = QMediaPlaylist()
        self.playlist.setPlaybackMode(QMediaPlaylist.Sequential)

        # ------------------- VISUALIZER THREAD ISOLATION -------------------
        self.viz_thread = QThread()
        self.viz_worker = VisualizerWorker()
        self.viz_worker.moveToThread(self.viz_thread)
        self.viz_thread.start()
        
        # Connect audio engine's signal directly to worker (High Performance)
        self.audio_engine.viz_data_ready.connect(self.viz_worker.process_buffer)
        self.viz_worker.data_ready.connect(self._on_viz_data_ready)

        # Video sekmesine özel: ayrı visualizer worker (ana spectrum'u etkilemesin)
        self._video_band_dynamic_max = []
        self.video_viz_worker = VisualizerWorker()
        self.video_viz_worker.moveToThread(self.viz_thread)
        self.video_audio_ready.connect(self.video_viz_worker.process_buffer)
        self.video_viz_worker.data_ready.connect(self._on_video_viz_data_ready)

        # Video klasör playlist durumu
        self._video_playlist_paths = []
        self._video_playlist_index = -1
        self._video_playlist_folder = ""
        
        print("✓ GlobalAudioEngine + VisualizerWorker (Direct Link) Active")


        self.library = LibraryManager()
        self.current_file_path = None
        self.config_data = {}

        self.theme = "AURA Mavi"
        self.themes = {
            "AURA Mavi": ("#40C4FF", "#FFFFFF", "#2A2A2A"),
            "Zümrüt Yeşil": ("#00E676", "#FFFFFF", "#1B2B1A"),
            "Güneş Turuncusu": ("#FF9800", "#FFFFFF", "#2B1B00"),
            "Kırmızı Ateş": ("#FF1744", "#FFFFFF", "#2A0A0A"),
            "Mor Gece": ("#7C4DFF", "#FFFFFF", "#1A1030"),
            # Yeni temalar (daha farklı görünüm)
            "Obsidyen": ("#00E5FF", "#E0E0E0", "#11151C"),
            "Solar": ("#FFB300", "#202020", "#FFF3E0"),
            "Mint": ("#64FFDA", "#1B1B1B", "#0F1F1C"),
            "Neon Gece": ("#FF4081", "#F5F5F5", "#0B0F1A"),
            "Slate": ("#82B1FF", "#ECEFF1", "#1C2331"),
            "Desert": ("#F4B183", "#2B2118", "#FFF1DB"),
            "Forest": ("#8BC34A", "#E8F5E9", "#0E1A0E"),
            "Candy": ("#FF6FB5", "#FFF5FA", "#1B0F1B"),
            "Ice": ("#7AD7F0", "#E0F7FA", "#0A1C24"),
        }

        self.vis_mode = "Spektrum Çubukları"  # Varsayılan: Angolla tarzı FFT spektrum
        self.use_projectm = False  # ProjectM kullan/kullanma
        self.is_shuffling = False
        self.is_repeating = False
        # EQ KALDIRILDI - Otomatik frekans hassasiyeti kullanılıyor

        self.vis_window = None
        self.vis_widget_main_window = None
        self.vis_widget_video_window = None
        self._visualizer_paused = False
        self._web_playing = False
        self._web_audio_last_ts = 0.0
        self._web_dsp_active = False
        self._web_pcm_seen = False
        self._web_playback_last_active_ts = 0.0
        self._web_playback_hold_secs = 1.2
        self._visualizer_noise_gate_db = -60.0
        self._visualizer_noise_gate_linear = 10 ** (self._visualizer_noise_gate_db / 20.0)

        self._create_controls()
        self._create_side_panel()
        self._create_main_content()
        self._create_menu_bar()
        self._connect_signals()
        # Sol kütüphanede çoklu seçim + sürükle bırak aktif et
        # Çoklu seçim + sürükle-bırak
        self.libraryTableWidget.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.libraryTableWidget.setDragEnabled(True)
        self.libraryTableWidget.setAcceptDrops(False)
        self.libraryTableWidget.setDragDropMode(QAbstractItemView.DragOnly)

        self.load_config()
        self.load_playlist()
        self.refresh_library_view()
        self.enable_playlist_features()

        # --- Gömülü Web Güvenliği Entegrasyonu ---
        # Ayar yöneticisi
        self.settingsManager = SettingsManager()
        # Güvenli web bileşenleri
        try:
            self._setup_secure_web_components()
        except Exception as e:
            print(f"⚠ Güvenli web bileşenleri kurulamadı: {e}")

    def _on_video_viz_data_ready(self, band_vals, pcm_raw):
        """Video sekmesine özel FFT verisi: sadece video ritim çubuklarını güncelle."""
        try:
            num_bars = len(band_vals)
            if num_bars <= 0:
                return

            if not isinstance(getattr(self, "_video_band_dynamic_max", None), list) or len(self._video_band_dynamic_max) != num_bars:
                self._video_band_dynamic_max = [1e-6] * num_bars

            decay = 0.96
            normalized = []
            for i, val in enumerate(band_vals):
                prev = self._video_band_dynamic_max[i] * decay
                peak = max(prev, val)
                self._video_band_dynamic_max[i] = peak
                normalized.append(min(1.0, float(val) / (peak + 1e-6)))

            intensity = sum(normalized) / num_bars
            self.send_video_visual_data(min(1.0, intensity * 1.5), normalized)
        except Exception:
            pass

    def send_video_visual_data(self, intensity, band_vals):
        """Video sekmesine özel görselleştirme: ana spectrum'u etkilemez."""
        try:
            if self.vis_widget_video_window and hasattr(self.vis_widget_video_window, 'update_sound_data'):
                self.vis_widget_video_window.update_sound_data(intensity, band_vals)
        except Exception:
            pass

    def _detect_language(self):
        code = QLocale.system().name().split("_")[0].lower()
        if code not in TRANSLATIONS:
            code = "en"
        return code

    def _tr(self, key: str) -> str:
        lang_dict = TRANSLATIONS.get(self.lang, TRANSLATIONS["en"])
        return lang_dict.get(key, TRANSLATIONS["en"].get(key, key))

    def _get_default_video_folder(self) -> str:
        """Sistemin varsayılan Video dizinini bul (XDG_VIDEOS_DIR).

        Linux'ta bu dizin genelde ~/Videos veya yerel dile göre ~/Videolar olabilir.
        Bulunamazsa makul adaylara düşer.
        """
        home = os.path.expanduser("~")

        # 1) XDG user-dirs
        try:
            cfg = os.path.join(home, ".config", "user-dirs.dirs")
            if os.path.exists(cfg):
                with open(cfg, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if not line.startswith("XDG_VIDEOS_DIR"):
                            continue
                        # Format: XDG_VIDEOS_DIR="$HOME/Videos"
                        parts = line.split("=", 1)
                        if len(parts) != 2:
                            break
                        raw = parts[1].strip().strip('"').strip("'")
                        raw = raw.replace("$HOME", home)
                        raw = os.path.expandvars(raw)
                        raw = os.path.expanduser(raw)
                        if raw:
                            return raw
        except Exception:
            pass

        # 2) Yaygın adaylar (TR + EN + olası yazımlar)
        candidates = [
            os.path.join(home, "Videolar"),
            os.path.join(home, "Videos"),
            os.path.join(home, "Videyolar"),
            os.path.join(home, "Video"),
        ]
        for p in candidates:
            if os.path.exists(p):
                return p

        # 3) Son çare: home
        return home

    def _build_visual_modes(self):
        base_modes = [
            "Çizgiler", "Daireler", "Spektrum Çubukları",
            "Ayna",
            "Angolla Analyzer", "Angolla Turbine", "Angolla Boom", "Angolla Block",
            "Enerji Halkaları", "Dalga Formu", "Pulsar", "Spiral", "Volcano",
            "Işın Çakışması", "Çift Spektrum", "Radyal Izgara", "Parıltı Dalgası",
            "Neon Aura", "Kristal Spektrum", "İnferno", "Aurora", "3D Çubuklar",
            "Çiçek", "Gelişmiş Dalga",
            "Energy Ring", "Circular Waveform", "3D Swirl", 
            "Pulse Explosion", "Tunnel Mode",
            # Yeni, benzersiz 10 mod
            "Winamp Retro", "Milkdrop Pulse", "Starfield Bass", "Plasma Flow",
            "Grid Warp", "Particle Rain", "Hex Pulse", "Neon Horizon",
            "Spectrum Tunnel", "Wave Orbit",
        ]
        return base_modes

    def toggle_visual_favorite(self, mode: str):
        if mode in self.vis_favorites:
            self.vis_favorites.remove(mode)
        else:
            self.vis_favorites.append(mode)
        self.save_config()

    def toggle_visual_auto_cycle(self):
        self.vis_auto_cycle = not self.vis_auto_cycle
        if self.vis_auto_cycle:
            self._reset_auto_cycle_index(self.vis_mode)
            self.vis_auto_timer.start(self.vis_auto_interval)
            self.statusBar().showMessage("Otomatik görselleştirme geçişi açık", 2000)
        else:
            self.vis_auto_timer.stop()
            self.statusBar().showMessage("Otomatik geçiş kapalı", 2000)
        self.save_config()

    def _reset_auto_cycle_index(self, current_mode: str):
        modes = self.vis_favorites if self.vis_favorites else self.vis_modes
        if current_mode in modes:
            self._vis_auto_index = modes.index(current_mode)
        else:
            self._vis_auto_index = 0

    def _cycle_visual_mode(self):
        modes = self.vis_favorites if self.vis_favorites else self.vis_modes
        if not modes:
            return
        self._vis_auto_index = (self._vis_auto_index + 1) % len(modes)
        self.set_visualization_mode(modes[self._vis_auto_index])

    def _setup_secure_web_components(self):
        """Güvenli profil, sayfa ve köprü kurulumunu yapar."""
        if QWebEngineView is None or QWebEngineProfile is None or QWebChannel is None:
            # WebEngine yoksa sessizce geç
            return
        
        # Profil
        profile = QWebEngineProfile("angolla_secure_profile", self)
        # Tüm isteklerde allowlist + HTTPS zorunluluğu (mümkünse)
        try:
            if QWebEngineUrlRequestInterceptor is not None and hasattr(profile, "setRequestInterceptor"):
                profile.setRequestInterceptor(AngollaWebRequestInterceptor(profile))
        except Exception:
            pass
        try:
            profile.settings().setAttribute(QWebEngineSettings.FullScreenSupportEnabled, True)
        except Exception:
            pass
        # Profil seviyesinde de temel güvenlik ayarları
        try:
            ps = profile.settings()
            ps.setAttribute(QWebEngineSettings.AllowRunningInsecureContent, False)
            if hasattr(QWebEngineSettings, "LocalContentCanAccessFileUrls"):
                ps.setAttribute(QWebEngineSettings.LocalContentCanAccessFileUrls, False)
            if hasattr(QWebEngineSettings, "LocalContentCanAccessRemoteUrls"):
                ps.setAttribute(QWebEngineSettings.LocalContentCanAccessRemoteUrls, False)
        except Exception:
            pass
        try:
            profile.setAudioMuted(False)
        except Exception:
            pass
        
        # Kalıcı oturum için depolama yolu ayarla (AppData/web_profile)
        storage_path = os.path.join(QStandardPaths.writableLocation(QStandardPaths.AppDataLocation), "web_profile")
        if not os.path.exists(storage_path):
            try:
                os.makedirs(storage_path, exist_ok=True)
            except Exception:
                pass
        profile.setPersistentStoragePath(storage_path)
        profile.setCachePath(storage_path)
        self.web_profile = profile

        # Web sekmesi indirme kontrolü (MIME + uzantı allowlist)
        try:
            if hasattr(profile, "downloadRequested"):
                profile.downloadRequested.connect(self._on_web_download_requested)
        except Exception:
            pass

        try:
            profile.setPersistentCookiesPolicy(QWebEngineProfile.ForcePersistentCookies)
            if hasattr(QWebEngineProfile, "AllowThirdPartyCookies") and hasattr(profile, "setThirdPartyCookiesPolicy"):
                profile.setThirdPartyCookiesPolicy(QWebEngineProfile.AllowThirdPartyCookies)
            profile.setHttpCacheType(QWebEngineProfile.DiskHttpCache)
            profile.setSpellCheckEnabled(False)
        except Exception:
            pass
        self._start_web_cache_timer()
        
        # Sayfa ve görünüm
        WebViewClass = ConstrainedWebEngineView if ConstrainedWebEngineView else QWebEngineView
        self.web_view = WebViewClass(self)
        self.web_view.setVisible(False) # Başlangıçta gizli
        # Web görünümünün ana pencereyi büyütmesini önlemek için boyut politikası
        try:
            from PyQt5.QtWidgets import QSizePolicy
            self.web_view.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        except Exception:
            pass

        self.web_page = AngollaWebPage(profile, self.web_view)
        self.web_view.setPage(self.web_page)
        try:
            self.web_view.settings().setAttribute(QWebEngineSettings.FullScreenSupportEnabled, True)
            self.web_view.settings().setAttribute(QWebEngineSettings.WebGLEnabled, True)
            self.web_view.settings().setAttribute(QWebEngineSettings.Accelerated2dCanvasEnabled, True)
        except Exception:
            pass
        try:
            self.web_page.setAudioMuted(False)
        except Exception:
            pass
        
        # Web sayfasının ana pencereyi boyutlandırmasını engelle (Google Login fix)
        self.web_page.geometryChangeRequested.connect(lambda geom: None)
        self.web_page.windowCloseRequested.connect(lambda: None)

        # Kanal ve bridge
        channel = QWebChannel(self.web_view)
        self.web_bridge = BridgeSecurityController()
        
        # Web ses verisi visualizer'a bağla
        if self.web_bridge and hasattr(self.web_bridge, 'web_audio_data'):
            self.web_bridge.web_audio_data.connect(self._process_web_audio)
        if self.web_bridge and hasattr(self.web_bridge, 'web_playback_state'):
            self.web_bridge.web_playback_state.connect(self._on_web_playback_state)
        if self.web_bridge and hasattr(self.web_bridge, 'video_playing'):
            self.web_bridge.video_playing.connect(self._on_web_video_playing)
        if self.web_bridge and hasattr(self.web_bridge, 'web_audio_pcm'):
            self.web_bridge.web_audio_pcm.connect(self._on_web_audio_pcm)
        
        # Ayarlardan whitelist yükle ve sınıflara uygula
        try:
            from config import TRUSTED_DOMAINS, BRIDGE_ALLOWED_SITES
            # Override with persistent settings
            td = self.settingsManager.get_trusted_domains()
            bs = self.settingsManager.get_bridge_allowed_sites()
            # Bridge ve page sınıfları modül seviyesindeki set'leri kullanıyor; güncelle
            globals()['TRUSTED_DOMAINS'] = td
            globals()['BRIDGE_ALLOWED_SITES'] = bs
        except Exception as e:
            print(f"Whitelist uygulama hatası: {e}")
        channel.registerObject("AngollaBridge", self.web_bridge)
        try:
            self.web_page.setWebChannel(channel)
        except Exception:
            pass
        try:
            from PyQt5.QtWebEngineWidgets import QWebEngineScript
            self._install_webchannel_script(QWebEngineScript, page=self.web_page)
        except Exception:
            pass
        # Bridge sinyallerini bağla
        try:
            self.web_bridge.ad_skip_requested.connect(self._on_bridge_ad_skip)
            print("✓ Bridge sinyali bağlandı: ad_skip_requested")
        except Exception as e:
            print(f"Bridge sinyal bağlama hatası: {e}")
        
        # 🎬 REKLAM GEÇIŞ KÖPRÜSÜ - JavaScript entegrasyon
        self.web_view.loadFinished.connect(self._on_page_loaded)
        # Statik scriptleri tüm alt çerçevelerde etkinleştir
        try:
            from PyQt5.QtWebEngineWidgets import QWebEngineScript
            self._enable_static_ad_skip(QWebEngineScript)
            print("✓ Static ad skip scripts enabled (subframes)")
        except Exception as e:
            print(f"⚠ Static script enable failed: {e}")
        
        # 🖥️ TAM EKRAN DESTEĞİ - YouTube player için
        try:
            self.web_page.fullScreenRequested.connect(self._handle_fullscreen_request)
            print("✓ Fullscreen support enabled")
        except Exception as e:
            print(f"⚠ Fullscreen setup failed: {e}")
        
        # Ana uygulamada kullanılan webView referansını güvenli görünüme eşitle
        self.webView = self.web_view
        try:
            self.webView.loadFinished.connect(self._on_page_loaded)  # Ad skip injection
            self.webView.titleChanged.connect(self._on_web_title_changed)
            self.webView.urlChanged.connect(self._on_web_url_changed)
        except Exception:
            pass

        # Video display widget
        self.video_display_widget = VideoDisplayWidget()
        self.playlist_stack.addWidget(self.video_display_widget)

        # Stack'e ekle (tekil olacak şekilde)
        # NOT: Artık mainContentStack içinde playlist_stack var. Oraya eklemeliyiz.
        if hasattr(self, 'playlist_stack'):
            try:
                if self.playlist_stack.indexOf(self.webView) == -1:
                    self.playlist_stack.addWidget(self.webView)
            except Exception:
                pass
        elif self.mainContentStack:
             # Fallback
            try:
                if self.mainContentStack.indexOf(self.webView) == -1:
                    self.mainContentStack.addWidget(self.webView)
            except Exception:
                pass

        # Başlangıç sayfası
        try:
            self.web_view.setHtml("<html><body style='background:#111;color:#eee;font-family:sans-serif'>Angolla Güvenli Web Görünümü</body></html>")
        except Exception:
            pass

    def _on_web_download_requested(self, download_item):
        """Web sekmesinden gelen indirme isteğini güvenli şekilde yönet."""
        # Not: Dosya adı/yolu asla loglanmamalı.
        try:
            mime = ""
            suggested = ""
            url = None
            try:
                if hasattr(download_item, "mimeType"):
                    mime = download_item.mimeType() or ""
            except Exception:
                mime = ""
            try:
                if hasattr(download_item, "suggestedFileName"):
                    suggested = download_item.suggestedFileName() or ""
            except Exception:
                suggested = ""
            try:
                if hasattr(download_item, "url"):
                    url = download_item.url()
            except Exception:
                url = None

            # Ek güvenlik: indirme URL'i de web allowlist/HTTPS kurallarına uymalı
            try:
                if url is not None and not _is_allowed_web_qurl(url):
                    if hasattr(download_item, "cancel"):
                        download_item.cancel()
                    QMessageBox.information(self, "Engellendi", "Bu indirme güvenlik nedeniyle engellendi.")
                    return
            except Exception:
                pass

            if not _is_allowed_download(mime, suggested):
                try:
                    if hasattr(download_item, "cancel"):
                        download_item.cancel()
                except Exception:
                    pass
                QMessageBox.information(
                    self,
                    "Engellendi",
                    "İndirme engellendi. Sadece resim, müzik veya video dosyalarına izin verilir."
                )
                return

            # Kullanıcıya kaydetme yeri sor (UI gösterimi serbest, log yok)
            default_dir = QStandardPaths.writableLocation(QStandardPaths.DownloadLocation)
            try:
                save_path, _ = QFileDialog.getSaveFileName(
                    self,
                    "Dosyayı Kaydet",
                    _os.path.join(default_dir, suggested) if suggested else default_dir,
                )
            except Exception:
                save_path = ""

            if not save_path:
                try:
                    if hasattr(download_item, "cancel"):
                        download_item.cancel()
                except Exception:
                    pass
                return

            # Son bir kontrol: kullanıcı uzantıyı değiştirdiyse yeniden denetle
            if not _is_allowed_download(mime, _os.path.basename(save_path)):
                try:
                    if hasattr(download_item, "cancel"):
                        download_item.cancel()
                except Exception:
                    pass
                QMessageBox.information(
                    self,
                    "Engellendi",
                    "Seçilen dosya türüne izin verilmiyor. Sadece resim, müzik veya video kaydedebilirsiniz."
                )
                return

            # Qt sürümüne göre API farklı olabilir
            try:
                directory = _os.path.dirname(save_path)
                filename = _os.path.basename(save_path)
                if hasattr(download_item, "setDownloadDirectory"):
                    download_item.setDownloadDirectory(directory)
                if hasattr(download_item, "setDownloadFileName"):
                    download_item.setDownloadFileName(filename)
                elif hasattr(download_item, "setPath"):
                    download_item.setPath(save_path)
            except Exception:
                pass

            try:
                if hasattr(download_item, "accept"):
                    download_item.accept()
            except Exception:
                pass
        except Exception:
            try:
                if hasattr(download_item, "cancel"):
                    download_item.cancel()
            except Exception:
                pass
    
    def _setup_web_control_buttons(self):
        """Web indirme ve kapat butonlarını oluştur (toolbar'da eklenecek)."""
        try:
            # Download action (Green)
            self.webDownloadAction = QAction("⬇ İndir", self)
            self.webDownloadAction.setToolTip("YouTube'dan video/müzik indir (MP3/MP4)")
            self.webDownloadAction.triggered.connect(self._web_download)
            self.webDownloadAction.setVisible(False)
            
        except Exception as e:
            print(f"Web button setup error: {e}")
    
    def _on_page_loaded(self, ok):
        """Sayfa yüklendiğinde ad skip scripti inject et."""
        if not ok or not getattr(self, "webView", None):
            return
            
        # 2. YouTube Görsel Katman Onarımı: Z-Index Fix
        # Sayfa yüklendiğinde web görünümünü en öne getir
        self.webView.raise_()
            
        print(f"✓ PAGE LOADED - YouTube sayfası yüklendi")
        if self.webView and self.webView.page():
            try:
                should_mute = bool(getattr(self, "_force_web_mute", False))
                self.webView.page().setAudioMuted(should_mute)
            except Exception:
                pass

        cookie_js = "document.cookie = 'DISABLE_POLYMER_VISUAL_UPDATE=true';"
        try:
            self.webView.page().runJavaScript(cookie_js)
        except Exception:
            pass
        local_storage_js = "try { localStorage.setItem('yt-player-av1-pref', '-1'); } catch (e) {}"
        try:
            self.webView.page().runJavaScript(local_storage_js)
        except Exception:
            pass
        
        # Web sesi listen-only (Chromium native) - sadece oynatma durumu izle
        try:
            playback_js = web_engine_handler.build_web_playback_state_js()
            self.webView.page().runJavaScript(playback_js)
        except Exception:
            pass
        # Sayfa yüklendiği an web sesini ve DSP ayarlarını senkronize et
        self.set_web_volume(self.volumeSlider.value())
        try:
            self.audio_engine.media_player.setVolume(self.volumeSlider.value())
            self.audio_engine.sync_dsp_params()
        except Exception:
            pass
        if hasattr(self, "webPosTimer") and not self.webPosTimer.isActive():
            self.webPosTimer.start()
        try:
            QTimer.singleShot(600, self._poll_web_status)
        except Exception:
            pass
        
        # 2. Ultra-Seri Reklam Geçme (Fast Action Skip)
        ad_skip_js = """
        (function() {
            console.log('🚀 Angolla Ultra-Seri Ad Skip Active');
            if (window.__angollaTakInterval) clearInterval(window.__angollaTakInterval);

            window.__angollaTakInterval = setInterval(function() {
                try {
                    // Algoritma: Buton oluştuğu milisaniyede tıkla
                    var skipBtn = document.querySelector('.ytp-ad-skip-button-modern, .ytp-ad-skip-button, .ytp-skip-ad-button');
                    if (skipBtn) {
                        skipBtn.click();
                        console.log('Angolla: Ad Skipped (Click)');
                    }

                    // Seri Geçiş: 5sn zorunlu reklamlar için 16x hız
                    var adOverlay = document.querySelector('.ytp-ad-player-overlay, .ytp-ad-overlay-container');
                    if (adOverlay) {
                        var video = document.querySelector('video');
                        if (video && !video.paused) {
                            video.playbackRate = 16.0;
                        }
                    }
                } catch(e) {}
            }, 100); // 100ms Watcher (Gözcü)
            
            console.log('✅ Fast Action Skip System ACTIVE');
            window.angollaAdSkipActive = true;
        })();
        """
        
        # Inject immediately
        try:
            self.webView.page().runJavaScript(ad_skip_js)
            print("✓ Ad skip script injected via runJavaScript")
        except Exception as e:
            print(f"⚠ Initial injection error: {e}")
        
    def _inject_ad_skip_js_retry(self):
        """1 saniye sonra tekrar inject et."""
        retry_js = """
        if (!window.angollaAdSkipActive) {
            console.log('⚠ Ad skip not active, injecting again...');
            // Re-run the full script
            (function() {
                const isAdActive = () => {
                    const body = document.body;
                    const player = document.getElementById('movie_player');
                    const adOverlay = document.querySelector('.ytp-ad-player-overlay, .ytp-ad-overlay-container, .ytp-ad-preview-container, .ytp-ad-duration-remaining');
                    const skipButtons = Array.from(document.querySelectorAll('.ytp-ad-skip-button-modern, .ytp-ad-skip-button'));
                    const hasVisibleSkip = skipButtons.some(btn => btn && btn.offsetParent !== null);
                    return (
                        (body && body.classList && (body.classList.contains('ad-showing') || body.classList.contains('ad-interrupting'))) ||
                        (player && player.classList && player.classList.contains('ad-showing')) ||
                        hasVisibleSkip || !!adOverlay
                    );
                };
                setInterval(function() {
                    if (!isAdActive()) return;
                    document.querySelectorAll('video').forEach(v => {
                        if (v && v.duration > 0 && v.duration < 90) {
                            v.playbackRate = 16;
                            v.muted = true;
                            v.volume = 0;
                            if (v.currentTime < v.duration - 0.15) {
                                v.currentTime = v.duration - 0.05;
                            }
                        }
                    });
                }, 25);
                window.angollaAdSkipActive = true;
            })();
        } else {
            console.log('✓ Ad skip already active');
        }
        """
        try:
            if self.webView:
                self.webView.page().runJavaScript(retry_js)
            print("✓ Retry injection executed")
        except Exception:
            pass

    
    def _handle_fullscreen_request(self, request):
        """YouTube player tam ekran isteğini işle"""
        if not getattr(self, "webView", None):
            return
        try:
            # PyQt sürümleri arasında toggleOn bazen method bazen property olabiliyor
            try:
                _toggle_attr = getattr(request, "toggleOn", False)
                toggle_on = _toggle_attr() if callable(_toggle_attr) else bool(_toggle_attr)
            except Exception:
                toggle_on = False

            try:
                request.accept()
            except Exception:
                pass

            try:
                print(f"🖥️ [WEB_FS] fullscreenRequested: toggle_on={toggle_on}")
            except Exception:
                pass

            if toggle_on:
                # Pseudo-fullscreen: UI'yi sadeleştir, pencereyi büyüt
                self._ui_fullscreen_state = {
                    "was_maximized": self.isMaximized(),
                    "geometry": self.geometry(),
                    "side_visible": self.side_panel.isVisible() if hasattr(self, "side_panel") else True,
                    "bottom_visible": self.bottom_widget.isVisible() if hasattr(self, "bottom_widget") else True,
                    "split_sizes": self.main_splitter.sizes() if hasattr(self, "main_splitter") else [],
                    "menubar_visible": self.menuBar().isVisible() if hasattr(self, "menuBar") and self.menuBar() else True,
                    "toolbar_visible": self.toolbar.isVisible() if hasattr(self, "toolbar") and self.toolbar else True,
                    "web_controls_visible": [w.isVisible() for w in getattr(self, "web_controls", [])] if hasattr(self, "web_controls") else [],
                    "web_download_visible": bool(getattr(self, 'webDownloadAction', None) and self.webDownloadAction.isVisible()) if hasattr(self, 'webDownloadAction') else False,
                }
                self._in_web_fullscreen = True

                # Web fullscreen çıkış overlay butonu (toolbar gizliyken de erişilebilir)
                try:
                    if getattr(self, "web_fs_exit_btn", None):
                        self.web_fs_exit_btn.setVisible(True)
                        self._update_window_close_btn_pos()
                except Exception:
                    pass

                # Sekmeler bağımsız: web tam ekrana girince diğer medya kaynaklarını durdur
                try:
                    self._apply_exclusive_mode('web')
                except Exception:
                    pass

                if hasattr(self, "playlist_stack") and self.webView:
                    try:
                        if self.playlist_stack.indexOf(self.webView) == -1:
                            self.playlist_stack.addWidget(self.webView)
                        self.playlist_stack.setCurrentWidget(self.webView)
                    except Exception:
                        pass
                if self.mainContentStack:
                    try:
                        self.mainContentStack.setCurrentIndex(0)
                    except Exception:
                        pass
                try:
                    if hasattr(self, "side_panel"):
                        self.side_panel.hide()
                    if hasattr(self, "bottom_widget"):
                        self.bottom_widget.hide()
                    try:
                        if hasattr(self, "menuBar") and self.menuBar():
                            self.menuBar().setVisible(False)
                    except Exception:
                        pass
                    if hasattr(self, "toolbar") and self.toolbar:
                        self.toolbar.setVisible(False)
                    if hasattr(self, 'web_controls'):
                        for w in self.web_controls:
                            try:
                                w.setVisible(False)
                            except Exception:
                                pass
                    if hasattr(self, 'webDownloadAction') and self.webDownloadAction:
                        try:
                            self.webDownloadAction.setVisible(False)
                        except Exception:
                            pass
                    if hasattr(self, "main_splitter"):
                        w = self.main_splitter.size().width()
                        self.main_splitter.setSizes([0, w])
                except Exception:
                    pass
                
                # Hide fileLabel (Top Bar) explicitly
                if hasattr(self, 'fileLabel') and self.fileLabel:
                    self.fileLabel.hide()

                # Force layout update to remove black gaps
                if hasattr(self, 'centralWidget') and self.centralWidget():
                    self.centralWidget().layout().setContentsMargins(0, 0, 0, 0)
                    self.centralWidget().layout().setSpacing(0)

                try:
                    self.showFullScreen()
                except Exception:
                    self.showMaximized()
                self.raise_()
                print("🖥️ [WEB_FS] Tam ekran modu: AÇIK")
                
                # RECURSIVE EVENT FILTER FOR WEBVIEW CHILDREN (Fixes mouse tracking in web fs)
                try:
                    self.webView.installEventFilter(self)
                    for child in self.webView.findChildren(QObject):
                        child.installEventFilter(self)
                except Exception:
                    pass

            else:
                self._exit_web_fullscreen_ui()
        except Exception as e:
            print(f"⚠️ Fullscreen toggle hatası: {e}")
            try:
                request.reject()
            except Exception:
                pass

    def _exit_web_fullscreen_ui(self):
        """Web fullscreen kapanırken UI'yi geri yükle (request gelmese de kullanılabilir)."""
        self._in_web_fullscreen = False
        try:
            if getattr(self, "web_fs_exit_btn", None):
                self.web_fs_exit_btn.setVisible(False)
        except Exception:
            pass
        state = getattr(self, "_ui_fullscreen_state", {})
        try:
            if hasattr(self, "side_panel") and state.get("side_visible", True):
                self.side_panel.show()
            if hasattr(self, "bottom_widget") and state.get("bottom_visible", True):
                self.bottom_widget.show()
            try:
                if hasattr(self, "menuBar") and self.menuBar():
                    self.menuBar().setVisible(bool(state.get("menubar_visible", True)))
            except Exception:
                pass
            if hasattr(self, "toolbar") and self.toolbar:
                self.toolbar.setVisible(bool(state.get("toolbar_visible", True)))
            if hasattr(self, 'web_controls'):
                prev = state.get("web_controls_visible", [])
                for i, w in enumerate(self.web_controls):
                    try:
                        w.setVisible(bool(prev[i]) if i < len(prev) else True)
                    except Exception:
                        pass
            if hasattr(self, 'webDownloadAction') and self.webDownloadAction:
                try:
                    self.webDownloadAction.setVisible(bool(state.get("web_download_visible", False)))
                except Exception:
                    pass

            if hasattr(self, "main_splitter"):
                sizes = state.get("split_sizes", [])
                if sizes:
                    self.main_splitter.setSizes(sizes)
        except Exception:
            pass

        try:
            # GEOMETRY RESTORE FIX
            if state.get("was_maximized"):
                self.showMaximized()
            else:
                geom = state.get("geometry")
                if geom and not geom.isEmpty():
                     self.setGeometry(geom)
                self.showNormal()
                
            # FORCE UI UPDATE
            QApplication.processEvents()
            # self.centralWidget().updateGeometry() -> centralWidget update
            if self.centralWidget():
                self.centralWidget().update()
            
        except Exception:
            try:
                self.showNormal()
            except:
                pass
            try:
                self.showNormal()
            except Exception:
                pass
        try:
            print("🖥️ [WEB_FS] Tam ekran modu: KAPALI")
        except Exception:
            pass

    def _on_bridge_ad_skip(self, site: str):
        """Bridge üzerinden gelen güvenli reklam geçiş isteğini uygula."""
        try:
            js = """
            (function(){
                try {
                    var btn = document.querySelector('.ytp-ad-skip-button-modern, .ytp-ad-skip-button, .ytp-skip-ad-button');
                    if (btn && btn.offsetParent !== null) {
                        btn.click();
                    }
                } catch(e) {}
            })();
            """
            if self.webView:
                self.webView.page().runJavaScript(js)
        except Exception:
            pass

    def _enable_static_ad_skip(self, QWebEngineScript):
        """YouTube alt çerçeveler için statik script ekle (DocumentCreation, subframes)."""
        if not hasattr(self, 'web_page') or self.web_page is None:
            return
        try:
            print("🔧 Enabling static ad skip scripts (checking enums)...")
            has_creation = hasattr(QWebEngineScript, 'DocumentCreation')
            has_ready = hasattr(QWebEngineScript, 'DocumentReady')
            print(f"   • DocumentCreation: {has_creation}, DocumentReady: {has_ready}")
            
            # 3. Safe Skip: CSS injection kaldırıldı (Siyah ekranı önlemek için)
            
            js_code = web_engine_handler.build_ad_skip_js(250)

            js_script = QWebEngineScript()
            js_script.setName('AngollaJS')
            js_script.setSourceCode(js_code)
            js_script.setInjectionPoint(QWebEngineScript.DocumentReady if has_ready else QWebEngineScript.DocumentCreation)
            if hasattr(QWebEngineScript, 'MainWorld'):
                js_script.setWorldId(QWebEngineScript.MainWorld)
            elif hasattr(QWebEngineScript, 'ApplicationWorld'):
                js_script.setWorldId(QWebEngineScript.ApplicationWorld)
            js_script.setRunsOnSubFrames(True)
            ok_js = self.web_page.scripts().insert(js_script)
            print(f"   • JS script inserted: {bool(ok_js)}")
            print("✅ Angolla TAK TAK TAK (static) prepared for subframes")
        except Exception as e:
            print(f"⚠ Failed enabling static scripts: {e}")

    def _start_web_cache_timer(self):
        """Web profile cache temizliğini periyodik yap."""
        if getattr(self, "web_cache_timer", None):
            return
        if not getattr(self, "web_profile", None):
            return
        self.web_cache_timer = QTimer(self)
        self.web_cache_timer.setInterval(10 * 60 * 1000)
        self.web_cache_timer.timeout.connect(self._clear_web_cache)
        self.web_cache_timer.start()

    def _clear_web_cache(self):
        """HTTP cache temizliği (stability için)."""
        try:
            if getattr(self, "web_profile", None):
                self.web_profile.clearHttpCache()
        except Exception:
            pass

    def _install_webchannel_script(self, QWebEngineScript, page=None):
        """QWebChannel JS'ini CSP/TrustedTypes engeline takılmadan enjekte et."""
        target_page = page if page is not None else getattr(self, "web_page", None)
        if not target_page:
            return
        try:
            from PyQt5.QtCore import QFile, QIODevice
        except Exception:
            return
        try:
            f = QFile(":/qtwebchannel/qwebchannel.js")
            if not f.open(QIODevice.ReadOnly):
                return
            src = bytes(f.readAll()).decode("utf-8", "ignore")
            f.close()
        except Exception:
            return
        try:
            script = QWebEngineScript()
            script.setName("AngollaQWebChannel")
            script.setSourceCode(src)
            if hasattr(QWebEngineScript, 'DocumentCreation'):
                script.setInjectionPoint(QWebEngineScript.DocumentCreation)
            else:
                script.setInjectionPoint(QWebEngineScript.DocumentReady)
            if hasattr(QWebEngineScript, 'MainWorld'):
                script.setWorldId(QWebEngineScript.MainWorld)
            elif hasattr(QWebEngineScript, 'ApplicationWorld'):
                script.setWorldId(QWebEngineScript.ApplicationWorld)
            script.setRunsOnSubFrames(True)
            ok = target_page.scripts().insert(script)
            print(f"✓ QWebChannel script injected: {bool(ok)}")
        except Exception as e:
            print(f"⚠ QWebChannel inject failed: {e}")
    
    def _on_visual_mode_changed_external(self, mode: str):
        """Widget içinden mod değiştiğinde auto-cycle indeksini hizala."""
        if self.vis_auto_cycle:
            self._reset_auto_cycle_index(mode)

    def _create_controls(self):
        self.prevButton = QPushButton()
        self.playButton = QPushButton()
        self.nextButton = QPushButton()
        
        # Hızlı İleri/Geri butonları (10 saniye)
        self.seekBackwardButton = QPushButton()
        self.seekForwardButton = QPushButton()
        
        icon_size = QSize(30, 30)
        self.icon_play = QIcon(os.path.join("icons", "media-playback-start.png"))
        self.icon_pause = QIcon(os.path.join("icons", "media-playback-pause.png"))
        icon_map = {
            self.prevButton: "media-skip-backward.png",   # önceki parça
            self.playButton: "media-playback-start.png",  # play
            self.nextButton: "media-skip-forward.png",    # sonraki parça
            # Not: bazı ikon setlerinde forward/backward dosya yönleri ters olabiliyor;
            # kullanıcı beklentisi: soldaki sola, sağdaki sağa baksın.
            self.seekBackwardButton: "media-seek-forward.png",   # 10sn geri (ikon yön düzeltme)
            self.seekForwardButton: "media-seek-backward.png",   # 10sn ileri (ikon yön düzeltme)
        }
        for btn, icon_name in icon_map.items():
            btn.setIcon(QIcon(os.path.join("icons", icon_name)))
            btn.setIconSize(icon_size)
            # Seek butonları biraz daha küçük
            if btn in (self.seekBackwardButton, self.seekForwardButton):
                btn.setFixedSize(34, 34)
                btn.setIconSize(QSize(24, 24))
            else:
                btn.setFixedSize(38, 38)
            # Not: overlay butonlarının burada gizlenmesine izin verme —
            # overlay görünürlüğü web açma/URL change sırasında kontrol edilir.

        self.shuffleButton = QPushButton()
        self.repeatButton = QPushButton()
        for btn in (self.shuffleButton, self.repeatButton):
            btn.setCheckable(True)
            btn.setFixedSize(34, 34)
            btn.setIconSize(QSize(22, 22))
            btn.setCursor(Qt.PointingHandCursor)

        self._shuffle_icon_off = QIcon(os.path.join("icons", "shuffle.svg"))
        self._shuffle_icon_on = QIcon(os.path.join("icons", "shuffle_active.svg"))
        self._repeat_icon_off = QIcon(os.path.join("icons", "repeat.svg"))
        self._repeat_icon_on = QIcon(os.path.join("icons", "repeat_active.svg"))
        self._shuffle_svg_template = self._load_svg_template("icons/shuffle_active.svg")
        self._repeat_svg_template = self._load_svg_template("icons/repeat_active.svg")
        self._aura_hue = 0
        self._apply_shuffle_button_state(False)
        self._apply_repeat_button_state(QMediaPlaylist.Sequential)

        control_buttons = [
            self.prevButton,
            self.playButton,
            self.nextButton,
            self.seekBackwardButton,
            self.seekForwardButton,
            self.shuffleButton,
            self.repeatButton,
        ]
        for btn in control_buttons:
            btn.setFlat(True)
            btn.setStyleSheet("""
                QPushButton {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 rgba(70, 70, 70, 180),
                        stop:1 rgba(50, 50, 50, 200));
                    border: 1px solid rgba(100, 100, 100, 150);
                    border-radius: 19px;
                    padding: 2px;
                }
                QPushButton:hover {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                        stop:0 rgba(64, 196, 255, 220),
                        stop:0.5 rgba(50, 180, 240, 230),
                        stop:1 rgba(40, 160, 220, 240));
                    border: 2px solid rgba(100, 220, 255, 255);
                    transform: scale(1.05);
                }
                QPushButton:pressed {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 rgba(40, 160, 220, 240),
                        stop:1 rgba(20, 120, 180, 255));
                    border: 2px solid rgba(64, 196, 255, 255);
                }
                QPushButton:checked { 
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 rgba(64, 196, 255, 220),
                        stop:1 rgba(40, 160, 220, 240));
                    border: 2px solid rgba(100, 220, 255, 255);
                }
                QPushButton:focus { outline: none; }
            """)

        self._aura_timer = QTimer(self)
        self._aura_timer.setInterval(60)
        self._aura_timer.timeout.connect(self._update_aura_icons)
        self._aura_timer.start()

        # EQ Button (Bottom Bar)
        self.eqButton = QPushButton("🎛️")
        self.eqButton.setFixedSize(32, 32)
        self.eqButton.setToolTip("DSP Equalizer")
        self.eqButton.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 rgba(60, 70, 80, 200),
                    stop:1 rgba(38, 50, 56, 230));
                border: 1px solid rgba(85, 85, 85, 180);
                font-size: 16px;
                border-radius: 8px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 rgba(80, 100, 120, 220),
                    stop:1 rgba(55, 71, 79, 250));
                border: 1px solid rgba(64, 196, 255, 200);
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 rgba(64, 196, 255, 240),
                    stop:1 rgba(40, 160, 220, 255));
                color: #000;
                border: 1px solid rgba(100, 220, 255, 255);
            }
        """)
        self.eqButton.clicked.connect(self._toggle_popup_eq)
        
        self.popup_eq = PopupEqualizerWidget(parent=self, manager=self.audio_manager)
        # Popup'i gizli baslat
        
        # Playback Rate Controls moved to Video HUD
        # self.playbackRateLabel, self.playbackRateNormalBtn, etc. are now in video_hud

        
        # Playback rate değişkeni
        self._current_playback_rate = 1.0
        self._playback_rate_steps = [0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 1.75, 2.0]
        self.popup_eq.hide()

        # Volume Slider - Modern gradient efektli
        self.volumeSlider = GradientSlider(Qt.Horizontal)
        self.volumeSlider.setMinimumWidth(100)
        self.volumeSlider.setFixedHeight(16)  # Biraz daha ince
        self.volumeSlider.setRange(0, 100)
        self.volumeSlider.setValue(70)

        self.positionSlider = GradientSlider(Qt.Horizontal)
        self.lblCurrentTime = QLabel("00:00")
        self.lblCurrentTime.setStyleSheet("color: #40C4FF; font-weight: bold; font-family: 'Segoe UI', sans-serif; font-size: 13px;")
        self.lblCurrentTime.setFixedWidth(50)
        self.lblCurrentTime.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        
        self.lblTotalTime = QLabel("00:00")
        self.lblTotalTime.setStyleSheet("color: #888; font-weight: bold; font-family: 'Segoe UI', sans-serif; font-size: 13px;")
        self.lblTotalTime.setFixedWidth(50)
        self.fileLabel = QLabel("Şu An Çalınan: -")
        self.fileLabel.setAlignment(Qt.AlignLeft)
        self.volumeLabel = QLabel("70%")
        self.volumeLabel.setFixedWidth(45)
        self.volumeLabel.setAlignment(Qt.AlignCenter)
        self.volumeLabel.setStyleSheet("""
            QLabel {
                color: #40C4FF;
                font-weight: bold;
                font-size: 12px;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 rgba(50, 50, 50, 180),
                    stop:1 rgba(30, 30, 30, 200));
                border: 1px solid rgba(80, 80, 80, 150);
                border-radius: 6px;
                padding: 2px 4px;
            }
        """)
        self.searchBar = None
        self.search_mode = "local"
        self.search_provider = None
        self.web_seek_timer = QTimer(self)
        self.web_seek_timer.setInterval(500)
        self.web_seek_timer.timeout.connect(self._poll_web_position)
        self.web_duration_ms = 0
        self.web_position_ms = 0
        # Clipboard izleme: dışarıdan kopyalanan YouTube linklerini algıla
        self.clipboard_timer = QTimer(self)
        self.clipboard_timer.setInterval(1500)
        self.clipboard_timer.timeout.connect(self._check_clipboard_for_url)
        self.clipboard_last_text = ""
        # Otomatik indirme: panoya yeni URL geldiğinde bir kere format dialogunu aç
        # Varsayılan olarak otomatik açma kapalı olsun — kullanıcı butona tıklayınca açılsın
        self._clipboard_auto_handled = ""
        self._auto_open_format_dialog = False
        self.clipboard_timer.start()
        self.mainContentStack = None
        self.monitor_stream = None
        self.monitor_timer = None
        self.monitor_queue = collections.deque(maxlen=5)
        self.monitor_device_name = "alsa_output.pci-0000_00_1f.3.analog-stereo.monitor"
        self._monitor_jitter_buffer = collections.deque()
        self._monitor_jitter_samples = 0
        self._monitor_gate_gain = 0.0
        self._monitor_gate_last_ts = 0.0
        self.toolbar = None

        self.libraryTableWidget = LibraryTableWidget()
        self.playlistWidget = PlaylistListWidget(player=self)
        # Gömülü web görünümü
        self.webView = None
        self._web_fullscreen_window = None
        # Etkinleştir: özel bağlam menüsü için politika
        self.playlistWidget.setContextMenuPolicy(Qt.CustomContextMenu)
        # Ayarlar menüsü
        settings_action = QAction("⚙️ Ayarlar", self)
        settings_action.triggered.connect(self._open_settings_dialog)
        if not self.toolbar:
            self.toolbar = QToolBar("Ana Toolbar", self)
            self.toolbar.setMovable(False)
            self.toolbar.setFloatable(False)
            self.toolbar.setAllowedAreas(Qt.TopToolBarArea)
            self.addToolBar(Qt.TopToolBarArea, self.toolbar)
        self.toolbar.addAction(settings_action)

        # Playlist sürükle-bırak & çoklu seçim aktif
        self.playlistWidget.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.playlistWidget.setAcceptDrops(True)
        self.playlistWidget.setDragDropMode(QAbstractItemView.DropOnly)

        # Fonksiyonları widget'a bağla
        self.playlistWidget.dragEnterEvent = self.dragEnterEvent
        self.playlistWidget.dropEvent = self.dropEvent

        # EQ KALDIRILDI - Otomatik frekans hassasiyeti kullanılıyor

        # ALBUMART LABEL - sol panelde kullanılacak (burada erken oluştur)
        # ALBUMART LABEL - sol panelde kullanılacak (burada erken oluştur)
        self.albumArtLabel = AnimatedCoverLabel(self)
        self.albumArtLabel.setAlignment(Qt.AlignCenter)
        self.albumArtLabel.setMinimumSize(0, 0)
        self.albumArtLabel.setStyleSheet("background: transparent; border: none;")
        self.albumArtLabel.setText("")

        self.infoDisplayWidget = InfoDisplayWidget()
        # Bağla: InfoDisplayWidget album kapaklarını dışsal label (sol panelde) ile yönetecek
        try:
            self.infoDisplayWidget.set_external_album_label(self.albumArtLabel)
        except Exception as e:
            print(f"Album label bağlantı hatası: {e}")
        
        # 🎨 GÖRSELLEŞTİRME (Eski FFT Çubuk Tabanlı)
        self.vis_widget_main_window = AnimatedVisualizationWidget(
            parent=None,
            initial_mode=self.vis_mode,
            show_full_visual=False
        )
        # Parent player bağlantısı - albüm rengi algılama için gerekli
        self.vis_widget_main_window.parent_player = self
        self.vis_widget_main_window.setFixedHeight(100)
        self.vis_widget_main_window.set_fps(30)

        # 🎬 VIDEO'YA ÖZEL RİTİM ÇUBUKLARI (ana spectrum'dan bağımsız)
        self.vis_widget_video_window = AnimatedVisualizationWidget(
            parent=None,
            initial_mode="Spektrum Çubukları",
            show_full_visual=False
        )
        self.vis_widget_video_window.parent_player = self
        self.vis_widget_video_window.setFixedHeight(100)
        self.vis_widget_video_window.set_fps(30)

        # Hover opaklık efekti: fare geldiğinde butonlar belirsin (opacity düşsün)
        from PyQt5.QtCore import QObject
        from PyQt5.QtWidgets import QGraphicsOpacityEffect

        class _HoverOpacityFilter(QObject):
            def __init__(self, widget):
                super().__init__(widget)
                self.widget = widget
                self.effect = QGraphicsOpacityEffect(widget)
                widget.setGraphicsEffect(self.effect)
                self.effect.setOpacity(0.7)

            def eventFilter(self, obj, event):
                from PyQt5.QtCore import QEvent
                if event.type() == QEvent.Enter:
                    self.effect.setOpacity(1.0)
                elif event.type() == QEvent.Leave:
                    if hasattr(self.widget, "isChecked") and self.widget.isChecked():
                        self.effect.setOpacity(1.0)
                    else:
                        self.effect.setOpacity(0.7)
                return False

        hover_targets = [
            self.prevButton, self.playButton, self.nextButton,
            self.shuffleButton, self.repeatButton
        ]
        for w in hover_targets:
            f = _HoverOpacityFilter(w)
            w.installEventFilter(f)

    def _open_settings_dialog(self):
        """Ayarlar dialog'unu aç ve whitelist'i güncelle."""
        dlg = SettingsDialog(self.settingsManager, self)
        if dlg.exec_():
            # Ayarlar değişti; web bileşenlerine uygula
            try:
                td = self.settingsManager.get_trusted_domains()
                bs = self.settingsManager.get_bridge_allowed_sites()
                globals()['TRUSTED_DOMAINS'] = td
                globals()['BRIDGE_ALLOWED_SITES'] = bs
                print("✓ Whitelist güncellendi ve uygulandı")
            except Exception as e:
                print(f"Whitelist güncelleme hatası: {e}")



    def _toggle_video_fullscreen(self):
        """Toggle video fullscreen mode"""
        if not hasattr(self, 'video_display_widget'):
            return

        video_widget = self.video_display_widget
        video_widget.controls_widget = getattr(self, 'bottom_widget', None)

        if video_widget.video_fullscreen:
            # Exit fullscreen
            video_widget.video_fullscreen = False
            self.showNormal()
            self.showMaximized() if self.isMaximized() else self.showNormal()

            # Reset controls position
            if hasattr(self, 'bottom_widget'):
                # Reset to original position (assuming bottom layout)
                self.bottom_widget.move(0, self.height() - self.bottom_widget.height())
                self.bottom_widget.show()

            if hasattr(self, 'toolbar'):
                self.toolbar.show()

            if hasattr(self, 'menuBar') and self.menuBar():
                self.menuBar().show()

            video_widget.hide_controls_timer.stop()

        else:
            # Enter fullscreen
            video_widget.video_fullscreen = True
            self.showFullScreen()

            # Position controls at bottom
            if hasattr(self, 'bottom_widget'):
                self.bottom_widget.move(0, self.height() - self.bottom_widget.height())
                self.bottom_widget.show()

            if hasattr(self, 'toolbar'):
                self.toolbar.hide()

            if hasattr(self, 'menuBar') and self.menuBar():
                self.menuBar().hide()

            # Start hide timer
            video_widget.hide_controls_timer.start()

    def _on_video_tree_double_click(self, index):
        """Video ağacından çift tıklama ile oynat"""
        try:
            if hasattr(self, 'video_proxy') and self.video_proxy is not None:
                index = self.video_proxy.mapToSource(index)
        except Exception:
            pass
        file_path = self.video_model.filePath(index)
        if os.path.isfile(file_path):
            self._play_video_file(file_path)

    def _set_video_playlist_from_folder(self, selected_path: str):
        """Seçilen videonun klasöründeki tüm videoları ada göre sıralı liste yap."""
        try:
            folder = os.path.dirname(selected_path)
            exts = self._supported_video_exts()
            entries = []
            for name in os.listdir(folder):
                p = os.path.join(folder, name)
                if not os.path.isfile(p):
                    continue
                if os.path.splitext(name)[1].lower() not in exts:
                    continue
                entries.append(p)
            entries.sort(key=lambda p: os.path.basename(p).lower())
            self._video_playlist_paths = entries
            self._video_playlist_folder = folder
            self._video_playlist_index = entries.index(selected_path) if selected_path in entries else (0 if entries else -1)
        except Exception:
            self._video_playlist_paths = [selected_path] if selected_path else []
            self._video_playlist_folder = os.path.dirname(selected_path) if selected_path else ""
            self._video_playlist_index = 0 if selected_path else -1

    def _video_get_next_path(self):
        try:
            paths = getattr(self, "_video_playlist_paths", []) or []
            idx = int(getattr(self, "_video_playlist_index", -1))
            if idx >= 0 and (idx + 1) < len(paths):
                return paths[idx + 1]
        except Exception:
            pass
        return None

    def _update_video_playlist_ui(self):
        """Klasör/mevcut/sonraki video bilgisini kullanıcıya göster."""
        try:
            paths = getattr(self, "_video_playlist_paths", []) or []
            idx = int(getattr(self, "_video_playlist_index", -1))
            cur = getattr(self, "_video_current_path", "") or ""
            folder = getattr(self, "_video_playlist_folder", "") or (os.path.dirname(cur) if cur else "")
            total = len(paths)
            cur_name = os.path.basename(cur) if cur else "-"
            next_path = self._video_get_next_path()
            next_name = os.path.basename(next_path) if next_path else "-"
            pos_txt = f"{idx+1}/{total}" if total > 0 and idx >= 0 else "-"
            self.fileLabel.setText(f"Video Klasörü: {os.path.basename(folder) or folder} | {pos_txt} | {cur_name} | Sonraki: {next_name}")
            try:
                self.statusBar().showMessage(f"Video Klasörü: {folder} | {pos_txt}: {cur_name} | Sonraki: {next_name}", 6000)
            except Exception:
                pass
        except Exception:
            pass

    @staticmethod
    def _supported_video_exts() -> set:
        # Yaygın video uzantıları (listeleme + oynatma kontrolünde ortak)
        return {
            ".mp4", ".m4v", ".mkv", ".avi", ".mov", ".webm", ".flv", ".wmv",
            ".mpg", ".mpeg", ".ts", ".m2ts", ".mts",
            ".3gp", ".3g2", ".ogv",
        }

    @classmethod
    def _supported_video_globs(cls) -> list:
        return [f"*{ext}" for ext in sorted(cls._supported_video_exts())]

    def _play_video_file(self, path, _build_playlist: bool = True):
        """Verilen yoldaki videoyu oynat"""
        if path and os.path.exists(path):
            # Önceki videoya ait temp altyazıları temizle (video değiştiyse)
            try:
                prev = str(getattr(self, '_video_current_path', '') or '')
                if prev and os.path.abspath(prev) != os.path.abspath(path):
                    self._cleanup_video_temp_files()
            except Exception:
                pass

            # Yalnızca yaygın yerel video uzantıları desteklenir
            ext = os.path.splitext(path)[1].lower()
            if ext not in self._supported_video_exts():
                # Popup yok; durumu kibarca bildir ve oynatma kontrolünü pasif tut
                try:
                    self.statusBar().showMessage("Desteklenmeyen format: oynatma devre dışı.", 5000)
                except Exception:
                    pass
                try:
                    print(f"[VIDEO] Desteklenmeyen format: {path}")
                except Exception:
                    pass
                try:
                    self._on_video_media_status_changed(None)
                except Exception:
                    pass
                return

            # Klasörde sıralı otomatik oynatma için playlist'i hazırla
            # Not: Eğer playlist boşsa veya klasör değiştiyse, _build_playlist False olsa bile kur.
            try:
                need_build = bool(_build_playlist)
                try:
                    paths = getattr(self, "_video_playlist_paths", None)
                    folder = str(getattr(self, "_video_playlist_folder", "") or "")
                    if not isinstance(paths, list) or not paths:
                        need_build = True
                    elif os.path.dirname(path) != folder:
                        need_build = True
                except Exception:
                    need_build = True

                if need_build:
                    self._set_video_playlist_from_folder(path)
                else:
                    # Playlist önceden hazırlanmışsa index'i güncelle
                    try:
                        if path in (getattr(self, "_video_playlist_paths", []) or []):
                            self._video_playlist_index = self._video_playlist_paths.index(path)
                    except Exception:
                        pass
            except Exception:
                try:
                    self._set_video_playlist_from_folder(path)
                except Exception:
                    pass
            # Ana medya oynatıcıyı durdur (ses karışmasın)
            self.mediaPlayer.stop()
            
            # Video oynatıcı
            if hasattr(self, 'videoPlayer'):
                url = QUrl.fromLocalFile(path)
                self._video_last_source_url = url
                self._video_last_source_text = path
                self._video_current_path = path
                try:
                    # Yeni video: altyazı cache'ini sıfırla (varsa)
                    st = getattr(self, '_video_settings_state', None)
                    if isinstance(st, dict):
                        st['subtitle_items'] = []
                        st['subtitle_index'] = 0
                        st['subtitle_path'] = None
                        st['subtitle_label'] = None
                        st['subtitle_loaded_path'] = None
                        self._video_settings_state = st
                except Exception:
                    pass
                try:
                    self._clear_video_error()
                except Exception:
                    pass
                
                # Re-set probe source to ensure it catches the new media
                if hasattr(self, 'videoProbe'):
                    try:
                        self.videoProbe.setSource(None)
                        self.videoProbe.setSource(self.videoPlayer)
                    except Exception:
                        pass

                self.videoPlayer.setMedia(QMediaContent(url))
                self.videoPlayer.play()
                self.statusBar().showMessage(f"Oynatılıyor: {os.path.basename(path)}", 5000)

                # UI bilgilendirme (klasör/mevcut/sonraki)
                try:
                    self._update_video_playlist_ui()
                except Exception:
                    pass
                
                # Playback rate'i uygula (kaydedilmiş veya mevcut değeri koru)
                try:
                    if hasattr(self, '_current_playback_rate'):
                        self.videoPlayer.setPlaybackRate(self._current_playback_rate)
                except Exception:
                    pass

                # Altyazı: mümkünse otomatik etkinleştir ve yükle
                try:
                    st = getattr(self, '_video_settings_state', {})
                    if not isinstance(st, dict):
                        st = {}
                    # Kaynak varsa ve kullanıcı kapatmadıysa (default false) otomatik aç
                    sources = []
                    try:
                        sources = self._discover_video_subtitle_sources(create_templates=False)
                    except Exception:
                        sources = []
                    if sources and not bool(st.get('subtitles_enabled')):
                        st['subtitles_enabled'] = True
                        self._video_settings_state = st
                    if bool(st.get('subtitles_enabled')):
                        self._ensure_video_subtitles_loaded()
                        try:
                            pos = int(self.videoPlayer.position() or 0)
                        except Exception:
                            pos = 0
                        self._update_video_subtitle_overlay(pos)
                except Exception:
                    pass

                # Ek açıklamalar açıksa güncelle
                try:
                    st = getattr(self, '_video_settings_state', {})
                    if isinstance(st, dict) and st.get('annotations'):
                        self._update_video_info_overlay()
                except Exception:
                    pass
                
                # Video rotation'ı ffprobe ile tespit et ve uygula
                try:
                    rotation = self._detect_video_rotation(path)
                    if rotation != 0 and hasattr(self, 'video_output_widget'):
                        self.video_output_widget.rotate_video(rotation, absolute=True)
                        self.statusBar().showMessage(f"Oynatılıyor: {os.path.basename(path)} (Döndürme: {rotation}°)", 5000)
                except Exception as e:
                    print(f"Rotation detection error: {e}")
                
                try:
                    # Kontrollerin videoPlayer'a göre aktifleşmesini tetikle
                    self._on_video_media_status_changed(QMediaPlayer.LoadedMedia)
                except Exception:
                    pass

    def _detect_video_rotation(self, path: str) -> int:
        """FFprobe veya ffmpeg ile video rotation metadata'sını tespit et."""
        import subprocess
        import json
        
        rotation = 0
        
        # Önce ffprobe ile dene
        try:
            cmd = [
                'ffprobe', '-v', 'quiet', '-print_format', 'json',
                '-show_streams', '-select_streams', 'v:0', path
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                data = json.loads(result.stdout)
                streams = data.get('streams', [])
                if streams:
                    stream = streams[0]
                    # rotation side_data veya tags içinde olabilir
                    side_data = stream.get('side_data_list', [])
                    for sd in side_data:
                        if 'rotation' in sd:
                            rotation = int(sd['rotation'])
                            break
                    if rotation == 0:
                        tags = stream.get('tags', {})
                        if 'rotate' in tags:
                            rotation = int(tags['rotate'])
        except FileNotFoundError:
            # ffprobe yok, mediainfo ile dene
            try:
                cmd = ['mediainfo', '--Output=Video;%Rotation%', path]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if result.returncode == 0 and result.stdout.strip():
                    rotation = int(float(result.stdout.strip()))
            except Exception:
                pass
        except Exception as e:
            print(f"FFprobe error: {e}")
        
        # Negatif değerleri pozitife çevir
        if rotation < 0:
            rotation = 360 + rotation
        
        # Geçerli rotation değerlerine normalize et
        if rotation not in [0, 90, 180, 270]:
            # En yakın değere yuvarla
            valid = [0, 90, 180, 270, 360]
            rotation = min(valid, key=lambda x: abs(x - rotation))
            if rotation == 360:
                rotation = 0
        
        print(f"🎬 Video Rotation Detected: {rotation}° for {os.path.basename(path)}")
        return rotation

    def _clear_video_error(self):
        try:
            if hasattr(self, 'video_error_overlay') and self.video_error_overlay:
                self.video_error_overlay.setVisible(False)
            if hasattr(self, 'video_error_label') and self.video_error_label:
                self.video_error_label.setText("")
        except Exception:
            pass

    def _show_video_error(self, message: str):
        """Video oynatılamadığında kısa, net mesaj göster.

        UX kuralı: Video formatı/codec tanınmadığında veya hata olduğunda ekstra popup/overlay gösterme.
        Bunun yerine sadece statusbar + log kullan.
        """
        msg = str(message or "").strip() or "Video oynatılamadı."

        # Her ihtimale karşı overlay kapalı kalsın
        try:
            self._clear_video_error()
        except Exception:
            pass

        try:
            self.statusBar().showMessage(msg.replace("\n", " "), 7000)
        except Exception:
            pass
        try:
            print(f"[VIDEO] {msg}")
        except Exception:
            pass

    def _video_open_in_browser(self):
        """Fallback: Kaynağı sistemin varsayılan uygulamasıyla aç (URL ise tarayıcı)."""
        try:
            url = getattr(self, '_video_last_source_url', None)
            if isinstance(url, QUrl) and url.isValid():
                QDesktopServices.openUrl(url)
                return
        except Exception:
            pass

        # Son çare: metinden URL dene
        try:
            txt = str(getattr(self, '_video_last_source_text', '') or '').strip()
            if txt:
                QDesktopServices.openUrl(QUrl.fromUserInput(txt))
        except Exception:
            pass

    def _on_video_error(self, *args):
        """QMediaPlayer hata callback (signature Qt sürümüne göre değişebilir)."""
        try:
            err_txt = ""
            try:
                err_txt = str(self.videoPlayer.errorString() or "").strip()
            except Exception:
                err_txt = ""
            if not err_txt:
                err_txt = "Teknik bir nedenle video oynatılamadı."

            # Codec/decoder/plugin eksikliği: UX'i bozmamak için overlay yok, sadece kısa status/log
            low = err_txt.lower()
            codec_like = any(k in low for k in (
                "codec", "decoder", "demux", "no decoder", "missing plugin",
                "could not decode", "not supported", "format error", "h264", "hevc", "av1",
            ))
            if codec_like:
                try:
                    self._clear_video_error()
                except Exception:
                    pass
                try:
                    self.statusBar().showMessage("Video oynatılamadı (codec/decoder eksik olabilir).", 5000)
                except Exception:
                    pass
                try:
                    print(f"[VIDEO] Codec/decoder eksik olabilir: {err_txt}")
                except Exception:
                    pass
                return

            # Diğer hatalarda da overlay/popup yok: sadece status/log
            self._show_video_error(err_txt)
        except Exception:
            pass

    # ==========================================================
    #  SEKME EXCLUSIVE MOD (Müzik / Video / Web)
    # ==========================================================
    def _get_active_media_mode(self) -> str:
        """Aktif ana modu döndür: 'music' | 'video' | 'web'."""
        try:
            if hasattr(self, 'mainContentStack') and self.mainContentStack.currentIndex() == 1:
                return 'video'
        except Exception:
            pass

        # mainContentStack index 0: playlist_container_widget (içinde playlist_stack var)
        try:
            if getattr(self, 'search_mode', None) == 'web' and hasattr(self, 'playlist_stack') and self.playlist_stack:
                if getattr(self, 'webView', None) and self.playlist_stack.currentWidget() == self.webView:
                    return 'web'
        except Exception:
            pass

        return 'music'

    def _on_exclusive_tab_changed(self, *args):
        """Sekmeler arası geçişte otomatik durdurma ve kaynak salma."""
        if getattr(self, '_exclusive_mode_guard', False):
            return
        self._exclusive_mode_guard = True
        try:
            mode = self._get_active_media_mode()
            self._apply_exclusive_mode(mode)
            self._sync_ui_with_active_mode(mode)
        finally:
            self._exclusive_mode_guard = False

    def _apply_exclusive_mode(self, mode: str):
        mode = str(mode or '').strip().lower()
        if mode not in ('music', 'video', 'web'):
            mode = 'music'

        if mode == 'music':
            # Video + web tamamen durdur
            self._deactivate_video_player(release=True)
            self._suspend_web_mode()

            # Daha önce otomatik durdurduysak geri dönünce kaldığı yerden çal
            try:
                if getattr(self, '_music_resume_pending', False):
                    self._music_resume_pending = False
                    if hasattr(self, 'playlist') and self.playlist and self.playlist.mediaCount() > 0:
                        self.mediaPlayer.play()
            except Exception:
                pass
            return

        if mode == 'video':
            # Müzik durdur + resume bayrağı
            try:
                if hasattr(self, 'mediaPlayer') and self.mediaPlayer:
                    if self.mediaPlayer.state() == QMediaPlayer.PlayingState:
                        self._music_resume_pending = True
                    if self.mediaPlayer.state() != QMediaPlayer.StoppedState:
                        self.mediaPlayer.stop()
            except Exception:
                pass

            # Web'i askıya al
            self._suspend_web_mode()
            return

        if mode == 'web':
            # Müzik + video durdur
            try:
                if hasattr(self, 'mediaPlayer') and self.mediaPlayer:
                    if self.mediaPlayer.state() == QMediaPlayer.PlayingState:
                        self._music_resume_pending = True
                    if self.mediaPlayer.state() != QMediaPlayer.StoppedState:
                        self.mediaPlayer.stop()
            except Exception:
                pass
            self._deactivate_video_player(release=True)

            # Web aktif: ses mute zorlamasını kaldır (site izinliyse)
            try:
                if getattr(self, 'webView', None) and self.webView and self.webView.page():
                    self.webView.page().setAudioMuted(False)
            except Exception:
                pass
            try:
                # Köprü tabanlı mute değişkeni varsa aç
                self._set_web_audio_muted(False)
            except Exception:
                pass
            return

    def _sync_ui_with_active_mode(self, mode: str):
        """Aktif moda göre ana kontrol barını güncelle."""
        try:
            if mode == 'video':
                # Video durumunu yansıt
                state = self.videoPlayer.state()
                playing = (state == QMediaPlayer.PlayingState)
                self.update_play_button_state(playing, source="video")
                
                # Slider ve süreleri güncelle
                dur = self.videoPlayer.duration()
                pos = self.videoPlayer.position()
                self._on_video_duration_changed(dur)
                self._on_video_position_changed(pos)
                
                # Volume
                vol = self.videoPlayer.volume()
                self.volumeSlider.blockSignals(True)
                self.volumeSlider.setValue(vol)
                self.volumeSlider.blockSignals(False)
                self._update_volume_label(vol)

                # Video modunda: video ritim çubukları aktif + kapak alanı kapalı
                try:
                    if hasattr(self, 'bottom_vis_stack') and self.bottom_vis_stack:
                        self.bottom_vis_stack.setCurrentIndex(1)
                except Exception:
                    pass
                try:
                    if hasattr(self, 'album_container') and self.album_container:
                        self.album_container.setVisible(False)
                except Exception:
                    pass
                
            elif mode == 'music':
                # Müzik durumunu yansıt
                state = self.audio_engine.media_player.state()
                playing = (state == QMediaPlayer.PlayingState)
                self.update_play_button_state(playing, source="music")

                # Müzik modunda: ana spectrum + kapak alanı açık
                try:
                    if hasattr(self, 'bottom_vis_stack') and self.bottom_vis_stack:
                        self.bottom_vis_stack.setCurrentIndex(0)
                except Exception:
                    pass
                try:
                    if hasattr(self, 'album_container') and self.album_container:
                        self.album_container.setVisible(True)
                except Exception:
                    pass
                
                # Slider ve süreleri güncelle
                dur = self.audio_engine.media_player.duration()
                pos = self.audio_engine.media_player.position()
                self._on_audio_duration_changed(dur)
                self._on_audio_position_changed(pos)
                
                # Volume
                vol = self.audio_engine.media_player.volume()
                self.volumeSlider.blockSignals(True)
                self.volumeSlider.setValue(vol)
                self.volumeSlider.blockSignals(False)
                self._update_volume_label(vol)
                
        except Exception as e:
            print(f"UI Sync Error: {e}")

    def _deactivate_video_player(self, release: bool = True):
        """Video oynatıcıyı durdur ve (istersen) kaynağı serbest bırak."""
        try:
            if getattr(self, '_in_video_fullscreen', False):
                self._exit_video_fullscreen()
        except Exception:
            pass

        try:
            if hasattr(self, '_video_fps_timer') and self._video_fps_timer:
                self._video_fps_timer.stop()
        except Exception:
            pass
        try:
            if hasattr(self, '_video_refresh_timer') and self._video_refresh_timer:
                self._video_refresh_timer.stop()
        except Exception:
            pass

        try:
            if hasattr(self, 'videoPlayer') and self.videoPlayer:
                self.videoPlayer.stop()
                if release:
                    try:
                        self.videoPlayer.setMedia(QMediaContent())
                    except Exception:
                        pass
        except Exception:
            pass

        try:
            self._clear_video_error()
        except Exception:
            pass

        # Video modülüne özel temp altyazıları temizle (sekmeden çıkış / mod değişimi)
        try:
            self._cleanup_video_temp_files()
        except Exception:
            pass

    def _suspend_web_mode(self):
        """Web sekmesi aktif değilken web audio/stream/capture kaynaklarını askıya al."""
        try:
            self._stop_web_media_playback()
        except Exception:
            pass

        # JS/engine tarafında kesin mute
        try:
            self._set_web_audio_muted(True)
        except Exception:
            pass
        try:
            if getattr(self, 'webView', None) and self.webView and self.webView.page():
                self.webView.page().setAudioMuted(True)
        except Exception:
            pass

        # CPU/RAM tüketen yardımcı süreçleri durdur
        try:
            if hasattr(self, 'webPosTimer') and self.webPosTimer and self.webPosTimer.isActive():
                self.webPosTimer.stop()
        except Exception:
            pass
        try:
            self._stop_web_seek_poll()
        except Exception:
            pass
        try:
            self._stop_monitor_capture()
        except Exception:
            pass
        try:
            if getattr(self, 'audio_engine', None):
                self.audio_engine.stop_web_audio()
        except Exception:
            pass

        # Ağ/stream yükünü azalt
        try:
            if getattr(self, 'webView', None) and self.webView:
                self.webView.stop()
        except Exception:
            pass

    # def _on_video_position_changed(self, position):
    #     """Video ilerledikçe slider güncelle"""
    #     # MERGED into the other definition
    #     pass

    # def _on_video_duration_changed(self, duration):
    #     """Video süresi değişince slider aralığı güncelle"""
    #     # MERGED into the other definition
    #     pass

    @staticmethod
    def _format_ms_time(ms: int) -> str:
        """Video zamanını 00:00 veya 01:02:03 formatında döndür."""
        try:
            total_seconds = max(0, int(ms) // 1000)
        except Exception:
            total_seconds = 0

        h = total_seconds // 3600
        m = (total_seconds % 3600) // 60
        s = total_seconds % 60

        if h > 0:
            return f"{h:02d}:{m:02d}:{s:02d}"
        return f"{m:02d}:{s:02d}"

    def _format_time(self, ms):
        """Milisaniyeyi 'mm:ss' veya 'H:mm:ss' formatına çevirir."""
        # 3600000ms = 1 saat. Eğer 1 saatten uzunsa H:mm:ss, değilse mm:ss
        try:
            total_seconds = max(0, int(ms) // 1000)
        except Exception:
            total_seconds = 0

        h = total_seconds // 3600
        m = (total_seconds % 3600) // 60
        s = total_seconds % 60

        if h > 0:
            return f"{h:02d}:{m:02d}:{s:02d}"
        return f"{m:02d}:{s:02d}"

    # def _on_video_state_changed(self, state):
    #     """HUD play ikonunu güncelle."""
    #     # MERGED into the other _on_video_state_changed definition
    #     pass

    def _video_toggle_play(self):
        if not hasattr(self, 'videoPlayer'):
            return
        try:
            if self.videoPlayer.state() == QMediaPlayer.PlayingState:
                self.videoPlayer.pause()
            else:
                self.videoPlayer.play()
        except Exception:
            pass

    def _video_seek_relative(self, delta_ms: int):
        if not hasattr(self, 'videoPlayer'):
            return
        try:
            pos = int(self.videoPlayer.position() or 0)
            dur = int(self.videoPlayer.duration() or 0)
            new_pos = max(0, min(dur if dur > 0 else pos + delta_ms, pos + int(delta_ms)))
            self.videoPlayer.setPosition(new_pos)
        except Exception:
            pass

    def _video_set_volume(self, v: int):
        if not hasattr(self, 'videoPlayer'):
            return
        try:
            v = int(v)
        except Exception:
            v = 0

        v = max(0, min(100, v))

        st = getattr(self, '_video_settings_state', {})
        try:
            if isinstance(st, dict) and st.get('stable_volume'):
                v = min(v, 80)
        except Exception:
            pass

        # Boost aktifse base volume olarak kaydet, sonra boost uygula
        try:
            if isinstance(st, dict) and st.get('volume_boost'):
                st['base_volume'] = v
                v = min(100, int(round(v * 1.35)))
                self._video_settings_state = st
            else:
                if isinstance(st, dict):
                    st['base_volume'] = v
                    self._video_settings_state = st
        except Exception:
            pass

        try:
            self.videoPlayer.setMuted(False)
            self.videoPlayer.setVolume(int(v))
        except Exception:
            pass

    def _video_toggle_mute(self):
        if not hasattr(self, 'videoPlayer'):
            return
        try:
            muted = bool(self.videoPlayer.isMuted())
            self.videoPlayer.setMuted(not muted)
        except Exception:
            pass

    # =========================================================================
    # VIDEO EKRANI SES/PARLAKLIK KONTROLÜ (FARE TEKERLEĞİ İLE)
    # =========================================================================
    def _adjust_video_volume_with_indicator(self, delta):
        """Video ekranının sol tarafında fare tekerleği ile ses seviyesini ayarla."""
        if not hasattr(self, 'videoPlayer'):
            return
        try:
            current = self.videoPlayer.volume()
            step = 5
            if delta > 0:
                new_vol = min(100, current + step)
            else:
                new_vol = max(0, current - step)

            self._video_set_volume(new_vol)
            
            # Dikey gösterge çubuğunu göster
            self._show_volume_indicator(new_vol)
        except Exception:
            pass

    def _adjust_video_brightness_with_indicator(self, delta):
        """Video ekranının sağ tarafında fare tekerleği ile parlaklığı ayarla.
        
        Parlaklık değerleri:
        - 0.0 = Tamamen karanlık
        - 1.0 = Normal (orijinal video parlaklığı)
        - 2.0 = Maksimum parlaklık
        
        Bu sadece video görüntüsünü etkiler, sistem parlaklığına dokunmaz.
        """
        step = 0.08  # Her adımda %8 değişim
        if delta > 0:
            self._video_brightness = min(2.0, self._video_brightness + step)
        else:
            self._video_brightness = max(0.0, self._video_brightness - step)
        
        # Parlaklık overlay'ini güncelle
        self._update_brightness_overlay()
        
        # Dikey gösterge çubuğunu göster (0-200 aralığını 0-100'e dönüştür)
        display_value = int(self._video_brightness * 50)  # 0-100 arası göster
        self._show_brightness_indicator(display_value)

    def _show_volume_indicator(self, value):
        """Sol tarafta dikey ses göstergesi göster."""
        video_widget = getattr(self, 'video_output_widget', None)
        if not video_widget:
            return
        
        # Indicator'ı oluştur veya güncelle
        if not hasattr(self, '_volume_indicator') or self._volume_indicator is None:
            self._volume_indicator = QWidget(video_widget)
            self._volume_indicator.setFixedSize(60, 200)
            self._volume_indicator.setStyleSheet("background: transparent;")
            self._volume_indicator.setAttribute(Qt.WA_TransparentForMouseEvents)
        
        # Pozisyonu ayarla (sol taraf, dikey orta)
        x = 40
        y = (video_widget.height() - 200) // 2
        self._volume_indicator.move(x, y)
        self._volume_indicator.show()
        self._volume_indicator.raise_()
        
        # İçeriği çiz
        self._draw_vertical_indicator(self._volume_indicator, value, "🔊", QColor(64, 196, 255))
        
        # Otomatik gizleme timer'ı
        if hasattr(self, '_volume_hide_timer'):
            self._volume_hide_timer.stop()
        else:
            self._volume_hide_timer = QTimer(self)
            self._volume_hide_timer.setSingleShot(True)
            self._volume_hide_timer.timeout.connect(lambda: self._hide_indicator(self._volume_indicator))
        self._volume_hide_timer.start(1500)

    def _show_brightness_indicator(self, value):
        """Sağ tarafta dikey parlaklık göstergesi göster."""
        video_widget = getattr(self, 'video_output_widget', None)
        if not video_widget:
            return
        
        # Indicator'ı oluştur veya güncelle
        if not hasattr(self, '_brightness_indicator') or self._brightness_indicator is None:
            self._brightness_indicator = QWidget(video_widget)
            self._brightness_indicator.setFixedSize(60, 200)
            self._brightness_indicator.setStyleSheet("background: transparent;")
            self._brightness_indicator.setAttribute(Qt.WA_TransparentForMouseEvents)
        
        # Pozisyonu ayarla (sağ taraf, dikey orta)
        x = video_widget.width() - 100
        y = (video_widget.height() - 200) // 2
        self._brightness_indicator.move(x, y)
        self._brightness_indicator.show()
        self._brightness_indicator.raise_()
        
        # İçeriği çiz
        self._draw_vertical_indicator(self._brightness_indicator, value, "☀", QColor(255, 193, 7))
        
        # Otomatik gizleme timer'ı
        if hasattr(self, '_brightness_hide_timer'):
            self._brightness_hide_timer.stop()
        else:
            self._brightness_hide_timer = QTimer(self)
            self._brightness_hide_timer.setSingleShot(True)
            self._brightness_hide_timer.timeout.connect(lambda: self._hide_indicator(self._brightness_indicator))
        self._brightness_hide_timer.start(1500)

    def _draw_vertical_indicator(self, widget, value, icon, color):
        """Dikey gösterge çubuğunu çiz."""
        # Mevcut pixmap'i temizle ve yeniden çiz
        pixmap = QPixmap(widget.size())
        pixmap.fill(Qt.transparent)
        
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Arka plan (yarı saydam yuvarlak dikdörtgen)
        bg_rect = QRectF(0, 0, 60, 200)
        painter.setBrush(QColor(0, 0, 0, 180))
        painter.setPen(Qt.NoPen)
        painter.drawRoundedRect(bg_rect, 15, 15)
        
        # İkon (üstte)
        painter.setPen(QColor(255, 255, 255))
        font = painter.font()
        font.setPointSize(18)
        painter.setFont(font)
        painter.drawText(QRectF(0, 10, 60, 30), Qt.AlignCenter, icon)
        
        # Değer yüzdesi (ortada)
        font.setPointSize(14)
        font.setBold(True)
        painter.setFont(font)
        painter.drawText(QRectF(0, 40, 60, 25), Qt.AlignCenter, f"{value}%")
        
        # Dikey çubuk (altta)
        bar_x = 22
        bar_y = 75
        bar_width = 16
        bar_height = 110
        
        # Çubuk arka planı
        painter.setBrush(QColor(60, 60, 60))
        painter.drawRoundedRect(QRectF(bar_x, bar_y, bar_width, bar_height), 8, 8)
        
        # Dolu kısım (aşağıdan yukarı)
        fill_height = int((value / 100.0) * bar_height)
        if fill_height > 0:
            fill_y = bar_y + bar_height - fill_height
            grad = QLinearGradient(bar_x, fill_y, bar_x, bar_y + bar_height)
            grad.setColorAt(0, color)
            grad.setColorAt(1, color.darker(120))
            painter.setBrush(grad)
            painter.drawRoundedRect(QRectF(bar_x, fill_y, bar_width, fill_height), 8, 8)
        
        painter.end()
        
        # Widget'a label olarak ekle
        if not hasattr(widget, '_indicator_label'):
            widget._indicator_label = QLabel(widget)
            widget._indicator_label.setGeometry(0, 0, 60, 200)
        widget._indicator_label.setPixmap(pixmap)
        widget._indicator_label.show()

    def _hide_indicator(self, indicator):
        """Göstergeyi gizle."""
        if indicator:
            indicator.hide()

    def _update_brightness_overlay(self):
        """Video parlaklık overlay'ini güncelle.
        
        Bu fonksiyon SADECE video görüntüsünü etkiler, sistem parlaklığına dokunmaz.
        
        Parlaklık değerleri:
        - 0.0 = Tamamen karanlık (siyah overlay %100)
        - 1.0 = Normal (overlay yok)
        - 2.0 = Maksimum parlaklık (beyaz overlay ile parlaklaştırma)
        """
        video_widget = getattr(self, 'video_output_widget', None)
        if not video_widget:
            return
        
        # Karartma overlay'i oluştur (siyah)
        if not hasattr(self, '_brightness_overlay') or self._brightness_overlay is None:
            self._brightness_overlay = QWidget(video_widget)
            self._brightness_overlay.setAttribute(Qt.WA_TransparentForMouseEvents)
            self._brightness_overlay.setObjectName("videoBrightnessOverlay")
        
        # Parlaklaştırma overlay'i oluştur (beyaz)
        if not hasattr(self, '_brighten_overlay') or self._brighten_overlay is None:
            self._brighten_overlay = QWidget(video_widget)
            self._brighten_overlay.setAttribute(Qt.WA_TransparentForMouseEvents)
            self._brighten_overlay.setObjectName("videoBrightenOverlay")
        
        # Tam ekran boyutunda
        self._brightness_overlay.setGeometry(0, 0, video_widget.width(), video_widget.height())
        self._brighten_overlay.setGeometry(0, 0, video_widget.width(), video_widget.height())
        
        brightness = self._video_brightness
        
        if brightness < 1.0:
            # KARARTMA: 0.0-1.0 arası = siyah overlay ile karart
            # brightness=0.0 -> alpha=255 (tamamen siyah)
            # brightness=1.0 -> alpha=0 (şeffaf)
            alpha = int((1.0 - brightness) * 255)
            self._brightness_overlay.setStyleSheet(f"background: rgba(0, 0, 0, {alpha});")
            self._brightness_overlay.show()
            self._brightness_overlay.raise_()
            self._brighten_overlay.hide()
            
        elif brightness > 1.0:
            # PARLAKLAŞTIRMA: 1.0-2.0 arası = beyaz overlay ile parlaklaştır
            # brightness=1.0 -> alpha=0 (şeffaf)
            # brightness=2.0 -> alpha=180 (parlak beyaz, tam beyaz değil)
            alpha = int((brightness - 1.0) * 180)
            self._brighten_overlay.setStyleSheet(f"background: rgba(255, 255, 255, {alpha});")
            self._brighten_overlay.show()
            self._brighten_overlay.raise_()
            self._brightness_overlay.hide()
            
        else:
            # NORMAL: brightness=1.0, her iki overlay da gizli
            self._brightness_overlay.hide()
            self._brighten_overlay.hide()
        
        # Indicator'ları her zaman en üstte tut
        if hasattr(self, '_volume_indicator') and self._volume_indicator:
            self._volume_indicator.raise_()
        if hasattr(self, '_brightness_indicator') and self._brightness_indicator:
            self._brightness_indicator.raise_()

        # Altyazıyı her zaman görünür tut (sadece video overlay alanında)
        try:
            if hasattr(self, '_video_subtitle_label') and self._video_subtitle_label and self._video_subtitle_label.isVisible():
                self._video_subtitle_label.raise_()
        except Exception:
            pass

        # Altyazı overlay'ini parlaklık katmanlarının üstünde tut
        try:
            self._raise_video_subtitle_overlay()
        except Exception:
            pass

    def _raise_video_subtitle_overlay(self):
        """Video altyazı label'ini her durumda en üstte tut (yalnız video overlay alanı)."""
        try:
            if hasattr(self, '_video_subtitle_label') and self._video_subtitle_label:
                # Sadece video overlay host içindeki stacking'i etkiler
                self._video_subtitle_label.raise_()
        except Exception:
            pass

    def _set_playback_rate(self, rate: float):
        """Video oynatma hızını ayarla."""
        if not hasattr(self, 'videoPlayer'):
            return
        try:
            # Rate'i geçerli aralıkta tut
            rate = max(0.25, min(2.0, rate))
            self._current_playback_rate = rate
            self.videoPlayer.setPlaybackRate(rate)
            
            # Label'ı güncelle
            if hasattr(self, 'playbackRateLabel'):
                self.playbackRateLabel.setText(f"{rate:.2f}x")
            
            # Durum çubuğunda bildir
            self.statusBar().showMessage(f"Oynatma hızı: {rate:.2f}x", 2000)
        except Exception as e:
            print(f"Playback rate ayarlama hatası: {e}")

    def _cycle_playback_rate(self):
        """Oynatma hızını döngüsel olarak değiştir."""
        rates = [0.5, 0.75, 1.0, 1.25, 1.5, 2.0]
        current = getattr(self, '_current_playback_rate', 1.0)
        next_rate = 1.0
        for r in rates:
            if r > current + 0.01: # Küçük tolerans
                next_rate = r
                break
        else:
            next_rate = rates[0]
        self._set_playback_rate(next_rate)

    def _set_playback_rate_normal(self):
        """Normal hıza (1.0x) dön."""
        self._set_playback_rate(1.0)

    def _increase_playback_rate(self):
        """Playback rate'i bir kademe artır."""
        try:
            current = self._current_playback_rate
            # Mevcut rate'den büyük en küçük adımı bul
            next_rate = None
            for step in self._playback_rate_steps:
                if step > current + 0.01:  # Küçük tolerans
                    next_rate = step
                    break
            
            if next_rate is None:
                # Son adımdaysak, maksimum değerde kal
                next_rate = self._playback_rate_steps[-1]
            
            self._set_playback_rate(next_rate)
        except Exception as e:
            print(f"Hız artırma hatası: {e}")

    def _decrease_playback_rate(self):
        """Playback rate'i bir kademe azalt."""
        try:
            current = self._current_playback_rate
            # Mevcut rate'den küçük en büyük adımı bul
            prev_rate = None
            for step in reversed(self._playback_rate_steps):
                if step < current - 0.01:  # Küçük tolerans
                    prev_rate = step
                    break
            
            if prev_rate is None:
                # İlk adımdaysak, minimum değerde kal
                prev_rate = self._playback_rate_steps[0]
            
            self._set_playback_rate(prev_rate)
        except Exception as e:
            print(f"Hız azaltma hatası: {e}")

    def _on_video_volume_changed(self, v: int):
        """VideoPlayer ses değiştiğinde (izole)."""
        pass  # HUD kaldırıldı, ana bar kontrolü yeterli

    def _on_video_muted_changed(self, muted: bool):
        """VideoPlayer mute değişince (izole)."""
        pass  # HUD kaldırıldı, ana bar kontrolü yeterli

    def _on_video_media_status_changed(self, status):
        """Medya yokken video HUD kontrollerini pasifleştir."""
        try:
            has_media = False
            try:
                # LoadedMedia / BufferedMedia gibi durumlarda kontrol aç
                has_media = status in (
                    QMediaPlayer.LoadedMedia,
                    QMediaPlayer.BufferedMedia,
                    QMediaPlayer.BufferingMedia,
                    QMediaPlayer.StalledMedia,
                    QMediaPlayer.EndOfMedia,
                )
            except Exception:
                # Enum erişimi yoksa en azından duration ile yaklaş
                has_media = bool(getattr(self.videoPlayer, 'duration', lambda: 0)() > 0)

            # Video kontrolleri artık ana bar üzerinden yönetiliyor
            # Klasör içi otomatik oynatma: video bittiğinde sıradakine geç
            try:
                if status == QMediaPlayer.EndOfMedia:
                    # Video bitti: bu videoya ait temp altyazıları temizle
                    try:
                        self._cleanup_video_temp_files()
                    except Exception:
                        pass

                    paths = getattr(self, "_video_playlist_paths", []) or []
                    idx = int(getattr(self, "_video_playlist_index", -1))
                    if idx >= 0 and (idx + 1) < len(paths):
                        next_path = paths[idx + 1]
                        self._video_playlist_index = idx + 1
                        self._play_video_file(next_path, _build_playlist=False)
                        return
                    elif idx >= 0 and len(paths) > 0:
                        # Liste bitti
                        try:
                            self.statusBar().showMessage("Video listesi bitti.", 4000)
                        except Exception:
                            pass
                        try:
                            # Çubukları yumuşakça düşür
                            self.send_video_visual_data(0.0, [0.0] * 96)
                        except Exception:
                            pass
            except Exception:
                pass
        except Exception:
            pass

    def _on_video_frame_rendered(self):
        try:
            self._video_fps_frames += 1
        except Exception:
            pass

    def _update_video_fps(self):
        """Video FPS güncelleme - HUD kaldırıldı."""
        try:
            fps = int(getattr(self, '_video_fps_frames', 0))
            self._video_fps_frames = 0
            # FPS göstergesi kaldırıldı - tek bar prensibi
        except Exception:
            pass

    def _qcolor_rgba(self, c: QColor, a: int) -> str:
        try:
            a = max(0, min(255, int(a)))
        except Exception:
            a = 255
        try:
            return f"rgba({c.red()},{c.green()},{c.blue()},{a})"
        except Exception:
            return "rgba(255,255,255,255)"

    def _apply_video_ui_theme(self):
        """Video kontrollerini tema/palette'e göre modern (YouTube benzeri) stillendir."""
        try:
            primary, text, bg = self._get_current_theme_colors()
        except Exception:
            pal = self.palette()
            primary, text, bg = pal.color(QPalette.Highlight), pal.color(QPalette.Text), pal.color(QPalette.Window)

        try:
            bg_val = int(bg.value())
        except Exception:
            bg_val = 0
        is_dark = bg_val < 140

        # Arka plan üzerine hafif "chip" rengi (tema uyumlu)
        mix_to = QColor(255, 255, 255) if is_dark else QColor(0, 0, 0)
        chip = self._mix_qcolors(bg, mix_to, 0.18)
        chip_hover = self._mix_qcolors(bg, mix_to, 0.26)
        border = self._mix_qcolors(chip, primary, 0.35)

        btn_style = (
            "QToolButton {"
            f" color: {self._qcolor_rgba(text, 235)};"
            f" background-color: {self._qcolor_rgba(chip, 170)};"
            f" border: 1px solid {self._qcolor_rgba(border, 180)};"
            " border-radius: 18px;"
            " padding: 6px;"
            " min-width: 36px; min-height: 36px;"
            "}"
            "QToolButton:disabled {"
            f" color: {self._qcolor_rgba(text, 120)};"
            f" background-color: {self._qcolor_rgba(chip, 90)};"
            f" border: 1px solid {self._qcolor_rgba(border, 80)};"
            "}"
            "QToolButton:hover {"
            f" background-color: {self._qcolor_rgba(chip_hover, 200)};"
            f" border: 1px solid {self._qcolor_rgba(primary, 200)};"
            "}"
            "QToolButton:pressed {"
            f" background-color: {self._qcolor_rgba(primary, 110)};"
            f" border: 1px solid {self._qcolor_rgba(primary, 220)};"
            "}"
        )

        lbl_style = f"color: {self._qcolor_rgba(text, 230)}; padding: 0 6px;"
        time_style = f"color: {self._qcolor_rgba(text, 220)}; padding: 0 6px;"

        # Normal mod zaman etiketleri
        for w in (getattr(self, 'video_time_current', None), getattr(self, 'video_time_total', None)):
            try:
                if w is not None:
                    w.setStyleSheet(time_style)
            except Exception:
                pass

        # Sadece video_fs_button için tema güncelle
        if hasattr(self, 'video_fs_button') and self.video_fs_button:
            try:
                self.video_fs_button.setStyleSheet(btn_style)
                self.video_fs_button.setCursor(Qt.PointingHandCursor)
                self.video_fs_button.setIconSize(QSize(18, 18))
            except Exception:
                pass

    def _on_fullscreen_mouse_move(self):
        """Unified handler for mouse movement in any fullscreen mode (Video or Web)."""
        is_video_fs = getattr(self, '_in_video_fullscreen', False)
        is_web_fs = getattr(self, '_in_web_fullscreen', False)

        if not (is_video_fs or is_web_fs):
            return
        
        # Cursor'ı hemen göster
        self.setCursor(Qt.ArrowCursor)
        if is_web_fs and hasattr(self, 'webView') and self.webView:
            self.webView.setCursor(Qt.ArrowCursor)
        if is_video_fs and hasattr(self, 'video_output_widget') and self.video_output_widget:
            self.video_output_widget.setCursor(Qt.ArrowCursor)
            if self.video_output_widget.viewport():
                self.video_output_widget.viewport().setCursor(Qt.ArrowCursor)
            
            # Video tam ekran bar auto-hide sistemini tetikle
            self._on_fs_mouse_move()
    
    # HUD fonksiyonları kaldırıldı - tam ekran HUD artık kullanılmıyor
    def _show_hud_with_animation(self):
        """HUD kaldırıldı - bu fonksiyon artık kullanılmıyor"""
        pass

    def _hide_video_hud(self):
        """HUD kaldırıldı - bu fonksiyon artık kullanılmıyor"""
        pass

    def _is_any_menu_open(self):
        """Herhangi bir menü veya popup açık mı kontrol et."""
        try:
            app = QApplication.instance()
            if app:
                active_popup = app.activePopupWidget()
                if active_popup:
                    return True
                active_modal = app.activeModalWidget()
                if active_modal:
                    return True
        except Exception:
            pass
        return False

    def _toggle_hud_pin(self):
        """HUD kaldırıldı - bu fonksiyon artık kullanılmıyor"""
        pass

    def _update_video_fullscreen_icons(self):
        """Video tam ekran buton simgesini güncelle (tek bar prensibi)."""
        in_fs = bool(getattr(self, '_in_video_fullscreen', False))
        try:
            if hasattr(self, 'video_fs_button') and self.video_fs_button:
                self.video_fs_button.setIcon(
                    self.style().standardIcon(QStyle.SP_TitleBarNormalButton if in_fs else QStyle.SP_TitleBarMaxButton)
                )
                self.video_fs_button.setToolTip("Tam ekrandan çık (ESC)" if in_fs else "Tam Ekran (F11)")
        except Exception:
            pass

    def _video_force_refresh(self):
        """Hedef FPS için viewport'u zorla tazele (decode FPS'i kilitlemez, sadece çizimi sınırlar)."""
        try:
            if not hasattr(self, 'video_output_widget') or self.video_output_widget is None:
                return
            # Video sayfası görünür değilse CPU harcama
            visible = bool(getattr(self, '_in_video_fullscreen', False))
            if not visible:
                try:
                    visible = bool(hasattr(self, 'mainContentStack') and self.mainContentStack.currentIndex() == 1)
                except Exception:
                    visible = False
            if not visible:
                return
            try:
                self.video_output_widget.viewport().update()
            except Exception:
                self.video_output_widget.update()
        except Exception:
            pass

    def _apply_video_target_fps_timer(self):
        try:
            if not hasattr(self, '_video_refresh_timer') or self._video_refresh_timer is None:
                return
            target = int(getattr(self, '_video_target_fps', 0) or 0)

            # Oynatmıyorsa timer'ı kapat
            try:
                is_playing = bool(hasattr(self, 'videoPlayer') and self.videoPlayer.state() == QMediaPlayer.PlayingState)
            except Exception:
                is_playing = False

            if (not is_playing) or target <= 0:
                if self._video_refresh_timer.isActive():
                    self._video_refresh_timer.stop()
                return

            interval_ms = max(1, int(round(1000.0 / float(target))))
            if self._video_refresh_timer.interval() != interval_ms or not self._video_refresh_timer.isActive():
                self._video_refresh_timer.start(interval_ms)
        except Exception:
            try:
                if hasattr(self, '_video_refresh_timer') and self._video_refresh_timer:
                    self._video_refresh_timer.stop()
            except Exception:
                pass

    def _set_video_target_fps(self, fps: int):
        try:
            fps = int(fps)
        except Exception:
            fps = 0
        if fps not in (0, 24, 30, 60):
            fps = 0
        self._video_target_fps = fps
        
        try:
            self._apply_video_target_fps_timer()
        except Exception:
            pass

    def _set_video_quality_mode(self, mode: str):
        try:
            mode = str(mode or "").strip().upper()
        except Exception:
            mode = "KALİTE"
        if mode not in ("KALİTE", "PERFORMANS"):
            mode = "KALİTE"
        self._video_quality_mode = mode

        if not hasattr(self, 'video_output_widget') or self.video_output_widget is None:
            return

        try:
            if mode == "PERFORMANS":
                try:
                    self.video_output_widget.setRenderHint(QPainter.Antialiasing, False)
                except Exception:
                    pass
                try:
                    self.video_output_widget.setRenderHint(QPainter.SmoothPixmapTransform, False)
                except Exception:
                    pass
                try:
                    self.video_output_widget.setViewportUpdateMode(QGraphicsView.MinimalViewportUpdate)
                except Exception:
                    pass
            else:
                try:
                    self.video_output_widget.setRenderHint(QPainter.Antialiasing, True)
                except Exception:
                    pass
                try:
                    self.video_output_widget.setRenderHint(QPainter.SmoothPixmapTransform, True)
                except Exception:
                    pass
                try:
                    self.video_output_widget.setViewportUpdateMode(QGraphicsView.FullViewportUpdate)
                except Exception:
                    pass
        except Exception:
            pass

    # =========================================================================
    # VIDEO: YouTube tarzı ayarlar paneli (Sadece video overlay içinde)
    # =========================================================================
    def _create_video_settings_ui(self):
        """Video penceresi üstünde (overlay) dişli + YouTube benzeri ayar paneli oluştur."""
        if not hasattr(self, 'video_overlay_host') or self.video_overlay_host is None:
            return

        # Durumlar (Sadece video için)
        if not hasattr(self, '_video_settings_state'):
            self._video_settings_state = {
                'volume_boost': False,
                'stable_volume': False,
                'cinematic': False,
                'annotations': False,
                'subtitles_enabled': False,
                'sleep_minutes': 0,
                'subtitle_items': [],
                'subtitle_index': 0,
                'subtitle_path': None,
                'subtitle_label': None,
                'subtitle_loaded_path': None,
                'base_volume': None,
            }

        # Dişli butonu (video üstünde, bardan bağımsız)
        try:
            if hasattr(self, 'video_settings_button') and self.video_settings_button:
                return
        except Exception:
            pass

        self.video_settings_button = QToolButton(self.video_overlay_host)
        self.video_settings_button.setObjectName('videoSettingsButton')
        try:
            icon_path = os.path.join(os.path.dirname(__file__), 'icons', 'configure.png')
            if os.path.exists(icon_path):
                self.video_settings_button.setIcon(QIcon(icon_path))
            else:
                self.video_settings_button.setIcon(self.style().standardIcon(QStyle.SP_FileDialogDetailedView))
        except Exception:
            self.video_settings_button.setIcon(self.style().standardIcon(QStyle.SP_FileDialogDetailedView))
        self.video_settings_button.setAutoRaise(True)
        self.video_settings_button.setToolTip('Video Ayarları')
        self.video_settings_button.setFixedSize(40, 40)
        self.video_settings_button.setIconSize(QSize(22, 22))
        self.video_settings_button.setCursor(Qt.PointingHandCursor)
        self.video_settings_button.clicked.connect(self._toggle_video_settings_panel)
        self.video_settings_button.setStyleSheet("""
            QToolButton#videoSettingsButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 rgba(50, 50, 50, 200),
                    stop:1 rgba(30, 30, 30, 230));
                border: 1px solid rgba(85, 85, 85, 150);
                border-radius: 10px;
                padding: 4px;
            }
            QToolButton#videoSettingsButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 rgba(64, 196, 255, 200),
                    stop:1 rgba(40, 160, 220, 230));
                border: 2px solid rgba(100, 220, 255, 255);
            }
            QToolButton#videoSettingsButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 rgba(40, 160, 220, 240),
                    stop:1 rgba(20, 120, 180, 255));
                border: 2px solid rgba(64, 196, 255, 255);
            }
        """)
        self.video_settings_button.show()
        self.video_settings_button.raise_()

        # Panel
        self._video_settings_panel = QFrame(self.video_overlay_host)
        self._video_settings_panel.setObjectName('videoSettingsPanel')
        self._video_settings_panel.setVisible(False)
        try:
            self._video_settings_panel.setAttribute(Qt.WA_StyledBackground, True)
            self._video_settings_panel.setAutoFillBackground(True)
        except Exception:
            pass
        self._video_settings_panel.setStyleSheet("""
            QFrame#videoSettingsPanel {
                background: rgba(15, 15, 15, 165);
                border: 1px solid rgba(255,255,255,70);
                border-radius: 14px;
            }
            QToolButton#videoSettingsRow {
                background: transparent;
                border: none;
                color: #ffffff;
                padding: 10px 12px;
                text-align: left;
                font-size: 14px;
            }
            QToolButton#videoSettingsRow:hover {
                background: rgba(255,255,255,28);
                border-radius: 10px;
            }
            QToolButton#videoSettingsRow:checked {
                background: rgba(64,196,255,45);
                border-radius: 10px;
            }
            QLabel#videoSettingsValue {
                color: rgba(255,255,255,180);
                font-size: 13px;
            }
            QLabel#videoSettingsChevron {
                color: rgba(255,255,255,150);
                font-size: 16px;
                padding-left: 6px;
            }
            QLabel#videoSettingsHeader {
                color: #ffffff;
                font-size: 14px;
                font-weight: bold;
            }
            QToolButton#videoSettingsBack {
                background: transparent;
                border: none;
                color: #ffffff;
                padding: 8px 10px;
            }
            QToolButton#videoSettingsOption {
                background: transparent;
                border: none;
                color: #ffffff;
                padding: 10px 12px;
                text-align: left;
                font-size: 14px;
            }
            QToolButton#videoSettingsOption:hover {
                background: rgba(255,255,255,30);
                border-radius: 10px;
            }
            QToolButton#videoSettingsOption:checked {
                background: rgba(64,196,255,70);
                border-radius: 10px;
            }
        """)
        self._video_settings_panel.setFixedWidth(360)

        self._video_settings_stack = QStackedWidget(self._video_settings_panel)
        panel_layout = QVBoxLayout(self._video_settings_panel)
        panel_layout.setContentsMargins(10, 10, 10, 10)
        panel_layout.addWidget(self._video_settings_stack)

        self._video_settings_page_main = QWidget()
        self._video_settings_page_speed = QWidget()
        self._video_settings_page_quality = QWidget()
        self._video_settings_page_sleep = QWidget()
        self._video_settings_page_subtitles = QWidget()

        self._video_settings_stack.addWidget(self._video_settings_page_main)
        self._video_settings_stack.addWidget(self._video_settings_page_speed)
        self._video_settings_stack.addWidget(self._video_settings_page_quality)
        self._video_settings_stack.addWidget(self._video_settings_page_sleep)
        self._video_settings_stack.addWidget(self._video_settings_page_subtitles)
        self._video_settings_stack.setCurrentWidget(self._video_settings_page_main)

        self._build_video_settings_pages()

        # Cinematic overlay
        self._video_cinematic_overlay = QWidget(self.video_overlay_host)
        self._video_cinematic_overlay.setVisible(False)
        self._video_cinematic_overlay.setAttribute(Qt.WA_TransparentForMouseEvents)
        self._video_cinematic_overlay.setStyleSheet("""
            QWidget {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 rgba(0,0,0,20),
                    stop:0.65 rgba(0,0,0,0),
                    stop:1 rgba(0,0,0,120));
            }
        """)
        self._video_cinematic_overlay.lower()

        # Annotations/info overlay
        self._video_info_overlay = QWidget(self.video_overlay_host)
        self._video_info_overlay.setVisible(False)
        self._video_info_overlay.setAttribute(Qt.WA_TransparentForMouseEvents)
        self._video_info_overlay.setStyleSheet(
            "background: rgba(0,0,0,160); border: 1px solid rgba(255,255,255,60); border-radius: 12px;"
        )
        info_l = QVBoxLayout(self._video_info_overlay)
        info_l.setContentsMargins(12, 10, 12, 10)
        self._video_info_label = QLabel('')
        self._video_info_label.setStyleSheet('color: white; font-size: 13px;')
        self._video_info_label.setWordWrap(True)
        info_l.addWidget(self._video_info_label)

        # Subtitles overlay
        self._video_subtitle_label = QLabel('', self.video_overlay_host)
        self._video_subtitle_label.setVisible(False)
        self._video_subtitle_label.setAlignment(Qt.AlignCenter)
        self._video_subtitle_label.setWordWrap(True)
        self._video_subtitle_label.setAttribute(Qt.WA_TransparentForMouseEvents)
        self._video_subtitle_label.setStyleSheet(
            "color: white; background: rgba(0,0,0,170); padding: 10px 14px; border-radius: 10px;"
            " font-size: 18px; font-weight: 600;"
        )

        # Sleep timer
        self._video_sleep_timer = QTimer(self)
        self._video_sleep_timer.setSingleShot(True)
        self._video_sleep_timer.timeout.connect(self._on_video_sleep_timeout)

        # Video overlay resize izleme
        try:
            self.video_overlay_host.installEventFilter(self)
        except Exception:
            pass

        try:
            self._reposition_video_settings_ui()
        except Exception:
            pass

    def _build_video_settings_pages(self):
        """Panel sayfalarını oluştur/güncelle."""
        def _ensure_vlayout(w: QWidget, margins=(0, 0, 0, 0), spacing=4):
            lay = w.layout()
            if lay is None:
                lay = QVBoxLayout(w)
            else:
                while lay.count():
                    it = lay.takeAt(0)
                    child = it.widget()
                    if child:
                        child.setParent(None)
            try:
                lay.setContentsMargins(*margins)
            except Exception:
                pass
            try:
                lay.setSpacing(int(spacing))
            except Exception:
                pass
            return lay

        def _header(title: str, back_cb):
            row = QWidget()
            hl = QHBoxLayout(row)
            hl.setContentsMargins(0, 0, 0, 0)
            back = QToolButton()
            back.setObjectName('videoSettingsBack')
            back.setText('←')
            back.setCursor(Qt.PointingHandCursor)
            back.clicked.connect(back_cb)
            lab = QLabel(title)
            lab.setObjectName('videoSettingsHeader')
            hl.addWidget(back)
            hl.addWidget(lab, 1)
            return row

        def _make_row(title: str, value: str, cb, *, icon: QIcon = None, has_submenu: bool = False,
                      is_toggle: bool = False, checked: bool = False):
            row = QWidget()
            hl = QHBoxLayout(row)
            hl.setContentsMargins(0, 0, 0, 0)
            btn = QToolButton()
            btn.setObjectName('videoSettingsRow')
            btn.setText(title)
            if icon is not None:
                btn.setIcon(icon)
                btn.setIconSize(QSize(22, 22))
                btn.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
            else:
                btn.setToolButtonStyle(Qt.ToolButtonTextOnly)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setAutoRaise(True)
            btn.clicked.connect(cb)
            if is_toggle:
                btn.setCheckable(True)
                btn.setChecked(bool(checked))
            val = QLabel(value)
            val.setObjectName('videoSettingsValue')
            chevron = QLabel('›')
            chevron.setObjectName('videoSettingsChevron')
            chevron.setVisible(bool(has_submenu))
            hl.addWidget(btn, 1)
            hl.addWidget(val, 0, Qt.AlignRight)
            hl.addWidget(chevron, 0, Qt.AlignRight)
            return row

        def _make_option_list(w: QWidget, title: str, options, current_key, on_select):
            lay = _ensure_vlayout(w, margins=(0, 0, 0, 0), spacing=4)
            lay.addWidget(_header(title, lambda: self._video_settings_stack.setCurrentWidget(self._video_settings_page_main)))
            for key, label in options:
                b = QToolButton()
                b.setObjectName('videoSettingsOption')
                b.setText(label)
                b.setCursor(Qt.PointingHandCursor)
                b.setCheckable(True)
                b.setAutoRaise(True)
                b.setChecked(str(key) == str(current_key))
                b.clicked.connect(lambda _=False, k=key: on_select(k))
                lay.addWidget(b)
            lay.addStretch(1)

        st = getattr(self, '_video_settings_state', {})

        def _std_icon(sp):
            try:
                return self.style().standardIcon(sp)
            except Exception:
                return None

        def _icon_from_file(name: str):
            try:
                p = os.path.join(os.path.dirname(__file__), 'icons', name)
                if os.path.exists(p):
                    return QIcon(p)
            except Exception:
                pass
            return None

        icon_boost = _icon_from_file('audio-volume-high.png') or _std_icon(QStyle.SP_MediaVolume)
        icon_stable = _std_icon(QStyle.SP_BrowserReload)
        icon_cine = _std_icon(QStyle.SP_DesktopIcon)
        icon_anno = _std_icon(QStyle.SP_MessageBoxInformation)
        icon_subs = _std_icon(QStyle.SP_FileDialogContentsView)
        icon_sleep = _std_icon(QStyle.SP_DialogResetButton)
        icon_speed = _std_icon(QStyle.SP_MediaPlay)
        icon_quality = _std_icon(QStyle.SP_FileDialogDetailedView)

        # --- MAIN PAGE ---
        main_l = _ensure_vlayout(self._video_settings_page_main, margins=(0, 0, 0, 0), spacing=4)

        main_l.addWidget(_make_row('Ses artırma', 'Açık' if st.get('volume_boost') else 'Kapalı',
                       self._toggle_video_volume_boost, icon=icon_boost, is_toggle=True, checked=st.get('volume_boost')))
        main_l.addWidget(_make_row('Sabit ses', 'Açık' if st.get('stable_volume') else 'Kapalı',
                       self._toggle_video_stable_volume, icon=icon_stable, is_toggle=True, checked=st.get('stable_volume')))
        main_l.addWidget(_make_row('Sinematik ışıklandırma', 'Açık' if st.get('cinematic') else 'Kapalı',
                       self._toggle_video_cinematic, icon=icon_cine, is_toggle=True, checked=st.get('cinematic')))
        main_l.addWidget(_make_row('Ek Açıklamalar', 'Açık' if st.get('annotations') else 'Kapalı',
                       self._toggle_video_annotations, icon=icon_anno, is_toggle=True, checked=st.get('annotations')))

        subs_val = 'Kapalı'
        try:
            if st.get('subtitles_enabled'):
                subs_val = str(st.get('subtitle_label') or '').strip() or 'Açık'
        except Exception:
            subs_val = 'Açık' if st.get('subtitles_enabled') else 'Kapalı'
        main_l.addWidget(_make_row('Altyazılar', subs_val,
                       self._open_video_subtitles_menu, icon=icon_subs, has_submenu=True))

        sleep_val = 'Kapalı'
        try:
            mins = int(st.get('sleep_minutes') or 0)
            if mins > 0:
                sleep_val = f"{mins} dk"
        except Exception:
            pass
        main_l.addWidget(_make_row('Uyku modu zamanlayıcı', sleep_val, self._open_video_sleep_menu,
                       icon=icon_sleep, has_submenu=True))

        rate_val = 'Normal'
        try:
            r = float(getattr(self, '_current_playback_rate', 1.0) or 1.0)
            rate_val = 'Normal' if abs(r - 1.0) < 1e-6 else f"{r:.2g}x"
        except Exception:
            pass
        main_l.addWidget(_make_row('Çalma hızı', rate_val, self._open_video_speed_menu,
                       icon=icon_speed, has_submenu=True))

        q_val = 'Otomatik'
        try:
            fps = int(getattr(self, '_video_target_fps', 0) or 0)
            qmode = str(getattr(self, '_video_quality_mode', 'KALİTE') or 'KALİTE')
            if fps > 0:
                q_val = f"{qmode.title()} ({fps}fps)"
            else:
                q_val = f"{qmode.title()} (Auto)"
        except Exception:
            pass
        main_l.addWidget(_make_row('Kalite', q_val, self._open_video_quality_menu,
                       icon=icon_quality, has_submenu=True))

        main_l.addStretch(1)

        # --- SPEED PAGE ---
        current_rate = float(getattr(self, '_current_playback_rate', 1.0) or 1.0)
        speed_opts = [(0.25, '0.25x'), (0.5, '0.5x'), (0.75, '0.75x'), (1.0, 'Normal'), (1.25, '1.25x'), (1.5, '1.5x'), (1.75, '1.75x'), (2.0, '2x')]
        _make_option_list(self._video_settings_page_speed, 'Çalma hızı', speed_opts, current_rate, self._set_video_playback_rate_from_menu)

        # --- QUALITY PAGE ---
        ql = _ensure_vlayout(self._video_settings_page_quality, margins=(0, 0, 0, 0), spacing=6)
        ql.addWidget(_header('Kalite', lambda: self._video_settings_stack.setCurrentWidget(self._video_settings_page_main)))

        # Ölçek
        scale_mode = int(getattr(getattr(self, 'video_output_widget', None), 'scale_mode', 2) or 2)
        scale_box = QFrame()
        scale_l = QVBoxLayout(scale_box)
        scale_l.setContentsMargins(0, 0, 0, 0)
        scale_l.setSpacing(4)
        t1 = QLabel('Çözünürlük')
        t1.setObjectName('videoSettingsHeader')
        scale_l.addWidget(t1)
        for key, label in [(2, 'Otomatik (Fit)'), (0, 'Doldur (Fill)'), (1, 'Orijinal (1:1)')]:
            b = QToolButton()
            b.setObjectName('videoSettingsOption')
            b.setText(label)
            b.setCursor(Qt.PointingHandCursor)
            b.setCheckable(True)
            b.setAutoRaise(True)
            b.setChecked(int(key) == int(scale_mode))
            b.clicked.connect(lambda _=False, k=key: self._set_video_scale_mode_from_menu(k))
            scale_l.addWidget(b)
        ql.addWidget(scale_box)

        # FPS
        fps_box = QFrame()
        fps_l = QVBoxLayout(fps_box)
        fps_l.setContentsMargins(0, 0, 0, 0)
        fps_l.setSpacing(4)
        t2 = QLabel('FPS')
        t2.setObjectName('videoSettingsHeader')
        fps_l.addWidget(t2)
        cur_fps = int(getattr(self, '_video_target_fps', 0) or 0)
        for key, label in [(0, 'Otomatik'), (24, '24 fps'), (30, '30 fps'), (60, '60 fps')]:
            b = QToolButton()
            b.setObjectName('videoSettingsOption')
            b.setText(label)
            b.setCursor(Qt.PointingHandCursor)
            b.setCheckable(True)
            b.setAutoRaise(True)
            b.setChecked(int(key) == int(cur_fps))
            b.clicked.connect(lambda _=False, k=key: self._set_video_target_fps_from_menu(k))
            fps_l.addWidget(b)
        ql.addWidget(fps_box)

        # Mod
        mode_box = QFrame()
        mode_l = QVBoxLayout(mode_box)
        mode_l.setContentsMargins(0, 0, 0, 0)
        mode_l.setSpacing(4)
        t3 = QLabel('Mod')
        t3.setObjectName('videoSettingsHeader')
        mode_l.addWidget(t3)
        cur_mode = str(getattr(self, '_video_quality_mode', 'KALİTE') or 'KALİTE').upper()
        for key, label in [('KALİTE', 'Kalite'), ('PERFORMANS', 'Performans')]:
            b = QToolButton()
            b.setObjectName('videoSettingsOption')
            b.setText(label)
            b.setCursor(Qt.PointingHandCursor)
            b.setCheckable(True)
            b.setAutoRaise(True)
            b.setChecked(str(key).upper() == cur_mode)
            b.clicked.connect(lambda _=False, k=key: self._set_video_quality_mode_from_menu(k))
            mode_l.addWidget(b)
        ql.addWidget(mode_box)
        ql.addStretch(1)

        # --- SLEEP PAGE ---
        cur_sleep = int(st.get('sleep_minutes') or 0)
        sleep_opts = [(0, 'Kapalı'), (5, '5 dk'), (10, '10 dk'), (30, '30 dk'), (60, '60 dk')]
        _make_option_list(self._video_settings_page_sleep, 'Uyku modu', sleep_opts, cur_sleep, self._set_video_sleep_minutes)

        # --- SUBTITLES PAGE ---
        cur_sub_on = bool(st.get('subtitles_enabled'))
        cur_sub_path = str(st.get('subtitle_path') or '')
        sl = _ensure_vlayout(self._video_settings_page_subtitles, margins=(0, 0, 0, 0), spacing=4)
        sl.addWidget(_header('Altyazılar', lambda: self._video_settings_stack.setCurrentWidget(self._video_settings_page_main)))

        # Kapalı
        b_off = QToolButton()
        b_off.setObjectName('videoSettingsOption')
        b_off.setText('Kapalı')
        b_off.setCheckable(True)
        b_off.setAutoRaise(True)
        b_off.setChecked(not cur_sub_on)
        b_off.clicked.connect(lambda: self._set_video_subtitles_enabled(False))
        sl.addWidget(b_off)

        # Hızlı dil seçenekleri (Whisper ile otomatik altyazı)
        # Not: Dosya yoksa Whisper ile otomatik transkripsiyon başlar
        for _k in ('turkce', 'ingilizce', 'fransizca', 'ispanyolca', 'arapca'):
            _lbl = self._subtitle_label_from_key(_k)
            b_lang = QToolButton()
            b_lang.setObjectName('videoSettingsOption')
            b_lang.setText(_lbl)
            b_lang.setCursor(Qt.PointingHandCursor)
            b_lang.setCheckable(True)
            b_lang.setAutoRaise(True)
            b_lang.setChecked(cur_sub_on and (str(st.get('subtitle_label') or '') == str(_lbl)))
            b_lang.clicked.connect(lambda _=False, k=_k: self._video_select_subtitle_language(k))
            sl.addWidget(b_lang)

        # Dil kaynakları (video yanındaki .vtt/.srt dosyaları)
        sources = []
        try:
            sources = self._discover_video_subtitle_sources(create_templates=False)
        except Exception:
            sources = []

        for key, label, path in sources:
            b = QToolButton()
            b.setObjectName('videoSettingsOption')
            b.setText(label)
            b.setCursor(Qt.PointingHandCursor)
            b.setCheckable(True)
            b.setAutoRaise(True)
            b.setChecked(cur_sub_on and (os.path.abspath(str(path)) == os.path.abspath(cur_sub_path)))
            b.clicked.connect(lambda _=False, p=path, l=label: self._set_video_subtitle_source_from_menu(p, l))
            sl.addWidget(b)

        if not sources:
            hint = QLabel('Altyazı bulunamadı. Video ile aynı klasöre şu dosyaları koyabilirsiniz:  videoAdi.turkce.vtt / videoAdi.ingilizce.vtt / videoAdi.arapca.vtt  (veya .srt)')
            hint.setStyleSheet('color: rgba(255,255,255,160); font-size: 12px; padding: 6px 2px;')
            hint.setWordWrap(True)
            sl.addWidget(hint)

        sl.addStretch(1)

    def _toggle_video_settings_panel(self):
        try:
            if not hasattr(self, '_video_settings_panel') or self._video_settings_panel is None:
                self._create_video_settings_ui()
        except Exception:
            self._create_video_settings_ui()
        if not hasattr(self, '_video_settings_panel') or self._video_settings_panel is None:
            return
        if self._video_settings_panel.isVisible():
            self._hide_video_settings_panel(animate=True)
        else:
            self._show_video_settings_panel(animate=True)

    def _show_video_settings_panel(self, animate: bool = True):
        if not hasattr(self, '_video_settings_panel') or self._video_settings_panel is None:
            return

        # Tam ekranda: panel açıkken alt bar kaybolmasın + panel stili bar ile uyumlu olsun
        in_fs = bool(getattr(self, '_in_video_fullscreen', False))
        if in_fs:
            try:
                # Tema/QSS'den izole: sabit yarı saydam modern kart (bar ile aynı şeffaflık)
                panel_bg = "rgba(0, 0, 0, 90)"      # 90/255 ~= 0.35
                border = "rgba(255, 255, 255, 35)"
                fg = "rgba(255,255,255,235)"
                fg_dim = "rgba(255,255,255,180)"
                hover_bg = "rgba(255,255,255,18)"
                checked_bg = "rgba(255,255,255,26)"
                accent = "rgba(64,196,255,140)"
                try:
                    self._video_settings_panel.setAttribute(Qt.WA_StyledBackground, True)
                    self._video_settings_panel.setAutoFillBackground(True)
                except Exception:
                    pass
                self._video_settings_panel.setStyleSheet(f"""
                    QFrame#videoSettingsPanel {{
                        background: {panel_bg};
                        border: 1px solid {border};
                        border-radius: 14px;
                    }}
                    QFrame#videoSettingsPanel QWidget {{
                        background: transparent;
                    }}
                    QFrame#videoSettingsPanel QFrame {{
                        background: transparent;
                    }}
                    QToolButton#videoSettingsRow {{
                        background: transparent;
                        border: none;
                        color: {fg};
                        padding: 12px 14px;
                        text-align: left;
                        font-size: 16px;
                        font-weight: 600;
                    }}
                    QToolButton#videoSettingsRow:hover {{
                        background: {hover_bg};
                        border-radius: 10px;
                    }}
                    QToolButton#videoSettingsRow:checked {{
                        background: {checked_bg};
                        border: 1px solid {accent};
                        border-radius: 10px;
                    }}
                    QLabel#videoSettingsValue {{
                        color: {fg_dim};
                        font-size: 14px;
                    }}
                    QLabel#videoSettingsChevron {{
                        color: {fg_dim};
                        font-size: 18px;
                        padding-left: 6px;
                    }}
                    QLabel#videoSettingsHeader {{
                        color: {fg};
                        font-size: 16px;
                        font-weight: bold;
                    }}
                    QToolButton#videoSettingsBack {{
                        background: transparent;
                        border: none;
                        color: {fg};
                        padding: 10px 12px;
                        font-size: 16px;
                    }}
                    QToolButton#videoSettingsOption {{
                        background: transparent;
                        border: none;
                        color: {fg};
                        padding: 12px 14px;
                        text-align: left;
                        font-size: 16px;
                        font-weight: 600;
                    }}
                    QToolButton#videoSettingsOption:hover {{
                        background: {hover_bg};
                        border-radius: 10px;
                    }}
                    QToolButton#videoSettingsOption:checked {{
                        background: {checked_bg};
                        border: 1px solid {accent};
                        border-radius: 10px;
                    }}
                """)
            except Exception:
                pass

            # Barı görünür tut + auto-hide timer'ını durdur
            try:
                if not getattr(self, '_fs_bars_visible', True):
                    self._animate_fs_bars_show()
            except Exception:
                pass
            try:
                self._stop_fs_bar_hide_timer()
            except Exception:
                pass
            try:
                self._fs_bars_visible = True
            except Exception:
                pass

        try:
            self._build_video_settings_pages()
        except Exception:
            pass
        self._video_settings_stack.setCurrentWidget(self._video_settings_page_main)
        self._video_settings_panel.show()
        self._video_settings_panel.raise_()
        try:
            self.video_settings_button.raise_()
        except Exception:
            pass
        try:
            self._reposition_video_settings_ui()
        except Exception:
            pass

        if not animate:
            return

        try:
            from PyQt5.QtWidgets import QGraphicsOpacityEffect
            from PyQt5.QtCore import QPropertyAnimation, QEasingCurve
            eff = self._video_settings_panel.graphicsEffect()
            if not isinstance(eff, QGraphicsOpacityEffect):
                eff = QGraphicsOpacityEffect(self._video_settings_panel)
                self._video_settings_panel.setGraphicsEffect(eff)
            eff.setOpacity(0.0)
            anim = QPropertyAnimation(eff, b"opacity", self)
            anim.setDuration(180)
            anim.setStartValue(0.0)
            anim.setEndValue(1.0)
            anim.setEasingCurve(QEasingCurve.InOutQuad)
            self._video_settings_fade_anim = anim
            anim.start()
        except Exception:
            pass

    def _hide_video_settings_panel(self, animate: bool = True):
        if not hasattr(self, '_video_settings_panel') or self._video_settings_panel is None:
            return
        if not self._video_settings_panel.isVisible():
            return

        in_fs = bool(getattr(self, '_in_video_fullscreen', False))
        if not animate:
            self._video_settings_panel.hide()
            if in_fs:
                try:
                    self._start_fs_bar_hide_timer()
                except Exception:
                    pass
            return

        try:
            from PyQt5.QtWidgets import QGraphicsOpacityEffect
            from PyQt5.QtCore import QPropertyAnimation, QEasingCurve
            eff = self._video_settings_panel.graphicsEffect()
            if not isinstance(eff, QGraphicsOpacityEffect):
                eff = QGraphicsOpacityEffect(self._video_settings_panel)
                self._video_settings_panel.setGraphicsEffect(eff)
            start = float(getattr(eff, 'opacity', lambda: 1.0)())
            anim = QPropertyAnimation(eff, b"opacity", self)
            anim.setDuration(160)
            anim.setStartValue(start)
            anim.setEndValue(0.0)
            anim.setEasingCurve(QEasingCurve.InOutQuad)
            def _after_hide():
                try:
                    self._video_settings_panel.hide()
                except Exception:
                    pass
                if in_fs:
                    try:
                        self._start_fs_bar_hide_timer()
                    except Exception:
                        pass
            anim.finished.connect(_after_hide)
            self._video_settings_fade_anim = anim
            anim.start()
        except Exception:
            self._video_settings_panel.hide()
            if in_fs:
                try:
                    self._start_fs_bar_hide_timer()
                except Exception:
                    pass

    def _reposition_video_settings_ui(self):
        """Dişli ve paneli video üzerinde sağ alt köşeye hizala."""
        if not hasattr(self, 'video_overlay_host') or self.video_overlay_host is None:
            return
        host = self.video_overlay_host
        margin = 16

        in_fs = bool(getattr(self, '_in_video_fullscreen', False))

        # Alt tarafta bar örtüşmesi (gerçek global geometriye göre hesapla)
        bottom_inset = 0
        try:
            host_tl = host.mapToGlobal(QPoint(0, 0))
            host_br = host.mapToGlobal(QPoint(host.width(), host.height()))
            host_bottom_y = int(host_br.y())

            def _calc_occlusion(w: QWidget) -> int:
                try:
                    if not w or not w.isVisible():
                        return 0
                    tl = w.mapToGlobal(QPoint(0, 0))
                    # Barın üst sınırı
                    bar_top_y = int(tl.y())
                    return max(0, host_bottom_y - bar_top_y)
                except Exception:
                    return 0

            # Öncelik: Video fullscreen barı
            if getattr(self, '_in_video_fullscreen', False) and hasattr(self, '_video_fs_controls'):
                bottom_inset = max(bottom_inset, _calc_occlusion(getattr(self, '_video_fs_controls', None)))

            # Normal mod: global bottom_widget örtüşüyorsa onu da dikkate al
            try:
                if hasattr(self, 'bottom_widget') and self.bottom_widget and self.bottom_widget.isVisible():
                    bottom_inset = max(bottom_inset, _calc_occlusion(self.bottom_widget))
            except Exception:
                pass
        except Exception:
            bottom_inset = 0

        try:
            if hasattr(self, '_video_cinematic_overlay') and self._video_cinematic_overlay:
                self._video_cinematic_overlay.setGeometry(0, 0, host.width(), host.height())
        except Exception:
            pass

        try:
            if hasattr(self, '_video_info_overlay') and self._video_info_overlay:
                self._video_info_overlay.adjustSize()
                self._video_info_overlay.move(margin, margin)
                self._video_info_overlay.raise_()
        except Exception:
            pass

        try:
            if hasattr(self, '_video_subtitle_label') and self._video_subtitle_label:
                self._video_subtitle_label.setFixedWidth(max(200, int(host.width() * 0.72)))
                self._video_subtitle_label.adjustSize()
                x = int((host.width() - self._video_subtitle_label.width()) / 2)
                y = int(host.height() - bottom_inset - self._video_subtitle_label.height() - margin - 10)
                self._video_subtitle_label.move(max(0, x), max(0, y))
                self._video_subtitle_label.raise_()
        except Exception:
            pass

        # Tam ekranda: overlay ikonlarını kapat (bar içindeki kontroller kullanılacak)
        try:
            if in_fs:
                if hasattr(self, 'video_settings_button') and self.video_settings_button:
                    self.video_settings_button.setVisible(False)
                if hasattr(self, 'video_fs_button') and self.video_fs_button:
                    self.video_fs_button.setVisible(False)
            else:
                # Settings button: mümkünse fullscreen butonunun SOLUNA hizala
                if hasattr(self, 'video_settings_button') and self.video_settings_button:
                    self.video_settings_button.setVisible(True)
                    bx = host.width() - self.video_settings_button.width() - margin
                    by = host.height() - bottom_inset - self.video_settings_button.height() - margin
                    try:
                        if hasattr(self, 'video_fs_button') and self.video_fs_button and self.video_fs_button.isVisible():
                            fs_geo = self.video_fs_button.geometry()
                            gap = 10
                            bx = max(margin, fs_geo.x() - gap - self.video_settings_button.width())
                            by = max(margin, fs_geo.y())
                    except Exception:
                        pass
                    self.video_settings_button.move(max(0, bx), max(0, by))
                    self.video_settings_button.raise_()
        except Exception:
            pass

        try:
            if hasattr(self, '_video_settings_panel') and self._video_settings_panel:
                self._video_settings_panel.adjustSize()
                px = host.width() - self._video_settings_panel.width() - margin
                py = host.height() - bottom_inset - self._video_settings_panel.height() - margin - 44
                try:
                    # Tam ekranda paneli bar içindeki Ayarlar butonuna göre hizala
                    if in_fs and hasattr(self, '_fs_settings_btn') and self._fs_settings_btn and self._fs_settings_btn.isVisible():
                        gp = self._fs_settings_btn.mapToGlobal(QPoint(0, 0))
                        lp = host.mapFromGlobal(gp)
                        ax = int(lp.x())
                        ay = int(lp.y())
                        aw = int(self._fs_settings_btn.width())
                        px = max(margin, ax + aw - self._video_settings_panel.width())
                        # Panelin altı, barın üst çizgisinin TAM üstünde olsun
                        try:
                            if hasattr(self, '_video_fs_controls') and self._video_fs_controls and self._video_fs_controls.isVisible():
                                bar_gp = self._video_fs_controls.mapToGlobal(QPoint(0, 0))
                                bar_top_local = host.mapFromGlobal(bar_gp).y()
                                py = int(bar_top_local) - self._video_settings_panel.height()
                            else:
                                py = ay - 8 - self._video_settings_panel.height()
                        except Exception:
                            py = ay - 8 - self._video_settings_panel.height()
                        py = max(margin, int(py))
                    elif hasattr(self, 'video_settings_button') and self.video_settings_button:
                        px = max(margin, self.video_settings_button.x() + self.video_settings_button.width() - self._video_settings_panel.width())
                        py = max(margin, self.video_settings_button.y() - 8 - self._video_settings_panel.height())
                except Exception:
                    pass
                self._video_settings_panel.move(max(0, px), max(0, py))
                self._video_settings_panel.raise_()
        except Exception:
            pass

    def _open_video_speed_menu(self):
        try:
            self._build_video_settings_pages()
        except Exception:
            pass
        self._video_settings_stack.setCurrentWidget(self._video_settings_page_speed)

    def _open_video_quality_menu(self):
        try:
            self._build_video_settings_pages()
        except Exception:
            pass
        self._video_settings_stack.setCurrentWidget(self._video_settings_page_quality)

    def _open_video_sleep_menu(self):
        try:
            self._build_video_settings_pages()
        except Exception:
            pass
        self._video_settings_stack.setCurrentWidget(self._video_settings_page_sleep)

    def _open_video_subtitles_menu(self):
        try:
            self._build_video_settings_pages()
        except Exception:
            pass
        self._video_settings_stack.setCurrentWidget(self._video_settings_page_subtitles)

    def _set_video_playback_rate_from_menu(self, rate):
        try:
            rate = float(rate)
        except Exception:
            rate = 1.0
        try:
            self._set_playback_rate(rate)
        except Exception:
            try:
                if hasattr(self, 'videoPlayer'):
                    self.videoPlayer.setPlaybackRate(rate)
            except Exception:
                pass
        try:
            self._build_video_settings_pages()
        except Exception:
            pass
        self._video_settings_stack.setCurrentWidget(self._video_settings_page_main)

    def _set_video_scale_mode_from_menu(self, mode: int):
        try:
            if hasattr(self, 'video_output_widget') and self.video_output_widget:
                self.video_output_widget.set_scale_mode(int(mode))
        except Exception:
            pass
        try:
            self._build_video_settings_pages()
        except Exception:
            pass

    def _set_video_target_fps_from_menu(self, fps: int):
        try:
            self._set_video_target_fps(int(fps))
        except Exception:
            pass
        try:
            self._build_video_settings_pages()
        except Exception:
            pass

    def _set_video_quality_mode_from_menu(self, mode: str):
        try:
            self._set_video_quality_mode(str(mode))
        except Exception:
            pass
        try:
            self._build_video_settings_pages()
        except Exception:
            pass

    def _set_video_sleep_minutes(self, minutes: int):
        try:
            minutes = int(minutes)
        except Exception:
            minutes = 0
        st = getattr(self, '_video_settings_state', {})
        st['sleep_minutes'] = max(0, minutes)
        self._video_settings_state = st
        try:
            if minutes <= 0:
                if hasattr(self, '_video_sleep_timer') and self._video_sleep_timer.isActive():
                    self._video_sleep_timer.stop()
            else:
                if hasattr(self, '_video_sleep_timer'):
                    self._video_sleep_timer.start(int(minutes) * 60 * 1000)
        except Exception:
            pass
        try:
            self._build_video_settings_pages()
        except Exception:
            pass
        self._video_settings_stack.setCurrentWidget(self._video_settings_page_main)

    def _on_video_sleep_timeout(self):
        try:
            if hasattr(self, 'videoPlayer'):
                self.videoPlayer.pause()
        except Exception:
            pass
        try:
            self.statusBar().showMessage('⏰ Uyku modu: Video duraklatıldı', 2500)
        except Exception:
            pass

    def _toggle_video_cinematic(self):
        st = getattr(self, '_video_settings_state', {})
        st['cinematic'] = not bool(st.get('cinematic'))
        self._video_settings_state = st
        try:
            if hasattr(self, '_video_cinematic_overlay') and self._video_cinematic_overlay:
                self._video_cinematic_overlay.setVisible(bool(st['cinematic']))
                self._video_cinematic_overlay.raise_()
        except Exception:
            pass
        try:
            self._build_video_settings_pages()
        except Exception:
            pass

    def _toggle_video_annotations(self):
        st = getattr(self, '_video_settings_state', {})
        st['annotations'] = not bool(st.get('annotations'))
        self._video_settings_state = st
        try:
            if hasattr(self, '_video_info_overlay') and self._video_info_overlay:
                if st['annotations']:
                    self._update_video_info_overlay()
                    self._video_info_overlay.show()
                    self._video_info_overlay.raise_()
                else:
                    self._video_info_overlay.hide()
        except Exception:
            pass
        try:
            self._build_video_settings_pages()
        except Exception:
            pass

    def _update_video_info_overlay(self):
        try:
            if not hasattr(self, '_video_info_label') or self._video_info_label is None:
                return
            src = str(getattr(self, '_video_last_source_text', '') or '')
            if not src:
                p = str(getattr(self, '_video_current_path', '') or '')
                src = os.path.basename(p) if p else 'Video'
            rate = float(getattr(self, '_current_playback_rate', 1.0) or 1.0)
            fps = int(getattr(self, '_video_target_fps', 0) or 0)
            qm = str(getattr(self, '_video_quality_mode', 'KALİTE') or 'KALİTE').title()
            extra = []
            if abs(rate - 1.0) > 1e-6:
                extra.append(f"Hız: {rate:.2g}x")
            extra.append(f"Mod: {qm}")
            if fps > 0:
                extra.append(f"FPS: {fps}")
            self._video_info_label.setText(src + "\n" + " • ".join(extra))
            self._video_info_overlay.adjustSize()
        except Exception:
            pass
        try:
            self._reposition_video_settings_ui()
        except Exception:
            pass

    def _toggle_video_volume_boost(self):
        st = getattr(self, '_video_settings_state', {})
        st['volume_boost'] = not bool(st.get('volume_boost'))
        self._video_settings_state = st
        try:
            self._apply_video_volume_boost_state()
        except Exception:
            pass
        try:
            self._build_video_settings_pages()
        except Exception:
            pass

    def _toggle_video_stable_volume(self):
        st = getattr(self, '_video_settings_state', {})
        st['stable_volume'] = not bool(st.get('stable_volume'))
        self._video_settings_state = st
        try:
            if hasattr(self, 'videoPlayer'):
                self._video_set_volume(int(self.videoPlayer.volume() or 0))
        except Exception:
            pass
        try:
            self._build_video_settings_pages()
        except Exception:
            pass

    def _apply_video_volume_boost_state(self):
        if not hasattr(self, 'videoPlayer'):
            return
        st = getattr(self, '_video_settings_state', {})
        try:
            current = int(self.videoPlayer.volume() or 0)
        except Exception:
            current = 0
        if st.get('base_volume') is None:
            st['base_volume'] = current
        try:
            if st.get('volume_boost'):
                base = int(st.get('base_volume') or current)
                boosted = min(100, int(round(base * 1.35)))
                self.videoPlayer.setVolume(boosted)
            else:
                base = int(st.get('base_volume') or current)
                self.videoPlayer.setVolume(int(base))
        except Exception:
            pass
        self._video_settings_state = st

    def _set_video_subtitles_enabled(self, enabled: bool):
        st = getattr(self, '_video_settings_state', {})
        st['subtitles_enabled'] = bool(enabled)
        self._video_settings_state = st
        try:
            if not enabled:
                if hasattr(self, '_video_subtitle_label') and self._video_subtitle_label:
                    self._video_subtitle_label.hide()
            else:
                self._ensure_video_subtitles_loaded()
                try:
                    pos = int(self.videoPlayer.position() or 0)
                except Exception:
                    pos = 0
                self._update_video_subtitle_overlay(pos)
        except Exception:
            pass
        try:
            self._build_video_settings_pages()
        except Exception:
            pass
        self._video_settings_stack.setCurrentWidget(self._video_settings_page_main)

    def _set_video_subtitle_source_from_menu(self, subtitle_path: str, label: str):
        """Menüden dil seçilince altyazıyı anında değiştir."""
        st = getattr(self, '_video_settings_state', {})
        try:
            subtitle_path = str(subtitle_path or '')
        except Exception:
            subtitle_path = ''
        try:
            label = str(label or '').strip() or 'Altyazı'
        except Exception:
            label = 'Altyazı'

        st['subtitles_enabled'] = True
        st['subtitle_path'] = subtitle_path
        st['subtitle_label'] = label
        st['subtitle_items'] = []
        st['subtitle_index'] = 0
        st['subtitle_loaded_path'] = None
        self._video_settings_state = st

        try:
            self._ensure_video_subtitles_loaded()
        except Exception:
            pass
        try:
            pos = int(self.videoPlayer.position() or 0)
        except Exception:
            pos = 0
        try:
            self._update_video_subtitle_overlay(pos)
        except Exception:
            pass

        try:
            self._build_video_settings_pages()
        except Exception:
            pass
        try:
            self._video_settings_stack.setCurrentWidget(self._video_settings_page_main)
        except Exception:
            pass

    def _discover_video_subtitle_sources(self, create_templates: bool = False):
        """Mevcut video için altyazı kaynaklarını keşfet (vtt/srt)."""
        video_path = str(getattr(self, '_video_current_path', '') or '')
        if not video_path:
            return []
        base, _ = os.path.splitext(video_path)
        folder = os.path.dirname(video_path)
        base_name = os.path.basename(base)

        if create_templates:
            try:
                self._maybe_create_default_video_subtitle_templates(base)
            except Exception:
                pass

        # adaylar: <base>.<lang>.(vtt|srt) ve klasik <base>.srt/<base>.vtt
        # ayrıca klasörde turkce.vtt / ingilizce.vtt / arapca.vtt gibi ortak adları da destekle
        candidates = []

        for ext in ('.vtt', '.srt'):
            candidates.append((None, f'{base}{ext}'))
            for lang in ('turkce', 'ingilizce', 'arapca', 'tr', 'en', 'ar'):
                candidates.append((lang, f'{base}.{lang}{ext}'))
                candidates.append((lang, os.path.join(folder, f'{lang}{ext}')))

        # klasördeki diğer .vtt/.srt dosyalarını da ekle (base_name.<something>.ext)
        try:
            for fn in os.listdir(folder):
                low = fn.lower()
                if not (low.endswith('.vtt') or low.endswith('.srt')):
                    continue
                full = os.path.join(folder, fn)
                if not os.path.isfile(full):
                    continue
                if os.path.abspath(full) in {os.path.abspath(p) for _, p in candidates}:
                    continue
                if low.startswith(base_name.lower() + '.'):
                    candidates.append((None, full))
        except Exception:
            pass

        def _label_from_path(p: str):
            fn = os.path.basename(p)
            name_no_ext = os.path.splitext(fn)[0]
            key = None
            if name_no_ext.lower().startswith(base_name.lower() + '.'):
                key = name_no_ext[len(base_name) + 1:]
            return self._subtitle_label_from_key(key), key

        out = []
        seen = set()
        for lang_key, p in candidates:
            try:
                if not p or not os.path.exists(p):
                    continue
                ap = os.path.abspath(p)
                if ap in seen:
                    continue
                seen.add(ap)
                label = None
                if lang_key:
                    label = self._subtitle_label_from_key(lang_key)
                else:
                    label, _ = _label_from_path(p)
                label = str(label or '').strip() or 'Altyazı'
                out.append((lang_key, label, p))
            except Exception:
                continue

        # sabit sıraya oturt
        order = {'turkce': 0, 'tr': 0, 'ingilizce': 1, 'en': 1, 'arapca': 2, 'ar': 2}
        def _sort_key(t):
            k, label, p = t
            if k in order:
                return (order[k], label)
            return (99, label)
        out.sort(key=_sort_key)
        return out

    def _video_apply_builtin_subtitle_template(self, lang_key: str):
        """Klasör yazılamazsa bile Türkçe/İngilizce/Arapça şablon altyazıyı anında uygula.

        Bu yalnızca video overlay'de çalışır ve dosya yazmayı gerektirmez.
        """
        try:
            lang_key = str(lang_key or '').strip().lower()
        except Exception:
            lang_key = ''
        if lang_key not in ('turkce', 'ingilizce', 'arapca'):
            return

        st = getattr(self, '_video_settings_state', {})
        if not isinstance(st, dict):
            st = {}

        label = self._subtitle_label_from_key(lang_key)
        if lang_key == 'turkce':
            text = 'Merhaba. Bu bir Türkçe altyazı şablonudur.\nAltyazı eklemek için video ile aynı klasöre .srt/.vtt koyun.'
        elif lang_key == 'ingilizce':
            text = 'Hello. This is an English subtitle template.\nPut a .srt/.vtt next to the video to use real subtitles.'
        else:
            text = 'مرحباً. هذا قالب ترجمة عربي.\nضع ملف .srt/.vtt بجانب الفيديو لاستخدام ترجمة حقيقية.'

        st['subtitles_enabled'] = True
        st['subtitle_label'] = label
        # 10 dakika boyunca tek bir cue (test/rehber amaçlı)
        st['subtitle_items'] = [(0, 10 * 60 * 1000, text)]
        st['subtitle_index'] = 0
        st['subtitle_path'] = None
        st['subtitle_loaded_path'] = f"__angolla_template__:{lang_key}"
        self._video_settings_state = st

        try:
            pos = int(self.videoPlayer.position() or 0)
        except Exception:
            pos = 0
        try:
            self._update_video_subtitle_overlay(pos)
        except Exception:
            pass

    def _video_select_subtitle_language(self, lang_key: str):
        """Menüden dil seçilince:
        - varsa gerçek dosyayı seç
        - yoksa Whisper ile otomatik oluştur (tüm diller için)
        """
        try:
            lang_key = str(lang_key or '').strip().lower()
        except Exception:
            lang_key = ''
        
        # Desteklenen diller ve Whisper kodları
        lang_to_whisper = {
            'turkce': 'tr',
            'ingilizce': 'en', 
            'fransizca': 'fr',
            'ispanyolca': 'es',
            'arapca': 'ar'
        }
        
        if lang_key not in lang_to_whisper:
            return

        video_path = str(getattr(self, '_video_current_path', '') or '')
        if not video_path:
            return
        base_no_ext, _ = os.path.splitext(video_path)

        # Önce mevcut kaynaklar arasında o dili ara
        try:
            sources = self._discover_video_subtitle_sources(create_templates=False)
        except Exception:
            sources = []
        picked = None
        for k, lbl, p in (sources or []):
            try:
                if str(k or '').strip().lower() in (lang_key, lang_to_whisper.get(lang_key, '')):
                    picked = (lbl, p)
                    break
            except Exception:
                continue

        if picked is not None:
            lbl, p = picked
            # Eğer template dosyasıysa (.angolla_sub_) Whisper çalıştır
            if '.angolla_sub_' in os.path.basename(p):
                try:
                    import whisper
                    # Whisper varsa otomatik transkripsiyon başlat
                    whisper_lang = lang_to_whisper.get(lang_key, 'tr')
                    self._start_whisper_transcription(whisper_lang)
                    return
                except ImportError:
                    pass  # Whisper yoksa normal template kullan
            self._set_video_subtitle_source_from_menu(p, lbl)
            return

        # Dosya bulunamadı - Whisper ile otomatik altyazı oluştur (tüm diller için)
        try:
            import whisper
            # Whisper varsa direkt transkripsiyon başlat
            whisper_lang = lang_to_whisper.get(lang_key, 'tr')
            self._start_whisper_transcription(whisper_lang)
            return
        except ImportError:
            pass  # Whisper yoksa template'e devam
        
        # Whisper yoksa gizli temp şablon dosyası oluşturmayı dene
        try:
            self._maybe_create_default_video_subtitle_templates(base_no_ext)
        except Exception:
            pass

        # Oluştuysa o dosyayı seç
        try:
            temp_paths = self._video_get_temp_subtitle_template_paths(base_no_ext)
        except Exception:
            temp_paths = []
        target_path = None
        for k, p in (temp_paths or []):
            if str(k or '').strip().lower() == lang_key:
                target_path = p
                break

        if target_path and os.path.exists(target_path):
            self._set_video_subtitle_source_from_menu(target_path, self._subtitle_label_from_key(lang_key))
            return

        # Son çare: dosyasız (in-memory) şablon
        self._video_apply_builtin_subtitle_template(lang_key)

    def _video_get_temp_subtitle_template_paths(self, base_no_ext: str):
        """Bu video için gizli temp altyazı şablon yollarını üret.

        Format: <klasör>/.angolla_sub_<videoAdı>.<dil>.vtt
        """
        try:
            base_no_ext = str(base_no_ext or '')
        except Exception:
            return []
        if not base_no_ext:
            return []
        folder = os.path.dirname(base_no_ext)
        base_name = os.path.basename(base_no_ext)
        if not folder or not base_name:
            return []
        out = []
        for key in ('turkce', 'ingilizce', 'fransizca', 'ispanyolca', 'arapca'):
            fn = f".angolla_sub_{base_name}.{key}.vtt"
            out.append((key, os.path.join(folder, fn)))
        return out

    def _video_register_temp_file(self, path: str):
        """Oluşturulan temp dosyayı video state'ine kaydet."""
        try:
            p = str(path or '')
        except Exception:
            return
        if not p:
            return
        st = getattr(self, '_video_settings_state', {})
        if not isinstance(st, dict):
            st = {}
        lst = st.get('temp_subtitle_files')
        if not isinstance(lst, list):
            lst = []
        ap = None
        try:
            ap = os.path.abspath(p)
        except Exception:
            ap = p
        if ap and ap not in lst:
            lst.append(ap)
        st['temp_subtitle_files'] = lst
        self._video_settings_state = st

    def _cleanup_video_temp_files(self):
        """Video modülünün oluşturduğu temp altyazı dosyalarını sil."""
        st = getattr(self, '_video_settings_state', {})
        if not isinstance(st, dict):
            return
        lst = st.get('temp_subtitle_files')
        if not isinstance(lst, list) or not lst:
            return

        keep = []
        for p in lst:
            try:
                if not p:
                    continue
                ap = os.path.abspath(str(p))
                fn = os.path.basename(ap)
                # Güvenlik: sadece bizim isim şablonumuza uyanları sil
                if not (fn.startswith('.angolla_sub_') and fn.lower().endswith('.vtt')):
                    keep.append(ap)
                    continue
                if os.path.exists(ap) and os.path.isfile(ap):
                    try:
                        os.remove(ap)
                    except Exception:
                        keep.append(ap)
            except Exception:
                continue

        st['temp_subtitle_files'] = keep
        self._video_settings_state = st

    @staticmethod
    def _subtitle_label_from_key(key: str) -> str:
        try:
            k = (key or '').strip().lower()
        except Exception:
            k = ''
        if k in ('turkce', 'tr', 'turkish'):
            return 'Türkçe'
        if k in ('ingilizce', 'en', 'english'):
            return 'İngilizce'
        if k in ('fransizca', 'fr', 'french'):
            return 'Fransızca'
        if k in ('ispanyolca', 'es', 'spanish'):
            return 'İspanyolca'
        if k in ('arapca', 'ar', 'arabic'):
            return 'Arapça'
        if not k:
            return 'Altyazı'
        return k.replace('_', ' ').replace('-', ' ').title()

    def _start_whisper_transcription(self, language_code='tr'):
        """Whisper ile video sesinden otomatik altyazı oluştur
        
        Args:
            language_code: Whisper dil kodu (tr, en, fr, es, ar vb.)
        """
        try:
            from PyQt5.QtCore import QThread, pyqtSignal
            import whisper
            import tempfile
            import subprocess
        except ImportError as e:
            QMessageBox.warning(self, 'Hata', f'Gerekli modül eksik: {e}\n\npip install openai-whisper')
            return

        # Video yolu kontrolü
        current_video = getattr(self, '_video_current_path', None)
        if not current_video or not os.path.exists(current_video):
            return
        
        # Dil adını kullanıcı için güzelleştir
        language_names = {'tr': 'Türkçe', 'en': 'İngilizce', 'fr': 'Fransızca', 'es': 'İspanyolca', 'ar': 'Arapça'}
        lang_display = language_names.get(language_code, language_code.upper())

        # Video'yu otomatik duraklat
        try:
            if hasattr(self, 'videoPlayer'):
                self.videoPlayer.pause()
        except:
            pass

        # Progress dialog (minimal, iptal yok)
        progress = QProgressDialog(f'{lang_display} altyazı oluşturuluyor...', None, 0, 0, self)
        progress.setWindowTitle('🎙️ Otomatik Altyazı')
        progress.setWindowModality(Qt.WindowModal)
        progress.setCancelButton(None)  # İptal butonu yok
        progress.setMinimumDuration(0)
        progress.setValue(0)
        progress.show()
        QApplication.processEvents()

        # Worker thread
        class WhisperWorker(QThread):
            finished_signal = pyqtSignal(str, str)  # subtitle_path, error_msg
            
            def __init__(self, video_path, language_code='tr'):
                super().__init__()
                self.video_path = video_path
                self.language_code = language_code
                
            def run(self):
                wav_path = None
                try:
                    # 1. Video'dan ses çıkar (WAV)
                    with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as tmp_wav:
                        wav_path = tmp_wav.name
                    
                    try:
                        result_ffmpeg = subprocess.run([
                            'ffmpeg', '-i', self.video_path,
                            '-vn', '-acodec', 'pcm_s16le',
                            '-ar', '16000', '-ac', '1',
                            '-y', wav_path
                        ], check=True, capture_output=True, text=True)
                    except subprocess.CalledProcessError as e:
                        if wav_path and os.path.exists(wav_path):
                            os.unlink(wav_path)
                        self.finished_signal.emit('', f'Ses çıkarma hatası: Video dosyasında ses bulunamadı veya codec hatası.\n\nFFmpeg: {e.stderr[:200]}')
                        return
                    except Exception as e:
                        if wav_path and os.path.exists(wav_path):
                            os.unlink(wav_path)
                        self.finished_signal.emit('', f'Ses çıkarma hatası: {e}')
                        return
                    
                    # Ses dosyası boyut kontrolü (çok küçükse sessiz video)
                    if wav_path and os.path.exists(wav_path):
                        if os.path.getsize(wav_path) < 1024:  # 1KB'den küçük
                            os.unlink(wav_path)
                            self.finished_signal.emit('', 'Video sessiz veya çok kısa. Transkripsiyon yapılamıyor.')
                            return
                    
                    # 2. Whisper ile transkripsiyon (CPU fallback ile)
                    try:
                        # İlk CUDA ile dene, başarısız olursa CPU
                        import torch
                        device = 'cuda' if torch.cuda.is_available() else 'cpu'
                        
                        model = whisper.load_model('small', device=device)
                        result = model.transcribe(
                            wav_path, 
                            language=self.language_code, 
                            task='transcribe',
                            fp16=False  # NaN hatalarını önlemek için FP16 kapalı
                        )
                    except RuntimeError as e:
                        # CUDA hatası - CPU ile tekrar dene
                        if 'cuda' in str(e).lower() or 'nan' in str(e).lower():
                            try:
                                model = whisper.load_model('small', device='cpu')
                                result = model.transcribe(wav_path, language=self.language_code, task='transcribe', fp16=False)
                            except Exception as e2:
                                if wav_path and os.path.exists(wav_path):
                                    os.unlink(wav_path)
                                self.finished_signal.emit('', f'Whisper CPU hatası: {e2}')
                                return
                        else:
                            if wav_path and os.path.exists(wav_path):
                                os.unlink(wav_path)
                            self.finished_signal.emit('', f'Whisper hatası: {e}')
                            return
                    except Exception as e:
                        if wav_path and os.path.exists(wav_path):
                            os.unlink(wav_path)
                        self.finished_signal.emit('', f'Whisper hatası: {e}')
                        return
                    
                    # 3. VTT dosyası oluştur
                    video_dir = os.path.dirname(self.video_path)
                    video_base = os.path.splitext(os.path.basename(self.video_path))[0]
                    subtitle_path = os.path.join(video_dir, f'{video_base}.whisper.vtt')
                    
                    # Sonuç boş mu kontrol et
                    if not result.get('segments'):
                        if wav_path and os.path.exists(wav_path):
                            os.unlink(wav_path)
                        self.finished_signal.emit('', 'Whisper hiçbir metin bulamadı. Video sessiz veya anlaşılmaz olabilir.')
                        return
                    
                    try:
                        with open(subtitle_path, 'w', encoding='utf-8') as f:
                            f.write('WEBVTT\n\n')
                            for segment in result['segments']:
                                start_time = self._format_vtt_time(segment['start'])
                                end_time = self._format_vtt_time(segment['end'])
                                text = segment['text'].strip()
                                if text:  # Boş metinleri atla
                                    f.write(f'{start_time} --> {end_time}\n{text}\n\n')
                    except Exception as e:
                        if wav_path and os.path.exists(wav_path):
                            os.unlink(wav_path)
                        self.finished_signal.emit('', f'VTT yazma hatası: {e}')
                        return
                    
                    # Temizlik
                    if wav_path and os.path.exists(wav_path):
                        try:
                            os.unlink(wav_path)
                        except:
                            pass
                    
                    self.finished_signal.emit(subtitle_path, '')
                    
                except Exception as e:
                    # Temizlik
                    if wav_path and os.path.exists(wav_path):
                        try:
                            os.unlink(wav_path)
                        except:
                            pass
                    self.finished_signal.emit('', f'Beklenmeyen hata: {e}')
            
            @staticmethod
            def _format_vtt_time(seconds):
                """Saniyeyi VTT formatına çevir (00:00:00.000)"""
                hours = int(seconds // 3600)
                minutes = int((seconds % 3600) // 60)
                secs = seconds % 60
                return f'{hours:02d}:{minutes:02d}:{secs:06.3f}'

        def on_whisper_finished(subtitle_path, error_msg):
            progress.close()
            
            if error_msg:
                # Hata sadece konsola yazdır, kullanıcıyı rahatsız etme
                print(f'[Whisper] Hata: {error_msg}')
            elif subtitle_path and os.path.exists(subtitle_path):
                # Sessizce altyazıyı yükle
                try:
                    # Dil label'ı oluştur
                    lang_label = language_names.get(language_code, 'Whisper')
                    self._set_video_subtitle_source_from_menu(subtitle_path, f'Whisper ({lang_label})')
                except Exception as e:
                    print(f'[Whisper] Altyazı yükleme hatası: {e}')
                # Ayarlar sayfasını sessizce yenile
                try:
                    self._build_video_settings_pages()
                except:
                    pass
            else:
                print('[Whisper] Altyazı dosyası oluşturulamadı')

        worker = WhisperWorker(current_video, language_code)
        worker.finished_signal.connect(on_whisper_finished)
        worker.start()
        
        # Worker'ı sakla (garbage collection'dan kurtarmak için)
        self._whisper_worker = worker


    def _maybe_create_default_video_subtitle_templates(self, base_no_ext: str):
        """Varsayılan dil şablonlarını oluştur (video klasöründe gizli temp dosya).

        Not:
        - Dosyalar yalnızca video modülü içinde kullanılır.
        - Video bittiğinde veya video sekmesinden çıkıldığında otomatik temizlenir.
        """
        try:
            base_no_ext = str(base_no_ext or '')
        except Exception:
            return
        if not base_no_ext:
            return

        folder = os.path.dirname(base_no_ext)
        if not folder or not os.path.isdir(folder):
            return

        # Yazılabilir değilse dokunma
        try:
            if not os.access(folder, os.W_OK):
                return
        except Exception:
            pass

        templates = {
            'turkce': (
                'WEBVTT\n\n'
                '00:00:00.000 --> 00:10:00.000\n'
                'Merhaba. Bu bir Türkçe altyazı şablonudur.\n'
                'Altyazı eklemek için bu dosyayı düzenleyin veya aynı klasöre .srt/.vtt koyun.\n\n'
            ),
            'ingilizce': (
                'WEBVTT\n\n'
                '00:00:00.000 --> 00:10:00.000\n'
                'Hello. This is an English subtitle template.\n'
                'Edit this file or put a .srt/.vtt next to the video.\n\n'
            ),
            'fransizca': (
                'WEBVTT\n\n'
                '00:00:00.000 --> 00:10:00.000\n'
                'Bonjour. Ceci est un modèle de sous-titre français.\n'
                'Modifiez ce fichier ou placez un .srt/.vtt à côté de la vidéo.\n\n'
            ),
            'ispanyolca': (
                'WEBVTT\n\n'
                '00:00:00.000 --> 00:10:00.000\n'
                'Hola. Esta es una plantilla de subtítulos en español.\n'
                'Edite este archivo o coloque un .srt/.vtt junto al video.\n\n'
            ),
            'arapca': (
                'WEBVTT\n\n'
                '00:00:00.000 --> 00:10:00.000\n'
                'مرحباً. هذا قالب ترجمة عربي.\n'
                'حرّر هذا الملف أو ضع ملف .srt/.vtt بجانب الفيديو.\n\n'
            ),
        }

        base_name = os.path.basename(base_no_ext)
        for key, content in templates.items():
            # Gizli temp: .angolla_sub_<videoAdı>.<dil>.vtt
            p = os.path.join(folder, f".angolla_sub_{base_name}.{key}.vtt")
            try:
                if not os.path.exists(p):
                    with open(p, 'w', encoding='utf-8') as f:
                        f.write(content)
                    try:
                        self._video_register_temp_file(p)
                    except Exception:
                        pass
            except Exception:
                pass

    def _ensure_video_subtitles_loaded(self):
        st = getattr(self, '_video_settings_state', {})
        video_path = str(getattr(self, '_video_current_path', '') or '')
        if not video_path:
            return

        desired = str(st.get('subtitle_path') or '')
        loaded = str(st.get('subtitle_loaded_path') or '')
        if desired and loaded and os.path.abspath(desired) == os.path.abspath(loaded) and st.get('subtitle_items'):
            return

        sources = []
        try:
            sources = self._discover_video_subtitle_sources(create_templates=False)
        except Exception:
            sources = []
        if not sources:
            return

        # Seçili yoksa ilk kaynağı seç
        if not desired or not os.path.exists(desired):
            try:
                _, lbl, p = sources[0]
                st['subtitle_path'] = p
                st['subtitle_label'] = lbl
                desired = p
            except Exception:
                return

        try:
            items = self._parse_subtitle_file(desired)
            st['subtitle_items'] = items
            st['subtitle_index'] = 0
            st['subtitle_loaded_path'] = desired
        except Exception:
            st['subtitle_items'] = []
            st['subtitle_index'] = 0
            st['subtitle_loaded_path'] = None
        self._video_settings_state = st

    def _parse_subtitle_file(self, path: str):
        ext = ''
        try:
            ext = os.path.splitext(str(path or ''))[1].lower()
        except Exception:
            ext = ''
        if ext == '.vtt':
            return self._parse_vtt_file(path)
        # varsayılan: srt
        return self._parse_srt_file(path)

    def _parse_vtt_file(self, path: str):
        def _ts_to_ms(ts: str) -> int:
            ts = (ts or '').strip().replace(',', '.')
            parts = ts.split(':')
            if len(parts) == 2:
                h = 0
                m = int(parts[0])
                s_part = parts[1]
            else:
                h = int(parts[0])
                m = int(parts[1])
                s_part = parts[2]
            if '.' in s_part:
                s_str, ms_str = s_part.split('.', 1)
                ms_str = (ms_str + '000')[:3]
            else:
                s_str, ms_str = s_part, '000'
            return (h * 3600 + m * 60 + int(s_str)) * 1000 + int(ms_str)

        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            raw = f.read()
        raw = raw.replace('\r', '')

        # WEBVTT header / NOTE bloklarını basitçe ayıkla
        lines = [ln for ln in raw.split('\n')]
        # baştaki WEBVTT satırını kaldır
        if lines and lines[0].strip().upper().startswith('WEBVTT'):
            lines = lines[1:]
        raw2 = '\n'.join(lines).strip()
        blocks = [b.strip() for b in raw2.split('\n\n') if b.strip()]

        items = []
        for b in blocks:
            b_lines = [ln.strip() for ln in b.split('\n') if ln.strip()]
            if not b_lines:
                continue
            if b_lines[0].upper().startswith('NOTE'):
                continue

            # zaman satırı: genelde ilk veya ikinci satır
            time_line = None
            for ln in b_lines[:3]:
                if '-->' in ln:
                    time_line = ln
                    break
            if not time_line:
                continue
            try:
                start_s, end_s = [x.strip() for x in time_line.split('-->')[:2]]
                # end tarafında ayar (align/position) varsa kırp
                end_s = end_s.split(' ')[0].strip()
                start_ms = _ts_to_ms(start_s)
                end_ms = _ts_to_ms(end_s)
            except Exception:
                continue

            # metin: zaman satırından sonraki satırlar
            try:
                ti = b_lines.index(time_line)
            except Exception:
                ti = 0
            text_lines = b_lines[ti + 1:]
            text = ' '.join(text_lines).strip()
            if not text:
                continue
            items.append((start_ms, end_ms, text))

        items.sort(key=lambda x: x[0])
        return items

    def _parse_srt_file(self, path: str):
        def _ts_to_ms(ts: str) -> int:
            h, m, rest = ts.split(':')
            s, ms = rest.split(',')
            return (int(h) * 3600 + int(m) * 60 + int(s)) * 1000 + int(ms)

        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            raw = f.read()
        blocks = [b.strip() for b in raw.replace('\r', '').split('\n\n') if b.strip()]
        items = []
        for b in blocks:
            lines = [ln.strip() for ln in b.split('\n') if ln.strip()]
            if len(lines) < 2:
                continue
            time_line = lines[1] if '-->' in lines[1] else lines[0]
            if '-->' not in time_line:
                continue
            try:
                start_s, end_s = [x.strip() for x in time_line.split('-->')[:2]]
                start_ms = _ts_to_ms(start_s)
                end_ms = _ts_to_ms(end_s.split(' ')[0])
            except Exception:
                continue
            text_lines = lines[2:] if '-->' in lines[1] else lines[1:]
            text = ' '.join(text_lines).strip()
            if not text:
                continue
            items.append((start_ms, end_ms, text))
        items.sort(key=lambda x: x[0])
        return items

    def _update_video_subtitle_overlay(self, position_ms: int):
        st = getattr(self, '_video_settings_state', {})
        if not st.get('subtitles_enabled'):
            return
        items = st.get('subtitle_items') or []
        if not items:
            return

        try:
            idx = int(st.get('subtitle_index') or 0)
        except Exception:
            idx = 0
        idx = max(0, min(idx, len(items) - 1))

        try:
            while idx > 0 and position_ms < items[idx][0]:
                idx -= 1
            while idx < len(items) - 1 and position_ms > items[idx][1]:
                idx += 1
        except Exception:
            pass

        st['subtitle_index'] = idx
        self._video_settings_state = st

        start_ms, end_ms, text = items[idx]
        show = (start_ms <= position_ms <= end_ms)
        try:
            if hasattr(self, '_video_subtitle_label') and self._video_subtitle_label:
                if show:
                    self._video_subtitle_label.setText(text)
                    self._video_subtitle_label.show()
                    self._video_subtitle_label.raise_()
                    self._reposition_video_settings_ui()
                else:
                    self._video_subtitle_label.hide()
        except Exception:
            pass
    def _get_current_theme_colors(self):
        """(primary, text, bg) QColor döndürür (tema uyumu için)."""
        try:
            theme_name = getattr(self, 'theme', None)
            if theme_name and hasattr(self, 'themes') and theme_name in self.themes:
                primary_hex, text_hex, bg_hex = self.themes[theme_name]
                return QColor(primary_hex), QColor(text_hex), QColor(bg_hex)
        except Exception:
            pass

        pal = self.palette()
        return pal.color(QPalette.Highlight), pal.color(QPalette.Text), pal.color(QPalette.Window)

    @staticmethod
    def _mix_qcolors(a: QColor, b: QColor, t: float) -> QColor:
        try:
            t = max(0.0, min(1.0, float(t)))
        except Exception:
            t = 0.5
        r = int(a.red() + (b.red() - a.red()) * t)
        g = int(a.green() + (b.green() - a.green()) * t)
        bl = int(a.blue() + (b.blue() - a.blue()) * t)
        return QColor(r, g, bl)

    def _set_video_aura_speed(self, speed: float):
        """Video slider aura hızını ayarla (1.0 = normal)."""
        try:
            self._video_aura_speed = max(0.0, float(speed))
        except Exception:
            self._video_aura_speed = 1.0

        try:
            if hasattr(self, 'video_seek_slider') and hasattr(self.video_seek_slider, 'set_aura_speed'):
                self.video_seek_slider.set_aura_speed(self._video_aura_speed)
        except Exception:
            pass

    def _update_video_hud_aura(self):
        """Video aura güncellemesi - HUD kaldırıldı."""
        pass  # HUD kaldırıldı, bu fonksiyon artık kullanılmıyor

    def _enable_video_hud_controls(self, enable=True):
        """Video HUD kontrollerini aktif/pasif yap - HUD kaldırıldı."""
        pass  # HUD kaldırıldı, bu fonksiyon artık kullanılmıyor

    def _get_fs_controls_theme_style(self):
        """Tam ekran kontrollerinin tema uyumlu stilini döndür - AURA EFEKTLİ."""
        primary, text, bg = self._get_current_theme_colors()
        
        # Tema parlaklığına göre koyu/açık mod belirle
        bg_brightness = bg.value()  # 0-255 arası
        is_dark_theme = bg_brightness < 140
        
        # Alt bar arka planını temadan bağımsız sabitle (yarı saydam şeffaf görünüm)
        # 90/255 ~= 0.35
        panel_bg = "rgba(0, 0, 0, 90)"

        # Aura gradient renkleri (mavi-cyan-pembe)
        if is_dark_theme:
            # Koyu tema
            btn_bg = "rgba(255, 255, 255, 18)"
            btn_border = "rgba(255, 255, 255, 30)"
            btn_text = "rgba(255, 255, 255, 230)"
            btn_hover_bg = f"rgba({primary.red()}, {primary.green()}, {primary.blue()}, 150)"
            btn_hover_border = f"rgba({primary.red()}, {primary.green()}, {primary.blue()}, 210)"
            label_color = "rgba(255, 255, 255, 220)"
            
            # PROGRESS BAR - Aura gradient (mavi->cyan->pembe)
            progress_groove_bg = "rgba(255, 255, 255, 25)"
            progress_groove_border = "rgba(100, 200, 255, 80)"
            progress_subpage_gradient_start = "rgba(64, 156, 255, 200)"  # Mavi
            progress_subpage_gradient_mid = "rgba(64, 224, 208, 220)"     # Cyan
            progress_subpage_gradient_end = "rgba(255, 105, 180, 200)"    # Pembe
            progress_subpage_shadow = "0 0 8px rgba(64, 196, 255, 150), 0 0 12px rgba(64, 224, 208, 100)"
            progress_handle_bg = "rgba(255, 255, 255, 240)"
            progress_handle_shadow = "0 0 6px rgba(100, 200, 255, 200)"
            
            # SES SLIDER - Aura gradient
            volume_groove_bg = "rgba(255, 255, 255, 30)"
            volume_groove_border = "rgba(64, 196, 255, 60)"
            volume_subpage_gradient_start = f"rgba({primary.red()}, {primary.green()}, {primary.blue()}, 200)"
            volume_subpage_gradient_end = "rgba(64, 224, 208, 200)"
            volume_subpage_shadow = "0 0 6px rgba(64, 196, 255, 120)"
            volume_handle_bg = "rgba(255, 255, 255, 240)"
            volume_handle_shadow = "0 0 4px rgba(100, 200, 255, 180)"
        else:
            # Açık tema
            btn_bg = "rgba(0, 0, 0, 12)"
            btn_border = "rgba(0, 0, 0, 25)"
            btn_text = f"rgba({text.red()}, {text.green()}, {text.blue()}, 230)"
            btn_hover_bg = f"rgba({primary.red()}, {primary.green()}, {primary.blue()}, 120)"
            btn_hover_border = f"rgba({primary.red()}, {primary.green()}, {primary.blue()}, 190)"
            label_color = f"rgba({text.red()}, {text.green()}, {text.blue()}, 220)"
            
            # PROGRESS BAR - Aura gradient (açık tema)
            progress_groove_bg = "rgba(0, 0, 0, 20)"
            progress_groove_border = "rgba(64, 156, 255, 60)"
            progress_subpage_gradient_start = "rgba(64, 156, 255, 180)"
            progress_subpage_gradient_mid = "rgba(64, 224, 208, 200)"
            progress_subpage_gradient_end = "rgba(255, 105, 180, 180)"
            progress_subpage_shadow = "0 0 6px rgba(64, 156, 255, 120), 0 0 10px rgba(64, 224, 208, 80)"
            progress_handle_bg = f"rgba({text.red()}, {text.green()}, {text.blue()}, 240)"
            progress_handle_shadow = "0 0 5px rgba(64, 156, 255, 160)"
            
            # SES SLIDER - Aura gradient
            volume_groove_bg = "rgba(0, 0, 0, 25)"
            volume_groove_border = "rgba(64, 156, 255, 50)"
            volume_subpage_gradient_start = f"rgba({primary.red()}, {primary.green()}, {primary.blue()}, 180)"
            volume_subpage_gradient_end = "rgba(64, 224, 208, 180)"
            volume_subpage_shadow = "0 0 5px rgba(64, 156, 255, 100)"
            volume_handle_bg = f"rgba({text.red()}, {text.green()}, {text.blue()}, 240)"
            volume_handle_shadow = "0 0 4px rgba(64, 156, 255, 140)"
        
        return f"""
            QWidget#videoFsControls {{
                /* Tek parça görünüm + yarı saydamlık */
                background: {panel_bg};
                border: none;
                border-radius: 0px;
                min-height: 128px;
                max-height: 128px;
            }}

            /* Global tema bazı alt widget'lara koyu arka plan basabiliyor.
               Slider pseudo-elementlerini bozmayacak şekilde container'ları şeffaf zorla. */
            QWidget#videoFsControls QWidget {{
                background: transparent;
            }}
            QWidget#videoFsControls QFrame {{
                background: transparent;
            }}
            
            /* Butonlar - EXTRA BÜYÜK ve Modern */
            QWidget#videoFsControls QToolButton {{
                background: rgba(255, 255, 255, 18);
                border: 1px solid rgba(255, 255, 255, 40);
                border-radius: 6px;
                color: rgba(255, 255, 255, 240);
                padding: 8px 12px;
                font-size: 14px;
                font-weight: bold;
                min-width: 40px;
                min-height: 36px;
            }}

            /* Ayarlar (dişli) butonu biraz daha belirgin olsun */
            QWidget#videoFsControls QToolButton#fsSettingsBtn {{
                font-size: 18px;
                padding: 6px 10px;
            }}

            /* Playback ikonları: sadece ikon görünsün */
            QWidget#videoFsControls QToolButton#fsBackBtn,
            QWidget#videoFsControls QToolButton#fsPlayBtn,
            QWidget#videoFsControls QToolButton#fsFwdBtn {{
                background: transparent;
                border: none;
                padding: 0px;
                border-radius: 0px;
                min-width: 0px;
                min-height: 0px;
            }}

            /* ±10 saniye: yazı ikonları büyük ve görünür olsun */
            QWidget#videoFsControls QToolButton#fsBack10Btn,
            QWidget#videoFsControls QToolButton#fsFwd10Btn {{
                background: transparent;
                border: none;
                padding: 0px;
                border-radius: 0px;
                min-width: 0px;
                min-height: 0px;
            }}
            QWidget#videoFsControls QToolButton#fsBackBtn:hover,
            QWidget#videoFsControls QToolButton#fsPlayBtn:hover,
            QWidget#videoFsControls QToolButton#fsFwdBtn:hover {{
                background: transparent;
                border: none;
            }}
            QWidget#videoFsControls QToolButton:hover {{
                background: rgba(100, 200, 255, 140);
                border: 1px solid rgba(100, 200, 255, 200);
            }}
            QWidget#videoFsControls QToolButton:pressed {{
                background: rgba(100, 200, 255, 180);
                border: 2px solid rgba(100, 200, 255, 240);
            }}
            
            /* Label'lar - Büyütülmüş */
            QWidget#videoFsControls QLabel {{
                color: rgba(255, 255, 255, 230);
                background: transparent;
                font-size: 14px;
                font-weight: 600;
            }}
            
            /* PROGRESS BAR - AURA EFEKTİ - Daha Kalın ve Belirgin */
            QWidget#videoFsControls QSlider#_fs_seek_slider::groove:horizontal {{
                height: 10px;
                background: rgba(255, 255, 255, 25);
                border: 1px solid rgba(100, 200, 255, 80);
                border-radius: 5px;
            }}
            QWidget#videoFsControls QSlider#_fs_seek_slider::sub-page:horizontal {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {progress_subpage_gradient_start},
                    stop:0.5 {progress_subpage_gradient_mid},
                    stop:1 {progress_subpage_gradient_end});
                border-radius: 5px;
                box-shadow: {progress_subpage_shadow};
            }}
            QWidget#videoFsControls QSlider#_fs_seek_slider::handle:horizontal {{
                background: {progress_handle_bg};
                width: 18px;
                height: 18px;
                margin: -5px 0;
                border-radius: 9px;
                border: 2px solid rgba(100, 200, 255, 200);
                box-shadow: {progress_handle_shadow};
            }}
            QWidget#videoFsControls QSlider#_fs_seek_slider::handle:horizontal:hover {{
                width: 20px;
                height: 20px;
                margin: -6px 0;
                border-radius: 10px;
                box-shadow: 0 0 8px rgba(100, 200, 255, 255);
            }}
            
            /* SES SLIDER - AURA EFEKTİ - Daha Kalın */
            QWidget#videoFsControls QSlider#_fs_volume_slider::groove:horizontal {{
                height: 6px;
                background: rgba(255, 255, 255, 30);
                border: 1px solid rgba(64, 196, 255, 60);
                border-radius: 3px;
            }}
            QWidget#videoFsControls QSlider#_fs_volume_slider::sub-page:horizontal {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {volume_subpage_gradient_start},
                    stop:1 {volume_subpage_gradient_end});
                border-radius: 3px;
                box-shadow: {volume_subpage_shadow};
            }}
            QWidget#videoFsControls QSlider#_fs_volume_slider::handle:horizontal {{
                background: {volume_handle_bg};
                width: 14px;
                height: 14px;
                margin: -4px 0;
                border-radius: 7px;
                border: 2px solid rgba(64, 196, 255, 180);
                box-shadow: {volume_handle_shadow};
            }}
            QWidget#videoFsControls QSlider#_fs_volume_slider::handle:horizontal:hover {{
                width: 16px;
                height: 16px;
                margin: -5px 0;
                border-radius: 8px;
                box-shadow: 0 0 6px rgba(100, 200, 255, 220);
            }}
            
            /* Diğer slider'lar (varsayılan) */
            QWidget#videoFsControls QSlider::groove:horizontal {{
                height: 5px;
                background: rgba(255, 255, 255, 30);
                border-radius: 2px;
            }}
            QWidget#videoFsControls QSlider::sub-page:horizontal {{
                background: rgba(100, 200, 255, 180);
                border-radius: 2px;
            }}
            QWidget#videoFsControls QSlider::handle:horizontal {{
                background: rgba(255, 255, 255, 220);
                width: 11px;
                margin: -3px 0;
                border-radius: 5px;
            }}
        """
    
    def _get_fs_bottom_widget_theme_style(self):
        """Tam ekran bottom_widget için tema uyumlu stil döndür."""
        primary, text, bg = self._get_current_theme_colors()
        
        bg_brightness = bg.value()
        is_dark_theme = bg_brightness < 140
        
        if is_dark_theme:
            # Koyu tema: şeffaf koyu bar (rgba 0,0,0,0.35 = 89)
            return f"""
                QWidget#bottomWidget {{
                    background: rgba(0, 0, 0, 89);
                    border-top: 1px solid rgba(255, 255, 255, 15);
                    border-radius: 0px;
                }}
                QWidget#bottomWidget QLabel {{
                    color: rgba(255, 255, 255, 220);
                    background: transparent;
                }}
                QWidget#bottomWidget QPushButton, QWidget#bottomWidget QToolButton {{
                    background: rgba(255, 255, 255, 12);
                    border: 1px solid rgba(255, 255, 255, 20);
                    border-radius: 5px;
                    color: rgba(255, 255, 255, 210);
                }}
                QWidget#bottomWidget QPushButton:hover, QWidget#bottomWidget QToolButton:hover {{
                    background: rgba({primary.red()}, {primary.green()}, {primary.blue()}, 110);
                    border: 1px solid rgba({primary.red()}, {primary.green()}, {primary.blue()}, 180);
                }}
                QWidget#bottomWidget QSlider::groove:horizontal {{
                    height: 5px;
                    background: rgba(255, 255, 255, 30);
                    border-radius: 2px;
                }}
                QWidget#bottomWidget QSlider::sub-page:horizontal {{
                    background: rgba({primary.red()}, {primary.green()}, {primary.blue()}, 180);
                    border-radius: 2px;
                }}
                QWidget#bottomWidget QSlider::handle:horizontal {{
                    background: rgba(255, 255, 255, 220);
                    width: 12px;
                    margin: -4px 0;
                    border-radius: 6px;
                }}
            """
        else:
            # Açık tema: şeffaf beyaz bar
            return f"""
                QWidget#bottomWidget {{
                    background: rgba(255, 255, 255, 89);
                    border-top: 1px solid rgba(0, 0, 0, 12);
                    border-radius: 0px;
                }}
                QWidget#bottomWidget QLabel {{
                    color: rgba({text.red()}, {text.green()}, {text.blue()}, 220);
                    background: transparent;
                }}
                QWidget#bottomWidget QPushButton, QWidget#bottomWidget QToolButton {{
                    background: rgba(0, 0, 0, 8);
                    border: 1px solid rgba(0, 0, 0, 15);
                    border-radius: 5px;
                    color: rgba({text.red()}, {text.green()}, {text.blue()}, 210);
                }}
                QWidget#bottomWidget QPushButton:hover, QWidget#bottomWidget QToolButton:hover {{
                    background: rgba({primary.red()}, {primary.green()}, {primary.blue()}, 90);
                    border: 1px solid rgba({primary.red()}, {primary.green()}, {primary.blue()}, 160);
                }}
                QWidget#bottomWidget QSlider::groove:horizontal {{
                    height: 5px;
                    background: rgba(0, 0, 0, 25);
                    border-radius: 2px;
                }}
                QWidget#bottomWidget QSlider::sub-page:horizontal {{
                    background: rgba({primary.red()}, {primary.green()}, {primary.blue()}, 180);
                    border-radius: 2px;
                }}
                QWidget#bottomWidget QSlider::handle:horizontal {{
                    background: rgba({text.red()}, {text.green()}, {text.blue()}, 210);
                    width: 12px;
                    margin: -4px 0;
                    border-radius: 6px;
                }}
            """

    def _create_video_fullscreen_controls(self):
        """Tam ekran modunda görünecek TEK ve KAPSAMLI kontrol barını oluştur."""
        if hasattr(self, '_video_fs_controls') and self._video_fs_controls:
            return  # Zaten oluşturulmuş
        
        # Ana konteyner - tam ekran tek bar
        self._video_fs_controls = QWidget(self)
        self._video_fs_controls.setObjectName("videoFsControls")
        try:
            # Bar yarı saydam olacağı için stylesheet arka planının kesin çizilmesini sağla
            self._video_fs_controls.setAttribute(Qt.WA_StyledBackground, True)
            self._video_fs_controls.setAttribute(Qt.WA_TranslucentBackground, False)
            self._video_fs_controls.setAutoFillBackground(True)
        except Exception:
            pass
        self._video_fs_controls.setStyleSheet(self._get_fs_controls_theme_style())
        # Bazı platformlarda QSS min/max-height her zaman uygulanmadığı için
        # bar yüksekliğini koddan sabitle (buton kırpılmasını engeller).
        self._video_fs_controls.setFixedHeight(128)
        
        # Ana horizontal layout - TEK SATIR
        main_layout = QHBoxLayout(self._video_fs_controls)
        main_layout.setContentsMargins(16, 10, 16, 10)
        main_layout.setSpacing(14)
        
        # === SOL: ZAMAN + SES ===
        left_container = QWidget()
        left_layout = QVBoxLayout(left_container)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(4)
        
        # Zaman göstergesi
        self._fs_time_label = QLabel("00:00 / 00:00")
        self._fs_time_label.setAlignment(Qt.AlignCenter)
        self._fs_time_label.setStyleSheet("font-size: 14px; font-weight: 600; color: rgba(255,255,255,230);")
        left_layout.addWidget(self._fs_time_label)
        
        main_layout.addWidget(left_container)
        
        # === ORTA: PLAYBACK + PROGRESS (MODERN LAYOUT) ===
        center_container = QWidget()
        center_layout = QVBoxLayout(center_container)
        center_layout.setContentsMargins(0, 0, 0, 0)
        center_layout.setSpacing(3)
        
        # Progress bar (üstte)
        self._fs_seek_slider = QSlider(Qt.Horizontal)
        self._fs_seek_slider.setObjectName("_fs_seek_slider")
        self._fs_seek_slider.setRange(0, 0)
        self._fs_seek_slider.setValue(0)
        self._fs_seek_slider.setTracking(True)
        self._fs_seek_slider.setMinimumWidth(400)
        self._fs_seek_slider.sliderPressed.connect(self._on_fs_seek_pressed)
        self._fs_seek_slider.sliderMoved.connect(self._on_fs_seek_moved)
        self._fs_seek_slider.sliderReleased.connect(self._on_fs_seek_released)
        center_layout.addWidget(self._fs_seek_slider)
        
        # Playback butonları (progress bar'ın altında, ortalanmış)
        playback_row = QWidget()
        playback_layout = QHBoxLayout(playback_row)
        # Playback grubunu kullanıcı açısından sağa kaydırmak için
        # layout'ın sol margin'ini DPI'ye göre arttır.
        # Not: Sol margin L olursa merkez yaklaşık L/2 sağa kayar.
        # 4.5cm sağ kayma için margin'i ~9cm ayarlıyoruz.
        try:
            dpi = 96.0
            screen = QApplication.primaryScreen()
            if screen:
                dpi = float(screen.logicalDotsPerInch())
            margin_left = int((dpi / 2.54) * 9.0)  # 9cm margin => ~4.5cm sağ kayma
        except Exception:
            margin_left = 150
        playback_layout.setContentsMargins(max(0, margin_left), 0, 0, 0)
        playback_layout.setSpacing(8)
        playback_layout.addStretch(1)
        
        # Önceki video (geri getir)
        self._fs_prev_btn = QToolButton()
        self._fs_prev_btn.setObjectName("fsBackBtn")
        self._fs_prev_btn.setAutoRaise(True)
        try:
            self._fs_prev_btn.setIcon(QIcon(os.path.join("icons", "media-skip-backward.png")))
            self._fs_prev_btn.setIconSize(QSize(34, 34))
            self._fs_prev_btn.setText("")
        except Exception:
            self._fs_prev_btn.setText("⏮")
        self._fs_prev_btn.setToolTip("Önceki video")
        self._fs_prev_btn.setFixedSize(62, 56)
        self._fs_prev_btn.clicked.connect(lambda: self._play_video_relative(-1))
        playback_layout.addWidget(self._fs_prev_btn)

        # -10sn butonu (play'in solunda)
        self._fs_back10_btn = QToolButton()
        self._fs_back10_btn.setObjectName("fsBack10Btn")
        self._fs_back10_btn.setAutoRaise(True)
        try:
            self._fs_back10_btn.setIcon(QIcon(os.path.join("icons", "seek10_fwd.svg")))
            self._fs_back10_btn.setIconSize(QSize(34, 34))
            self._fs_back10_btn.setText("")
        except Exception:
            self._fs_back10_btn.setText("⟲10")
        self._fs_back10_btn.setToolTip("-10 saniye")
        self._fs_back10_btn.setFixedSize(62, 56)
        self._fs_back10_btn.clicked.connect(lambda: self._seek_relative(-10000))
        playback_layout.addWidget(self._fs_back10_btn)
        
        # Play/Pause butonu (EXTRA BÜYÜK MODERN)
        self._fs_play_btn = QToolButton()
        self._fs_play_btn.setObjectName("fsPlayBtn")
        self._fs_play_btn.setAutoRaise(True)
        try:
            self._fs_play_btn.setIcon(QIcon(os.path.join("icons", "media-playback-start.png")))
            self._fs_play_btn.setIconSize(QSize(38, 38))
            self._fs_play_btn.setText("")
        except Exception:
            self._fs_play_btn.setText("▶")
        self._fs_play_btn.setToolTip("Oynat/Duraklat")
        self._fs_play_btn.setFixedSize(68, 60)
        self._fs_play_btn.clicked.connect(self._on_fs_play_clicked)
        playback_layout.addWidget(self._fs_play_btn)

        # +10sn butonu (play'in sağında)
        self._fs_fwd10_btn = QToolButton()
        self._fs_fwd10_btn.setObjectName("fsFwd10Btn")
        self._fs_fwd10_btn.setAutoRaise(True)
        try:
            self._fs_fwd10_btn.setIcon(QIcon(os.path.join("icons", "seek10_back.svg")))
            self._fs_fwd10_btn.setIconSize(QSize(34, 34))
            self._fs_fwd10_btn.setText("")
        except Exception:
            self._fs_fwd10_btn.setText("⟳10")
        self._fs_fwd10_btn.setToolTip("+10 saniye")
        self._fs_fwd10_btn.setFixedSize(62, 56)
        self._fs_fwd10_btn.clicked.connect(lambda: self._seek_relative(10000))
        playback_layout.addWidget(self._fs_fwd10_btn)
        
        # Sonraki video (geri getir)
        self._fs_next_btn = QToolButton()
        self._fs_next_btn.setObjectName("fsFwdBtn")
        self._fs_next_btn.setAutoRaise(True)
        try:
            self._fs_next_btn.setIcon(QIcon(os.path.join("icons", "media-skip-forward.png")))
            self._fs_next_btn.setIconSize(QSize(34, 34))
            self._fs_next_btn.setText("")
        except Exception:
            self._fs_next_btn.setText("⏭")
        self._fs_next_btn.setToolTip("Sonraki video")
        self._fs_next_btn.setFixedSize(62, 56)
        self._fs_next_btn.clicked.connect(lambda: self._play_video_relative(1))
        playback_layout.addWidget(self._fs_next_btn)
        
        playback_layout.addStretch(1)
        center_layout.addWidget(playback_row)
        
        main_layout.addWidget(center_container, 1)
        
        # === SAĞ: HIZ + FPS + AYARLAR ===
        right_container = QWidget()
        right_layout = QHBoxLayout(right_container)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(6)

        # Ses kontrolü (sağ tarafa taşındı)
        volume_container = QWidget()
        volume_layout = QHBoxLayout(volume_container)
        volume_layout.setContentsMargins(0, 0, 0, 0)
        volume_layout.setSpacing(4)

        volume_icon = QLabel("🔊")
        volume_icon.setStyleSheet("font-size: 16px;")
        self._fs_volume_slider = QSlider(Qt.Horizontal)
        self._fs_volume_slider.setObjectName("_fs_volume_slider")
        self._fs_volume_slider.setRange(0, 100)
        self._fs_volume_slider.setValue(70)
        self._fs_volume_slider.setFixedWidth(110)
        self._fs_volume_slider.valueChanged.connect(self._on_fs_volume_changed)
        self._fs_volume_label = QLabel("70%")
        self._fs_volume_label.setFixedWidth(35)
        self._fs_volume_label.setStyleSheet("font-size: 13px; font-weight: 600; color: rgba(255,255,255,230);")

        volume_layout.addWidget(volume_icon)
        volume_layout.addWidget(self._fs_volume_slider)
        volume_layout.addWidget(self._fs_volume_label)
        right_layout.addWidget(volume_container)
        
        # Hız
        self._fs_speed_btn = QToolButton()
        self._fs_speed_btn.setText("1.0x")
        self._fs_speed_btn.setToolTip("Oynatma Hızı")
        self._fs_speed_btn.setFixedSize(52, 36)
        self._fs_speed_btn.clicked.connect(self._on_fs_speed_clicked)
        right_layout.addWidget(self._fs_speed_btn)
        
        # FPS
        self._fs_fps_btn = QToolButton()
        self._fs_fps_btn.setText("Auto")
        self._fs_fps_btn.setToolTip("Hedef FPS")
        self._fs_fps_btn.setFixedSize(52, 36)
        self._fs_fps_btn.clicked.connect(self._on_fs_fps_clicked)
        right_layout.addWidget(self._fs_fps_btn)
        
        # Ayırıcı
        sep = QFrame()
        sep.setFrameShape(QFrame.VLine)
        sep.setStyleSheet("background: rgba(255,255,255,30);")
        sep.setFixedWidth(1)
        right_layout.addWidget(sep)
        
        # Tam ekran çıkış
        self._fs_exit_btn = QToolButton()
        self._fs_exit_btn.setText("⛶")
        self._fs_exit_btn.setToolTip("Çık (ESC)")
        self._fs_exit_btn.setFixedSize(40, 36)
        self._fs_exit_btn.clicked.connect(self._exit_video_fullscreen)
        right_layout.addWidget(self._fs_exit_btn)
        
        # Ayarlar
        self._fs_settings_btn = QToolButton()
        self._fs_settings_btn.setObjectName("fsSettingsBtn")
        self._fs_settings_btn.setText("")
        self._fs_settings_btn.setToolTip("Ayarlar")
        self._fs_settings_btn.setFixedSize(48, 40)
        self._fs_settings_btn.setAutoRaise(True)
        try:
            # YouTube benzeri dişli: önce sistem tema ikonu dene
            icon = QIcon.fromTheme('preferences-system')
            if icon.isNull():
                icon = QIcon.fromTheme('settings')
            if icon.isNull():
                icon = QIcon.fromTheme('preferences-system-settings')
            if not icon.isNull():
                self._fs_settings_btn.setIcon(icon)
            else:
                # Fallback: unicode dişli
                self._fs_settings_btn.setText("⚙")
        except Exception:
            try:
                self._fs_settings_btn.setText("⚙")
            except Exception:
                pass
        try:
            self._fs_settings_btn.setIconSize(QSize(24, 24))
        except Exception:
            pass
        self._fs_settings_btn.clicked.connect(self._on_fs_settings_clicked)
        right_layout.addWidget(self._fs_settings_btn)
        
        main_layout.addWidget(right_container)
        
        # RGB LED animasyon timer'ı başlat
        self._rgb_animation_offset = 0.0
        self._rgb_timer = QTimer(self)
        self._rgb_timer.timeout.connect(self._update_rgb_gradient)
        self._rgb_timer.start(80)  # Daha yavaş ve yumuşak animasyon
        
        # Başlangıçta gizle
        self._video_fs_controls.hide()
        
        # Seek tracking durumu
        self._fs_seeking = False
    
    def _on_fs_play_clicked(self):
        """Tam ekran play/pause butonu."""
        if not hasattr(self, 'videoPlayer'):
            return
        
        if self.videoPlayer.state() == QMediaPlayer.PlayingState:
            self.videoPlayer.pause()
        else:
            self.videoPlayer.play()
    
    def _on_fs_seek_pressed(self):
        """Seek slider basıldı."""
        self._fs_seeking = True
    
    def _on_fs_seek_moved(self, value):
        """Seek slider hareket ediyor."""
        if hasattr(self, '_fs_time_label') and hasattr(self, 'videoPlayer'):
            duration = self.videoPlayer.duration()
            time_str = f"{self._format_time(value)} / {self._format_time(duration)}"
            self._fs_time_label.setText(time_str)
    
    def _on_fs_seek_released(self):
        """Seek slider bırakıldı."""
        if hasattr(self, 'videoPlayer') and hasattr(self, '_fs_seek_slider'):
            self.videoPlayer.setPosition(self._fs_seek_slider.value())
        self._fs_seeking = False
    
    def _seek_relative(self, ms):
        """Göreceli seek (+ veya - ms)."""
        if not hasattr(self, 'videoPlayer'):
            return
        current = self.videoPlayer.position()
        duration = self.videoPlayer.duration()
        new_pos = max(0, min(duration, current + ms))
        self.videoPlayer.setPosition(new_pos)

    def _get_video_sibling_files(self, current_path: str) -> list:
        """Aynı klasördeki desteklenen videoları (sıralı) döndür."""
        try:
            if not current_path or not os.path.isfile(current_path):
                return []
            folder = os.path.dirname(current_path)
            if not folder or not os.path.isdir(folder):
                return []
            exts = self._supported_video_exts() if hasattr(self, '_supported_video_exts') else set()
            files = []
            for name in os.listdir(folder):
                path = os.path.join(folder, name)
                if not os.path.isfile(path):
                    continue
                ext = os.path.splitext(name)[1].lower()
                if exts and ext not in exts:
                    continue
                files.append(path)
            files.sort(key=lambda p: os.path.basename(p).lower())
            return files
        except Exception:
            return []

    def _play_video_relative(self, delta: int):
        """Mevcut videoya göre önceki/sonraki videoyu aç (aynı klasör içinde)."""
        try:
            delta = int(delta)
        except Exception:
            delta = 0
        if delta == 0:
            return

        current_path = getattr(self, '_video_last_source_text', '') or ''
        siblings = self._get_video_sibling_files(current_path)
        if not siblings:
            return
        try:
            idx = siblings.index(current_path)
        except ValueError:
            idx = 0
        new_idx = (idx + delta) % len(siblings)
        new_path = siblings[new_idx]
        try:
            self._play_video_file(new_path)
        except Exception:
            pass
    
    def _update_rgb_gradient(self):
        """RGB LED animasyon güncelleme - progress bar için."""
        if not hasattr(self, '_fs_seek_slider'):
            return
        
        # Offset'i artır (0.0 → 1.0 → 0.0 döngüsü) - yavaşlatıldı
        self._rgb_animation_offset += 0.008
        if self._rgb_animation_offset > 1.0:
            self._rgb_animation_offset = 0.0
        
        # RGB LED renkler: Mavi → Mor → Pembe → Kırmızı → Turuncu → Sarı → Yeşil → Cyan → Mavi
        colors = [
            (64, 156, 255),    # Mavi
            (138, 43, 226),    # Mor
            (255, 105, 180),   # Pembe  
            (255, 69, 0),      # Kırmızı-Turuncu
            (255, 165, 0),     # Turuncu
            (255, 215, 0),     # Sarı
            (50, 205, 50),     # Yeşil
            (64, 224, 208),    # Cyan
        ]
        
        # Offset'e göre renk interpolasyonu
        num_colors = len(colors)
        offset = self._rgb_animation_offset * num_colors
        idx1 = int(offset) % num_colors
        idx2 = (idx1 + 1) % num_colors
        frac = offset - int(offset)
        
        # İki renk arasında interpolasyon
        c1, c2 = colors[idx1], colors[idx2]
        r = int(c1[0] + (c2[0] - c1[0]) * frac)
        g = int(c1[1] + (c2[1] - c1[1]) * frac)
        b = int(c1[2] + (c2[2] - c1[2]) * frac)
        
        # İkinci renk (gradient için)
        idx3 = (idx2 + 1) % num_colors
        c3 = colors[idx3]
        r2 = int(c2[0] + (c3[0] - c2[0]) * frac)
        g2 = int(c2[1] + (c3[1] - c2[1]) * frac)
        b2 = int(c2[2] + (c3[2] - c2[2]) * frac)
        
        # Animasyonlu gradient CSS oluştur (seek + volume)
        rgb_style = f"""
        QWidget#videoFsControls QSlider#_fs_seek_slider::sub-page:horizontal {{
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 rgba({r}, {g}, {b}, 220),
                stop:0.5 rgba({r2}, {g2}, {b2}, 240),
                stop:1 rgba({r}, {g}, {b}, 220));
            border: none;
        }}
        QWidget#videoFsControls QSlider#_fs_volume_slider::sub-page:horizontal {{
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 rgba({r}, {g}, {b}, 210),
                stop:0.5 rgba({r2}, {g2}, {b2}, 230),
                stop:1 rgba({r}, {g}, {b}, 210));
            border: none;
        }}
        """
        
        # Tema stilini al ve RGB stilini ekle
        base_style = self._get_fs_controls_theme_style()
        self._video_fs_controls.setStyleSheet(base_style + rgb_style)
    
    def _update_fs_controls_state(self):
        """Tam ekran kontrollerini video durumuna göre güncelle."""
        if not hasattr(self, '_video_fs_controls') or not self._video_fs_controls:
            return
        if not hasattr(self, 'videoPlayer'):
            return
        
        # Play/Pause butonu
        if hasattr(self, '_fs_play_btn'):
            is_playing = self.videoPlayer.state() == QMediaPlayer.PlayingState
            try:
                icon_name = "media-playback-pause.png" if is_playing else "media-playback-start.png"
                self._fs_play_btn.setIcon(QIcon(os.path.join("icons", icon_name)))
                self._fs_play_btn.setText("")
            except Exception:
                self._fs_play_btn.setText("⏸" if is_playing else "▶")
            self._fs_play_btn.setToolTip("Duraklat" if is_playing else "Oynat")
        
        # Progress ve zaman
        if not getattr(self, '_fs_seeking', False):
            position = self.videoPlayer.position()
            duration = self.videoPlayer.duration()
            
            if hasattr(self, '_fs_seek_slider'):
                self._fs_seek_slider.blockSignals(True)
                self._fs_seek_slider.setMaximum(duration if duration > 0 else 0)
                self._fs_seek_slider.setValue(position)
                self._fs_seek_slider.blockSignals(False)
            
            # Tek label'da her iki zaman
            if hasattr(self, '_fs_time_label'):
                time_str = f"{self._format_time(position)} / {self._format_time(duration)}"
                self._fs_time_label.setText(time_str)
        
        # Ses
        if hasattr(self, '_fs_volume_slider') and hasattr(self, '_fs_volume_label'):
            vol = self.videoPlayer.volume()
            self._fs_volume_slider.blockSignals(True)
            self._fs_volume_slider.setValue(vol)
            self._fs_volume_slider.blockSignals(False)
            self._fs_volume_label.setText(f"{vol}%")
        
        # Hız
        if hasattr(self, '_fs_speed_btn'):
            rate = getattr(self, '_current_playback_rate', 1.0)
            self._fs_speed_btn.setText(f"{rate:.2f}x")
        
        # FPS
        if hasattr(self, '_fs_fps_btn'):
            fps = getattr(self, '_video_target_fps', 0)
            self._fs_fps_btn.setText("Auto" if fps == 0 else str(fps))
    
    def _format_time(self, ms):
        """Milisaniyeyi MM:SS formatına çevir."""
        if ms < 0:
            ms = 0
        total_seconds = ms // 1000
        minutes = total_seconds // 60
        seconds = total_seconds % 60
        return f"{minutes:02d}:{seconds:02d}"
    
    def _on_fs_volume_changed(self, value):
        """Tam ekran ses slider değişikliği."""
        if hasattr(self, 'videoPlayer'):
            self.videoPlayer.setVolume(value)
            self.videoPlayer.setMuted(False)
        if hasattr(self, '_fs_volume_label'):
            self._fs_volume_label.setText(f"{value}%")
    
    def _on_fs_speed_clicked(self):
        """Tam ekran hız butonu - döngüsel değiştir."""
        rates = [0.5, 0.75, 1.0, 1.25, 1.5, 2.0]
        current = getattr(self, '_current_playback_rate', 1.0)
        next_rate = rates[0]
        for i, r in enumerate(rates):
            if abs(r - current) < 0.01:
                next_rate = rates[(i + 1) % len(rates)]
                break
        self._set_playback_rate(next_rate)
        if hasattr(self, '_fs_speed_btn'):
            self._fs_speed_btn.setText(f"{next_rate:.2f}x")
    
    def _on_fs_fps_clicked(self):
        """Tam ekran FPS butonu - döngüsel değiştir."""
        fps_options = [0, 24, 30, 60]  # 0 = Auto
        current = getattr(self, '_video_target_fps', 0)
        next_fps = fps_options[0]
        for i, f in enumerate(fps_options):
            if f == current:
                next_fps = fps_options[(i + 1) % len(fps_options)]
                break
        self._set_video_target_fps(next_fps)
        if hasattr(self, '_fs_fps_btn'):
            self._fs_fps_btn.setText("Auto" if next_fps == 0 else str(next_fps))
    
    def _on_fs_settings_clicked(self):
        """Tam ekran ayarlar butonu - video ayarlar panelini aç/kapat."""
        try:
            if not hasattr(self, '_video_settings_panel') or self._video_settings_panel is None:
                self._create_video_settings_ui()
        except Exception:
            pass
        try:
            self._toggle_video_settings_panel()
        except Exception:
            pass
    
    def _reset_fs_speed(self):
        """Hızı sıfırla."""
        self._set_playback_rate(1.0)
        if hasattr(self, '_fs_speed_btn'):
            self._fs_speed_btn.setText("1.00x")
    
    def _init_fs_bar_auto_hide(self):
        """Tam ekran bar otomatik gizleme sistemini başlat."""
        # Auto-hide timer (3 saniye)
        if not hasattr(self, '_fs_bar_hide_timer'):
            self._fs_bar_hide_timer = QTimer(self)
            self._fs_bar_hide_timer.setSingleShot(True)
            self._fs_bar_hide_timer.timeout.connect(self._on_fs_bar_hide_timeout)
        
        # Animasyon durumu
        self._fs_bars_visible = True
        self._fs_bar_animating = False
    
    def _start_fs_bar_hide_timer(self):
        """Bar gizleme zamanlayıcısını başlat/sıfırla."""
        if not getattr(self, '_in_video_fullscreen', False):
            return
        # Video ayar paneli açıkken alt bar asla kaybolmasın
        try:
            if hasattr(self, '_video_settings_panel') and self._video_settings_panel and self._video_settings_panel.isVisible():
                return
        except Exception:
            pass
        if hasattr(self, '_fs_bar_hide_timer'):
            self._fs_bar_hide_timer.stop()
            self._fs_bar_hide_timer.start(3000)  # 3 saniye
    
    def _stop_fs_bar_hide_timer(self):
        """Bar gizleme zamanlayıcısını durdur."""
        if hasattr(self, '_fs_bar_hide_timer'):
            self._fs_bar_hide_timer.stop()
    
    def _is_mouse_over_fs_bars(self):
        """Fare bar veya kontroller üzerinde mi kontrol et."""
        cursor_pos = QCursor.pos()
        
        # Tek kontrol barı kontrolü
        if hasattr(self, '_video_fs_controls') and self._video_fs_controls and self._video_fs_controls.isVisible():
            fs_global = self._video_fs_controls.mapToGlobal(QPoint(0, 0))
            fs_rect = QRect(fs_global, self._video_fs_controls.size())
            if fs_rect.contains(cursor_pos):
                return True
        
        return False
    
    def _on_fs_bar_hide_timeout(self):
        """3 saniye sonra bar gizleme kontrolü."""
        if not getattr(self, '_in_video_fullscreen', False):
            return

        # Video ayar paneli açıkken alt bar asla kaybolmasın
        try:
            if hasattr(self, '_video_settings_panel') and self._video_settings_panel and self._video_settings_panel.isVisible():
                return
        except Exception:
            pass
        
        # Fare bar üzerindeyse gizleme, timer'ı yeniden başlat
        if self._is_mouse_over_fs_bars():
            self._start_fs_bar_hide_timer()
            return
        
        # Akıcı animasyonla barları gizle
        self._animate_fs_bars_hide()
    
    def _animate_fs_bars_hide(self):
        """Tek barı aşağı doğru akıcı animasyonla gizle."""
        if getattr(self, '_fs_bar_animating', False):
            return
        if not getattr(self, '_fs_bars_visible', True):
            return
        
        self._fs_bar_animating = True
        self._fs_bars_visible = False
        
        # Tek kontrol barı animasyonu
        if hasattr(self, '_video_fs_controls') and self._video_fs_controls and self._video_fs_controls.isVisible():
            self._fs_controls_anim = QPropertyAnimation(self._video_fs_controls, b"pos")
            self._fs_controls_anim.setDuration(300)
            self._fs_controls_anim.setEasingCurve(QEasingCurve.OutCubic)
            start_pos = self._video_fs_controls.pos()
            end_pos = QPoint(start_pos.x(), self.height())  # Ekran dışına
            self._fs_controls_anim.setStartValue(start_pos)
            self._fs_controls_anim.setEndValue(end_pos)
            self._fs_controls_anim.finished.connect(self._on_fs_bar_hide_finished)
            self._fs_controls_anim.start()
        
        # İmleci gizle
        self.setCursor(Qt.BlankCursor)
        if hasattr(self, 'video_output_widget') and self.video_output_widget:
            self.video_output_widget.setCursor(Qt.BlankCursor)
    
    def _on_fs_bar_hide_finished(self):
        """Bar gizleme animasyonu tamamlandı."""
        self._fs_bar_animating = False
    
    def _animate_fs_bars_show(self):
        """Tek barı aşağıdan yukarı akıcı animasyonla göster."""
        if getattr(self, '_fs_bar_animating', False):
            return
        if getattr(self, '_fs_bars_visible', True):
            return
        
        self._fs_bar_animating = True
        self._fs_bars_visible = True
        
        # İmleci göster
        self.setCursor(Qt.ArrowCursor)
        if hasattr(self, 'video_output_widget') and self.video_output_widget:
            self.video_output_widget.setCursor(Qt.ArrowCursor)
        
        # Tek kontrol barı animasyonu - ekranın altına yakın konumlandır
        if hasattr(self, '_video_fs_controls') and self._video_fs_controls:
            target_y = self.height() - self._video_fs_controls.height()
            
            self._fs_controls_anim = QPropertyAnimation(self._video_fs_controls, b"pos")
            self._fs_controls_anim.setDuration(250)
            self._fs_controls_anim.setEasingCurve(QEasingCurve.OutCubic)
            start_pos = self._video_fs_controls.pos()
            end_pos = QPoint(0, target_y)
            self._fs_controls_anim.setStartValue(start_pos)
            self._fs_controls_anim.setEndValue(end_pos)
            self._fs_controls_anim.finished.connect(self._on_fs_bar_show_finished)
            self._fs_controls_anim.start()
    
    def _on_fs_bar_show_finished(self):
        """Bar gösterme animasyonu tamamlandı."""
        self._fs_bar_animating = False
        # Timer'ı yeniden başlat
        self._start_fs_bar_hide_timer()
    
    def _on_fs_mouse_move(self):
        """Tam ekranda fare hareket etti - barları göster ve timer'ı sıfırla."""
        if not getattr(self, '_in_video_fullscreen', False):
            return
        
        # Barlar gizliyse göster
        if not getattr(self, '_fs_bars_visible', True):
            self._animate_fs_bars_show()
        else:
            # Timer'ı sıfırla
            self._start_fs_bar_hide_timer()
            # İmleci göster
            self.setCursor(Qt.ArrowCursor)
            if hasattr(self, 'video_output_widget') and self.video_output_widget:
                self.video_output_widget.setCursor(Qt.ArrowCursor)
    
    def _show_video_fs_controls(self):
        """Tam ekran kontrollerini göster ve konumlandır."""
        if not hasattr(self, '_video_fs_controls') or not self._video_fs_controls:
            self._create_video_fullscreen_controls()
        
        # Tema uyumlu stil uygula
        if hasattr(self, '_video_fs_controls') and self._video_fs_controls:
            self._video_fs_controls.setStyleSheet(self._get_fs_controls_theme_style())
        
        # Tüm kontrolleri güncelle
        self._update_fs_controls_state()
        
        # Konumlandır (ekranın alt kısmında)
        self._video_fs_controls.setParent(self)
        self._video_fs_controls.setFixedWidth(self.width())
        
        # Ekran altına yakın konumlandır
        y_pos = self.height() - self._video_fs_controls.height()
        self._video_fs_controls.move(0, y_pos)
        self._video_fs_controls.raise_()
        self._video_fs_controls.show()
        
        # Auto-hide sistemini başlat
        self._init_fs_bar_auto_hide()
        self._fs_bars_visible = True
        self._start_fs_bar_hide_timer()
    
    def _hide_video_fs_controls(self):
        """Tam ekran kontrollerini gizle."""
        # Timer'ı durdur
        self._stop_fs_bar_hide_timer()
        
        if hasattr(self, '_video_fs_controls') and self._video_fs_controls:
            self._video_fs_controls.hide()

    def _toggle_video_fullscreen(self):
        """Yerel video tam ekran toggle (HUD sadece tam ekranda görünür)."""
        if getattr(self, '_in_video_fullscreen', False):
            self._exit_video_fullscreen()
        else:
            self._enter_video_fullscreen()

    def _enter_video_fullscreen(self):
        if getattr(self, '_in_video_fullscreen', False):
            return
        # Sadece video sayfasında anlamlı (otomatik sekme/panel değiştirme yok)
        try:
            if hasattr(self, 'mainContentStack') and self.mainContentStack.currentIndex() != 1:
                return
        except Exception:
            return

        self._video_fullscreen_state = {
            'was_maximized': self.isMaximized(),
            'geometry': self.geometry(),
            'side_visible': self.side_panel.isVisible() if hasattr(self, 'side_panel') else True,
            'bottom_visible': self.bottom_widget.isVisible() if hasattr(self, 'bottom_widget') else True,
            'split_sizes': self.main_splitter.sizes() if hasattr(self, 'main_splitter') else [],
        }
        self._in_video_fullscreen = True
        
        # Parlaklığı normal seviyeye sıfırla (her fullscreen girişinde)
        self._video_brightness = 1.0
        if hasattr(self, '_brightness_overlay') and self._brightness_overlay:
            self._brightness_overlay.hide()
        if hasattr(self, '_brighten_overlay') and self._brighten_overlay:
            self._brighten_overlay.hide()

        try:
            if hasattr(self, 'side_panel'):
                self.side_panel.hide()
            
            # TAMAMEN ANA BAR'I GİZLE - Tam ekranda kullanılmayacak
            if hasattr(self, 'bottom_widget'):
                # Orijinal durum kaydet
                if not hasattr(self, '_bottom_widget_original_visible'):
                    self._bottom_widget_original_visible = self.bottom_widget.isVisible()
                if not hasattr(self, '_bottom_widget_original_style'):
                    self._bottom_widget_original_style = self.bottom_widget.styleSheet()
                
                # TAMAMEN GİZLE
                self.bottom_widget.hide()
            
            # Hide ALL top bars (menu, status, toolbars)
            if self.menuBar(): 
                self.menuBar().hide()
            if self.statusBar(): 
                self.statusBar().hide()
            if hasattr(self, 'fileLabel'): 
                self.fileLabel.hide()
            
            # Force layout update to remove black gaps
            if hasattr(self, 'centralWidget') and self.centralWidget():
                self.centralWidget().layout().setContentsMargins(0, 0, 0, 0)
                self.centralWidget().layout().setSpacing(0)
                self.centralWidget().layout().activate()
            
            # Ensure all parent containers have zero margins
            if hasattr(self, 'main_splitter'):
                self.main_splitter.setHandleWidth(0)
                self.main_splitter.setContentsMargins(0, 0, 0, 0)
                # Force the second widget (video) to take all space
                self.main_splitter.setSizes([0, self.width()])
            if hasattr(self, 'mainContentStack'):
                self.mainContentStack.setContentsMargins(0, 0, 0, 0)
                if self.mainContentStack.layout():
                    self.mainContentStack.layout().setContentsMargins(0, 0, 0, 0)
            if hasattr(self, 'video_container'):
                self.video_container.setContentsMargins(0, 0, 0, 0)
                if self.video_container.layout():
                    self.video_container.layout().setContentsMargins(0, 0, 0, 0)
            
            if hasattr(self, 'video_overlay_host') and self.video_overlay_host.layout():
                self.video_overlay_host.layout().setContentsMargins(0, 0, 0, 0)
            
            # Hide all toolbars explicitly
            for toolbar in self.findChildren(QToolBar):
                toolbar.hide()
        except Exception:
            pass

        # Normal slider gizli (tam ekranda kullanılmıyor)
        try:
            if hasattr(self, 'video_seek_row'):
                self.video_seek_row.setVisible(False)
            if hasattr(self, 'video_controls_row'):
                self.video_controls_row.setVisible(False)
            if hasattr(self, 'video_seek_slider'):
                self.video_seek_slider.setVisible(False)
            
            if hasattr(self, 'video_output_widget'):
                self.video_output_widget._update_video_transform()

            # Tam ekranda overlay ikonlarını kullanma (tek bar prensibi)
            if hasattr(self, 'video_fs_button') and self.video_fs_button:
                self.video_fs_button.setVisible(False)
            try:
                if hasattr(self, 'video_settings_button') and self.video_settings_button:
                    self.video_settings_button.setVisible(False)
            except Exception:
                pass

            if hasattr(self, '_video_fps_timer'):
                self._video_fps_frames = 0
                self._video_fps_timer.start()
            
            if hasattr(self, 'video_output_widget'):
                self.video_output_widget.installEventFilter(self)
                self.video_output_widget.setMouseTracking(True)
                if self.video_output_widget.viewport():
                     self.video_output_widget.viewport().installEventFilter(self)
                     self.video_output_widget.viewport().setMouseTracking(True)
            
            self.video_output_widget.setFocus(Qt.OtherFocusReason)
            self._update_video_fullscreen_icons()
            
            # Tam ekran ek kontrollerini göster
            self._show_video_fs_controls()
        except Exception:
            pass

        try:
            self.showFullScreen()
            # Ensure video output widget fills the entire screen by updating layout
            if hasattr(self, 'video_output_widget'):
                self.video_output_widget.updateGeometry()
                if hasattr(self.video_output_widget, '_update_video_transform'):
                    self.video_output_widget._update_video_transform()
            
            # Force layout and paint update
            if self.centralWidget() and self.centralWidget().layout():
                self.centralWidget().layout().activate()
            self.update()
            
            # Start with cursor visible
            self.setCursor(Qt.ArrowCursor)
            
            # Tam ekran kontrollerini yeniden konumlandır (showFullScreen sonrası)
            QTimer.singleShot(100, self._reposition_fs_controls)
        except Exception:
            self.showMaximized()
    
    def _reposition_fs_controls(self):
        """Tam ekran kontrollerini yeniden konumlandır."""
        if not getattr(self, '_in_video_fullscreen', False):
            return
        if hasattr(self, '_video_fs_controls') and self._video_fs_controls:
            self._video_fs_controls.setFixedWidth(self.width())
            y_pos = self.height() - self._video_fs_controls.height()
            self._video_fs_controls.move(0, y_pos)
            self._video_fs_controls.raise_()

        try:
            self._reposition_video_settings_ui()
        except Exception:
            pass

    def _exit_video_fullscreen(self):
        if not getattr(self, '_in_video_fullscreen', False):
            return
        self._in_video_fullscreen = False
        
        # Tam ekran ek kontrollerini gizle
        self._hide_video_fs_controls()

        # Video ayarlar panelini kapat
        try:
            self._hide_video_settings_panel(animate=False)
        except Exception:
            pass
        
        # Bar animasyon durumunu sıfırla
        self._fs_bars_visible = True
        self._fs_bar_animating = False
        
        # Ana barı geri göster
        if hasattr(self, 'bottom_widget'):
            if hasattr(self, '_bottom_widget_original_visible'):
                self.bottom_widget.setVisible(self._bottom_widget_original_visible)
            else:
                self.bottom_widget.show()
            if hasattr(self, '_bottom_widget_original_style'):
                self.bottom_widget.setStyleSheet(self._bottom_widget_original_style)
        
        # Cursor'ı normal yap
        self.setCursor(Qt.ArrowCursor)
        if hasattr(self, 'video_output_widget') and self.video_output_widget:
            self.video_output_widget.setCursor(Qt.ArrowCursor)
            if self.video_output_widget.viewport():
                self.video_output_widget.viewport().setCursor(Qt.ArrowCursor)

        state = getattr(self, '_video_fullscreen_state', {})
        
        # ÖNCE pencereyi normal moda al
        try:
            if state.get('was_maximized'):
                self.showMaximized()
            else:
                self.showNormal()
                geom = state.get('geometry')
                if geom and not geom.isEmpty():
                    self.setGeometry(geom)
        except Exception:
            self.showNormal()

        # UI RESTORE - Tüm elemanları geri getir
        try:
            # Show top bars
            if self.menuBar(): 
                self.menuBar().setVisible(True)
            if hasattr(self, 'fileLabel'): 
                self.fileLabel.setVisible(True)
            if self.statusBar(): 
                self.statusBar().show()
            
            # Show all toolbars
            for toolbar in self.findChildren(QToolBar):
                 toolbar.setVisible(True)
            
            # KRITIK: Sol panel ve splitter'ı düzgün geri yükle
            if hasattr(self, 'side_panel'):
                self.side_panel.setVisible(True)
                self.side_panel.show()
            
            # bottom_widget orijinal stile geri dön
            if hasattr(self, 'bottom_widget'):
                if hasattr(self, '_bottom_widget_original_style'):
                    self.bottom_widget.setStyleSheet(self._bottom_widget_original_style)
                else:
                    # Varsayılan stil
                    self.bottom_widget.setStyleSheet("""
                        QWidget#bottomWidget {
                            background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                stop:0 rgba(42, 42, 42, 240),
                                stop:1 rgba(20, 20, 20, 250));
                            border-top: 1px solid rgba(80, 80, 80, 120);
                            border-radius: 0px;
                        }
                    """)
            
            if hasattr(self, 'main_splitter'):
                self.main_splitter.setHandleWidth(4)
                # Splitter boyutlarını geri yükle
                sizes = state.get('split_sizes', [250, 950])
                if not sizes or len(sizes) < 2:
                    sizes = [250, 950]
                # Sol panel en az 200px olsun
                if sizes[0] < 200:
                    sizes[0] = 250
                self.main_splitter.setSizes(sizes)
            
            # Video sekmesinde kal
            if hasattr(self, 'mainContentStack'):
                self.mainContentStack.setCurrentIndex(1)
            
            # Sidebar'da Video Arşivi seçili olsun
            if hasattr(self, 'sidebarNav'):
                self.sidebarNav.setCurrentRow(2)
            
            # Fullscreen butonu görünür olsun
            if hasattr(self, 'video_fs_button'):
                self.video_fs_button.setVisible(True)

            # Video ayarlar butonu görünür olsun
            try:
                if hasattr(self, 'video_settings_button') and self.video_settings_button:
                    self.video_settings_button.setVisible(True)
            except Exception:
                pass

        except Exception:
            pass
            
        # Cleanup timers and event filters
        try:
            if hasattr(self, '_video_fps_timer'):
                self._video_fps_timer.stop()
            if hasattr(self, 'video_output_widget'):
                self.video_output_widget.removeEventFilter(self)
            
            self._update_video_fullscreen_icons()
        except Exception:
            pass

        # Force UI refresh
        try:
            self.activateWindow()
            QApplication.processEvents()
            if self.centralWidget():
                self.centralWidget().updateGeometry()
                self.centralWidget().update()
            if hasattr(self, 'main_splitter'):
                self.main_splitter.update()
        except Exception:
            pass

        try:
            self._reposition_video_settings_ui()
        except Exception:
            pass
            
    def _set_video_position(self, position):
        """Slider hareket edince videoyu o konuma al"""
        if hasattr(self, 'videoPlayer'):
            self.videoPlayer.setPosition(position)

    def _on_video_metadata_changed(self):
        """Video metallerine göre otomatik yön düzeltme."""
        if not hasattr(self, 'videoPlayer') or not self.videoPlayer.isMetaDataAvailable():
            return

        # Olası metadata key'leri (Qt sürümüne göre değişebilir)
        rotation = 0
        try:
            # Yaygın anahtarlar: "Orientation", "Rotate", "Angle"
            # Değerleri integer olarak almayı dene
            orientation_keys = ["Orientation", "Rotate", "Rotation", "Angle"]
            for key in orientation_keys:
                val = self.videoPlayer.metaData(key)
                if val is not None:
                    try:
                        rotation = int(val)
                        if rotation != 0:
                            break
                    except:
                        pass
        except Exception:
            pass
            
        # Eğer metadata'da varsa otomatik uygula
        if rotation != 0:
            # FIX: Bazı Android cihazlarda/PyQt sürümlerinde 90/270 ters algılanabiliyor.
            # Kullanıcı raporuna göre: Metadata 270 iken video ters (upside down) görünüyor.
            # Bu durumda 180 derece fark var demektir. 270 -> 90'a ve 90 -> 270'e çeviriyoruz.
            if rotation == 270:
                print(f"🎬 Correction: 270° detected -> Applying 90° to fix inversion.")
                rotation = 90
            elif rotation == 90:
                print(f"🎬 Correction: 90° detected -> Applying 270° to fix inversion.")
                rotation = 270
                
            print(f"🎬 Video Metadata Rotation Found: {rotation}° (Applied) -> Auto-fix.")
            self.video_output_widget.rotate_video(rotation, absolute=True)
            self.statusBar().showMessage(f"Video Otomatik Düzeltildi ({rotation}°)", 3000)

    def _auto_resize_window_to_video(self):
        """Video metadatasındaki çözünürlüğe göre pencere boyutunu ayarla."""
        # Sadece normal modda ve video yüklenince çalışsın
        if self.isFullScreen() or self.isMaximized() or getattr(self, '_in_miniplayer_mode', False):
            return

        # Kullanıcı ayarı kontrol edilebilir (Şimdilik varsayılan aktif)
        try:
            resolution = self.videoPlayer.metaData("Resolution")
            if not resolution or not isinstance(resolution, QSize):
                return
                
            vid_w = resolution.width()
            vid_h = resolution.height()
            
            if vid_w <= 0 or vid_h <= 0:
                return

            # Ekran boyutunu al
            screen = QApplication.primaryScreen().availableGeometry()
            screen_w = screen.width()
            screen_h = screen.height()
            
            # Hedef boyut (Video + UI payı)
            # UI genişliği: SidePanel (250)
            # UI yüksekliği: TitleBar + BottomBar (~120)
            
            target_w = vid_w + 250
            target_h = vid_h + 120
            
            # Ekrana sığmıyorsa orantılı küçült
            ratio = vid_w / vid_h
            
            if target_w > screen_w * 0.9:
                target_w = int(screen_w * 0.9)
                new_vid_w = target_w - 250
                target_h = int(new_vid_w / ratio) + 120
                
            if target_h > screen_h * 0.9:
                target_h = int(screen_h * 0.9)
                new_vid_h = target_h - 120
                target_w = int(new_vid_h * ratio) + 250
                
            # Minimum boyutları koru
            target_w = max(target_w, 800)
            target_h = max(target_h, 600)
            
            self.resize(target_w, target_h)
            # Ortala
            rect = self.frameGeometry()
            rect.moveCenter(screen.center())
            self.move(rect.topLeft())
        except Exception as e:
            print(f"Auto-resize error: {e}")


    # ==========================================================
    #  SOL PANEL (Kütüphane – Listeler – Dosyalar)
    # ==========================================================
    def _create_side_panel(self):
        """
        🎨 ANGOLLA SIDEBAR (Icon Menu + Content)
        ┌───┬──────────────┐
        │🏠 │ Kütüphane    │
        │📁 │ Dosyalar     │
        │📋 │ Playlistler  │
        │🌐 │ Internet     │
        │💿 │ Cihazlar     │
        │ℹ️ │ Şarkı Bilgi │
        │🎤 │ Sanatçı     │
        └───┴──────────────┘
        """
        
        # ═══════════════════════════════════════════════════════════
        # 1. SOL MENU (Icon Sidebar)
        # ═══════════════════════════════════════════════════════════
        self.sidebarNav = QListWidget()
        self.sidebarNav.setFixedWidth(70)
        self.sidebarNav.setIconSize(QSize(32, 32))
        
        menu_items = [
            (os.path.join("icons", "nav_library.svg"), self._tr("library"), 0),
            (os.path.join("icons", "nav_files.svg"), self._tr("files"), 1),
            (os.path.join("icons", "nav_video.svg"), "Video", 2),
            (os.path.join("icons", "nav_playlists.svg"), self._tr("playlists"), 3),
            (os.path.join("icons", "nav_internet.svg"), self._tr("internet"), 4),
            (os.path.join("icons", "nav_devices.svg"), self._tr("devices"), 5),
            (os.path.join("icons", "nav_info.svg"), self._tr("song_info"), 6),
            (os.path.join("icons", "nav_artist.svg"), self._tr("artist_info"), 7)
        ]
        
        for icon_path, label, page_index in menu_items:
            item = QListWidgetItem()
            item.setIcon(QIcon(icon_path))
            item.setTextAlignment(Qt.AlignCenter)
            item.setToolTip(label)
            item.setData(Qt.UserRole, label)
            item.setData(Qt.UserRole + 2, page_index)
            item.setData(Qt.UserRole + 1, icon_path)
            item.setText("")
            self.sidebarNav.addItem(item)
        
        self.sidebarNav.setStyleSheet("""
            QListWidget {
                background-color: #37474F;
                border: none;
                outline: none;
                font-size: 24px;
            }
            QListWidget::item {
                padding: 6px;
                margin: 1px;
                border-radius: 6px;
            }
            QListWidget::item:hover {
                background-color: #455A64;
            }
            QListWidget::item:selected {
                background-color: #40C4FF;
                color: #000;
            }
        """)
        
        self.sidebarNav.setCurrentRow(1)  # "Dosyalar" seçili başlat
        self.sidebarNav.currentRowChanged.connect(self._on_sidebar_changed)
        self.sidebarNav.itemPressed.connect(self._on_sidebar_pressed)
        
        # ═══════════════════════════════════════════════════════════
        # 2. SAĞ CONTENT (Stacked Widget - Her Menü İçin)
        # ═══════════════════════════════════════════════════════════
        self.sidebarStack = QStackedWidget()
        
        # --- SAYFA 0: Kütüphane ---
        library_page = QWidget()
        library_layout = QVBoxLayout(library_page)
        library_layout.setContentsMargins(0, 0, 0, 0)
        library_header = QLabel("📚 Kütüphane")
        library_header.setStyleSheet("font-weight: bold; padding: 8px; background-color: #333;")
        library_layout.addWidget(library_header)
        library_layout.addWidget(self.libraryTableWidget)
        
        # --- SAYFA 1: Dosyalar ---
        file_label = QLabel("📁 Dosyalar")
        file_label.setStyleSheet("font-weight: bold; padding: 8px; background-color: #333;")
        
        self.file_model = QFileSystemModel()
        self.file_model.setRootPath(QDir.homePath())
        # Dosya ağacında tüm medya tiplerini göster; dizinler her zaman görünsün
        self.file_model.setFilter(QDir.AllDirs | QDir.NoDotAndDotDot | QDir.Files)
        self.file_model.setNameFilters([
            "*.mp3", "*.flac", "*.ogg", "*.m4a", "*.m4b", "*.wav", "*.aac", "*.wma", "*.opus",
            "*.mp4", "*.mkv", "*.webm", "*.avi", "*.mov", "*.m3u", "*.pls"
        ])
        # Dizinlerin kaybolmaması için filtreyi sadece dosyalara uygula
        self.file_model.setNameFilterDisables(True)
        
        self.file_tree = QTreeView()
        self.file_tree.setModel(self.file_model)
        self.file_tree.hideColumn(1)
        self.file_tree.hideColumn(2)
        self.file_tree.hideColumn(3)
        self.file_tree.setHeaderHidden(True)
        
        # Yerel Müzik klasörü (Music / Müzik) varsa onu kök yap
        home_path = os.path.expanduser("~")
        candidate_paths = [
            os.path.join(home_path, "Music"),
            os.path.join(home_path, "Müzik"),
            QDir.homePath(),
        ]
        for p in candidate_paths:
            if os.path.exists(p):
                self.file_tree.setRootIndex(self.file_model.index(p))
                break
        
        self.file_tree.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.file_tree.setDragEnabled(True)
        self.file_tree.setDragDropMode(QAbstractItemView.DragOnly)
        self.file_tree.doubleClicked.connect(self.file_tree_double_clicked)
        self.file_tree.activated.connect(self.file_tree_double_clicked)  # Enter tuşu ile aç
        self.file_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.file_tree.customContextMenuRequested.connect(self.show_file_context_menu)
        self.file_tree.installEventFilter(self)
        
        self.file_tree.setStyleSheet("""
            QTreeView {
                border: none;
                background-color: #1e1e1e;
                color: #e0e0e0;
            }
            QTreeView::item:hover { background-color: #2a4a6a; }
            QTreeView::item:selected { background-color: #40C4FF; color: #000; }
        """)
        
        files_page = QWidget()
        files_layout = QVBoxLayout(files_page)
        files_layout.setContentsMargins(0, 0, 0, 0)
        files_layout.addWidget(file_label)
        files_layout.addWidget(self.file_tree)
        
        video_sidebar_placeholder = QWidget()

        # --- SAYFA 3: EQ (REMOVED) ---
        # Dummy EQ sayfası kaldırıldı; sidebar sırası gerçek sayfalarla birebir.
        
        # --- SAYFA 4-8: Diğerleri ---
        # Playlistler sayfası
        playlists_page = QWidget()
        playlists_layout = QVBoxLayout(playlists_page)
        playlists_layout.setContentsMargins(8, 8, 8, 8)
        header_pl = QLabel(f"📋 {self._tr('playlists')}")
        header_pl.setStyleSheet("font-weight: bold; padding: 8px; background-color: #333;")
        playlists_layout.addWidget(header_pl)
        btn_save = QPushButton(self._tr("save_playlist"))
        btn_load = QPushButton(self._tr("load_playlist"))
        btn_refresh = QPushButton(self._tr("refresh_playlist"))
        for b in (btn_save, btn_load, btn_refresh):
            b.setStyleSheet("padding:6px; background:#2f3b46; border:1px solid #555; border-radius:4px;")
            b.setCursor(Qt.PointingHandCursor)
        btn_save.clicked.connect(self.save_playlist)
        btn_load.clicked.connect(self.load_playlist)
        btn_refresh.clicked.connect(self.load_playlist)
        playlists_layout.addWidget(btn_save)
        playlists_layout.addWidget(btn_load)
        playlists_layout.addWidget(btn_refresh)
        playlists_layout.addStretch(1)

        # ---------------------------------------------------------------------------
        # VIDEO PAGE (Smart Sidebar + Tree + Dynamic Seek)
        # ---------------------------------------------------------------------------
        
        # 1. Custom File System Model (Sadece Videolar)
        # Standart QFileSystemModel setNameFilters bazen dizinleri de gizleyebiliyor veya hantal kalabiliyor.
        # Basitce QFileSystemModel kullanalim ve nameFilterDisables(False) yapalim.
        self.video_model = QFileSystemModel()
        # Video Klasörü: sistemin varsayılan Videos/Videolar dizini (yoksa oluştur)
        vid_path = self._get_default_video_folder()
        try:
            os.makedirs(vid_path, exist_ok=True)
        except Exception:
            pass
        self.video_model.setRootPath(vid_path)
        self.video_model.setFilter(QDir.AllDirs | QDir.NoDotAndDotDot | QDir.Files)
        # Kesin filtre: klasörler + yalnızca video uzantılı dosyalar
        self.video_proxy = self._VideoOnlyProxyModel(self._supported_video_exts(), self)
        self.video_proxy.setSourceModel(self.video_model)
        
        # 2. Tree View
        self.video_tree_widget = QTreeView()
        self.video_tree_widget.setModel(self.video_proxy)
        self.video_tree_widget.setFixedWidth(250) # Layout Lock
        self.video_tree_widget.setHeaderHidden(True)
        # Sadece Isim kolonu kalsin
        for col in range(1, 4):
            self.video_tree_widget.hideColumn(col)
        
        # Root Path ~/Videos (Varsa) yoksa Home
        self.video_tree_widget.setRootIndex(self.video_proxy.mapFromSource(self.video_model.index(vid_path)))
            
        self.video_tree_widget.setStyleSheet("""
            QTreeView {
                background-color: #1e1e1e;
                color: #e0e0e0;
                border: none;
            }
            QTreeView::item {
                padding: 4px;
            }
            QTreeView::item:hover { background-color: #2a4a6a; }
            QTreeView::item:selected { background-color: #40C4FF; color: #000; }
        """)
        self.video_tree_widget.doubleClicked.connect(self._on_video_tree_double_click)

        video_page = QWidget()
        video_layout = QVBoxLayout(video_page)
        video_layout.setContentsMargins(0,0,0,0)
        
        video_header = QLabel(f"🎬 Video Arşivi ({os.path.basename(vid_path) or vid_path})")
        video_header.setStyleSheet("font-weight: bold; padding: 8px; background-color: #333;")
        video_layout.addWidget(video_header)
        video_layout.addWidget(self.video_tree_widget)



        internet_page = QWidget()
        internet_layout = QVBoxLayout(internet_page)
        internet_layout.setContentsMargins(8, 8, 8, 8)
        header_web = QLabel(f"🌐 {self._tr('internet_header')}")
        header_web.setStyleSheet("font-weight: bold; padding: 8px; background-color: #333;")
        internet_layout.addWidget(header_web)
        web_buttons = [
            ("YouTube Music", "https://music.youtube.com/", "youtube_music", "youtube_music.svg"),
            ("YouTube", "https://www.youtube.com/", "youtube", "youtube.svg"),
            ("Spotify", "https://open.spotify.com/", "spotify", "spotify.svg"),
            ("Deezer", "https://www.deezer.com/", "deezer", "deezer.svg"),
            ("SoundCloud", "https://soundcloud.com/", "soundcloud", "soundcloud.svg"),
            ("Mixcloud", "https://www.mixcloud.com/", "mixcloud", "mixcloud.svg"),
        ]
        for text, url, provider, icon_file in web_buttons:
            btn = QPushButton(text)
            icon_path = os.path.join("icons", icon_file)
            if os.path.exists(icon_path):
                btn.setIcon(QIcon(icon_path))
                btn.setIconSize(QSize(24, 24))
            
            btn.setStyleSheet("padding:6px; background:#2f3b46; border:1px solid #555; border-radius:4px; text-align:left; font-size:14px; padding-left:10px;")
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(lambda checked=False, u=url, p=provider: self._open_embedded_web(u, p))
            internet_layout.addWidget(btn)
        internet_layout.addStretch(1)

        # Cihazlar sayfası
        devices_page = QWidget()
        devices_layout = QVBoxLayout(devices_page)
        devices_layout.setContentsMargins(8, 8, 8, 8)
        header_dev = QLabel(f"💿 {self._tr('devices')}")
        header_dev.setStyleSheet("font-weight: bold; padding: 8px; background-color: #333;")
        devices_layout.addWidget(header_dev)
        devices_layout.addWidget(QLabel("Yerel aygıtlar ve çıkışlar listelenecek.\n(Şimdilik yalnızca varsayılan ses çıkışı kullanılıyor.)"))
        devices_layout.addStretch(1)

        # Şarkı Bilgisi sayfası
        songinfo_page = QWidget()
        songinfo_layout = QVBoxLayout(songinfo_page)
        songinfo_layout.setContentsMargins(8, 8, 8, 8)
        header_song = QLabel(f"ℹ️ {self._tr('song_info')}")
        header_song.setStyleSheet("font-weight: bold; padding: 8px; background-color: #333;")
        songinfo_layout.addWidget(header_song)
        self.song_info_title = QLabel(f"{self._tr('song_info')}: -")
        self.song_info_artist = QLabel(f"{self._tr('artist_info')}: -")
        self.song_info_album = QLabel("Albüm: -")
        self.song_info_duration = QLabel("Süre: -")
        self.song_info_path = QLabel("Konum: -")
        for lbl in [self.song_info_title, self.song_info_artist, self.song_info_album, self.song_info_duration, self.song_info_path]:
            lbl.setStyleSheet("padding:4px;")
            songinfo_layout.addWidget(lbl)
        songinfo_layout.addStretch(1)

        # Sanatçı Bilgisi sayfası
        artist_page = QWidget()
        artist_layout = QVBoxLayout(artist_page)
        artist_layout.setContentsMargins(8, 8, 8, 8)
        header_artist = QLabel(f"🎤 {self._tr('artist_info')}")
        header_artist.setStyleSheet("font-weight: bold; padding: 8px; background-color: #333;")
        artist_layout.addWidget(header_artist)
        self.artist_info_label = QLabel(f"{self._tr('artist_info')}: -")
        self.artist_tracks_label = QLabel("Son çalınanlar: -")
        for lbl in [self.artist_info_label, self.artist_tracks_label]:
            lbl.setStyleSheet("padding:4px;")
            artist_layout.addWidget(lbl)
        artist_layout.addStretch(1)
        
        # Stack'e sayfaları ekle
        self.sidebarStack.addWidget(library_page)
        self.sidebarStack.addWidget(files_page)
        self.sidebarStack.addWidget(video_page)        # Index 2: Video Listesi (Artik Burada)
        self.sidebarStack.addWidget(playlists_page)
        self.sidebarStack.addWidget(internet_page)
        self.sidebarStack.addWidget(devices_page)
        self.sidebarStack.addWidget(songinfo_page)
        self.sidebarStack.addWidget(artist_page)
        
        self.sidebarStack.setCurrentIndex(1)  # Dosyalar
        
        # ═══════════════════════════════════════════════════════════
        # 3. ALBÜM KAPAĞI (Alt Bölüm)
        # ═══════════════════════════════════════════════════════════
        # albumArtLabel zaten _create_controls() içinde oluşturuldu
        self.albumArtLabel.setStyleSheet("background: transparent; border: none;")
        
        album_container = QWidget()
        # Video modunda tamamen gizlemek için referans sakla
        self.album_container = album_container
        album_container.setObjectName("albumContainer")
        # Çerçeve ve arka planı temizle (Saf Resim Modu)
        album_container.setStyleSheet("background: transparent; border: none;")
        album_container.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        
        album_layout = QVBoxLayout(album_container)
        album_layout.setContentsMargins(0, 0, 0, 0)
        album_layout.setSpacing(0)
        
        self.albumArtHolder = AlbumArtHolder(self.albumArtLabel)
        self.albumArtHolder.setStyleSheet("background: transparent; border: none;")
        self.albumArtLabel.setParent(self.albumArtHolder)
        album_layout.addWidget(self.albumArtHolder)
        
        # ═══════════════════════════════════════════════════════════
        # 4. RIGHT SIDE LAYOUT (Stack + Albüm) - Splitter Kaldırıldı
        # ═══════════════════════════════════════════════════════════
        right_side_widget = QWidget()
        right_side_layout = QVBoxLayout(right_side_widget)
        right_side_layout.setContentsMargins(0, 0, 0, 0)
        right_side_layout.setSpacing(0)
        right_side_layout.addWidget(self.sidebarStack, stretch=1)
        right_side_layout.addWidget(album_container, stretch=0)
        
        # ═══════════════════════════════════════════════════════════
        # 5. FULL SIDEBAR (Nav + Content)
        # ═══════════════════════════════════════════════════════════
        sidebar_container = QWidget()
        sidebar_layout = QHBoxLayout(sidebar_container)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        sidebar_layout.setSpacing(0)
        sidebar_layout.addWidget(self.sidebarNav)
        sidebar_layout.addWidget(right_side_widget)
        
        sidebar_container.setMinimumWidth(280)
        sidebar_container.setMaximumWidth(350)
        
        self.side_panel = sidebar_container
    
    def _on_sidebar_changed(self, index):
        """Sidebar menü seçimi değiştiğinde stack sayfasını güncelle"""
        item = self.sidebarNav.item(index) if index >= 0 else None
        page_index = index
        if item is not None:
            page_data = item.data(Qt.UserRole + 2)
            if isinstance(page_data, int):
                page_index = page_data

        # 1. Tam Sekme İzolasyonu (Resource Management)
        # Internet dışı bir sekmeye geçiliyorsa web'i tamamen kapat
        # (Cihazlar/Şarkı Bilgisi/Sanatçı Bilgisi sekmeleri web kapatmasın)
        web_visible = False
        if getattr(self, "webView", None) and self.webView.isVisible():
            web_visible = True
        elif getattr(self, "web_view", None) and self.web_view.isVisible():
            web_visible = True
        if page_index not in (4, 5, 6, 7) and (self.search_mode == "web" or web_visible):
            self._close_embedded_web()

        # Web/Internet sekmesine geçince yerel sesi durdur ve web monitörünü başlat
        if page_index == 4:
            if hasattr(self, 'mediaPlayer'):
                self.mediaPlayer.stop()
            self.search_mode = "web"
            self._web_mode_activated_ts = time.time()
            self._web_pcm_seen = False
            self._start_monitor_capture()

        # Video moduna geçiliyorsa Müzik çaları durdur
        if page_index == 2: # Video
            if hasattr(self, 'mediaPlayer'):
                self.mediaPlayer.stop()
        # Müzik moduna (veya diğerlerine) geçiliyorsa Video çaları durdur
        else:
            if hasattr(self, 'videoPlayer'):
                self.videoPlayer.stop()

        self.sidebarStack.setCurrentIndex(page_index)

        if page_index == 2:  # Video Modu
            self.mainContentStack.setCurrentIndex(1)
            self.statusBar().showMessage("Akıllı Video Modu: Arşiv görüntüleniyor...", 3000)
        else:
            self.mainContentStack.setCurrentIndex(0)

    def _on_sidebar_pressed(self, item):
        """Aynı sekmeye tekrar tıklanınca web görünümünü kapat."""
        if item is None:
            return
        index = self.sidebarNav.row(item)
        if index < 0:
            return
        web_visible = False
        if getattr(self, "webView", None) and self.webView.isVisible():
            web_visible = True
        elif getattr(self, "web_view", None) and self.web_view.isVisible():
            web_visible = True
        if index not in (4, 5, 6, 7) and (self.search_mode == "web" or web_visible):
            self._close_embedded_web()
        if index == self.sidebarNav.currentRow() and self.search_mode == "web" and index == 4:
            self._close_embedded_web()
            self._on_sidebar_changed(index)

    def _remove_web_close_button(self, toolbar):
        """Toolbar'daki web kapat butonunu kaldır."""
        if not toolbar:
            return
        for action in list(toolbar.actions()):
            text = action.text().lower().strip()
            tip = action.toolTip().lower().strip() if action.toolTip() else ""
            if ("web" in text and "kapat" in text) or ("web" in tip and "kapat" in tip):
                toolbar.removeAction(action)
        for btn in toolbar.findChildren(QToolButton):
            text = btn.text().lower().strip()
            tip = btn.toolTip().lower().strip() if btn.toolTip() else ""
            if ("web" in text and "kapat" in text) or ("web" in tip and "kapat" in tip):
                btn.setVisible(False)


    # ==========================================================
    #  ANA İÇERİK (playlist + info panel + alt kontroller)
    # ==========================================================
    def _on_video_audio_probed(self, buffer):
        """Video ses verisini (QAudioBuffer) işleyip visualizer'a gönder."""
        try:
            byte_count = buffer.byteCount()
            if byte_count == 0:
                return
            
            # QAudioBuffer -> Raw Bytes
            # PyQt5'te buffer.data() sip.voidptr döner, asstring() ile bytes alınır.
            raw_data = buffer.data().asstring(byte_count)
            
            fmt = buffer.format()
            sample_size = fmt.sampleSize()
            channels = fmt.channelCount()
            sample_rate = fmt.sampleRate()
            
            # Worker thread'e sinyal ile gönder
            self.video_audio_ready.emit(raw_data, sample_size, channels, sample_rate)
        except Exception:
            pass

    def _create_main_content(self):
        """
        🎨 ANGOLLA LAYOUT + TOOLBAR
        ┌────────────────────────────────────────┐
        │ 🔙🔜📁🔄 [Toolbar] [Search Bar]      │
        ├──────────┬─────────────────────────────┤
        │ Sidebar  │ Playlist Table              │
        │ (Menü)   │ Track│Title│Artist│Album   │
        ├──────────┴─────────────────────────────┤
        │ ▶️⏸️⏭️🔀🔁 [Controls] [Vol]          │
        └────────────────────────────────────────┘
        """
        
        # ═══════════════════════════════════════════════════════════
        # 1. TOOLBAR (Angolla Tarzı)
        # ═══════════════════════════════════════════════════════════
        toolbar = QToolBar("Main Toolbar")
        toolbar.setMovable(False)
        toolbar.setFloatable(False)
        toolbar.setAllowedAreas(Qt.TopToolBarArea)
        toolbar.setMovable(False)
        toolbar.setIconSize(QSize(24, 24))
        self.toolbar = toolbar
        
        # Modern ikonlu butonlar
        def _mk_tool_button(icon, tooltip, callback):
            btn = QToolButton()
            btn.setIcon(icon)
            btn.setIconSize(QSize(20, 20))
            btn.setToolTip(tooltip)
            btn.setAutoRaise(True)
            btn.clicked.connect(callback)
            btn.setStyleSheet("""
                QToolButton {
                    background-color: #2f3b46;
                    border: 1px solid #555;
                    border-radius: 6px;
                    padding: 6px;
                }
                QToolButton:pressed { background-color: #456071; }
            """)
            return btn

        # Web Gezinme Butonları
        self.webBackBtn = QToolButton()
        self.webBackBtn.setIcon(self.style().standardIcon(QStyle.SP_ArrowBack))
        self.webBackBtn.clicked.connect(self._web_back)

        self.webForwardBtn = QToolButton()
        self.webForwardBtn.setIcon(self.style().standardIcon(QStyle.SP_ArrowForward))
        self.webForwardBtn.clicked.connect(self._web_forward)
        
        self.webHomeBtn = QToolButton()
        self.webHomeBtn.setIcon(self.style().standardIcon(QStyle.SP_DirHomeIcon))
        self.webHomeBtn.clicked.connect(self._web_home)
        
        
        # Web Adres Çubuğu
        self.webUrlBar = QLineEdit()
        self.webUrlBar.setPlaceholderText("URL veya Arama...")
        self.webUrlBar.returnPressed.connect(self._web_load_url)
        self.webUrlBar.setFixedWidth(200)

        # Web Kontrolleri Listesi (Toplu gizle/göster için)
        self.web_controls = [
            self.webBackBtn, self.webForwardBtn, self.webHomeBtn, 
            self.webUrlBar
        ]
        
        # Başlangıçta gizle
        for w in self.web_controls:
            w.setVisible(False)

        style = self.style()
        backBtn = _mk_tool_button(style.standardIcon(QStyle.SP_ArrowBack), self._tr("back"), self._nav_back)
        forwardBtn = _mk_tool_button(style.standardIcon(QStyle.SP_ArrowForward), self._tr("forward"), self._nav_forward)
        refreshBtn = _mk_tool_button(style.standardIcon(QStyle.SP_BrowserReload), self._tr("refresh_library"), self.scan_library)
        backBtn.setCursor(Qt.PointingHandCursor)
        forwardBtn.setCursor(Qt.PointingHandCursor)
        refreshBtn.setCursor(Qt.PointingHandCursor)
        for b in (backBtn, forwardBtn, refreshBtn):
            b.setCursor(Qt.PointingHandCursor)
        

        
        toolbar.addWidget(backBtn)
        toolbar.addWidget(forwardBtn)
        toolbar.addSeparator()
        toolbar.addWidget(refreshBtn)
        toolbar.addSeparator()
        
        # Web kontrollerini ekle (başlangıçta gizli)
        for w in self.web_controls:
            toolbar.addWidget(w)
            
        toolbar.addSeparator()

        
        toolbar.setStyleSheet("""
            QToolBar {
                background-color: #263238;
                border-bottom: 1px solid #444;
                spacing: 4px;
                padding: 4px;
            }
            QPushButton {
                background-color: #37474F;
                border: none;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #455A64;
            }
            QPushButton:pressed {
                background-color: #40C4FF;
            }
        """)
        
        self.addToolBar(toolbar)
        
        # ═══ WEB BUTONLARI - TOOLBAR'DA SAĞ TARAFA EKLE ═══
        # Action'ları şimdi oluştur
        self._setup_web_control_buttons()
        
        # Spacer ekle (butonları sağa itmek için)
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        toolbar.addWidget(spacer)
        
        # Web control actions directly to toolbar (if they exist)
        if hasattr(self, 'webDownloadAction'):
            toolbar.addAction(self.webDownloadAction)
        self._remove_web_close_button(toolbar)
        
        
        # ═══════════════════════════════════════════════════════════
        # 2. NOW PLAYING LABEL
        # ═══════════════════════════════════════════════════════════
        self.fileLabel.setStyleSheet("""
            QLabel {
                background-color: #1e1e1e;
                color: #40C4FF;
                padding: 6px 12px;
                font-weight: bold;
                border-bottom: 1px solid #444;
            }
        """)
        
        # ═══════════════════════════════════════════════════════════
        # 2. ORTA BÖLÜM: SOL PANEL + PLAYLIST (SPLITTER)
        # ═══════════════════════════════════════════════════════════
        # Playlist / WebView arasında geçiş için stack
        self.mainContentStack = QStackedWidget()
        
        # PAGE 0: Playlist & Web (Mevcut yapı)
        self.playlist_container_widget = QWidget()
        pc_layout = QVBoxLayout(self.playlist_container_widget)
        pc_layout.setContentsMargins(0,0,0,0)
        
        self.playlist_stack = QStackedWidget() # Icerde Web ve Playlist degisimi icin
        self.playlist_stack.addWidget(self.playlistWidget)
        
        # Web View'i da buraya tasiyacagiz ama self.webView henuz olusmadiysa sonra eklenir
        # Mevcut kod self.mainContentStack'e ekliyordu. Biz simdi self.playlist_stack'e ekleyelim
        # self.webView referansini guncelleyelim
        
        pc_layout.addWidget(self.playlist_stack)
        
        self.mainContentStack.addWidget(self.playlist_container_widget) # Index 0

        
        # PAGE 1: Video Player (Flip Fixed + Visualizer)
        self.video_output_widget = VideoDisplayWidget()
        self.video_output_widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        # Video hedef FPS / kalite ayarları (decode'u kilitleyemez; viewport refresh ile pratik sınırlama)
        self._video_target_fps = 0  # 0 = Auto
        self._video_quality_mode = "KALİTE"  # KALİTE | PERFORMANS
        self._video_refresh_timer = QTimer(self)
        try:
            self._video_refresh_timer.setTimerType(Qt.PreciseTimer)
        except Exception:
            pass
        self._video_refresh_timer.timeout.connect(self._video_force_refresh)
        try:
            self._set_video_quality_mode(self._video_quality_mode)
        except Exception:
            pass

        # Dynamic Gradient Slider for Video (normal mod)
        self.video_seek_slider = GradientSlider(Qt.Horizontal)
        self.video_seek_slider.setRange(0, 0)
        self.video_seek_slider.sliderMoved.connect(self._set_video_position)
        # GradientSlider zaten fixedHeight=20 olarak ayarlı

        # Normal mod zaman göstergeleri
        self.video_time_current = QLabel("00:00")
        self.video_time_total = QLabel("00:00")
        for _lbl in (self.video_time_current, self.video_time_total):
            _lbl.setStyleSheet("color: #e0e0e0; padding: 0 8px; font-size: 13px; font-weight: bold;")

        # Video overlay host (video + HUD)
        self.video_overlay_host = QWidget()
        self.video_overlay_host.setStyleSheet("background: black;")
        vgrid = QGridLayout(self.video_overlay_host)
        vgrid.setContentsMargins(0, 0, 0, 0)
        vgrid.setSpacing(0)
        vgrid.addWidget(self.video_output_widget, 0, 0)
        vgrid.setRowStretch(0, 1)
        vgrid.setColumnStretch(0, 1)

        # Video hata/uyarı overlay (oynatılamazsa kullanıcıya kısa mesaj + fallback)
        self.video_error_overlay = QWidget(self.video_overlay_host)
        self.video_error_overlay.setVisible(False)
        self.video_error_overlay.setObjectName("videoErrorOverlay")
        self.video_error_overlay.setStyleSheet(
            "#videoErrorOverlay { background: rgba(0,0,0,160); border: 1px solid rgba(255,255,255,60); border-radius: 10px; }"
        )
        eo_layout = QVBoxLayout(self.video_error_overlay)
        eo_layout.setContentsMargins(14, 12, 14, 12)
        eo_layout.setSpacing(10)
        self.video_error_label = QLabel("")
        self.video_error_label.setWordWrap(True)
        self.video_error_label.setAlignment(Qt.AlignCenter)
        self.video_error_open_btn = QToolButton()
        self.video_error_open_btn.setText("Tarayıcıda Aç")
        self.video_error_open_btn.setAutoRaise(True)
        self.video_error_open_btn.clicked.connect(self._video_open_in_browser)
        eo_layout.addWidget(self.video_error_label)
        eo_layout.addWidget(self.video_error_open_btn, alignment=Qt.AlignCenter)
        vgrid.addWidget(self.video_error_overlay, 0, 0, alignment=Qt.AlignCenter)

        # Normal mod: Tam ekran butonu (video sekmesiyle izole) - Modern tasarım
        self.video_fs_button = QToolButton(self.video_overlay_host)
        self.video_fs_button.setIcon(self.style().standardIcon(QStyle.SP_TitleBarMaxButton))
        self.video_fs_button.setAutoRaise(True)
        self.video_fs_button.setToolTip("Tam Ekran (F11)")
        self.video_fs_button.clicked.connect(self._toggle_video_fullscreen)
        self.video_fs_button.setFixedSize(40, 40)
        self.video_fs_button.setIconSize(QSize(22, 22))
        self.video_fs_button.setStyleSheet("""
            QToolButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 rgba(50, 50, 50, 200),
                    stop:1 rgba(30, 30, 30, 230));
                border: 1px solid rgba(85, 85, 85, 150);
                border-radius: 10px;
                padding: 4px;
            }
            QToolButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 rgba(64, 196, 255, 200),
                    stop:1 rgba(40, 160, 220, 230));
                border: 2px solid rgba(100, 220, 255, 255);
            }
            QToolButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 rgba(40, 160, 220, 240),
                    stop:1 rgba(20, 120, 180, 255));
                border: 2px solid rgba(64, 196, 255, 255);
            }
        """)
        # Sağ alt köşeye yerleştir (AlignBottom | AlignRight)
        vgrid.addWidget(self.video_fs_button, 0, 0, alignment=Qt.AlignBottom | Qt.AlignRight)

        # Video (sadece) YouTube tarzı ayarlar paneli (overlay)
        try:
            self._create_video_settings_ui()
        except Exception:
            pass

        # Video ekranı için parlaklık/ses overlay'leri (tam ekran modunda kullanılır)
        self._video_brightness = 1.0  # 0.0-2.0 arası (0=karanlık, 1=normal, 2=parlak)
        self._brightness_overlay = None
        self._volume_indicator = None
        self._brightness_indicator = None

        # Video Container (host + normal seek)
        self.video_container = QWidget()
        v_layout = QVBoxLayout(self.video_container)
        v_layout.setContentsMargins(0, 0, 0, 0)
        v_layout.setSpacing(0)
        v_layout.addWidget(self.video_overlay_host)

        # Normal mod: zaman + scrubber (tek satır) - REMOVED: Main bar used instead
        # self.video_seek_row = QWidget()
        # seek_row_layout = QHBoxLayout(self.video_seek_row)
        # seek_row_layout.setContentsMargins(10, 6, 10, 6)
        # seek_row_layout.setSpacing(8)
        # seek_row_layout.addWidget(self.video_time_current)
        # seek_row_layout.addWidget(self.video_seek_slider, 1)
        # seek_row_layout.addWidget(self.video_time_total)
        # v_layout.addWidget(self.video_seek_row)

        # Normal mod: YouTube tarzı kontrol satırı (izole) - REMOVED: Main bar used instead
        # self.video_controls_row = QWidget()
        # ctrl_layout = QHBoxLayout(self.video_controls_row)
        # ctrl_layout.setContentsMargins(10, 6, 10, 10)
        # ctrl_layout.setSpacing(10)

        # Video kontrolleri: Ana bar (bottom_widget) video için de kullanılır
        # Sadece video_fs_button overlay olarak tutulur (tam ekran geçişi için)
        
        # Ayrı bir player instance kullan (ses çakışmasını yönetmek için)
        self.videoPlayer = QMediaPlayer(None, QMediaPlayer.VideoSurface)
        self.videoPlayer.setVideoOutput(self.video_output_widget.video_item)
        self._video_last_source_url = None
        self._video_last_source_text = ""
        self.videoPlayer.positionChanged.connect(self._on_video_position_changed)
        self.videoPlayer.durationChanged.connect(self._on_video_duration_changed)
        try:
            self.videoPlayer.stateChanged.connect(self._on_video_state_changed)
        except Exception:
            pass

        # Video hata yakalama (Qt sürümüne göre farklı isimler)
        try:
            self.videoPlayer.errorOccurred.connect(self._on_video_error)
        except Exception:
            try:
                self.videoPlayer.error.connect(self._on_video_error)
            except Exception:
                pass

        # Video kontrolleri tamamen videoPlayer ile izole senkron kalsın
        try:
            self.videoPlayer.volumeChanged.connect(self._on_video_volume_changed)
        except Exception:
            pass
        try:
            self.videoPlayer.mutedChanged.connect(self._on_video_muted_changed)
        except Exception:
            pass
        try:
            self.videoPlayer.mediaStatusChanged.connect(self._on_video_media_status_changed)
        except Exception:
            pass

        # Başlangıç ses seviyesi
        try:
            self.videoPlayer.setMuted(False)
            self.videoPlayer.setVolume(70)  # Varsayılan %70
        except Exception:
            pass

        # Video UI: tema uyumlu stil uygula (sadece video sekmesi)
        try:
            self._apply_video_ui_theme()
            self._update_video_fullscreen_icons()
        except Exception:
            pass
        # AUTO ROTATION: Metadata değişince yönü kontrol et
        self.videoPlayer.metaDataChanged.connect(self._on_video_metadata_changed)
        # AUTO RESIZE: Metadata değişince pencere boyutunu videoya göre ayarla
        self.videoPlayer.metaDataChanged.connect(self._auto_resize_window_to_video)
        
        # VISUALIZER ENTEGRASYONU (Video Sesi -> Barlar)
        self.videoProbe = QAudioProbe(self)
        self.videoProbe.setSource(self.videoPlayer)
        # Video ses verisini görselleştiriciye yönlendir
        self.videoProbe.audioBufferProbed.connect(self._on_video_audio_probed)

        self.mainContentStack.addWidget(self.video_container) # Page 1

        # FPS ölçümü
        self._video_fps_frames = 0
        self._video_fps_timer = QTimer(self)
        self._video_fps_timer.setInterval(1000)
        self._video_fps_timer.timeout.connect(self._update_video_fps)
        try:
            self.video_output_widget.frameRendered.connect(self._on_video_frame_rendered)
        except Exception:
            pass

        # Video aura hızı (slider animasyonu için)
        self._video_aura_speed = 0.08

        # Video slider'larını mevcut tema rengine yaklaştır
        try:
            primary, _, _ = self._get_current_theme_colors()
            if hasattr(self, 'video_seek_slider') and hasattr(self.video_seek_slider, 'set_aura_base_color'):
                self.video_seek_slider.set_aura_base_color(primary)
            self._set_video_aura_speed(self._video_aura_speed)
        except Exception:
            pass

        # Video fullscreen state
        self._in_video_fullscreen = False
        self._video_fullscreen_state = {}

        self.main_splitter = QSplitter(Qt.Horizontal)
        self.main_splitter.addWidget(self.side_panel)
        self.main_splitter.addWidget(self.mainContentStack)
        self.main_splitter.setSizes([250, 950])  # Sol dar, sağ geniş
        self.main_splitter.setCollapsible(0, False)
        self.main_splitter.setCollapsible(1, False)

        # Sekmeler tamamen bağımsız: stack değişince diğer medya kaynaklarını durdur
        self._exclusive_mode_guard = False
        self._music_resume_pending = False
        try:
            self.mainContentStack.currentChanged.connect(self._on_exclusive_tab_changed)
        except Exception:
            pass
        try:
            if hasattr(self, 'playlist_stack') and self.playlist_stack:
                self.playlist_stack.currentChanged.connect(self._on_exclusive_tab_changed)
        except Exception:
            pass
        
        # ═══════════════════════════════════════════════════════════
        # 3. ALT BÖLÜM: KONTROLLER + GÖRSELLEŞTİRME
        # ═══════════════════════════════════════════════════════════
        
        # --- SEEK BAR (Zaman + Slider) ---
        seekLayout = QHBoxLayout()
        seekLayout.addWidget(self.lblCurrentTime)
        seekLayout.addWidget(self.positionSlider)
        seekLayout.addWidget(self.lblTotalTime)
        seekLayout.setContentsMargins(20, 2, 20, 0) # Reduced margins for thinner bar
        seekLayout.setSpacing(8)
        
        ctrlLayout = QHBoxLayout()
        ctrlLayout.setSpacing(12)
        ctrlLayout.addWidget(self.shuffleButton)
        ctrlLayout.addWidget(self.prevButton)
        ctrlLayout.addWidget(self.playButton)
        ctrlLayout.addWidget(self.nextButton)
        ctrlLayout.addWidget(self.repeatButton)
        
        # Volume Area: [EQ] [VolLabel] [Slider]
        volLayout = QHBoxLayout()
        volLayout.setSpacing(8)
        volLayout.addWidget(self.eqButton) # ADDED HERE
        volLayout.addWidget(self.volumeLabel)
        volLayout.addWidget(self.volumeSlider)
        
        # Ana Alt Layout
        # [CLEANUP] Redundant layouts removed to fix parenting issues
        # seekLayout and controlBar will be added to bottomContainer directly below.

        
        # --- CONTROL BAR (Tek satır: Spacer - Buttons - Spacer - Volume) ---
        controlBar = QHBoxLayout()
        
        # Butonları tam ortalamak için sol boşluğu biraz daha geniş tutuyoruz
        # Çünkü sağdaki ses paneli yer kaplıyor. 
        # Böylece (Sol Boşluk) > (Sağ Boşluk) yaparak butonları sağa itiyoruz.
        controlBar.addStretch(2)  # Sol boşluk (2 kat)
        
        # Volume controls
        # EQ Button (Ses Efektleri) - Already added, ensure tooltip
        self.eqButton.setToolTip("Ses Efektleri (DSP)")
        
        controlBar.addWidget(self.shuffleButton)
        # controlBar.addWidget(self.seekBackwardButton)  # REMOVED: Moved to Video HUD
        controlBar.addWidget(self.prevButton)
        controlBar.addWidget(self.playButton)
        controlBar.addWidget(self.nextButton)
        # controlBar.addWidget(self.seekForwardButton)  # REMOVED: Moved to Video HUD
        controlBar.addWidget(self.repeatButton)
        
        controlBar.addStretch(1)  # Sağ boşluk (1 kat)
        
        # Playback Rate Controls (Video Hızlandırma) - REMOVED: Moved to Video HUD
        # controlBar.addWidget(QLabel("⏩ Hız:"))
        # controlBar.addWidget(self.playbackRateDecreaseBtn)
        # controlBar.addWidget(self.playbackRateLabel)
        # controlBar.addWidget(self.playbackRateIncreaseBtn)
        # controlBar.addWidget(self.playbackRateNormalBtn)
        # controlBar.addSpacing(15)
        
        # Volume controls (aynı satırın sağ ucunda)
        controlBar.addWidget(self.eqButton) # EQ Button (Ses Efektleri) - FIXED VISIBILITY
        controlBar.addWidget(QLabel(f"🔊 {self._tr('volume')}:"))
        controlBar.addWidget(self.volumeSlider)
        controlBar.addWidget(self.volumeLabel)
        
        controlBar.setSpacing(10)
        controlBar.setContentsMargins(0, 0, 0, 4) # Reduced bottom margin
        
        # --- BOTTOM CONTAINER (Kontroller + Görselleştirme) ---
        bottomContainer = QVBoxLayout()
        bottomContainer.setSpacing(0)
        bottomContainer.setContentsMargins(0, 0, 0, 0)
        bottomContainer.addLayout(seekLayout)
        bottomContainer.addLayout(controlBar)
        # Spektrum alanı: Müzik ve Video için ayrı widget (video sekmesi ana spectrum'u etkilemesin)
        self.bottom_vis_stack = QStackedWidget()
        self.bottom_vis_stack.addWidget(self.vis_widget_main_window)
        self.bottom_vis_stack.addWidget(self.vis_widget_video_window)
        self.bottom_vis_stack.setCurrentIndex(0)
        bottomContainer.addWidget(self.bottom_vis_stack)
        
        # Bottom widget wrapper
        bottomWidget = QWidget()
        bottomWidget.setObjectName("bottomWidget")
        bottomWidget.setLayout(bottomContainer)
        # Modern gradient ve transparan arka plan (tema değişiminde güncellenecek)
        bottomWidget.setStyleSheet("""
            QWidget#bottomWidget {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 rgba(42, 42, 42, 240),
                    stop:1 rgba(20, 20, 20, 250));
                border-top: 1px solid rgba(80, 80, 80, 120);
                border-radius: 0px;
            }
        """)
        self.bottom_widget = bottomWidget
        
        # ═══════════════════════════════════════════════════════════
        # 4. ANA DÜZENİ BİRLEŞTİR (Vertical: Üst + Orta + Alt)
        # ═══════════════════════════════════════════════════════════
        mainLayout = QVBoxLayout()
        # Ana pencerenin, alt widget'ların minimum/sizeHint değerlerine göre
        # otomatik yeniden boyutlanmasını tamamen kapat.
        try:
            from PyQt5.QtWidgets import QLayout
            mainLayout.setSizeConstraint(QLayout.SetNoConstraint)
        except Exception:
            pass
        mainLayout.setSpacing(0)
        mainLayout.setContentsMargins(0, 0, 0, 0)
        mainLayout.addWidget(self.fileLabel)
        mainLayout.addWidget(self.main_splitter, stretch=1)  # Genişleyebilir
        mainLayout.addWidget(bottomWidget)  # Sabit yükseklik
        
        # ═══════════════════════════════════════════════════════════
        # 5. CENTRAL WIDGET AYARLA
        # ═══════════════════════════════════════════════════════════
        centralWidget = QWidget()
        centralWidget.setObjectName("mainCentral")
        centralWidget.setLayout(mainLayout)
        # Kullanıcı kontrolünü korumak için makul bir minimum ver, otomatik büyütme yok
        try:
            centralWidget.setMinimumSize(400, 300)
            self.setMinimumSize(500, 350)
        except Exception:
            pass
        self.setCentralWidget(centralWidget)
        
        # ═══════════════════════════════════════════════════════════
        # 6. STATUS BAR
        # ═══════════════════════════════════════════════════════════
        self.setStatusBar(QStatusBar())

    # ==========================================================
    #  MENÜ ÇUBUĞU
    # ==========================================================

    def _create_menu_bar(self):
        menuBar = self.menuBar()

        fileMenu = menuBar.addMenu(self._tr("menu_file"))
        addFilesAction = QAction(self._tr("menu_add_files"), self)
        addFilesAction.triggered.connect(self.menu_add_files)
        fileMenu.addAction(addFilesAction)

        addFolderAction = QAction(self._tr("menu_add_folder"), self)
        addFolderAction.triggered.connect(self.menu_add_folder)
        fileMenu.addAction(addFolderAction)

        fileMenu.addSeparator()
        exitAction = QAction(self._tr("menu_exit"), self)
        exitAction.triggered.connect(self.close)
        fileMenu.addAction(exitAction)


        viewMenu = menuBar.addMenu(self._tr("menu_view"))

        toggleVisAction = QAction(self._tr("menu_open_visual"), self)
        toggleVisAction.triggered.connect(self.toggle_visualization_window)
        viewMenu.addAction(toggleVisAction)

        themeMenu = viewMenu.addMenu(self._tr("menu_theme"))
        for name in self.themes.keys():
            a = QAction(name, self)
            a.triggered.connect(
                lambda checked=False, n=name: self.set_theme(n)
            )
            themeMenu.addAction(a)

        toolsMenu = menuBar.addMenu(self._tr("menu_tools"))
        scanLibAction = QAction(self._tr("menu_scan_library"), self)
        scanLibAction.triggered.connect(self.scan_library)
        toolsMenu.addAction(scanLibAction)

        prefsAction = QAction(self._tr("menu_prefs"), self)
        prefsAction.triggered.connect(self.show_preferences)
        toolsMenu.addAction(prefsAction)

        helpMenu = menuBar.addMenu(self._tr("menu_help"))
        aboutAction = QAction(self._tr("menu_about"), self)
        aboutAction.triggered.connect(self.show_about)
        helpMenu.addAction(aboutAction)

        # MenuBar Hover Efektleri
        menubar_stylesheet = """
        QMenuBar {
            background-color: #1a1a1a;
            color: #e0e0e0;
            border-bottom: 1px solid #444;
            padding: 4px;
        }
        QMenuBar::item:hover {
            background-color: #40C4FF;
            color: #000;
            border-radius: 2px;
        }
        QMenuBar::item:selected {
            background-color: #5EA4D1;
            color: #fff;
        }
        QMenu {
            background-color: #1a1a1a;
            color: #e0e0e0;
            border: 1px solid #444;
            border-radius: 4px;
            padding: 4px;
        }
        QMenu::item:hover {
            background-color: #40C4FF;
            color: #000;
            padding-left: 20px;
            padding-right: 10px;
        }
        QMenu::item:selected {
            background-color: #40C4FF;
            color: #000;
        }
        """
        menuBar.setStyleSheet(menubar_stylesheet)

    # ==========================================================
    #  SİNYAL / KISA YOL BAĞLANTILARI
    # ==========================================================
    def _connect_signals(self):
        self.playButton.clicked.connect(self.play_pause)
        self.nextButton.clicked.connect(self._next_track)
        
        # F2 Shortcut (Miniplayer)
        self.shortcut_miniplayer = QShortcut(QKeySequence("F2"), self)
        self.shortcut_miniplayer.activated.connect(self._toggle_miniplayer_mode)
        self.prevButton.clicked.connect(self._prev_track)
        
        # Hızlı ileri/geri butonları (10 saniye)
        self.seekBackwardButton.clicked.connect(lambda: self._nudge_position(-10000))
        self.seekForwardButton.clicked.connect(lambda: self._nudge_position(10000))

        self.shuffleButton.clicked.connect(self.toggle_shuffle)
        self.repeatButton.clicked.connect(self.toggle_repeat)

        self.playlistWidget.doubleClicked.connect(self.playlist_double_clicked)
        self.file_tree.doubleClicked.connect(self.file_tree_double_clicked)
        self.playlistWidget.customContextMenuRequested.connect(
            self.show_playlist_context_menu
        )
        self.libraryTableWidget.doubleClicked.connect(self.library_double_clicked)
        self.libraryTableWidget.customContextMenuRequested.connect(
            self.show_library_context_menu
        )

        self.volumeSlider.valueChanged.connect(self._on_master_volume_changed)
        self.volumeSlider.valueChanged.connect(self._update_volume_label)
        self.volumeSlider.valueChanged.connect(self.save_config)
        self.volumeSlider.valueChanged.connect(self._apply_web_volume)

        self.positionSlider.sliderMoved.connect(self._set_position_safely_moved)
        self.positionSlider.sliderReleased.connect(self._set_position_safely)

        # Audio Engine Signals
        self.audio_engine.media_player.positionChanged.connect(self._on_audio_position_changed)
        self.audio_engine.media_player.durationChanged.connect(self._on_audio_duration_changed)
        self.playlist.currentIndexChanged.connect(self.playlist_position_changed)
        self.audio_engine.media_player.stateChanged.connect(self._update_status_bar)
        self.audio_engine.media_player.mediaStatusChanged.connect(self._media_status_changed)
        
        # 🌈 Progress bar sürekli rainbow animasyonu için timer
        self.progress_bar_timer = QTimer(self)
        self.progress_bar_timer.timeout.connect(self._update_progress_bar_style)
        self.progress_bar_timer.start(16)  # ~60 FPS akıcı renk değişimi

        # ===== KLAVYE KIŞAYOLLARI =====
        # Kısayol referanslarını sakla ve konfigürasyondan uygulanabilir hale getir
        self._shortcuts = {}
        default_shortcuts = {
            "play_pause": "Space",
            "next_track": "Ctrl+Right",
            "prev_track": "Ctrl+Left",
            "open_files": "Ctrl+O",
            "open_folder": "Ctrl+F",
            "open_visual": "Ctrl+V",
            "open_prefs": "Ctrl+,",
            "show_about": "Ctrl+H",
            "seek_backward": "F3",
            "seek_forward": "F4",
            "prev_track_fast": "F1",
            "next_track_fast": "F2",
            "play_selected": "Return",
            "toggle_shuffle": "Ctrl+Shift+S",
            "toggle_repeat": "Ctrl+Shift+R",
            "volume_up": "Up",
            "volume_down": "Down",
            "mute": "M",
        }
        # Oluşturma
        self._shortcuts["play_pause"] = QShortcut(QKeySequence(default_shortcuts["play_pause"]), self, activated=self.play_pause)
        self._shortcuts["next_track"] = QShortcut(QKeySequence(default_shortcuts["next_track"]), self, activated=self._next_track)
        self._shortcuts["prev_track"] = QShortcut(QKeySequence(default_shortcuts["prev_track"]), self, activated=self._prev_track)
        self._shortcuts["open_files"] = QShortcut(QKeySequence(default_shortcuts["open_files"]), self, activated=self.menu_add_files)
        self._shortcuts["open_folder"] = QShortcut(QKeySequence(default_shortcuts["open_folder"]), self, activated=self.menu_add_folder)
        self._shortcuts["open_visual"] = QShortcut(QKeySequence(default_shortcuts["open_visual"]), self, activated=self.toggle_visualization_window)
        self._shortcuts["open_prefs"] = QShortcut(QKeySequence(default_shortcuts["open_prefs"]), self, activated=self.show_preferences)
        self._shortcuts["show_about"] = QShortcut(QKeySequence(default_shortcuts["show_about"]), self, activated=self.show_about)
        self._shortcuts["prev_track_fast"] = QShortcut(QKeySequence(default_shortcuts["prev_track_fast"]), self, activated=self._prev_track)
        self._shortcuts["next_track_fast"] = QShortcut(QKeySequence(default_shortcuts["next_track_fast"]), self, activated=self._next_track)
        self._shortcuts["seek_backward"] = QShortcut(QKeySequence(default_shortcuts["seek_backward"]), self, activated=lambda: self._nudge_position(-5000))
        self._shortcuts["seek_forward"] = QShortcut(QKeySequence(default_shortcuts["seek_forward"]), self, activated=lambda: self._nudge_position(5000))
        self._shortcuts["play_selected"] = QShortcut(QKeySequence(default_shortcuts["play_selected"]), self, activated=self._play_selected_shortcut)
        self._shortcuts["toggle_shuffle"] = QShortcut(QKeySequence(default_shortcuts["toggle_shuffle"]), self, activated=self.toggle_shuffle)
        self._shortcuts["toggle_repeat"] = QShortcut(QKeySequence(default_shortcuts["toggle_repeat"]), self, activated=self.toggle_repeat)
        self.shortcutVolumeUp = QShortcut(QKeySequence(default_shortcuts["volume_up"]), self, activated=lambda: self._volume_shortcut(5))
        self.shortcutVolumeDown = QShortcut(QKeySequence(default_shortcuts["volume_down"]), self, activated=lambda: self._volume_shortcut(-5))
        self.shortcutVolumeUp.setContext(Qt.ApplicationShortcut)
        self.shortcutVolumeDown.setContext(Qt.ApplicationShortcut)
        self._shortcuts["volume_up"] = self.shortcutVolumeUp
        self._shortcuts["volume_down"] = self.shortcutVolumeDown
        self._shortcuts["mute"] = QShortcut(QKeySequence(default_shortcuts["mute"]), self, activated=self._toggle_mute)
        # Konfigürasyondan varsa uygula
        self._default_shortcuts = default_shortcuts
        self._apply_shortcuts_from_config()
        
        # Seçim Kısayolları (Widget-specific - Context-aware)
        self.playlistWidget.installEventFilter(self._create_select_all_filter(self.playlistWidget))
        self.libraryTableWidget.installEventFilter(self._create_select_all_filter(self.libraryTableWidget))
        self.file_tree.installEventFilter(self._create_select_all_filter(self.file_tree))
        
        # Silme Kısayolları (Widget-specific)
        self.playlistWidget.installEventFilter(self._create_delete_filter(self._delete_from_playlist))
        self.libraryTableWidget.installEventFilter(self._create_delete_filter(self._delete_from_library))


        # Web Polling Timer (İlerleme çubuğu için)
        self.webPosTimer = QTimer(self)
        self.webPosTimer.setInterval(1000)  # Her 1 saniyede bir kontrol et
        self.webPosTimer.timeout.connect(self._poll_web_status)

    def _apply_shortcuts_from_config(self):
        """JSON config içindeki kısayol tanımlarını uygular."""
        try:
            sc_map = self.config_data.get("shortcuts", {})
            if not isinstance(sc_map, dict):
                sc_map = {}
            for name, shortcut in self._shortcuts.items():
                seq_str = sc_map.get(name, self._default_shortcuts.get(name))
                if isinstance(seq_str, str) and seq_str.strip():
                    try:
                        shortcut.setKey(QKeySequence(seq_str))
                    except Exception:
                        pass
        except Exception:
            pass

    # ------------------------------------------------------------------#
    # OYNATMA
    # ------------------------------------------------------------------#

    def play_pause(self):
        # 1. Video Modu Kontrolü
        if self.mainContentStack.currentIndex() == 1: # Video Page
            if hasattr(self, 'videoPlayer'):
                if self.videoPlayer.state() == QMediaPlayer.PlayingState:
                    self.videoPlayer.pause()
                    self.playButton.setIcon(QIcon(os.path.join("icons", "media-playback-start.png")))
                else:
                    self.videoPlayer.play()
                    self.playButton.setIcon(QIcon(os.path.join("icons", "media-playback-pause.png")))
            return

        # 2. Web Modu
        if self.search_mode == "web" and self.webView:
            self._web_play_pause()  # JS üzerinden video.play/pause tetikle
            if not self.webPosTimer.isActive():
                self.webPosTimer.start()
            return

        # 3. Isolated Audio Engine
        if not self.audio_engine: return

        state = self.audio_engine.media_player.state()
        if state == QMediaPlayer.PlayingState:
            self.audio_engine.media_player.pause()
            self.playButton.setIcon(QIcon(os.path.join("icons", "media-playback-start.png")))
        else:
            if self.playlist.currentIndex() < 0 and self.playlist.mediaCount() > 0:
                self.playlist.setCurrentIndex(0)

            # Use play_file signal for clean start or just play() if already loaded
            if self.audio_engine.media_player.mediaStatus() == QMediaPlayer.NoMedia:
                self.playlist_position_changed(self.playlist.currentIndex()) # Trigger load
            else:
                self.audio_engine.media_player.play()

            self.playButton.setIcon(QIcon(os.path.join("icons", "media-playback-pause.png")))

    def _next_track(self, _reason: str = None):
        if self.mainContentStack.currentIndex() == 1:  # Video Mode
            try:
                self._video_next_in_folder()
            except Exception:
                pass
            return

        if self.search_mode == "web" and self.webView:
            self._web_next()
            return
            
        if self.playlist.mediaCount() == 0:
            return
        current = self.playlist.currentIndex()
        if current < 0:
            current = 0
        next_index = (current + 1) % self.playlist.mediaCount()
        self._set_next_track_change_reason(_reason or "manual_next")
        self._play_index(next_index)

    def _prev_track(self, _reason: str = None):
        if self.mainContentStack.currentIndex() == 1:  # Video Mode
            try:
                self._video_prev_in_folder()
            except Exception:
                pass
            return

        

        if self.search_mode == "web" and self.webView:
            self._web_prev()
            return

        if self.playlist.mediaCount() == 0:
            return
        current = self.playlist.currentIndex()
        if current < 0:
            current = 0
        prev_index = (current - 1) % self.playlist.mediaCount()
        self._set_next_track_change_reason(_reason or "manual_prev")
        self._play_index(prev_index)

    def _set_next_track_change_reason(self, reason: str):
        try:
            self._track_change_reason = str(reason or "")
        except Exception:
            self._track_change_reason = None

    def _video_next_in_folder(self):
        """Video modunda: aynı klasörde sıradaki videoyu aç."""
        try:
            cur = str(getattr(self, '_video_current_path', '') or '')
        except Exception:
            cur = ''
        if not cur or not os.path.isfile(cur):
            try:
                self.statusBar().showMessage("Video: sıradaki bulunamadı.", 2500)
            except Exception:
                pass
            return

        # Playlist yoksa/yanlışsa yeniden kur
        try:
            paths = getattr(self, '_video_playlist_paths', None)
            folder = str(getattr(self, '_video_playlist_folder', '') or '')
            if not isinstance(paths, list) or not paths or os.path.dirname(cur) != folder:
                self._set_video_playlist_from_folder(cur)
        except Exception:
            try:
                self._set_video_playlist_from_folder(cur)
            except Exception:
                pass

        try:
            paths = getattr(self, '_video_playlist_paths', []) or []
            idx = int(getattr(self, '_video_playlist_index', -1))
        except Exception:
            paths, idx = [], -1

        # Index yoksa current'a göre bul
        if idx < 0 and cur and paths:
            try:
                idx = paths.index(cur)
            except Exception:
                idx = 0

        if idx >= 0 and (idx + 1) < len(paths):
            next_path = paths[idx + 1]
            self._video_playlist_index = idx + 1
            self._play_video_file(next_path, _build_playlist=False)
            return

        try:
            self.statusBar().showMessage("Video: liste bitti.", 2500)
        except Exception:
            pass

    def _video_prev_in_folder(self):
        """Video modunda: aynı klasörde önceki videoyu aç."""
        try:
            cur = str(getattr(self, '_video_current_path', '') or '')
        except Exception:
            cur = ''
        if not cur or not os.path.isfile(cur):
            try:
                self.statusBar().showMessage("Video: önceki bulunamadı.", 2500)
            except Exception:
                pass
            return

        # Playlist yoksa/yanlışsa yeniden kur
        try:
            paths = getattr(self, '_video_playlist_paths', None)
            folder = str(getattr(self, '_video_playlist_folder', '') or '')
            if not isinstance(paths, list) or not paths or os.path.dirname(cur) != folder:
                self._set_video_playlist_from_folder(cur)
        except Exception:
            try:
                self._set_video_playlist_from_folder(cur)
            except Exception:
                pass

        try:
            paths = getattr(self, '_video_playlist_paths', []) or []
            idx = int(getattr(self, '_video_playlist_index', -1))
        except Exception:
            paths, idx = [], -1

        # Index yoksa current'a göre bul
        if idx < 0 and cur and paths:
            try:
                idx = paths.index(cur)
            except Exception:
                idx = 0

        if idx > 0 and idx < len(paths):
            prev_path = paths[idx - 1]
            self._video_playlist_index = idx - 1
            self._play_video_file(prev_path, _build_playlist=False)
            return

        try:
            self.statusBar().showMessage("Video: listenin başı.", 2500)
        except Exception:
            pass

    def _should_crossfade_for_reason(self, reason: str) -> bool:
        ms = int(getattr(self, "_pb_crossfade_ms", 0) or 0)
        if ms <= 0:
            return False
        r = (reason or "").strip().lower()
        if r in ("manual_next", "manual_prev", "manual_select"):
            return bool(getattr(self, "_pb_manual_crossfade_enabled", False))
        if r == "auto_crossfade":
            return bool(getattr(self, "_pb_auto_crossfade_enabled", False))
        return False

    def toggle_shuffle(self):
        self.is_shuffling = self.shuffleButton.isChecked()
        self._apply_shuffle_button_state(self.is_shuffling)
        self.save_config()

    def toggle_repeat(self):
        self.is_repeating = self.repeatButton.isChecked()
        self._apply_repeat_button_state(self.is_repeating)
        self.save_config()
        self.config_data["repeat_mode"] = self.is_repeating

    def _update_volume_label(self, value):
        self.volumeLabel.setText(f"{value}%")

    def _adjust_volume(self, delta):
        """Ses seviyesini ayarla (Up: +5%, Down: -5%)."""
        new_volume = max(0, min(100, self.volumeSlider.value() + delta))
        self.volumeSlider.setValue(new_volume)
        self.statusBar().showMessage(f"🔊 Ses: {new_volume}%", 1000)

    def _toggle_mute(self):
        """Sesi aç/kapat (M tuşu)."""
        # Context Aware Mute
        if self.mainContentStack.currentIndex() == 1: # Video Tab
            if self.videoPlayer.isMuted():
                self.videoPlayer.setMuted(False)
                self.statusBar().showMessage("🔊 Ses Açık", 1000)
            else:
                self.videoPlayer.setMuted(True)
                self.statusBar().showMessage("🔇 Sessiz", 1000)
            return

        if self.mediaPlayer.volume() > 0:
            self._muted_volume = self.mediaPlayer.volume()
            self.mediaPlayer.setVolume(0)
            self.volumeSlider.blockSignals(True)
            self.volumeSlider.setValue(0)
            self.volumeSlider.blockSignals(False)
            self.statusBar().showMessage("🔇 Sessiz", 1000)
            self._apply_web_volume(0)
        else:
            volume = getattr(self, '_muted_volume', 50)
            self.mediaPlayer.setVolume(volume)
            self.volumeSlider.blockSignals(True)
            self.volumeSlider.setValue(volume)
            self.volumeSlider.blockSignals(False)
            self.statusBar().showMessage(f"🔊 Ses: {volume}%", 1000)
            self._apply_web_volume(volume)

    def _delete_from_playlist(self):
        """Çalma listesinden seçili öğeyi sil (Delete tuşu)."""
        current_row = self.playlistWidget.currentRow()
        if current_row >= 0:
            self.playlistWidget.takeItem(current_row)
            self.playlist.removeMedia(current_row)
            self.save_playlist()
            self.statusBar().showMessage(f"📍 Öğe silindi", 1500)

    def _delete_from_library(self):
        """Kütüphaneden seçili öğeyi sil (Delete tuşu)."""
        selected_rows = self.libraryTableWidget.selectionModel().selectedRows()
        if selected_rows:
            self.statusBar().showMessage(f"📍 {len(selected_rows)} öğe silindi", 1500)

    def _create_select_all_filter(self, widget):
        """Ctrl+A için event filter oluştur."""
        class SelectAllFilter(QObject):
            def eventFilter(self_inner, obj, event):
                if event.type() == QEvent.KeyPress:
                    if event.key() == Qt.Key_A and event.modifiers() & Qt.ControlModifier:
                        widget.selectAll()
                        return True
                return False
        return SelectAllFilter(self)

    def _create_delete_filter(self, callback):
        """Delete tuşu için event filter oluştur."""
        class DeleteFilter(QObject):
            def eventFilter(self_inner, obj, event):
                if event.type() == QEvent.KeyPress:
                    if event.key() == Qt.Key_Delete:
                        callback()
                        return True
                return False
        return DeleteFilter(self)

    # --------------------------------------------------------------
    # GENEL EVENT FILTER
    # --------------------------------------------------------------
    def eventFilter(self, obj, event):
        # Video ayarlar paneli: dışarı tıklanınca kapat ve resize'da hizala
        try:
            if hasattr(self, '_video_settings_panel') and self._video_settings_panel and self._video_settings_panel.isVisible():
                if event.type() == QEvent.MouseButtonPress:
                    gp = None
                    try:
                        gp = event.globalPos()
                    except Exception:
                        gp = None
                    if gp is not None:
                        in_panel = self._video_settings_panel.rect().contains(self._video_settings_panel.mapFromGlobal(gp))
                        in_btn = False
                        try:
                            if hasattr(self, 'video_settings_button') and self.video_settings_button:
                                in_btn = self.video_settings_button.rect().contains(self.video_settings_button.mapFromGlobal(gp))
                        except Exception:
                            in_btn = False
                        if not in_btn:
                            try:
                                if getattr(self, '_in_video_fullscreen', False) and hasattr(self, '_fs_settings_btn') and self._fs_settings_btn:
                                    in_btn = self._fs_settings_btn.rect().contains(self._fs_settings_btn.mapFromGlobal(gp))
                            except Exception:
                                pass
                        if (not in_panel) and (not in_btn):
                            self._hide_video_settings_panel(animate=True)
        except Exception:
            pass

        try:
            if obj == getattr(self, 'video_overlay_host', None) and event.type() in (QEvent.Resize, QEvent.Show):
                self._reposition_video_settings_ui()
        except Exception:
            pass

        # Video Fullscreen Wheel Event (Sol=ses, Sağ=parlaklık)
        is_video_fs = getattr(self, '_in_video_fullscreen', False)
        if is_video_fs and event.type() == QEvent.Wheel:
            video_widget = getattr(self, 'video_output_widget', None)
            is_on_video = (obj == video_widget)
            if video_widget and hasattr(video_widget, 'viewport'):
                is_on_video = is_on_video or (obj == video_widget.viewport())
            
            if is_on_video:
                delta = event.angleDelta().y()
                pos = event.pos()
                widget_width = video_widget.width()
                
                # Sol %30 = ses, Sağ %30 = parlaklık
                if pos.x() < widget_width * 0.30:
                    # SOL TARAF: Ses seviyesi
                    self._adjust_video_volume_with_indicator(delta)
                    event.accept()
                    return True
                elif pos.x() > widget_width * 0.70:
                    # SAĞ TARAF: Parlaklık
                    self._adjust_video_brightness_with_indicator(delta)
                    event.accept()
                    return True
        
        # Video Fullscreen Mouse Move
        if is_video_fs:
            # Check if event is from video_output_widget or its viewport
            is_video_obj = (obj == getattr(self, 'video_output_widget', None))
            if not is_video_obj and hasattr(self, 'video_output_widget') and self.video_output_widget:
                is_video_obj = (obj == self.video_output_widget.viewport())
            
            if is_video_obj and event.type() in (QEvent.MouseMove, QEvent.HoverMove):
                self._on_fullscreen_mouse_move()
        
        # Web Fullscreen Mouse Move
        if getattr(self, '_in_web_fullscreen', False):
            if event.type() == QEvent.MouseMove or event.type() == QEvent.HoverMove:
                 self._on_fullscreen_mouse_move()

        # Arama kutusu: Enter/Return bastığında aramayı tetikle
        if obj == getattr(self, "searchBar", None) and event.type() in (QEvent.FocusIn, QEvent.FocusOut):
            self._set_volume_shortcuts_enabled(event.type() != QEvent.FocusIn)

        # Dosya ağacı: Enter ile seçili dosyaları ekle/çal
        if obj == getattr(self, "file_tree", None) and event.type() == QEvent.KeyPress:
            if event.key() in (Qt.Key_Return, Qt.Key_Enter):
                indexes = self.file_tree.selectionModel().selectedIndexes()
                paths = []
                for idx in indexes:
                    if idx.column() != 0:
                        continue
                    p = self.file_model.filePath(idx)
                    if os.path.isdir(p) and len(indexes) == 1:
                        # Tek klasör seçiliyse içine gir
                        self.file_tree.setRootIndex(idx)
                        return True
                    elif os.path.isfile(p):
                        paths.append(p)
                if paths:
                    self._add_files_to_playlist(paths, add_to_library=False)
                    self.playlist.setCurrentIndex(self.playlist.mediaCount() - 1)
                    self.mediaPlayer.play()
                return True
        # WebView yeniden boyutlanınca overlay'i sağ üstte tut
        overlay_parent = self.mainContentStack if hasattr(self, "mainContentStack") else None
        if obj == getattr(self, "webView", None) and event.type() in (QEvent.Resize, QEvent.Show):
            self._position_web_overlay()
        if overlay_parent and obj == overlay_parent and event.type() in (QEvent.Resize, QEvent.Show):
            self._position_web_overlay()
        if obj == self and event.type() == QEvent.Resize:
            self._update_window_close_btn_pos()
        # Video fullscreen WM ile kapatılırsa (örn. pencere yöneticisi/F11), UI'yi geri topla
        if obj == self and event.type() == QEvent.WindowStateChange:
            try:
                if getattr(self, '_in_video_fullscreen', False) and not self.isFullScreen():
                    self._exit_video_fullscreen()
            except Exception:
                pass
            try:
                if getattr(self, '_in_web_fullscreen', False) and not self.isFullScreen():
                    self._exit_web_fullscreen_ui()
            except Exception:
                pass
        return super().eventFilter(obj, event)

    def _position_web_overlay(self):
        """Web kapatma ve indirme overlay butonlarını sağ üste hizala."""
        # Keep overlays aligned to the top window area (use the common updater)
        try:
            self._update_window_close_btn_pos()
        except Exception:
            pass

    def _update_window_close_btn_pos(self):
        """Web fullscreen çıkış butonunu (overlay) sağ üste hizala."""
        btn = getattr(self, "web_fs_exit_btn", None)
        wv = getattr(self, "webView", None)
        if not btn or not wv:
            return

        try:
            btn.setVisible(bool(getattr(self, "_in_web_fullscreen", False)))
        except Exception:
            pass

        try:
            if not btn.isVisible():
                return
        except Exception:
            return

        try:
            margin = 12
            x = max(margin, wv.width() - btn.sizeHint().width() - margin)
            y = margin
            btn.move(x, y)
            btn.raise_()
        except Exception:
            pass

    def _web_exit_fullscreen(self):
        """Web player tam ekrandan çık (site request üretmese de fail-safe)."""
        try:
            if getattr(self, "webView", None) and self.webView.page() and QWebEnginePage is not None:
                self.webView.page().triggerAction(QWebEnginePage.ExitFullScreen)
        except Exception:
            pass

        def _fallback_restore():
            try:
                if getattr(self, "_in_web_fullscreen", False):
                    self._exit_web_fullscreen_ui()
            except Exception:
                pass

        try:
            QTimer.singleShot(350, _fallback_restore)
        except Exception:
            pass

    def _on_download_clicked(self):
        """Web indirme butonuna tıklandığında format seçici göster."""
        if not getattr(self, 'webView', None):
            return
        try:
            url = self.webView.url().toString()
        except Exception:
            return
        if "youtube" not in url and "youtu.be" not in url:
            QMessageBox.warning(self, "Uyarı", "Şu an sadece YouTube desteklenmektedir.")
            return

        formats = []
        cmd_base = resolve_yt_dlp_command()
        if not cmd_base:
            QMessageBox.warning(
                self,
                "yt-dlp eksik",
                "İndirme için yt-dlp gereklidir. pyqt_venv içinde `python -m pip install yt-dlp` komutunu çalıştırıp yeniden deneyin."
            )
            return
        try:
            import subprocess
            p = subprocess.Popen(cmd_base + ["-F", url], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            out, err = p.communicate(timeout=12)
            for l in out.splitlines():
                l = l.strip()
                if not l:
                    continue
                parts = l.split()
                fid = parts[0]
                rest = ' '.join(parts[1:])
                formats.append((fid, rest))
        except Exception:
            formats = [('mp3', 'MP3 (audio)'), ('mp4', 'MP4 (video)')]

        dlg = QDialog(self)
        dlg.setWindowTitle('İndir - Format Seç')
        v = QVBoxLayout(dlg)
        lbl = QLabel('Format seçin (seçtiğiniz formatın yaklaşık boyutu gösterilir):')
        v.addWidget(lbl)
        combo = QComboBox(dlg)
        for fid, desc in formats:
            combo.addItem(f"{fid}  |  {desc}", fid)
        v.addWidget(combo)

        h = QHBoxLayout()
        btn_download = QPushButton('İndir')
        btn_cancel = QPushButton('İptal')
        h.addStretch(1)
        h.addWidget(btn_download)
        h.addWidget(btn_cancel)
        v.addLayout(h)

        def on_cancel():
            dlg.reject()

        def on_download():
            fid = combo.currentData()
            save_dir = QStandardPaths.writableLocation(QStandardPaths.MusicLocation)
            save_dir = QFileDialog.getExistingDirectory(self, "Kaydedilecek Klasör", save_dir)
            if not save_dir:
                return
            chosen_fmt = ('fmt:' + fid) if str(fid).isdigit() else fid
            self.dl_worker = DownloadWorker(url, chosen_fmt, save_dir)
            prog = DownloadProgressDialog(self.dl_worker, self)
            self.dl_worker.finished_sig.connect(self._on_download_finished)
            self.dl_worker.start()
            prog.exec_()
            dlg.accept()

        btn_cancel.clicked.connect(on_cancel)
        btn_download.clicked.connect(on_download)
        dlg.exec_()

    def _on_web_title_changed(self, title: str):
        if getattr(self, "search_mode", "") != "web":
            return
        current_url = self.webView.url() if self.webView else QUrl()
        self._update_web_nowplaying(title, current_url)

    def _on_web_url_changed(self, qurl: QUrl):
        if getattr(self, "search_mode", "") != "web":
            return
        title = self.webView.title() if self.webView else ""
        self._update_web_nowplaying(title, qurl)

        # Güvenlik Kilidi Göstergesi (URL Bar Görsel Geri Bildirim)
        if hasattr(self, 'webUrlBar'):
            if qurl.scheme() == "https":
                # Güvenli: Yeşil çerçeve
                self.webUrlBar.setStyleSheet("QLineEdit { border: 1px solid #00E676; color: #fff; background-color: #1a1a1a; padding: 4px; border-radius: 4px; }")
                self.webUrlBar.setToolTip("🔒 Güvenli Bağlantı (HTTPS) - Şifre girmek güvenli")
            else:
                # Güvensiz: Kırmızı çerçeve
                self.webUrlBar.setStyleSheet("QLineEdit { border: 1px solid #FF1744; color: #fff; background-color: #1a1a1a; padding: 4px; border-radius: 4px; }")
                self.webUrlBar.setToolTip("⚠ GÜVENLİ DEĞİL - Şifre girmeyin!")

    def _update_web_nowplaying(self, title: str, qurl: QUrl):
        """Web oynatıcıdayken kapak ve başlık/artist bilgisini göster."""
        if not qurl:
            return
        title = (title or "").strip() or qurl.toString()
        provider = self.search_provider or qurl.host()
        # Etiketleri güncelle
        self.fileLabel.setText(f"Şu An Çalınan: {title}")
        self.infoDisplayWidget.titleLabel.setText(f"Başlık: {title}")
        self.infoDisplayWidget.artistLabel.setText(f"Sanatçı: {provider}")
        self.infoDisplayWidget.albumLabel.setText("Albüm: -")

        # Youtube kapak resmi getir
        pixmap = None
        vid = self._extract_youtube_id(qurl)
        if vid:
            thumb_url = f"https://img.youtube.com/vi/{vid}/hqdefault.jpg"
            try:
                with urllib.request.urlopen(thumb_url, timeout=5) as resp:
                    data = resp.read()
                    pix = QPixmap()
                    if pix.loadFromData(QByteArray(data)):
                        pixmap = pix
            except Exception:
                pixmap = None

        if pixmap:
            self.update_cover_art(pixmap)
        else:
            # kapak bulunamazsa YouTube Music'te path'den tahmin et
            if qurl.host().endswith("music.youtube.com") or qurl.host().endswith("youtube.com"):
                thumb_guess = None
                # URL içinde "watch?v=" varsa o ID'yi al
                vid = self._extract_youtube_id(qurl)
                if vid:
                    thumb_guess = f"https://i.ytimg.com/vi/{vid}/hqdefault.jpg"
                if thumb_guess:
                    try:
                        with urllib.request.urlopen(thumb_guess, timeout=5) as resp:
                            data = resp.read()
                            pix2 = QPixmap()
                            if pix2.loadFromData(QByteArray(data)):
                                self.update_cover_art(pix2)
                                return
                    except Exception:
                        pass
            # kapak bulunamazsa temizle
            self.update_cover_art(None)

    def update_cover_art(self, pixmap):
        if pixmap is None:
            if hasattr(self.albumArtLabel, "set_cover_pixmap"):
                self.albumArtLabel.set_cover_pixmap(None)
            else:
                self.albumArtLabel.setText("")
                self.albumArtLabel.setPixmap(QPixmap())
            return
        if hasattr(self.albumArtLabel, "set_cover_pixmap"):
            self.albumArtLabel.set_cover_pixmap(pixmap)
        else:
            self.albumArtLabel.setPixmap(
                pixmap.scaled(200, 200, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            )

    def _apply_web_volume(self, volume: int):
        """Web player sesini (varsa) JS ile güncelle."""
        if getattr(self, "search_mode", "") != "web" or not self.webView:
            return
        
        # Eğer DSP aktifse, web elementinin sesini %100 (1.0) yap ki tam sinyal alalım.
        # Ses kontrolünü Python tarafındaki GlobalAudioEngine yapacak.
        if getattr(self, "_web_dsp_active", False):
             vol_to_set = 1.0
        else:
             vol_to_set = max(0, min(100, int(volume))) / 100.0

        js = f"""
        (() => {{
          if (window.__angollaSetWebVolume) {{
            window.__angollaSetWebVolume({vol_to_set});
            return;
          }}
          const setVol = (v) => {{
            const elts = Array.from(document.querySelectorAll('video,audio'));
            for (const el of elts) {{
              el.volume = v;
              el.muted = false; // Yakalama için her zaman açık olmalı
            }}
          }};
          setVol({vol_to_set});
        }})();
        """
        try:
            self.webView.page().runJavaScript(js)
        except Exception:
            pass

    def set_web_volume(self, volume: int):
        """Web sesini arayüzdeki master seviyeye senkronize et."""
        self._apply_web_volume(volume)

    # ------------------------------------------------------------------#
    # WEB SEEK POLL (duration/position)
    # ------------------------------------------------------------------#
    def _start_web_seek_poll(self):
        if self.web_seek_timer and not self.web_seek_timer.isActive():
            self.web_seek_timer.start()

    def _stop_web_seek_poll(self):
        if self.web_seek_timer and self.web_seek_timer.isActive():
            self.web_seek_timer.stop()
        self.web_duration_ms = 0
        self.web_position_ms = 0
        # Temizle
        self.positionSlider.setRange(0, 0)
        self.positionSlider.setValue(0)
        self.lblCurrentTime.setText("00:00")
        self.lblTotalTime.setText("00:00")

    def _poll_web_position(self):
        if getattr(self, "search_mode", "") != "web" or not self.webView:
            return
        js = """
        (() => {
          const v = document.querySelector('video');
          if (!v || !v.duration || Number.isNaN(v.duration)) return null;
          return {t: v.currentTime || 0, d: v.duration || 0};
        })();
        """
        try:
            self.webView.page().runJavaScript(js, self._update_web_position_from_js)
        except Exception:
            pass

    def _update_web_position_from_js(self, res):
        if res is None or not isinstance(res, dict):
            return
        cur = float(res.get("t", 0.0))
        dur = float(res.get("d", 0.0))
        if dur <= 0:
            return
        pos_ms = int(cur * 1000)
        dur_ms = int(dur * 1000)
        self.web_duration_ms = dur_ms
        self.web_position_ms = pos_ms
        # Slider ve label güncelle
        self.positionSlider.blockSignals(True)
        self.positionSlider.setRange(0, dur_ms)
        self.positionSlider.setValue(pos_ms)
        self.positionSlider.blockSignals(False)
        self.lblCurrentTime.setText(self._format_time(pos_ms))
        self.lblTotalTime.setText(self._format_time(dur_ms))

    def _web_seek(self, seconds: float):
        """Web video içine seek et."""
        if getattr(self, "search_mode", "") != "web" or not self.webView:
            return
        js = f"""
        (() => {{
          const v = document.querySelector('video');
          if (!v || !v.duration || Number.isNaN(v.duration)) return;
          const s = {seconds};
          v.currentTime = Math.max(0, Math.min(v.duration, s));
        }})();
        """
        try:
            self.webView.page().runJavaScript(js)
        except Exception:
            pass

    # ------------------------------------------------------------------#
    # SİSTEM MONİTÖR YAKALAMA (PipeWire/Pulse monitor)
    # ------------------------------------------------------------------#
    def _select_monitor_device(self):
        """sounddevice ile uygun monitor kaynağını seç."""
        if not SD_AVAILABLE:
            return None
        try:
            devices = sd.query_devices()
        except Exception:
            return None
        # Önce bilinen loopback kaynakları
        preferred = [
            "alsa_output.pci-0000_00_1f.3.analog-stereo.monitor",
            "alsa_output.usb-0c76_USB_PnP_Audio_Device-00.analog-stereo.monitor",
            "easyeffects_sink.monitor",
            "Easy Effects Sink",
            "Easy Effects Source",
            "Çıktı Düzey Ölçer",
            "Spektrum",
            "default_audio_device.monitor",
            "pipewire",
            "pulse",
            "default",
        ]
        # Kullanıcı ayarı varsa en başa koy
        if getattr(self, "monitor_device_name", None) and self.monitor_device_name not in preferred:
            preferred.insert(0, self.monitor_device_name)

        def _match(name, devname):
            return name.lower() in devname.lower()

        for name in preferred:
            for idx, dev in enumerate(devices):
                devname = dev.get("name", "")
                if _match(name, devname):
                    return idx
        # "monitor" içeren herhangi bir cihaz
        for idx, dev in enumerate(devices):
            if "monitor" in dev.get("name", "").lower():
                return idx
        # Hiç yoksa, herhangi bir giriş kanalı olan ilk cihaz
        for idx, dev in enumerate(devices):
            if (dev.get("max_input_channels", 0) or 0) > 0:
                return idx
        return None

    def _start_monitor_capture(self):
        """Sistem monitor sesini yakala ve görselleştir."""
        if not SD_AVAILABLE or getattr(self, "monitor_stream", None):
            return
        device_idx = self._select_monitor_device()
        if device_idx is None:
            try:
                devs = sd.query_devices()
                names = [d.get("name", "") for d in devs]
                print(f"Monitor kaynak bulunamadı; mevcut cihazlar: {names}")
            except Exception:
                print("Monitor kaynak bulunamadı; sistem ses görselleştirmesi devre dışı.")
            if hasattr(self, "statusBar"):
                self.statusBar().showMessage("Sistem ses kaynağı bulunamadı (monitor).", 4000)
            return
        try:
            devices = sd.query_devices()
            dev = devices[device_idx]
            samplerate = int(dev.get("default_samplerate", 48000) or 48000)
            self.monitor_queue.clear()
            if not self.monitor_timer:
                self.monitor_timer = QTimer(self)
                self.monitor_timer.timeout.connect(self._drain_monitor_queue)
            self.monitor_timer.start(15)  # ~62 FPS (Daha seri yakalama)

            def _callback(indata, frames, time_info, status):
                if status:
                    return
                # kopyala, ana thread'e bırak
                self.monitor_queue.append((indata.copy(), samplerate))

            self.monitor_stream = sd.InputStream(
                device=device_idx,
                channels=min(2, dev.get("max_input_channels", 2) or 2),
                samplerate=samplerate,
                blocksize=1024,
                dtype="float32",
                callback=_callback,
            )
            self.monitor_stream.start()
            print(f"Sistem monitor yakalama başlatıldı (device idx {device_idx}, {dev.get('name')}).")
            if hasattr(self, "statusBar"):
                self.statusBar().showMessage("Sistem ses görselleştirme: açık", 3000)
        except Exception as e:
            print(f"Monitor yakalama başlatılamadı: {e}")
            self.monitor_stream = None
            if self.monitor_timer:
                self.monitor_timer.stop()
            if hasattr(self, "statusBar"):
                self.statusBar().showMessage("Sistem ses görselleştirmesi başlatılamadı.", 4000)

    def _stop_monitor_capture(self):
        """Monitor yakalamayı durdur."""
        if getattr(self, "monitor_timer", None):
            self.monitor_timer.stop()
        if getattr(self, "monitor_stream", None):
            try:
                self.monitor_stream.stop()
                self.monitor_stream.close()
            except Exception:
                pass
        self.monitor_stream = None
        self.monitor_queue.clear()

    def _drain_monitor_queue(self):
        """Monitor kuyruğundan veri alıp FFT uygula."""
        if not self.monitor_queue:
            return
        samples, sr = self.monitor_queue.pop()
        
        # Resampling: 44100Hz → 48000Hz (pipeline_error:14 çözümü)
        TARGET_RATE = 48000
        if np is not None and sr != TARGET_RATE and sr > 0:
            try:
                # Mono veya stereo için ayrı işlem
                if samples.ndim == 1:
                    old_len = len(samples)
                    new_len = int(old_len * TARGET_RATE / sr)
                    old_indices = np.arange(old_len)
                    new_indices = np.linspace(0, old_len - 1, new_len)
                    samples = np.interp(new_indices, old_indices, samples).astype(np.float32)
                else:
                    # Stereo: her kanal için ayrı resample
                    old_len = samples.shape[0]
                    new_len = int(old_len * TARGET_RATE / sr)
                    old_indices = np.arange(old_len)
                    new_indices = np.linspace(0, old_len - 1, new_len)
                    resampled = np.zeros((new_len, samples.shape[1]), dtype=np.float32)
                    for ch in range(samples.shape[1]):
                        resampled[:, ch] = np.interp(new_indices, old_indices, samples[:, ch])
                    samples = resampled
                sr = TARGET_RATE
            except Exception as e:
                print(f"Resampling hatası: {e}")
        
        # İlk birkaç kare için enerji logu (debug)
        self._maybe_feed_monitor_to_dsp(samples, sr)
        if self.search_mode == "web":
            if not getattr(self, "_web_pcm_seen", False):
                self._emit_pcm_to_visualizer(samples, sr)
            return
        self._process_samples_array(samples, sr)

    def _emit_pcm_to_visualizer(self, samples, sample_rate, channels=0):
        """Send PCM samples through the same visualizer pipeline as local audio."""
        if np is None or not getattr(self, "audio_engine", None):
            return
        try:
            data = np.asarray(samples, dtype=np.float32)
        except Exception:
            return
        if data.size == 0:
            return
        if data.ndim > 1:
            channels = int(data.shape[1])
            data = data.reshape(-1, channels)
        else:
            if channels <= 0:
                channels = 1
            frames = data.size // channels
            if frames <= 0:
                return
            data = data[: frames * channels]
        if channels <= 0:
            channels = 1
        if self.search_mode == "web":
            data = np.clip(data * 3.0, -1.0, 1.0)
        sr = int(sample_rate) if sample_rate and sample_rate > 0 else 48000
        self.audio_engine.viz_data_ready.emit(data.tobytes(), 32, channels, sr)

    def _process_samples_array(self, samples, sample_rate):
        """NumPy dizisinden FFT çıkar (monitor için)."""
        if np is None:
            return
            
        # ═══════════════════════════════════════════════════════════════
        # STEREO → MONO ÇEVRİMİ (Tutarlı ritim analizi için)
        # ═══════════════════════════════════════════════════════════════
        if samples.ndim > 1:
            samples = np.mean(samples, axis=1)
        samples = samples.astype(np.float32)
        
        # ═══════════════════════════════════════════════════════════════
        # WEB MOD: 3.0x GAIN BOOST (Düşük web ses seviyesi için)
        # ═══════════════════════════════════════════════════════════════
        is_web = (self.search_mode == "web")
        if is_web:
            samples = np.clip(samples * 2.2, -1.0, 1.0) # 3.0x çok fazlaydı, bloklaşmayı önlemek için 2.2x
        
        N = len(samples)
        if N < 512:
            return
            
        # Web modunda visualizer'ı ZORLA aktif et
        if is_web and getattr(self, "_visualizer_paused", False):
            self._set_visualizer_paused(False, fade=False)
        
        # ═══════════════════════════════════════════════════════════════
        # WEB MOD: Video oynatılmıyorsa ritim çubuklarını YAVAŞÇA DURDUR
        # (Ani kesinti yerine yumuşak geçiş)
        # ═══════════════════════════════════════════════════════════════
        if is_web:
            web_playing = getattr(self, "_web_playing", False)
            video_count = getattr(self, "_last_web_video_count", 0)
            
            if not web_playing or video_count <= 0:
                # Video oynatılmıyor - yumuşak düşüş uygula
                if hasattr(self, "_prev_monitor_bands") and self._prev_monitor_bands:
                    # Önceki değerleri %85 azalt (ani sıfırlama yerine fade-out)
                    faded = [v * 0.85 for v in self._prev_monitor_bands]
                    self._prev_monitor_bands = faded
                    if max(faded) > 0.01:  # Hala görünür değer varsa göster
                        intensity = sum(faded) / len(faded)
                        self.send_visual_data(intensity, faded)
                        return
                # Tamamen sıfırla
                zero_vals = [0.0] * 96
                self.send_visual_data(0.0, zero_vals)
                return
                
        rms = float(np.sqrt(np.mean(samples * samples)))
        
        # Noise gate kontrolü (web için daha düşük eşik - kesinti önleme)
        noise_gate = 0.005 if is_web else self._visualizer_noise_gate_linear
        
        if rms < noise_gate:
            # Ani sıfırlama yerine yumuşak düşüş
            if is_web and hasattr(self, "_prev_monitor_bands") and self._prev_monitor_bands:
                faded = [v * 0.9 for v in self._prev_monitor_bands]
                self._prev_monitor_bands = faded
                if max(faded) > 0.005:
                    self.send_visual_data(sum(faded)/len(faded), faded)
                    return
            zero_vals = [0.0] * 96
            self.send_visual_data(0.0, zero_vals)
            return
        if rms >= 0.05 and getattr(self, "_visualizer_paused", False):
            self._set_visualizer_paused(False, fade=False)
        if rms <= 0.001 or abs(rms - 1.0) <= 0.001:
            zero_vals = [0.0] * 96
            self.send_visual_data(0.0, zero_vals)
            return
            
        window = np.hanning(len(samples))
        windowed_samples = samples * window
        fft = np.fft.rfft(windowed_samples, n=4096)
        magnitude = np.abs(fft)
        num_bars = 96
        band_vals = []
        nyquist = sample_rate / 2.0
        freq_per_bin = nyquist / len(magnitude)
        min_freq = 20.0
        max_freq = min(20000.0, nyquist)
        freq_limits = []
        for i in range(num_bars + 1):
            ratio = (max_freq / min_freq) ** (i / num_bars)
            freq_limits.append(min_freq * ratio)
        for i in range(num_bars):
            freq_start = freq_limits[i]
            freq_end = freq_limits[i + 1]
            bin_start = int(freq_start / freq_per_bin)
            bin_end = int(freq_end / freq_per_bin)
            if bin_end <= bin_start:
                bin_end = bin_start + 1
            segment = magnitude[bin_start:bin_end]
            if segment.size:
                band_energy = float(np.sqrt(np.mean(segment ** 2)))
            else:
                band_energy = 0.0
            freq_ratio = i / num_bars
            if freq_ratio < 0.2:
                sensitivity = 1.5
            elif freq_ratio < 0.5:
                sensitivity = 1.0
            else:
                sensitivity = 0.9
            band_vals.append(band_energy * sensitivity)
        if not hasattr(self, "band_dynamic_max") or len(self.band_dynamic_max) != num_bars:
            self.band_dynamic_max = [1e-6] * num_bars
        decay = 0.94 if is_web else 0.97 # Web modunda tepeler daha hızlı düşsün
        norm_vals = []
        for i, val in enumerate(band_vals):
            prev = self.band_dynamic_max[i] * decay
            peak = max(prev, val)
            self.band_dynamic_max[i] = peak
            norm_vals.append(val / (peak + 1e-6))
        band_vals = [max(0.0, min(1.0, v)) for v in norm_vals]
        
        # ═══════════════════════════════════════════════════════════════
        # ANTI-JITTER SMOOTHING: Daha akıcı geçişler için EMA
        # ═══════════════════════════════════════════════════════════════
        if not hasattr(self, "_prev_monitor_bands") or len(self._prev_monitor_bands) != len(band_vals):
            self._prev_monitor_bands = band_vals[:]
        else:
            # Web modu için çok daha seri tepki (alpha=0.95)
            # Yerel mod için seri tepki (alpha=0.80)
            alpha = 0.95 if is_web else 0.80
            band_vals = [alpha * new + (1.0 - alpha) * old 
                        for new, old in zip(band_vals, self._prev_monitor_bands)]
            self._prev_monitor_bands = band_vals[:]
        
        if len(band_vals) > 10:
            bass_energy = np.mean(band_vals[:10])
            mid_energy = np.mean(band_vals[10:40])
            treble_energy = np.mean(band_vals[40:])
            intensity = bass_energy * 0.6 + mid_energy * 0.3 + treble_energy * 0.1
        else:
            intensity = np.mean(band_vals)
        intensity = np.clip(intensity, 0.0, 1.0)
        self.send_visual_data(intensity, band_vals)

    def _maybe_feed_monitor_to_dsp(self, samples, sample_rate):
        """Phase 3: Simplified Monitor Feeding (C++ does the heavy lifting)."""
        if self.search_mode != "web" or getattr(self, "_web_pcm_seen", False):
            return
            
        # 1-second delay for safety
        now = time.time()
        web_mode_ts = getattr(self, "_web_mode_activated_ts", 0.0)
        if (now - web_mode_ts) < 1.0:
            return
            
        # No player - No sound rule
        if getattr(self, "_last_web_video_count", 0) <= 0:
            return

        # Bypass mode: monitor verisi yalnızca görselleştirme için kullanılacak
        return

    @staticmethod
    def _extract_youtube_id(qurl: QUrl) -> Optional[str]:
        """Basit youtube/youtube music/video id yakalama."""
        try:
            url = qurl.toString()
            parsed = urllib.parse.urlparse(url)
            if "youtube" in parsed.netloc:
                qs = urllib.parse.parse_qs(parsed.query)
                if "v" in qs:
                    return qs["v"][0]
                parts = parsed.path.split("/")
                for p in reversed(parts):
                    if p and len(p) >= 8:
                        return p
            if "youtu.be" in parsed.netloc:
                parts = parsed.path.split("/")
                if len(parts) >= 2:
                    return parts[-1]
        except Exception:
            return None
        return None

    def set_visualization_mode(self, mode: str):
        self.vis_mode = mode
        self.config_data["vis_mode"] = mode
        if self.vis_widget_main_window:
            self.vis_widget_main_window.set_vis_mode(mode)
        if self.vis_window and self.vis_window.visualizationWidget:
            self.vis_window.visualizationWidget.set_vis_mode(mode)
        self.save_config()
        self.statusBar().showMessage(f"Görselleştirme modu: {mode}", 3000)
        if self.vis_auto_cycle and self.vis_auto_timer.isActive():
            self._reset_auto_cycle_index(mode)

    def _update_info_panels(self, title, artist, album, path):
        """Şarkı ve sanatçı bilgi panellerini güncelle."""
        if not title:
            if hasattr(self, "song_info_title"):
                self.song_info_title.setText(f"{self._tr('song_info')}: -")
                self.song_info_artist.setText(f"{self._tr('artist_info')}: -")
                self.song_info_album.setText("Albüm: -")
                self.song_info_duration.setText("Süre: -")
                self.song_info_path.setText("Konum: -")
            if hasattr(self, "artist_info_label"):
                self.artist_info_label.setText(f"{self._tr('artist_info')}: -")
                self.artist_tracks_label.setText("Son çalınanlar: -")
            return

        if hasattr(self, "song_info_title"):
            self.song_info_title.setText(f"{self._tr('song_info')}: {title}")
            self.song_info_artist.setText(f"{self._tr('artist_info')}: {artist}")
            self.song_info_album.setText(f"Albüm: {album}")
            dur_ms = self.mediaPlayer.duration()
            if dur_ms > 0:
                dur_str = QTime(0, 0).addMSecs(dur_ms).toString("mm:ss")
            else:
                dur_str = "-"
            self.song_info_duration.setText(f"Süre: {dur_str}")
            self.song_info_path.setText(f"Konum: {path}")
        if hasattr(self, "artist_info_label"):
            self.artist_info_label.setText(f"{self._tr('artist_info')}: {artist}")
            # Son çalınanlar: mevcut playlistte aynı sanatçıdan ilk 5 parça
            tracks = []
            for i in range(self.playlistWidget.count()):
                item = self.playlistWidget.item(i)
                p = item.data(Qt.UserRole)
                t, a, _ = self._get_tags_from_file(p)
                if a == artist:
                    tracks.append(t)
                if len(tracks) >= 5:
                    break
            if tracks:
                self.artist_tracks_label.setText("Son çalınanlar: " + ", ".join(tracks))
            else:
                self.artist_tracks_label.setText("Son çalınanlar: -")

    def toggle_visualization_window(self):
        if self.vis_window and self.vis_window.isVisible():
            self.vis_window.close()
            self.vis_window = None
            self.statusBar().showMessage("Görselleştirme Penceresi Kapandı", 2000)
        else:
            self.vis_window = VisualizationWindow(self)
            self.vis_window.show()
            
            # Tema ayarı
            if hasattr(self.vis_window.visualizationWidget, 'set_color_theme'):
                self.vis_window.visualizationWidget.set_color_theme(
                    self.themes[self.theme][0],
                    self.themes[self.theme][2]
                )
            
            self.statusBar().showMessage("Görselleştirme Penceresi Açıldı", 2000)

    def _vis_window_closed(self):
        self.vis_window = None

    def update_play_button_state(self, playing: bool, source: str = None):
        if not hasattr(self, "playButton"):
            return
        if hasattr(self, "icon_play") and hasattr(self, "icon_pause"):
            icon = self.icon_pause if playing else self.icon_play
        else:
            icon_name = "media-playback-pause.png" if playing else "media-playback-start.png"
            icon = QIcon(os.path.join("icons", icon_name))
        self.playButton.setIcon(icon)

    def _on_video_state_changed(self, state):
        """Video oynatma durumu değişince."""
        # Main Play Button Update
        if state == QMediaPlayer.PlayingState:
            self.update_play_button_state(True, source="video")
        elif state == QMediaPlayer.PausedState:
            self.update_play_button_state(False, source="video")
        elif state == QMediaPlayer.StoppedState:
            self.update_play_button_state(False, source="video")

        try:
            # Aura hızını duruma göre ayarla
            if state == QMediaPlayer.PlayingState:
                self._set_video_aura_speed(1.0)
                self._clear_video_error()
            elif state == QMediaPlayer.PausedState:
                self._set_video_aura_speed(0.20)
            else:
                self._set_video_aura_speed(0.08)
                
            # FPS Timer
            self._apply_video_target_fps_timer()
        except Exception:
            pass
        
        # Tam ekran kontrollerini güncelle
        if getattr(self, '_in_video_fullscreen', False):
            self._update_fs_controls_state()

        # Video durunca/pauselayınca ritim çubuklarını yumuşakça düşür
        try:
            if state in (QMediaPlayer.PausedState, QMediaPlayer.StoppedState):
                self.send_video_visual_data(0.0, [0.0] * 96)
        except Exception:
            pass

    def _update_status_bar(self, state):
        if self.search_mode == "web":
            return
        if state == QMediaPlayer.PlayingState:
            self.update_play_button_state(True, source="local")
            self.statusBar().showMessage(
                f"Çalınıyor: {self.fileLabel.text().replace('Şu An Çalınan: ', '')}",
                0
            )
            if self.search_mode != "web":
                self._set_visualizer_paused(False, fade=False)
        
        elif state == QMediaPlayer.PausedState:
            self.update_play_button_state(False, source="local")
            self.statusBar().showMessage(
                f"Duraklatıldı: {self.fileLabel.text().replace('Şu An Çalınan: ', '')}",
                0
            )
            if self.search_mode != "web":
                self._set_visualizer_paused(True, fade=True)
            self._stop_fallback_visualizer()
                
        elif state == QMediaPlayer.StoppedState:
            self.update_play_button_state(False, source="local")
            self.statusBar().showMessage("Durduruldu.", 3000)
            if self.search_mode != "web":
                self._set_visualizer_paused(True, fade=True)
            self._stop_fallback_visualizer()
    
    # _check_probe_status removed as it's obsolete.


    # ------------------------------------------------------------------#
    # MEDYA OLAYLARI
    # ------------------------------------------------------------------#

    def _update_progress_bar_style(self):
        """🌈 Progress bar rainbow gradient'i sürekli güncelle (akıcı animasyon)"""
        total_duration = self.mediaPlayer.duration()
        if total_duration > 0:
            # Rainbow animasyon (zaman bazlı, müzik durdurulsa bile devam eder)
            rainbow_offset = (time.time() * 30) % 360
            
            hue1 = int(rainbow_offset % 360)
            hue2 = int((rainbow_offset + 90) % 360)
            hue3 = int((rainbow_offset + 180) % 360)
            hue4 = int((rainbow_offset + 270) % 360)
            
            # Progress bar style
            progress_style = f"""
                QSlider::groove:horizontal {{
                    background: #333; height: 8px; border-radius: 4px;
                }}
                QSlider::sub-page:horizontal {{
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                        stop:0 hsl({hue1}, 95%, 50%),
                        stop:0.33 hsl({hue2}, 95%, 50%),
                        stop:0.66 hsl({hue3}, 95%, 50%),
                        stop:1 hsl({hue4}, 95%, 50%));
                    height: 8px; border-radius: 4px;
                }}
                QSlider::add-page:horizontal {{
                    background: #2E2E2E; border-radius: 4px;
                }}
                QSlider::handle:horizontal {{
                    background: #40C4FF; border: 2px solid #000;
                    width: 14px; margin: -5px 0; border-radius: 7px;
                }}
            """
            
            # Volume slider style (horizontal - yatay)
            volume_style = f"""
                QSlider::groove:horizontal {{
                    background: #333; height: 6px; border-radius: 3px;
                }}
                QSlider::sub-page:horizontal {{
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                        stop:0 hsl({hue1}, 95%, 50%),
                        stop:0.33 hsl({hue2}, 95%, 50%),
                        stop:0.66 hsl({hue3}, 95%, 50%),
                        stop:1 hsl({hue4}, 95%, 50%));
                    height: 6px; border-radius: 3px;
                }}
                QSlider::add-page:horizontal {{
                    background: #2E2E2E; border-radius: 3px;
                }}
                QSlider::handle:horizontal {{
                    background: #40C4FF; border: 2px solid #000;
                    width: 12px; margin: -4px 0; border-radius: 6px;
                }}
            """
            
            try:
                self.positionSlider.setStyleSheet(progress_style)
                self.volumeSlider.setStyleSheet(volume_style)
            except:
                pass

    def _on_master_volume_changed(self, volume):
        """Ana ses değişince aktif player'a uygula."""
        # Audio Engine
        if hasattr(self, 'audio_engine'):
            self.audio_engine.media_player.setVolume(volume)
        
        # Video Player
        if hasattr(self, 'videoPlayer'):
            self.videoPlayer.setVolume(volume)

    def _on_audio_position_changed(self, position):
        """Sadece ses sekmesi aktifse slider'ı güncelle."""
        if self.mainContentStack.currentIndex() == 0: # Audio/Playlist Tab
            self.position_changed(position)

    def _on_audio_duration_changed(self, duration):
        """Sadece ses sekmesi aktifse slider range'i güncelle."""
        if self.mainContentStack.currentIndex() == 0:
            self.duration_changed(duration)

    def _on_video_position_changed(self, position):
        """Video pozisyonu değişince (Video sekmesi aktifse) ana slider'ı güncelle."""
        # Main slider update (if video tab active)
        if self.mainContentStack.currentIndex() == 1: # Video Tab
            if not self.positionSlider.isSliderDown():
                self.positionSlider.setValue(position)
            
            # Update labels
            total_duration = self.videoPlayer.duration()
            if total_duration > 0:
                current_time = self._format_time(position)
                self.lblCurrentTime.setText(current_time)
        
        # Tam ekran kontrollerini güncelle
        if getattr(self, '_in_video_fullscreen', False):
            self._update_fs_controls_state()

        # Video altyazı (overlay) güncelle
        try:
            st = getattr(self, '_video_settings_state', {})
            if isinstance(st, dict) and st.get('subtitles_enabled'):
                self._update_video_subtitle_overlay(int(position))
        except Exception:
            pass

        # Ek açıklamalar (info overlay) güncelle
        try:
            st = getattr(self, '_video_settings_state', {})
            if isinstance(st, dict) and st.get('annotations'):
                self._update_video_info_overlay()
        except Exception:
            pass

    def _on_video_duration_changed(self, duration):
        """Video süresi değişince."""
        # Main slider range (if video tab active)
        if self.mainContentStack.currentIndex() == 1:
            self.positionSlider.setRange(0, duration)
            if duration > 0:
                total_time = self._format_time(duration)
                self.lblTotalTime.setText(total_time)

    def position_changed(self, position):
        if not self.positionSlider.isSliderDown():
            self.positionSlider.setValue(position)

        total_duration = self.audio_engine.media_player.duration()
        if total_duration > 0:
            current_time = self._format_time(position)
            total_time = self._format_time(total_duration)
            self.lblCurrentTime.setText(current_time)
            self.lblTotalTime.setText(total_time)

            # Auto Crossfade Trigger (yeni sistem)
            cf_ms = int(getattr(self, "_pb_crossfade_ms", 0) or 0)
            if bool(getattr(self, "_pb_auto_crossfade_enabled", False)) and cf_ms > 0 and not getattr(self, "_crossfade_triggered", False):
                remaining = total_duration - position
                if remaining <= cf_ms and self.audio_engine.media_player.state() == QMediaPlayer.PlayingState:
                    if self.playlist.currentIndex() < self.playlist.mediaCount() - 1 or \
                       self.playlist.playbackMode() in (QMediaPlaylist.Loop, QMediaPlaylist.CurrentItemInLoop):
                        # Auto-crossfade ile parça bitmeden ileri alındıktan sonra,
                        # eski parçadan gelebilecek EndOfMedia durumunu bir kez yoksaymak için işaretle.
                        try:
                            self._auto_crossfade_guard = (time.monotonic(), int(self.playlist.currentIndex()))
                        except Exception:
                            self._auto_crossfade_guard = None
                        self._crossfade_triggered = True
                        self._next_track(_reason="auto_crossfade")

    def duration_changed(self, duration):
        # Yeni parça yüklendiğinde auto-crossfade tetikleyicisini yeniden etkinleştir.
        # (Playlist index değişimi, özellikle gap-free/crossfade sırasında, gerçek oynatma
        # hemen değişmeyebildiği için burada resetlemek zincirleme atlamayı engeller.)
        self._crossfade_triggered = False
        self.positionSlider.setRange(0, duration)
        if duration > 0:
            total_time = self._format_time(duration)
            self.lblTotalTime.setText(total_time)
        else:
            self.lblCurrentTime.setText("00:00")
            self.lblTotalTime.setText("00:00")


    def _set_position_safely(self):
        """Slider bırakılınca ilgili konuma git (Web/Local/Video)."""
        val = self.positionSlider.value()
        
        if self.search_mode == "web" and self.webView:
            if self.positionSlider.maximum() > 1000:
                seconds = val / 1000.0
                self._web_seek(seconds)
        elif self.mainContentStack.currentIndex() == 1: # Video Tab
            if hasattr(self, 'videoPlayer'):
                self.videoPlayer.setPosition(val)
        else: # Audio Tab
            if self.audio_engine:
                self.audio_engine.media_player.setPosition(val)
            
    def _set_position_safely_moved(self, val):
        """Slider sürüklenirken label'ı güncelle."""
        # Web modunda mevcut duruma göre güncelle
        if self.search_mode == "web" and self.web_duration_ms > 0:
            self.lblCurrentTime.setText(self._format_time(val))
            self.lblTotalTime.setText(self._format_time(self.web_duration_ms))
        elif self.mainContentStack.currentIndex() == 1: # Video Tab
             self.lblCurrentTime.setText(self._format_time(val))
        else:
            self.lblCurrentTime.setText(self._format_time(val))
            # Keep total as previous or ...
            self.lblTotalTime.setText("...")

    def play_pause(self):
        """Oynat/Duraklat (Context Aware)."""
        if self.mainContentStack.currentIndex() == 1: # Video Tab
            self._video_toggle_play()
        else: # Audio Tab
            if self.search_mode == "web":
                self._web_toggle_play()
            else:
                if self.audio_engine.media_player.state() == QMediaPlayer.PlayingState:
                    self.audio_engine.media_player.pause()
                else:
                    self.audio_engine.media_player.play()

    def _nudge_position(self, delta_ms: int):
        """Pozisyonu ileri/geri kaydır (F3/F4) - Context Aware."""
        if self.mainContentStack.currentIndex() == 1: # Video Tab
            if hasattr(self, 'videoPlayer') and self.videoPlayer.isSeekable():
                new_pos = max(0, self.videoPlayer.position() + delta_ms)
                self.videoPlayer.setPosition(new_pos)
                self.positionSlider.setValue(new_pos)
        else: # Audio Tab
            if not self.audio_engine or not self.audio_engine.media_player.isSeekable():
                return
            new_pos = max(0, self.audio_engine.media_player.position() + delta_ms)
            self.audio_engine.media_player.setPosition(new_pos)
            self.positionSlider.setValue(new_pos)

    def _play_selected_shortcut(self):
        """Enter tuşu ile mevcut seçimden çal/ekle."""
        widget = QApplication.focusWidget()
        if widget == self.playlistWidget:
            index = self.playlistWidget.currentIndex()
            if index and index.isValid():
                self.playlist_double_clicked(index)
        elif widget == self.file_tree:
            index = self.file_tree.currentIndex()
            if index and index.isValid():
                self.file_tree_double_clicked(index)
        elif widget == self.libraryTableWidget:
            index = self.libraryTableWidget.currentIndex()
            if index and index.isValid():
                self.library_double_clicked(index)

    def _apply_language_strings(self):
        """Arayüz metinlerini mevcut dile göre tazele."""
        # Shuffle/Repeat ikonlarını güncelle
        self._apply_shuffle_button_state(self.is_shuffling)
        self._apply_repeat_button_state(self.is_repeating)

        # Sidebar item etiketlerini güncelle
        labels = [
            self._tr("library"),
            self._tr("files"),
            "Video",
            self._tr("playlists"),
            self._tr("internet"),
            self._tr("devices"),
            self._tr("song_info"),
            self._tr("artist_info")
        ]
        for i in range(min(len(labels), self.sidebarNav.count())):
            item = self.sidebarNav.item(i)
            item.setToolTip(labels[i])
            item.setData(Qt.UserRole, labels[i])
            item.setText("")

        # Ses etiketi
        self.volumeLabel.setText(f"{self.volumeSlider.value()}%")
        # Arama placeholder
        if hasattr(self, "searchBar"):
            self.searchBar.setPlaceholderText(f"🔍 {self._tr('search')}")
        # Menü barı metinlerini güncelle
        self.menuBar().clear()
        self._create_menu_bar()

    def _apply_shuffle_button_state(self, enabled):
        if not hasattr(self, "shuffleButton"):
            return
        self.shuffleButton.setChecked(bool(enabled))
        if enabled:
            self._update_aura_icons(force=True)
        else:
            self.shuffleButton.setIcon(self._shuffle_icon_off)
        self.shuffleButton.setToolTip(
            self._tr("shuffle_on") if enabled else self._tr("shuffle_off")
        )
        self._set_button_opacity(self.shuffleButton, bool(enabled))

    def _apply_repeat_button_state(self, mode_or_enabled):
        if not hasattr(self, "repeatButton"):
            return
        if isinstance(mode_or_enabled, bool):
            is_enabled = mode_or_enabled
            tooltip = self._tr("repeat_one") if is_enabled else self._tr("repeat_off")
        else:
            mode = mode_or_enabled
            is_enabled = mode in (QMediaPlaylist.Loop, QMediaPlaylist.CurrentItemInLoop)
            if mode == QMediaPlaylist.CurrentItemInLoop:
                tooltip = self._tr("repeat_one")
            elif mode == QMediaPlaylist.Loop:
                tooltip = self._tr("repeat_list")
            else:
                tooltip = self._tr("repeat_off")

        self.repeatButton.setChecked(is_enabled)
        if is_enabled:
            self._update_aura_icons(force=True)
        else:
            self.repeatButton.setIcon(self._repeat_icon_off)
        self.repeatButton.setToolTip(tooltip)
        self._set_button_opacity(self.repeatButton, is_enabled)

    def _load_svg_template(self, path):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return handle.read()
        except Exception:
            return ""

    def _make_svg_icon(self, svg_template, color, size):
        if not svg_template or QSvgRenderer is None:
            return None
        color_hex = "#{:02x}{:02x}{:02x}".format(color.red(), color.green(), color.blue())
        svg_data = svg_template.replace("#4cff5a", color_hex)
        svg_data = svg_data.replace("#8a8a8a", color_hex)
        renderer = QSvgRenderer(QByteArray(svg_data.encode("utf-8")))
        pixmap = QPixmap(size)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing, True)
        # RGB aura glow behind the icon for the "keyboard light" effect.
        glow = QRadialGradient(size.width() / 2, size.height() / 2, min(size.width(), size.height()) * 0.5)
        glow_color = QColor(color)
        glow_color.setAlpha(140)
        glow.setColorAt(0.0, glow_color)
        glow.setColorAt(1.0, QColor(color.red(), color.green(), color.blue(), 0))
        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(glow))
        radius = min(size.width(), size.height()) * 0.48
        painter.drawEllipse(QPointF(size.width() / 2, size.height() / 2), radius, radius)
        renderer.render(painter)
        painter.end()
        return QIcon(pixmap)

    def _update_aura_icons(self, force=False):
        active_shuffle = hasattr(self, "shuffleButton") and self.shuffleButton.isChecked()
        active_repeat = hasattr(self, "repeatButton") and self.repeatButton.isChecked()
        if not (active_shuffle or active_repeat):
            if force:
                if hasattr(self, "shuffleButton"):
                    self.shuffleButton.setIcon(self._shuffle_icon_off)
                if hasattr(self, "repeatButton"):
                    self.repeatButton.setIcon(self._repeat_icon_off)
            return

        self._aura_hue = (self._aura_hue + 4) % 360
        color = QColor.fromHsv(self._aura_hue, 255, 255)
        size = self.shuffleButton.iconSize() if hasattr(self, "shuffleButton") else QSize(20, 20)

        if active_shuffle:
            icon = self._make_svg_icon(self._shuffle_svg_template, color, size)
            if icon is not None:
                self.shuffleButton.setIcon(icon)
        if active_repeat:
            icon = self._make_svg_icon(self._repeat_svg_template, color, size)
            if icon is not None:
                self.repeatButton.setIcon(icon)

    def _set_button_opacity(self, button, active):
        try:
            from PyQt5.QtWidgets import QGraphicsOpacityEffect
        except Exception:
            return
        effect = button.graphicsEffect()
        if isinstance(effect, QGraphicsOpacityEffect):
            effect.setOpacity(1.0 if active else 0.7)

    def playlist_position_changed(self, index):
        # ═══════════════════════════════════════════════════════════════
        # YEREL MÜZİK: Web monitor yakalamayı durdur
        # ═══════════════════════════════════════════════════════════════
        if self.search_mode == "web":
            self._stop_monitor_capture()
            self.search_mode = "local"
            self._web_pcm_seen = False
            
        if index < 0 or index >= self.playlist.mediaCount():
            self.current_file_path = None
            self.fileLabel.setText("Şu An Çalınan: -")
            self.infoDisplayWidget.clear_info()
            if hasattr(self.albumArtLabel, "set_cover_pixmap"):
                self.albumArtLabel.set_cover_pixmap(None)
            else:
                self.albumArtLabel.setText("")
                self.albumArtLabel.setPixmap(QPixmap())
            if self.vis_widget_main_window and hasattr(self.vis_widget_main_window, "reset_visualizer"):
                self.vis_widget_main_window.reset_visualizer()
            self._update_info_panels(None, None, None, None)
            self._apply_album_color_theme(None)
            return

        url = self.playlist.media(index).request().url()
        self.current_file_path = url.toLocalFile()
        title, artist, album = self._get_tags_from_file(self.current_file_path)

        self.fileLabel.setText(f"Şu An Çalınan: {artist} - {title}")
        self.infoDisplayWidget.update_info(title, artist, album, self.current_file_path)
        self._update_info_panels(title, artist, album, self.current_file_path)
        self._apply_album_color_theme(self.current_file_path)

        for i in range(self.playlistWidget.count()):
            item = self.playlistWidget.item(i)
            item.setSelected(i == index)
        if 0 <= index < self.playlistWidget.count():
            self.playlistWidget.setCurrentRow(index)

        # Trigger Play in Engine (manual/auto crossfade kontrolü)
        if hasattr(self, 'audio_engine'):
            reason = getattr(self, "_track_change_reason", None)
            enable_cf = self._should_crossfade_for_reason(reason)
            cf_ms = int(getattr(self, "_pb_crossfade_ms", 0) or 0)
            try:
                self.audio_engine.set_crossfade_duration(cf_ms if enable_cf else 0)
            except Exception:
                pass
            try:
                # Manuel geçişlerde (ileri/geri/seçim) "eski parça tekrarlandı" hissini azaltan profil
                self.audio_engine.set_crossfade_context(reason or "")
            except Exception:
                pass
            self._track_change_reason = None
            QTimer.singleShot(0, lambda: self.audio_engine.play_file(self.current_file_path))
            self.playButton.setIcon(QIcon(os.path.join("icons", "media-playback-pause.png")))

    def _play_index(self, index):
        count = self.playlist.mediaCount()
        if count <= 0:
            return
        index = max(0, min(index, count - 1))
        if self.playlist.currentIndex() == index:
            media = self.playlist.media(index)
            url = media.request().url() if media.isNull() is False else QUrl()
            path = url.toLocalFile()
            if path and hasattr(self, "audio_engine"):
                try:
                    # Aynı parçayı yeniden başlatırken crossfade istemiyoruz
                    self.audio_engine.set_crossfade_duration(0)
                except Exception:
                    pass
                QTimer.singleShot(0, lambda: self.audio_engine.play_file(path))
                self.playButton.setIcon(QIcon(os.path.join("icons", "media-playback-pause.png")))
            return
        self.playlist.setCurrentIndex(index)

    def _media_status_changed(self, status):
        if status == QMediaPlayer.InvalidMedia:
            self.statusBar().showMessage("❌ Dosya açılamadı, sonraki parçaya geçiliyor.", 3000)
            count = self.playlist.mediaCount()
            if count <= 0:
                return
            current = self.playlist.currentIndex()
            if self.is_shuffling and count > 1:
                next_index = current
                while next_index == current:
                    next_index = random.randint(0, count - 1)
                self._play_index(next_index)
            else:
                next_index = (current + 1) % count
                self._play_index(next_index)
            return
        if status == QMediaPlayer.EndOfMedia:
            # Auto-crossfade ile parça bitmeden değiştirildiyse, eski parçanın EndOfMedia
            # bildirimi kısa süre sonra gelip bir kez daha ilerletme yapabilir.
            # Bunu, yakın zamanda auto-crossfade yapıldıysa ve playlist index'i değiştiyse yoksay.
            try:
                guard = getattr(self, "_auto_crossfade_guard", None)
                if isinstance(guard, tuple) and len(guard) == 2:
                    t0, from_idx = guard
                    cf_ms = int(getattr(self, "_pb_crossfade_ms", 0) or 0)
                    window_s = max(2.0, (cf_ms / 1000.0) + 1.0)
                    if (time.monotonic() - float(t0)) <= window_s and int(self.playlist.currentIndex()) != int(from_idx):
                        self._auto_crossfade_guard = None
                        return
            except Exception:
                pass
            count = self.playlist.mediaCount()
            if count <= 0:
                return
            current = self.playlist.currentIndex()
            if self.is_repeating:
                self._set_next_track_change_reason("auto_end")
                self._play_index(current)
                return
            if self.is_shuffling and count > 1:
                next_index = current
                while next_index == current:
                    next_index = random.randint(0, count - 1)
                self._set_next_track_change_reason("auto_end")
                self._play_index(next_index)
                return

            next_index = (current + 1) % count
            self._set_next_track_change_reason("auto_end")
            self._play_index(next_index)
    # Obsolete offline DSP logic removed.
    # DSP is now handled in real-time by the thread-isolated GlobalAudioEngine.

    def update_playlist_order_after_drag(self):
        new_paths = []
        for i in range(self.playlistWidget.count()):
            item = self.playlistWidget.item(i)
            new_paths.append(item.data(Qt.UserRole))

        current_path = self.current_file_path

        self.playlist.clear()
        for path in new_paths:
            self.playlist.addMedia(QMediaContent(QUrl.fromLocalFile(path)))

        if current_path and current_path in new_paths:
            new_index = new_paths.index(current_path)
            self.playlist.setCurrentIndex(new_index)
        elif self.playlist.mediaCount() > 0:
            self.playlist.setCurrentIndex(0)

        if self.audio_engine.media_player.state() == QMediaPlayer.PlayingState:
            self.audio_engine.media_player.play()

    # ------------------------------------------------------------------#
    # MEDYA EKLEME
    # ------------------------------------------------------------------#

    def _add_media(self, file_path, add_to_library=False):
        if not os.path.exists(file_path):
            return

        ext = os.path.splitext(file_path)[1].lower()
        if ext not in [".mp3", ".flac", ".ogg", ".m4a", ".m4b", ".mp4", ".wav", ".aac", ".wma", ".opus"]:
            self.statusBar().showMessage(
                f"Hata: Desteklenmeyen dosya türü: {ext}", 5000
            )
            return

        title, artist, album, duration = self._get_tags_from_file_with_duration(file_path)

        if add_to_library:
            self.library.add_track(file_path, {
                "title": title,
                "artist": artist,
                "album": album,
                "duration": duration,
            })

        # Real-time DSP handled by GlobalAudioEngine
        url = QUrl.fromLocalFile(file_path)
        self.playlist.addMedia(QMediaContent(url))

        display_text = f"{artist} - {title}"
        item = QListWidgetItem(display_text)
        item.setData(Qt.UserRole, file_path)
        self.playlistWidget.addItem(item)

        self.statusBar().showMessage(
            f"Çalma listesine eklendi: {display_text}", 3000
        )

    def _add_files_to_playlist(self, paths: list, add_to_library=False):
        for path in paths:
            if os.path.isdir(path):
                self._add_folder(path, add_to_library)
            else:
                self._add_media(path, add_to_library)
        if add_to_library:
            self.refresh_library_view()

    def _add_folder(self, folder_path, add_to_library=False):
        if not os.path.isdir(folder_path):
            return
        for root, _, files in os.walk(folder_path):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in [".mp3", ".flac", ".ogg", ".m4a", ".m4b", ".mp4", ".wav", ".aac", ".wma", ".opus"]:
                    self._add_media(os.path.join(root, file), add_to_library)

    def _get_tags_from_file_with_duration(self, file_path):
        title = os.path.basename(file_path)
        artist = "Bilinmeyen Sanatçı"
        album = "Bilinmeyen Albüm"
        duration = 0

        if MutagenFile is not None and os.path.exists(file_path):
            try:
                audio = MutagenFile(file_path)
                if audio:
                    if audio.info and hasattr(audio.info, "length"):
                        duration = int(audio.info.length * 1000)

                    if audio.tags:
                        if ID3 and isinstance(audio.tags, ID3):
                            title = str(audio.tags.get("TIT2", [title])[0])
                            artist = str(audio.tags.get("TPE1", [artist])[0])
                            album = str(audio.tags.get("TALB", [album])[0])
                        elif MP4 and isinstance(audio, MP4):
                            title = str(audio.tags.get("\xa9nam", [title])[0])
                            artist = str(audio.tags.get("\xa9ART", [artist])[0])
                            album = str(audio.tags.get("\xa9alb", [album])[0])
            except Exception:
                pass

        return title, artist, album, duration

    def _get_tags_from_file(self, file_path):
        t, a, al, _ = self._get_tags_from_file_with_duration(file_path)
        return t, a, al

    # ------------------------------------------------------------------#
    # KÜTÜPHANE
    # ------------------------------------------------------------------#

    def scan_library(self):
        folder = QFileDialog.getExistingDirectory(
            self, "Kütüphaneye Klasör Ekle ve Tara"
        )
        if folder:
            self.statusBar().showMessage("Kütüphane taranıyor...", 0)
            self._add_folder(folder, add_to_library=True)
            self.refresh_library_view()
            self.statusBar().showMessage("Kütüphane taraması tamamlandı.", 3000)

    def refresh_library_view(self):
        tracks = self.library.get_all_tracks()
        self.libraryTableWidget.load_tracks(tracks)

    def show_library_context_menu(self, point):
        menu = QMenu(self)
        item = self.libraryTableWidget.itemAt(point)
        if item:
            add_to_playlist = QAction("Çalma Listesine Ekle", self)
            add_to_playlist.triggered.connect(self.add_selected_lib_to_playlist)
            menu.addAction(add_to_playlist)
        menu.exec_(self.libraryTableWidget.mapToGlobal(point))

    def add_selected_lib_to_playlist(self):
        paths = self.libraryTableWidget.get_selected_paths()
        for path in paths:
            self._add_media(path, add_to_library=False)

    # ------------------------------------------------------------------#
    # DOSYA AĞACI MENÜSÜ
    # ------------------------------------------------------------------#

    def show_file_context_menu(self, point):
        """Context menu for file tree with YouTube search, Bluetooth, remove from playlist options."""
        menu = QMenu(self)
        index = self.file_tree.indexAt(point)
        if not index.isValid():
            return

        path = self.file_model.filePath(index)
        
        # YouTube ara (üzerindeki dosya/klasör adını ara)
        youtube_action = QAction("🔍 YouTube'da Ara", self)
        def _search_youtube():
            query = os.path.basename(path)
            q = urllib.parse.quote_plus(query)
            url = f"https://www.youtube.com/results?search_query={q}"
            try:
                webbrowser.open(url)
            except Exception:
                pass
        youtube_action.triggered.connect(_search_youtube)
        menu.addAction(youtube_action)

        # Bluetooth cihazları (henüz uygulanmadı ama yer ayırt)
        bluetooth_action = QAction("📱 Bluetooth Cihazları", self)
        def _show_bluetooth():
            self.statusBar().showMessage("Bluetooth desteği yakında gelecek.", 3000)
        bluetooth_action.triggered.connect(_show_bluetooth)
        menu.addAction(bluetooth_action)

        menu.addSeparator()

        # Çalma listesine ekle
        add_action = QAction("➕ Çalma Listesine Ekle", self)
        def _add_to_playlist():
            if os.path.isfile(path):
                self._add_media(path, add_to_library=False)
            elif os.path.isdir(path):
                self._add_folder(path, add_to_library=False)
            self.statusBar().showMessage(f"Eklendi: {os.path.basename(path)}", 2000)
        add_action.triggered.connect(_add_to_playlist)
        menu.addAction(add_action)

        # Çalma listesinden kaldır
        remove_action = QAction("❌ Çalma Listesinden Kaldır", self)
        def _remove_from_playlist():
            # Playlist'te bu yolu bulup kaldır
            for i in range(self.playlistWidget.count()):
                item = self.playlistWidget.item(i)
                if item and item.data(Qt.UserRole) == path:
                    self.playlistWidget.takeItem(i)
                    self.playlist.removeMedia(i)
                    self.save_playlist()
                    break
            self.statusBar().showMessage(f"Kaldırıldı: {os.path.basename(path)}", 2000)
        remove_action.triggered.connect(_remove_from_playlist)
        menu.addAction(remove_action)

        # Seçili öğeleri kaldır
        delete_action = QAction("🗑️ Seçili Öğeleri Kaldır", self)
        def _delete_selected():
            selected = self.file_tree.selectedIndexes()
            for idx in selected:
                p = self.file_model.filePath(idx)
                for i in range(self.playlistWidget.count()):
                    item = self.playlistWidget.item(i)
                    if item and item.data(Qt.UserRole) == p:
                        self.playlistWidget.takeItem(i)
                        self.playlist.removeMedia(i)
                        break
            self.save_playlist()
            self.statusBar().showMessage("Seçili öğeler kaldırıldı.", 2000)
        delete_action.triggered.connect(_delete_selected)
        menu.addAction(delete_action)

        menu.exec_(self.file_tree.mapToGlobal(point))

    # ------------------------------------------------------------------#
    # ÇALMA LİSTESİ MENÜSÜ
    # ------------------------------------------------------------------#

    def show_playlist_context_menu(self, point):
        menu = QMenu(self)
        item = self.playlistWidget.itemAt(point)
        if item:
            # YouTube'da ara
            ytAction = QAction("🔍 YouTube'da Ara", self)
            def _search_youtube():
                items = self.playlistWidget.selectedItems()
                if not items:
                    return
                query = items[0].text()
                q = urllib.parse.quote_plus(query)
                url = f"https://www.youtube.com/results?search_query={q}"
                try:
                    webbrowser.open(url)
                except Exception:
                    pass
            ytAction.triggered.connect(_search_youtube)
            menu.addAction(ytAction)

            # Seçili ögeleri ara
            searchAction = QAction("🔎 Seçili Ögeleri Ara", self)
            def _search_selected():
                items = self.playlistWidget.selectedItems()
                if not items:
                    return
                query = items[0].text()
                q = urllib.parse.quote_plus(query)
                url = f"https://www.google.com/search?q={q}"
                try:
                    webbrowser.open(url)
                except Exception:
                    pass
            searchAction.triggered.connect(_search_selected)
            menu.addAction(searchAction)

            # Bluetooth'a paylaş
            btAction = QAction("📱 Bluetooth EKLE PAYLAŞMAK İÇİN", self)
            def _share_bluetooth():
                from PyQt5.QtWidgets import QMessageBox
                QMessageBox.information(
                    self, "Bluetooth Paylaşımı",
                    "Bu özellik yakında mevcut olacak.\n\n" +
                    "Şarkıları Bluetooth cihazlarına gönderebileceksiniz."
                )
            btAction.triggered.connect(_share_bluetooth)
            menu.addAction(btAction)

            menu.addSeparator()

            # Seçili öğeleri kaldır
            removeAction = QAction("❌ Seçili Öğeleri Kaldır", self)
            removeAction.triggered.connect(self.remove_selected_playlist_items)
            menu.addAction(removeAction)

        # Çalma listesini temizle
        clearAction = QAction("🗑️ Çalma Listesini Temizle", self)
        clearAction.triggered.connect(self.clear_playlist)
        menu.addAction(clearAction)

        menu.exec_(self.playlistWidget.mapToGlobal(point))

    def remove_selected_playlist_items(self):
        items_to_remove = self.playlistWidget.selectedItems()
        if not items_to_remove:
            return

        rows = sorted(
            [self.playlistWidget.row(item) for item in items_to_remove],
            reverse=True
        )
        for row in rows:
            self.playlist.removeMedia(row)
        for item in items_to_remove:
            self.playlistWidget.takeItem(self.playlistWidget.row(item))

        self.statusBar().showMessage(
            f"{len(rows)} öğe çalma listesinden kaldırıldı.", 3000
        )

    def clear_playlist(self):
        self.playlist.clear()
        self.playlistWidget.clear()
        self.mediaPlayer.stop()
        self.current_file_path = None
        self.fileLabel.setText("Şu An Çalınan: -")
        self.infoDisplayWidget.clear_info()
        self.statusBar().showMessage("Çalma listesi temizlendi.", 3000)

    # ------------------------------------------------------------------#
    # DOSYA NAVİGASYONU
    # ------------------------------------------------------------------#

    def file_tree_double_clicked(self, index):
        path = self.file_model.filePath(index)
        if self.file_model.isDir(index):
            self.file_tree.setRootIndex(index)
        else:
            self._add_files_to_playlist([path])
            try:
                self._set_next_track_change_reason("manual_select")
            except Exception:
                pass
            self._play_index(self.playlist.mediaCount() - 1)

    def _go_up_directory(self):
        current_index = self.file_tree.rootIndex()
        parent_index = self.file_model.parent(current_index)
        if parent_index.isValid() and \
                self.file_model.filePath(current_index) != QDir.homePath():
            self.file_tree.setRootIndex(parent_index)
        elif self.file_model.filePath(current_index) != QDir.homePath():
            self.file_tree.setRootIndex(self.file_model.index(QDir.homePath()))

    def _open_current_folder(self):
        """Çalan parçanın klasörünü dosya gezgininde aç."""
        if not self.current_file_path or not os.path.exists(self.current_file_path):
            return
        folder = os.path.dirname(self.current_file_path)
        try:
            QDesktopServices.openUrl(QUrl.fromLocalFile(folder))
        except Exception:
            pass

    def _go_home_directory(self):
        """Dosya ağacını ev klasörüne getir (ileri butonu)."""

        try:
            self.file_tree.setRootIndex(self.file_model.index(QDir.homePath()))
        except Exception:
            pass

    def _open_download_dialog(self):
        """Web'den indirme diyalogunu aç."""
        if not self.webView:
            return
            
        url = self.webView.url().toString()
        if "youtube" not in url and "youtu.be" not in url:
            QMessageBox.warning(self, "Uyarı", "Şu an sadece YouTube desteklenmektedir.")
            return

        dlg = DownloadFormatDialog(self)
        if dlg.exec_() == QDialog.Accepted:
            fmt = dlg.get_format()
            
            # Kayıt yeri sor
            music_dir = QStandardPaths.writableLocation(QStandardPaths.MusicLocation)
            save_dir = QFileDialog.getExistingDirectory(self, "Kaydedilecek Klasör", music_dir)
            
            if save_dir:
                # İndirmeyi başlat
                self.statusBar().showMessage(f"İndiriliyor ({fmt})...")
                
                # Worker oluştur
                self.dl_worker = DownloadWorker(url, fmt, save_dir)
                self.dl_worker.progress_sig.connect(lambda msg: self.statusBar().showMessage(f"İndiriliyor: {msg}"))
                self.dl_worker.finished_sig.connect(self._on_download_finished)
                self.dl_worker.start()

    def _on_download_finished(self, success, msg):
        if success:
            QMessageBox.information(self, "Başarılı", msg)
            self.statusBar().showMessage("İndirme tamamlandı.", 5000)
            # Kütüphane görünümünü yenile (indirilen dosyanın albüm kapağını göstermek için)
            try:
                self.refresh_library_view()
            except Exception:
                pass
        else:
            QMessageBox.critical(self, "Hata", f"İndirme başarısız:\n{msg}")
            self.statusBar().showMessage("İndirme hatası.", 5000)

    # --------------------------------------------------------------
    # Clipboard destekli hızlı indirme
    # --------------------------------------------------------------
    def _check_clipboard_for_url(self):
        try:
            cb = QApplication.clipboard()
            text = cb.text().strip()
            if not text:
                # gizle
                if hasattr(self, 'angollaDownloadBtn') and self.angollaDownloadBtn:
                    self.angollaDownloadBtn.setVisible(False)
                self.clipboard_last_text = ""
                return
            if text == self.clipboard_last_text:
                return
            self.clipboard_last_text = text
            # Basit YouTube URL tespiti
            if ("youtube.com/watch" in text) or ("youtu.be/" in text) or ("music.youtube.com" in text):
                if hasattr(self, 'angollaDownloadBtn') and self.angollaDownloadBtn:
                    self.angollaDownloadBtn.setVisible(True)
                    # Eğer otomatik açma açıksa, yeni URL için format dialogunu otomatik aç
                    if getattr(self, '_auto_open_format_dialog', False) and text != getattr(self, '_clipboard_auto_handled', ''):
                        self._clipboard_auto_handled = text
                        QTimer.singleShot(700, self._on_clipboard_download_clicked)
            else:
                if hasattr(self, 'angollaDownloadBtn') and self.angollaDownloadBtn:
                    self.angollaDownloadBtn.setVisible(False)
        except Exception:
            pass

    def _on_clipboard_download_clicked(self):
        # Panodaki URL'yi al ve indirme diyalogunu başlat
        try:
            cb = QApplication.clipboard()
            url = cb.text().strip()
            if not url:
                QMessageBox.warning(self, "Uyarı", "Panoda URL yok.")
                return
            if "youtube" not in url and "youtu.be" not in url:
                QMessageBox.warning(self, "Uyarı", "Panodaki URL bir YouTube bağlantısı değil.")
                return
            dlg = DownloadFormatDialog(self)
            if dlg.exec_() == QDialog.Accepted:
                fmt = dlg.get_format()
                music_dir = QStandardPaths.writableLocation(QStandardPaths.MusicLocation)
                save_dir = QFileDialog.getExistingDirectory(self, "Kaydedilecek Klasör", music_dir)
                if save_dir:
                    self.dl_worker = DownloadWorker(url, fmt, save_dir)
                    # Modal ilerleme penceresi göster
                    dlg = DownloadProgressDialog(self.dl_worker, self)
                    # Ayrıca bitiş durumunu ana pencereye bildir
                    self.dl_worker.finished_sig.connect(self._on_download_finished)
                    self.dl_worker.start()
                    dlg.exec_()
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"İndirme başlatılamadı:\n{e}")

    def _web_back(self):
        """Toolbar geri: web açıksa web geçmişi, değilse dosya ağacı."""
        if self.search_mode == "web" and hasattr(self, 'webView') and self.webView:
            try:
                if self.webView.history().canGoBack():
                    print("✓ Web geri gidiliyor...")
                    self.webView.back()
                else:
                    print("⚠ Web geçmişinde geri gidilecek sayfa yok")
            except Exception as e:
                print(f"⚠ Web geri hatası: {e}")
        else:
            self._go_up_directory()

    def _web_forward(self):
        """Toolbar ileri: web açıksa web geçmişi, değilse ev dizini."""
        if self.search_mode == "web" and hasattr(self, 'webView') and self.webView:
            try:
                if self.webView.history().canGoForward():
                    print("✓ Web ileri gidiliyor...")
                    self.webView.forward()
                else:
                    print("⚠ Web geçmişinde ileri gidilecek sayfa yok")
            except Exception as e:
                print(f"⚠ Web ileri hatası: {e}")
        else:
            self._go_home_directory()

    def _web_home(self):
        """Web ana sayfasına dön (YouTube Music)."""
        if self.webView:
            self.webView.setUrl(QUrl("https://music.youtube.com"))
            
    def _web_load_url(self):
        """Adres çubuğundaki URL'yi yükle."""
        if not self.webView or not hasattr(self, 'webUrlBar'):
            return
            
        text = self.webUrlBar.text().strip()
        if not text:
            return
            
        if not text.startswith("http"):
            # Arama yap (girdi URL-encode edilmeden query'ye basılmasın)
            try:
                q = urllib.parse.quote_plus(text)
            except Exception:
                q = text
            url = f"https://www.google.com/search?q={q}"
        else:
            url = text

        # Katı: HTTP'yi daha UI seviyesinde engelle
        try:
            if url.lower().startswith("http://"):
                self.webView.setHtml(_blocked_html("HTTP bağlantılarına izin verilmiyor. Lütfen HTTPS kullanın."))
                return
        except Exception:
            pass
            
        self._stop_web_media_playback()
        self.webView.setUrl(QUrl(url))

    def _nav_back(self):
        """Toolbar geri: web açıksa web geçmişi, değilse dosya ağacı."""
        if self.search_mode == "web" and hasattr(self, 'webView') and self.webView:
            try:
                if self.webView.history().canGoBack():
                    print("✓ [NAV_BACK] Web geri gidiliyor...")
                    self.webView.back()
                else:
                    print("⚠ [NAV_BACK] Web geçmişinde geri gidilecek sayfa yok")
            except Exception as e:
                print(f"⚠ [NAV_BACK] Web geri hatası: {e}")
        else:
            self._go_up_directory()


    def _nav_forward(self):
        """Toolbar ileri: web açıksa web geçmişi, değilse ev klasörü."""
        if self.search_mode == "web" and hasattr(self, 'webView') and self.webView:
            try:
                if self.webView.history().canGoForward():
                    print("✓ [NAV_FORWARD] Web ileri gidiliyor...")
                    self.webView.forward()
                else:
                    print("⚠ [NAV_FORWARD] Web geçmişinde ileri gidilecek sayfa yok")
            except Exception as e:
                print(f"⚠ [NAV_FORWARD] Web ileri hatası: {e}")
        else:
            self._go_home_directory()

    def keyPressEvent(self, event):
        """Genel kısayollar (özellikle web tam ekran ESC çıkışı)."""
        try:
            if event.key() == Qt.Key_Escape:
                # Web sekmesi tam ekrandaysa ESC ile çık
                if self.isFullScreen() and getattr(self, "_in_web_fullscreen", False):
                    print("🖥️ [WEB_FS] ESC basıldı: tam ekrandan çık")
                    try:
                        if self.webView and self.webView.page() and QWebEnginePage is not None:
                            self.webView.page().triggerAction(QWebEnginePage.ExitFullScreen)
                    except Exception:
                        pass
                    # Eğer site event üretmezse fail-safe olarak UI'yi geri getir
                    try:
                        if self.isFullScreen():
                            self.showNormal()
                    except Exception:
                        pass
                    event.accept()
                    return

                # Video tam ekrandaysa ESC ile çık
                if getattr(self, "_in_video_fullscreen", False):
                    try:
                        self._exit_video_fullscreen()
                    except Exception:
                        pass
                    event.accept()
                    return

            # Video sayfasındayken F11 fullscreen toggle
            if event.key() == Qt.Key_F11:
                try:
                    # Web fullscreen aktifse öncelik: web fullscreen'den çık
                    if self.isFullScreen() and getattr(self, "_in_web_fullscreen", False):
                        self._web_exit_fullscreen()
                        event.accept()
                        return
                    if hasattr(self, "mainContentStack") and self.mainContentStack.currentIndex() == 1:
                        self._toggle_video_fullscreen()
                        event.accept()
                        return
                except Exception:
                    pass
            
            # Playback rate kısayolları (video modunda)
            if hasattr(self, "mainContentStack") and self.mainContentStack.currentIndex() == 1:
                # ] tuşu: Hızı artır
                if event.key() == Qt.Key_BracketRight:
                    try:
                        self._increase_playback_rate()
                        event.accept()
                        return
                    except Exception:
                        pass
                
                # [ tuşu: Hızı azalt
                if event.key() == Qt.Key_BracketLeft:
                    try:
                        self._decrease_playback_rate()
                        event.accept()
                        return
                    except Exception:
                        pass
                
                # \ veya = tuşu: Normal hız
                if event.key() in (Qt.Key_Backslash, Qt.Key_Equal):
                    try:
                        self._set_playback_rate_normal()
                        event.accept()
                        return
                    except Exception:
                        pass
        except Exception:
            pass

        super().keyPressEvent(event)

    def _volume_shortcut(self, delta: int):
        """Yukarı/aşağı kısayolu."""
        self._adjust_volume(delta)

    def _set_volume_shortcuts_enabled(self, enabled: bool):
        """Arama kutusuna odaklanınca ses kısayollarını kapat/aç."""
        for sc in (getattr(self, "shortcutVolumeUp", None), getattr(self, "shortcutVolumeDown", None)):
            if sc:
                sc.setEnabled(enabled)



    def _web_go_back(self):
        if self.webView and self.webView.history().canGoBack():
            self.webView.back()

    def _web_go_forward(self):
        if self.webView and self.webView.history().canGoForward():
            self.webView.forward()

    def _open_embedded_web(self, url: str, provider: str):
        """Internet butonlarından gömülü webi açar."""
        # Web platformuna geçildiğinde yerel müziği duraklat
        # (Aynı anda iki ses kaynağı çalışmasın)
        if self.mediaPlayer.state() in (QMediaPlayer.PlayingState, QMediaPlayer.PausedState):
            self.mediaPlayer.stop()
            print(f"🌐 {provider} platformuna geçildi - yerel müzik durduruldu")
        if hasattr(self, 'videoPlayer') and self.videoPlayer.state() != QMediaPlayer.StoppedState:
            self.videoPlayer.stop()

        if not self._ensure_webview(provider):
            QMessageBox.warning(self, "WebEngine Yok", "PyQt WebEngine yüklenemedi, iç tarayıcı açılamıyor. Lütfen 'python-pyqt5-webengine' paketini kurun.")
            return
        self._stop_web_media_playback()
        self.search_mode = "web"
        self._web_mode_activated_ts = time.time()
        self.search_provider = provider
        # Arama çubuğu kaldırıldı
        self.webView.setVisible(True)

        if self.mainContentStack:
            self.mainContentStack.setCurrentIndex(0)
        if hasattr(self, 'playlist_stack') and self.webView:
            if self.playlist_stack.indexOf(self.webView) == -1:
                self.playlist_stack.addWidget(self.webView)
            self.playlist_stack.setCurrentWidget(self.webView)
        
        # 2. YouTube Görsel Katman Onarımı: Z-Index
        self.webView.raise_()

        self.webView.raise_()
        if self.webView.page():
            try:
                self.webView.page().setAudioMuted(False)
            except Exception:
                pass

        self._web_playing = False
        self._web_audio_last_ts = 0.0
        self.update_play_button_state(False, source="web")
        self._set_visualizer_paused(True, fade=False)
        self._reset_visualizer_immediate()
        self._web_dsp_active = False
        self._web_pcm_seen = False
        self._force_web_mute = False
        self._set_web_audio_muted(False)
        
        # Web açıldığında mevcut ses ve monitor yakalamayı uygula
        self._apply_web_volume(self.volumeSlider.value())
        self._start_web_seek_poll()
        if hasattr(self, "webPosTimer") and not self.webPosTimer.isActive():
            self.webPosTimer.start()
        self._start_monitor_capture()
        if hasattr(self, "toolbar"):
            self._remove_web_close_button(self.toolbar)
        
        # Web kontrollerini göster
        if hasattr(self, 'web_controls'):
            for w in self.web_controls:
                w.setVisible(True)
        
        # Web butonlarını GÖSTER
        if hasattr(self, 'webDownloadAction') and self.webDownloadAction:
            self.webDownloadAction.setVisible(True)
            self.webDownloadAction.setEnabled(True)
            
        # [ROBUSTNESS] Layout bazen hemen güncellenmiyor, biraz bekleyip zorla gösterelim
        QTimer.singleShot(100, self._force_web_buttons_layout)
        
        self.webView.load(QUrl(url))
        
    def _force_web_buttons_layout(self):
        """Web butonlarının görünürlüğünü ve layout'unu zorla güncelle."""
        if hasattr(self, 'webDownloadAction'):
            self.webDownloadAction.setVisible(True)

    def _web_download(self):
        """Web sayfasından indirmeyi başlat."""
        print("🔽 _web_download çağrıldı")
        if not self.webView:
            print("✗ webView yok!")
            return
        try:
            url = self.webView.url().toString()
            print(f"📌 URL: {url}")
            if "youtube" not in url and "youtu.be" not in url:
                QMessageBox.warning(self, "Uyarı", "Şu an sadece YouTube/YouTube Music desteklenmektedir.")
                return
            
            # Video başlığını al (varsa)
            current_title = self.webView.title() or "Video"
            print(f"📝 Başlık: {current_title}")
            
            # Süreyi hesapla (position slider'dan)
            duration_sec = self.positionSlider.maximum() / 1000.0 if hasattr(self, 'positionSlider') else 0
            print(f"⏱️ Süre: {duration_sec}s")
            
            # DownloadDialog'u aç
            dlg = DownloadDialog(self, video_title=current_title, duration=duration_sec)
            print("✓ Dialog açıldı")
            if dlg.exec_() == QDialog.Accepted:
                print("✓ Dialog onaylandı")
                result = dlg.get_data()
                print(f"📦 Sonuç: {result}")
                if not result:
                    print("✗ Sonuç boş!")
                    return
                
                action = result.get('action')
                print(f"🎬 Action: {action}")
                
                if action == 'download_video':
                    # Video indirme
                    fmt = result.get('fid', 'best')
                    self._start_download(url, f"fmt:{fmt}", QStandardPaths.writableLocation(QStandardPaths.MoviesLocation))
                    
                elif action == 'download_audio':
                    # Ses indirme (klasör seçilmiş)
                    fmt = result.get('format', 'mp3')
                    quality = result.get('quality', '192')
                    output_folder = result.get('output_folder')
                    print(f"🎵 Ses indirme: {fmt} @ {quality}kbps -> {output_folder}")
                    if output_folder:
                        download_fmt = f"audio_extract|{fmt}|{quality}"
                        self._start_download(url, download_fmt, output_folder)
                    
                elif action == 'extract_audio':
                    # Ses çıkart (varsayılan klasör)
                    fmt = result.get('format', 'mp3')
                    quality = result.get('quality', '192')
                    download_fmt = f"audio_extract|{fmt}|{quality}"
                    print(f"🎵 Ses çıkart: {fmt} @ {quality}kbps")
                    self._start_download(url, download_fmt, QStandardPaths.writableLocation(QStandardPaths.MusicLocation))
            else:
                print("✗ Dialog iptal edildi")
                    
        except Exception as e:
            import traceback
            print(f"Download error: {e}")
            print(traceback.format_exc())
            QMessageBox.critical(self, "Hata", f"İndirme başlatılamadı:\n{e}")
    
    def _toggle_miniplayer_mode(self):
        """Normal mode ve Miniplayer modu arasında geçiş yap."""
        if getattr(self, '_in_miniplayer_mode', False):
            # Exit Miniplayer
            self._in_miniplayer_mode = False
            self.setWindowFlags(Qt.Window) # Reset flags
            self.show()
            
            # Restore UI elements
            if hasattr(self, 'side_panel'): self.side_panel.show()
            if hasattr(self, 'fileLabel'): self.fileLabel.show()
            if hasattr(self, 'menuBar'): self.menuBar().setVisible(True)
            if hasattr(self, 'toolbar'): self.toolbar.setVisible(True)
            if hasattr(self, 'bottom_widget'): self.bottom_widget.show() # Show regular bottom bar
            
            # Resize back to reasonable size if too small
            if self.width() < 800:
                self.resize(1000, 700)
                
            # If we were in video page, ensure video output is corrected
            if self.mainContentStack.currentWidget() == self.video_container:
                 self.video_output_widget.set_scale_mode(self.video_output_widget.scale_mode)

        else:
            # Enter Miniplayer
            # Only allow if in Video Page
            if self.mainContentStack.currentWidget() != self.video_container:
                # Switch to video page if video is loaded, else maybe ignore?
                # User specifically asked for this for video.
                self.mainContentStack.setCurrentWidget(self.video_container)

            self._in_miniplayer_mode = True
            
            # Hide surrounding UI to just show video
            if hasattr(self, 'side_panel'): self.side_panel.hide()
            if hasattr(self, 'fileLabel'): self.fileLabel.hide()
            if hasattr(self, 'menuBar'): self.menuBar().setVisible(False)
            if hasattr(self, 'toolbar'): self.toolbar.setVisible(False)
            if hasattr(self, 'bottom_widget'): self.bottom_widget.hide() # Hide bottom bar, use HUD
            
            # Set Always on Top and frameless/compact
            self.setWindowFlags(Qt.Window | Qt.CustomizeWindowHint | Qt.WindowTitleHint | Qt.WindowStaysOnTopHint)
            self.show()
            
            # Resize to small size
            self.resize(480, 270)
            
            # Ensure layout is tight
            if hasattr(self, 'centralWidget') and self.centralWidget():
                self.centralWidget().layout().setContentsMargins(0, 0, 0, 0)

    def _start_download(self, url, fmt, output_folder):
        """İndirme işlemini başlat."""
        print(f"🚀 _start_download çağrıldı:")
        print(f"   URL: {url}")
        print(f"   Format: {fmt}")
        print(f"   Klasör: {output_folder}")
        try:
            from download_dialog import DownloadWorker
            self.dl_worker = DownloadWorker(url, fmt, output_folder)
            print("✓ DownloadWorker oluşturuldu")
            
            # Progress dialog
            prog = DownloadProgressDialog(self.dl_worker, self)
            print("✓ Progress dialog oluşturuldu")
            self.dl_worker.finished_sig.connect(lambda success, msg: self._on_download_complete(success, msg))
            print("✓ Signal bağlandı")
            self.dl_worker.start()
            print("✓ Worker başlatıldı")
            prog.exec_()
            print("✓ Progress dialog tamamlandı")
            
        except Exception as e:
            import traceback
            print(f"Download error: {e}")
            print(traceback.format_exc())
            QMessageBox.critical(self, "Hata", f"İndirme başlatılamadı:\n{e}")
    
    def _on_download_complete(self, success, message):
        """İndirme tamamlandığında bildirim göster."""
        if success:
            QMessageBox.information(self, "Başarılı", message)
            self.statusBar().showMessage("İndirme tamamlandı!", 3000)
        else:
            QMessageBox.warning(self, "Hata", f"İndirme başarısız:\n{message}")
            self.statusBar().showMessage("İndirme hatası", 3000)

    def _close_embedded_web(self):
        """Gömülü web'i kapatıp playlist görünümüne dön."""
        self.search_mode = "local"
        self.search_provider = None
        # Arama çubuğu kaldırıldı
        self._web_playing = False
        self._web_audio_last_ts = 0.0
        self._stop_web_media_playback()
        if hasattr(self, "webPosTimer") and self.webPosTimer.isActive():
            self.webPosTimer.stop()
        self._web_dsp_active = False
        self._web_pcm_seen = False
        self._set_web_audio_muted(False)
        if self.audio_engine:
            self.audio_engine.stop_web_audio()
        
        # Phase 6: Strict Termination of Monitor Capture
        self._stop_monitor_capture()
        
        # Web kontrollerini gizle
        if hasattr(self, 'web_controls'):
            for w in self.web_controls:
                w.setVisible(False)
        
        # Web butonlarını GİZLE
        if hasattr(self, 'webDownloadAction') and self.webDownloadAction:
            self.webDownloadAction.setVisible(False)

        if self.webView:
            if self.webView.page():
                self.webView.page().setAudioMuted(True) # 3. Sekme Odaklı Ses Yönetimi
            try:
                self.webView.stop()
                self.webView.setUrl(QUrl("about:blank"))
            except Exception:
                pass
            self.webView.setVisible(False)

        if hasattr(self, 'playlist_stack') and self.playlistWidget:
            self.playlist_stack.setCurrentWidget(self.playlistWidget)
        if hasattr(self, "mainContentStack") and self.mainContentStack:
            self.mainContentStack.setCurrentIndex(0)
        self._stop_monitor_capture()
        self._stop_web_seek_poll()
        
        # 1. Müzik Sekmesi Kilidi: Yerel oynatıcıyı resetle
        if hasattr(self, 'mediaPlayer'):
            self.mediaPlayer.stop()
            
        local_playing = False
        if self.audio_engine and self.audio_engine.media_player:
            local_playing = (self.audio_engine.media_player.state() == QMediaPlayer.PlayingState)
        self._set_visualizer_paused(not local_playing, fade=True)
        self._reset_visualizer_immediate() # 3. Otomatik Reset

    def _process_web_audio(self, audio_data):
        """Web platformlarından gelen ses verisi visualizer'a gönder."""
        # 4. Küresel Ses Senkronizasyonu: Yerel moddaysak web verisini yoksay
        if self.search_mode != "web":
            return
        # Web listen-only: spektrum verisini işleme
        return

    @pyqtSlot(list, int, int)
    def _on_web_audio_pcm(self, samples, sample_rate, channels):
        if self.search_mode != "web":
            return
        if not getattr(self, "_web_pcm_seen", False):
            self._web_pcm_seen = True
            self._stop_monitor_capture()
        self._emit_pcm_to_visualizer(samples, sample_rate, channels)

    def _ensure_webview(self, provider=None):
        """WebEngine'i sonradan kurulduysa dinamik yükle ve yerleştir."""
        if self.webView:
            return True
        # Güvenli web bileşeni hazırsa onu kullan
        if getattr(self, "web_view", None):
            self.webView = self.web_view
            if hasattr(self, "playlist_stack"):
                if self.playlist_stack.indexOf(self.webView) == -1:
                    self.playlist_stack.addWidget(self.webView)
            elif self.mainContentStack:
                if self.mainContentStack.indexOf(self.webView) == -1:
                    self.mainContentStack.addWidget(self.webView)
            return True
        QEView = _import_webengine()
        if QEView is None:
            return False
        try:
            self.webView = QEView()
            self.webView.setVisible(False)
            try:
                from PyQt5.QtWidgets import QSizePolicy
                self.webView.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
            except Exception:
                pass
            try:
                from PyQt5.QtWebEngineWidgets import QWebEngineSettings  # type: ignore
                self.webView.settings().setAttribute(QWebEngineSettings.FullScreenSupportEnabled, True)
                self.webView.settings().setAttribute(QWebEngineSettings.WebGLEnabled, True)
                self.webView.settings().setAttribute(QWebEngineSettings.Accelerated2dCanvasEnabled, True)
                self.webView.settings().setAttribute(QWebEngineSettings.PluginsEnabled, True)
                self.webView.settings().setAttribute(QWebEngineSettings.PlaybackRequiresUserGesture, True)
                self.webView.page().fullScreenRequested.connect(self._handle_fullscreen_request)
                self.webView.fullScreenRequested.connect(self._handle_fullscreen_request)
            except Exception:
                pass
            # QWebChannel köprüsünü kur
            try:
                import web_engine_handler
                web_engine_handler.setup_web_channel(self.webView.page(), self)
            except Exception as e:
                print(f"QWebChannel köprüsü kurulamadı: {e}")
            try:
                from PyQt5.QtWebEngineWidgets import QWebEngineScript
                self._install_webchannel_script(QWebEngineScript, page=self.webView.page())
            except Exception:
                pass
            self.webView.loadFinished.connect(self._on_page_loaded)
            self.webView.loadFinished.connect(lambda ok: self._apply_webview_theme())
            self.webView.titleChanged.connect(self._on_web_title_changed)
            self.webView.urlChanged.connect(self._on_web_url_changed)

            # Web fullscreen çıkış butonu (toolbar gizliyken de erişilebilir)
            try:
                self.web_fs_exit_btn = QToolButton(self.webView)
                self.web_fs_exit_btn.setAutoRaise(True)
                self.web_fs_exit_btn.setToolTip("Tam ekrandan çık (ESC/F11)")
                self.web_fs_exit_btn.setIcon(self.style().standardIcon(QStyle.SP_TitleBarNormalButton))
                self.web_fs_exit_btn.setVisible(False)
                self.web_fs_exit_btn.clicked.connect(self._web_exit_fullscreen)
                self.web_fs_exit_btn.setStyleSheet(
                    "QToolButton { background: rgba(0,0,0,120); border: 1px solid rgba(255,255,255,80); border-radius: 14px; padding: 6px; }"
                    "QToolButton:hover { background: rgba(0,0,0,170); }"
                    "QToolButton:pressed { background: rgba(64,196,255,120); }"
                )
                self.web_fs_exit_btn.raise_()
            except Exception:
                self.web_fs_exit_btn = None
            if hasattr(self, "playlist_stack"):
                self.playlist_stack.addWidget(self.webView)
            elif self.mainContentStack:
                self.mainContentStack.addWidget(self.webView)
            return True
        except Exception as e:
            print(f"WebEngine oluşturulamadı: {e}")
            self.webView = None
            return False

    def _is_system_dark(self) -> bool:
        """Palet parlaklığından basit koyu/açık tespiti."""
        pal = QApplication.palette()
        return pal.color(QPalette.Window).value() < 128

    def _set_web_audio_muted(self, muted: bool):
        if not self.webView or not self.webView.page():
            return
        mval = "true" if muted else "false"
        try:
            self.webView.page().setAudioMuted(muted)
        except Exception:
            pass
        js = f"""
        (function() {{
            try {{
                if (window.__angollaSetMuteWebAudio) {{
                    window.__angollaSetMuteWebAudio({mval});
                }} else {{
                    window.__angollaMuteWebAudio = {mval};

            elif mode == 'web':
                # Web modunda görselleştirme ana widget üzerinden çalışır
                try:
                    if hasattr(self, 'bottom_vis_stack') and self.bottom_vis_stack:
                        self.bottom_vis_stack.setCurrentIndex(0)
                except Exception:
                    pass
                    if (window.__angollaOutputGain) {{
                        window.__angollaOutputGain.gain.value = {0.0 if muted else 1.0};
                    }}
                    if (!window.__angollaOutputGain) {{
                        try {{
                            var els = document.querySelectorAll('video, audio');
                            for (var i = 0; i < els.length; i++) {{
                                var el = els[i];
                                if ({mval}) {{
                                    if (typeof el.__angollaPrevVolume !== 'number') {{
                                        el.__angollaPrevVolume = el.volume;
                                    }}
                                    el.muted = true;
                                    el.volume = 0;
                                }} else {{
                                    el.muted = false;
                                    if (typeof el.__angollaPrevVolume === 'number') {{
                                        el.volume = el.__angollaPrevVolume;
                                    }}
                                }}
                            }}
                        }} catch (e) {{}}
                    }}
                }}
            }} catch (e) {{}}
        }})();
        """
        try:
            self.webView.page().runJavaScript(js)
        except Exception:
            pass

    def _stop_web_media_playback(self):
        """Web sayfasındaki tüm medya öğelerini durdur."""
        if not self.webView:
            return
        js = """
        (function() {
            var els = document.querySelectorAll('video, audio');
            for (var i = 0; i < els.length; i++) {
                try { els[i].pause(); } catch (e) {}
            }
        })();
        """
        try:
            self.webView.page().runJavaScript(js)
        except Exception:
            pass
        self._web_playing = False
        self.update_play_button_state(False, source="web")

    def _web_play_pause(self):
        """Web modunda oynat/durdur komutu gönder."""
        js = """
        (function() {
            try {
                window.__angollaUserGestureTS = Date.now();
                window.__angollaAllowPlayUntil = Date.now() + 6000;
                if (window.__angollaInitAudioFromGesture) {
                    window.__angollaInitAudioFromGesture();
                }
            } catch (e) {}
            var v = document.querySelector('video') || document.querySelector('audio');
            if (v) {
                if (v.paused) v.play(); else v.pause();
            } else {
                // Spotify özel
                var btn = document.querySelector('[data-testid="control-button-playpause"]');
                if (btn) btn.click();
                
                // Deezer özel
                var dbtn = document.querySelector('[data-testid="play_button_play"]'); 
                if(!dbtn) dbtn = document.querySelector('[data-testid="play_button_pause"]');
                if (dbtn) dbtn.click();
            }
        })();
        """
        if self.webView:
            self.webView.page().runJavaScript(js)

    def _web_next(self):
        """Web modunda ileri komutu gönder."""
        js = """
        (function() {
            // YouTube Music
            var ytmBtn = document.querySelector('.next-button') || document.querySelector('[aria-label="Next song"]');
            if (ytmBtn) { ytmBtn.click(); return; }

            // YouTube (Standard)
            var ybtn = document.querySelector('.ytp-next-button');
            if (ybtn) { ybtn.click(); return; }
            
            // Spotify
            var sbtn = document.querySelector('[data-testid="control-button-skip-forward"]');
            if (sbtn) { sbtn.click(); return; }
            
            // Deezer
            var dbtn = document.querySelector('[data-testid="next_track_button"]');
            if (dbtn) { dbtn.click(); return; }
            
            // SoundCloud
            var scbtn = document.querySelector('.skipControl__next');
            if (scbtn) { scbtn.click(); return; }
        })();
        """
        if self.webView:
            self.webView.page().runJavaScript(js)

    def _web_seek(self, seconds):
        """Web oynatıcıyı belirtilen saniyeye al (YouTube API + HTML5)."""
        js = f"""
        (function() {{
            // 1. YouTube API Check
            var player = document.getElementById('movie_player');
            if (player && typeof player.seekTo === 'function') {{
                player.seekTo({seconds}, true);
                return;
            }}
            
            // 2. HTML5 Fallback
            var v = document.querySelector('video') || document.querySelector('audio');
            if (v) {{
                v.currentTime = {seconds};
            }}
        }})();
        """
        if self.webView:
            self.webView.page().runJavaScript(js)

    def _format_time(self, ms):
        """Milisaniyeyi 'mm:ss' veya 'H:mm:ss' formatına çevirir."""
        try:
            total_seconds = max(0, int(ms) // 1000)
        except Exception:
            total_seconds = 0

        h = total_seconds // 3600
        m = (total_seconds % 3600) // 60
        s = total_seconds % 60

        if h > 0:
            return f"{h:02d}:{m:02d}:{s:02d}"
        return f"{m:02d}:{s:02d}"

    def _poll_web_status(self):
        """Web sayfasındaki medya durumunu (süre, pozisyon) sorgula."""
        if not self.webView or self.search_mode != "web":
            return
            
        js = """
        (function() {
            // 4. KÜRESEL KONTROLLER (Düzeltme)
            // Reklam sırasında durumu güncelleme ki sayaç şaşmasın
            var player = document.querySelector('.html5-video-player');
            if (player && player.classList.contains('ad-showing')) {
                return null; 
            }

            var debug = [];
            
            function log(msg) { debug.push(msg); }

            // Helper: duration geçerli mi?
            function isValid(v) {
                return v && v.duration > 0 && !isNaN(v.duration) && isFinite(v.duration);
            }

            // 1. YouTube API (global movie_player) - En sağlam yöntem
            // YouTube Music genelde window.movie_player kullanır
            var mp = document.getElementById('movie_player') || window.movie_player;
            if (mp && typeof mp.getCurrentTime === 'function' && typeof mp.getDuration === 'function') {
                var d = mp.getDuration();
                var c = mp.getCurrentTime();
                log("Found movie_player. Dur: " + d + " Curr: " + c);
                if (d > 0) {
                    var paused = (typeof mp.getPlayerState === 'function') ? (mp.getPlayerState() !== 1) : true;
                    return [c, d, paused, debug.join('|')];
                }
            } else {
                log("No valid movie_player found");
            }

            // 2. Video Elementlerini Tara
            var videos = document.getElementsByTagName('video');
            log("Found " + videos.length + " video elements");
            
            var bestV = null;
            
            for (var i = 0; i < videos.length; i++) {
                var v = videos[i];
                log("V" + i + ": src=" + v.currentSrc.substr(0, 20) + " dur=" + v.duration + " paused=" + v.paused);
                
                if (isValid(v)) {
                    if (!v.paused) { return [v.currentTime, v.duration, v.paused, debug.join('|'), videos.length]; }
                    if (!bestV) { bestV = v; }
                }
            }
            
            if (bestV) {
                return [bestV.currentTime, bestV.duration, bestV.paused, debug.join('|'), videos.length];
            }
            
            return [0, 0, true, debug.join('|'), videos.length];
        })();
        """
        def callback(result):
            if result is None:
                self._on_web_playback_state(True, False, True, True)
                return
            if result and isinstance(result, list) and len(result) >= 4:
                curr = float(result[0] or 0)
                total = float(result[1] or 0)
                is_paused = bool(result[2])
                debug_log = str(result[3])
                video_count = int(result[4] if len(result) > 4 else 0)
                
                # Debug çıktısını terminale bas (User isteği)
                if int(total) == 0:
                     pass

                # Toplam süre geçerli mi?
                if total > 0:
                    # Slider max güncelle
                    new_max = int(total * 1000)
                    if self.positionSlider.maximum() != new_max:
                        self.positionSlider.setMaximum(new_max)
                        
                    # Kullanıcı elle kaydırmıyorsa güncelle
                    if not self.positionSlider.isSliderDown():
                        val = int(curr * 1000)
                        self.positionSlider.setValue(min(val, new_max))
                    
                    # Label update
                    t_curr = self._format_time(int(curr * 1000))
                    t_total = self._format_time(int(total * 1000))
                    self.lblCurrentTime.setText(t_curr)
                    self.lblTotalTime.setText(t_total)
                else:
                    self.lblCurrentTime.setText("00:00")
                    self.lblTotalTime.setText("...")

                # 4. Play Buton Senkronizasyonu
                if self.search_mode == "web":
                    self.update_play_button_state(not is_paused, source="web")
                ended = total > 0 and curr >= max(0.0, total - 0.25)
                self._on_web_playback_state(is_paused, ended, False, False, video_count=video_count)
            else:
                # Beklenmeyen dönüş formatı
                if result:
                    pass
                    
        self.webView.page().runJavaScript(js, callback)

    def _web_prev(self):
        """Web modunda geri komutu gönder."""
        js = """
        (function() {
            // YouTube Music
            var ytmBtn = document.querySelector('.previous-button') || document.querySelector('[aria-label="Previous song"]');
            if (ytmBtn) { ytmBtn.click(); return; }

            // YouTube (Standard)
            var ybtn = document.querySelector('.ytp-prev-button');
            if (ybtn && ybtn.getAttribute('aria-disabled') !== 'true') { 
                ybtn.click(); 
                return; 
            }
            
            // Spotify
            var sbtn = document.querySelector('[data-testid="control-button-skip-back"]');
            if (sbtn) { sbtn.click(); return; }
            
            // Deezer
            var dbtn = document.querySelector('[data-testid="prev_track_button"]');
            if (dbtn) { dbtn.click(); return; }
            
            // SoundCloud
            var scbtn = document.querySelector('.skipControl__previous');
            if (scbtn) { scbtn.click(); return; }
            
            // Fallback
            window.history.back();
        })();
        """
        if self.webView:
            self.webView.page().runJavaScript(js)

    def _apply_webview_theme(self):
        """WebView içeriğine basit koyu tema enjekte et (sisteme göre)."""
        if not self.webView:
            return
        dark = self._is_system_dark()
        css = """
        html, body {
            background-color: #0f0f10 !important;
            color: #e4e4e4 !important;
        }
        """
        script = f"""
        (() => {{
            const id = '__angolla_web_theme';
            let style = document.getElementById(id);
            if ({str(dark).lower()}) {{
                if (!style) {{
                    style = document.createElement('style');
                    style.id = id;
                    document.documentElement.appendChild(style);
                }}
                style.textContent = `{css}`;
            }} else if (style) {{
                style.remove();
            }}
        }})();
        """
        try:
            self.webView.page().runJavaScript(script)
        except Exception:
            pass

    def _apply_album_color_theme(self, path: Optional[str]):
        """Kapak rengini album paneli, alt bar ve ana alan üzerine hafifçe uygula."""
        base_album = "#263238"
        base_bottom = "#2A2A2A"
        bottom = self.findChild(QWidget, "bottomWidget")
        central = self.findChild(QWidget, "mainCentral")

        if not path or not os.path.exists(path):
            style = f"""
            QWidget#bottomWidget {{ background-color: {base_bottom}; border-top: 1px solid #444; }}
            QWidget#mainCentral {{ background-color: {base_bottom}; }}
            """
            if bottom:
                bottom.setStyleSheet(style)
            if central:
                central.setStyleSheet(style)
            return

        cover_path = None
        folder = os.path.dirname(path)
        for name in ("cover.jpg", "folder.jpg", "cover.png", "album.png", "cover.jpeg", "folder.jpeg"):
            p = os.path.join(folder, name)
            if os.path.exists(p):
                cover_path = p
                break

        if cover_path:
            dominant = InfoDisplayWidget.extract_dominant_color(cover_path)
        else:
            dominant = None

        if dominant is None:
            return

        rgba = (dominant.red(), dominant.green(), dominant.blue(), 160)
        style = f"""
        QWidget#bottomWidget {{
            background-color: rgba({rgba[0]}, {rgba[1]}, {rgba[2]}, {max(30, rgba[3]-20)});
            border-top: 1px solid #444;
        }}
        QWidget#mainCentral {{
            background-color: rgba({rgba[0]}, {rgba[1]}, {rgba[2]}, {max(40, rgba[3]-40)});
        }}
        """
        if bottom:
            bottom.setStyleSheet(style)
        if central:
            central.setStyleSheet(style)

    def _apply_album_color_theme(self, path: Optional[str]):
        """Albüm kapağından renk alıp album paneli ve alt bar'a yumuşak renk uygula."""
        base_album = "#263238"
        base_bottom = "#2A2A2A"
        bottom = self.findChild(QWidget, "bottomWidget")

        if not path or not os.path.exists(path):
            style = f"""
            QWidget#bottomWidget {{ background-color: {base_bottom}; border-top: 1px solid #444; }}
            """
            if bottom:
                bottom.setStyleSheet(style)
            return

        # Kapak dosyası ara
        cover_path = None
        folder = os.path.dirname(path)
        for name in ("cover.jpg", "folder.jpg", "cover.png", "album.png"):
            p = os.path.join(folder, name)
            if os.path.exists(p):
                cover_path = p
                break

        if cover_path:
            dominant = InfoDisplayWidget.extract_dominant_color(cover_path)
        else:
            dominant = None

        if dominant is None:
            return

        rgba = (dominant.red(), dominant.green(), dominant.blue(), 70)
        style = f"""
        QWidget#bottomWidget {{
            background-color: rgba({rgba[0]}, {rgba[1]}, {rgba[2]}, {max(30, rgba[3]-20)});
            border-top: 1px solid #444;
        }}
        """
        if bottom:
            bottom.setStyleSheet(style)

    def menu_add_files(self):
        files, _ = QFileDialog.getOpenFileNames(
            self, "Müzik Dosyası Ekle", QDir.homePath(),
            "Müzik Dosyaları (*.mp3 *.flac *.ogg *.m4a *.m4b *.mp4 *.wav *.aac *.wma *.opus)"
        )
        if files:
            self._add_files_to_playlist(files, add_to_library=False)

    def menu_add_folder(self):
        # Artık dosya ağacından seçim yapılıyor; harici dialogu kapat
        return

    def playlist_double_clicked(self, index):
        try:
            self._set_next_track_change_reason("manual_select")
        except Exception:
            pass
        self._play_index(index.row())

    def library_double_clicked(self, index: QModelIndex):
        row = index.row()
        path = self.libraryTableWidget.item(row, 0).data(Qt.UserRole)
        if path:
            for i in range(self.playlistWidget.count()):
                if self.playlistWidget.item(i).data(Qt.UserRole) == path:
                    try:
                        self._set_next_track_change_reason("manual_select")
                    except Exception:
                        pass
                    self._play_index(i)
                    return
            self._add_media(path, add_to_library=False)
            try:
                self._set_next_track_change_reason("manual_select")
            except Exception:
                pass
            self._play_index(self.playlist.mediaCount() - 1)

    # --------------------------------------------------------------
    #  TERCIHLER PENCERESINI AÇ
    # --------------------------------------------------------------
    def show_preferences(self):
        dialog = PreferencesDialog(self)
        dialog.exec_()

    # --------------------------------------------------------------
    # HAKKINDA / INFO DİYALOĞU (Eksik olan fonksiyon ekleniyor)
    # --------------------------------------------------------------
    def show_about(self):
        from PyQt5.QtWidgets import QMessageBox
        QMessageBox.information(
            self,
            "Angolla Music Player",
            "🎵 Angolla Music Player\n\n"
            "Angolla ilhamlı gelişmiş PyQt5 müzik oynatıcı.\n"
            "Geliştirici: Muhammet Dali\n"
            "Sürüm: 1.0\n\n"
            "🎹 Kısayollar:\n"
            "- F1: Önceki parça\n"
            "- F2: Sonraki parça\n"
            "- F3: 5 sn geri sar\n"
            "- F4: 5 sn ileri sar\n"
            "- Ctrl+V: Görselleştirme penceresi\n"
            "- Ctrl+,: Tercihler\n"
            "- Ctrl+H: Hakkında"
        )



    # ------------------------------------------------------------------#
    # SES VERİSİ / GERÇEK FFT SPEKTRUM
    # ------------------------------------------------------------------#

    # process_audio_buffer removed (obsolete with sounddevice direct link)

    def _on_viz_data_ready(self, band_vals, pcm_raw):
        """Update UI with pre-calculated FFT data from thread"""
        # Phase 4: Allow visualizer in web mode
        # (pcm_raw now comes from GlobalAudioEngine._web_audio_callback)
            
        self._last_pcm_data = pcm_raw # For ProjectM
        
        num_bars = len(band_vals)
        if not hasattr(self, "band_dynamic_max") or len(self.band_dynamic_max) != num_bars:
            self.band_dynamic_max = [1e-6] * num_bars
        
        is_web = getattr(self, "search_mode", None) == "web"
        decay = 0.92 if is_web else 0.96
        if is_web:
            decay = 0.92  # Web modunda tepelerin daha hızlı düşmesi için (seri hareket)
        normalized = []
        for i, val in enumerate(band_vals):
            prev = self.band_dynamic_max[i] * decay
            peak = max(prev, val)
            self.band_dynamic_max[i] = peak
            normalized.append(min(1.0, val / (peak + 1e-6)))
        
        # Dispatch to widgets
        intensity = sum(normalized) / num_bars if num_bars > 0 else 0
        self.send_visual_data(min(1.0, intensity * 1.5), normalized)


    def send_visual_data(self, intensity, band_vals):
        """Görselleştirme verilerini widget'lara gönder"""
        # Web modunda visualizer'ı zorla aktif tut
        is_web = getattr(self, "search_mode", None) == "web"
        if getattr(self, "_visualizer_paused", False) and not is_web:
            return
        # Ana pencere
        if self.vis_widget_main_window and hasattr(self.vis_widget_main_window, 'update_sound_data'):
            self.vis_widget_main_window.update_sound_data(intensity, band_vals)
        
        # Tam ekran pencere
        if self.vis_window and hasattr(self.vis_window, 'visualizationWidget'):
            if hasattr(self.vis_window.visualizationWidget, 'update_sound_data'):
                self.vis_window.visualizationWidget.update_sound_data(intensity, band_vals)
        
        # ProjectM'e de gönder (eğer aktifse)
        if self.vis_window and hasattr(self.vis_window, 'is_projectm') and self.vis_window.is_projectm:
            if hasattr(self.vis_window.visualizationWidget, 'consume_audio_data'):
                try:
                    # PCM verisi gönder - 16-bit stereo format
                    if hasattr(self, '_last_pcm_data') and self._last_pcm_data:
                        # NumPy array'e çevir (ProjectM consume_audio_data int16 array bekliyor)
                        pcm_array = np.frombuffer(self._last_pcm_data, dtype=np.int16)
                        self.vis_window.visualizationWidget.consume_audio_data(pcm_array)
                except Exception as e:
                    # İlk hatada log, sonra sessiz
                    if not hasattr(self, '_projectm_audio_error_logged'):
                        print(f"⚠ ProjectM ses besleme hatası: {e}")
                        self._projectm_audio_error_logged = True

    def _set_visualizer_paused(self, paused: bool, fade: bool = True):
        """Visualizer guncellemelerini durdur/devam ettir."""
        self._visualizer_paused = bool(paused)
        if self.vis_widget_main_window and hasattr(self.vis_widget_main_window, 'set_visualizer_paused'):
            self.vis_widget_main_window.set_visualizer_paused(self._visualizer_paused, fade)
        if self.vis_window and hasattr(self.vis_window, 'visualizationWidget'):
            widget = self.vis_window.visualizationWidget
            if hasattr(widget, 'set_visualizer_paused'):
                widget.set_visualizer_paused(self._visualizer_paused, fade)

    def _reset_visualizer_immediate(self):
        """Visualizer verisini aninda sifirla."""
        if self.vis_widget_main_window and hasattr(self.vis_widget_main_window, 'reset_visualizer'):
            self.vis_widget_main_window.reset_visualizer()
        if self.vis_window and hasattr(self.vis_window, 'visualizationWidget'):
            widget = self.vis_window.visualizationWidget
            if hasattr(widget, 'reset_visualizer'):
                widget.reset_visualizer()

    @pyqtSlot(bool)
    def _on_web_video_playing(self, playing: bool):
        if self.search_mode != "web":
            return
        self._web_playing = bool(playing)
        if self._web_playing:
            self._web_playback_last_active_ts = time.time()
            if hasattr(self, "webPosTimer") and not self.webPosTimer.isActive():
                self.webPosTimer.start()
            if hasattr(self, "web_seek_timer") and not self.web_seek_timer.isActive():
                self._start_web_seek_poll()
            if hasattr(self, 'mediaPlayer') and self.mediaPlayer.state() == QMediaPlayer.PlayingState:
                self.mediaPlayer.stop()
            self._set_visualizer_paused(False, fade=False)
        else:
            if self.audio_engine:
                self.audio_engine.stop_web_audio()


    def _start_fallback_visualizer(self):
        """QAudioProbe çalışmıyorsa fallback visualizer başlat"""
        if not hasattr(self, 'fallback_timer'):
            from PyQt5.QtCore import QTimer
            self.fallback_timer = QTimer(self)
            self.fallback_timer.timeout.connect(self._fallback_visual_update)
        
        if not self.fallback_timer.isActive():
            print("⚠️ QAudioProbe ses verisi göndermiyor - Fallback visualizer aktif")
            self.fallback_timer.start(33)  # ~30 FPS
    
    def _stop_fallback_visualizer(self):
        """Fallback visualizer'ı durdur"""
        if hasattr(self, 'fallback_timer') and self.fallback_timer.isActive():
            self.fallback_timer.stop()
    
    def _fallback_visual_update(self):
        """Fallback: Simüle edilmiş ses verisi üret"""
        import random
        import math
        
        # Müzik çalıyor mu kontrol et
        if self.mediaPlayer.state() != QMediaPlayer.PlayingState:
            return
        
        # 3 saniye sonra probe çalışıyorsa fallback'i kapat
        if self.probe_call_count > 3:
            self._stop_fallback_visualizer()
            print("✓ QAudioProbe çalışmaya başladı - Fallback kapatıldı")
            return
        
        # Simüle edilmiş 96-band spektrum verisi
        num_bars = 96
        band_vals = []
        
        # Sentetik spektrum: Bass güçlü, treble zayıf (gerçekçi)
        base_intensity = 0.5 + random.random() * 0.3
        for i in range(num_bars):
            # Logaritmik azalma (bass → treble)
            freq_factor = 1.0 - (i / num_bars) * 0.7
            # Rastgele varyasyon (ritim simülasyonu)
            random_variation = 0.7 + random.random() * 0.6
            # Sinüsoidal dalgalanma (müzikal ritim)
            time_phase = (self.mediaPlayer.position() / 100.0) % (2 * math.pi)
            sine_wave = 0.5 + 0.5 * math.sin(time_phase + i * 0.1)
            
            val = base_intensity * freq_factor * random_variation * sine_wave
            band_vals.append(val)
        
        # Intensity hesapla (bass-weighted)
        intensity = sum(band_vals[:20]) / 20.0
        
        # Görselleştirmelere gönder
        self.send_visual_data(intensity, band_vals)


    # ------------------------------------------------------------------#
    # AYARLAR / KAYDET / YÜKLE
    # ------------------------------------------------------------------#

    def set_theme(self, name, save=True):
        if name not in self.themes:
            return
        self.theme = name
        if save:
            self.config_data["theme"] = name

        # Tema modunu al (Varsayılan: Koyu)
        mode = self.config_data.get("theme_mode", "Koyu")
        
        # Temel renkleri al
        primary_color, default_text, default_bg = self.themes[name]
        
        # Stil oluştur (Modular)
        style = self._get_theme_stylesheet(mode, primary_color, default_text, default_bg)
        
        # Tüm uygulamaya uygula (Global)
        self.setStyleSheet(style)
        # QApplication.instance().setStyleSheet(style) # Bazen çakışma yapabilir, self tercih edilir

        # Altbar gradient ve transparan arka planını tema rengine göre güncelle
        if hasattr(self, 'bottom_widget') and self.bottom_widget:
            # Tema rengi için gradient oluştur
            primary_rgb = QColor(primary_color)
            bg_rgb = QColor(default_bg)
            
            # Gradient için renk geçişi hesapla (koyu/açık tema uyumlu)
            if mode == "Koyu":  # Koyu tema
                grad_start = f"rgba({bg_rgb.red()}, {bg_rgb.green()}, {bg_rgb.blue()}, 240)"
                grad_end = f"rgba({max(0, bg_rgb.red()-20)}, {max(0, bg_rgb.green()-20)}, {max(0, bg_rgb.blue()-20)}, 250)"
                border_col_rgba = f"rgba({primary_rgb.red()}, {primary_rgb.green()}, {primary_rgb.blue()}, 180)"
            else:  # Açık tema
                grad_start = f"rgba(255, 255, 255, 240)"
                grad_end = f"rgba(240, 240, 240, 250)"
                border_col_rgba = f"rgba({primary_rgb.red()}, {primary_rgb.green()}, {primary_rgb.blue()}, 100)"
            
            self.bottom_widget.setStyleSheet(f"""
                QWidget#bottomWidget {{
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 {grad_start},
                        stop:1 {grad_end});
                    border-top: 2px solid {border_col_rgba};
                    border-radius: 0px;
                }}
            """)

    def _get_theme_stylesheet(self, mode, primary_color, default_text, default_bg):
        """Generates the QSS stylesheet based on theme mode and colors."""
        if mode == "Açık":
            # Açık Tema Renkleri
            bg_color = "#F5F5F5"
            text_color = "#222222"
            widget_bg = "#FFFFFF"
            list_bg = "#FFFFFF"
            border_color = primary_color
            slider_groove = "#CCCCCC"
            slider_add = "#DDDDDD"
            handle_border = "#AAAAAA"
            list_border = "#DDDDDD"
            
            # Butonlar için özel açık tema ayarı
            btn_bg = "#FFFFFF"
            btn_hover = QColor(primary_color).lighter(160).name()
            btn_pressed = QColor(primary_color).lighter(140).name()
            selected_text_color = "white"
            
        else:
            # Koyu Tema Renkleri (Varsayılan)
            bg_color = default_bg
            text_color = default_text
            widget_bg = QColor(bg_color).lighter(110).name()
            list_bg = QColor(bg_color).lighter(105).name()
            border_color = primary_color
            slider_groove = "#555"
            slider_add = "#2d2d2d"
            handle_border = "#333"
            list_border = "#444"
            
            btn_bg = widget_bg
            btn_hover = QColor(primary_color).darker(150).name()
            btn_pressed = QColor(primary_color).darker(200).name()
            selected_text_color = "black"

        return f"""
        QMainWindow, QWidget, QDialog {{
            background-color: {bg_color};
            color: {text_color};
        }}
        QPushButton, QComboBox, QLineEdit {{
            color: {text_color};
            background-color: {btn_bg};
            border: 1px solid {border_color};
            border-radius: 4px;
        }}
        QPushButton:hover {{
            background-color: {btn_hover};
        }}
        QPushButton:pressed {{
            background-color: {btn_pressed};
        }}
        QSlider::groove:horizontal {{
            border: 0px;
            height: 6px;
            background: {slider_groove};
            margin: 2px 0;
            border-radius: 3px;
        }}
        QSlider::sub-page:horizontal {{
            background: {primary_color};
            height: 6px;
            border-radius: 3px;
        }}
        QSlider::add-page:horizontal {{
            background: {slider_add};
            height: 6px;
            border-radius: 3px;
        }}
        QSlider::handle:horizontal {{
            background: {primary_color};
            border: 1px solid {handle_border};
            width: 14px;
            margin: -4px 0;
            border-radius: 7px;
        }}
        QLabel, QCheckBox {{
            color: {text_color};
        }}
        QListWidget, QTreeView, QTableWidget {{
            border: 1px solid {list_border};
            background-color: {list_bg};
            color: {text_color};
        }}
        QListWidget::item:selected, QTreeView::item:selected,
        QTableWidget::item:selected {{
            background: {primary_color};
            color: {selected_text_color};
        }}
        QSplitter::handle {{
            background-color: {QColor(primary_color).darker(130).name()};
        }}
        QMenu {{
            background-color: {widget_bg};
            border: 1px solid {border_color};
            color: {text_color};
        }}
        QMenu::item:selected {{
            background-color: {primary_color};
            color: {selected_text_color};
        }}
        """
        
        # Butonları tema rengine göre güncelle
        if hasattr(self, 'prevButton'):
            control_buttons = [self.prevButton, self.playButton, self.nextButton, 
                             self.shuffleButton, self.repeatButton, 
                             self.seekBackwardButton, self.seekForwardButton]
            primary_rgb = QColor(primary_color)
            btn_style = f"""
                QPushButton {{
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 rgba(70, 70, 70, 180),
                        stop:1 rgba(50, 50, 50, 200));
                    border: 1px solid rgba(100, 100, 100, 150);
                    border-radius: 19px;
                    padding: 2px;
                }}
                QPushButton:hover {{
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                        stop:0 rgba({primary_rgb.red()}, {primary_rgb.green()}, {primary_rgb.blue()}, 220),
                        stop:0.5 rgba({max(0, primary_rgb.red()-20)}, {max(0, primary_rgb.green()-20)}, {max(0, primary_rgb.blue()-20)}, 230),
                        stop:1 rgba({max(0, primary_rgb.red()-30)}, {max(0, primary_rgb.green()-30)}, {max(0, primary_rgb.blue()-30)}, 240));
                    border: 2px solid rgba({min(255, primary_rgb.red()+40)}, {min(255, primary_rgb.green()+40)}, {min(255, primary_rgb.blue()+40)}, 255);
                }}
                QPushButton:pressed {{
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 rgba({max(0, primary_rgb.red()-30)}, {max(0, primary_rgb.green()-30)}, {max(0, primary_rgb.blue()-30)}, 240),
                        stop:1 rgba({max(0, primary_rgb.red()-60)}, {max(0, primary_rgb.green()-60)}, {max(0, primary_rgb.blue()-60)}, 255));
                    border: 2px solid rgba({primary_rgb.red()}, {primary_rgb.green()}, {primary_rgb.blue()}, 255);
                }}
                QPushButton:checked {{ 
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 rgba({primary_rgb.red()}, {primary_rgb.green()}, {primary_rgb.blue()}, 220),
                        stop:1 rgba({max(0, primary_rgb.red()-30)}, {max(0, primary_rgb.green()-30)}, {max(0, primary_rgb.blue()-30)}, 240));
                    border: 2px solid rgba({min(255, primary_rgb.red()+40)}, {min(255, primary_rgb.green()+40)}, {min(255, primary_rgb.blue()+40)}, 255);
                }}
                QPushButton:focus {{ outline: none; }}
            """
            for btn in control_buttons:
                btn.setStyleSheet(btn_style)
        
        # Volume slider'a tema rengini uygula
        if hasattr(self, 'volumeSlider') and hasattr(self.volumeSlider, 'set_aura_base_color'):
            self.volumeSlider.set_aura_base_color(QColor(primary_color))

        # Görselleştirme widget'larını güncelle
        if self.vis_widget_main_window and hasattr(self.vis_widget_main_window, 'set_color_theme'):
            self.vis_widget_main_window.set_color_theme(primary_color, bg_color)
        if self.vis_window and self.vis_window.visualizationWidget:
            if hasattr(self.vis_window.visualizationWidget, 'set_color_theme'):
                self.vis_window.visualizationWidget.set_color_theme(primary_color, bg_color)
            # Görselleştirme penceresinin arka planını da güncelle
            self.vis_window.setStyleSheet(f"""
                QMainWindow {{
                    background-color: {bg_color};
                }}
            """)

        if save:
            self.save_config()

        # Video sekmesi kontrolleri: tema değişince yeniden stillendir
        try:
            self._apply_video_ui_theme()
        except Exception:
            pass

    def save_playlist(self):
        paths = []
        for i in range(self.playlistWidget.count()):
            item = self.playlistWidget.item(i)
            paths.append(item.data(Qt.UserRole))

        data = {
            "paths": paths,
            "current_index": self.playlist.currentIndex()
        }
        try:
            with open(PLAYLIST_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            print(f"Çalma listesi kaydetme hatası: {e}")

    def load_playlist(self):
        # JSON yoksa, eski pickle playlist varsa migrate dene
        if not os.path.exists(PLAYLIST_FILE):
            for pkl_name in ("angolla_playlist.pkl", "playlist.pkl"):
                if os.path.exists(pkl_name):
                    try:
                        migrate_pickle_playlist_to_json(pkl_name, PLAYLIST_FILE)
                    except Exception:
                        pass
                    break
        if not os.path.exists(PLAYLIST_FILE):
            return
        try:
            with open(PLAYLIST_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)

            if isinstance(data, dict):
                playlist_paths = data.get("paths", [])
                current_index = data.get("current_index", -1)
            else:
                print("Kayıtlı çalma listesi geçersiz formatta.")
                return

            self.playlist.clear()
            self.playlistWidget.clear()

            valid_paths = []
            for path in playlist_paths:
                if os.path.exists(path):
                    title, artist, _, _ = \
                        self._get_tags_from_file_with_duration(path)
                    url = QUrl.fromLocalFile(path)
                    self.playlist.addMedia(QMediaContent(url))
                    display_text = f"{artist} - {title}"
                    item = QListWidgetItem(display_text)
                    item.setData(Qt.UserRole, path)
                    self.playlistWidget.addItem(item)
                    valid_paths.append(path)
                else:
                    print(f"Dosya bulunamadı, listeden çıkarılıyor: {path}")

            if valid_paths:
                self.playlist.setCurrentIndex(
                    min(current_index, len(valid_paths) - 1)
                )

            self.statusBar().showMessage(
                f"{len(valid_paths)} parça yüklendi.", 3000
            )
        except Exception as e:
            print(f"Çalma listesi yükleme hatası: {e}")
            if os.path.exists(PLAYLIST_FILE):
                os.remove(PLAYLIST_FILE)

    def save_config(self):
        self.config_data["volume"] = self.mediaPlayer.volume()
        self.config_data["shuffle_mode"] = self.is_shuffling
        self.config_data["repeat_mode"] = self.is_repeating
        self.config_data["theme"] = self.theme
        self.config_data["show_album_art"] = self.infoDisplayWidget._album_art_visible
        self.config_data["vis_mode"] = self.vis_mode
        self.config_data["use_projectm"] = self.use_projectm
        self.config_data["vis_favorites"] = self.vis_favorites
        self.config_data["vis_auto_cycle"] = self.vis_auto_cycle
        self.config_data["lang"] = self.lang
        self.config_data["playback_rate"] = getattr(self, '_current_playback_rate', 1.0)

        # Config'i dosyaya JSON olarak kaydet (pickle yok)
        try:
            atomic_write_json(CONFIG_FILE, self.config_data)
        except Exception as e:
            print(f"Ayar kaydetme hatası (JSON dosya): {e}")

        # Geriye dönük uyumluluk: QSettings içinde de JSON string tut (pickle yok)
        settings = QSettings(SETTINGS_KEY, "AngollaPlayer")
        try:
            settings.setValue("config_json", json.dumps(self.config_data))
        except Exception:
            pass

    def load_config(self):
        # 1) Önce config dosyasından yükle
        obj = load_json_file(CONFIG_FILE)
        if isinstance(obj, dict):
            self.config_data = obj
        else:
            self.config_data = {}

        # 2) Dosya yoksa: QSettings JSON'dan migrate et
        if not self.config_data:
            settings = QSettings(SETTINGS_KEY, "AngollaPlayer")
            try:
                val = settings.value("config_json")
                if val and isinstance(val, str):
                    migrated = json.loads(val)
                    if isinstance(migrated, dict):
                        self.config_data = migrated
                        try:
                            atomic_write_json(CONFIG_FILE, self.config_data)
                        except Exception:
                            pass
            except Exception:
                pass

        # 3) Eski pickle dosyaları varsa (lokal) güvenli migrate dene
        if not self.config_data:
            for pkl_name in ("angolla_config.pkl", "angolla_settings.pkl", "config.pkl"):
                if os.path.exists(pkl_name):
                    try:
                        if migrate_pickle_config_to_json(pkl_name, CONFIG_FILE):
                            obj2 = load_json_file(CONFIG_FILE)
                            if isinstance(obj2, dict):
                                self.config_data = obj2
                            break
                    except Exception:
                        pass

        vol = self.config_data.get("volume", 70)
        self.mediaPlayer.setVolume(vol)
        self.volumeSlider.setValue(vol)

        repeat_mode_val = self.config_data.get("repeat_mode", False)
        is_shuffle = bool(self.config_data.get("shuffle_mode", False))
        self.is_shuffling = is_shuffle
        if isinstance(repeat_mode_val, bool):
            self.is_repeating = repeat_mode_val
        else:
            self.is_repeating = repeat_mode_val in (
                QMediaPlaylist.Loop,
                QMediaPlaylist.CurrentItemInLoop,
            )

        self._apply_shuffle_button_state(self.is_shuffling)
        self._apply_repeat_button_state(self.is_repeating)

        theme_name = self.config_data.get("theme", "AURA Mavi")
        self.set_theme(theme_name, save=False)

        show_art = self.config_data.get("show_album_art", True)
        self.infoDisplayWidget.set_album_art_visibility(show_art)

        self.vis_mode = self.config_data.get("vis_mode", "Çizgiler")
        self.use_projectm = self.config_data.get("use_projectm", False)

        # Playback: Yumuşak Geçiş (Clementine benzeri)
        try:
            pb = self._get_playback_soft_transition_settings_from_config()
            self.apply_playback_soft_transition_settings(pb, preview=False)
        except Exception:
            pass
        
        # Playback rate'i yükle
        saved_rate = self.config_data.get("playback_rate", 1.0)
        try:
            self._current_playback_rate = float(saved_rate)
            if hasattr(self, 'playbackRateLabel'):
                self.playbackRateLabel.setText(f"{self._current_playback_rate:.2f}x")
        except Exception:
            self._current_playback_rate = 1.0
        self.lang = self.config_data.get("lang", self.lang)

    def _get_playback_soft_transition_settings_from_config(self) -> Dict[str, Any]:
        """Config'ten playback fade/crossfade ayarlarını okur (gerekirse migrate eder)."""
        pb = self.config_data.get("playback_soft_transitions")
        if isinstance(pb, dict):
            out = {
                "stop_fade_enabled": bool(pb.get("stop_fade_enabled", False)),
                "manual_crossfade_enabled": bool(pb.get("manual_crossfade_enabled", False)),
                "auto_crossfade_enabled": bool(pb.get("auto_crossfade_enabled", False)),
                "fade_out_on_pause": bool(pb.get("fade_out_on_pause", False)),
                "fade_in_on_resume": bool(pb.get("fade_in_on_resume", False)),
                "crossfade_ms": int(pb.get("crossfade_ms", 1000) or 0),
                "fade_ms": int(pb.get("fade_ms", 400) or 0),
            }
            return out

        # Geriye dönük migrate: eski crossfade_duration slider'ı
        old_cf = self.config_data.get("crossfade_duration")
        try:
            old_cf = int(old_cf)
        except Exception:
            old_cf = 0

        enabled = bool(old_cf > 0)
        return {
            "stop_fade_enabled": False,
            "manual_crossfade_enabled": enabled,
            "auto_crossfade_enabled": enabled,
            "fade_out_on_pause": False,
            "fade_in_on_resume": False,
            "crossfade_ms": int(old_cf) if old_cf > 0 else 1000,
            "fade_ms": 400,
        }

    def apply_playback_soft_transition_settings(self, settings: Dict[str, Any], preview: bool = True):
        """Ayarları anında uygular. preview=True ise sadece runtime etkiler, config yazmaz."""
        if not isinstance(settings, dict):
            return

        self._pb_stop_fade_enabled = bool(settings.get("stop_fade_enabled", False))
        self._pb_manual_crossfade_enabled = bool(settings.get("manual_crossfade_enabled", False))
        self._pb_auto_crossfade_enabled = bool(settings.get("auto_crossfade_enabled", False))
        self._pb_fade_out_on_pause = bool(settings.get("fade_out_on_pause", False))
        self._pb_fade_in_on_resume = bool(settings.get("fade_in_on_resume", False))
        self._pb_crossfade_ms = max(0, int(settings.get("crossfade_ms", 1000) or 0))
        self._pb_fade_ms = max(0, int(settings.get("fade_ms", 400) or 0))

        # Engine: transport fade ayarları (sadece müzik)
        try:
            if getattr(self, "audio_engine", None):
                self.audio_engine.configure_transport_fades(
                    fade_ms=self._pb_fade_ms,
                    stop_fade_enabled=self._pb_stop_fade_enabled,
                    fade_out_on_pause=self._pb_fade_out_on_pause,
                    fade_in_on_resume=self._pb_fade_in_on_resume,
                )
                # Crossfade'i sürekli açık bırakma: sadece parça geçişi anında aktive edeceğiz.
                self.audio_engine.set_crossfade_duration(0)
        except Exception:
            pass

        # Çubuk rengi ve stili yükle (Eski AnimatedVisualizationWidget için)
        bar_color = self.config_data.get("bar_color")
        if bar_color is None or bar_color == "#40C4FF":
            # Varsayılanı dinamik aura moduna çek (RGB)
            bar_color = "RGB"
            self.config_data["bar_color"] = bar_color
        if self.vis_widget_main_window and hasattr(self.vis_widget_main_window, '_set_bar_color'):
            self.vis_widget_main_window._set_bar_color(bar_color)
        
        bar_style = self.config_data.get("bar_style", "solid")
        if self.vis_widget_main_window:
            self.vis_widget_main_window.bar_style_mode = bar_style
        # Bar stili seçimini tazele
        if hasattr(self.vis_widget_main_window, 'bar_style_mode'):
            if hasattr(self.vis_widget_main_window, '_set_bar_style'):
                self.vis_widget_main_window._set_bar_style(bar_style)

        # Görselleştirme yapılandırması yükle
        vis_sensitivity = self.config_data.get("vis_sensitivity", 50)
        vis_color_intensity = self.config_data.get("vis_color_intensity", 75)
        vis_density = self.config_data.get("vis_density", 60)
        self.vis_favorites = self.config_data.get("vis_favorites", [])
        self.vis_auto_cycle = self.config_data.get("vis_auto_cycle", False)
        if self.vis_auto_cycle:
            self._reset_auto_cycle_index(self.vis_mode)
            self.vis_auto_timer.start(self.vis_auto_interval)
        
        if self.vis_widget_main_window and hasattr(self.vis_widget_main_window, 'set_vis_config'):
            self.vis_widget_main_window.set_vis_config(vis_sensitivity, vis_color_intensity, vis_density)
        if self.vis_window and self.vis_window.visualizationWidget:
            if hasattr(self.vis_window.visualizationWidget, 'set_vis_config'):
                self.vis_window.visualizationWidget.set_vis_config(vis_sensitivity, vis_color_intensity, vis_density)

    def _apply_eq_settings(self, gains):
        """
        EQ değerlerini C++ motoruna veya işleyiciye gönderir.
        Değerler float(val / 10.0) hassasiyetindedir.
        """
        # Burada asıl C++ bağlantısı olabilir, şimdilik hassas değerleri yazalım.
        print(f"DSP Signal Update: {gains}")
        # Örnek: bridge.set_eq_bands(gains)

    
    def _toggle_popup_eq(self):
        """EQ Popup'ı aç/kapat"""
        if self.popup_eq.isVisible():
            self.popup_eq.hide()
        else:
            # Professional Window: Center on Screen/Parent
            # self.popup_eq is a QDialog/Window
            self.popup_eq.show()
            
            # Center logic
            frameGm = self.popup_eq.frameGeometry()
            screen = QApplication.desktop().screenNumber(QApplication.desktop().cursor().pos())
            centerPoint = QApplication.desktop().screenGeometry(screen).center()
            frameGm.moveCenter(centerPoint)
            self.popup_eq.move(frameGm.topLeft())
            
            self.popup_eq.raise_()

    def closeEvent(self, event):
        """Uygulama kapatılırken kaynakları temizle"""
        # Old dsp_bridge cleanup removed as it's now handled by GlobalAudioEngine.
            
        print("\n🔄 Uygulama kapatılıyor...")
        
        try:
            self._stop_monitor_capture()
        except Exception:
            pass

        try:
            if self.vis_window:
                self.vis_window.close()
            if hasattr(self, 'vis_widget_main_window'):
                self.vis_widget_main_window.animation_timer.stop()
            
            self.save_playlist()
            self.save_config()
            print("  ✓ Ayarlar kaydedildi")
            
            self.library.close()
            self.mediaPlayer.stop()

            if getattr(self, "audio_engine", None):
                self.audio_engine.shutdown()

            for attr in ("webView", "web_view"):
                view = getattr(self, attr, None)
                if not view:
                    continue
                try:
                    view.stop()
                except Exception:
                    pass
                try:
                    page = view.page()
                    if page:
                        page.deleteLater()
                except Exception:
                    pass
                try:
                    view.deleteLater()
                except Exception:
                    pass
                try:
                    setattr(self, attr, None)
                except Exception:
                    pass
            
            print("👋 Görüşmek üzere!\n")
            
        except Exception as e:
            print(f"⚠️ Cleanup hatası: {e}")
            pass
        
        event.accept()
    # ------------------------------------------------------------ #
    # PLAYLIST – Çoklu seçim + sürükle bırak + CTRL+A aktif etme
    # ------------------------------------------------------------ #
    def enable_playlist_features(self):
        self.playlistWidget.setSelectionMode(QAbstractItemView.ExtendedSelection)  # CTRL+A aktif
        self.playlistWidget.setDragDropMode(QAbstractItemView.InternalMove)        # sürükle bırak
        self.playlistWidget.setDefaultDropAction(Qt.MoveAction)
        self.playlistWidget.setAcceptDrops(True)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        for url in event.mimeData().urls():
            path = url.toLocalFile()
            if path.lower().endswith((".mp3", ".wav", ".flac", ".ogg", ".m4a", ".m4b", ".mp4", ".aac", ".wma", ".opus")):
                title, artist, _, _ = self._get_tags_from_file_with_duration(path)
                item = QListWidgetItem(f"{artist} - {title}")
                item.setData(Qt.UserRole, path)
                self.playlistWidget.addItem(item)
                self.playlist.addMedia(QMediaContent(QUrl.fromLocalFile(path)))

        event.acceptProposedAction()
        self.save_playlist()


# ---------------------------------------------------------------------------
# AYAR DİYALOĞU
# ---------------------------------------------------------------------------

class PreferencesDialog(QDialog):
    def __init__(self, parent: AngollaPlayer):
        super().__init__(parent)
        self.setWindowTitle("Angolla Ayarları")
        self.parent = parent
        self.setFixedSize(900, 650)
        self._preview_dirty = False
        self._original_playback_preview = {}
        try:
            self._original_playback_preview = self.parent._get_playback_soft_transition_settings_from_config()
        except Exception:
            self._original_playback_preview = {}
        self._create_category_list()
        self._create_widgets()
        self._layout_widgets()
        self._connect_signals()

    def _reset_playback_soft_transitions_to_defaults(self):
        """Oynatma/Yumuşak Geçiş ayarlarını varsayılanlara döndürür (anında preview)."""
        try:
            widgets = [
                getattr(self, "currentTrackGlowCheck", None),
                getattr(self, "softStopCheck", None),
                getattr(self, "manualCrossfadeCheck", None),
                getattr(self, "autoCrossfadeCheck", None),
                getattr(self, "fadeOutOnPauseCheck", None),
                getattr(self, "fadeInOnResumeCheck", None),
                getattr(self, "crossfadeMsSpin", None),
                getattr(self, "fadeMsSpin", None),
            ]
            for w in widgets:
                if w is not None:
                    try:
                        w.blockSignals(True)
                    except Exception:
                        pass

            # Varsayılanlar: Akıcı oynatma (yumuşak geçiş + çapraz geçiş açık)
            self.currentTrackGlowCheck.setChecked(True)
            self.softStopCheck.setChecked(True)
            self.manualCrossfadeCheck.setChecked(True)
            self.autoCrossfadeCheck.setChecked(True)
            # Pause/Resume fade kullanıcı tercihine daha bağlı; varsayılanda kapalı tut
            self.fadeOutOnPauseCheck.setChecked(False)
            self.fadeInOnResumeCheck.setChecked(False)
            # Süreler: hızlı ama hissedilir geçiş
            self.crossfadeMsSpin.setValue(2000)
            self.fadeMsSpin.setValue(400)
        except Exception:
            pass
        finally:
            try:
                for w in (
                    getattr(self, "currentTrackGlowCheck", None),
                    getattr(self, "softStopCheck", None),
                    getattr(self, "manualCrossfadeCheck", None),
                    getattr(self, "autoCrossfadeCheck", None),
                    getattr(self, "fadeOutOnPauseCheck", None),
                    getattr(self, "fadeInOnResumeCheck", None),
                    getattr(self, "crossfadeMsSpin", None),
                    getattr(self, "fadeMsSpin", None),
                ):
                    if w is not None:
                        try:
                            w.blockSignals(False)
                        except Exception:
                            pass
            except Exception:
                pass

        # Tek seferde preview uygula
        try:
            self._preview_playback_soft_transitions()
        except Exception:
            pass

    def _get_icon(self, name: str) -> QIcon:
        icon_path = os.path.join(os.path.dirname(__file__), "icons", name)
        return QIcon(icon_path) if os.path.exists(icon_path) else QIcon()

    def _create_category_list(self):
        self.categoryList = QListWidget()
        self.categoryList.setMaximumWidth(200)
        self.categoryList.setIconSize(QSize(28, 28))
        self.categoryList.setSpacing(2)
        self.categoryList.setUniformItemSizes(True)
        self.categoryList.setStyleSheet("""
            QListWidget {
                background-color: #2a2a2a;
                color: #ffffff;
                border: none;
                outline: none;
            }
            QListWidget::item { padding: 6px 10px; margin: 0; }
            QListWidget::item:selected { background-color: #0078d7; color: #ffffff; }
            QListWidget::item:hover { background-color: #3a3a3a; }
        """)
        self.category_map = {}
        font_bold = QFont(); font_bold.setBold(True); font_bold.setPointSize(10)

        header_playback = QListWidgetItem("Playback")
        header_playback.setFlags(header_playback.flags() & ~Qt.ItemIsSelectable)
        header_playback.setFont(font_bold)
        brush = header_playback.foreground(); brush.setColor(QColor("#888888")); header_playback.setForeground(brush)
        self.categoryList.addItem(header_playback)

        item_genel = QListWidgetItem(self._get_icon("configure.png"), "⚙️ Genel")
        self.categoryList.addItem(item_genel); self.category_map["⚙️ Genel"] = 0

        item_play = QListWidgetItem(self._get_icon("view-media-playlist.png"), "▶️ Oynatma")
        self.categoryList.addItem(item_play); self.category_map["▶️ Oynatma"] = 1

        header_visual = QListWidgetItem("Visual")
        header_visual.setFlags(header_visual.flags() & ~Qt.ItemIsSelectable)
        header_visual.setFont(font_bold)
        brush2 = header_visual.foreground(); brush2.setColor(QColor("#888888")); header_visual.setForeground(brush2)
        self.categoryList.addItem(header_visual)

        item_vis = QListWidgetItem(self._get_icon("view-media-visualization.png"), "🎆 Görselleştirme")
        self.categoryList.addItem(item_vis); self.category_map["🎆 Görselleştirme"] = 2

        # Yeni: Kısayollar
        item_short = QListWidgetItem(self._get_icon("configure-shortcuts.png"), "⌨️ Kısayollar")
        self.categoryList.addItem(item_short); self.category_map["⌨️ Kısayollar"] = 3

        self.categoryList.setCurrentRow(1)

    def _create_widgets(self):
        # Genel
        self.albumArtCheck = QCheckBox("Albüm Kapağını Göster (Bilgi Paneli)")
        self.albumArtCheck.setChecked(self.parent.config_data.get("show_album_art", True))

        self.themeLabel = QLabel("Tema Seçimi:")
        self.themeCombo = QComboBox(); self.themeCombo.addItems(self.parent.themes.keys())
        self.themeCombo.setCurrentText(self.parent.config_data.get("theme", "AURA Mavi"))

        self.themeModeLabel = QLabel("Tema Modu:")
        self.themeModeCombo = QComboBox()
        self.themeModeCombo.addItems(["Koyu", "Açık"])
        self.themeModeCombo.setCurrentText(self.parent.config_data.get("theme_mode", "Koyu"))

        self.langLabel = QLabel("Dil:")
        self.langCombo = QComboBox()
        lang_map = {"en": "English", "tr": "Türkçe", "es": "Español", "fr": "Français", "de": "Deutsch", "ar": "العربية"}
        for code, name in lang_map.items(): self.langCombo.addItem(name, code)
        cur_lang = self.parent.config_data.get("lang", self.parent.lang); idx = self.langCombo.findData(cur_lang)
        if idx >= 0: self.langCombo.setCurrentIndex(idx)

        self.shareLabel = QLabel("Paylaşım Seçeneği:")
        self.shareButton = QPushButton("Şarkıyı Paylaş (Simülasyon)")

        # Oynatma (Clementine benzeri)
        self.currentTrackGlowCheck = QCheckBox("Mevcut parçada parlayan bir animasyon göster")
        self.currentTrackGlowCheck.setChecked(bool(self.parent.config_data.get("playback_current_track_glow", True)))

        pb = {}
        try:
            pb = self.parent._get_playback_soft_transition_settings_from_config()
        except Exception:
            pb = {}

        self.softStopCheck = QCheckBox("Bir parça durdurulurken yumuşak geç")
        self.softStopCheck.setChecked(bool(pb.get("stop_fade_enabled", False)))

        self.manualCrossfadeCheck = QCheckBox("Parça değiştirirken elle çapraz geçiş yap")
        self.manualCrossfadeCheck.setChecked(bool(pb.get("manual_crossfade_enabled", False)))

        self.autoCrossfadeCheck = QCheckBox("Parça değiştirirken otomatik olarak çapraz geçiş yap")
        self.autoCrossfadeCheck.setChecked(bool(pb.get("auto_crossfade_enabled", False)))

        self.fadeOutOnPauseCheck = QCheckBox("Duraklatırken yumuşakça ses azalt (fade out)")
        self.fadeOutOnPauseCheck.setChecked(bool(pb.get("fade_out_on_pause", False)))

        self.fadeInOnResumeCheck = QCheckBox("Devam ettirirken yumuşakça ses artır (fade in)")
        self.fadeInOnResumeCheck.setChecked(bool(pb.get("fade_in_on_resume", False)))

        self.crossfadeMsLabel = QLabel("Çapraz geçiş süresi (ms):")
        self.crossfadeMsSpin = QSpinBox()
        self.crossfadeMsSpin.setRange(0, 10000)
        self.crossfadeMsSpin.setSingleStep(100)
        self.crossfadeMsSpin.setValue(int(pb.get("crossfade_ms", 2000)))

        self.fadeMsLabel = QLabel("Yumuşak geçiş süresi (ms):")
        self.fadeMsSpin = QSpinBox()
        self.fadeMsSpin.setRange(0, 5000)
        self.fadeMsSpin.setSingleStep(100)
        self.fadeMsSpin.setValue(int(pb.get("fade_ms", 400)))

        self.softTransitionGroup = QGroupBox("Yumuşak Geçiş")
        self.playbackDefaultsButton = QPushButton("Varsayılan Ayarlar")
        g = QGridLayout(self.softTransitionGroup)
        g.setColumnStretch(0, 1)
        row = 0
        g.addWidget(self.softStopCheck, row, 0, 1, 2); row += 1
        g.addWidget(self.manualCrossfadeCheck, row, 0, 1, 2); row += 1
        g.addWidget(self.autoCrossfadeCheck, row, 0, 1, 2); row += 1
        g.addWidget(self.fadeOutOnPauseCheck, row, 0, 1, 2); row += 1
        g.addWidget(self.fadeInOnResumeCheck, row, 0, 1, 2); row += 1
        g.addWidget(self.crossfadeMsLabel, row, 0)
        g.addWidget(self.crossfadeMsSpin, row, 1); row += 1
        g.addWidget(self.fadeMsLabel, row, 0)
        g.addWidget(self.fadeMsSpin, row, 1); row += 1
        g.addWidget(self.playbackDefaultsButton, row, 0, 1, 2); row += 1
        g.setRowStretch(row, 1)

        # Görselleştirme ayarları (Playback sayfasından taşındı)
        self.visModeLabel = QLabel("Görselleştirme Modu:")
        self.visModeCombo = QComboBox(); self.visModeCombo.addItems([
            "Çubuklar", "Çizgiler", "Daireler", "Spektrum Çubukları",
            "Ayna",
            "Angolla Analyzer", "Angolla Turbine", "Angolla Boom", "Angolla Block",
            "Enerji Halkaları", "Dalga Formu",
            "Pulsar", "Spiral", "Volcano", "Energy Ring", "Circular Waveform", "3D Swirl", "Pulse Explosion", "Tunnel Mode"
        ])
        current_mode = self.parent.config_data.get("vis_mode", "bars")
        if current_mode == "bars":
            current_mode = "Çubuklar"
        elif current_mode == "lines":
            current_mode = "Çizgiler"
        self.visModeCombo.setCurrentText(current_mode)

        self.projectmCheck = QCheckBox("✨ ProjectM Görselleştirme Kullan (100+ MilkDrop Preset)")
        self.projectmCheck.setChecked(self.parent.config_data.get("use_projectm", False))
        if not HAS_PROJECTM:
            self.projectmCheck.setEnabled(False)
            self.projectmCheck.setToolTip("ProjectM yüklenmedi - viz_engine modülü gerekli")

        # Görselleştirme Config
        self.visConfigLabel = QLabel("🎆 Görselleştirme Yapılandırması:"); self.visConfigLabel.setStyleSheet("font-weight: bold;")
        self.sensitivityLabel = QLabel("Duyarlılık:")
        self.sensitivitySlider = QSlider(Qt.Horizontal); self.sensitivitySlider.setRange(1, 100)
        self.sensitivitySlider.setValue(self.parent.config_data.get("vis_sensitivity", 50))
        self.sensitivityValueLabel = QLabel(f"{self.sensitivitySlider.value()}%")

        self.colorLabel = QLabel("Renk Yoğunluğu:")
        self.colorSlider = QSlider(Qt.Horizontal); self.colorSlider.setRange(1, 100)
        self.colorSlider.setValue(self.parent.config_data.get("vis_color_intensity", 75))
        self.colorValueLabel = QLabel(f"{self.colorSlider.value()}%")

        self.densityLabel = QLabel("Parçacık Yoğunluğu:")
        self.densitySlider = QSlider(Qt.Horizontal); self.densitySlider.setRange(1, 100)
        self.densitySlider.setValue(self.parent.config_data.get("vis_density", 60))
        self.densityValueLabel = QLabel(f"{self.densitySlider.value()}%")

    def _create_general_page(self):
        widget = QWidget(); layout = QGridLayout(widget); layout.setColumnStretch(1, 1)
        layout.addWidget(self.albumArtCheck, 0, 0, 1, 2)
        layout.addWidget(self.themeLabel, 1, 0); layout.addWidget(self.themeCombo, 1, 1)
        layout.addWidget(self.themeModeLabel, 2, 0); layout.addWidget(self.themeModeCombo, 2, 1)
        layout.addWidget(self.langLabel, 3, 0); layout.addWidget(self.langCombo, 3, 1)
        layout.addWidget(self.shareLabel, 4, 0); layout.addWidget(self.shareButton, 4, 1)
        layout.setRowStretch(5, 1)
        return widget

    def _create_playback_page(self):
        widget = QWidget(); layout = QGridLayout(widget); layout.setColumnStretch(1, 1)
        row = 0
        layout.addWidget(self.currentTrackGlowCheck, row, 0, 1, 2); row += 1
        layout.addWidget(self.softTransitionGroup, row, 0, 1, 2); row += 1
        layout.setRowStretch(row, 1)
        return widget

    def _create_visualization_page(self):
        widget = QWidget(); layout = QGridLayout(widget); layout.setColumnStretch(1, 1)
        layout.addWidget(self.visModeLabel, 0, 0); layout.addWidget(self.visModeCombo, 0, 1)
        layout.addWidget(self.projectmCheck, 1, 0, 1, 2)
        layout.addWidget(self.visConfigLabel, 2, 0, 1, 2)
        layout.addWidget(self.sensitivityLabel, 3, 0)
        h_sens = QHBoxLayout(); h_sens.addWidget(self.sensitivitySlider); h_sens.addWidget(self.sensitivityValueLabel); layout.addLayout(h_sens, 3, 1)
        layout.addWidget(self.colorLabel, 4, 0)
        h_color = QHBoxLayout(); h_color.addWidget(self.colorSlider); h_color.addWidget(self.colorValueLabel); layout.addLayout(h_color, 4, 1)
        layout.addWidget(self.densityLabel, 5, 0)
        h_den = QHBoxLayout(); h_den.addWidget(self.densitySlider); h_den.addWidget(self.densityValueLabel); layout.addLayout(h_den, 5, 1)
        layout.setRowStretch(6, 1)
        return widget

    def _create_shortcuts_page(self):
        widget = QWidget(); layout = QGridLayout(widget); layout.setColumnStretch(1, 1)
        # Kısayol tanımları
        actions = [
            ("play_pause", "Oynat/Duraklat"),
            ("next_track", "Sonraki Parça"),
            ("prev_track", "Önceki Parça"),
            ("seek_backward", "Geri Sar (5 sn)"),
            ("seek_forward", "İleri Sar (5 sn)"),
            ("open_files", "Dosya Ekle"),
            ("open_folder", "Klasör Ekle"),
            ("open_visual", "Görselleştirme Penceresi"),
            ("open_prefs", "Tercihler"),
            ("show_about", "Hakkında"),
            ("toggle_shuffle", "Karıştır"),
            ("toggle_repeat", "Tekrar"),
            ("play_selected", "Seçileni Çal"),
            ("volume_up", "Ses +"),
            ("volume_down", "Ses -"),
            ("mute", "Sessiz")
        ]
        self.shortcutsEditors = {}
        current_map = self.parent.config_data.get("shortcuts", {})
        row = 0
        for key, label in actions:
            layout.addWidget(QLabel(label+":"), row, 0)
            editor = QKeySequenceEdit()
            # Varsayılan veya mevcut değer
            seq = current_map.get(key, getattr(self.parent, "_default_shortcuts", {}).get(key, ""))
            try:
                if isinstance(seq, str) and seq:
                    editor.setKeySequence(QKeySequence(seq))
            except Exception:
                pass
            self.shortcutsEditors[key] = editor
            layout.addWidget(editor, row, 1)
            row += 1
        layout.setRowStretch(row, 1)
        return widget

    def _layout_widgets(self):
        main_layout = QVBoxLayout(self)
        content_layout = QHBoxLayout()
        content_layout.addWidget(self.categoryList, 0)

        self.stackedWidget = QStackedWidget()
        self.stackedWidget.addWidget(self._create_general_page())
        self.stackedWidget.addWidget(self._create_playback_page())
        self.stackedWidget.addWidget(self._create_visualization_page())
        self.stackedWidget.addWidget(self._create_shortcuts_page())
        content_layout.addWidget(self.stackedWidget, 1)

        main_layout.addLayout(content_layout, 1)

        btn_layout = QHBoxLayout(); btn_layout.addStretch()
        self.okButton = QPushButton("✓ Tamam"); self.applyButton = QPushButton("✓ Uygula"); self.cancelButton = QPushButton("✕ İptal")
        btn_layout.addWidget(self.okButton); btn_layout.addWidget(self.applyButton); btn_layout.addWidget(self.cancelButton)
        main_layout.addLayout(btn_layout)

    def _connect_signals(self):
        self.categoryList.itemClicked.connect(self._on_category_selected)
        self.albumArtCheck.stateChanged.connect(self._on_value_changed)
        self.themeModeCombo.currentTextChanged.connect(self._on_value_changed)
        self.themeCombo.currentTextChanged.connect(self._on_value_changed)
        self.langCombo.currentIndexChanged.connect(self._on_value_changed)
        self.visModeCombo.currentTextChanged.connect(self._on_value_changed)
        self.projectmCheck.stateChanged.connect(self._on_value_changed)
        self.shareButton.clicked.connect(self._share_clicked)
        self.sensitivitySlider.valueChanged.connect(self._update_sensitivity_label); self.sensitivitySlider.sliderReleased.connect(self._on_value_changed)
        self.colorSlider.valueChanged.connect(self._update_color_label); self.colorSlider.sliderReleased.connect(self._on_value_changed)
        self.densitySlider.valueChanged.connect(self._update_density_label); self.densitySlider.sliderReleased.connect(self._on_value_changed)
        # Playback soft transition preview (anında etki)
        for w in (
            self.currentTrackGlowCheck,
            self.softStopCheck,
            self.manualCrossfadeCheck,
            self.autoCrossfadeCheck,
            self.fadeOutOnPauseCheck,
            self.fadeInOnResumeCheck,
        ):
            try:
                w.stateChanged.connect(self._preview_playback_soft_transitions)
            except Exception:
                pass
        try:
            self.crossfadeMsSpin.valueChanged.connect(self._preview_playback_soft_transitions)
        except Exception:
            pass
        try:
            self.fadeMsSpin.valueChanged.connect(self._preview_playback_soft_transitions)
        except Exception:
            pass

        try:
            self.playbackDefaultsButton.clicked.connect(self._reset_playback_soft_transitions_to_defaults)
        except Exception:
            pass

        self.okButton.clicked.connect(self._on_ok); self.applyButton.clicked.connect(self._on_apply); self.cancelButton.clicked.connect(self._on_cancel)

    def _on_category_selected(self, item):
        if item.text() in self.category_map:
            self.stackedWidget.setCurrentIndex(self.category_map[item.text()])

    def _on_value_changed(self):
        pass

    def _on_ok(self):
        self._apply_settings(); self.accept()

    def _on_apply(self):
        self._apply_settings()

    def _on_cancel(self):
        # Preview uygulanmışsa geri al
        try:
            if self._preview_dirty:
                self.parent.apply_playback_soft_transition_settings(self._original_playback_preview, preview=True)
        except Exception:
            pass
        self.reject()

    def _update_sensitivity_label(self, value):
        self.sensitivityValueLabel.setText(f"{value}%")

    def _update_color_label(self, value):
        self.colorValueLabel.setText(f"{value}%")

    def _update_density_label(self, value):
        self.densityValueLabel.setText(f"{value}%")

    def _apply_settings(self):
        self.parent.config_data["show_album_art"] = self.albumArtCheck.isChecked()
        # Eski ayar (deprecated): artık kullanılmıyor
        try:
            self.parent.config_data.pop("crossfade_duration", None)
        except Exception:
            pass
        # Playback soft transition ayarlarını kaydet
        self.parent.config_data["playback_current_track_glow"] = bool(self.currentTrackGlowCheck.isChecked())
        pb_settings = {
            "stop_fade_enabled": bool(self.softStopCheck.isChecked()),
            "manual_crossfade_enabled": bool(self.manualCrossfadeCheck.isChecked()),
            "auto_crossfade_enabled": bool(self.autoCrossfadeCheck.isChecked()),
            "fade_out_on_pause": bool(self.fadeOutOnPauseCheck.isChecked()),
            "fade_in_on_resume": bool(self.fadeInOnResumeCheck.isChecked()),
            "crossfade_ms": int(self.crossfadeMsSpin.value()),
            "fade_ms": int(self.fadeMsSpin.value()),
        }
        self.parent.config_data["playback_soft_transitions"] = pb_settings
        try:
            self.parent.apply_playback_soft_transition_settings(pb_settings, preview=False)
        except Exception:
            pass
        
        # ProjectM ayarı
        use_projectm = self.projectmCheck.isChecked()
        if self.parent.use_projectm != use_projectm:
            self.parent.use_projectm = use_projectm
            self.parent.config_data["use_projectm"] = use_projectm
            # Görselleştirme penceresi açıksa yenile
            if self.parent.vis_window:
                self.parent.vis_window.close()
                self.parent.open_visualization_window()
        selected_theme = self.themeCombo.currentText()
        selected_mode = self.themeModeCombo.currentText()
        
        mode_changed = False
        if self.parent.config_data.get("theme_mode") != selected_mode:
            self.parent.config_data["theme_mode"] = selected_mode
            mode_changed = True

        if self.parent.theme != selected_theme or mode_changed:
            self.parent.set_theme(selected_theme, save=False)

        lang_code = self.langCombo.currentData()
        if lang_code and self.parent.lang != lang_code:
            self.parent.lang = lang_code
            self.parent.config_data["lang"] = lang_code
            try: self.parent._apply_language_strings()
            except Exception: pass

        vis_mode_text = self.visModeCombo.currentText()
        if self.parent.vis_mode != vis_mode_text:
            self.parent.vis_mode = vis_mode_text
            self.parent.config_data["vis_mode"] = vis_mode_text
            if self.parent.vis_widget_main_window:
                self.parent.vis_widget_main_window.set_vis_mode(vis_mode_text)
            if self.parent.vis_window and hasattr(self.parent.vis_window.visualizationWidget, 'set_vis_mode'):
                self.parent.vis_window.visualizationWidget.set_vis_mode(vis_mode_text)

        sens = self.sensitivitySlider.value(); color_int = self.colorSlider.value(); density = self.densitySlider.value()
        self.parent.config_data["vis_sensitivity"] = sens
        self.parent.config_data["vis_color_intensity"] = color_int
        self.parent.config_data["vis_density"] = density
        if self.parent.vis_widget_main_window and hasattr(self.parent.vis_widget_main_window, 'set_vis_config'):
            self.parent.vis_widget_main_window.set_vis_config(sens, color_int, density)
        if self.parent.vis_window and self.parent.vis_window.visualizationWidget:
            if hasattr(self.parent.vis_window.visualizationWidget, 'set_vis_config'):
                self.parent.vis_window.visualizationWidget.set_vis_config(sens, color_int, density)

        if hasattr(self.parent, 'infoDisplayWidget'):
            self.parent.infoDisplayWidget.set_album_art_visibility(self.albumArtCheck.isChecked())
        # Kısayolları uygula
        try:
            sc_map = {}
            for key, editor in (self.shortcutsEditors or {}).items():
                try:
                    seq = editor.keySequence().toString()
                    if seq:
                        sc_map[key] = seq
                except Exception:
                    pass
            if sc_map:
                self.parent.config_data["shortcuts"] = sc_map
                # Uygula ve kaydet
                self.parent._apply_shortcuts_from_config()
        except Exception:
            pass
        self.parent.save_config()

    def _preview_playback_soft_transitions(self, *_args):
        """Ayarlar uygulanmadan önce (Apply/OK) anlık önizleme uygular."""
        try:
            pb_settings = {
                "stop_fade_enabled": bool(self.softStopCheck.isChecked()),
                "manual_crossfade_enabled": bool(self.manualCrossfadeCheck.isChecked()),
                "auto_crossfade_enabled": bool(self.autoCrossfadeCheck.isChecked()),
                "fade_out_on_pause": bool(self.fadeOutOnPauseCheck.isChecked()),
                "fade_in_on_resume": bool(self.fadeInOnResumeCheck.isChecked()),
                "crossfade_ms": int(self.crossfadeMsSpin.value()),
                "fade_ms": int(self.fadeMsSpin.value()),
            }
            self.parent.apply_playback_soft_transition_settings(pb_settings, preview=True)
            self._preview_dirty = True
        except Exception:
            pass

    def _share_clicked(self):
        current_file = self.parent.current_file_path
        if current_file:
            title, artist, _ = self.parent._get_tags_from_file(current_file)
            QMessageBox.information(
                self, self.parent._tr("share_success_title"),
                self.parent._tr("share_success_body").format(artist=artist, title=title)
            )
        else:
            QMessageBox.warning(
                self, self.parent._tr("share_error_title"),
                self.parent._tr("share_error_body")
            )


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    # Video için iki profil:
    #  - Varsayılan: Yazılım GL + GPU kapalı (siyah ekranı çözer)
    #  - ANGOLLA_HW_VIDEO=1 ise donanım hızlandırma (başarırsak daha akıcı)
    use_hw = os.environ.get("ANGOLLA_HW_VIDEO", "0") == "1"
    if use_hw:
        chrome_flags = [
            "--ignore-gpu-blocklist",
            "--enable-gpu",
            "--enable-gpu-rasterization",
            "--enable-zero-copy",
            "--disable-accelerated-video-decode",
            "--disable-gpu-memory-buffer-video-frames",
            "--audio-buffer-size=2048",
            "--disable-web-security",
            "--disable-audio-output-resampling",
            "--force-wave-audio",
            "--use-gl=desktop",
            "--disable-gpu-sandbox",
            "--no-sandbox",
            "--enable-features=VaapiVideoDecoder",
        ]
    else:
        # Yazılım GL + SwiftShader + GPU kapalı
        try:
            from PyQt5.QtCore import Qt, QCoreApplication
            QCoreApplication.setAttribute(Qt.AA_UseSoftwareOpenGL)
        except Exception:
            pass
        chrome_flags = [
            "--disable-gpu",
            "--disable-gpu-compositing",
            "--disable-accelerated-video-decode",
            "--disable-gpu-memory-buffer-video-frames",
            "--audio-buffer-size=2048",
            "--disable-software-rasterizer",
            "--disable-web-security",
            "--disable-audio-output-resampling",
            "--force-wave-audio",
            "--use-gl=swiftshader",
            "--ignore-gpu-blocklist",
            "--disable-gpu-sandbox",
            "--no-sandbox",
        ]

    os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = " ".join(chrome_flags)
    os.environ["QTWEBENGINE_DISABLE_SANDBOX"] = "1"

    # Varsayılan ayarlarda da tam ekran desteğini açık et
    try:
        QWebEngineSettings.defaultSettings().setAttribute(QWebEngineSettings.FullScreenSupportEnabled, True)
    except Exception:
        pass
    
    app = QApplication(sys.argv)
    app.setFont(QFont("Ubuntu", 10))
    
    window = AngollaPlayer()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    if MutagenFile is None:
        print("\n!!! UYARI: Mutagen yüklenmedi. 'pip install mutagen' ile yükleyin.")
    if np is None:
        print("\n!!! UYARI: NumPy yüklenmedi. Görselleştirme sınırlı çalışacak. 'pip install numpy' önerilir.")
    main()