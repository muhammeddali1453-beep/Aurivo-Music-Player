import numpy as np
import random # YENİ: Random eklendi
import os
import platform
import psutil
from PyQt5.QtWidgets import (
    QWidget, QMenu, QAction, QOpenGLWidget, QDialog, QVBoxLayout, 
    QHBoxLayout, QListWidget, QPushButton, QLineEdit, QLabel, QAbstractItemView,
    QGridLayout, QComboBox, QSpinBox, QListWidgetItem
)
from PyQt5.QtCore import QTimer, Qt, QRectF, QPointF, QTime
from PyQt5.QtGui import QPainter, QColor, QBrush, QPen, QPainterPath, QLinearGradient, QRadialGradient

# OpenGL import
try:
    from OpenGL.GL import glClearColor, glClear, GL_COLOR_BUFFER_BIT
    HAS_OPENGL = True
except ImportError:
    HAS_OPENGL = False
    print("⚠ PyOpenGL bulunamadı - OpenGL görselleştirme devre dışı")

# --- PROJECTM ENTEGRASYON KODU BAŞLANGICI ---
try:
    # viz_engine C++ modülünden ProjectM wrapper'ını yükle
    import viz_engine
    HAS_PROJECTM = hasattr(viz_engine, "ProjectM")
    if HAS_PROJECTM:
        print("✓ ProjectM C++ motoru yüklendi (viz_engine)")
    else:
        print("⚠ viz_engine yüklendi ama ProjectM sınıfı yok")
except ImportError as e:
    HAS_PROJECTM = False
    print(f"✗ viz_engine yüklenemedi: {e}")
# --- PROJECTM ENTEGRASYON KODU BİTİŞİ ---

# ============================================================================
# OTOMATİK SİSTEM ALGILAMA VE PERFORMANS YÖNETİMİ
# ============================================================================

class SystemPerformanceDetector:
    """Sistem yeteneklerini algılayıp uygun performans ayarlarını belirle"""
    
    def __init__(self):
        self.cpu_count = psutil.cpu_count(logical=True)
        self.cpu_freq = psutil.cpu_freq()
        self.memory = psutil.virtual_memory()
        self.platform = platform.system()
        
        # Performans profili hesapla
        self.profile = self._detect_profile()
        self.recommended_fps = self._get_recommended_fps()
        
        print(f"🖥️ Sistem Algılama:")
        print(f"   CPU: {self.cpu_count} çekirdek @ {self.cpu_freq.current if self.cpu_freq else 0:.0f} MHz")
        print(f"   RAM: {self.memory.total / (1024**3):.1f} GB (kullanılabilir: {self.memory.available / (1024**3):.1f} GB)")
        print(f"   Platform: {self.platform}")
        print(f"   Performans Profili: {self.profile.upper()}")
        print(f"   Önerilen FPS: {self.recommended_fps}")
    
    def _detect_profile(self):
        """Düşük/Orta/Yüksek performans profilini belirle"""
        score = 0
        
        # CPU skoru
        if self.cpu_count >= 8:
            score += 3
        elif self.cpu_count >= 4:
            score += 2
        else:
            score += 1
        
        # RAM skoru
        ram_gb = self.memory.total / (1024**3)
        if ram_gb >= 16:
            score += 3
        elif ram_gb >= 8:
            score += 2
        else:
            score += 1
        
        # CPU frekansı
        if self.cpu_freq and self.cpu_freq.current > 3000:
            score += 2
        elif self.cpu_freq and self.cpu_freq.current > 2000:
            score += 1
        
        # Profil belirleme
        if score >= 7:
            return "high"
        elif score >= 4:
            return "medium"
        else:
            return "low"
    
    def _get_recommended_fps(self):
        """Profile göre önerilen FPS"""
        if self.profile == "high":
            return 60  # Yüksek performans sistemler
        elif self.profile == "medium":
            return 45  # Orta seviye sistemler
        else:
            return 30  # Düşük performans sistemler
    
    def get_buffer_size(self):
        """Profile göre görselleştirme buffer boyutu"""
        if self.profile == "high":
            return 128
        elif self.profile == "medium":
            return 96
        else:
            return 64

class PerformanceMonitor:
    """Gerçek zamanlı performans izleme ve dinamik ayarlama"""
    
    def __init__(self, target_fps=60):
        self.target_fps = target_fps
        self.target_frame_time = 1000.0 / target_fps  # ms
        self.frame_times = []  # Son 60 frame süresi
        self.max_samples = 60
        self.last_frame_time = QTime.currentTime()
        self.fps_drop_count = 0
        self.adjustment_cooldown = 0
        
    def start_frame(self):
        """Frame başlangıcını işaretle"""
        self.last_frame_time = QTime.currentTime()
    
    def end_frame(self):
        """Frame bitişini işaretle ve performans analizi yap"""
        now = QTime.currentTime()
        elapsed = self.last_frame_time.msecsTo(now)
        
        self.frame_times.append(elapsed)
        if len(self.frame_times) > self.max_samples:
            self.frame_times.pop(0)
        
        return elapsed
    
    def get_avg_frame_time(self):
        """Ortalama frame süresi (ms)"""
        if not self.frame_times:
            return 0
        return sum(self.frame_times) / len(self.frame_times)
    
    def get_current_fps(self):
        """Gerçek zamanlı FPS"""
        avg = self.get_avg_frame_time()
        if avg > 0:
            return 1000.0 / avg
        return 0
    
    def is_performance_degraded(self):
        """Performans düşüşü var mı?"""
        if len(self.frame_times) < 30:
            return False
        
        avg = self.get_avg_frame_time()
        # Hedef sürenin %150'sinden fazlaysa sorun var
        return avg > (self.target_frame_time * 1.5)
    
    def should_reduce_quality(self):
        """Kalite düşürülmeli mi?"""
        if self.is_performance_degraded():
            self.fps_drop_count += 1
            if self.fps_drop_count > 10 and self.adjustment_cooldown <= 0:
                self.adjustment_cooldown = 120  # 2 saniye cooldown
                return True
        else:
            self.fps_drop_count = max(0, self.fps_drop_count - 1)
        
        if self.adjustment_cooldown > 0:
            self.adjustment_cooldown -= 1
        
        return False

class SwirlParticle:
    """3D Galaxy/Swirl Efekti için Parçacık Sınıfı"""
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

class PyQtGraphVisualizer(QWidget):
    """
    Angolla Music Player - Gelişmiş Spektrum Görselleştirici (Python-Native)
    Tam Özellikli:
    - Çoklu Modlar: Çubuklar, Çizgiler, Dalga, Daire
    - Renk Temaları: Mavi, Yeşil, Mor, Ateş, Beyaz
    - Efektler: Hayalet (Ghost) Efekti, Ayna Modu
    - Akıllı Adaptif AGC: Sessizlik algılama ve hızlı adaptasyon
    - Yüksek Performanslı QPainter Çizimi
    """
    def __init__(self, parent=None):
        super().__init__(parent)

        # Widget Ayarları
        self.setStyleSheet("background-color: #000000;")
        self.setAutoFillBackground(True)
        self.setContextMenuPolicy(Qt.DefaultContextMenu)

        # Sistem Algılama ve Performans Yönetimi
        self.system_detector = SystemPerformanceDetector()
        self.performance_monitor = PerformanceMonitor(target_fps=self.system_detector.recommended_fps)
        self.auto_quality_enabled = True  # Otomatik kalite ayarlama
        self.performance_warnings = 0

        # Veri Yapıları (Otomatik boyutlandırma)
        self.target_size = self.system_detector.get_buffer_size()
        self.data = np.zeros(self.target_size)
        self.target_data = np.zeros(self.target_size)
        self.smoothing_alpha = 0.20  # Seri tepki için artırıldı
        self.visual_gain = 1.6       # Orta seviye yükseklik (ses sonuna kadar dolmasın)
        # Adaptif seviye tahmini (Angolla benzeri sabit hedef)
        self.level_est = 0.55
        self.target_level = 0.6
        self.agc_attack = 0.18   # daha hızlı yükseliş tepkisi
        self.agc_release = 0.08  # yavaş düşüş tepkisi

        # Hayalet Efekti (Peak Hold)
        self.peak_data = np.zeros(self.target_size)
        self.peak_decay = 0.015
        # Serbest düşüş fiziği için ek buffer'lar
        self.bar_velocity = np.zeros(self.target_size, dtype=float)
        self.bar_gravity_accel = 0.015  # Yerçekimi ivmesi (daha hızlı düşüş)
        self.bar_gravity_damping = 0.88  # Hava direnci

        self.peak_velocity = np.zeros(self.target_size, dtype=float)
        self.peak_hold = np.zeros(self.target_size, dtype=int)
        self.peak_hold_frames = 4       # Çizgi tepeyi çok kısa tut
        # Yay benzeri (spring) tepe fiziği
        self.peak_fall_accel = 0.012     # Tepeler için yerçekimi
        self.peak_velocity_damping = 0.90
        self.peak_spring_k = 0.12        # Tepeyi bara doğru çeken yay sabiti

        # AGC / Limiter Değişkenleri
        self.agc_enabled = True
        self.max_peak = 0.5
        self.min_threshold = 0.15
        self.silence_timer = 0
        self.limiter_soft = True       # Yumuşak limiter (tanh) yüksek sesleri ezer
        self._agc_attack = 0.02        # Çok yavaş atak (düşmeyi engelle)
        self._agc_release = 0.15       # Hızlı release (hızla normale dön)

        # Görsel Ayarlar (Varsayılanlar)
        self.mode = "bars" # Varsayılan: Bar çözümleyici
        self.color_theme = "cyan"
        self.ghost_effect = True
        self.mirror_mode = False

        # 3D Swirl & Yoğunluk Verileri
        self.swirl_particles = []
        self.vis_density = 60
        self.vis_sensitivity = 50
        self.bass_intensity = 0.0
        self.mid_intensity = 0.0
        self.treble_intensity = 0.0
        self.sound_intensity = 0.0
        self.fps = self.system_detector.recommended_fps  # Otomatik FPS
        self.bar_phase = 0.0 # Animasyon fazı
        self.vis_color_intensity = 80 # Renk yoğunluğu
        self.vis_fps = self.system_detector.recommended_fps  # Otomatik FPS

        # ProjectM entegrasyon bayrakları (bazı widget'larda None kalabilir)
        self.projectm_engine = None
        self.engine_ready = False
        self.preset_hard_cut = False
        # ProjectM otomatik preset döngüsü
        self.pm_auto_cycle = False
        self.pm_cycle_interval = 15000  # ms
        self.pm_cycle_timer = QTimer(self)
        self.pm_cycle_timer.timeout.connect(self._pm_random)

        # Renk Paletleri (Gradient Başlangıç - Bitiş)
        self.colors = {
            "cyan":   (QColor(0, 220, 255), QColor(0, 80, 200)),  # Elektrik Mavisi
            "green":  (QColor(0, 255, 100), QColor(0, 100, 20)),  # Matrix Yeşili
            "purple": (QColor(220, 0, 255), QColor(80, 0, 150)),  # Neon Mor
            "fire":   (QColor(255, 200, 0), QColor(255, 20, 0)),   # Ateş
            "white":  (QColor(255, 255, 255), QColor(100, 100, 100)), # Siyah/Beyaz
            
            # --- Angolla Temalar (Ana Uygulama ile Uyumlu) ---
            "AURA Mavi":       (QColor("#40C4FF"), QColor("#0091EA")),
            "Zümrüt Yeşil":    (QColor("#00E676"), QColor("#00600F")),
            "Güneş Turuncusu": (QColor("#FF9800"), QColor("#E65100")),
            "Kırmızı Ateş":    (QColor("#FF1744"), QColor("#880E4F")),
            "Mor Gece":        (QColor("#7C4DFF"), QColor("#311B92")),
            "Obsidyen":        (QColor("#00E5FF"), QColor("#263238")),
            "Solar":           (QColor("#FFB300"), QColor("#FF6F00")),
            "Mint":            (QColor("#64FFDA"), QColor("#004D40")),
            "Neon Gece":       (QColor("#FF4081"), QColor("#880E4F")),
            "Slate":           (QColor("#82B1FF"), QColor("#37474F")),
            "Desert":          (QColor("#F4B183"), QColor("#E65100")),
            "Forest":          (QColor("#8BC34A"), QColor("#33691E")),
            "Candy":           (QColor("#FF6FB5"), QColor("#880E4F")),
            "Ice":             (QColor("#7AD7F0"), QColor("#01579B")),
            
            # --- ÖZEL EFEKT ---
            "rgb_aura":       (QColor(0,0,0), QColor(0,0,0)) # Kod içinde dinamik hesaplanacak
        }

        # Angolla Physics Vars (TÜM MODLAR için roof physics)
        self.clem_band_count = 96  # 64 → 96 (Angolla'a yakın yoğunluk)
        self.clem_bars = np.zeros(self.clem_band_count, dtype=float)
        self.clem_roofs = np.zeros(self.clem_band_count, dtype=float)
        self.clem_roof_velocity = np.zeros(self.clem_band_count, dtype=float)
        self.clem_roof_hold = np.zeros(self.clem_band_count, dtype=int) # Kaç frame tuttuğunu sayar
        
        # Angolla roof physics constants (tüm modlar için)
        # Peak çizgileri: KISA hold + HIZLI düşüş (yerçekimi tarzı)
        self.roof_hold_frames = 24  # 64 → 24 (çizgiler yukarıda kalmasın, hızlı düşsün)
        self.roof_fall_accel = 0.008  # 0.002 → 0.008 (daha güçlü yerçekimi)
        self.roof_velocity_damping = (1.0 - 1.0/16.0)  # 1/48 → 1/16 (hızlı decay)

        # Timer
        self.timer = QTimer(self)
        self._set_timer_interval()
        self.timer.timeout.connect(self.update)
        self.timer.start()

    def set_fps(self, fps):
        """Bars/wave render FPS değerini ayarla (PyQtGraph tabanlı)."""
        try:
            self.vis_fps = int(fps)
            # Performans monitörünü güncelle
            if hasattr(self, 'performance_monitor'):
                self.performance_monitor.target_fps = self.vis_fps
                self.performance_monitor.target_frame_time = 1000.0 / self.vis_fps
        except Exception:
            return
        self._set_timer_interval()

    def set_vis_config(self, sensitivity: int, color_intensity: int, density: int):
        """Ayarlar diyalogundan gelen görselleştirme konfigürasyonunu uygula."""
        try:
            self.vis_sensitivity = int(max(1, min(sensitivity, 100)))
            self.vis_color_intensity = int(max(1, min(color_intensity, 100)))
            self.vis_density = int(max(1, min(density, 100)))
        except Exception:
            return
        # Renk temasını yeniden hesaplayan veya partikül sayısını etkileyen alanlar bir sonraki update'de devreye girer.
        # PyQtGraph'ta anlık etkisi için repaint tetikle.
        self.update()

    def _set_timer_interval(self):
        # FPS değerini güvenli aralıkta sınırla ve zamanlayıcıyı atomik olarak güncelle
        # Not: Çok yüksek FPS (>
        # 90) bazı sistemlerde Qt/SIP yeniden çizim baskısı ile kararlılık sorunlarına yol açabiliyor.
        # Bu nedenle üst sınırı 90 FPS'e çekiyoruz ve minimum intervali 10ms yapıyoruz.
        fps_raw = int(getattr(self, "vis_fps", 60))
        # Üst sınırı 120 FPS; minimum 20 FPS (Angolla seçenekleriyle uyumlu)
        fps = max(20, min(fps_raw, 120))
        self.vis_fps = fps

        try:
            if self.timer.isActive():
                self.timer.stop()
        except Exception:
            pass

        # Çok düşük interval (<= 6ms) Qt event loop'u zorlayabilir.
        # 120 FPS için teorik 8.33ms; burada 8ms tabanı uyguluyoruz.
        interval_ms = max(8, int(1000 / max(fps, 1)))
        self.timer.setInterval(interval_ms)
        try:
            self.timer.start()
        except Exception:
            # Son çare: singleShot ile tetikleyerek UI thread'i canlı tutalım
            from PyQt5.QtCore import QTimer as _QTimer
            _QTimer.singleShot(interval_ms, self.update)

    def update_audio_buffer(self, audio_data: np.ndarray):
        if audio_data is None or len(audio_data) == 0:
            self.target_data[:] = 0
            return
        
        # Debug: İlk 3 çağrıda veri aldığını göster
        if not hasattr(self, '_update_count'):
            self._update_count = 0
        if self._update_count < 3:
            print(f"🎨 PyQtGraphVisualizer: Ses verisi alındı (#{self._update_count+1}), len={len(audio_data)}, max={np.max(audio_data):.2f}")
            self._update_count += 1

        y = np.abs(audio_data)
        # Duyarlılık: 50 referans alınarak ölçekleme. 50→1.0, 100→~2.0, 1→~0.05
        sens_gain = max(0.05, self.vis_sensitivity / 50.0)
        y = y * sens_gain

        # 1. Resize/Resample
        # 1. Dynamic Resize: Gelen veri boyutuna göre buffer'ları güncelle
        # Bu sayede main.py'den 96 veya 128 gelmesi fark etmez, adapte olur.
        if self.mode == "angolla":
             self._update_angolla_physics(y)
             return
        
        # Diğer modlar için standart işleme + ANGOLLA ROOF PHYSICS
        # Hedef veriyi güncelle (Smooth transition için)
        if len(y) != self.target_size:
            # Buffer boyutu uyuşmazsa yeniden ayarla
            self.target_size = len(y)
            self.data = np.zeros(self.target_size)
            self.target_data = np.zeros(self.target_size)
            self.peak_data = np.zeros(self.target_size)
            self.bar_velocity = np.zeros(self.target_size, dtype=float)
            self.peak_velocity = np.zeros(self.target_size, dtype=float)
            self.peak_hold = np.zeros(self.target_size, dtype=int)
            # Roof physics bufferlarını da güncelle
            self.clem_bars = np.zeros(self.target_size, dtype=float)
            self.clem_roofs = np.zeros(self.target_size, dtype=float)
            self.clem_roof_velocity = np.zeros(self.target_size, dtype=float)
            self.clem_roof_hold = np.zeros(self.target_size, dtype=int)
            print(f"📏 Visualizer buffer yeniden boyutlandırıldı: {self.target_size}")

        # 2. Log Scale
        y_log = np.log10(y + 1)

        # 3. AGC (Auto Gain Control) - ADAPTİF HIZLI İYİLEŞME
        if self.agc_enabled:
            # Angolla-benzeri: 85. persentil seviyeyi takip edip sabit hedefe yaklaştır
            current_level = float(np.percentile(y_log, 85))
            if current_level < 0.05:
                self.silence_timer += 1
            else:
                self.silence_timer = 0

            rate = self.agc_attack if current_level > self.level_est else self.agc_release
            self.level_est = (1 - rate) * self.level_est + rate * current_level

            # Hedefe göre kazanç hesapla ve sınırla
            gain = self.target_level / max(self.level_est, 1e-3)
            gain = np.clip(gain, 0.9, 4.0)

            y_norm = y_log * gain
        else:
            y_norm = y_log / 6.0

        # Kontrastı artır (dinamik his için biraz daha agresif)
        y_norm = y_norm ** 1.45


        # Noise Gate
        y_norm[y_norm < 0.02] = 0

        # Adaptif taban kesme: ortalama gürültüyü sıfırla ki barlar bağımsız oynasın
        avg_level = float(np.mean(y_norm))
        gate = max(0.01, avg_level * 0.20)
        y_norm = np.clip(y_norm - gate, 0.0, None)

        # Görsel kazanç: barların görünürlüğünü artır
        y_norm = y_norm * self.visual_gain

        # Yumuşak limiter: aşırı yüksek barların ekranda patlamasını engeller
        if self.limiter_soft:
            y_norm = np.tanh(y_norm * 1.05)

        # KESKİN yükselme / hızlı düşüş - NET hareketler (smooth değil!)
        alpha_up = 0.60   # yükselirken çok daha hızlı tepki
        alpha_down = 0.30 # düşerken daha hızlı
        prev = self.target_data
        next_vals = np.empty_like(prev)
        rising = y_norm >= prev
        next_vals[rising] = (1 - alpha_up) * y_norm[rising] + alpha_up * prev[rising]
        next_vals[~rising] = (1 - alpha_down) * y_norm[~rising] + alpha_down * prev[~rising]

        self.target_data = np.clip(next_vals, 0, 1.4)
        
        # ═══════════════════════════════════════════════════════════
        # BAR GRAVITY PHYSICS: Çubuklar yerçekimi ile serbest düşer
        # ═══════════════════════════════════════════════════════════
        if len(self.bar_velocity) != len(self.target_data):
            self.bar_velocity = np.zeros(len(self.target_data), dtype=float)
        
        for i in range(len(self.target_data)):
            target_h = self.target_data[i]
            current_h = self.data[i]

            if target_h > current_h:
                # Ses çubukları yukarı doğru fırlatır
                current_h = target_h
                self.bar_velocity[i] = 0.0
            else:
                # Ses desteği yoksa yerçekimi aşağı çeker
                self.bar_velocity[i] = (self.bar_velocity[i] + self.bar_gravity_accel) * self.bar_gravity_damping
                current_h = max(0.0, current_h - self.bar_velocity[i])

            # Minik değerleri sıfırla ki titreme olmasın
            if current_h < 0.0005:
                current_h = 0.0
                self.bar_velocity[i] = 0.0

            self.data[i] = current_h
        

        # ═══════════════════════════════════════════════════════════
        # PEAK (GHOST) FIZIGI: Tepeler kısa bekleyip serbest düşer
        # ═══════════════════════════════════════════════════════════
        if len(self.peak_velocity) != len(self.target_data):
            self.peak_velocity = np.zeros(len(self.target_data), dtype=float)
            self.peak_hold = np.zeros(len(self.target_data), dtype=int)
            self.peak_data = np.zeros(len(self.target_data), dtype=float)

        for i in range(len(self.target_data)):
            bar_height = self.data[i]

            if bar_height > self.peak_data[i]:
                # Tepeyi anında bar seviyesine çek
                self.peak_data[i] = bar_height
                self.peak_velocity[i] = 0.0
                self.peak_hold[i] = self.peak_hold_frames
            else:
                if self.peak_hold[i] > 0:
                    self.peak_hold[i] -= 1
                else:
                    # Yay benzeri hareket: bar_height hedef, tepe yayla geri çekilir
                    force = (bar_height - self.peak_data[i]) * self.peak_spring_k
                    self.peak_velocity[i] = (self.peak_velocity[i] + force) * self.peak_velocity_damping
                    # Yerçekimi ekle
                    self.peak_velocity[i] -= self.peak_fall_accel

                    new_peak = self.peak_data[i] + self.peak_velocity[i]
                    if new_peak < 0.0005:
                        new_peak = 0.0
                        self.peak_velocity[i] = 0.0
                    self.peak_data[i] = new_peak

        # --- YENİ: Detaylı Yoğunluk Analizi (Swirl/Galaxy için) ---
        # 3 band'a böl: Bass (%0-15), Mid (%15-50), Treble (%50-100)
        clip_data = self.target_data
        n_bins = len(clip_data)

        # Bass
        bass_end = int(n_bins * 0.15)
        self.bass_intensity = np.mean(clip_data[:bass_end]) if bass_end > 0 else 0

        # Mid
        mid_end = int(n_bins * 0.50)
        self.mid_intensity = np.mean(clip_data[bass_end:mid_end]) if mid_end > bass_end else 0

        # Treble
        self.treble_intensity = np.mean(clip_data[mid_end:]) if n_bins > mid_end else 0

        # Genel Ses Şiddeti
        self.sound_intensity = np.mean(clip_data)

    def contextMenuEvent(self, event):
        menu = QMenu(self)
        menu.setStyleSheet("""
            QMenu { background-color: #222; color: #eee; border: 1px solid #444; }
            QMenu::item { padding: 5px 20px; }
            QMenu::item:selected { background-color: #0078d7; }
        """)

        # Başlık
        title = menu.addAction("Görselleştirme Ayarları")
        title.setEnabled(False)
        menu.addSeparator()

        # --- Modlar ---
        mod_menu = menu.addMenu("📊 Görselleştirme Modu")

        action_map = {
            "bars": "Bar çözümleyici",
            "pyramid_bars": "Piramit",
            "mirror_bars": "Ayna Modu",
            "round_bars": "Yuvarlak Barlar",
            "lines": "Osiloskop",
            "wave": "Dalga",
            "circle": "Daire",
            "swirl3d": "3D Galaxy",
            "energy_ring": "Energy Ring"
        }

        # İsimleri Screenshot'a göre güncelle (Kullanıcı İsteği)
        # Screenshot: "Bar çözümleyici", "Blok çözümleyici", "Sonogram", "Türbin"
        # Bizdekileri bu isimlere map edelim:
        action_map["bars"] = "Bar çözümleyici"
        action_map["pyramid_bars"] = "Blok çözümleyici" # Yakın eşleşme
        # Boom çözümleyici kaldırıldı (Kullanıcı isteği)
        
        # Diğerleri olduğu gibi kalsın veya yenilerini ekleyelim

        for m_key, m_name in action_map.items():
            act = mod_menu.addAction(m_name)
            act.setCheckable(True)
            act.setChecked(self.mode == m_key)
            act.triggered.connect(lambda chk, m=m_key: self.set_mode(m))

        # --- Renkler ---
        col_menu = menu.addMenu("🎨 Renk Teması")
        # Tüm tanımlı renkleri menüye ekle
        for c_key in self.colors.keys():
            # İsim güzelleştirme (varsa)
            display_name = c_key
            if c_key == "cyan": display_name = "Mavi (Varsayılan)"
            elif c_key == "green": display_name = "Matrix Yeşili"
            elif c_key == "rgb_aura": display_name = "🌈 RGB Aura (Asus Style)"
            
            act = col_menu.addAction(display_name)
            act.setCheckable(True)
            act.setChecked(self.color_theme == c_key)
            act.triggered.connect(lambda chk, c=c_key: self.set_color(c))

        menu.addSeparator()

        # --- Efektler ---

        # Hayalet Efekti
        act_ghost = menu.addAction("👻 Hayalet Efekti (Peak)")
        act_ghost.setCheckable(True)
        act_ghost.setChecked(self.ghost_effect)
        act_ghost.triggered.connect(lambda chk: self.set_option("ghost", chk))

        # Ayna Modu
        act_mirror = menu.addAction("🪞 Ayna Modu (Simetri)")
        act_mirror.setCheckable(True)
        act_mirror.setChecked(self.mirror_mode)
        act_mirror.triggered.connect(lambda chk: self.set_option("mirror", chk))

        # FPS Seçimi (Angolla tarzı etiketlerle)
        fps_menu = menu.addMenu("⏱️ FPS")
        fps_options = [
            ("Düşük (20 fps)", 20),
            ("Orta (25 fps)", 25),
            ("Yüksek (30 fps)", 30),
            ("Süper yüksek (60 fps)", 60),
        ]
        for label, fps_val in fps_options:
            act_fps = fps_menu.addAction(label)
            act_fps.setCheckable(True)
            act_fps.setChecked(int(getattr(self, "vis_fps", 60)) == fps_val)
            act_fps.triggered.connect(lambda chk, v=fps_val: self.set_fps(v))

        menu.addSeparator()
        # Ana görselleştirme penceresini açma
        if hasattr(self.parent(), "toggle_visualization_window"):
            act_open = menu.addAction("🖼️ Görselleştirme Penceresini Aç")
            act_open.triggered.connect(self.parent().toggle_visualization_window)

        # ProjectM preset kontrolleri
        if HAS_PROJECTM and self.projectm_engine:
            menu.addSeparator()
            preset_menu = menu.addMenu("🎆 ProjectM Presetleri")

            act_rand = preset_menu.addAction("🎲 Rastgele Preset")
            act_rand.triggered.connect(self._pm_random)

            preset_menu.addSeparator()
            act_hard = preset_menu.addAction("⚡ Keskin Geçiş (Hard Cut)")
            act_hard.setCheckable(True)
            act_hard.setChecked(self.preset_hard_cut)
            act_hard.triggered.connect(self._toggle_hard_cut)

        # NOT: AGC menüden kaldırıldı ama arka planda her zaman çalışıyor.

        menu.exec_(event.globalPos())

    # --- ProjectM preset helpers ---
    def _pm_random(self):
        if self.projectm_engine and self.engine_ready:
            try:
                self.projectm_engine.preset_random(self.preset_hard_cut)
            except Exception as e:
                print(f"✗ ProjectM random preset hatası: {e}")

    def _toggle_hard_cut(self, val):
        self.preset_hard_cut = bool(val)

    def toggle_mode(self):
        modes = ["bars", "pyramid_bars", "mirror_bars", "round_bars", "energy_ring", "swirl_3d", "wave", "angolla"]
        try:
            current_idx = modes.index(self.mode)
            self.mode = modes[(current_idx + 1) % len(modes)]
        except ValueError:
            self.mode = "bars"

    def set_mode(self, mode):
        self.mode = mode
        self.update()

    def set_color(self, color):
        self.color_theme = color
        self.update()

    def set_option(self, opt, val):
        if opt == "ghost": self.ghost_effect = val
        elif opt == "mirror": self.mirror_mode = val
        elif opt == "agc": self.agc_enabled = val
        elif opt == "auto_quality": self.auto_quality_enabled = val
        self.update()
    
    def _reduce_quality(self):
        """Performans düşüşünde otomatik kalite azaltma"""
        self.performance_warnings += 1
        
        if self.performance_warnings == 1:
            # İlk uyarı: FPS'i düşür
            current_fps = self.vis_fps
            if current_fps > 30:
                new_fps = max(30, current_fps - 15)
                self.set_fps(new_fps)
                print(f"⚠️ Performans düşük - FPS otomatik düşürüldü: {current_fps} → {new_fps}")
        elif self.performance_warnings == 2:
            # İkinci uyarı: Efektleri kapat
            if self.ghost_effect:
                self.ghost_effect = False
                print(f"⚠️ Performans düşük - Hayalet efekti kapatıldı")
        elif self.performance_warnings >= 3:
            # Üçüncü uyarı: Buffer boyutunu küçült
            if self.target_size > 64:
                old_size = self.target_size
                self.target_size = max(64, self.target_size - 32)
                self._resize_buffers()
                print(f"⚠️ Performans düşük - Buffer boyutu küçültüldü: {old_size} → {self.target_size}")
                self.performance_warnings = 0  # Reset
    
    def _resize_buffers(self):
        """Buffer'ları yeniden boyutlandır"""
        self.data = np.zeros(self.target_size)
        self.target_data = np.zeros(self.target_size)
        self.peak_data = np.zeros(self.target_size)
        self.bar_velocity = np.zeros(self.target_size, dtype=float)
        self.peak_velocity = np.zeros(self.target_size, dtype=float)
        self.peak_hold = np.zeros(self.target_size, dtype=int)
        self.clem_bars = np.zeros(self.target_size, dtype=float)
        self.clem_roofs = np.zeros(self.target_size, dtype=float)
        self.clem_roof_velocity = np.zeros(self.target_size, dtype=float)
        self.clem_roof_hold = np.zeros(self.target_size, dtype=int)

    def paintEvent(self, event):
        # Performans monitörü - frame başlangıcı
        if hasattr(self, 'performance_monitor'):
            self.performance_monitor.start_frame()
        
        painter = QPainter(self)
        
        # Antialiasing - düşük performansta kapat
        if hasattr(self, 'system_detector') and self.system_detector.profile != "low":
            painter.setRenderHint(QPainter.Antialiasing)

        # Animasyon fazını güncelle
        self.bar_phase += 0.5

        # Çizim Verisi Hazırla
        if self.mode == "angolla":
            draw_data = self.clem_bars
            draw_peaks = self.clem_roofs
        else:
            draw_data = self.data
            draw_peaks = self.peak_data

        if self.mirror_mode:
            # Ortadan ikiye ayna: [Data reversed] + [Data]
            draw_data = np.concatenate((draw_data[::-1], draw_data))
            draw_peaks = np.concatenate((draw_peaks[::-1], draw_peaks))

        # Mod Çizimi Çağır
        if self.mode == "angolla":
             self._draw_angolla_bars(painter)
        elif self.mode in ["bars", "pyramid_bars", "mirror_bars", "round_bars"]:
            self._draw_bars(painter, draw_data, draw_peaks)
        elif self.mode == "lines":
            self._draw_lines(painter, draw_data)
        elif self.mode == "wave":
            self._draw_lines(painter, draw_data, is_wave=True)
        elif self.mode == "circle":
            self._draw_circle(painter, draw_data)
        elif self.mode == "swirl3d":
            self._draw_3d_swirl(painter, self.width(), self.height(), draw_data)
        elif self.mode == "energy_ring":
            self._draw_energy_ring(painter, self.width(), self.height(), draw_data)
        else:
            self._draw_bars(painter, draw_data, draw_peaks)
        
        # Performans monitörü - frame bitişi ve analiz
        if hasattr(self, 'performance_monitor'):
            frame_time = self.performance_monitor.end_frame()
            
            # Her 60 frame'de bir performans kontrolü
            if len(self.performance_monitor.frame_times) >= 60:
                if self.auto_quality_enabled and self.performance_monitor.should_reduce_quality():
                    self._reduce_quality()
                    self.performance_monitor.frame_times.clear()  # Reset

    def _draw_energy_ring(self, painter, w, h, data):
        """
        Energy Ring / Energy Flower
        - FFT bantlarını merkezden dışa halka şeklinde çizer
        - Ses yoğunluğuna göre renk ve boyut değişir
        - Bass vuruşlarında pulsating efekt
        """
        if not data is not None and len(data) > 0:
            return

        cx, cy = w // 2, h // 2
        max_r = min(w, h) // 2 * 0.85
        count = len(data)

        # Arka plan gradient (koyu)
        try:
            gradient = QRadialGradient(cx, cy, max_r)
            gradient.setColorAt(0, QColor(20, 10, 30, 255))
            gradient.setColorAt(1, QColor(5, 5, 15, 255))
            painter.fillRect(0, 0, w, h, gradient)
        except:
             painter.fillRect(0, 0, w, h, QColor(0,0,0))

        # Ana enerji halkası - FFT değerlerine göre titreşen
        num_petals = min(count, 64)  # Maksimum 64 petal

        for i in range(num_petals):
            v = data[int(i * len(data) / num_petals)] if len(data) > 0 else 0.0
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

            color = QColor.fromHsv(hue % 360, min(255, saturation), min(255, value), min(255, alpha))

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

    def _draw_3d_swirl(self, painter, w, h, data):
        """
        3D Swirl / Galaxy Mode (Ported from Angolla Visual)
        - FFT verilerine göre dönen parçacık sistemi
        - Parçacıkların rengi bass + mid + treble'a göre değişir
        - 3D derinlik efekti (Z-axis simulation)
        """
        cx, cy = w // 2, h // 2
        max_r = min(w, h) // 2 * 0.9

        # Arka plan (koyu, space-like)
        # NOT: Zaten siyah arka plan var, üzerine şeffaf bir katman atabiliriz derinlik için
        # painter.fillRect(0, 0, w, h, QColor(5, 5, 15, 255))

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
            size = particle.size * z_scale
            if size < 1: size = 1

            particles_with_depth.append((particle.z, x, y, size, particle.color))

        # Z-depth'e göre sırala (uzaktan yakına = depth-buffer simulation)
        particles_with_depth.sort(key=lambda p: p[0])

        painter.setPen(Qt.NoPen)

        for z, x, y, size, color in particles_with_depth:
            # Renk modifikasyonu: bass/mid/treble yoğunluğuna göre

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
            painter.drawEllipse(int(x - size/2), int(y - size/2), int(size), int(size))

    def _get_colors(self):
        return self.colors.get(self.color_theme, self.colors["cyan"])

    def _draw_bars(self, p, data, peaks):
        w = self.width()
        h = self.height()
        count = len(data)
        
        # Stil modifikasyonları için veri işleme
        display_data = list(data)
        display_peaks = list(peaks)
        
        if self.mode == "pyramid_bars":
            # Piramit: Baslar ortada, tizler kenarlarda
            # Veriyi ikiye böl, bir yarısını ters çevirip birleştir
            half = count // 2
            new_data = [0.0] * count
            new_peaks = [0.0] * count
            mid = count // 2
            
            # Baslar (düşük index) ortaya doğru yayılır
            for i in range(min(half, len(data))): # Ensure index is within bounds
                val = data[i] 
                pk = peaks[i]
                
                # Place current frequency band symmetrically around the center
                # Example: data[0] -> new_data[mid], data[1] -> new_data[mid+1] and new_data[mid-2]
                # This creates a pyramid where lower frequencies are central.
                if mid + i < count:
                    new_data[mid + i] = val
                    new_peaks[mid + i] = pk
                if mid - 1 - i >= 0:
                    new_data[mid - 1 - i] = val
                    new_peaks[mid - 1 - i] = pk
            
            display_data = new_data
            display_peaks = new_peaks
            
        elif self.mode == "mirror_bars":
             # Ayna: Üstte ve altta barlar
             # Bu draw içinde halledilecek
             pass

        bar_w = w / count
        # ⚡ Angolla rendering: bar 85% → 95% (daha geniş, gap minimum)
        bar_width_ratio = 0.95  # Gap minimize edildi
        
        c1, c2 = self._get_colors()

        p.setPen(Qt.NoPen)

        for i, val in enumerate(display_data):
            bar_h = val * h
            
            if self.mode == "mirror_bars":
                # Ortadan yukarı ve aşağı
                # bar_h toplam yükseklik, yarısı yukarı yarısı aşağı
                x = i * bar_w
                cy = h / 2
                half_h = bar_h / 2
                y_top = cy - half_h
                rect = QRectF(x, y_top, bar_w * bar_width_ratio, bar_h)
            else:
                x = i * bar_w
                y = h - bar_h
                rect = QRectF(x, y, bar_w * bar_width_ratio, bar_h)

            # Gradyan
            if self.color_theme == "rgb_aura":
                hue = int((i * 4 - self.bar_phase * 2) % 360) 
                c1 = QColor.fromHsv(hue, 255, 255)
                c2 = QColor.fromHsv(hue, 240, 100)
            
            grad = QLinearGradient(rect.topLeft(), rect.bottomLeft())
            grad.setColorAt(0, c2 if self.mode != "mirror_bars" else c1)
            grad.setColorAt(0.5, c1) 
            grad.setColorAt(1, c2) 
            # Mirror modda orta parlak, uçlar koyu olsun
            
            p.setBrush(grad)

            # Çubuk Çiz
            if self.mode == "round_bars":
                p.drawRoundedRect(rect, bar_w * 0.3, bar_w * 0.3)  # Daha ince corner radius
            else:
                p.drawRect(rect)

            # Hayalet Çizgi (Peak) - Angolla tarzı (1px)
            if self.ghost_effect:
                peak_h = display_peaks[i] * h
                if self.mode == "mirror_bars":
                    # Mirror peak: üstte ve altta çizgi
                    peak_y = h - peak_h
                    # Angolla tarzı ince peak çizgi (1px)
                    p.fillRect(QRectF(x, peak_y - 1, bar_w * bar_width_ratio, 1), QColor(255, 255, 255, 220))
                else:
                    # Normal mode peak (1px)
                    peak_y = h - peak_h
                    p.fillRect(QRectF(x, peak_y - 1, bar_w * bar_width_ratio, 1), QColor(255, 255, 255, 220))

    def _update_angolla_physics(self, raw_data):
        """
        Angolla kaynak kodundan port edilmiş fizik motoru.
        Mantık:
        1. Logaritmik scale (Low volume detail)
        2. Lineer yerçekimi (Sabit hızda düşüş)
        3. Sticky Peaks (Tepede asılı kalma + hızlanan düşüş)
        """
        if raw_data is None or len(raw_data) == 0:
            return

        # 1. Resample raw_data to clem_band_count (Linear Interp)
        # 64 bar genellikle idealdir
        current_scope = np.interp(
            np.linspace(0, len(raw_data), self.clem_band_count),
            np.arange(len(raw_data)),
            raw_data
        )

        # Fizik parametreleri (Angolla kaynak kodundan uyarlı)
        # Hız ayarları (lineer düşüş tabanı)
        max_down = 0.060

        # Peak (Roof) parametreleri (Angolla benzeri)
        # kRoofHoldTime = 48; kRoofVelocityReductionFactor = 32
        roof_hold_frames = 24
        roof_fall_accel = 0.010
        roof_velocity_damping = (1.0 - 1.0/32.0)  # her karede hız sönümü
        
        # GÜRÜLTÜ AZALTMA & GAIN AYARLARI
        # Kullanıcı isteği: Saf ses algılama (Noise Gate) + Dengeli yükseklik
        noise_gate = 0.03 # %3 altındaki sesleri görmezden gel (Dip gürültüsü)
        
        # BALANCED GAIN: Dengeli yükseklik (5x)
        gain_boost = 5.0 

        for i in range(self.clem_band_count):
            val = current_scope[i]
            
            # 1. Gain Boost (Daha yükseğe zıplasın)
            val = val * self.visual_gain * gain_boost
            
            # 2. Noise Gate (Saf ses)
            if val < noise_gate * self.visual_gain * gain_boost: # Gate'i de scale et
                if val < noise_gate: # Veya ham değer kontrolü
                     val = 0.0
            
            # 3. Curve Boost (Düşük midleri daha da parlat)
            if val > 0:
                val = val ** 0.8
            
            if val < 0: val = 0
            if val > 1: val = 1
            
            target_h = np.log10(1.0 + 255.0 * val) / 2.408 # log10(256) ≈ 2.408
            
            if target_h > 1.0: target_h = 1.0
            
            # -- Bar Physics --
            current_h = self.clem_bars[i]
            
            if target_h > current_h:
                 # YUKARI: INSTANT RISE (1.0)
                 self.clem_bars[i] = target_h
            else:
                 # AŞAĞI: Lineer Düşüş
                 new_h = current_h - max_down
                 if new_h < target_h: new_h = target_h 
                 if new_h < 0: new_h = 0
                 self.clem_bars[i] = new_h

            # -- Roof (Peak) Physics --
            if self.clem_bars[i] > self.clem_roofs[i]:
                # Yeni tepeye anında çık ve roof'u tut
                self.clem_roofs[i] = self.clem_bars[i]
                self.clem_roof_velocity[i] = 0.0
                self.clem_roof_hold[i] = roof_hold_frames
            else:
                if self.clem_roof_hold[i] > 0:
                    # Bekleme süresi boyunca roof sabit kalsın
                    self.clem_roof_hold[i] -= 1
                else:
                    # Hızlanarak düş, fakat her karede sönümle (kRoofVelocityReductionFactor)
                    self.clem_roof_velocity[i] = (self.clem_roof_velocity[i] + roof_fall_accel) * roof_velocity_damping
                    self.clem_roofs[i] -= self.clem_roof_velocity[i]
                    if self.clem_roofs[i] < 0:
                        self.clem_roofs[i] = 0.0
                        self.clem_roof_velocity[i] = 0.0

    def _draw_angolla_bars(self, p):
        """
        Angolla tarzı çizim.
        Referans: Koyu Mavi -> Açık Cyan Gradient
        Kayıp (Gap): Çok ince (1px)
        """
        w = self.width()
        h = self.height()
        
        count = self.clem_band_count
        bar_w = w / count
        
        # Renkler (Referans görselden)
        # Alt: Koyu Lacivert/Mavi
        # Üst: Parlak Turkuaz/Cyan
        c_bottom = QColor(0, 50, 150)   # Koyu Mavi
        c_top = QColor(100, 255, 255)   # Parlak Cyan
        
        if self.color_theme != "cyan": 
             c_top, c_bottom = self._get_colors()

        p.setPen(Qt.NoPen)
        
        gap = 1 # 1 pixel gap for crisp look
        
        for i in range(count):
            bar_h = self.clem_bars[i] * h
            roof_h = self.clem_roofs[i] * h
            
            x = int(i * bar_w)
            w_draw = int(bar_w) - gap
            if w_draw < 1: w_draw = 1
            
            # 1. Bar Çizimi
            y = h - bar_h
            rect = QRectF(x, y, w_draw, bar_h) 
            
            # Basit Gradient
            grad = QLinearGradient(x, h, x, 0)
            grad.setColorAt(0, c_bottom)
            grad.setColorAt(1, c_top)
            
            p.setBrush(grad)
            p.drawRect(rect)
            
            # 2. Roof (Peak) Çizimi - İnce ve Keskin
            peak_y = int(h - roof_h)
            p.fillRect(x, peak_y - 1, w_draw, 2, QColor(255, 255, 255, 255))


    def _draw_lines(self, p, data, is_wave=False):
        w = self.width()
        h = self.height()
        count = len(data)

        c1, c2 = self._get_colors()

        path = QPainterPath()

        if is_wave:
            # Dalga formu (Ortada hizalı)
            cy = h / 2
            path.moveTo(0, cy)
            for i, val in enumerate(data):
                x = i * (w / (count - 1))
                amp = val * (h / 2)
                path.lineTo(x, cy - amp)
            # Alt taraf için geri dön
            for i in range(count - 1, -1, -1):
                x = i * (w / (count - 1))
                amp = data[i] * (h / 2)
                path.lineTo(x, cy + amp)
            path.closeSubpath()
        else:
            # Normal Alan Grafiği (Alttan hizalı)
            path.moveTo(0, h)
            for i, val in enumerate(data):
                x = i * (w / (count - 1))
                y = h - (val * h)
                path.lineTo(x, y)
            path.lineTo(w, h)
            path.closeSubpath()

        # Dolgu
        fill_color = QColor(c1)
        fill_color.setAlpha(120)
        p.setBrush(fill_color)
        p.setPen(QPen(c1, 2))
        p.drawPath(path)

    def _draw_circle(self, p, data):
        w = self.width()
        h = self.height()
        cx, cy = w/2, h/2

        c1, c2 = self._get_colors()

        # Basal Yarıçap
        base_r = min(w, h) * 0.2
        max_dist = min(w, h) * 0.3

        # Daire etrafına noktalar diz
        count = len(data)
        angle_step = (2 * np.pi) / count

        # Dış Çizgi Yolu
        path_out = QPainterPath()

        points = []
        for i, val in enumerate(data):
            angle = i * angle_step - (np.pi / 2) # Tepeden başla
            r = base_r + (val * max_dist)
            x = cx + r * np.cos(angle)
            y = cy + r * np.sin(angle)
            points.append(QPointF(x, y))

        if points:
            path_out.moveTo(points[0])
            for pt in points[1:]:
                path_out.lineTo(pt)
            path_out.closeSubpath()

        # Çiz
        p.setPen(QPen(c1, 2))
        p.setBrush(QColor(c2.red(), c2.green(), c2.blue(), 100))
        p.drawPath(path_out)

        # Merkezde Bass Efekti
        avg = np.mean(data)
        pulse_r = base_r * (0.8 + avg * 0.5)
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(255, 255, 255, 30))
        p.drawEllipse(QPointF(cx, cy), pulse_r, pulse_r)




# ============================================================================
# PROJECTM PRESET SELECTION DIALOG (ANGOLLA STYLE)
# ============================================================================

class PresetSelectionDialog(QDialog):
    def __init__(self, visualizer, parent=None):
        super().__init__(parent)
        self.visualizer = visualizer
        self.setWindowTitle("Görsel seç")
        self.resize(600, 500)
        # Daha parlak, daha belirgin stiller (Angolla benzeri)
        self.setStyleSheet("""
            QDialog { background-color: #353535; color: #f0f0f0; font-family: Segoe UI, sans-serif; }
            QListWidget { 
                background-color: #252525; 
                color: #ffffff; 
                border: 1px solid #555;
                font-size: 13px;
                border-radius: 4px;
                outline: none;
            }
            QListWidget::item { 
                padding: 6px; 
                border-bottom: 1px solid #303030; 
                color: #e0e0e0;
            }
            QListWidget::item:selected { 
                background-color: #0078d7; 
                color: #ffffff;
            }
            QListWidget::item:hover { 
                background-color: #3a3a3a; 
            }
            QListWidget::indicator { 
                width: 18px; 
                height: 18px; 
                border: 1px solid #888;
                background: #444;
                border-radius: 3px;
            }
            QListWidget::indicator:checked {
                background: #0078d7;
                border-color: #0099ff;
                image: none; /* Standart tik yerine renk değişimi */
            }
            
            QComboBox, QSpinBox {
                background-color: #444;
                color: #fff;
                border: 1px solid #666;
                padding: 5px;
                border-radius: 3px;
                min-height: 25px;
            }
            QComboBox::drop-down { border: none; }
            QComboBox QAbstractItemView {
                background-color: #444;
                color: #fff;
                selection-background-color: #0078d7;
            }
            
            QPushButton {
                background-color: #555;
                color: #fff;
                border: 1px solid #666;
                padding: 6px 15px;
                border-radius: 4px;
                min-width: 80px;
            }
            QPushButton:hover { background-color: #666; border-color: #888; }
            QPushButton:pressed { background-color: #444; }
            QLabel { color: #ddd; }
        """)

        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(15, 15, 15, 15)

        # 1. Üst Kontroller
        top_layout = QGridLayout()
        top_layout.setSpacing(10)

        # Görüntüleme kipi
        top_layout.addWidget(QLabel("Görüntüleme kipi", alignment=Qt.AlignRight), 0, 0)
        self.combo_mode = QComboBox()
        self.combo_mode.addItems(["Listeden seç", "Rastgele", "Sabit"])
        top_layout.addWidget(self.combo_mode, 0, 1)

        # Gecikme
        top_layout.addWidget(QLabel("Görselleştirmeler arasındaki gecikme", alignment=Qt.AlignRight), 1, 0)
        
        delay_layout = QHBoxLayout()
        self.spin_delay = QSpinBox()
        self.spin_delay.setRange(5, 3600)
        self.spin_delay.setValue(15) # Default 15 sec
        self.spin_delay.setSuffix(" saniye")
        delay_layout.addWidget(self.spin_delay)
        delay_layout.addStretch()
        
        top_layout.addLayout(delay_layout, 1, 1)
        
        layout.addLayout(top_layout)

        # 2. Liste
        self.list_widget = QListWidget()
        self.list_widget.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.list_widget.setAlternatingRowColors(True)
        # ÖNEMLİ: Seçim değişince önizleme yap
        self.list_widget.itemClicked.connect(self.preview_preset)
        layout.addWidget(self.list_widget)

        # 3. Alt Butonlar
        bottom_layout = QHBoxLayout()
        
        self.btn_select_all = QPushButton("Tümünü Seç")
        self.btn_select_none = QPushButton("Hiçbirini Seçme")
        
        self.btn_select_all.clicked.connect(self.select_all)
        self.btn_select_none.clicked.connect(self.select_none)
        
        bottom_layout.addWidget(self.btn_select_all)
        bottom_layout.addWidget(self.btn_select_none)
        bottom_layout.addStretch()
        
        self.btn_ok = QPushButton("✔ Tamam")
        self.btn_ok.setStyleSheet("background-color: #0078d7; font-weight: bold; border: none;")
        self.btn_ok.clicked.connect(self.accept_config)
        bottom_layout.addWidget(self.btn_ok)
        
        layout.addLayout(bottom_layout)

        # Yükle
        self.all_presets = []
        self.load_presets()
        self.load_current_config()

    def load_presets(self):
        self.list_widget.clear()
        eng = self.visualizer.projectm_engine
        if not eng: return

        try:
            count = eng.get_playlist_size()
            for i in range(count):
                name = eng.get_preset_name(i)
                self.all_presets.append((i, name))
                
                item = QListWidgetItem(name)
                item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
                item.setCheckState(Qt.Unchecked)
                item.setData(Qt.UserRole, i)
                self.list_widget.addItem(item)
        except Exception as e:
            print(f"Preset loading error: {e}")

    def load_current_config(self):
        # Visualizer'dan mevcut configi al
        cfg = getattr(self.visualizer, 'preset_config', {})
        
        # Mode
        mode_idx = cfg.get("mode_index", 0)
        self.combo_mode.setCurrentIndex(mode_idx)

        # Delay
        delay = cfg.get("delay", 15)
        self.spin_delay.setValue(delay)

        # Selected Items
        selected_indices = cfg.get("selected_indices", set())
        
        # Eğer config boşsa (ilk açılış), hepsini seçili yap (Angolla mantığı)
        if not cfg:
            self.select_all()
        else:
            for i in range(self.list_widget.count()):
                item = self.list_widget.item(i)
                idx = item.data(Qt.UserRole)
                if idx in selected_indices:
                    item.setCheckState(Qt.Checked)
    
    def select_all(self):
        for i in range(self.list_widget.count()):
            self.list_widget.item(i).setCheckState(Qt.Checked)
            
    def select_none(self):
        for i in range(self.list_widget.count()):
            self.list_widget.item(i).setCheckState(Qt.Unchecked)

    def preview_preset(self, item=None):
        """Listeden seçilene tıklandığında önizleme yap"""
        if item is None:
            item = self.list_widget.currentItem()
        if item:
            idx = item.data(Qt.UserRole)
            print(f"👁 Önizleme: Index {idx}")
            self.visualizer.set_preset(idx)
        else:
            print("✗ Önizleme: Item bulunamadı")

    def accept_config(self):
        # Ayarları topla ve Visualizer'a kaydet
        selected_indices = set()
        for i in range(self.list_widget.count()):
            item = self.list_widget.item(i)
            if item.checkState() == Qt.Checked:
                selected_indices.add(item.data(Qt.UserRole))
        
        config = {
            "mode_index": self.combo_mode.currentIndex(),
            "mode_str": self.combo_mode.currentText(),
            "delay": self.spin_delay.value(),
            "selected_indices": selected_indices
        }
        
        self.visualizer.apply_preset_Config(config)
        self.accept()

# Eski metotları temizle
 


# ============================================================================
# PROJECTM OPENGL GÖRSELLEŞTIRME WIDGET
# ============================================================================

class ProjectMVisualizer(QOpenGLWidget):
    """
    ProjectM OpenGL Görselleştirici
    - Hardware-accelerated MilkDrop preset rendering
    - 100+ preset koleksiyonu
    - Gerçek zamanlı PCM audio feed
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        
        # Sistem algılama
        self.system_detector = SystemPerformanceDetector()
        self.performance_monitor = PerformanceMonitor(target_fps=self.system_detector.recommended_fps)
        self.auto_quality_enabled = True
        
        self.projectm_engine = None
        self.engine_ready = False
        self.audio_buffer = np.zeros(1024, dtype=np.int16)
        self.preset_hard_cut = False
        self.preset_dir = os.path.join(os.path.dirname(__file__), "presets")
        self.font_dir = "/usr/share/fonts/TTF"  # Arch Linux font path
        self.vis_fps = self.system_detector.recommended_fps  # Otomatik FPS
        self.pm_auto_cycle = False  # Otomatik preset döngüsü
        self.pm_auto_interval = 15000  # 15 saniye
        self.pm_cycle_interval = 15000  # Döngü aralığı (ms)
        
        # Otomatik döngü timer'ı
        self.pm_cycle_timer = QTimer(self)
        self.pm_cycle_timer.timeout.connect(self._pm_random)
        
        # Preset dizini kontrolü
        if not os.path.exists(self.preset_dir):
            print(f"⚠ Preset dizini bulunamadı: {self.preset_dir}")
            self.preset_dir = os.path.expanduser("~/.projectM/presets")
            print(f"  Alternatif deneniyor: {self.preset_dir}")
        
        
        # Font dizini kontrolü
        if not os.path.exists(self.font_dir):
            for alt_font in ["/usr/share/fonts/truetype", "/usr/share/fonts"]:
                if os.path.exists(alt_font):
                    self.font_dir = alt_font
                    break
        
        # OpenGL context ayarları
        self.setUpdateBehavior(QOpenGLWidget.NoPartialUpdate)
        
        print(f"📁 ProjectM Preset dizini: {self.preset_dir}")
        print(f"📁 Font dizini: {self.font_dir}")

        # --- YENİ: Angolla Tarzı Otomatik Döngü (Auto-Cycle) ---
        self.preset_config = {
            "mode_index": 0,    # 0: Listeden, 1: Rastgele, 2: Sabit
            "delay": 15,        # Saniye
            "selected_indices": set() # Boşsa tümü
        }
        self.preset_timer = QTimer(self)
        self.preset_timer.timeout.connect(self._on_preset_timer)
    
    def apply_preset_Config(self, config):
        """Diyalogdan gelen ayarları uygula"""
        self.preset_config = config
        
        # Timer ayarla
        self.preset_timer.stop()
        
        mode = config.get("mode_index", 0)
        delay = config.get("delay", 15)
        
        if mode == 2: # Sabit
            pass
        else:
            # 0 (Listeden) veya 1 (Rastgele) -> Timer kur
            if delay < 1: delay = 1
            self.preset_timer.start(delay * 1000)
            
            # Hemen bir tane seç
            self._on_preset_timer()

    def _on_preset_timer(self):
        """Zamanlayıcı tetiklendiğinde preset değiştir"""
        if not self.projectm_engine or not self.engine_ready:
            return

        mode = self.preset_config.get("mode_index", 0)
        selected_indices = list(self.preset_config.get("selected_indices", []))
        
        # Eğer liste boşsa, tüm liste varsayılır
        if not selected_indices:
            try:
                total = self.projectm_engine.get_playlist_size()
                selected_indices = list(range(total))
            except:
                return

        if not selected_indices:
            return

        if mode == 1: # Rastgele (Tüm havuzdan veya seçililerden)
             import random
             idx = random.choice(selected_indices)
             self.set_preset(idx)
        
        elif mode == 0: # Listeden Sırayla
             # Şimdilik rastgele yapalım çünkü sırayı tutacak state eklemedik
             # İdealde: self.current_preset_list_index += 1
             import random
             idx = random.choice(selected_indices)
             self.set_preset(idx)
    
    def initializeGL(self):
        """OpenGL başlatma - ProjectM motorunu oluştur"""
        if not HAS_PROJECTM:
            print("✗ ProjectM kullanılamıyor - OpenGL görselleştirme devre dışı")
            return
        
        try:
            w, h = self.width(), self.height()
            # Minimum boyut kontrolü - ProjectM küçük widget'larda sorun çıkarabilir
            if w < 200 or h < 100:
                print(f"⚠ Widget boyutu çok küçük ({w}x{h}), minimum 400x200 ayarlanıyor")
                w, h = max(400, w), max(200, h)
            if w == 0 or h == 0:
                w, h = 800, 600
            
            print(f"🎨 ProjectM motoru başlatılıyor: {w}x{h}")
            
            # Preset dizini kontrolü
            if not os.path.exists(self.preset_dir):
                print(f"✗ Preset dizini yok: {self.preset_dir}")
                print("  ProjectM başlatılamıyor - preset'ler gerekli")
                return
            
            self.projectm_engine = viz_engine.ProjectM(
                self.preset_dir,
                self.font_dir,
                w, h
            )
            
            # Engine'in hazır olması için kısa bekleme
            QTimer.singleShot(100, self._mark_engine_ready)
            
            # Render timer başlat - güvenli FPS ile
            safe_fps = max(20, min(self.vis_fps, 120))
            interval_ms = max(8, int(1000 / safe_fps))
            self.render_timer = QTimer(self)
            self.render_timer.timeout.connect(self.update)
            self.render_timer.start(interval_ms)
            print(f"✓ ProjectM render timer: {safe_fps} FPS ({interval_ms}ms)")
            
            print("✓ ProjectM motoru başarıyla başlatıldı!")
        except Exception as e:
            import traceback
            print(f"✗ ProjectM başlatma hatası: {e}")
            print(traceback.format_exc())
            self.projectm_engine = None
    
    def _mark_engine_ready(self):
        """Engine hazır olduğunu işaretle"""
        self.engine_ready = True
        print("✓ ProjectM engine render için hazır")
        # Siyah ekranı önlemek için hemen bir preset seç
        if self.projectm_engine:
            try:
                # Rastgele bir preset seç
                self.projectm_engine.preset_random(True)
            except Exception as e:
                print(f"Başlangıç görseli seçilemedi: {e}")
    
    def resizeGL(self, w, h):
        """Pencere boyutu değiştiğinde"""
        if self.projectm_engine:
            try:
                self.projectm_engine.window_resize(w, h)
            except Exception as e:
                print(f"✗ ProjectM resize hatası: {e}")
    
    def paintGL(self):
        """Her frame'de çağrılır - ProjectM render"""
        if self.projectm_engine and self.engine_ready:
            try:
                # Performans monitörü
                self.performance_monitor.start_frame()
                
                # Hızlı çağrılarda frame skip (koruma)
                if not hasattr(self, '_last_paint_time'):
                    self._last_paint_time = QTime.currentTime()
                    self._frame_skip_warned = False
                
                # Minimum 5ms aralık (200 FPS üst sınır)
                now = QTime.currentTime()
                elapsed_ms = self._last_paint_time.msecsTo(now)
                
                if elapsed_ms < 5:
                    # Çok hızlı, skip
                    if not self._frame_skip_warned:
                        print(f"⚠ paintGL çok hızlı çağrılıyor ({elapsed_ms}ms), frame skip aktif")
                        self._frame_skip_warned = True
                    return
                
                self._last_paint_time = now
                self.projectm_engine.opengl_render()
                
                # Performans analizi
                frame_time = self.performance_monitor.end_frame()
                if self.auto_quality_enabled and self.performance_monitor.should_reduce_quality():
                    self._auto_adjust_quality()
            except Exception as e:
                # İlk hatada log, sonra sessiz
                if not hasattr(self, '_render_error_logged'):
                    print(f"✗ ProjectM render hatası: {e}")
                    import traceback
                    traceback.print_exc()
                    self._render_error_logged = True
        else:
            # Fallback: Siyah ekran
            if HAS_OPENGL:
                glClearColor(0.0, 0.0, 0.0, 1.0)
                glClear(GL_COLOR_BUFFER_BIT)
    
    def update_audio_buffer(self, audio_data: np.ndarray):
        """
        Ses verisi güncellemesi
        audio_data: FFT magnitude array veya raw PCM samples
        """
        # Debug: İlk 3 çağrıda veri aldığını göster
        if not hasattr(self, '_projectm_update_count'):
            self._projectm_update_count = 0
        if self._projectm_update_count < 3:
            engine_status = "✓ Aktif" if (self.projectm_engine and self.engine_ready) else "✗ Yok/Hazır değil"
            print(f"🎆 ProjectMVisualizer.update_audio_buffer: Engine={engine_status}, data_len={len(audio_data) if audio_data is not None else 0}")
            self._projectm_update_count += 1
        
        if not self.projectm_engine or not self.engine_ready:
            return
        
        try:
            # FFT magnitude'i int16 PCM'e dönüştür
            # Basit yaklaşım: normalize ve scale
            if len(audio_data) > 0:
                # Normalize (0-1 range)
                max_val = np.max(audio_data)
                if max_val > 0:
                    normalized = audio_data / max_val
                else:
                    normalized = audio_data
                
                # Int16 range'e scale (-32768 to 32767)
                pcm_data = (normalized * 16384).astype(np.int16)
                
                # Stereo için duplicate (ProjectM stereo bekler)
                stereo_pcm = np.column_stack((pcm_data, pcm_data)).flatten()
                
                # ProjectM'e gönder
                frames = len(pcm_data)
                self.projectm_engine.pcm_add_short(stereo_pcm, frames)
                
                if self._projectm_update_count < 3:
                    print(f"  ✓ ProjectM'e {frames} frame PCM gönderildi")
        except Exception as e:
            print(f"✗ ProjectM PCM feed hatası: {e}")
        
        # Render tetikle
        self.update()
    
    def consume_audio_data(self, pcm_data):
        """
        PCM ses verisi besle (16-bit stereo veya mono)
        pcm_data: bytes veya numpy array (int16)
        """
        if not self.projectm_engine or not self.engine_ready:
            return
        
        try:
            # Bytes ise numpy array'e çevir
            if isinstance(pcm_data, bytes):
                pcm_array = np.frombuffer(pcm_data, dtype=np.int16)
            else:
                pcm_array = pcm_data
            
            # Debug
            if not hasattr(self, '_consume_count'):
                self._consume_count = 0
            if self._consume_count < 5:
                print(f"🎵 consume_audio_data: {len(pcm_array)} samples")
                self._consume_count += 1
            
            # Stereo check - ProjectM stereo bekliyor
            if len(pcm_array) % 2 != 0:
                # Mono -> Stereo
                mono = pcm_array
                pcm_array = np.column_stack((mono, mono)).flatten()
            
            # ProjectM'e besle
            frames = len(pcm_array) // 2  # Stereo frames
            self.projectm_engine.pcm_add_short(pcm_array, frames)
            
            if self._consume_count <= 5:
                print(f"  ✓ ProjectM'e {frames} stereo frames gönderildi")
        except Exception as e:
            if not hasattr(self, '_consume_error_logged'):
                print(f"✗ consume_audio_data hatası: {e}")
                import traceback
                traceback.print_exc()
                self._consume_error_logged = True
    
    def contextMenuEvent(self, event):
        """Sağ tık menüsü - Preset seçimi vb."""
        menu = QMenu(self)
        menu.setStyleSheet("""
            QMenu { background-color: #222; color: #eee; border: 1px solid #444; }
            QMenu::item { padding: 5px 20px; }
            QMenu::item:selected { background-color: #0078d7; }
        """)
        
        
        info_action = menu.addAction("🎆 ProjectM Görselleştirme")
        info_action.setEnabled(False)
        
        menu.addSeparator()

        # Preset Seçici
        act_select = menu.addAction("📂 Görselleştirmeleri Seç...")
        act_select.triggered.connect(self.open_preset_selector)

        menu.addSeparator()

        # FPS seçenekleri (bars/wave için)
        fps_menu = menu.addMenu("⏱️ FPS")
        for fps_val in (45, 60, 75, 90, 120):
            act_fps = fps_menu.addAction(f"{fps_val} FPS")
            act_fps.setCheckable(True)
            act_fps.setChecked(self.vis_fps == fps_val)
            act_fps.triggered.connect(lambda chk, v=fps_val: self.set_fps(v))

        if hasattr(self, 'preset_hard_cut'):
             act_hard = menu.addAction("⚡ Keskin Geçiş (Hard Cut)")
             act_hard.setCheckable(True)
             act_hard.setChecked(self.preset_hard_cut)
             act_hard.triggered.connect(self._toggle_hard_cut)
        
        act_rand = menu.addAction("🎲 Rastgele Preset")
        act_rand.triggered.connect(self._pm_random)

        # Performans Bilgisi (sadece debug için)
        if hasattr(self, 'performance_monitor'):
            menu.addSeparator()
            perf_info = menu.addAction(f"📊 FPS: {self.performance_monitor.get_current_fps():.1f} (Hedef: {self.vis_fps})")
            perf_info.setEnabled(False)
            
            profile_icon = {"high": "🚀", "medium": "⚙️", "low": "🐌"}
            profile_text = f"{profile_icon.get(self.system_detector.profile, '?')} Profil: {self.system_detector.profile.upper()}"
            perf_profile = menu.addAction(profile_text)
            perf_profile.setEnabled(False)
            
            # Otomatik kalite ayarlama
            act_auto_qual = menu.addAction("🎯 Otomatik Kalite Ayarlama")
            act_auto_qual.setCheckable(True)
            act_auto_qual.setChecked(self.auto_quality_enabled)
            act_auto_qual.triggered.connect(lambda chk: self.set_option("auto_quality", chk))
        
        # Otomatik preset döngüsü
        act_auto = menu.addAction("🔁 Otomatik Preset Döngüsü")
        act_auto.setCheckable(True)
        act_auto.setChecked(self.pm_auto_cycle)
        act_auto.triggered.connect(self._toggle_pm_auto_cycle)

        # Döngü süresi
        interval_menu = menu.addMenu("⏱️ Döngü Süresi")
        for ms, label in [(5000, "5 sn"), (10000, "10 sn"), (15000, "15 sn"), (30000, "30 sn")]:
            act_i = interval_menu.addAction(label)
            act_i.setCheckable(True)
            act_i.setChecked(self.pm_cycle_interval == ms)
            act_i.triggered.connect(lambda chk, v=ms: self._set_pm_cycle_interval(v))

        menu.exec_(event.globalPos())

    def open_preset_selector(self):
        if not self.projectm_engine:
            return
        dlg = PresetSelectionDialog(self, self)
        dlg.exec_()
        
    def set_preset(self, index):
        """Belirtilen index'teki preset'i yükle"""
        if not self.projectm_engine:
            print("✗ set_preset: ProjectM engine yok")
            return
        if not self.engine_ready:
            print("✗ set_preset: Engine henüz hazır değil")
            return
        
        try:
            preset_name = self.projectm_engine.get_preset_name(index)
            print(f"🎨 Preset değiştiriliyor: [{index}] {preset_name}")
            self.projectm_engine.select_preset(index)
            self.update()  # Hemen render et
            print(f"✓ Preset başarıyla yüklendi: {preset_name}")
        except Exception as e:
            print(f"✗ Preset seçim hatası [{index}]: {e}")

    def _pm_random(self):
        if self.projectm_engine and self.engine_ready:
             self.projectm_engine.preset_random(self.preset_hard_cut)

    def _toggle_hard_cut(self, val):
        self.preset_hard_cut = val

    def _toggle_pm_auto_cycle(self, val):
        self.pm_auto_cycle = bool(val)
        if self.pm_auto_cycle:
            self.pm_cycle_timer.start(self.pm_cycle_interval)
        else:
            self.pm_cycle_timer.stop()

    def _set_pm_cycle_interval(self, ms):
        self.pm_cycle_interval = int(ms)
        self.pm_cycle_timer.setInterval(self.pm_cycle_interval)
        if self.pm_auto_cycle and not self.pm_cycle_timer.isActive():
            self.pm_cycle_timer.start(self.pm_cycle_interval)

    def set_fps(self, fps):
        """Render FPS'i ayarla (ProjectM render timer)."""
        try:
            self.vis_fps = int(fps)
            # Performans monitörünü güncelle
            self.performance_monitor.target_fps = self.vis_fps
            self.performance_monitor.target_frame_time = 1000.0 / self.vis_fps
            
            # Timer'ı güvenli şekilde güncelle
            if hasattr(self, 'render_timer') and self.render_timer:
                self.render_timer.stop()
                # FPS'i güvenli aralıkta sınırla (20-120 FPS)
                safe_fps = max(20, min(self.vis_fps, 120))
                interval_ms = max(8, int(1000 / safe_fps))
                self.render_timer.setInterval(interval_ms)
                self.render_timer.start()
                print(f"⏱️ ProjectM FPS güncellendi: {safe_fps} FPS ({interval_ms}ms)")
        except Exception as e:
            print(f"✗ set_fps hatası: {e}")
    
    def _auto_adjust_quality(self):
        """ProjectM için otomatik kalite ayarlama"""
        current_fps = self.vis_fps
        if current_fps > 45:
            new_fps = max(45, current_fps - 15)
            self.set_fps(new_fps)
            print(f"⚠️ ProjectM performans düşük - FPS otomatik düşürüldü: {current_fps} → {new_fps}")
            self.performance_monitor.frame_times.clear()
# --- SINIF EŞİTLEME KODU BİTİŞİ ---
