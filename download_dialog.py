import importlib.util
import os
import shutil
import sys
import re
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QLabel, QLineEdit, QComboBox,
    QWidget, QPushButton, QHBoxLayout, QMessageBox, QFrame,
    QButtonGroup
)
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt5.QtGui import QPainter, QLinearGradient, QColor, QBrush, QPen

class RGBFrame(QFrame):
    """Animasyonlu RGB Aura Arka Planı"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.offset = 0.0
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._animate)
        self.timer.start(50) # ~20 FPS akıcı animasyon

    def _animate(self):
        self.offset += 0.005 # Hız ayarı
        if self.offset > 1.0:
            self.offset -= 1.0
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Gradient Yönü: Çapraz
        grad = QLinearGradient(0, 0, self.width(), self.height())
        
        # Rainbow Colors (Hue Cycle)
        # 6-7 durak noktası
        stops = [0.0, 0.16, 0.33, 0.5, 0.66, 0.83, 1.0]
        for stop in stops:
            # Hue kaydırma mantığı
            hue = (stop + self.offset) % 1.0
            # Canlı ve parlak renkler için: Saturation=0.85, Lightness=0.5
            color = QColor.fromHslF(hue, 0.85, 0.5, 0.5) # Alpha 0.5 (Yarı saydam)
            # User screenshotda arka plan koyu idi, belki alpha'yı artırmalıyız?
            # User "klavye ışıkları" dedi, parlak olmalı ama içeriği okutmalı.
            # Alpha 0.4-0.5 gibi iyidir.
            grad.setColorAt(stop, color)
            
        painter.setBrush(QBrush(grad))
        painter.setPen(Qt.NoPen)
        
        # Köşe yuvarlatma (border-radius: 15px)
        rect = self.rect()
        painter.drawRoundedRect(rect, 15, 15)
        
        # İnce bir çerçeve (Border)
        painter.setBrush(Qt.NoBrush)
        border_pen = QPen(QColor(255, 255, 255, 80)) # Hafif beyaz çerçeve
        border_pen.setWidth(2)
        painter.setPen(border_pen)
        painter.drawRoundedRect(rect, 15, 15)

class DownloadDialog(QDialog):
    """
    Modern, Unified İndirme Diyalogu
    User Request: Single view matching the reference screenshot.
    """
    def __init__(self, parent=None, video_title="", duration=0):
        super().__init__(parent)
        self.setWindowTitle("İndir - Format Seç")
        self.setFixedSize(600, 520) # Sabit boyut (Resize kapalı)
        self.setStyleSheet("""
            QDialog {
                /* System theme default background */
            }
            QLabel {
                background: transparent;
                font-size: 13px;
                font-weight: 500;
            }
            QLineEdit {
                border: 1px solid #727272;
                border-radius: 4px;
                padding: 6px;
                font-size: 13px;
                background-color: palette(base);
                color: palette(text);
            }
            QComboBox {
                border: 1px solid #727272;
                border-radius: 4px;
                padding: 6px;
                font-size: 13px;
                min-height: 25px;
                background-color: palette(base);
                color: palette(text);
            }
            QComboBox::drop-down {
                border: none;
                width: 30px;
                subcontrol-origin: padding;
                subcontrol-position: top right;
            }
            QComboBox::down-arrow {
                image: url(icons/down_arrow.svg);
                width: 12px;
                height: 12px;
                margin-right: 15px;
            }
            
            /* Buttons */
            QPushButton {
                font-weight: bold;
                border-radius: 6px;
                padding: 10px 20px;
                font-size: 14px;
                border: none;
                color: white;
            }
            #BtnDownload {
                background-color: #57F287; /* Bright Green - Brand */
                color: #000000;
            }
            #BtnDownload:hover {
                background-color: #43B581;
            }
            #BtnMore {
                background-color: #5865F2; /* Blurple - Brand */
            }
            #BtnMore:hover {
                background-color: #4752C4;
            }
            #BtnExtract {
                background-color: #5865F2;
                min-width: 120px;
            }
             #BtnExtract:hover {
                background-color: #4752C4;
            }
            
            /* Header Buttons (Fake Tabs) */
            QPushButton#HeaderBtnVideo {
                background-color: rgba(0, 0, 0, 0.2); 
                color: palette(text);
                border-top-left-radius: 8px;
                border-bottom-left-radius: 8px;
                border: 1px solid rgba(0,0,0,0.1);
                margin: 0px;
            }
             QPushButton#HeaderBtnAudio {
                background-color: #5865F2; /* Active Blue */
                color: #FFFFFF;
                border-top-left-radius: 0px;
                border-bottom-left-radius: 0px;
                border-top-right-radius: 8px;
                border-bottom-right-radius: 8px;
                padding: 15px;
                font-size: 16px;
                margin: 0px;
            }
            

            
            /* Özel Başlık Label */
            #LblTitle {
                font-size: 14px;
                font-weight: bold;
            }
            /* ScrollBar */
            QScrollBar:vertical {
                border: none;
                background: rgba(0,0,0,0.1);
                width: 10px;
            }
            QScrollBar::handle:vertical {
                background: rgba(0,0,0,0.3);
                min-height: 20px;
                border-radius: 5px;
            }
            QScrollBar::add-line:vertical { height: 0px; }
            QScrollBar::sub-line:vertical { height: 0px; }
        """)

        self.formats = []
        self.result_data = None 

        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(25, 25, 25, 25)
        
        # --- HEADER (Video | Ses ) ---
        header_layout = QHBoxLayout()
        header_layout.setSpacing(0)
        
        self.btn_header_video = QPushButton("Video")
        self.btn_header_video.setObjectName("HeaderBtnVideo")
        self.btn_header_video.setCursor(Qt.PointingHandCursor)
        
        self.btn_header_audio = QPushButton("Ses")
        self.btn_header_audio.setObjectName("HeaderBtnAudio")
        self.btn_header_audio.setCursor(Qt.PointingHandCursor)
        
        header_layout.addWidget(self.btn_header_video, 1)
        header_layout.addWidget(self.btn_header_audio, 1)
        layout.addLayout(header_layout)

        # --- TITLE AREA ---
        title_row = QHBoxLayout()
        lbl_title = QLabel("Başlık :")
        lbl_title.setObjectName("LblTitle")
        self.txt_title = QLineEdit(video_title)
        title_row.addWidget(lbl_title)
        title_row.addWidget(self.txt_title)
        layout.addLayout(title_row)
        
        # --- VIDEO CONTAINER ---
        # Using RGBFrame for animated background (User Request)
        self.video_container = RGBFrame()
        v_layout = QVBoxLayout(self.video_container)
        v_layout.setContentsMargins(20, 20, 20, 20) # Match AudioFrame margins
        v_layout.setSpacing(15) # Match AudioFrame spacing

        # Branding & Title for Video (Consistency)
        lbl_v_brand = QLabel("Aurivo Player")
        lbl_v_brand.setAlignment(Qt.AlignCenter)
        lbl_v_brand.setStyleSheet("font-size: 24px; font-weight: 900; color: #FFFFFF; margin-bottom: 5px; letter-spacing: 1px;")
        v_layout.addWidget(lbl_v_brand)

        lbl_v_title = QLabel("Video İndir")
        lbl_v_title.setAlignment(Qt.AlignCenter)
        lbl_v_title.setStyleSheet("font-size: 16px; font-weight: bold;")
        v_layout.addWidget(lbl_v_title)

        # Video Format
        fmt_row = QHBoxLayout()
        fmt_row.addWidget(QLabel("Format seçin"))
        self.combo_video = QComboBox()
        
        # SADELEŞTİRİLMİŞ PRESETLER (Kullanıcı İsteği)
        self.combo_video.addItem("Otomatik (En İyi) - Önerilen", "bestvideo+bestaudio/best")
        self.combo_video.addItem("Yüksek Kalite (1080p)", "bestvideo[height<=1080]+bestaudio/best[height<=1080]")
        self.combo_video.addItem("Orta Kalite (720p)", "bestvideo[height<=720]+bestaudio/best[height<=720]")
        self.combo_video.addItem("Veri Tasarrufu (480p)", "bestvideo[height<=480]+bestaudio/best[height<=480]")
        
        fmt_row.addWidget(self.combo_video, 1)
        v_layout.addLayout(fmt_row)
        
        # Video Action Buttons ('İndir' + 'Daha fazla ayar')
        action_row = QHBoxLayout()
        action_row.setSpacing(10)
        
        self.btn_download = QPushButton("İndir")
        self.btn_download.setObjectName("BtnDownload")
        self.btn_download.setCursor(Qt.PointingHandCursor)
        self.btn_download.setMinimumWidth(150)
        self.btn_download.setMinimumHeight(45)
        
        self.btn_more = QPushButton("Daha fazla ayar")
        self.btn_more.setObjectName("BtnMore")
        self.btn_more.setCursor(Qt.PointingHandCursor)
        self.btn_more.setMinimumWidth(150)
        self.btn_more.setMinimumHeight(45)
        
        action_row.addStretch(1)
        action_row.addWidget(self.btn_download)
        action_row.addWidget(self.btn_more)
        action_row.addStretch(1)
        v_layout.addLayout(action_row)
        
        layout.addWidget(self.video_container)
        
        # --- AUDIO CONTAINER (Extract) ---
        # Using RGBFrame for animated background
        self.audio_frame = RGBFrame()
        self.audio_frame.setObjectName("AudioFrame")
        af_layout = QVBoxLayout(self.audio_frame)
        af_layout.setContentsMargins(20, 20, 20, 20)
        af_layout.setSpacing(15)
        
        # Branding
        lbl_af_brand = QLabel("Aurivo Player")
        lbl_af_brand.setAlignment(Qt.AlignCenter)
        lbl_af_brand.setStyleSheet("font-size: 24px; font-weight: 900; color: #FFFFFF; margin-bottom: 5px; letter-spacing: 1px;")
        af_layout.addWidget(lbl_af_brand)
        
        # Box Title
        lbl_af_title = QLabel("Sesi çıkart")
        lbl_af_title.setAlignment(Qt.AlignCenter)
        lbl_af_title.setStyleSheet("font-size: 16px; font-weight: bold;")
        af_layout.addWidget(lbl_af_title)
        
        # Audio Format
        af_fmt_row = QHBoxLayout()
        af_fmt_row.addWidget(QLabel("Format seçin"))
        self.combo_audio_fmt = QComboBox()
        self.combo_audio_fmt.addItems(["Mp3", "M4a", "Opus", "Wav", "Alac", "Flac"])
        af_fmt_row.addWidget(self.combo_audio_fmt, 1)
        af_layout.addLayout(af_fmt_row)
        
        # Audio Quality (with Estimated Sizes)
        af_qual_row = QHBoxLayout()
        af_qual_row.addWidget(QLabel("Kalite Seç"))
        self.combo_audio_qual = QComboBox()
        
        # Helper to calc size string
        def calc_size(kbps):
            if duration > 0:
                mb = (kbps * duration) / 8192
                return f"~{mb:.1f} MB"
            return ""

        s_192 = calc_size(192)
        s_320 = calc_size(320)
        s_128 = calc_size(128)
        
        # If duration known, show size first? User said "yerine mp3 dosyasının ağırlığı olmalı"
        # "mesela 3MB veya yükseldikçe..."
        # So replace "Normal (192kbps)" with "Normal (~4.5MB)" or similar
        
        # Format: "Label (Size)" if size available, else "Label (kbps)"
        if duration > 0:
             self.combo_audio_qual.addItem(f"Normal ({s_192})", "192")
             self.combo_audio_qual.addItem(f"Yüksek ({s_320})", "320")
             self.combo_audio_qual.addItem(f"Düşük ({s_128})", "128")
        else:
             self.combo_audio_qual.addItem("Normal (192kbps)", "192")
             self.combo_audio_qual.addItem("Yüksek (320kbps)", "320")
             self.combo_audio_qual.addItem("Düşük (128kbps)", "128")
        
        af_qual_row.addWidget(self.combo_audio_qual, 1)
        af_layout.addLayout(af_qual_row)
        
        # Audio Action Buttons ('İndir' + 'Çıkart')
        btn_extract_row = QHBoxLayout()
        btn_extract_row.setSpacing(10)
        
        self.btn_audio_download = QPushButton("İndir")
        self.btn_audio_download.setObjectName("BtnDownload")
        self.btn_audio_download.setCursor(Qt.PointingHandCursor)
        self.btn_audio_download.setMinimumWidth(150)
        self.btn_audio_download.setMinimumHeight(45)
        
        self.btn_extract = QPushButton("Çıkart")
        self.btn_extract.setObjectName("BtnExtract")
        self.btn_extract.setCursor(Qt.PointingHandCursor)
        self.btn_extract.setMinimumWidth(150)
        self.btn_extract.setMinimumHeight(45)
        
        btn_extract_row.addStretch(1)
        btn_extract_row.addWidget(self.btn_audio_download)
        btn_extract_row.addWidget(self.btn_extract)
        btn_extract_row.addStretch(1)
        af_layout.addLayout(btn_extract_row)
        
        layout.addWidget(self.audio_frame)
        
        # Default State: Video Active
        self.current_mode = "video"
        self._update_ui_state()
        
        # Connect Signals
        self.btn_header_video.clicked.connect(lambda: self.set_mode("video"))
        self.btn_header_audio.clicked.connect(lambda: self.set_mode("audio"))
        
        self.btn_download.clicked.connect(self.on_click_download_video)
        self.btn_audio_download.clicked.connect(self.on_click_download_audio)
        self.btn_extract.clicked.connect(self.on_click_extract_audio)
        self.btn_more.clicked.connect(lambda: QMessageBox.information(self, "Bilgi", "Gelişmiş ayarlar yakında eklenecek."))

    def set_mode(self, mode):
        self.current_mode = mode
        self._update_ui_state()

    def _update_ui_state(self):
        # Style Header Buttons
        active_style = """
            background-color: #5865F2; /* Active Blue */
            color: #FFFFFF;
            border: none;
            padding: 15px;
            font-size: 16px;
            margin: 0px;
        """
        inactive_style = """
            background-color: rgba(0, 0, 0, 0.2); 
            color: palette(text);
            border: 1px solid rgba(0,0,0,0.1);
            margin: 0px;
            padding: 15px; /* Ensure consistent padding */
            font-size: 16px; /* Ensure consistent font size */
        """
        
        # Rounded corners handling
        video_style = inactive_style
        audio_style = inactive_style

        if self.current_mode == "video":
            video_style = active_style
        else: # self.current_mode == "audio"
            audio_style = active_style
        
        # Apply specific border radii
        video_style += "border-top-left-radius: 8px; border-bottom-left-radius: 8px; border-top-right-radius: 0px; border-bottom-right-radius: 0px;"
        audio_style += "border-top-right-radius: 8px; border-bottom-right-radius: 8px; border-top-left-radius: 0px; border-bottom-left-radius: 0px;"

        self.btn_header_video.setStyleSheet(video_style)
        self.btn_header_audio.setStyleSheet(audio_style)
        
        # Toggle Visibility
        if self.current_mode == "video":
            self.video_container.setVisible(True)
            self.audio_frame.setVisible(False)
        else:
            self.video_container.setVisible(False)
            self.audio_frame.setVisible(True)

    def on_click_download_video(self):
        # Seçilen formatı al (artık preset string)
        fid = self.combo_video.currentData()
        title = self.txt_title.text()
        self.result_data = {
            'action': 'download_video',
            'fid': fid,
            'title': title
        }
        self.accept()

    def on_click_download_audio(self):
        """İndir butonu: Klasör seç ve indir"""
        from PyQt5.QtWidgets import QFileDialog
        from PyQt5.QtCore import QStandardPaths
        
        # Klasör seçim dialogunu aç
        default_dir = QStandardPaths.writableLocation(QStandardPaths.MusicLocation)
        folder = QFileDialog.getExistingDirectory(self, "İndirme Klasörü Seç", default_dir)
        
        if not folder:
            # Kullanıcı iptal etti
            return
        
        fmt = self.combo_audio_fmt.currentText().lower()
        quality = self.combo_audio_qual.currentData()
        title = self.txt_title.text()
        self.result_data = {
            'action': 'download_audio',
            'format': fmt,
            'quality': quality,
            'title': title,
            'output_folder': folder
        }
        self.accept()
    
    def on_click_extract_audio(self):
        fmt = self.combo_audio_fmt.currentText().lower()
        quality = self.combo_audio_qual.currentData()
        title = self.txt_title.text()
        self.result_data = {
            'action': 'extract_audio',
            'format': fmt,
            'quality': quality,
            'title': title
        }
        self.accept()
        
    def get_data(self):
        return self.result_data

# ---------------------------------------------------------
# yt-dlp finder
# ---------------------------------------------------------
def resolve_yt_dlp_command():
    """
    Prefer the virtualenv-local yt-dlp; fall back to PATH or python -m yt_dlp.
    Returns command list or None if not found.
    """
    candidates = []
    exe_dir = os.path.dirname(sys.executable)
    repo_root = os.path.dirname(os.path.abspath(__file__))
    candidates.append(os.path.join(repo_root, "pyqt_venv", "bin", "yt-dlp"))
    for name in ("yt-dlp", "yt_dlp"):
        candidates.append(os.path.join(exe_dir, name))
        candidates.append(shutil.which(name))
    candidates.append(os.path.join(os.path.dirname(__file__), "yt-dlp"))

    for cand in candidates:
        if cand and os.path.exists(cand) and os.access(cand, os.X_OK):
            return [cand]

    try:
        if importlib.util.find_spec("yt_dlp"):
            return [sys.executable, "-m", "yt_dlp"]
    except Exception:
        pass
    return None

# ---------------------------------------------------------
# Merged DownloadWorker (Moved from aurivo_downloader.py)
# ---------------------------------------------------------
from PyQt5.QtCore import QThread, pyqtSignal

class DownloadWorker(QThread):
    """Arka planda yt-dlp çalıştıran işçi thread."""
    finished_sig = pyqtSignal(bool, str)  # success, message
    progress_sig = pyqtSignal(str)
    percent_sig = pyqtSignal(int)

    def __init__(self, url, fmt, output_path):
        super().__init__()
        self.url = url
        self.fmt = fmt  # 'mp3' or 'mp4' or custom string
        self.output_path = output_path
        self._process = None
        self._terminated = False

    def run(self):
        import subprocess
        import re
        import os
        import sys

        cmd_base = resolve_yt_dlp_command()
        if not cmd_base:
            self.finished_sig.emit(
                False,
                "yt-dlp bulunamadı. pyqt_venv içinde `python -m pip install yt-dlp` komutunu çalıştırıp tekrar deneyin."
            )
            return

        # Komut oluşturma
        cmd = cmd_base + ["--no-playlist", "--newline"] # --newline output parsing için önemli

        # Çıktı şablonu (Title.ext)
        out_tmpl = f"{self.output_path}/%(title)s.%(ext)s"
        cmd.extend(["-o", out_tmpl])

        # If fmt is an explicit yt-dlp format id (prefix 'fmt:'), use it
        if isinstance(self.fmt, str) and self.fmt.startswith('fmt:'):
            fmt_id = self.fmt.split(':', 1)[1]
            cmd.extend(["-f", fmt_id])
        elif isinstance(self.fmt, str) and self.fmt.startswith('audio_extract|'):
            # audio_extract|mp3|192
            parts = self.fmt.split('|')
            if len(parts) >= 3:
                ext = parts[1]
                qual = parts[2]
                cmd.extend(["-x", "--audio-format", ext])
                # Bitrate handling
                if qual.isdigit() and int(qual) > 10:
                    cmd.extend(["--audio-quality", f"{qual}K"])
                else:
                     cmd.extend(["--audio-quality", "0"]) # Default best
                cmd.extend(["--embed-thumbnail", "--add-metadata"])
            else:
                 # Fallback
                 cmd.extend(["-x", "--audio-format", "mp3", "--audio-quality", "0"])
        elif self.fmt == 'mp3':
            # Audio only conversion
            cmd.extend(["-x", "--audio-format", "mp3", "--audio-quality", "0", "--embed-thumbnail", "--add-metadata"])
        else:
            # Best MP4 video
            # For video also try to embed metadata/thumbnail if possible
            cmd.extend(["-f", "best[ext=mp4]/best", "--embed-thumbnail", "--add-metadata"])

        cmd.append(self.url)

        try:
            # Subprocess başlat
            self._process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, universal_newlines=True
            )

            # Regex for progress [download]  45.5% of 10.00MiB at 2.50MiB/s ETA 00:03
            progress_regex = re.compile(r'\[download\]\s+(\d+\.?\d*)%')

            def _sanitize_progress_line(s: str) -> str:
                # Güvenlik: Dosya adı ve yolunu UI logunda gösterme.
                try:
                    if not s:
                        return s
                    out = s
                    # İndirme klasör yolunu maskele
                    try:
                        if self.output_path:
                            out = out.replace(self.output_path, "<klasör>")
                    except Exception:
                        pass
                    # "Destination:" gibi satırlarda dosya yolunu maskele
                    out = re.sub(r"(?i)\bDestination:\s+.*$", "Destination: <dosya>", out)
                    out = re.sub(r"(?i)\bMerging formats into\s+.*$", "Merging formats into <dosya>", out)
                    out = re.sub(r"(?i)\bWriting video thumbnail to\s+.*$", "Writing video thumbnail to <dosya>", out)
                    out = re.sub(r"(?i)\bDeleting original file\s+.*$", "Deleting original file <dosya>", out)
                    # Genel path maskesi: /a/b/c.ext veya ./a/b.ext
                    out = re.sub(r"(?:(?:\./|/)[^\s'\"]+)+\.(?:[A-Za-z0-9]{1,6})", "<dosya>", out)
                    return out
                except Exception:
                    return "<log>"

            for line in self._process.stdout:
                line = line.strip()
                if line:
                    # Parse percentage
                    match = progress_regex.search(line)
                    if match:
                        try:
                            val = float(match.group(1))
                            self.percent_sig.emit(int(val))
                        except ValueError:
                            pass
                    
                    self.progress_sig.emit(_sanitize_progress_line(line))

            self._process.wait()

            if self._terminated:
                # Eğer kullanıcı iptal ettiyse, iptal mesajını gönder
                self.finished_sig.emit(False, "İndirme iptal edildi.")
                return

            if self._process.returncode == 0:
                self.percent_sig.emit(100) # Ensure 100% at end
                self.finished_sig.emit(True, "İndirme tamamlandı!")
            else:
                self.finished_sig.emit(False, f"Hata oluştu. Kod: {self._process.returncode}")

        except Exception as e:
            self.finished_sig.emit(False, str(e))

    def terminate_download(self):
        """Çalışan alt süreci sonlandırıp iptal durumunu işaretler."""
        try:
            self._terminated = True
            if self._process and self._process.poll() is None:
                self._process.terminate()
                try:
                    self._process.wait(timeout=3)
                except Exception:
                    try:
                        self._process.kill()
                    except Exception:
                        pass
        except Exception:
            pass
