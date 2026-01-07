import ctypes
import os
import sys
import numpy as np


class LiveDSPBridge:
    def __init__(self, lib_path: str | None = None):
        resolved_path = self._resolve_dsp_lib_path(lib_path)
        if not os.path.exists(resolved_path):
            searched = "\n".join(f" - {p}" for p in self._candidate_dsp_paths())
            raise FileNotFoundError(
                "DSP Library not found. Looked for:\n"
                f"{searched}\n"
                f"(Last tried: {resolved_path})"
            )

        self.lib = ctypes.CDLL(resolved_path)

        self.lib.create_dsp.restype = ctypes.c_void_p
        self.lib.destroy_dsp.argtypes = [ctypes.c_void_p]
        self.lib.process_dsp.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_float),
            ctypes.c_int,
            ctypes.c_int
        ]
        self.lib.set_eq_band.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_float]

        self.has_process_web_audio = False
        try:
            self.lib.process_web_audio.argtypes = [
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_float),
                ctypes.c_int,
                ctypes.c_int
            ]
            self.has_process_web_audio = True
        except AttributeError:
            self.has_process_web_audio = False

        self.has_eq_bands = False
        try:
            self.lib.set_eq_bands.argtypes = [
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_float),
                ctypes.c_int
            ]
            self.has_eq_bands = True
        except AttributeError:
            self.has_eq_bands = False

        self.lib.set_tone_params.argtypes = [
            ctypes.c_void_p,
            ctypes.c_float,
            ctypes.c_float,
            ctypes.c_float
        ]
        self.has_set_bass_gain = False
        try:
            self.lib.set_bass_gain.argtypes = [ctypes.c_void_p, ctypes.c_float]
            self.has_set_bass_gain = True
        except AttributeError:
            self.has_set_bass_gain = False

        self.has_set_treble_gain = False
        try:
            self.lib.set_treble_gain.argtypes = [ctypes.c_void_p, ctypes.c_float]
            self.has_set_treble_gain = True
        except AttributeError:
            self.has_set_treble_gain = False
        self.lib.set_stereo_width.argtypes = [ctypes.c_void_p, ctypes.c_float]
        self.lib.set_master_toggle.argtypes = [ctypes.c_void_p, ctypes.c_int]
        self.lib.set_dsp_enabled.argtypes = [ctypes.c_void_p, ctypes.c_int]

        self.has_set_sample_rate = False
        try:
            self.lib.set_sample_rate.argtypes = [ctypes.c_void_p, ctypes.c_float]
            self.has_set_sample_rate = True
        except AttributeError:
            self.has_set_sample_rate = False

        self.has_set_web_lpf = False
        try:
            self.lib.set_web_lpf.argtypes = [ctypes.c_void_p, ctypes.c_float]
            self.has_set_web_lpf = True
        except AttributeError:
            self.has_set_web_lpf = False

        self.has_set_force_mute = False
        try:
            self.lib.set_force_mute.argtypes = [ctypes.c_void_p, ctypes.c_int]
            self.has_set_force_mute = True
        except AttributeError:
            self.has_set_force_mute = False

        self.has_process_monitor_audio = False
        try:
            self.lib.process_monitor_audio.argtypes = [
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_float),
                ctypes.c_int,
                ctypes.c_int
            ]
            self.has_process_monitor_audio = True
        except AttributeError:
            self.has_process_monitor_audio = False

        self.dsp_ptr = self.lib.create_dsp()

    @staticmethod
    def _default_dsp_lib_name() -> str:
        if sys.platform.startswith("win"):
            return "aurivo_dsp.dll"
        if sys.platform == "darwin":
            return "aurivo_dsp.dylib"
        return "aurivo_dsp.so"

    @staticmethod
    def _iter_search_dirs() -> list[str]:
        dirs: list[str] = []

        # Repo/script working dir
        try:
            dirs.append(os.path.abspath(os.path.dirname(__file__)))
        except Exception:
            pass
        dirs.append(os.getcwd())

        # PyInstaller extraction dir (onefile)
        meipass = getattr(sys, "_MEIPASS", None)
        if isinstance(meipass, str) and meipass:
            dirs.append(meipass)
            dirs.append(os.path.join(meipass, "_internal"))

        # Frozen executable dir (onedir)
        if getattr(sys, "frozen", False):
            exe_dir = os.path.dirname(sys.executable)
            dirs.append(exe_dir)
            dirs.append(os.path.join(exe_dir, "_internal"))

        # De-dup while preserving order
        seen: set[str] = set()
        unique_dirs: list[str] = []
        for d in dirs:
            d = os.path.abspath(d)
            if d not in seen:
                unique_dirs.append(d)
                seen.add(d)
        return unique_dirs

    @classmethod
    def _candidate_dsp_paths(cls) -> list[str]:
        name = cls._default_dsp_lib_name()
        return [os.path.join(d, name) for d in cls._iter_search_dirs()]

    @classmethod
    def _resolve_dsp_lib_path(cls, lib_path: str | None) -> str:
        if lib_path:
            # Kullanıcı açıkça verdiyse ona sadık kal.
            return lib_path

        for p in cls._candidate_dsp_paths():
            if os.path.exists(p):
                return p

        # Bulunamadı; en azından anlamlı bir varsayılan döndür.
        candidates = cls._candidate_dsp_paths()
        return candidates[-1] if candidates else cls._default_dsp_lib_name()

    def __del__(self):
        if hasattr(self, "lib") and self.dsp_ptr:
            self.lib.destroy_dsp(self.dsp_ptr)

    def process_buffer(self, buffer_np: np.ndarray, channels: int = 2):
        if self.dsp_ptr and buffer_np.dtype == np.float32:
            if buffer_np.ndim == 2 and buffer_np.shape[1] == 2:
                num_frames = buffer_np.shape[0]
                channels = 2
            else:
                num_frames = len(buffer_np) // channels
            self.lib.process_dsp(
                self.dsp_ptr,
                buffer_np.ctypes.data_as(ctypes.POINTER(ctypes.c_float)),
                num_frames,
                channels
            )

    def process_web_audio(self, buffer_np: np.ndarray, channels: int = 2):
        if self.dsp_ptr and buffer_np.dtype == np.float32:
            if buffer_np.ndim == 2 and buffer_np.shape[1] == 2:
                num_frames = buffer_np.shape[0]
                channels = 2
            else:
                num_frames = len(buffer_np) // channels
            if self.has_process_web_audio:
                self.lib.process_web_audio(
                    self.dsp_ptr,
                    buffer_np.ctypes.data_as(ctypes.POINTER(ctypes.c_float)),
                    num_frames,
                    channels
                )
            else:
                self.lib.process_dsp(
                    self.dsp_ptr,
                    buffer_np.ctypes.data_as(ctypes.POINTER(ctypes.c_float)),
                    num_frames,
                    channels
                )

    def set_eq_band(self, band: int, gain: float):
        self.lib.set_eq_band(self.dsp_ptr, band, gain)

    def set_eq_bands(self, gains):
        if not self.dsp_ptr:
            return
        gains_np = np.ascontiguousarray(gains, dtype=np.float32)
        if self.has_eq_bands:
            self.lib.set_eq_bands(
                self.dsp_ptr,
                gains_np.ctypes.data_as(ctypes.POINTER(ctypes.c_float)),
                gains_np.size
            )
        else:
            for i, gain in enumerate(gains_np):
                self.lib.set_eq_band(self.dsp_ptr, int(i), float(gain))

    def set_tone_params(self, bass: float, mid: float, treble: float):
        self.lib.set_tone_params(self.dsp_ptr, bass, mid, treble)

    def set_bass_gain(self, bass: float):
        if self.has_set_bass_gain and self.dsp_ptr:
            self.lib.set_bass_gain(self.dsp_ptr, bass)

    def set_treble_gain(self, treble: float):
        if self.has_set_treble_gain and self.dsp_ptr:
            self.lib.set_treble_gain(self.dsp_ptr, treble)

    def set_stereo_width(self, width: float):
        self.lib.set_stereo_width(self.dsp_ptr, width)

    def set_master_toggle(self, enabled: bool):
        self.lib.set_master_toggle(self.dsp_ptr, 1 if enabled else 0)

    def set_dsp_enabled(self, enabled: bool):
        self.lib.set_dsp_enabled(self.dsp_ptr, 1 if enabled else 0)

    def set_sample_rate(self, sample_rate: float):
        if self.has_set_sample_rate and self.dsp_ptr:
            self.lib.set_sample_rate(self.dsp_ptr, float(sample_rate))

    def set_web_lpf(self, freq: float):
        if self.has_set_web_lpf and self.dsp_ptr:
            self.lib.set_web_lpf(self.dsp_ptr, float(freq))

    def set_force_mute(self, mute: bool):
        if self.has_set_force_mute and self.dsp_ptr:
            self.lib.set_force_mute(self.dsp_ptr, 1 if mute else 0)

    def process_monitor_audio(self, buffer_np: np.ndarray, in_sample_rate: int):
        if self.dsp_ptr and buffer_np.dtype == np.float32:
            if buffer_np.ndim == 2 and buffer_np.shape[1] == 2:
                num_frames = buffer_np.shape[0]
            else:
                num_frames = len(buffer_np) // 2
            if self.has_process_monitor_audio:
                self.lib.process_monitor_audio(
                    self.dsp_ptr,
                    buffer_np.ctypes.data_as(ctypes.POINTER(ctypes.c_float)),
                    num_frames,
                    in_sample_rate
                )
            else:
                self.process_web_audio(buffer_np)
