#include <algorithm>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <memory>
#include <pybind11/numpy.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <vector>

// KissFFT'yi dahil et
#include "kiss_fft.h"
#include "tools/kiss_fftr.h"

#ifdef VIZ_WITH_PROJECTM
#include <libprojectM/projectM.hpp>
#endif

namespace py = pybind11;

// FFT boyutu sabit (1024 nokta FFT)
constexpr int NFFT = 1024;
constexpr int VISUALIZER_BINS = 100;

class BarVisualizer {
private:
  kiss_fftr_cfg fft_cfg;

public:
  BarVisualizer() {
    // FFT yapılandırmasını başlat
    fft_cfg = kiss_fftr_alloc(NFFT, 0, NULL, 0); // 0=ters FFT değil
    std::cout << "C++ BarVisualizer motoru KissFFT ile başlatıldı."
              << std::endl;
  }

  ~BarVisualizer() {
    if (fft_cfg) {
      free(fft_cfg);
    }
  }

  py::array_t<double> process_audio_data(py::array_t<double> input_data) {

    auto buf = input_data.request();
    if (buf.ptr == nullptr) {
      throw std::runtime_error("Input data is invalid (nullptr)");
    }

    const double *ptr = static_cast<const double *>(buf.ptr);
    size_t input_size = buf.shape[0];

    // 1. Gelen veriyi FFT boyutuna uygun hale getir (Sadece ilk 1024 örneği al)
    int sample_count = std::min((int)input_size, NFFT);

    // 2. FFT için giriş ve çıkış tamponları
    kiss_fft_scalar timedata[NFFT] = {0}; // Giriş (Ses örnekleri)
    kiss_fft_cpx freqdata[NFFT / 2 + 1];  // Çıkış (Frekanslar)

    // Veriyi kopyala
    for (int i = 0; i < sample_count; ++i) {
      timedata[i] = (kiss_fft_scalar)ptr[i];
    }

    // 3. FFT'yi hesapla
    kiss_fftr(fft_cfg, timedata, freqdata);

    // 4. Genlikleri (Magnitude) ve Logaritmik (dB) Değeri hesapla
    std::vector<double> magnitudes(NFFT / 2 + 1);
    for (size_t i = 0; i < NFFT / 2 + 1; ++i) {
      // Genlik = sqrt(gerçek kısım^2 + sanal kısım^2)
      double mag = std::sqrt(freqdata[i].r * freqdata[i].r +
                             freqdata[i].i * freqdata[i].i);

      // Logaritmik Dönüşüm (dB)
      // 20 * log10(1.0 + mag)
      double db_val = 20.0 * std::log10(1.0 + mag);

      // Negatif değerleri engelle
      magnitudes[i] = std::max(0.0, db_val);
    }

    // 5. Boyutu 100 çubuğa indirgeme
    std::vector<double> result(VISUALIZER_BINS);
    for (int i = 0; i < VISUALIZER_BINS; ++i) {
      // Basit bir örnekleme (sampling) veya ortalama alma yapılabilir.
      // Burada basitçe düşük frekanslardan yüksek frekanslara doğru alıyoruz.
      // Daha iyi bir görselleştirme için logaritmik indeksleme gerekebilir ama
      // şimdilik lineer eşleme ile devam ediyoruz.
      if ((size_t)i < magnitudes.size()) {
        result[i] = magnitudes[i];
      } else {
        result[i] = 0.0;
      }
    }

    // Sonucu Python'a numpy dizisi olarak geri döndürme
    // py::array_t(size, data_pointer) creates a copy
    return py::array_t<double>(VISUALIZER_BINS, result.data());
  }
};

#ifdef VIZ_WITH_PROJECTM
/**
 * Minimal ProjectM wrapper for Python.
 * Exposes render, resize and PCM feed methods.
 */
class ProjectMWrapper {
private:
  std::unique_ptr<projectM> engine;

public:
  ProjectMWrapper(const std::string &preset_dir, const std::string &font_dir,
                  int width, int height) {
    projectM::Settings settings;
    settings.meshX = 32;
    settings.meshY = 24;
    settings.fps = 60; // Daha yüksek varsayılan (Aurivo 35, biz 60)
    settings.textureSize = 512;
    settings.windowWidth = width;
    settings.windowHeight = height;
    settings.presetURL = preset_dir;
    settings.menuFontURL = font_dir;
    settings.titleFontURL = font_dir;

    engine = std::make_unique<projectM>(settings);
    engine->projectM_resetGL(width, height);
  }

  void opengl_render() {
    if (engine) {
      engine->renderFrame();
    }
  }

  void window_resize(int w, int h) {
    if (engine) {
      engine->projectM_resetGL(w, h);
    }
  }

  void pcm_add_short(
      py::array_t<int16_t, py::array::c_style | py::array::forcecast> pcm,
      int sample_frames) {
    if (!engine) {
      return;
    }

    auto buf = pcm.request();
    if (buf.ndim != 1) {
      throw std::runtime_error("pcm_add_short expects a 1-D int16 array");
    }

    // Incoming data is interleaved stereo. sample_frames = frames per channel.
    const int total_values = static_cast<int>(buf.size);
    const int frames_available =
        total_values / 2; // stereo -> two ints per frame
    const int frames_to_send =
        std::max(0, std::min(sample_frames, frames_available));
    if (frames_to_send == 0) {
      return;
    }

    const int16_t *data_ptr = static_cast<const int16_t *>(buf.ptr);
    engine->pcm()->addPCM16Data(reinterpret_cast<const short *>(data_ptr),
                                static_cast<short>(frames_to_send));
  }

  // --- Preset Kontrolü ---
  void preset_random(bool hard_cut) {
    if (engine) {
      engine->selectRandom(hard_cut);
    }
  }

  // YENİ: Playlist Boyutu
  unsigned int get_playlist_size() {
    if (engine) {
      return engine->getPlaylistSize();
    }
    return 0;
  }

  // YENİ: Preset Adı
  std::string get_preset_name(unsigned int index) {
    // std::cout << "DEBUG: get_preset_name called for index " << index <<
    // std::endl;
    if (engine) {
      if (index < engine->getPlaylistSize()) {
        try {
          return engine->getPresetName(index);
        } catch (const std::exception &e) {
          std::cerr << "ProjectM getPresetName exception: " << e.what()
                    << std::endl;
          return "Error Loading Preset Name";
        } catch (...) {
          return "Unknown Preset (Error)";
        }
      }
    }
    return "";
  }

  // YENİ: Preset Seçme (Index ile)
  void select_preset(unsigned int index) {
    if (engine && index < engine->getPlaylistSize()) {
      engine->selectPreset(index);
    }
  }
};
#endif

// pybind11 ile C++ sınıfını Python'a bağlama
PYBIND11_MODULE(viz_engine, m) {
  m.doc() =
      "pybind11 ile bağlanmış C++ Görselleştirme Motoru (KissFFT Destekli)";

  py::class_<BarVisualizer>(m, "BarVisualizer")
      .def(py::init<>())
      .def("process_audio_data", &BarVisualizer::process_audio_data);

#ifdef VIZ_WITH_PROJECTM
  py::class_<ProjectMWrapper>(m, "ProjectM")
      .def(py::init<const std::string &, const std::string &, int, int>())
      .def("opengl_render", &ProjectMWrapper::opengl_render)
      .def("window_resize", &ProjectMWrapper::window_resize)
      .def("pcm_add_short", &ProjectMWrapper::pcm_add_short)
      .def("preset_random", &ProjectMWrapper::preset_random,
           py::arg("hard_cut") = false)
      .def("get_playlist_size", &ProjectMWrapper::get_playlist_size)
      .def("get_preset_name", &ProjectMWrapper::get_preset_name)
      .def("select_preset", &ProjectMWrapper::select_preset);
#endif
}
