#include <algorithm>
#include <array>
#include <cmath>
#include <vector>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

// Angolla Safe EQ Engine (32-band only)
namespace AngollaDSP {

static const int NUM_BANDS = 32;
static float gSampleRate = 48000.0f;
static const float MIN_EQ_FREQ = 20.0f;
static const float MAX_EQ_FREQ = 20000.0f;
static const float NOISE_GATE_DB = -60.0f;
static const float NOISE_GATE_RMS = std::pow(10.0f, NOISE_GATE_DB / 20.0f);

static inline float clampf(float value, float min_value, float max_value) {
  return std::max(min_value, std::min(value, max_value));
}

// Windowed Sinc Resampler (Fixed 44.1k -> 48k for Monitor)
struct Resampler {
  float bufferL[256], bufferR[256];
  int writePos;
  double phase;
  double ratio;

  Resampler() : writePos(0), phase(0.0), ratio(48000.0 / 44100.0) {
    std::fill(bufferL, bufferL + 256, 0.0f);
    std::fill(bufferR, bufferR + 256, 0.0f);
  }

  void push(float L, float R) {
    bufferL[writePos] = L;
    bufferR[writePos] = R;
    writePos = (writePos + 1) % 256;
  }

  // Simple High-quality Linear Interpolation (Efficient for real-time bypass)
  // For true Windowed-Sinc, it would require much more state/buffer.
  // We'll use a 4-point Hermite if possible, or high-order Linear.
  void process(float *inL, float *inR, int inFrames, float *out,
               int &outFrames) {
    double step = 1.0 / ratio;
    int outIdx = 0;
    while (phase < inFrames) {
      int i = (int)phase;
      double f = phase - i;

      float L, R;
      if (i + 1 < inFrames) {
        L = inL[i] * (1.0f - (float)f) + inL[i + 1] * (float)f;
        R = inR[i] * (1.0f - (float)f) + inR[i + 1] * (float)f;
      } else {
        L = inL[i];
        R = inR[i];
      }

      out[outIdx * 2] = L;
      out[outIdx * 2 + 1] = R;
      outIdx++;
      phase += step;
    }
    phase -= inFrames;
    outFrames = outIdx;
  }
};

static std::array<float, NUM_BANDS> makeCenterFrequencies() {
  std::array<float, NUM_BANDS> freqs{};
  float log_min = std::log10(MIN_EQ_FREQ);
  float log_max = std::log10(MAX_EQ_FREQ);
  float step = (log_max - log_min) / (NUM_BANDS - 1);
  for (int i = 0; i < NUM_BANDS; ++i) {
    freqs[i] = std::pow(10.0f, log_min + step * i);
  }
  return freqs;
}

static const std::array<float, NUM_BANDS> CENTER_FREQUENCIES =
    makeCenterFrequencies();

// ==================================================================================
// BIQUAD FILTER CORE
// ==================================================================================
struct Biquad {
  float b0, b1, b2, a1, a2;
  float x1, x2, y1, y2;

  Biquad() : b0(1), b1(0), b2(0), a1(0), a2(0), x1(0), x2(0), y1(0), y2(0) {}

  void reset() { x1 = x2 = y1 = y2 = 0; }

  void setPeakingEQ(float centerFreq, float Q, float gaindB) {
    float A = std::pow(10.0f, gaindB / 40.0f);
    float omega = 2.0f * (float)M_PI * centerFreq / gSampleRate;
    float sn = std::sin(omega);
    float cs = std::cos(omega);
    float alpha = sn / (2.0f * Q);

    float b0_tmp = 1.0f + alpha * A;
    float b1_tmp = -2.0f * cs;
    float b2_tmp = 1.0f - alpha * A;
    float a0_tmp = 1.0f + alpha / A;
    float a1_tmp = -2.0f * cs;
    float a2_tmp = 1.0f - alpha / A;

    b0 = b0_tmp / a0_tmp;
    b1 = b1_tmp / a0_tmp;
    b2 = b2_tmp / a0_tmp;
    a1 = a1_tmp / a0_tmp;
    a2 = a2_tmp / a0_tmp;
  }

  void setLowShelf(float cutoffFreq, float gaindB) {
    float A = std::pow(10.0f, gaindB / 40.0f);
    float omega = 2.0f * (float)M_PI * cutoffFreq / gSampleRate;
    float sn = std::sin(omega);
    float cs = std::cos(omega);
    float beta = std::sqrt(A + A);

    float b0_tmp = A * ((A + 1) - (A - 1) * cs + beta * sn);
    float b1_tmp = 2 * A * ((A - 1) - (A + 1) * cs);
    float b2_tmp = A * ((A + 1) - (A - 1) * cs - beta * sn);
    float a0_tmp = (A + 1) + (A - 1) * cs + beta * sn;
    float a1_tmp = -2 * ((A - 1) + (A + 1) * cs);
    float a2_tmp = (A + 1) + (A - 1) * cs - beta * sn;

    b0 = b0_tmp / a0_tmp;
    b1 = b1_tmp / a0_tmp;
    b2 = b2_tmp / a0_tmp;
    a1 = a1_tmp / a0_tmp;
    a2 = a2_tmp / a0_tmp;
  }

  void setHighShelf(float cutoffFreq, float gaindB) {
    float A = std::pow(10.0f, gaindB / 40.0f);
    float omega = 2.0f * (float)M_PI * cutoffFreq / gSampleRate;
    float sn = std::sin(omega);
    float cs = std::cos(omega);
    float beta = std::sqrt(A + A);

    float b0_tmp = A * ((A + 1) + (A - 1) * cs + beta * sn);
    float b1_tmp = -2 * A * ((A - 1) + (A + 1) * cs);
    float b2_tmp = A * ((A + 1) + (A - 1) * cs - beta * sn);
    float a0_tmp = (A + 1) - (A - 1) * cs + beta * sn;
    float a1_tmp = 2 * ((A - 1) - (A + 1) * cs);
    float a2_tmp = (A + 1) - (A - 1) * cs - beta * sn;

    b0 = b0_tmp / a0_tmp;
    b1 = b1_tmp / a0_tmp;
    b2 = b2_tmp / a0_tmp;
    a1 = a1_tmp / a0_tmp;
    a2 = a2_tmp / a0_tmp;
  }

  void setLowPass(float cutoffFreq, float Q) {
    float fc = clampf(cutoffFreq, 10.0f, gSampleRate * 0.45f);
    float omega = 2.0f * (float)M_PI * fc / gSampleRate;
    float sn = std::sin(omega);
    float cs = std::cos(omega);
    float alpha = sn / (2.0f * Q);

    float b0_tmp = (1.0f - cs) * 0.5f;
    float b1_tmp = 1.0f - cs;
    float b2_tmp = (1.0f - cs) * 0.5f;
    float a0_tmp = 1.0f + alpha;
    float a1_tmp = -2.0f * cs;
    float a2_tmp = 1.0f - alpha;

    b0 = b0_tmp / a0_tmp;
    b1 = b1_tmp / a0_tmp;
    b2 = b2_tmp / a0_tmp;
    a1 = a1_tmp / a0_tmp;
    a2 = a2_tmp / a0_tmp;
  }

  void setHighPass(float cutoffFreq, float Q) {
    float fc = clampf(cutoffFreq, 10.0f, gSampleRate * 0.45f);
    float omega = 2.0f * (float)M_PI * fc / gSampleRate;
    float sn = std::sin(omega);
    float cs = std::cos(omega);
    float alpha = sn / (2.0f * Q);

    float b0_tmp = (1.0f + cs) * 0.5f;
    float b1_tmp = -(1.0f + cs);
    float b2_tmp = (1.0f + cs) * 0.5f;
    float a0_tmp = 1.0f + alpha;
    float a1_tmp = -2.0f * cs;
    float a2_tmp = 1.0f - alpha;

    b0 = b0_tmp / a0_tmp;
    b1 = b1_tmp / a0_tmp;
    b2 = b2_tmp / a0_tmp;
    a1 = a1_tmp / a0_tmp;
    a2 = a2_tmp / a0_tmp;
  }

  inline float process(float input) {
    float output = b0 * input + b1 * x1 + b2 * x2 - a1 * y1 - a2 * y2;
    if (std::abs(output) < 1e-20f)
      output = 0.0f;
    x2 = x1;
    x1 = input;
    y2 = y1;
    y1 = output;
    return output;
  }
};

// ==================================================================================
// MASTER DSP CHAIN (EQ + Tone_Space)
// ==================================================================================
class MasterDSP {
private:
  std::vector<Biquad> filtersLeft, filtersRight;
  Biquad lowExciterL, lowExciterR;
  Biquad highExciterL, highExciterR;
  Biquad smartBassL, smartBassR;
  Biquad bassLoudL, bassLoudR;
  Biquad bassProtectL, bassProtectR;
  Biquad toneMidL, toneMidR;
  Biquad toneHighL, toneHighR;
  Biquad webLowPassL, webLowPassR;
  float webLowPassFreq;
  float gains[NUM_BANDS];
  float targetGains[NUM_BANDS];
  float currentGains[NUM_BANDS];
  float targetTone[3];
  float currentTone[3];
  float targetStereoWidth;
  float currentStereoWidth;
  float targetPreGain;
  float currentPreGain;
  float currentMasterGain;
  float smartMix;
  std::array<int, NUM_BANDS> activeBands;
  int activeBandCount;
  float limiterCeiling;
  bool smartEnabled;
  bool dspEnabled;
  bool needsRebuild;

  // Steady-State Noise Detector
  float lastRMS;
  float rmsVariance;
  int frozenCounter;
  bool signalFrozen;
  bool forceMute;
  float monitorGateThreshold;
  Resampler monitorResampler;

public:
  MasterDSP()
      : targetPreGain(1.0f), currentPreGain(1.0f), activeBandCount(0),
        webLowPassFreq(8000.0f) {
    filtersLeft.resize(NUM_BANDS);
    filtersRight.resize(NUM_BANDS);
    for (int i = 0; i < NUM_BANDS; ++i) {
      gains[i] = 1.0f;
      targetGains[i] = 1.0f;
      currentGains[i] = 1.0f;
    }
    targetTone[0] = targetTone[1] = targetTone[2] = 1.0f;
    currentTone[0] = currentTone[1] = currentTone[2] = 1.0f;
    targetStereoWidth = 1.0f;
    currentStereoWidth = 1.0f;
    currentMasterGain = 1.0f;
    smartMix = 0.3f;
    smartEnabled = true;
    dspEnabled = true;
    needsRebuild = false;

    limiterCeiling = std::pow(10.0f, -0.3f / 20.0f);

    lastRMS = 0.0f;
    rmsVariance = 1.0f;
    frozenCounter = 0;
    signalFrozen = false;
    forceMute = false;
    monitorGateThreshold = std::pow(10.0f, -35.0f / 20.0f); // Phase 3 Hard Gate
  }

  void rebuildFilters() {
    for (auto &f : filtersLeft)
      f.reset();
    for (auto &f : filtersRight)
      f.reset();
    lowExciterL.reset();
    lowExciterR.reset();
    highExciterL.reset();
    highExciterR.reset();
    smartBassL.reset();
    smartBassR.reset();
    bassLoudL.reset();
    bassLoudR.reset();
    bassProtectL.reset();
    bassProtectR.reset();
    toneMidL.reset();
    toneMidR.reset();
    toneHighL.reset();
    toneHighR.reset();
    webLowPassL.reset();
    webLowPassR.reset();

    const float Q = 2.5f;
    for (int b = 0; b < NUM_BANDS; ++b) {
      if (b == 0) {
        filtersLeft[b].setLowShelf(CENTER_FREQUENCIES[b], currentGains[b]);
        filtersRight[b].setLowShelf(CENTER_FREQUENCIES[b], currentGains[b]);
      } else if (b == NUM_BANDS - 1) {
        filtersLeft[b].setHighShelf(CENTER_FREQUENCIES[b], currentGains[b]);
        filtersRight[b].setHighShelf(CENTER_FREQUENCIES[b], currentGains[b]);
      } else {
        filtersLeft[b].setPeakingEQ(CENTER_FREQUENCIES[b], Q, currentGains[b]);
        filtersRight[b].setPeakingEQ(CENTER_FREQUENCIES[b], Q, currentGains[b]);
      }
    }

    lowExciterL.setLowPass(120.0f, 0.7f);
    lowExciterR.setLowPass(120.0f, 0.7f);
    highExciterL.setHighPass(6000.0f, 0.7f);
    highExciterR.setHighPass(6000.0f, 0.7f);

    smartBassL.setLowPass(120.0f, 0.7f);
    smartBassR.setLowPass(120.0f, 0.7f);
    bassLoudL.setLowShelf(100.0f, currentTone[0]);
    bassLoudR.setLowShelf(100.0f, currentTone[0]);
    bassProtectL.setLowPass(140.0f, 0.7f);
    bassProtectR.setLowPass(140.0f, 0.7f);

    toneMidL.setPeakingEQ(1000.0f, 0.8f, currentTone[1]);
    toneMidR.setPeakingEQ(1000.0f, 0.8f, currentTone[1]);
    toneHighL.setHighShelf(10000.0f, currentTone[2]);
    toneHighR.setHighShelf(10000.0f, currentTone[2]);
    webLowPassL.setLowPass(webLowPassFreq, 0.7f);
    webLowPassR.setLowPass(webLowPassFreq, 0.7f);
  }

  void setSampleRate(float sr) {
    float clamped = clampf(sr, 8000.0f, 192000.0f);
    if (std::abs(clamped - gSampleRate) < 1.0f)
      return;
    gSampleRate = clamped;
    needsRebuild = true;
  }

  void updateTargets() {
    float max_boost = 0.0f;
    for (int i = 0; i < NUM_BANDS; ++i) {
      targetGains[i] = gains[i];
      float weight = (i == 0 || i == NUM_BANDS - 1) ? 0.6f : 1.0f;
      float weighted = targetGains[i] * weight;
      if (weighted > max_boost)
        max_boost = weighted;
    }
    float soft_boost = 6.0f * std::tanh(max_boost / 6.0f);
    targetPreGain = std::pow(10.0f, -(soft_boost * 0.60f) / 20.0f);
  }

  void setEQGain(int band, float db) {
    if (band >= 0 && band < NUM_BANDS) {
      gains[band] = db;
      updateTargets();
    }
  }

  void setEQGains(const float *newGains, int numBands) {
    if (!newGains)
      return;
    int count = numBands;
    if (count > NUM_BANDS)
      count = NUM_BANDS;
    for (int i = 0; i < count; ++i)
      gains[i] = newGains[i];
    updateTargets();
  }

  void setDSPEnabled(bool enabled) { dspEnabled = enabled; }

  void setToneParams(float bass, float mid, float treble) {
    targetTone[0] = bass;
    targetTone[1] = mid;
    targetTone[2] = treble;
  }

  void setStereoWidth(float width) {
    targetStereoWidth = clampf(width, 0.0f, 2.0f);
  }

  void setMasterToggle(bool active) { smartEnabled = active; }

  void setWebLPF(float freq) {
    float clamped = clampf(freq, 200.0f, 20000.0f);
    if (std::abs(clamped - webLowPassFreq) > 1.0f) {
      webLowPassFreq = clamped;
      webLowPassL.setLowPass(webLowPassFreq, 0.7f);
      webLowPassR.setLowPass(webLowPassFreq, 0.7f);
    }
  }

  void processBuffer(float *buffer, int numFrames, int channels) {
    if (!buffer || channels != 2)
      return;

    int total_samples = numFrames * channels;
    if (total_samples <= 0)
      return;

    double sum_sq = 0.0;
    for (int i = 0; i < total_samples; ++i) {
      float v = buffer[i];
      sum_sq += static_cast<double>(v) * static_cast<double>(v);
    }
    float rms = std::sqrt(sum_sq / total_samples);
    if (rms < NOISE_GATE_RMS) {
      std::fill(buffer, buffer + total_samples, 0.0f);
      return;
    }

    if (needsRebuild) {
      rebuildFilters();
      needsRebuild = false;
    }

    if (!dspEnabled)
      return;

    const float smoothingSamples = std::max(512.0f, gSampleRate * 0.02f);
    const float smartHeadroomDb = -3.0f;
    const float smartStep = 1.0f / smoothingSamples;
    const float invSmoothing = 1.0f / smoothingSamples;
    const float smoothThreshold = 0.0001f;
    const float Q = 2.5f;
    const float toneQ = 0.8f;
    const float duckThresholdDb = 10.0f;
    const float duckRangeDb = 5.0f;
    const float duckMaxDb = -6.0f;
    const float bassLimit = limiterCeiling * 0.85f;
    const float hardLimiterCeiling = 1.0f;

    auto hard_limit = [&](float x) {
      if (x > hardLimiterCeiling)
        return hardLimiterCeiling;
      if (x < -hardLimiterCeiling)
        return -hardLimiterCeiling;
      return x;
    };

    for (int i = 0; i < numFrames * 2; i += 2) {
      float &L = buffer[i];
      float &R = buffer[i + 1];
      float inL = L;
      float inR = R;

      float smartTarget = smartEnabled ? 1.0f : 0.0f;
      if (smartMix < smartTarget) {
        smartMix = std::min(smartTarget, smartMix + smartStep);
      } else if (smartMix > smartTarget) {
        smartMix = std::max(smartTarget, smartMix - smartStep);
      }

      if (smartMix > 0.0f) {
        float lowL = smartBassL.process(inL);
        float lowR = smartBassR.process(inR);
        float drive = 1.4f;
        float harmL = std::tanh(lowL * drive) - lowL;
        float harmR = std::tanh(lowR * drive) - lowR;
        inL += harmL * (0.12f * smartMix);
        inR += harmR * (0.12f * smartMix);
        float headroom = std::pow(10.0f, (smartHeadroomDb * smartMix) / 20.0f);
        inL *= headroom;
        inR *= headroom;
      }

      currentPreGain += (targetPreGain - currentPreGain) * invSmoothing;
      currentStereoWidth +=
          (targetStereoWidth - currentStereoWidth) * invSmoothing;

      activeBandCount = 0;
      for (int b = 0; b < NUM_BANDS; ++b) {
        float diff = targetGains[b] - currentGains[b];
        if (std::abs(diff) > smoothThreshold) {
          currentGains[b] += diff * invSmoothing;
          if (b == 0) {
            filtersLeft[b].setLowShelf(CENTER_FREQUENCIES[b], currentGains[b]);
            filtersRight[b].setLowShelf(CENTER_FREQUENCIES[b], currentGains[b]);
          } else if (b == NUM_BANDS - 1) {
            filtersLeft[b].setHighShelf(CENTER_FREQUENCIES[b], currentGains[b]);
            filtersRight[b].setHighShelf(CENTER_FREQUENCIES[b],
                                         currentGains[b]);
          } else {
            filtersLeft[b].setPeakingEQ(CENTER_FREQUENCIES[b], Q,
                                        currentGains[b]);
            filtersRight[b].setPeakingEQ(CENTER_FREQUENCIES[b], Q,
                                         currentGains[b]);
          }
        } else if (diff != 0.0f) {
          currentGains[b] = targetGains[b];
          if (b == 0) {
            filtersLeft[b].setLowShelf(CENTER_FREQUENCIES[b], currentGains[b]);
            filtersRight[b].setLowShelf(CENTER_FREQUENCIES[b], currentGains[b]);
          } else if (b == NUM_BANDS - 1) {
            filtersLeft[b].setHighShelf(CENTER_FREQUENCIES[b], currentGains[b]);
            filtersRight[b].setHighShelf(CENTER_FREQUENCIES[b],
                                         currentGains[b]);
          } else {
            filtersLeft[b].setPeakingEQ(CENTER_FREQUENCIES[b], Q,
                                        currentGains[b]);
            filtersRight[b].setPeakingEQ(CENTER_FREQUENCIES[b], Q,
                                         currentGains[b]);
          }
        }

        if (currentGains[b] != 0.0f) {
          activeBands[activeBandCount++] = b;
        }
      }

      L = inL * currentPreGain;
      R = inR * currentPreGain;

      for (int j = 0; j < activeBandCount; ++j) {
        int b = activeBands[j];
        L = filtersLeft[b].process(L);
        R = filtersRight[b].process(R);
      }

      float low_boost = currentGains[0];
      float high_boost = currentGains[NUM_BANDS - 1];

      float low_amount = clampf((low_boost - 10.0f) / 5.0f, 0.0f, 1.0f);
      float high_amount = clampf((high_boost - 10.0f) / 5.0f, 0.0f, 1.0f);

      if (low_amount > 0.0f) {
        float lowL = lowExciterL.process(L);
        float lowR = lowExciterR.process(R);
        float drive = 1.0f + (low_amount * 2.0f);
        float harmL = std::tanh(lowL * drive) - lowL;
        float harmR = std::tanh(lowR * drive) - lowR;
        L += harmL * (0.10f * low_amount);
        R += harmR * (0.10f * low_amount);
      }

      if (high_amount > 0.0f) {
        float highL = highExciterL.process(L);
        float highR = highExciterR.process(R);
        float drive = 1.0f + (high_amount * 2.5f);
        float harmL = std::tanh(highL * drive) - highL;
        float harmR = std::tanh(highR * drive) - highR;
        L += harmL * (0.08f * high_amount);
        R += harmR * (0.08f * high_amount);
      }

      // Tone Space (post-EQ)
      for (int t = 0; t < 3; ++t) {
        float diff = targetTone[t] - currentTone[t];
        if (std::abs(diff) > smoothThreshold) {
          currentTone[t] += diff * invSmoothing;
        } else if (diff != 0.0f) {
          currentTone[t] = targetTone[t];
        }
      }
      if (smartMix > 0.0f) {
        // Phase 1: Professional Low-Shelf (100Hz) at the start of the chain
        bassLoudL.setLowShelf(100.0f, currentTone[0]);
        bassLoudR.setLowShelf(100.0f, currentTone[0]);
        toneMidL.setPeakingEQ(1000.0f, toneQ, currentTone[1]);
        toneMidR.setPeakingEQ(1000.0f, toneQ, currentTone[1]);
        toneHighL.setHighShelf(10000.0f, currentTone[2]);
        toneHighR.setHighShelf(10000.0f, currentTone[2]);

        float toneScale = smartMix;
        float L_proc = L;
        float R_proc = R;

        // Sequential Processing: Bass -> Mid -> High
        L_proc = bassLoudL.process(L_proc);
        R_proc = bassLoudR.process(R_proc);
        L_proc = toneMidL.process(L_proc);
        R_proc = toneMidR.process(R_proc);
        L_proc = toneHighL.process(L_proc);
        R_proc = toneHighR.process(R_proc);

        // Blend based on smartMix
        L = L * (1.0f - toneScale) + L_proc * toneScale;
        R = R * (1.0f - toneScale) + R_proc * toneScale;

        if (currentStereoWidth != 1.0f) {
          float M = (L + R) * 0.5f;
          float S = (L - R) * 0.5f;
          S *= currentStereoWidth;
          L = M + S;
          R = M - S;
        }
      }

      float duckAmount = 0.0f;
      if (smartMix > 0.0f && currentTone[0] > duckThresholdDb) {
        duckAmount = clampf((currentTone[0] - duckThresholdDb) / duckRangeDb,
                            0.0f, 1.0f);
      }
      // Phase 6: Dynamic Bass AGC (Headroom Management)
      // Reduce master gain as low-end boost increases to prevent "boaty"
      // distortion
      float max_low_boost = 0.0f;
      for (int b = 0; b < 6; ++b) { // Monitor first 6 bands (~20Hz to ~200Hz)
        if (currentGains[b] > max_low_boost)
          max_low_boost = currentGains[b];
      }

      float bass_reduction_db = std::max(0.0f, max_low_boost * 0.45f);
      float tone_bass_boost_db = std::max(0.0f, currentTone[0]) * smartMix;
      float tone_bass_reduction_db = tone_bass_boost_db * 0.333f; // 3dB boost -> 1dB reduction
      float duck_db = duckMaxDb * duckAmount * smartMix;
      float targetMaster =
          limiterCeiling *
          std::pow(10.0f,
                   (duck_db - bass_reduction_db - tone_bass_reduction_db) /
                       20.0f);

      currentMasterGain += (targetMaster - currentMasterGain) * invSmoothing;
      L *= currentMasterGain;
      R *= currentMasterGain;

      auto bass_limit = [&](float x) {
        float ax = std::abs(x);
        if (ax <= bassLimit)
          return x;
        float excess = ax - bassLimit;
        float k = 6.0f;
        float compressed = bassLimit + (1.0f - std::exp(-k * excess)) / k;
        return (x < 0.0f) ? -compressed : compressed;
      };

      float lowL = bassProtectL.process(L);
      float lowR = bassProtectR.process(R);
      L = (L - lowL) + bass_limit(lowL);
      R = (R - lowR) + bass_limit(lowR);

      auto soft_limit = [&](float x) {
        float ax = std::abs(x);
        if (ax <= limiterCeiling)
          return x;
        float excess = ax - limiterCeiling;
        float k = 4.0f;
        float compressed = limiterCeiling + (1.0f - std::exp(-k * excess)) / k;
        return (x < 0.0f) ? -compressed : compressed;
      };
      L = soft_limit(L);
      R = soft_limit(R);

      // Final Stereo sync clamp
      buffer[i] = hard_limit(L);
      buffer[i + 1] = hard_limit(R);
    }
  }

  void processWebBuffer(float *buffer, int numFrames, int channels) {
    int total_samples = numFrames * channels;
    if (!buffer || channels != 2 || forceMute) {
      if (buffer && total_samples > 0)
        std::fill(buffer, buffer + total_samples, 0.0f);
      return;
    }
    if (total_samples <= 0)
      return;

    // Hard Limiter & Cleaner Pre-process
    for (int i = 0; i < total_samples; ++i) {
      if (std::isnan(buffer[i]) || std::isinf(buffer[i]))
        buffer[i] = 0.0f;
      buffer[i] = clampf(buffer[i], -0.8f, 0.8f);
    }

    double sum_sq = 0.0;
    for (int i = 0; i < total_samples; ++i) {
      float v = buffer[i];
      sum_sq += static_cast<double>(v) * static_cast<double>(v);
    }
    float rms = std::sqrt(sum_sq / total_samples);

    // Phase 3: Hard -35dB Gate
    if (rms < monitorGateThreshold) {
      std::fill(buffer, buffer + total_samples, 0.0f);
      return;
    }

    for (int i = 0; i < numFrames; ++i) {
      float L = buffer[i * 2];
      float R = buffer[i * 2 + 1];

      // Dynamic LPF implementation
      L = webLowPassL.process(L);
      R = webLowPassR.process(R);

      buffer[i * 2] = clampf(L, -0.8f, 0.8f);
      buffer[i * 2 + 1] = clampf(R, -0.8f, 0.8f);
    }

    // Steady-State Noise Detector (Hiss/Frozen kill)
    if (rms > 0.5f) { // Slightly lower threshold for quicker kill
      float diff = std::abs(rms - lastRMS);
      if (diff < 0.00005f) { // Even more sensitive
        frozenCounter++;
      } else {
        frozenCounter = std::max(0, frozenCounter - 5);
      }

      if (frozenCounter > 15) { // Quicker kill (~300ms)
        signalFrozen = true;
      } else {
        signalFrozen = false;
      }
    } else {
      frozenCounter = 0;
      signalFrozen = false;
    }
    lastRMS = rms;

    if (signalFrozen) {
      std::fill(buffer, buffer + total_samples, 0.0f);
      return;
    }

    processBuffer(buffer, numFrames, channels);

    // Final Safety Clamp
    for (int i = 0; i < total_samples; ++i) {
      buffer[i] = clampf(buffer[i], -0.8f, 0.8f);
    }
  } // End of processWebBuffer

  void setForceMute(bool mute) { forceMute = mute; }

  void processMonitorBuffer(float *buffer, int numFrames, int inSampleRate) {
    if (!buffer)
      return;

    if (inSampleRate == 48000) {
      processWebBuffer(buffer, numFrames, 2);
      return;
    }

    // High-quality resampling to 48k (Limited to numFrames to maintain sync)
    // We pull frames, resample, and copy back exactly what Python expects.
    int maxOutFrames = (int)(numFrames * 1.2) + 64;
    static std::vector<float> resampled(maxOutFrames * 2);

    std::vector<float> inL(numFrames), inR(numFrames);
    for (int i = 0; i < numFrames; ++i) {
      inL[i] = buffer[i * 2];
      inR[i] = buffer[i * 2 + 1];
    }

    int outFrames = 0;
    monitorResampler.process(inL.data(), inR.data(), numFrames,
                             resampled.data(), outFrames);

    // Process the resampled buffer through the web chain (EQ/Tone/Gate)
    processWebBuffer(resampled.data(), outFrames, 2);

    // Copy back to output pointer. Since Python pulled 'numFrames' from a 44.1k
    // queue but expects them to fill a 48k buffer, we copy as much as we have.
    // Usually outFrames will be > numFrames by ~9%.
    int copyFrames = std::min(numFrames, outFrames);
    std::copy(resampled.begin(), resampled.begin() + copyFrames * 2, buffer);

    // Fill remainder with zero if any (safety)
    if (copyFrames < numFrames) {
      std::fill(buffer + copyFrames * 2, buffer + numFrames * 2, 0.0f);
    }
  }
}; // This closes the MasterDSP class

} // namespace AngollaDSP

// ==================================================================================
// C-INTERFACE
// ==================================================================================
extern "C" {

void *create_dsp() { return new AngollaDSP::MasterDSP(); }

void destroy_dsp(void *dsp) {
  delete static_cast<AngollaDSP::MasterDSP *>(dsp);
}

void process_dsp(void *dsp, float *buffer, int numFrames, int channels) {
  if (dsp)
    static_cast<AngollaDSP::MasterDSP *>(dsp)->processBuffer(buffer, numFrames,
                                                             channels);
}

void process_audio_frame(void *dsp, float *buffer, int numFrames,
                         int channels) {
  process_dsp(dsp, buffer, numFrames, channels);
}

void process_web_audio(void *dsp, float *buffer, int numFrames, int channels) {
  if (dsp)
    static_cast<AngollaDSP::MasterDSP *>(dsp)->processWebBuffer(
        buffer, numFrames, channels);
}

void set_eq_band(void *dsp, int band, float gain) {
  if (dsp)
    static_cast<AngollaDSP::MasterDSP *>(dsp)->setEQGain(band, gain);
}

void set_eq_bands(void *dsp, const float *gains, int numBands) {
  if (dsp)
    static_cast<AngollaDSP::MasterDSP *>(dsp)->setEQGains(gains, numBands);
}

void set_tone_params(void *dsp, float bass, float mid, float treble) {
  if (dsp)
    static_cast<AngollaDSP::MasterDSP *>(dsp)->setToneParams(bass, mid, treble);
}

void set_stereo_width(void *dsp, float width) {
  if (dsp)
    static_cast<AngollaDSP::MasterDSP *>(dsp)->setStereoWidth(width);
}

void set_master_toggle(void *dsp, int active) {
  if (dsp)
    static_cast<AngollaDSP::MasterDSP *>(dsp)->setMasterToggle(active != 0);
}

void set_dsp_enabled(void *dsp, int enabled) {
  if (dsp)
    static_cast<AngollaDSP::MasterDSP *>(dsp)->setDSPEnabled(enabled != 0);
}

void set_sample_rate(void *dsp, float sample_rate) {
  if (dsp)
    static_cast<AngollaDSP::MasterDSP *>(dsp)->setSampleRate(sample_rate);
}

void set_web_lpf(void *dsp, float freq) {
  if (dsp)
    static_cast<AngollaDSP::MasterDSP *>(dsp)->setWebLPF(freq);
}

void set_force_mute(void *dsp, int mute) {
  if (dsp)
    static_cast<AngollaDSP::MasterDSP *>(dsp)->setForceMute(mute != 0);
}

void process_monitor_audio(void *dsp, float *buffer, int numFrames,
                           int inSampleRate) {
  if (dsp)
    static_cast<AngollaDSP::MasterDSP *>(dsp)->processMonitorBuffer(
        buffer, numFrames, inSampleRate);
}

} // extern "C"
