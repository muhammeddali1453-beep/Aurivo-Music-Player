#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

struct SubtitleCue {
    int64_t start_ms{0};
    int64_t end_ms{0};
    std::string text;
};

class SubtitleEngine {
public:
    SubtitleEngine() = default;

    // Load/replace a language track.
    // lang_key can be "tr", "en", "ar", "turkce", "ingilizce", etc.
    void load_language(const std::string& lang_key, const std::string& file_path);

    // Set active language.
    void set_active_language(const std::string& lang_key);

    // Convenience: set active language by file path (auto-key inferred from filename).
    void set_active_by_path(const std::string& file_path);

    // Get current subtitle text for the active language at time.
    // Returns empty string if no subtitle should be shown.
    std::string get_text_ms(int64_t position_ms);
    std::string get_text_seconds(double seconds);

    // Active track stats (for UI/debug)
    int active_cue_count() const;
    int64_t active_end_ms() const;

    // Introspection / management
    std::vector<std::string> available_languages() const;
    std::string active_language() const;
    void clear();

private:
    struct Track {
        std::vector<SubtitleCue> cues;
        std::vector<int64_t> starts;
        int last_index{0};
        int64_t last_ms{-1};
    };

    std::unordered_map<std::string, Track> tracks_;
    std::string active_lang_;

    static std::string normalize_lang_key(std::string key);
    static std::string infer_lang_key_from_path(const std::string& file_path);

    static Track parse_file(const std::string& file_path);
    static Track parse_srt(const std::string& content);
    static Track parse_vtt(const std::string& content);

    static bool parse_time_to_ms_srt_like(const std::string& ts, int64_t* out_ms);
    static bool parse_time_to_ms_vtt_like(const std::string& ts, int64_t* out_ms);

    static std::string read_text_file_utf8(const std::string& file_path);

    static std::string trim(const std::string& s);
    static std::vector<std::string> split_lines(const std::string& s);
    static std::vector<std::string> split_blocks_blankline(const std::string& s);

    static std::string join_text_lines(const std::vector<std::string>& lines, size_t start_index);

    static std::string to_lower_ascii(std::string s);

    std::string get_text_ms_for_track(Track& t, int64_t position_ms);
};
