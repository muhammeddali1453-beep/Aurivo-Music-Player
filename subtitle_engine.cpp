#include "subtitle_engine.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <stdexcept>

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

namespace py = pybind11;

static bool ends_with_ci(const std::string& s, const std::string& suffix) {
    if (s.size() < suffix.size()) return false;
    for (size_t i = 0; i < suffix.size(); i++) {
        char a = static_cast<char>(std::tolower(static_cast<unsigned char>(s[s.size() - suffix.size() + i])));
        char b = static_cast<char>(std::tolower(static_cast<unsigned char>(suffix[i])));
        if (a != b) return false;
    }
    return true;
}

std::string SubtitleEngine::to_lower_ascii(std::string s) {
    for (char& ch : s) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return s;
}

std::string SubtitleEngine::trim(const std::string& s) {
    size_t i = 0;
    while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) i++;
    if (i == s.size()) return "";
    size_t j = s.size() - 1;
    while (j > i && std::isspace(static_cast<unsigned char>(s[j]))) j--;
    return s.substr(i, (j - i) + 1);
}

std::vector<std::string> SubtitleEngine::split_lines(const std::string& s) {
    std::vector<std::string> out;
    std::string line;
    std::istringstream iss(s);
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        out.push_back(line);
    }
    return out;
}

std::vector<std::string> SubtitleEngine::split_blocks_blankline(const std::string& s) {
    std::string norm = s;
    // normalize CRLF
    norm.erase(std::remove(norm.begin(), norm.end(), '\r'), norm.end());

    std::vector<std::string> blocks;
    std::string cur;
    std::istringstream iss(norm);
    std::string line;
    bool last_blank = false;
    while (std::getline(iss, line)) {
        bool blank = trim(line).empty();
        if (blank) {
            if (!cur.empty() && !last_blank) {
                blocks.push_back(trim(cur));
                cur.clear();
            }
            last_blank = true;
            continue;
        }
        last_blank = false;
        cur += line;
        cur += '\n';
    }
    if (!cur.empty()) blocks.push_back(trim(cur));

    std::vector<std::string> out;
    out.reserve(blocks.size());
    for (const auto& b : blocks) {
        if (!trim(b).empty()) out.push_back(trim(b));
    }
    return out;
}

std::string SubtitleEngine::join_text_lines(const std::vector<std::string>& lines, size_t start_index) {
    std::string out;
    for (size_t i = start_index; i < lines.size(); i++) {
        std::string t = trim(lines[i]);
        if (t.empty()) continue;
        if (!out.empty()) out += "\n";
        out += t;
    }
    return trim(out);
}

std::string SubtitleEngine::read_text_file_utf8(const std::string& file_path) {
    std::ifstream f(file_path, std::ios::binary);
    if (!f) {
        throw std::runtime_error("SubtitleEngine: cannot open file: " + file_path);
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    std::string content = ss.str();

    // Drop UTF-8 BOM if present
    if (content.size() >= 3 && static_cast<unsigned char>(content[0]) == 0xEF &&
        static_cast<unsigned char>(content[1]) == 0xBB && static_cast<unsigned char>(content[2]) == 0xBF) {
        content = content.substr(3);
    }
    return content;
}

bool SubtitleEngine::parse_time_to_ms_srt_like(const std::string& ts, int64_t* out_ms) {
    // Expected: HH:MM:SS,mmm (also accept '.' instead of ',')
    std::string t = trim(ts);
    if (t.size() < 8) return false;

    // remove any trailing cue settings (just in case)
    // SRT usually doesn't have, but tolerate spaces.
    size_t sp = t.find(' ');
    if (sp != std::string::npos) t = t.substr(0, sp);

    t = trim(t);
    // replace '.' with ',' to unify
    for (char& c : t) {
        if (c == '.') c = ',';
    }

    // Split H:M:rest
    size_t p1 = t.find(':');
    if (p1 == std::string::npos) return false;
    size_t p2 = t.find(':', p1 + 1);
    if (p2 == std::string::npos) return false;

    std::string hh = t.substr(0, p1);
    std::string mm = t.substr(p1 + 1, p2 - (p1 + 1));
    std::string rest = t.substr(p2 + 1);

    size_t pc = rest.find(',');
    if (pc == std::string::npos) return false;

    std::string ss = rest.substr(0, pc);
    std::string ms = rest.substr(pc + 1);

    if (ms.size() > 3) ms = ms.substr(0, 3);
    while (ms.size() < 3) ms.push_back('0');

    try {
        int64_t H = std::stoll(hh);
        int64_t M = std::stoll(mm);
        int64_t S = std::stoll(ss);
        int64_t MS = std::stoll(ms);
        *out_ms = (H * 3600 + M * 60 + S) * 1000 + MS;
        return true;
    } catch (...) {
        return false;
    }
}

bool SubtitleEngine::parse_time_to_ms_vtt_like(const std::string& ts, int64_t* out_ms) {
    // Expected: HH:MM:SS.mmm OR MM:SS.mmm (accept ',' too)
    std::string t = trim(ts);
    if (t.empty()) return false;

    size_t sp = t.find(' ');
    if (sp != std::string::npos) t = t.substr(0, sp);

    for (char& c : t) {
        if (c == ',') c = '.';
    }

    std::vector<std::string> parts;
    {
        std::string cur;
        for (char c : t) {
            if (c == ':') {
                parts.push_back(cur);
                cur.clear();
            } else {
                cur.push_back(c);
            }
        }
        parts.push_back(cur);
    }

    int64_t H = 0, M = 0, S = 0, MS = 0;

    auto parse_sec_ms = [&](const std::string& s_part) -> bool {
        std::string sp2 = s_part;
        size_t dot = sp2.find('.');
        std::string ss = sp2;
        std::string ms = "000";
        if (dot != std::string::npos) {
            ss = sp2.substr(0, dot);
            ms = sp2.substr(dot + 1);
        }
        if (ms.size() > 3) ms = ms.substr(0, 3);
        while (ms.size() < 3) ms.push_back('0');
        try {
            S = std::stoll(ss);
            MS = std::stoll(ms);
            return true;
        } catch (...) {
            return false;
        }
    };

    try {
        if (parts.size() == 3) {
            H = std::stoll(parts[0]);
            M = std::stoll(parts[1]);
            if (!parse_sec_ms(parts[2])) return false;
        } else if (parts.size() == 2) {
            M = std::stoll(parts[0]);
            if (!parse_sec_ms(parts[1])) return false;
        } else {
            return false;
        }

        *out_ms = (H * 3600 + M * 60 + S) * 1000 + MS;
        return true;
    } catch (...) {
        return false;
    }
}

SubtitleEngine::Track SubtitleEngine::parse_srt(const std::string& content) {
    Track t;
    auto blocks = split_blocks_blankline(content);
    for (const auto& b : blocks) {
        auto lines = split_lines(b);
        std::vector<std::string> nonempty;
        nonempty.reserve(lines.size());
        for (const auto& ln : lines) {
            std::string x = trim(ln);
            if (!x.empty()) nonempty.push_back(x);
        }
        if (nonempty.size() < 2) continue;

        // Find time line (usually line 1, sometimes line 0)
        size_t time_idx = std::string::npos;
        for (size_t i = 0; i < std::min<size_t>(3, nonempty.size()); i++) {
            if (nonempty[i].find("-->") != std::string::npos) {
                time_idx = i;
                break;
            }
        }
        if (time_idx == std::string::npos) continue;

        std::string time_line = nonempty[time_idx];
        size_t arrow = time_line.find("-->");
        if (arrow == std::string::npos) continue;
        std::string left = trim(time_line.substr(0, arrow));
        std::string right = trim(time_line.substr(arrow + 3));

        // right may have extra settings, cut at space
        size_t sp = right.find(' ');
        if (sp != std::string::npos) right = right.substr(0, sp);

        int64_t start_ms = 0, end_ms = 0;
        if (!parse_time_to_ms_srt_like(left, &start_ms)) continue;
        if (!parse_time_to_ms_srt_like(right, &end_ms)) continue;
        if (end_ms <= start_ms) continue;

        std::string text = join_text_lines(nonempty, time_idx + 1);
        if (text.empty()) continue;

        t.cues.push_back({start_ms, end_ms, text});
    }

    std::sort(t.cues.begin(), t.cues.end(), [](const SubtitleCue& a, const SubtitleCue& b) {
        return a.start_ms < b.start_ms;
    });
    t.starts.reserve(t.cues.size());
    for (const auto& c : t.cues) t.starts.push_back(c.start_ms);
    t.last_index = 0;
    t.last_ms = -1;
    return t;
}

SubtitleEngine::Track SubtitleEngine::parse_vtt(const std::string& content) {
    Track t;

    std::string norm = content;
    norm.erase(std::remove(norm.begin(), norm.end(), '\r'), norm.end());

    // Drop header line "WEBVTT" and anything until first blank line if present
    auto lines = split_lines(norm);
    size_t start_line = 0;
    if (!lines.empty()) {
        std::string h = trim(lines[0]);
        if (to_lower_ascii(h).rfind("webvtt", 0) == 0) {
            start_line = 1;
            // skip optional header metadata until blank line
            while (start_line < lines.size() && !trim(lines[start_line]).empty()) start_line++;
            while (start_line < lines.size() && trim(lines[start_line]).empty()) start_line++;
        }
    }

    std::string rest;
    for (size_t i = start_line; i < lines.size(); i++) {
        rest += lines[i];
        rest += '\n';
    }

    auto blocks = split_blocks_blankline(rest);
    for (const auto& b : blocks) {
        auto b_lines_raw = split_lines(b);
        std::vector<std::string> b_lines;
        b_lines.reserve(b_lines_raw.size());
        for (const auto& ln : b_lines_raw) {
            std::string x = trim(ln);
            if (!x.empty()) b_lines.push_back(x);
        }
        if (b_lines.empty()) continue;
        if (to_lower_ascii(b_lines[0]).rfind("note", 0) == 0) continue;

        // Find time line
        size_t time_idx = std::string::npos;
        for (size_t i = 0; i < std::min<size_t>(3, b_lines.size()); i++) {
            if (b_lines[i].find("-->") != std::string::npos) {
                time_idx = i;
                break;
            }
        }
        if (time_idx == std::string::npos) continue;

        std::string time_line = b_lines[time_idx];
        size_t arrow = time_line.find("-->");
        if (arrow == std::string::npos) continue;

        std::string left = trim(time_line.substr(0, arrow));
        std::string right = trim(time_line.substr(arrow + 3));
        // right can include cue settings after space
        size_t sp = right.find(' ');
        if (sp != std::string::npos) right = right.substr(0, sp);

        int64_t start_ms = 0, end_ms = 0;
        if (!parse_time_to_ms_vtt_like(left, &start_ms)) continue;
        if (!parse_time_to_ms_vtt_like(right, &end_ms)) continue;
        if (end_ms <= start_ms) continue;

        std::string text = join_text_lines(b_lines, time_idx + 1);
        if (text.empty()) continue;

        t.cues.push_back({start_ms, end_ms, text});
    }

    std::sort(t.cues.begin(), t.cues.end(), [](const SubtitleCue& a, const SubtitleCue& b) {
        return a.start_ms < b.start_ms;
    });
    t.starts.reserve(t.cues.size());
    for (const auto& c : t.cues) t.starts.push_back(c.start_ms);
    t.last_index = 0;
    t.last_ms = -1;
    return t;
}

SubtitleEngine::Track SubtitleEngine::parse_file(const std::string& file_path) {
    std::string content = read_text_file_utf8(file_path);
    if (ends_with_ci(file_path, ".vtt")) {
        return parse_vtt(content);
    }
    // default SRT
    return parse_srt(content);
}

std::string SubtitleEngine::normalize_lang_key(std::string key) {
    key = trim(key);
    key = to_lower_ascii(key);
    if (key == "turkish") key = "turkce";
    if (key == "english") key = "ingilizce";
    if (key == "arabic") key = "arapca";
    return key;
}

std::string SubtitleEngine::infer_lang_key_from_path(const std::string& file_path) {
    // heuristics: videoName.<key>.vtt or <key>.vtt etc.
    std::string fp = file_path;
    // basename
    size_t slash = fp.find_last_of("/\\");
    std::string base = (slash == std::string::npos) ? fp : fp.substr(slash + 1);
    // drop ext
    size_t dot = base.find_last_of('.');
    std::string no_ext = (dot == std::string::npos) ? base : base.substr(0, dot);

    // if has another dot, take suffix as key
    size_t dot2 = no_ext.find_last_of('.');
    std::string key = (dot2 == std::string::npos) ? no_ext : no_ext.substr(dot2 + 1);
    key = normalize_lang_key(key);

    // map common short keys
    if (key == "tr") return "turkce";
    if (key == "en") return "ingilizce";
    if (key == "ar") return "arapca";
    return key;
}

void SubtitleEngine::load_language(const std::string& lang_key, const std::string& file_path) {
    std::string k = normalize_lang_key(lang_key);
    if (k.empty()) {
        k = infer_lang_key_from_path(file_path);
        if (k.empty()) k = "default";
    }
    Track t = parse_file(file_path);
    tracks_[k] = std::move(t);
    if (active_lang_.empty()) active_lang_ = k;
}

void SubtitleEngine::set_active_language(const std::string& lang_key) {
    std::string k = normalize_lang_key(lang_key);
    if (k.empty()) return;
    if (tracks_.find(k) == tracks_.end()) return;
    active_lang_ = k;
}

void SubtitleEngine::set_active_by_path(const std::string& file_path) {
    std::string k = infer_lang_key_from_path(file_path);
    set_active_language(k);
}

std::vector<std::string> SubtitleEngine::available_languages() const {
    std::vector<std::string> out;
    out.reserve(tracks_.size());
    for (const auto& kv : tracks_) out.push_back(kv.first);
    std::sort(out.begin(), out.end());
    return out;
}

std::string SubtitleEngine::active_language() const { return active_lang_; }

void SubtitleEngine::clear() {
    tracks_.clear();
    active_lang_.clear();
}

std::string SubtitleEngine::get_text_ms_for_track(Track& t, int64_t position_ms) {
    if (t.cues.empty()) return "";

    // fast path: sequential playback
    int idx = t.last_index;
    if (idx < 0) idx = 0;
    if (idx >= static_cast<int>(t.cues.size())) idx = static_cast<int>(t.cues.size()) - 1;

    // If time moves backwards or jumps, use binary search
    bool need_search = (t.last_ms < 0) || (position_ms < t.last_ms - 2000) || (position_ms > t.last_ms + 5000);

    if (need_search) {
        auto it = std::upper_bound(t.starts.begin(), t.starts.end(), position_ms);
        if (it == t.starts.begin()) {
            idx = 0;
        } else {
            idx = static_cast<int>((it - t.starts.begin()) - 1);
        }
    } else {
        // small steps: adjust around last index
        while (idx > 0 && position_ms < t.cues[idx].start_ms) idx--;
        while (idx < static_cast<int>(t.cues.size()) - 1 && position_ms > t.cues[idx].end_ms) idx++;
    }

    t.last_index = idx;
    t.last_ms = position_ms;

    const auto& c = t.cues[idx];
    if (c.start_ms <= position_ms && position_ms <= c.end_ms) return c.text;
    return "";
}

std::string SubtitleEngine::get_text_ms(int64_t position_ms) {
    if (active_lang_.empty()) return "";
    auto it = tracks_.find(active_lang_);
    if (it == tracks_.end()) return "";
    return get_text_ms_for_track(it->second, position_ms);
}

std::string SubtitleEngine::get_text_seconds(double seconds) {
    if (seconds < 0) seconds = 0;
    int64_t ms = static_cast<int64_t>(seconds * 1000.0);
    return get_text_ms(ms);
}

int SubtitleEngine::active_cue_count() const {
    if (active_lang_.empty()) return 0;
    auto it = tracks_.find(active_lang_);
    if (it == tracks_.end()) return 0;
    return static_cast<int>(it->second.cues.size());
}

int64_t SubtitleEngine::active_end_ms() const {
    if (active_lang_.empty()) return 0;
    auto it = tracks_.find(active_lang_);
    if (it == tracks_.end()) return 0;
    if (it->second.cues.empty()) return 0;
    return it->second.cues.back().end_ms;
}

PYBIND11_MODULE(subtitle_engine, m) {
    m.doc() = "Aurivo Subtitle Engine (C++ backend, SRT/VTT, multi-language)";

    py::class_<SubtitleEngine>(m, "SubtitleEngine")
        .def(py::init<>())
        .def("load_language", &SubtitleEngine::load_language, py::arg("lang_key"), py::arg("file_path"))
        .def("set_active_language", &SubtitleEngine::set_active_language, py::arg("lang_key"))
        .def("set_active_by_path", &SubtitleEngine::set_active_by_path, py::arg("file_path"))
        .def("get_text_ms", &SubtitleEngine::get_text_ms, py::arg("position_ms"))
        .def("get_text_seconds", &SubtitleEngine::get_text_seconds, py::arg("seconds"))
        .def("active_cue_count", &SubtitleEngine::active_cue_count)
        .def("active_end_ms", &SubtitleEngine::active_end_ms)
        .def("available_languages", &SubtitleEngine::available_languages)
        .def("active_language", &SubtitleEngine::active_language)
        .def("clear", &SubtitleEngine::clear);
}
