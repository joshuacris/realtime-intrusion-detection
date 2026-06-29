#pragma once

#include <nlohmann/json.hpp>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>

namespace ids {

// Structured logging: one compact JSON object per line, to LOG_FILE (env) else
// stderr. Keeping machine-parseable events off stdout means the human summaries
// (printf) and the log don't mix. Each record gets a `ts_ms` timestamp.
class JsonLogger {
public:
    JsonLogger() {
        if (const char* p = std::getenv("LOG_FILE")) {
            out_ = std::fopen(p, "a");
            owned_ = (out_ != nullptr);
        }
        if (!out_) out_ = stderr;
    }
    ~JsonLogger() { if (owned_ && out_) std::fclose(out_); }

    void log(nlohmann::json j) {
        j["ts_ms"] = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        const std::string s{j.dump()};
        std::fprintf(out_, "%s\n", s.c_str());
    }

private:
    std::FILE* out_{nullptr};
    bool       owned_{false};
};

}  // namespace ids
