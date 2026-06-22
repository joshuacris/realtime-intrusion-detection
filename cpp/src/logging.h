#pragma once

#include <nlohmann/json.hpp>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>

// ===================================================================
// JsonLogger — structured logging: one compact JSON object per line.
//
// Writes to the file named by LOG_FILE (env), else stderr. Keeping these
// machine-parseable event lines OFF stdout means the human summaries (printf)
// and the structured log don't mix, and the log can be grepped / piped to jq /
// shipped to a log system. Each record gets a `ts_ms` epoch-millis timestamp.
// ===================================================================
class JsonLogger {
public:
    JsonLogger() {
        if (const char* p = std::getenv("LOG_FILE")) {
            out_ = std::fopen(p, "a");      // append
            owned_ = (out_ != nullptr);
        }
        if (!out_) out_ = stderr;           // fallback
    }
    ~JsonLogger() { if (owned_ && out_) std::fclose(out_); }

    void log(nlohmann::json j) {
        j["ts_ms"] = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        const std::string s = j.dump();
        std::fprintf(out_, "%s\n", s.c_str());
    }

private:
    std::FILE* out_ = nullptr;
    bool       owned_ = false;
};