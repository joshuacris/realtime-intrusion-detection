#include "kafka_consumer.h"
#include "kafka_producer.h"
#include "onnx_model.h"
#include "redis_dedup.h"

#include <nlohmann/json.hpp>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <vector>

static std::atomic<bool> g_running{true};
static void handle_signal(int) { g_running = false; }

// Decision threshold: env THRESHOLD > models/threshold.txt > default 0.69.
static double load_threshold() {
    if (const char* e = std::getenv("THRESHOLD")) return std::atof(e);
    std::ifstream f("models/threshold.txt");
    double t;
    if (f >> t) return t;
    return 0.69;
}

int main() {
    const char* be = std::getenv("KAFKA_BROKERS");
    const std::string brokers = be ? be : "localhost:9092";
    const char* mp = std::getenv("MODEL_PATH");
    const std::string model_path = mp ? mp : "models/xgboost_intrusion.onnx";
    const double threshold = load_threshold();

    std::signal(SIGINT,  handle_signal);
    std::signal(SIGTERM, handle_signal);

    // Redis dedup config (12-factor env, default localhost:6379, 60s window).
    const char* rh = std::getenv("REDIS_HOST");
    const std::string redis_host = rh ? rh : "localhost";
    const int redis_port = std::getenv("REDIS_PORT")
                         ? std::atoi(std::getenv("REDIS_PORT")) : 6379;

    OnnxModel model(model_path);
    KafkaConsumer consumer(brokers, "inference-server", "model-ready-features");
    KafkaProducer producer(brokers, "scored-flows");
    RedisDedup dedup(redis_host, redis_port, 60 /* seconds */);
    printf("inference_server: model-ready-features -> scored-flows "
           "(model %s, threshold %.2f, dedup %s)\n",
           model_path.c_str(), threshold,
           dedup.enabled() ? "on" : "OFF (redis unavailable, fail-open)");

    constexpr std::size_t BATCH = 64;
    std::vector<float> feats;              // flat [count*58] feature buffer
    std::vector<nlohmann::json> metas;     // per-row 5-tuple metadata
    feats.reserve(BATCH * OnnxModel::FEATURES);
    metas.reserve(BATCH);

    long processed = 0, alerts = 0, fired = 0, suppressed = 0, errors = 0;

    // Score the accumulated batch, publish a verdict per row, then clear.
    auto flush = [&]() {
        if (metas.empty()) return;
        const std::size_t n = metas.size();

        auto t0 = std::chrono::steady_clock::now();
        std::vector<float> probs = model.predict(feats, n);
        auto t1 = std::chrono::steady_clock::now();
        long per_us = std::chrono::duration_cast<std::chrono::microseconds>(
                          t1 - t0).count() / static_cast<long>(n);

        for (std::size_t i = 0; i < n; ++i) {
            const int label = probs[i] >= threshold ? 1 : 0;
            nlohmann::json& m = metas[i];

            // For attacks, dedup on (src,dst,proto): first in the 60s window
            // fires (alert=true); repeats are suppressed (alert=false).
            bool alert = false;
            if (label == 1) {
                alerts++;
                const std::string key = "alert:" + m.value("srcip", std::string(""))
                                      + ":" + m.value("dstip", std::string(""))
                                      + ":" + m.value("proto", std::string(""));
                alert = dedup.is_new_alert(key);
                if (alert) fired++; else suppressed++;
            }

            m["attack_prob"] = probs[i];
            m["label"]       = label;
            m["alert"]       = alert;   // true only for NOVEL attacks (post-dedup)
            m["latency_us"]  = per_us;
            producer.send(m.value("srcip", std::string("")), m.dump());
            processed++;
        }
        feats.clear();
        metas.clear();
    };

    while (g_running) {
        auto raw = consumer.poll(100);
        if (!raw) { flush(); continue; }   // idle: flush partial batch (bounds latency)

        try {
            nlohmann::json in = nlohmann::json::parse(*raw);
            const auto& f = in.at("features");
            if (f.size() != OnnxModel::FEATURES) { errors++; continue; }
            for (const auto& v : f) feats.push_back(v.get<float>());

            nlohmann::json meta;
            meta["srcip"]  = in.value("srcip", std::string(""));
            meta["sport"]  = in.value("sport", 0);
            meta["dstip"]  = in.value("dstip", std::string(""));
            meta["dsport"] = in.value("dsport", 0);
            meta["proto"]  = in.value("proto", std::string(""));
            metas.push_back(std::move(meta));

            if (metas.size() >= BATCH) flush();
        } catch (const std::exception& e) {
            errors++;
            fprintf(stderr, "skip bad message: %s\n", e.what());
        }
    }

    flush();
    producer.flush();
    consumer.close();
    printf("\nshutting down: scored %ld, attacks %ld "
           "(fired %ld, suppressed %ld by dedup), errors %ld\n",
           processed, alerts, fired, suppressed, errors);
    printf("kafka delivered: %llu  failed: %llu\n",
           (unsigned long long)producer.delivered(),
           (unsigned long long)producer.failed());
    return 0;
}