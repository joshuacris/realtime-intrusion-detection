#include "messaging/kafka_consumer.hpp"
#include "messaging/kafka_producer.hpp"
#include "model/onnx_model.hpp"
#include "dedup/redis_dedup.hpp"
#include "observability/metrics.hpp"
#include "observability/logging.hpp"

#include <prometheus/counter.h>
#include <prometheus/histogram.h>
#include <nlohmann/json.hpp>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <vector>

using namespace ids;

static std::atomic<bool> g_running{true};
static void handle_signal(int) { g_running = false; }

// Decision threshold: env THRESHOLD > models/threshold.txt > default 0.69.
static double load_threshold() {
    if (const char* e = std::getenv("THRESHOLD")) return std::atof(e);
    std::ifstream f{"models/threshold.txt"};
    double t;
    if (f >> t) return t;
    return 0.69;
}

int main() {
    const char* be{std::getenv("KAFKA_BROKERS")};
    const std::string brokers{be ? be : "localhost:9092"};
    const char* mp{std::getenv("MODEL_PATH")};
    const std::string model_path{mp ? mp : "models/xgboost_intrusion.onnx"};
    const double threshold{load_threshold()};

    std::signal(SIGINT,  handle_signal);
    std::signal(SIGTERM, handle_signal);

    const char* rh{std::getenv("REDIS_HOST")};
    const std::string redis_host{rh ? rh : "localhost"};
    const int redis_port{std::getenv("REDIS_PORT")
                         ? std::atoi(std::getenv("REDIS_PORT")) : 6379};

    OnnxModel model{model_path};
    KafkaConsumer consumer{brokers, "inference-server", "model-ready-features"};
    KafkaProducer producer{brokers, "scored-flows"};
    RedisDedup dedup{redis_host, redis_port, 60};
    printf("inference_server: model-ready-features -> scored-flows "
           "(model %s, threshold %.2f, dedup %s)\n",
           model_path.c_str(), threshold,
           dedup.enabled() ? "on" : "OFF (redis unavailable, fail-open)");

    constexpr std::size_t BATCH{64};
    std::vector<float> feats;            // flat [count*58] feature buffer
    std::vector<nlohmann::json> metas;   // per-row 5-tuple metadata
    feats.reserve(BATCH * OnnxModel::FEATURES);
    metas.reserve(BATCH);

    long processed{0}, alerts{0}, fired{0}, suppressed{0}, errors{0};

    JsonLogger logger;

    Metrics metrics{"0.0.0.0:9103"};
    auto& scored_total = prometheus::BuildCounter()
        .Name("ids_scored_total").Help("flows scored")
        .Register(*metrics.registry).Add({});
    auto& fired_total = prometheus::BuildCounter()
        .Name("ids_alerts_fired_total").Help("novel alerts emitted (post-dedup)")
        .Register(*metrics.registry).Add({});
    auto& suppressed_total = prometheus::BuildCounter()
        .Name("ids_alerts_suppressed_total").Help("duplicate alerts suppressed")
        .Register(*metrics.registry).Add({});
    auto& latency = prometheus::BuildHistogram()
        .Name("ids_inference_latency_seconds").Help("per-flow inference latency")
        .Register(*metrics.registry)
        .Add({}, prometheus::Histogram::BucketBoundaries{
            1e-6, 5e-6, 1e-5, 2.5e-5, 5e-5, 1e-4, 2.5e-4, 5e-4, 1e-3, 5e-3});

    // Score the accumulated batch, publish a verdict per row, then clear.
    auto flush = [&]() {
        if (metas.empty()) return;
        const std::size_t n{metas.size()};

        const auto t0 = std::chrono::steady_clock::now();
        const std::vector<float> probs = model.predict(feats, n);
        const auto t1 = std::chrono::steady_clock::now();
        const long per_us{std::chrono::duration_cast<std::chrono::microseconds>(
                              t1 - t0).count() / static_cast<long>(n)};

        for (std::size_t i = 0; i < n; ++i) {
            const int label{probs[i] >= threshold ? 1 : 0};
            nlohmann::json& m{metas[i]};

            // Attacks dedup on (src,dst,proto): first in the 60s window fires,
            // repeats are suppressed.
            bool alert{false};
            if (label == 1) {
                alerts++;
                const std::string key{"alert:" + m.value("srcip", std::string(""))
                                      + ":" + m.value("dstip", std::string(""))
                                      + ":" + m.value("proto", std::string(""))};
                alert = dedup.is_new_alert(key);
                if (alert) fired++; else suppressed++;
            }

            m["attack_prob"] = probs[i];
            m["label"]       = label;
            m["alert"]       = alert;
            m["latency_us"]  = per_us;
            producer.send(m.value("srcip", std::string("")), m.dump());
            processed++;

            scored_total.Increment();
            latency.Observe(per_us / 1e6);
            if (label == 1) (alert ? fired_total : suppressed_total).Increment();

            logger.log({
                {"flow_id", m.value("srcip", std::string("")) + ":"
                          + std::to_string(m.value("sport", 0)) + "->"
                          + m.value("dstip", std::string("")) + ":"
                          + std::to_string(m.value("dsport", 0)) + "/"
                          + m.value("proto", std::string(""))},
                {"prediction", label},
                {"confidence", probs[i]},
                {"alert",      alert},
                {"latency_us", per_us},
            });
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
           static_cast<unsigned long long>(producer.delivered()),
           static_cast<unsigned long long>(producer.failed()));
    return 0;
}
