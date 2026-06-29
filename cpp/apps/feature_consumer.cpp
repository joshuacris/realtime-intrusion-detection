#include "messaging/kafka_consumer.hpp"
#include "messaging/kafka_producer.hpp"
#include "flow/feature_schema.hpp"
#include "observability/metrics.hpp"

#include <prometheus/counter.h>
#include <nlohmann/json.hpp>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>

using namespace ids;

// Flipped from a signal handler so the loop finishes the current message and
// shuts down cleanly. std::atomic makes the cross-context access safe.
static std::atomic<bool> g_running{true};
static void handle_signal(int) { g_running = false; }

int main() {
    const char* env{std::getenv("KAFKA_BROKERS")};
    const std::string brokers{env ? env : "localhost:9092"};

    std::signal(SIGINT,  handle_signal);
    std::signal(SIGTERM, handle_signal);

    KafkaConsumer consumer{brokers, "feature-consumer", "raw-flows"};
    KafkaProducer producer{brokers, "model-ready-features"};

    Metrics metrics{"0.0.0.0:9102"};
    auto& flows_ingested = prometheus::BuildCounter()
        .Name("ids_flows_ingested_total").Help("flows encoded to model-ready features")
        .Register(*metrics.registry).Add({});

    printf("feature_consumer: reading raw-flows -> model-ready-features "
           "(broker %s)\n", brokers.c_str());

    long processed{0}, errors{0};
    // Throughput is measured between the first and last processed message, so
    // trailing idle time doesn't dilute the rate.
    using clk = std::chrono::steady_clock;
    clk::time_point t_first, t_last;

    while (g_running) {
        auto raw = consumer.poll(500);
        if (!raw) continue;

        try {
            nlohmann::json flow = nlohmann::json::parse(*raw);
            const std::vector<double> feats{schema::to_feature_vector(flow)};

            // Keep the 5-tuple for tracing/alerts alongside the feature vector.
            nlohmann::json out;
            out["srcip"]    = flow.value("srcip", "");
            out["sport"]    = flow.value("sport", 0);
            out["dstip"]    = flow.value("dstip", "");
            out["dsport"]   = flow.value("dsport", 0);
            out["proto"]    = flow.value("proto", "");
            out["features"] = feats;

            producer.send(out["srcip"].get<std::string>(), out.dump());
            processed++;
            flows_ingested.Increment();

            const auto now = clk::now();
            if (processed == 1) t_first = now;
            t_last = now;
            if (processed % 5000 == 0) {
                const double s{std::chrono::duration<double>(t_last - t_first).count()};
                printf("  processed %ld (%.0f msg/s)\n",
                       processed, s > 0 ? processed / s : 0.0);
            }
        } catch (const std::exception& e) {
            errors++;
            fprintf(stderr, "skip bad message: %s\n", e.what());
        }
    }

    const double active_s{(processed > 0)
        ? std::chrono::duration<double>(t_last - t_first).count() : 0.0};
    printf("\nshutting down: processed %ld, errors %ld\n", processed, errors);
    if (active_s > 0)
        printf("sustained: %.3fs active = %.0f msg/s\n", active_s, processed / active_s);
    producer.flush();
    consumer.close();
    printf("kafka delivered: %llu  failed: %llu\n",
           static_cast<unsigned long long>(producer.delivered()),
           static_cast<unsigned long long>(producer.failed()));
    return 0;
}
