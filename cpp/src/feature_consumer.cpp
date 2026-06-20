#include "kafka_consumer.h"
#include "kafka_producer.h"
#include "feature_schema.h"

#include <nlohmann/json.hpp>
#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstdlib>

// A service runs forever. We flip this flag from a signal handler so the main
// loop can finish the current message and shut down cleanly. std::atomic makes
// the cross-context write/read safe; sig_atomic-style flag is the standard idiom.
static std::atomic<bool> g_running{true};
static void handle_signal(int) { g_running = false; }

int main() {
    // Config from the environment (12-factor; same pattern as the extractor).
    const char* env = std::getenv("KAFKA_BROKERS");
    const std::string brokers = env ? env : "localhost:9092";

    // Ctrl-C (SIGINT) and `docker stop` (SIGTERM) -> graceful shutdown.
    std::signal(SIGINT,  handle_signal);
    std::signal(SIGTERM, handle_signal);

    KafkaConsumer consumer(brokers, "feature-consumer", "raw-flows");
    KafkaProducer producer(brokers, "model-ready-features");

    printf("feature_consumer: reading raw-flows -> model-ready-features "
           "(broker %s)\n", brokers.c_str());

    long processed = 0, errors = 0;
    while (g_running) {
        // Wait up to 500ms for the next flow. nullopt = nothing right now;
        // loop again (and re-check g_running so Ctrl-C is responsive).
        auto raw = consumer.poll(500);
        if (!raw) continue;

        try {
            nlohmann::json flow = nlohmann::json::parse(*raw);
            std::vector<double> feats = schema::to_feature_vector(flow);

            // Build the inference request: keep the 5-tuple for tracing/alerts,
            // plus the model-ready feature vector.
            nlohmann::json out;
            out["srcip"]    = flow.value("srcip", "");
            out["sport"]    = flow.value("sport", 0);
            out["dstip"]    = flow.value("dstip", "");
            out["dsport"]   = flow.value("dsport", 0);
            out["proto"]    = flow.value("proto", "");
            out["features"] = feats;

            // Key by source IP (same partitioning choice as the extractor).
            producer.send(out["srcip"].get<std::string>(), out.dump());
            processed++;
            if (processed % 5000 == 0)
                printf("  processed %ld flows...\n", processed);
        } catch (const std::exception& e) {
            // A malformed message shouldn't kill the service — skip and count.
            errors++;
            fprintf(stderr, "skip bad message: %s\n", e.what());
        }
    }

    printf("\nshutting down: processed %ld, errors %ld\n", processed, errors);
    producer.flush();   // make sure queued outputs are delivered
    consumer.close();   // commit final offsets, leave the group
    printf("kafka delivered: %llu  failed: %llu\n",
           (unsigned long long)producer.delivered(),
           (unsigned long long)producer.failed());
    return 0;
}