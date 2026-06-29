#pragma once

#include <prometheus/exposer.h>
#include <prometheus/registry.h>
#include <cstdlib>
#include <memory>
#include <string>

namespace ids {

// Runs an embedded /metrics HTTP endpoint (prometheus-cpp "pull") and holds the
// registry. Keep one alive for the whole service; build counters/histograms on
// `.registry` and the exposer serves them. Bind address: METRICS_ADDR env, else
// the supplied default.
struct Metrics {
    prometheus::Exposer exposer;
    std::shared_ptr<prometheus::Registry> registry;

    explicit Metrics(const std::string& default_addr)
        : exposer{std::getenv("METRICS_ADDR") ? std::getenv("METRICS_ADDR")
                                              : default_addr},
          registry{std::make_shared<prometheus::Registry>()} {
        exposer.RegisterCollectable(registry);
    }
};

}  // namespace ids
