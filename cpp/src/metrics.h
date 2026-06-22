#pragma once

#include <prometheus/exposer.h>
#include <prometheus/registry.h>
#include <cstdlib>
#include <memory>
#include <string>

// ===================================================================
// Metrics — starts a Prometheus /metrics HTTP endpoint and holds the registry.
//
// Prometheus uses a PULL model: this runs a tiny embedded HTTP server (via the
// prometheus-cpp "pull" library) that serves the current metric values at
// http://<addr>/metrics; the Prometheus server scrapes it every few seconds.
//
// Keep one Metrics alive for the whole service. Build counters/histograms on
// `.registry` and bump them from the code; the exposer serves them in the
// background. Bind address comes from METRICS_ADDR env (default supplied).
// ===================================================================
struct Metrics {
    prometheus::Exposer exposer;
    std::shared_ptr<prometheus::Registry> registry;

    explicit Metrics(const std::string& default_addr)
        : exposer(std::getenv("METRICS_ADDR") ? std::getenv("METRICS_ADDR")
                                              : default_addr),
          registry(std::make_shared<prometheus::Registry>()) {
        exposer.RegisterCollectable(registry);
    }
};