// Standalone inference benchmark — isolates ONNX Run() from the Kafka path.
//
// Usage: bench_inference [model.onnx] [batch] [iters] [features.jsonl]
//   features.jsonl: optional file of {"features":[...58...]} lines (real inputs);
//   if omitted, a single synthetic vector is used.
//
// Reports throughput (flows/sec) and per-batch / per-flow latency percentiles.
#include "onnx_model.h"

#include <nlohmann/json.hpp>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

int main(int argc, char** argv) {
    const std::string model = argc > 1 ? argv[1] : "models/xgboost_intrusion.onnx";
    const std::size_t batch = argc > 2 ? std::strtoul(argv[2], nullptr, 10) : 64;
    const std::size_t iters = argc > 3 ? std::strtoul(argv[3], nullptr, 10) : 5000;
    const std::string feat_file = argc > 4 ? argv[4] : "";

    OnnxModel m(model);

    // Pool of real feature vectors (cycled to fill batches).
    std::vector<std::vector<float>> pool;
    if (!feat_file.empty()) {
        std::ifstream f(feat_file);
        std::string line;
        while (std::getline(f, line)) {
            if (line.empty()) continue;
            auto j = nlohmann::json::parse(line, nullptr, false);
            if (j.is_discarded() || !j.contains("features")) continue;
            std::vector<float> v;
            for (const auto& x : j["features"]) v.push_back(x.get<float>());
            if (v.size() == OnnxModel::FEATURES) pool.push_back(std::move(v));
        }
    }
    if (pool.empty()) {                       // fallback: one synthetic flow
        std::vector<float> v(OnnxModel::FEATURES, 0.0f);
        v[4] = 1;        // proto_tcp
        v[7 + 4] = 1;    // service_http
        v[16 + 1] = 1;   // state_FIN
        pool.push_back(v);
    }
    printf("model=%s batch=%zu iters=%zu pool=%zu\n",
           model.c_str(), batch, iters, pool.size());

    // Pack `batch` vectors from the pool into a flat buffer starting at `start`.
    std::vector<float> flat(batch * OnnxModel::FEATURES);
    auto fill = [&](std::size_t start) {
        for (std::size_t i = 0; i < batch; ++i) {
            const auto& v = pool[(start + i) % pool.size()];
            std::copy(v.begin(), v.end(),
                      flat.begin() + i * OnnxModel::FEATURES);
        }
    };

    fill(0);
    for (int w = 0; w < 50; ++w) m.predict(flat, batch);   // warm up

    std::vector<long> lat;
    lat.reserve(iters);
    auto t0 = std::chrono::steady_clock::now();
    for (std::size_t it = 0; it < iters; ++it) {
        fill(it * batch);                      // refresh inputs OUTSIDE timing
        auto a = std::chrono::steady_clock::now();
        auto out = m.predict(flat, batch);
        auto b = std::chrono::steady_clock::now();
        lat.push_back(std::chrono::duration_cast<std::chrono::microseconds>(
                          b - a).count());
        if (out.empty()) return 1;             // stop the optimizer eliding the call
    }
    auto t1 = std::chrono::steady_clock::now();

    const double total_s = std::chrono::duration<double>(t1 - t0).count();
    const std::size_t flows = batch * iters;
    std::sort(lat.begin(), lat.end());
    auto pct = [&](double p) { return lat[static_cast<std::size_t>(p * (lat.size() - 1))]; };

    printf("throughput: %.0f flows/s  (%zu flows in %.3fs)\n",
           flows / total_s, flows, total_s);
    printf("per-batch latency us: p50=%ld p99=%ld max=%ld\n",
           pct(0.50), pct(0.99), lat.back());
    printf("per-flow  latency us: p50=%.3f p99=%.3f\n",
           static_cast<double>(pct(0.50)) / batch,
           static_cast<double>(pct(0.99)) / batch);
    return 0;
}