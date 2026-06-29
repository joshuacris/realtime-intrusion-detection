#pragma once

#include "net/packet.hpp"
#include "flow/flow.hpp"
#include <unordered_map>
#include <functional>
#include <cstdint>

namespace ids {

using FlowMap = std::unordered_map<FlowKey, FlowState, FlowKeyHash>;

// Called once per completed flow. The aggregator stays ignorant of what happens
// next (print / JSON / Kafka) — it just hands the finished flow to this sink.
using FlowSink = std::function<void(const FlowKey&, const FlowState&)>;

// Groups packets into flows and emits each one when it terminates (TCP FIN/RST)
// or goes idle (timeout).
class FlowAggregator {
public:
    explicit FlowAggregator(FlowSink sink,
                            uint64_t idle_timeout_us = 60000000ULL);

    void add_packet(const Packet& p);

    // Emit every flow still open at end-of-stream. Call once after the last packet.
    void flush();

    std::size_t flow_count() const { return flows_.size(); }

private:
    void emit(const FlowKey& key, const FlowState& st);
    void sweep_idle(uint64_t now_us);

    FlowMap   flows_;
    FlowSink  sink_;
    uint64_t  idle_timeout_us_;
    uint64_t  now_us_{0};
    uint64_t  pkts_since_sweep_{0};
};

}  // namespace ids
