#pragma once

#include "packet.h"
#include "flow.h"
#include <unordered_map>
#include <functional>
#include <cstdint>

// A type alias (C++'s `typedef`). Saves us writing the long map type
// everywhere and gives it a readable name.
using FlowMap = std::unordered_map<FlowKey, FlowState, FlowKeyHash>;

// Called once for each COMPLETED flow. The aggregator stays ignorant of what
// happens next (print? JSON? Kafka?) — it just hands the finished flow to this
// sink. Same callback pattern as read_pcap.
using FlowSink = std::function<void(const FlowKey&, const FlowState&)>;

// ===================================================================
// FlowAggregator — consumes packets, groups them into flows, and emits each
// flow to the sink once it terminates (TCP FIN/RST) or goes idle (timeout).
// ===================================================================
class FlowAggregator {
public:
    // `explicit` stops the compiler from silently converting a FlowSink into a
    // FlowAggregator behind your back (good hygiene for single-arg constructors).
    // idle_timeout_us: a flow with no packets for this long is considered ended.
    explicit FlowAggregator(FlowSink sink,
                            uint64_t idle_timeout_us = 60000000ULL /* 60 s */);

    // Feed one parsed packet in. May emit zero or more completed flows.
    void add_packet(const Packet& p);

    // Emit every flow still open at end-of-stream. Call once after the last
    // packet (a pcap file ends; a live stream never would).
    void flush();

    // How many flows are still in progress (not yet emitted).
    std::size_t flow_count() const { return flows_.size(); }

private:
    void emit(const FlowKey& key, const FlowState& st);  // hand a flow to the sink
    void sweep_idle(uint64_t now_us);                    // expire idle flows

    FlowMap   flows_;
    FlowSink  sink_;
    uint64_t  idle_timeout_us_;
    uint64_t  now_us_ = 0;             // latest packet timestamp seen
    uint64_t  pkts_since_sweep_ = 0;   // throttles how often we sweep
};
