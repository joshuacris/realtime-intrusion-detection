#pragma once

#include "packet.h"
#include <cstdint>
#include <cstddef>
#include <functional>   // std::hash

// TCP control-flag bit masks (byte 13 of the TCP header). Used to detect
// connection teardown: RST = abrupt reset, FIN = graceful close.
static constexpr uint8_t TCP_FIN = 0x01;
static constexpr uint8_t TCP_SYN = 0x02;
static constexpr uint8_t TCP_RST = 0x04;
static constexpr uint8_t TCP_ACK = 0x10;

// ===================================================================
// FlowKey — the identity of a single conversation (a "flow").
//
// A flow is the 5-tuple (src_ip, dst_ip, src_port, dst_port, proto).
// But A->B and B->A are the SAME conversation, so we store the key in a
// CANONICAL (direction-independent) form: the numerically smaller
// (ip, port) endpoint always goes in slot "a", the larger in slot "b".
// That way both directions of traffic produce an identical FlowKey and
// land in the same hash-map bucket.
//
// Knowing *which* side initiated the flow (to split sbytes vs dbytes) is
// NOT stored here — that lives in FlowState, decided by the first packet.
// ===================================================================
struct FlowKey {
    uint32_t ip_a;
    uint32_t ip_b;
    uint16_t port_a;
    uint16_t port_b;
    uint8_t  proto;

    // Two keys are equal iff all five fields match. In Python a tuple gets
    // this for free; in C++ we must spell it out so unordered_map can detect
    // hash collisions vs. genuine matches.
    bool operator==(const FlowKey& o) const {
        return ip_a == o.ip_a && ip_b == o.ip_b &&
               port_a == o.port_a && port_b == o.port_b &&
               proto == o.proto;
    }
};

// Build a canonical key from a packet's endpoints. Ordering endpoints
// consistently (smaller one first) is what makes the key bidirectional.
inline FlowKey make_flow_key(const Packet& p) {
    FlowKey k{};
    k.proto = p.proto;

    // Compare endpoints as (ip, port) pairs and put the smaller first.
    bool src_is_smaller =
        (p.src_ip < p.dst_ip) ||
        (p.src_ip == p.dst_ip && p.src_port <= p.dst_port);

    if (src_is_smaller) {
        k.ip_a = p.src_ip; k.port_a = p.src_port;
        k.ip_b = p.dst_ip; k.port_b = p.dst_port;
    } else {
        k.ip_a = p.dst_ip; k.port_a = p.dst_port;
        k.ip_b = p.src_ip; k.port_b = p.src_port;
    }
    return k;
}

// ===================================================================
// FlowKeyHash — teaches unordered_map how to hash a FlowKey.
//
// std::unordered_map needs a hash function for its key type. For built-in
// types (int, string) the standard library provides std::hash. For our
// custom struct we provide our own "functor": a struct with operator()
// that takes a FlowKey and returns a size_t hash. We pass it as the map's
// 3rd template argument: unordered_map<FlowKey, FlowState, FlowKeyHash>.
//
// The mix() helper is the well-known hash_combine recipe (from Boost): it
// folds each field into a running seed so that different field orderings
// produce well-distributed, low-collision hashes. The magic constant
// 0x9e3779b97f4a7c15 is derived from the golden ratio.
// ===================================================================
struct FlowKeyHash {
    static void mix(std::size_t& seed, std::size_t value) {
        seed ^= value + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
    }

    std::size_t operator()(const FlowKey& k) const {
        std::size_t seed = 0;
        mix(seed, std::hash<uint32_t>{}(k.ip_a));
        mix(seed, std::hash<uint32_t>{}(k.ip_b));
        mix(seed, std::hash<uint16_t>{}(k.port_a));
        mix(seed, std::hash<uint16_t>{}(k.port_b));
        mix(seed, std::hash<uint8_t>{}(k.proto));
        return seed;
    }
};

// ===================================================================
// FlowState — the running statistics we accumulate for one flow as
// packets arrive. This is the VALUE stored in the map (FlowKey -> FlowState).
//
// "Source" (s*) = the flow initiator: whoever sent the first packet.
// "Dest"   (d*) = the other endpoint. We record the initiator's identity
// in init_ip/init_port on the first packet, then classify every later
// packet's direction by comparing against it.
//
// Only the core accumulators are here for now (1.3b). Later steps add:
//   1.3e: jitter / interpacket / handshake timestamp fields
//   1.3f: TCP state + service
//   1.3g: ct_* sliding-window features
// ===================================================================
struct FlowState {
    // --- direction reference (set from the first packet) ---
    uint32_t init_ip   = 0;   // src_ip of the first packet = the "source"
    uint16_t init_port = 0;   // src_port of the first packet
    bool     seen      = false; // has the first packet initialized this flow?

    // --- timing (Stime / Ltime / dur) ---
    uint64_t first_ts_us = 0;
    uint64_t last_ts_us  = 0;

    // --- per-direction packet counts (spkts / dpkts) ---
    uint64_t spkts = 0;
    uint64_t dpkts = 0;

    // --- per-direction byte counts (sbytes / dbytes) ---
    uint64_t sbytes = 0;
    uint64_t dbytes = 0;

    // --- header snapshots: first value seen per direction (sttl/dttl/swin/dwin) ---
    uint8_t  sttl = 0;
    uint8_t  dttl = 0;
    uint16_t swin = 0;
    uint16_t dwin = 0;

    // --- accumulated TCP flags per direction (for state / loss later) ---
    uint8_t  s_flags = 0;   // OR of all source->dest TCP flags
    uint8_t  d_flags = 0;   // OR of all dest->source TCP flags

    // --- inter-arrival + jitter accumulation, per direction ---
    // (sinpkt/dinpkt = mean gap between packets; sjit/djit = mean change in gap)
    uint64_t s_last_ts   = 0;   // timestamp of previous source-side packet
    uint64_t d_last_ts   = 0;   // timestamp of previous dest-side packet
    double   s_intpkt_sum = 0;  uint64_t s_intpkt_n = 0;  // sum & count of source gaps
    double   d_intpkt_sum = 0;  uint64_t d_intpkt_n = 0;
    double   s_prev_int  = 0;   double s_jit_sum = 0;  uint64_t s_jit_n = 0;
    double   d_prev_int  = 0;   double d_jit_sum = 0;  uint64_t d_jit_n = 0;

    // --- TCP 3-way handshake timestamps (synack / ackdat / tcprtt) ---
    uint64_t syn_ts    = 0;  bool has_syn    = false;  // pure SYN (source)
    uint64_t synack_ts = 0;  bool has_synack = false;  // SYN+ACK (dest)
    uint64_t ack_ts    = 0;  bool has_ack    = false;  // final ACK (source)

    // Helper: is this packet flowing from the initiator (source) side?
    bool is_from_source(const Packet& p) const {
        return p.src_ip == init_ip && p.src_port == init_port;
    }
};
