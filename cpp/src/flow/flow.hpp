#pragma once

#include "net/packet.hpp"
#include <cstdint>
#include <cstddef>
#include <functional>

namespace ids {

// TCP control-flag bit masks (byte 13 of the TCP header).
inline constexpr uint8_t TCP_FIN{0x01};
inline constexpr uint8_t TCP_SYN{0x02};
inline constexpr uint8_t TCP_RST{0x04};
inline constexpr uint8_t TCP_ACK{0x10};

// Identity of one conversation. Stored canonically (smaller (ip,port) endpoint
// in slot "a") so both directions of traffic hash to the same key.
struct FlowKey {
    uint32_t ip_a{};
    uint32_t ip_b{};
    uint16_t port_a{};
    uint16_t port_b{};
    uint8_t  proto{};

    bool operator==(const FlowKey& o) const {
        return ip_a == o.ip_a && ip_b == o.ip_b &&
               port_a == o.port_a && port_b == o.port_b &&
               proto == o.proto;
    }
};

inline FlowKey make_flow_key(const Packet& p) {
    FlowKey k{};
    k.proto = p.proto;

    const bool src_is_smaller{
        (p.src_ip < p.dst_ip) ||
        (p.src_ip == p.dst_ip && p.src_port <= p.dst_port)};

    if (src_is_smaller) {
        k.ip_a = p.src_ip; k.port_a = p.src_port;
        k.ip_b = p.dst_ip; k.port_b = p.dst_port;
    } else {
        k.ip_a = p.dst_ip; k.port_a = p.dst_port;
        k.ip_b = p.src_ip; k.port_b = p.src_port;
    }
    return k;
}

// Hash functor for FlowKey (unordered_map's 3rd template arg). mix() is the
// Boost hash_combine recipe; the constant derives from the golden ratio.
struct FlowKeyHash {
    static void mix(std::size_t& seed, std::size_t value) {
        seed ^= value + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
    }

    std::size_t operator()(const FlowKey& k) const {
        std::size_t seed{0};
        mix(seed, std::hash<uint32_t>{}(k.ip_a));
        mix(seed, std::hash<uint32_t>{}(k.ip_b));
        mix(seed, std::hash<uint16_t>{}(k.port_a));
        mix(seed, std::hash<uint16_t>{}(k.port_b));
        mix(seed, std::hash<uint8_t>{}(k.proto));
        return seed;
    }
};

// Running per-flow statistics — the value stored against each FlowKey.
// "s*" = the initiator (first packet's sender); "d*" = the other endpoint.
struct FlowState {
    uint32_t init_ip{};
    uint16_t init_port{};
    bool     seen{false};      // has the first packet initialized this flow?
    bool     emitted{false};   // closed+emitted; lingers to absorb stragglers

    uint64_t first_ts_us{};
    uint64_t last_ts_us{};

    uint64_t spkts{};
    uint64_t dpkts{};
    uint64_t sbytes{};
    uint64_t dbytes{};

    uint8_t  sttl{};
    uint8_t  dttl{};
    uint16_t swin{};
    uint16_t dwin{};

    uint8_t  s_flags{};        // OR of all source->dest TCP flags
    uint8_t  d_flags{};

    // Inter-arrival mean (sinpkt/dinpkt) and jitter (sjit/djit) accumulators.
    uint64_t s_last_ts{};
    uint64_t d_last_ts{};
    double   s_intpkt_sum{}; uint64_t s_intpkt_n{};
    double   d_intpkt_sum{}; uint64_t d_intpkt_n{};
    double   s_prev_int{};   double s_jit_sum{}; uint64_t s_jit_n{};
    double   d_prev_int{};   double d_jit_sum{}; uint64_t d_jit_n{};

    // The UNSW tap recorded each packet twice; this signature of the last
    // accepted packet lets add_packet drop the immediate byte-identical duplicate.
    bool     last_from_src{false};
    uint32_t last_seq{};
    uint32_t last_len{};
    uint8_t  last_flags{};
    uint64_t last_pkt_ts{};

    // Retransmission detection (sloss/dloss): a segment starting below the
    // highest stream position already seen carries already-sent bytes.
    uint32_t s_max_seq_end{}; bool s_seq_init{false}; uint64_t sloss{};
    uint32_t d_max_seq_end{}; bool d_seq_init{false}; uint64_t dloss{};

    // TCP handshake timestamps (synack/ackdat/tcprtt).
    uint64_t syn_ts{};    bool has_syn{false};
    uint64_t synack_ts{}; bool has_synack{false};
    uint64_t ack_ts{};    bool has_ack{false};

    bool is_from_source(const Packet& p) const {
        return p.src_ip == init_ip && p.src_port == init_port;
    }
};

}  // namespace ids
