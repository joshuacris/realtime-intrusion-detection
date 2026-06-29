#pragma once

#include <cstdint>

namespace ids {

// One parsed IPv4 packet — the unit the pcap reader hands to the rest of the
// system. All multi-byte fields are in host byte order.
struct Packet {
    uint32_t src_ip{};
    uint32_t dst_ip{};
    uint16_t src_port{};      // 0 for ICMP / portless protocols
    uint16_t dst_port{};
    uint8_t  proto{};         // 1=ICMP, 6=TCP, 17=UDP
    uint8_t  tcp_flags{};
    uint8_t  ttl{};
    uint16_t tcp_window{};
    uint32_t tcp_seq{};
    uint64_t timestamp_us{};
    uint32_t payload_len{};    // application-layer bytes (excludes headers)
    uint32_t ip_total_len{};   // whole IP datagram size
};

}  // namespace ids
