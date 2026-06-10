#pragma once    // include guard — see takeaways. Replaces the classic
                // #ifndef PACKET_H / #define PACKET_H / #endif dance.

#include <cstdint>

// -------------------------------------------------------------------
// One parsed packet. This is the unit the pcap reader hands back to the
// rest of the system. Identical layout to a C struct.
// -------------------------------------------------------------------
struct Packet {
    uint32_t src_ip;        // source IP, host byte order (already ntohl'd)
    uint32_t dst_ip;        // destination IP, host byte order
    uint16_t src_port;      // 0 for ICMP / portless protocols
    uint16_t dst_port;      // 0 for ICMP / portless protocols
    uint8_t  proto;         // IP protocol: 1=ICMP, 6=TCP, 17=UDP
    uint8_t  tcp_flags;     // TCP flag bitmask (0 if not TCP)
    uint8_t  ttl;           // IP time-to-live (feeds sttl/dttl per direction)
    uint16_t tcp_window;    // TCP advertised window (feeds swin/dwin; 0 if not TCP)
    uint64_t timestamp_us;  // capture time, microseconds since epoch
    uint32_t payload_len;   // application-layer bytes (excludes all headers)
    uint32_t ip_total_len;  // whole IP datagram size (feeds sbytes/dbytes)
};
