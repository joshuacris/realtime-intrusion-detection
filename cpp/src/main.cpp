#include <cstdio>    // C++ name for <stdio.h> — printf, etc.
#include <cstdint>   // C++ name for <stdint.h> — uint32_t, uint16_t, etc.
#include <cstring>   // C++ name for <string.h> — memset, memcpy, etc.

// -------------------------------------------------------------------
// Packet struct — the raw data we read off the wire (or from a pcap file).
// This is identical to a C struct. C++ structs and C structs work the same
// way: same memory layout, same field access with '.', same sizeof().
// -------------------------------------------------------------------
struct Packet {
    uint32_t src_ip;       // source IP as a 32-bit integer (network byte order)
    uint32_t dst_ip;       // destination IP
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;        // IP protocol number: 6=TCP, 17=UDP, 1=ICMP
    uint8_t  tcp_flags;    // bitmask: SYN=0x02, ACK=0x10, FIN=0x01, RST=0x04
    uint64_t timestamp_us; // microseconds since epoch
    uint32_t payload_len;  // bytes of application data (not including headers)
};

// Helper: print a 32-bit IP integer as "a.b.c.d"
// In C you'd write this the same way — nothing new here.
static void print_ip(uint32_t ip) {
    printf("%u.%u.%u.%u",
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8)  & 0xFF,
         ip        & 0xFF);
}

int main() {
    printf("flow_extractor starting up\n");

    // Create a test packet — 'Packet p = {}' is the C++ way of
    // zero-initializing a struct. Same as memset(&p, 0, sizeof(p)) in C.
    Packet p = {};
    p.src_ip       = (192u << 24) | (168u << 16) | (0u << 8) | 1u; // 192.168.0.1
    p.dst_ip       = (192u << 24) | (168u << 16) | (0u << 8) | 2u; // 192.168.0.2
    p.src_port     = 54321;
    p.dst_port     = 80;
    p.proto        = 6;    // TCP
    p.tcp_flags    = 0x02; // SYN
    p.timestamp_us = 1748000000000000ULL;
    p.payload_len  = 512;

    printf("packet: ");
    print_ip(p.src_ip);
    printf(":%u -> ", p.src_port);
    print_ip(p.dst_ip);
    printf(":%u  proto=%u  flags=0x%02X  len=%u\n",
        p.dst_port,
        (unsigned)p.proto,
        (unsigned)p.tcp_flags,
        p.payload_len);

    printf("sizeof(Packet) = %zu bytes\n", sizeof(Packet));
    printf("build OK — ready for Phase 1.2 (pcap reader)\n");

    return 0;
}
