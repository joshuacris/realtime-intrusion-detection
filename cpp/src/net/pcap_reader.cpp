#include "net/pcap_reader.hpp"

#include <pcap.h>
#include <arpa/inet.h>
#include <cstdio>
#include <cstring>

namespace ids {

namespace {

constexpr int SLL_HDR_LEN{16};   // Linux "cooked" capture (DLT_LINUX_SLL)
constexpr int ETH_HDR_LEN{14};   // standard Ethernet (DLT_EN10MB)

constexpr uint16_t ETHERTYPE_IPV4{0x0800};
constexpr uint8_t  IP_PROTO_ICMP{1};
constexpr uint8_t  IP_PROTO_TCP{6};
constexpr uint8_t  IP_PROTO_UDP{17};

// memcpy (not a pointer cast) avoids the alignment/strict-aliasing UB of reading
// a multi-byte value straight from the packet buffer; the compiler folds it to a
// single load. Network data is big-endian, so convert to host order.
uint16_t read_be16(const u_char* p) {
    uint16_t v;
    std::memcpy(&v, p, sizeof(v));
    return ntohs(v);
}

uint32_t read_be32(const u_char* p) {
    uint32_t v;
    std::memcpy(&v, p, sizeof(v));
    return ntohl(v);
}

}  // namespace

long read_pcap(const char* path,
               const std::function<void(const Packet&)>& on_packet) {
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle{pcap_open_offline(path, errbuf)};
    if (handle == nullptr) {
        fprintf(stderr, "error: cannot open %s: %s\n", path, errbuf);
        return -1;
    }

    // Link-layer type decides how many bytes precede the IP header.
    int link_hdr_len;
    switch (pcap_datalink(handle)) {
        case DLT_LINUX_SLL: link_hdr_len = SLL_HDR_LEN; break;
        case DLT_EN10MB:    link_hdr_len = ETH_HDR_LEN; break;
        default:
            fprintf(stderr, "error: unsupported link type %d\n",
                    pcap_datalink(handle));
            pcap_close(handle);
            return -1;
    }

    long parsed{0};
    struct pcap_pkthdr* header;
    const u_char* data;

    // pcap_next_ex returns 1 per packet, -2 at EOF, -1 on error.
    int rc;
    while ((rc = pcap_next_ex(handle, &header, &data)) == 1) {
        const uint32_t caplen{header->caplen};

        // Layer 2: we need only the EtherType (last 2 bytes of the link header).
        if (caplen < static_cast<uint32_t>(link_hdr_len)) continue;
        if (read_be16(data + link_hdr_len - 2) != ETHERTYPE_IPV4) continue;

        // Layer 3: IPv4 header. Byte 0's low nibble is IHL in 32-bit words, so
        // the header length is variable (IP options) and must be read, not assumed.
        const u_char* ip{data + link_hdr_len};
        if (caplen < static_cast<uint32_t>(link_hdr_len) + 20) continue;

        const uint8_t ihl = (ip[0] & 0x0F) * 4;
        if (ihl < 20) continue;

        const uint16_t total_len{read_be16(ip + 2)};
        const uint8_t  ttl{ip[8]};
        const uint8_t  proto{ip[9]};
        const uint32_t src_ip{read_be32(ip + 12)};
        const uint32_t dst_ip{read_be32(ip + 16)};

        // Layer 4: ports + (for TCP) flags. `l4` skips the IP header via IHL.
        const u_char* l4{ip + ihl};
        const uint32_t l4_offset{static_cast<uint32_t>(l4 - data)};
        uint16_t src_port{0}, dst_port{0};
        uint8_t  tcp_flags{0};
        uint16_t tcp_window{0};
        uint32_t tcp_seq{0};
        uint32_t l4_hdr_len{0};

        if (proto == IP_PROTO_TCP) {
            if (caplen < l4_offset + 20) continue;   // min TCP header
            src_port   = read_be16(l4 + 0);
            dst_port   = read_be16(l4 + 2);
            tcp_seq    = read_be32(l4 + 4);
            l4_hdr_len = (l4[12] >> 4) * 4;           // data offset, in 32-bit words
            tcp_flags  = l4[13];
            tcp_window = read_be16(l4 + 14);
        } else if (proto == IP_PROTO_UDP) {
            if (caplen < l4_offset + 8) continue;
            src_port   = read_be16(l4 + 0);
            dst_port   = read_be16(l4 + 2);
            l4_hdr_len = 8;                           // UDP header is always 8 bytes
        } else if (proto == IP_PROTO_ICMP) {
            l4_hdr_len = 0;                           // no ports
        } else {
            continue;
        }

        Packet pkt{};
        pkt.src_ip       = src_ip;
        pkt.dst_ip       = dst_ip;
        pkt.src_port     = src_port;
        pkt.dst_port     = dst_port;
        pkt.proto        = proto;
        pkt.tcp_flags    = tcp_flags;
        pkt.ttl          = ttl;
        pkt.tcp_window   = tcp_window;
        pkt.tcp_seq      = tcp_seq;
        pkt.ip_total_len = total_len;
        pkt.timestamp_us = static_cast<uint64_t>(header->ts.tv_sec) * 1000000ULL
                         + static_cast<uint64_t>(header->ts.tv_usec);

        // Guard against unsigned underflow on a malformed (too-small) total_len.
        const uint32_t headers{static_cast<uint32_t>(ihl) + l4_hdr_len};
        pkt.payload_len = (total_len > headers) ? (total_len - headers) : 0;

        on_packet(pkt);
        parsed++;
    }

    pcap_close(handle);
    return parsed;
}

}  // namespace ids
