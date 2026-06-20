#include "pcap_reader.h"

#include <pcap.h>        // the libpcap API
#include <arpa/inet.h>   // ntohs / ntohl (network-to-host byte order)
#include <cstdio>
#include <cstring>       // memcpy

// -------------------------------------------------------------------
// Constants. `constexpr` is C++ for "compile-time constant" — like a
// #define but type-safe and scoped. Prefer it over #define in C++.
// -------------------------------------------------------------------
static constexpr int SLL_HDR_LEN = 16;   // Linux "cooked" capture (DLT_LINUX_SLL)
static constexpr int ETH_HDR_LEN = 14;   // standard Ethernet (DLT_EN10MB)

static constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;

static constexpr uint8_t IP_PROTO_ICMP = 1;
static constexpr uint8_t IP_PROTO_TCP  = 6;
static constexpr uint8_t IP_PROTO_UDP  = 17;

// -------------------------------------------------------------------
// Safe multi-byte reads.
//
// Network data is big-endian. Casting a (u_char*) straight to (uint16_t*)
// and dereferencing is UNDEFINED BEHAVIOR in C/C++ (alignment + strict
// aliasing). The correct, portable way is memcpy into a properly-typed
// variable — the compiler optimizes a 2/4-byte memcpy into a single load,
// so there's no performance cost. This is a real C++ (and C) gotcha.
// -------------------------------------------------------------------
static uint16_t read_be16(const u_char* p) {
    uint16_t v;
    std::memcpy(&v, p, sizeof(v));
    return ntohs(v);    // big-endian on the wire -> host byte order
}

static uint32_t read_be32(const u_char* p) {
    uint32_t v;
    std::memcpy(&v, p, sizeof(v));
    return ntohl(v);
}

long read_pcap(const char* path,
               const std::function<void(const Packet&)>& on_packet) {
    char errbuf[PCAP_ERRBUF_SIZE];   // libpcap writes error text here

    // Open the capture file. Like fopen(), but returns a pcap_t* handle.
    pcap_t* handle = pcap_open_offline(path, errbuf);
    if (handle == nullptr) {         // nullptr is C++'s typed NULL
        fprintf(stderr, "error: cannot open %s: %s\n", path, errbuf);
        return -1;
    }

    // What link layer was this captured with? Determines how many bytes
    // to skip before the IP header begins.
    int datalink = pcap_datalink(handle);
    int link_hdr_len;
    if (datalink == DLT_LINUX_SLL) {
        link_hdr_len = SLL_HDR_LEN;
    } else if (datalink == DLT_EN10MB) {
        link_hdr_len = ETH_HDR_LEN;
    } else {
        fprintf(stderr, "error: unsupported link type %d\n", datalink);
        pcap_close(handle);
        return -1;
    }

    long parsed = 0;
    struct pcap_pkthdr* header;   // per-packet metadata: timestamp, lengths
    const u_char* data;           // pointer to the raw captured bytes

    // pcap_next_ex returns:
    //   1  -> a packet was read
    //   0  -> timeout (live captures only; never for files)
    //  -2  -> end of file
    //  -1  -> error
    int rc;
    while ((rc = pcap_next_ex(handle, &header, &data)) == 1) {
        // caplen = bytes actually captured (could be < real length if a
        // snap length was set during capture).
        uint32_t caplen = header->caplen;

        // ================= Layer 2: the link layer =================
        // The outermost envelope: addressing for ONE physical hop (the local
        // cable/switch). It carries MAC addresses, but those are useless for
        // end-to-end identity (they change at every router hop), so we ignore
        // them. We need exactly ONE field from it: the EtherType, which says
        // "what kind of packet is inside this envelope?" It lives in the last
        // 2 bytes of both the SLL (16-byte) and Ethernet (14-byte) headers.
        if (caplen < static_cast<uint32_t>(link_hdr_len)) continue;
        uint16_t ethertype = read_be16(data + link_hdr_len - 2);
        if (ethertype != ETHERTYPE_IPV4) continue;   // skip IPv6 / ARP / etc.

        // ================= Layer 3: the IPv4 header =================
        // Internet-wide, host-to-host addressing. Standardized byte layout
        // (RFC 791, unchanged since 1981). `ip` points to where it begins,
        // i.e. just past the link header.
        const u_char* ip = data + link_hdr_len;
        if (caplen < static_cast<uint32_t>(link_hdr_len) + 20) continue;

        // Byte 0 packs TWO values in its two nibbles (4-bit halves):
        //   high nibble = IP version (4),
        //   low nibble  = IHL (header length) measured in 32-bit WORDS.
        // The IP header is usually 20 bytes but can be longer if "IP options"
        // are present, so we must read IHL to know where Layer 4 starts.
        // We never hardcode 20 -> we read the real length here. (IHL * 4 = bytes)
        uint8_t ihl = (ip[0] & 0x0F) * 4;
        if (ihl < 20) continue;                       // malformed: header too small

        uint16_t total_len = read_be16(ip + 2);       // size of whole IP datagram
        uint8_t  ttl       = ip[8];                    // hops remaining (feeds sttl/dttl)
        uint8_t  proto     = ip[9];                   // what's inside: 1=ICMP 6=TCP 17=UDP
        uint32_t src_ip    = read_be32(ip + 12);      // who is talking...
        uint32_t dst_ip    = read_be32(ip + 16);      // ...to whom (core of IDS)

        // ================= Layer 4: TCP / UDP / ICMP =================
        // Identifies WHICH PROGRAM on the host (via ports) and, for TCP, the
        // connection state (via flags). `l4` skips past the IP header using the
        // IHL length we computed above -- this is exactly why IHL mattered.
        const u_char* l4 = ip + ihl;
        uint32_t l4_offset = static_cast<uint32_t>(l4 - data);  // bytes consumed so far
        uint16_t src_port = 0, dst_port = 0;
        uint8_t  tcp_flags = 0;
        uint16_t tcp_window = 0;
        uint32_t tcp_seq = 0;
        uint32_t l4_hdr_len = 0;

        if (proto == IP_PROTO_TCP) {
            // TCP: connection-oriented. Header is VARIABLE length (it can carry
            // TCP options), so we read its "data offset" to size it.
            if (caplen < l4_offset + 20) continue;     // min TCP header is 20 bytes
            src_port  = read_be16(l4 + 0);             // bytes 0-1: source port
            dst_port  = read_be16(l4 + 2);             // bytes 2-3: dest port (e.g. 80=HTTP)
            // Bytes 4-7: sequence number. TCP numbers every BYTE it sends; the
            // seq says "this segment starts at byte N of my stream". Seeing a
            // segment start below the highest byte already sent = retransmission.
            tcp_seq    = read_be32(l4 + 4);
            // Byte 12 high nibble = data offset = header length in 32-bit words.
            l4_hdr_len = (l4[12] >> 4) * 4;            // (like IHL, but for TCP)
            // Byte 13 = control-flag bitmask. The flag PATTERN reveals behavior:
            //   SYN(0x02)->SYN-ACK(0x12)->ACK(0x10) is a healthy 3-way handshake;
            //   a flood of lone SYNs = SYN-flood DoS; RST bursts = port scanning.
            tcp_flags  = l4[13];
            // Bytes 14-15 = advertised receive window (flow-control buffer size).
            tcp_window = read_be16(l4 + 14);
        } else if (proto == IP_PROTO_UDP) {
            // UDP: connectionless. No handshake, no flags, header is ALWAYS
            // exactly 8 bytes (no options) -- so we hardcode 8 here.
            if (caplen < l4_offset + 8) continue;
            src_port   = read_be16(l4 + 0);
            dst_port   = read_be16(l4 + 2);
            l4_hdr_len = 8;
        } else if (proto == IP_PROTO_ICMP) {
            // ICMP: control/diagnostic traffic (ping, "host unreachable").
            // It has NO port concept, so src/dst ports stay 0.
            l4_hdr_len = 0;
        } else {
            continue;                                  // ignore other protocols (OSPF, etc.)
        }

        // ---- Assemble the Packet ----
        Packet pkt = {};
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

        // Application-layer payload = whole datagram minus all the headers we
        // walked through: payload = total_len - IP_header - L4_header.
        // The guard avoids unsigned underflow: on uint32_t, (5 - 10) wraps to
        // ~4 billion, not -5, so a malformed too-small total_len could explode
        // payload_len. Clamp at 0 instead.
        uint32_t headers = ihl + l4_hdr_len;
        pkt.payload_len  = (total_len > headers) ? (total_len - headers) : 0;

        on_packet(pkt);   // hand the parsed packet to the caller
        parsed++;
    }

    pcap_close(handle);
    return parsed;
}
