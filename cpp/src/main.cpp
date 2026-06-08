#include "packet.h"
#include "pcap_reader.h"

#include <cstdio>
#include <cstdint>

// Print a host-order IP integer as "a.b.c.d".
static void print_ip(uint32_t ip) {
    printf("%u.%u.%u.%u",
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8)  & 0xFF,
         ip        & 0xFF);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file.pcap>\n", argv[0]);
        return 1;
    }

    // Counters the lambda below will update. Declared here in main's scope.
    long total = 0, tcp = 0, udp = 0, icmp = 0;
    int  printed = 0;

    // The lambda: [&] means "capture all the variables I use, by reference"
    // (total, tcp, printed, ...). It behaves like a function pointer that
    // also remembers those variables. read_pcap calls it once per packet.
    long n = read_pcap(argv[1], [&](const Packet& p) {
        total++;
        if      (p.proto == 6)  tcp++;
        else if (p.proto == 17) udp++;
        else if (p.proto == 1)  icmp++;

        // Print the first 10 packets so we can eyeball-verify the parse.
        if (printed < 10) {
            printf("  ");
            print_ip(p.src_ip); printf(":%-5u -> ", p.src_port);
            print_ip(p.dst_ip);
            printf(":%-5u  proto=%-2u flags=0x%02X len=%u\n",
                p.dst_port, (unsigned)p.proto,
                (unsigned)p.tcp_flags, p.payload_len);
            printed++;
        }
    });

    if (n < 0) return 1;   // read_pcap already printed the error

    printf("\n--- summary ---\n");
    printf("total parsed: %ld\n", total);
    printf("  TCP:  %ld\n", tcp);
    printf("  UDP:  %ld\n", udp);
    printf("  ICMP: %ld\n", icmp);
    return 0;
}
