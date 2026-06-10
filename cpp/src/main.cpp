#include "packet.h"
#include "pcap_reader.h"
#include "flow_aggregator.h"
#include "flow_json.h"

#include <cstdio>
#include <fstream>   // std::ofstream

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file.pcap> [out.jsonl]\n", argv[0]);
        return 1;
    }
    const char* out_path = (argc >= 3) ? argv[2] : "flows.jsonl";

    std::ofstream out(out_path);
    if (!out) {
        fprintf(stderr, "error: cannot open %s for writing\n", out_path);
        return 1;
    }

    long emitted = 0;

    // The sink: runs whenever a flow completes. Serialize it as one JSON line
    // (JSON Lines format: one self-contained JSON object per line).
    FlowAggregator agg([&](const FlowKey& key, const FlowState& st) {
        out << flow_to_json(key, st).dump() << "\n";
        emitted++;
    });

    long total_packets = 0;
    long n = read_pcap(argv[1], [&](const Packet& p) {
        agg.add_packet(p);
        total_packets++;
    });
    if (n < 0) return 1;

    agg.flush();   // emit flows still open when the capture ends

    printf("packets parsed: %ld\n", total_packets);
    printf("flows emitted:  %ld\n", emitted);
    printf("output written: %s\n", out_path);
    return 0;
}
