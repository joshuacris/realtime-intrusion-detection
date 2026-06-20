#include "packet.h"
#include "pcap_reader.h"
#include "flow_aggregator.h"
#include "flow_history.h"
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
    FlowHistory history;   // last-100-connections window for the ct_* features

    // The sink: runs whenever a flow completes. Compute its ct_* context from
    // the recent-connection window, then serialize as one JSON line.
    FlowAggregator agg([&](const FlowKey& key, const FlowState& st) {
        // Destination = whichever canonical endpoint is NOT the initiator.
        uint32_t dst_ip; uint16_t dst_port;
        if (st.init_ip == key.ip_a && st.init_port == key.port_a) {
            dst_ip = key.ip_b; dst_port = key.port_b;
        } else {
            dst_ip = key.ip_a; dst_port = key.port_a;
        }

        FlowRecord rec{};
        rec.src_ip  = st.init_ip;
        rec.dst_ip  = dst_ip;
        rec.sport   = st.init_port;
        rec.dport   = dst_port;
        rec.service = service_name(st.init_port, dst_port);
        rec.state   = flow_state_label(key, st);
        rec.sttl    = st.sttl;
        rec.dttl    = st.dttl;

        CtFeatures ct = history.observe(rec);
        out << flow_to_json(key, st, ct).dump() << "\n";
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
