#include "net/packet.hpp"
#include "net/pcap_reader.hpp"
#include "flow/aggregator.hpp"
#include "flow/history.hpp"
#include "flow/json.hpp"
#include "messaging/kafka_producer.hpp"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <memory>

using namespace ids;

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file.pcap> [out.jsonl]\n", argv[0]);
        return 1;
    }
    // Two optional sinks: a .jsonl file (2nd arg) and/or Kafka (KAFKA_BROKERS env).
    const char* out_path{(argc >= 3) ? argv[2] : nullptr};
    const char* brokers{std::getenv("KAFKA_BROKERS")};

    std::ofstream out;
    if (out_path) {
        out.open(out_path);
        if (!out) {
            fprintf(stderr, "error: cannot open %s for writing\n", out_path);
            return 1;
        }
    }

    std::unique_ptr<KafkaProducer> producer;
    if (brokers) producer = std::make_unique<KafkaProducer>(brokers, "raw-flows");

    if (!out_path && !brokers) {
        fprintf(stderr, "warning: no output configured "
                        "(pass a .jsonl path and/or set KAFKA_BROKERS)\n");
    }

    long emitted{0};
    FlowHistory history;   // last-100-connections window for the ct_* features

    // Runs per completed flow: compute ct_* context, serialize once, fan out.
    FlowAggregator agg{[&](const FlowKey& key, const FlowState& st) {
        uint32_t dst_ip;
        uint16_t dst_port;
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

        const CtFeatures ct{history.observe(rec)};
        const std::string json{flow_to_json(key, st, ct).dump()};

        if (out) out << json << "\n";
        // Key by source IP so a host's flows stay on one partition (and ordered).
        if (producer) producer->send(ip_to_string(st.init_ip), json);
        emitted++;
    }};

    long total_packets{0};
    const long n{read_pcap(argv[1], [&](const Packet& p) {
        agg.add_packet(p);
        total_packets++;
    })};
    if (n < 0) return 1;

    agg.flush();
    if (producer) producer->flush();

    printf("packets parsed: %ld\n", total_packets);
    printf("flows emitted:  %ld\n", emitted);
    if (out_path) printf("file written:   %s\n", out_path);
    if (producer) {
        printf("kafka delivered: %llu   failed: %llu\n",
               static_cast<unsigned long long>(producer->delivered()),
               static_cast<unsigned long long>(producer->failed()));
    }
    return 0;
}
