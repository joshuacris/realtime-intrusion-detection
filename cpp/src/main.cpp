#include "packet.h"
#include "pcap_reader.h"
#include "flow_aggregator.h"
#include "flow_history.h"
#include "flow_json.h"
#include "kafka_producer.h"

#include <cstdio>
#include <cstdlib>   // std::getenv
#include <fstream>   // std::ofstream
#include <memory>    // std::unique_ptr

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file.pcap> [out.jsonl]\n", argv[0]);
        return 1;
    }
    // Two independent output sinks, either/both can be enabled:
    //   - file: optional 2nd arg (a path to a .jsonl file)
    //   - kafka: enabled when the KAFKA_BROKERS env var is set (12-factor config)
    const char* out_path = (argc >= 3) ? argv[2] : nullptr;
    const char* brokers  = std::getenv("KAFKA_BROKERS");   // e.g. "localhost:9092"

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

    long emitted = 0;
    FlowHistory history;   // last-100-connections window for the ct_* features

    // The sink: runs whenever a flow completes. Compute its ct_* context from
    // the recent-connection window, serialize once, then fan out to file/kafka.
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
        std::string json = flow_to_json(key, st, ct).dump();   // serialize once

        if (out) out << json << "\n";
        if (producer) {
            // Key by source IP so all flows from one host land on one partition
            // (and stay ordered). With 1 partition today it's harmless; it's the
            // right design for when we add partitions in 2.5.
            producer->send(ip_to_string(st.init_ip), json);
        }
        emitted++;
    });

    long total_packets = 0;
    long n = read_pcap(argv[1], [&](const Packet& p) {
        agg.add_packet(p);
        total_packets++;
    });
    if (n < 0) return 1;

    agg.flush();   // emit flows still open when the capture ends

    if (producer) {
        producer->flush();   // wait for all queued Kafka messages to deliver
    }

    printf("packets parsed: %ld\n", total_packets);
    printf("flows emitted:  %ld\n", emitted);
    if (out_path) printf("file written:   %s\n", out_path);
    if (producer) {
        printf("kafka delivered: %llu   failed: %llu\n",
               (unsigned long long)producer->delivered(),
               (unsigned long long)producer->failed());
    }
    return 0;
}
