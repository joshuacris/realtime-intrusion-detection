#pragma once

#include "flow.h"
#include <nlohmann/json.hpp>   // the vcpkg JSON library
#include <string>
#include <cstdio>

// Format a host-order IP integer as a "a.b.c.d" string.
inline std::string ip_to_string(uint32_t ip) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
        (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
    return std::string(buf);
}

// Map IP protocol number -> the lowercase name UNSW-NB15 uses.
inline const char* proto_name(uint8_t proto) {
    switch (proto) {
        case 6:  return "tcp";
        case 17: return "udp";
        case 1:  return "icmp";
        default: return "other";
    }
}

// Build a JSON object for one completed flow, using UNSW feature field names so
// it lines up with the model's expected inputs downstream. Only the features we
// can compute so far are included; derived ones (loads, jitter, ct_*) come in
// later sub-steps and will be added here.
inline nlohmann::json flow_to_json(const FlowKey& key, const FlowState& st) {
    // The destination is whichever canonical endpoint is NOT the initiator.
    uint32_t dst_ip;
    uint16_t dst_port;
    if (st.init_ip == key.ip_a && st.init_port == key.port_a) {
        dst_ip = key.ip_b; dst_port = key.port_b;
    } else {
        dst_ip = key.ip_a; dst_port = key.port_a;
    }

    double dur = (st.last_ts_us - st.first_ts_us) / 1e6;   // seconds

    // ---- Derived features (1.3e) ----
    // Guard every division: a 1-packet or 0-duration flow must not divide by 0.
    double smean = st.spkts ? static_cast<double>(st.sbytes) / st.spkts : 0.0;
    double dmean = st.dpkts ? static_cast<double>(st.dbytes) / st.dpkts : 0.0;
    double sload = dur > 0 ? st.sbytes * 8.0 / dur : 0.0;        // source bits/sec
    double dload = dur > 0 ? st.dbytes * 8.0 / dur : 0.0;        // dest bits/sec
    double rate  = dur > 0 ? (st.spkts + st.dpkts) / dur : 0.0;  // packets/sec

    // Timing: gaps stored in microseconds -> report milliseconds (UNSW units).
    double sinpkt = st.s_intpkt_n ? (st.s_intpkt_sum / st.s_intpkt_n) / 1000.0 : 0.0;
    double dinpkt = st.d_intpkt_n ? (st.d_intpkt_sum / st.d_intpkt_n) / 1000.0 : 0.0;
    double sjit   = st.s_jit_n ? (st.s_jit_sum / st.s_jit_n) / 1000.0 : 0.0;
    double djit   = st.d_jit_n ? (st.d_jit_sum / st.d_jit_n) / 1000.0 : 0.0;

    // Handshake RTT (seconds). Only set when the relevant packets were seen.
    double synack = (st.has_syn && st.has_synack)
                  ? (st.synack_ts - st.syn_ts) / 1e6 : 0.0;
    double ackdat = (st.has_synack && st.has_ack)
                  ? (st.ack_ts - st.synack_ts) / 1e6 : 0.0;
    double tcprtt = synack + ackdat;

    nlohmann::json j;
    j["srcip"]  = ip_to_string(st.init_ip);    // (debug; not a model feature)
    j["sport"]  = st.init_port;
    j["dstip"]  = ip_to_string(dst_ip);
    j["dsport"] = dst_port;
    j["proto"]  = proto_name(key.proto);
    j["dur"]    = dur;
    j["spkts"]  = st.spkts;
    j["dpkts"]  = st.dpkts;
    j["sbytes"] = st.sbytes;
    j["dbytes"] = st.dbytes;
    j["sttl"]   = st.sttl;
    j["dttl"]   = st.dttl;
    j["swin"]   = st.swin;
    j["dwin"]   = st.dwin;
    j["smean"]  = smean;
    j["dmean"]  = dmean;
    j["sload"]  = sload;
    j["dload"]  = dload;
    j["rate"]   = rate;
    j["sinpkt"] = sinpkt;
    j["dinpkt"] = dinpkt;
    j["sjit"]   = sjit;
    j["djit"]   = djit;
    j["synack"] = synack;
    j["ackdat"] = ackdat;
    j["tcprtt"] = tcprtt;
    return j;
}
