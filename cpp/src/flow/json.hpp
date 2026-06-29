#pragma once

#include "flow/flow.hpp"
#include "flow/history.hpp"
#include <nlohmann/json.hpp>
#include <string>
#include <cstdio>

namespace ids {

inline std::string ip_to_string(uint32_t ip) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
        (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
    return std::string(buf);
}

inline const char* proto_name(uint8_t proto) {
    switch (proto) {
        case 6:  return "tcp";
        case 17: return "udp";
        case 1:  return "icmp";
        default: return "other";
    }
}

// Argus-style connection state, approximated from observed flags. Labels match
// the model's one-hot buckets (FIN/INT/CON/REQ; everything else -> "other").
inline const char* flow_state_label(const FlowKey& key, const FlowState& st) {
    if (key.proto == 6) {
        if ((st.s_flags | st.d_flags) & TCP_RST) return "RST";
        if ((st.s_flags & TCP_FIN) && (st.d_flags & TCP_FIN)) return "FIN";
        if (st.dpkts == 0)   return "INT";   // initiated, never answered
        if (st.has_synack)   return "CON";   // handshake completed
        return "REQ";
    }
    if (key.proto == 17) {
        return (st.spkts > 0 && st.dpkts > 0) ? "CON" : "INT";
    }
    return "ECO";   // ICMP -> "other" bucket downstream
}

// Application service approximated from the well-known port (UNSW used Bro DPI).
inline const char* service_name(uint16_t a, uint16_t b) {
    for (uint16_t port : {a, b}) {
        switch (port) {
            case 80: case 8080: return "http";
            case 53:            return "dns";
            case 25:            return "smtp";
            case 20:            return "ftp-data";
            case 21:            return "ftp";
            case 22:            return "ssh";
            case 110:           return "pop3";
            default: break;
        }
    }
    return "-";
}

// Serialize one completed flow using UNSW feature field names so it lines up
// with the model's expected inputs downstream.
inline nlohmann::json flow_to_json(const FlowKey& key, const FlowState& st,
                                   const CtFeatures& ct) {
    uint32_t dst_ip;
    uint16_t dst_port;
    if (st.init_ip == key.ip_a && st.init_port == key.port_a) {
        dst_ip = key.ip_b; dst_port = key.port_b;
    } else {
        dst_ip = key.ip_a; dst_port = key.port_a;
    }

    const double dur{(st.last_ts_us - st.first_ts_us) / 1e6};

    // Every division is guarded: a 1-packet or 0-duration flow must not divide by 0.
    const double smean{st.spkts ? static_cast<double>(st.sbytes) / st.spkts : 0.0};
    const double dmean{st.dpkts ? static_cast<double>(st.dbytes) / st.dpkts : 0.0};
    const double sload{dur > 0 ? st.sbytes * 8.0 / dur : 0.0};
    const double dload{dur > 0 ? st.dbytes * 8.0 / dur : 0.0};
    const double rate{dur > 0 ? (st.spkts + st.dpkts) / dur : 0.0};

    // Gaps are stored in microseconds; UNSW reports milliseconds.
    const double sinpkt{st.s_intpkt_n ? (st.s_intpkt_sum / st.s_intpkt_n) / 1000.0 : 0.0};
    const double dinpkt{st.d_intpkt_n ? (st.d_intpkt_sum / st.d_intpkt_n) / 1000.0 : 0.0};
    const double sjit{st.s_jit_n ? (st.s_jit_sum / st.s_jit_n) / 1000.0 : 0.0};
    const double djit{st.d_jit_n ? (st.d_jit_sum / st.d_jit_n) / 1000.0 : 0.0};

    const double synack{(st.has_syn && st.has_synack)
                      ? (st.synack_ts - st.syn_ts) / 1e6 : 0.0};
    const double ackdat{(st.has_synack && st.has_ack)
                      ? (st.ack_ts - st.synack_ts) / 1e6 : 0.0};
    const double tcprtt{synack + ackdat};

    nlohmann::json j;
    j["srcip"]  = ip_to_string(st.init_ip);   // debug only; not a model feature
    j["sport"]  = st.init_port;
    j["dstip"]  = ip_to_string(dst_ip);
    j["dsport"] = dst_port;
    j["proto"]  = proto_name(key.proto);
    j["state"]  = flow_state_label(key, st);
    j["service"] = service_name(st.init_port, dst_port);
    j["dur"]    = dur;
    j["sloss"]  = st.sloss;
    j["dloss"]  = st.dloss;
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

    // Land-attack fingerprint: src and dst are the same endpoint.
    j["is_sm_ips_ports"] = (st.init_ip == dst_ip && st.init_port == dst_port) ? 1 : 0;

    j["ct_srv_src"]       = ct.ct_srv_src;
    j["ct_srv_dst"]       = ct.ct_srv_dst;
    j["ct_dst_ltm"]       = ct.ct_dst_ltm;
    j["ct_src_ltm"]       = ct.ct_src_ltm;
    j["ct_src_dport_ltm"] = ct.ct_src_dport_ltm;
    j["ct_dst_sport_ltm"] = ct.ct_dst_sport_ltm;
    j["ct_dst_src_ltm"]   = ct.ct_dst_src_ltm;
    j["ct_state_ttl"]     = ct.ct_state_ttl;

    // DPI stubs: need HTTP/FTP payload parsing (Bro did this for UNSW); 0 for the
    // overwhelming majority of flows until application-layer parsing is added.
    j["trans_depth"]       = 0;
    j["response_body_len"] = 0;
    j["ct_flw_http_mthd"]  = 0;
    j["is_ftp_login"]      = 0;
    j["ct_ftp_cmd"]        = 0;
    return j;
}

}  // namespace ids
