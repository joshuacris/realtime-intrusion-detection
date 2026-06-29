#pragma once

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <algorithm>

// The canonical model-input contract: a fixed 58-feature vector (21 one-hot
// columns + 37 raw numerics). Tree models split on raw thresholds, so no scaling.
// If this order disagrees with the order the model was trained/exported with,
// every prediction is silently wrong — this is the single source of truth, and
// the ONNX export must reuse these exact lists. Ordering matches preprocessing.py
// (get_dummies / Index.difference produce categories alphabetically).
namespace ids::schema {

// "Top" categories kept as-is; anything else collapses to "other".
inline const std::vector<std::string> PROTO_TOP{
    "tcp", "udp", "unas", "arp", "ospf", "sctp"};
inline const std::vector<std::string> SERVICE_TOP{
    "-", "http", "dns", "smtp", "ftp-data", "ftp", "ssh", "pop3"};
inline const std::vector<std::string> STATE_TOP{
    "FIN", "INT", "CON", "REQ"};

// One-hot column order = bucket categories sorted alphabetically (incl. "other").
inline const std::vector<std::string> PROTO_OHE{
    "arp", "ospf", "other", "sctp", "tcp", "udp", "unas"};                  // 7
inline const std::vector<std::string> SERVICE_OHE{
    "-", "dns", "ftp", "ftp-data", "http", "other", "pop3", "smtp", "ssh"}; // 9
inline const std::vector<std::string> STATE_OHE{
    "CON", "FIN", "INT", "REQ", "other"};                                   // 5

// The 37 raw numeric features, alphabetical (matches Index.difference order).
inline const std::vector<std::string> NUM_COLS{
    "ackdat", "ct_dst_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
    "ct_flw_http_mthd", "ct_ftp_cmd", "ct_src_dport_ltm", "ct_src_ltm",
    "ct_srv_dst", "ct_srv_src", "ct_state_ttl", "dbytes", "dinpkt", "djit",
    "dload", "dloss", "dmean", "dpkts", "dttl", "dur", "dwin", "is_ftp_login",
    "is_sm_ips_ports", "rate", "response_body_len", "sbytes", "sinpkt", "sjit",
    "sload", "sloss", "smean", "spkts", "sttl", "swin", "synack", "tcprtt",
    "trans_depth"};                                                         // 37

inline constexpr std::size_t FEATURE_COUNT{7 + 9 + 5 + 37};   // 58

// Collapse a raw category to its bucket: keep if in `top`, else "other".
inline std::string bucket(const std::string& value,
                          const std::vector<std::string>& top) {
    return (std::find(top.begin(), top.end(), value) != top.end())
           ? value : "other";
}

// Turn one flow's JSON into the ordered 58-element feature vector.
inline std::vector<double> to_feature_vector(const nlohmann::json& flow) {
    std::vector<double> v;
    v.reserve(FEATURE_COUNT);

    const std::string pb{bucket(flow.value("proto", std::string("-")), PROTO_TOP)};
    for (const auto& c : PROTO_OHE)   v.push_back(pb == c ? 1.0 : 0.0);

    const std::string sb{bucket(flow.value("service", std::string("-")), SERVICE_TOP)};
    for (const auto& c : SERVICE_OHE) v.push_back(sb == c ? 1.0 : 0.0);

    const std::string tb{bucket(flow.value("state", std::string("-")), STATE_TOP)};
    for (const auto& c : STATE_OHE)   v.push_back(tb == c ? 1.0 : 0.0);

    for (const auto& name : NUM_COLS) v.push_back(flow.value(name, 0.0));

    return v;
}

}  // namespace ids::schema
