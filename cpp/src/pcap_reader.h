#pragma once

#include "packet.h"
#include <functional>

// Reads every packet from a pcap file and calls `on_packet` once per
// successfully-parsed IPv4 TCP/UDP/ICMP packet.
//
// `on_packet` is a std::function — think of it as a function pointer that can
// also carry captured state (see takeaways). The caller passes a lambda.
//
// Returns the number of packets parsed, or -1 on a fatal error
// (file not found, unsupported link-layer type).
long read_pcap(const char* path,
               const std::function<void(const Packet&)>& on_packet);
