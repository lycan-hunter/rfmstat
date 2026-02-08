#pragma once

#include <pcap.h>

#include <string>
namespace rfmstat {
bool interface_exists(const std::string& iface);

uint32_t channel_to_mhz(const uint8_t& channel);

}  // namespace rfmstat
