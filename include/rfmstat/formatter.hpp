#pragma once
#include <cstdint>
#include <sstream>
#include <string>

#include "rfmstat/channel_data.hpp"

namespace rfmstat {
std::string get_channel_rate(const double& pps, const uint32_t& freq_mhz);

std::string get_channel_audit(const ChannelData& d, const uint32_t& timeout);

}  // namespace rfmstat
