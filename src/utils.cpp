#include "rfmstat/utils.hpp"

#include <pcap.h>

#include <format>
#include <regex>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace rfmstat {

std::vector<uint8_t> parse_raw_channels(const std::string& input) {
    std::regex full_format_re(R"(^(\d+(-\d+)?)(,\s*\d+(-\d+)?)*$)");
    if (input.empty() || !std::regex_match(input, full_format_re)) {
        throw std::invalid_argument("Invalid format. Use: 1-11,13,14");
    }
    std::set<int> unique_channels;
    std::regex part_re(R"((\d+)(?:-(\d+))?)");
    
    auto it = std::sregex_iterator(input.begin(), input.end(), part_re);
    auto end = std::sregex_iterator();

    for (; it != end; ++it) {
        std::smatch match = *it;
        try {
            int start = std::stoi(match[1].str());
            
            if (match[2].matched) {
                int end_range = std::stoi(match[2].str());
                if (start > end_range) {
                    throw std::invalid_argument("Reverse range: " + match.str());
                }
                for (int i = start; i <= end_range; ++i) {
                    unique_channels.insert(i);
                }
            } else {
                unique_channels.insert(start);
            }
        } catch (const std::out_of_range&) {
            throw std::invalid_argument("Channel number out of integer range");
        }
    }
    return {unique_channels.begin(), unique_channels.end()};
}

bool interface_exists(const std::string& iface) {
  pcap_if_t* alldevs;
  char errbuf[PCAP_ERRBUF_SIZE];

  if (pcap_findalldevs(&alldevs, errbuf) == -1) return false;

  bool found = false;
  for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
    if (iface == d->name) {
      found = true;
      break;
    }
  }

  pcap_freealldevs(alldevs);
  return found;
}

uint32_t channel_to_mhz(const uint8_t& channel) {
  if (channel >= 1 && channel <= 13) return 2407 + (channel * 5);
  if (channel == 14) return 2484;
  if (channel >= 36 && channel <= 165) return 5000 + (channel * 5);

  throw std::invalid_argument(
      std::format("Invalid Wi-Fi channel: {}", std::to_string(channel)));
}

}  // namespace rfmstat
