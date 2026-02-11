#include "rfmstat/utils.hpp"
#include "rfmstat/channel_data.hpp"

#include <pcap.h>

#include <format>
#include <regex>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace rfmstat {

std::vector<uint8_t> parse_raw_channels(const std::string& input) {
    if (input.empty()) {
        throw std::invalid_argument("Empty channel list");
    }

    static const std::regex full_check_re(R"(^[\d,\-\s]+$)");
    if (!std::regex_match(input, full_check_re)) {
        throw std::invalid_argument("Invalid characters in string: " + input);
    }

    std::set<uint8_t> unique_channels;
    static const std::regex part_re(R"((\d+)(?:-(\d+))?)");
    
    auto it = std::sregex_iterator(input.begin(), input.end(), part_re);
    auto end = std::sregex_iterator();

    if (it == end) {
        throw std::invalid_argument("No valid channels found in: " + input);
    }

    for (; it != end; ++it) {
        std::smatch match = *it;
        
        try {
            int start = std::stoi(match[1].str());
            
            if (match[2].matched) { 
                int stop = std::stoi(match[2].str());
                
                if (start > stop) {
                    throw std::invalid_argument("Reverse range not allowed: " + match.str());
                }
                if (stop > 255) throw std::out_of_range("");

                for (int i = start; i <= stop; ++i) {
                    unique_channels.insert(static_cast<uint8_t>(i));
                }
            } else {
                if (start > 255) throw std::out_of_range("");
                unique_channels.insert(static_cast<uint8_t>(start));
            }
        } catch (const std::out_of_range&) {
            throw std::invalid_argument("Channel number out of range (0-255): " + match.str());
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

uint32_t channel_to_mhz(const uint8_t channel, const rfmstat::WiFiFreqs& freq) {
    switch (freq) {
        case rfmstat::WiFiFreqs::FREQ_24GHz:
            if (channel >= 1 && channel <= 13) {
                return 2407 + (channel * 5);
            }
            if (channel == 14) {
                return 2484;
            }
            break;

        case rfmstat::WiFiFreqs::FREQ_5GHz:
            if (channel >= 32 && channel <= 177) {
                return 5000 + (channel * 5);
            }
            break;

        case rfmstat::WiFiFreqs::FREQ_6GHz:
            if (channel >= 1 && channel <= 233) {
                return 5940 + (channel * 5);
            }
            break;
    }
    throw std::invalid_argument(
        std::format("Invalid Wi-Fi channel {} for the selected band", channel)
    );
}


}  // namespace rfmstat
