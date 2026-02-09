#include "rfmstat/utils.hpp"

#include <pcap.h>

#include <format>
#include <stdexcept>
#include <string>
namespace rfmstat {
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
