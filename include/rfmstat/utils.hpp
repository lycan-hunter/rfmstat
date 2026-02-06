#pragma once

#include <pcap.h>

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

}  // namespace rfmstat
