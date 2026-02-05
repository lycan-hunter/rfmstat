#pragma once
#include <pcap.h>

#include <cstdint>
#include <string>

namespace rfmstat {
class ChannelSniffer {
 public:
  uint64_t get_pps();
  bool start_sniff();
  bool stop_sniff();
  uint64_t _pps;
  uint8_t _channel;
  std::string _iface;

 private:
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle =
      nullptr;  // pcap_open_live(iface.c_str(), BUFSIZ, 1, 1000, errbuf);

  ChannelSniffer();
  ~ChannelSniffer();
};
}  // namespace rfmstat