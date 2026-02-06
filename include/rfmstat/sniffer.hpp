#pragma once
#include <pcap.h>

#include <cstdint>
#include <memory>
#include <string>
#include <array>

namespace rfmstat {
class ChannelSniffer {
 public:
  ChannelSniffer(uint8_t channel, std::string iface);
  ~ChannelSniffer();

  void start_sniff(uint8_t channel = 0, std::string iface = std::string(""));
  void stop_sniff();

  bool is_sniffing() const { return _is_sniffing; }

  uint8_t channel;
  std::string iface;
  //   uint64_t pps() const { return &_pps; }
  std::string errbuf() const { return std::string(_errbuf); }

  const std::array<uint64_t, 234>& channels_pps() const {
    return _channels_pps;
  }

 private:
  std::array<uint64_t, 234> _channels_pps;
  uint64_t _pps = 0;
  char _errbuf[PCAP_ERRBUF_SIZE] = {0};
  bool _is_sniffing = false;
  pcap_t* _sniffer =
      nullptr;  // pcap_open_live(iface.c_str(), BUFSIZ, 1, 1000, errbuf);
};
}  // namespace rfmstat