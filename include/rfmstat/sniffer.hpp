#pragma once
#include <pcap.h>

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <pair>

namespace rfmstat {
class ChannelSniffer {
 public:
  ChannelSniffer(uint8_t channel, std::string iface);
  ~ChannelSniffer();

  void start_sniff(uint8_t channel = 0, std::string iface = std::string(""));
  void stop_sniff();
  void summing_pps();

  bool is_sniffing() const { return _is_sniffing; }

  uint8_t channel;
  std::string iface;
  //   uint64_t pps() const { return &_pps; }
  std::string errbuf() const { return std::string(_errbuf); }

  const std::array<uint64_t, 234>& channels_pps() const {
    return _channels_info;
  }

  static void pcap_callback(u_char* user_data,
                            const struct pcap_pkthdr* packet_header,
                            const u_char* packet_bytes);
  void handle_packet(const struct pcap_pkthdr* header, const u_char* bytes);

 private:
  std::array<uint64_t, 234> _channels_info;
  uint64_t _pps = 0;
  char _errbuf[PCAP_ERRBUF_SIZE] = {0};
  bool _is_sniffing = false;
  pcap_t* _sniffer =
      nullptr;  // pcap_open_live(iface.c_str(), BUFSIZ, 1, 1000, errbuf);
};
}  // namespace rfmstat