#pragma once
#include <pcap.h>

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "rfmstat/channel_data.hpp"

namespace rfmstat {
class ChannelSniffer {
 public:
  ChannelSniffer(const uint8_t& channel, const std::string& iface, const uint64_t& timeout);
  ~ChannelSniffer();

  ChannelSniffer(const ChannelSniffer&) = delete;
  ChannelSniffer& operator=(const ChannelSniffer&) = delete;

  void start_sniff();
  void stop_sniff();
  void sniff_current_channel();

  bool is_sniffing() const { return _is_sniffing; }

  uint8_t channel = 0;
  std::string iface;

  uint64_t timeout;

  std::string errbuf() const { return std::string(_errbuf); }

  const std::array<rfmstat::ChannelData, 234>& channels_info() const {
    return _channels_info;
  }

  static void pcap_callback(u_char* user_data,
                            const struct pcap_pkthdr* packet_header,
                            const u_char* packet_bytes);
  void handle_packet(const struct pcap_pkthdr* header, const u_char* bytes);

 private:
  std::array<rfmstat::ChannelData, 234> _channels_info;

  char _errbuf[PCAP_ERRBUF_SIZE] = {0};
  bool _is_sniffing = false;
  pcap_t* _sniffer =
      nullptr;  // pcap_open_live(iface.c_str(), BUFSIZ, 1, 1000, errbuf);
};
}  // namespace rfmstat