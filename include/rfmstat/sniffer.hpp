#pragma once
#include <pcap.h>

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

namespace rfmstat {
class ChannelSniffer {
 public:
  ChannelSniffer(uint8_t channel, std::string iface);
  ~ChannelSniffer();

  void start_sniff(uint8_t channel = 0, std::string iface = std::string(""));
  void stop_sniff();
  void sniff_current_channel();

  bool is_sniffing() const { return _is_sniffing; }

  uint8_t channel;
  std::string iface;

  std::string errbuf() const { return std::string(_errbuf); }

  const std::array<std::pair<uint64_t,uint64_t>, 234>& channels_info() const {
    return _channels_info;
  }

  static void pcap_callback(u_char* user_data,
                            const struct pcap_pkthdr* packet_header,
                            const u_char* packet_bytes);
  void handle_packet(const struct pcap_pkthdr* header, const u_char* bytes);

 private:
  // PAIR: <uint64_t packets, uint64_t avg_packet_lenght>
  std::array<std::pair<uint64_t,uint64_t>, 234> _channels_info;

  uint64_t _timeout = 5000;

  uint64_t _packets = 0;
  uint64_t _len = 0;
  char _errbuf[PCAP_ERRBUF_SIZE] = {0};
  bool _is_sniffing = false;
  pcap_t* _sniffer =
      nullptr;  // pcap_open_live(iface.c_str(), BUFSIZ, 1, 1000, errbuf);
};
}  // namespace rfmstat