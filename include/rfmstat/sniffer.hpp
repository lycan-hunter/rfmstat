#pragma once
#include <pcap.h>

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <utility>

#include "rfmstat/channel_data.hpp"

namespace rfmstat {
class ChannelSniffer {
 public:
  ChannelSniffer(const uint8_t& channel, const std::string& iface,
                 const uint64_t& timeout);
  ~ChannelSniffer();

  ChannelSniffer(const ChannelSniffer&) = delete;
  ChannelSniffer& operator=(const ChannelSniffer&) = delete;

  void start_sniff();
  void stop_sniff();
  void sniff_current_channel();

  bool is_sniffing() const { return _is_sniffing; }

  uint8_t channel = 0;
  WiFiFreqs freq_type = WiFiFreqs::FREQ_24GHz;
  std::string iface;

  uint32_t timeout;

  std::string errbuf() const { return std::string(_errbuf); }

  const std::vector<ChannelData>& channels_info(const WiFiFreqs& ftype) const {
    if (ftype == WiFiFreqs::FREQ_24GHz){
    return _channels_info_24;
  } else if (ftype == WiFiFreqs::FREQ_5GHz){

    return _channels_info_5;
  } else if (ftype == WiFiFreqs::FREQ_6GHz){

    return _channels_info_6;
  } else {
    throw std::invalid_argument("Cannot get channels info for, incorrect freq type");
  }
}

 private:
  static void pcap_callback(u_char* user_data,
                            const struct pcap_pkthdr* packet_header,
                            const u_char* packet_bytes);
  void handle_packet(const struct pcap_pkthdr* header, const u_char* bytes);

  std::vector<ChannelData>& _get_mut_channels_info() {
     if (freq_type == WiFiFreqs::FREQ_24GHz){
    return _channels_info_24;
  } else if (freq_type == WiFiFreqs::FREQ_5GHz){

    return _channels_info_5;
  } else if (freq_type == WiFiFreqs::FREQ_6GHz){
    return _channels_info_6;
  } else {
    throw std::invalid_argument("Cannot get channels info for, incorrect freq type");
  } 
  }
  
  std::vector<ChannelData> _channels_info_24;
  std::vector<ChannelData> _channels_info_5;
  std::vector<ChannelData> _channels_info_6;
  


  char _errbuf[PCAP_ERRBUF_SIZE] = {0};
  bool _is_sniffing = false;
  pcap_t* _sniffer =
      nullptr;  // pcap_open_live(iface.c_str(), BUFSIZ, 1, 1000, errbuf);
};
}  // namespace rfmstat