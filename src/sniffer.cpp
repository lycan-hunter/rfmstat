#include "rfmstat/sniffer.hpp"

#include <format>
#include <iostream>
#include <stdexcept>

#include "rfmstat/utils.hpp"

namespace rfmstat {
ChannelSniffer::ChannelSniffer(uint8_t channel, std::string iface) {
  if (channel == 0 || channel > 233) {
    throw std::invalid_argument(
        std::format("Incorrect channel specified ('{}') !", channel));
  }
  if (!interface_exists(iface)) {
    throw std::invalid_argument(
        std::format("Interface '{}' is not exists or not found !", iface));
  }
  _channels_info.fill(0);
}

ChannelSniffer::~ChannelSniffer() {
  if (_is_sniffing) {
    ChannelSniffer::stop_sniff();
  }
}

void ChannelSniffer::start_sniff(uint8_t channel, std::string iface) {
  if (channel == 0) {
    channel = this->channel;
  }
  if (iface.empty()) {
    iface = this->iface;
  }
  if (_is_sniffing) {
    throw std::runtime_error("Sniffer already exists, stop it before starting");
  }
  _sniffer = pcap_open_live(iface.c_str(), BUFSIZ, 1, 5, _errbuf);
  _is_sniffing = true;
}

void ChannelSniffer::stop_sniff() {
  if (!_is_sniffing) {
    throw std::runtime_error("Sniffer is not exists, start it before stopping");
  } else {
    pcap_breakloop(_sniffer);
    pcap_close(_sniffer);
    _sniffer = nullptr;
  }
}

void ChannelSniffer::pcap_callback(u_char* user_data,
                                   const struct pcap_pkthdr* packet_header,
                                   const u_char* packet_bytes) {
  auto* sniffer = reinterpret_cast<ChannelSniffer*>(user_data);

  sniffer->handle_packet(packet_header, packet_bytes);
}

void ChannelSniffer::handle_packet(const struct pcap_pkthdr* header,
                                   const u_char* bytes) {}

void ChannelSniffer::summing_pps() {
  if (!_is_sniffing) {
    throw std::runtime_error("Sniffer is not exists, start it before stopping");
  }
}

}  // namespace rfmstat
