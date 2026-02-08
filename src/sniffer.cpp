#include "rfmstat/sniffer.hpp"

#include <chrono>
#include <format>
#include <iostream>
#include <stdexcept>
#include <thread>

#include "rfmstat/utils.hpp"

namespace rfmstat {
ChannelSniffer::ChannelSniffer(const uint8_t& channel, const std::string& iface,
                               const uint64_t& timeout) {
  if (channel == 0 || channel > 233) {
    throw std::invalid_argument(
        std::format("Incorrect channel specified ('{}') !", channel));
  }
  if (!interface_exists(iface)) {
    throw std::invalid_argument(
        std::format("Interface '{}' is not exists or not found !", iface));
  }
  this->timeout = timeout;
  this->iface = iface;
  this->channel = channel;
}

ChannelSniffer::~ChannelSniffer() {
  if (_is_sniffing) {
    ChannelSniffer::stop_sniff();
  }
}

void ChannelSniffer::start_sniff() {
  if (iface.empty()) {
    throw std::logic_error("No interface specified");
  }
  if (_is_sniffing) {
    throw std::runtime_error("Sniffer already exists, stop it before starting");
  }
  std::string _serrbuf;
  _sniffer = pcap_create(iface.c_str(), _errbuf);
  _serrbuf = std::string(_errbuf);
  if (!_serrbuf.empty()) {
    throw std::runtime_error(
        std::format("Failed to create sniffer: {}", _serrbuf));
  }

  pcap_set_snaplen(_sniffer, BUFSIZ);
  pcap_set_promisc(_sniffer, 1);
  pcap_set_timeout(_sniffer, 1);
  pcap_set_immediate_mode(_sniffer, 1);
  pcap_setnonblock(_sniffer, 1, _errbuf);
  _serrbuf = std::string(_errbuf);
  if (!_serrbuf.empty()) {
    throw std::runtime_error(
        std::format("Failed to set sniffer unblock: {}", _serrbuf));
  }
  pcap_activate(_sniffer);

  _is_sniffing = _sniffer != nullptr ? true : false;
}

void ChannelSniffer::stop_sniff() {
  if (!_is_sniffing) {
    throw std::runtime_error("Sniffer is not exists, start it before stopping");
  } else {
    pcap_breakloop(_sniffer);
    pcap_close(_sniffer);
    _sniffer = nullptr;
    _is_sniffing = false;
  }
}

void ChannelSniffer::pcap_callback(u_char* user_data,
                                   const struct pcap_pkthdr* packet_header,
                                   const u_char* packet_bytes) {
  auto* sniffer = reinterpret_cast<ChannelSniffer*>(user_data);

  sniffer->handle_packet(packet_header, packet_bytes);
}

void ChannelSniffer::handle_packet(const struct pcap_pkthdr* header, const u_char* bytes) {
    std::cout << '.' << std::endl;
    uint16_t rt_len = *(uint16_t*)(bytes + 2);
    if (header->caplen < (uint32_t)rt_len + 1) return;

    const u_char* wlan_frame = bytes + rt_len;
    uint8_t fc = wlan_frame[0];

    FrameType frame = static_cast<FrameType>(fc & 0xFC);

    auto& stats = _channels_info[this->channel];

    _channels_info[this->channel].packets++;
    _channels_info[this->channel].length += header->len;


    switch (frame) {
        // --- Management ---
        case FrameType::MgmtBeacon:     stats.mgmt_beacon++; break;
        case FrameType::MgmtAssocReq:   stats.mgmt_assoc++; break;
        case FrameType::MgmtAuth:       stats.mgmt_auth++; break;
        case FrameType::MgmtProbeReq:   stats.mgmt_probe_req++; break;
        case FrameType::MgmtDeauth:     stats.mgmt_deauth++; break;

        // --- Control ---
        case FrameType::CtrlRTS:        stats.ctrl_rts++; break;
        case FrameType::CtrlCTS:        stats.ctrl_cts++; break;
        case FrameType::CtrlAck:        stats.ctrl_ack++; break;

        // --- Data ---
        case FrameType::DataPlain:      stats.data_plain++; break;
        case FrameType::DataQoS:        stats.data_qos++; break;
        case FrameType::DataNull:       stats.data_null++; break;

        default:
            stats.unknown++;
            break;
    }
}


void ChannelSniffer::sniff_current_channel() {
  if (!_is_sniffing) {
    throw std::runtime_error(
        "Sniffer is not exists, start it before summing up info");
  }
  auto start = std::chrono::steady_clock::now();
  std::cout << std::format("Sniffing {}@{}", channel, iface) << std::endl;
  while (std::chrono::steady_clock::now() - start <
         std::chrono::milliseconds(timeout)) {
    pcap_dispatch(_sniffer, -1, ChannelSniffer::pcap_callback,
                  reinterpret_cast<u_char*>(this));

    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
}

}  // namespace rfmstat
