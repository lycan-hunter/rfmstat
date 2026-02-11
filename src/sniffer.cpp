#include "rfmstat/sniffer.hpp"

#include <chrono>
#include <format>
#include <iostream>
#include <stdexcept>
#include <thread>

#include "rfmstat/channel_data.hpp"
#include "rfmstat/formatter.hpp"
#include "rfmstat/utils.hpp"

namespace rfmstat {
ChannelSniffer::ChannelSniffer(const uint8_t& channel, const std::string& iface,
                               const uint64_t& timeout, bool verbose)
    : _channels_info_24(256), _channels_info_5(256), _channels_info_6(256) {
  if (channel > 233) {
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
  this->verbose = verbose;
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

void ChannelSniffer::handle_packet(const struct pcap_pkthdr* header,
                                   const u_char* bytes) {
  // std::cout << '.' << std::endl;
  uint16_t rt_len = *(uint16_t*)(bytes + 2);
  if (header->caplen < (uint32_t)rt_len + 1) return;

  const u_char* wlan_frame = bytes + rt_len;
  uint8_t type_subtype = (wlan_frame[0] >> 2);
  FrameType frame = static_cast<FrameType>(type_subtype);

  auto& current_channels_info = _get_mut_channels_info();
  auto& stats = current_channels_info[this->channel];

  current_channels_info[this->channel].packets++;
  current_channels_info[this->channel].length += header->len;

  switch (frame) {
    // --- Management ---
    case FrameType::MgmtBeacon:
      stats.mgmt_beacon++;
      break;
    case FrameType::MgmtAssocReq:
      stats.mgmt_assoc++;
      break;
    case FrameType::MgmtAuth:
      stats.mgmt_auth++;
      break;
    case FrameType::MgmtProbeReq:
      stats.mgmt_probe_req++;
      break;
    case FrameType::MgmtDeauth:
      stats.mgmt_deauth++;
      break;
    case FrameType::MgmtProbeRes:
      stats.mgmt_probe_res++;
      break;
    case FrameType::MgmtAction:
      stats.mgmt_action++;
      break;

    // --- Control ---
    case FrameType::CtrlRTS:
      stats.ctrl_rts++;
      break;
    case FrameType::CtrlCTS:
      stats.ctrl_cts++;
      break;
    case FrameType::CtrlAck:
      stats.ctrl_ack++;
      break;
    case FrameType::CtrlBA:
      stats.ctrl_ba++;
      break;
    case FrameType::CtrlBA_Req:
      stats.ctrl_ba_req++;
      break;

    // --- Data ---
    case FrameType::DataPlain:
      stats.data_plain++;
      break;
    case FrameType::DataQoS:
      stats.data_qos++;
      break;
    case FrameType::DataNull:
      stats.data_null++;
      break;

    default:
      stats.unknown++;
      break;
  }
}

void ChannelSniffer::sniff_current_channel() {
  if (!_is_sniffing) {
    throw std::runtime_error(
        "Sniffer does not exist, start it before sniffing");
  }

  auto start = std::chrono::steady_clock::now();
  auto& current_channels_info = _get_mut_channels_info();
  current_channels_info[channel].ballast_channel = false;

  while (true) {
    auto now = std::chrono::steady_clock::now();
    auto elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(now - start);

    if (elapsed.count() >= timeout) break;

    pcap_dispatch(_sniffer, -1, ChannelSniffer::pcap_callback,
                  reinterpret_cast<u_char*>(this));

    double seconds = elapsed.count() / 1000.0;
    double current_pps = 0.0;

    if (seconds > 0.01) {
      current_pps =
          static_cast<double>(current_channels_info[channel].packets) / seconds;
    }

    uint32_t freq_mhz = rfmstat::channel_to_mhz(channel, freq_type);
    if (verbose) {
      std::cerr << "\r"
                << std::format(
                       "Monitoring on {:>2} channel ({} MHz), at {} {:<30}",
                       channel, freq_mhz, iface,
                       rfmstat::get_channel_rate(current_pps, freq_mhz))
                << std::flush;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
}

}  // namespace rfmstat
