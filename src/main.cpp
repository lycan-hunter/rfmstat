// TODO: Wright channles parser, man info and README.md
#include <pcap.h>

#ifndef _WIN32
#include <unistd.h>
#endif

#include <CLI/CLI.hpp>
#include <algorithm>
#include <array>
#include <chrono>
#include <format>
#include <iostream>
#include <memory>
#include <thread>
#include <utility>

#include "rfmstat/banner.hpp"
#include "rfmstat/formatter.hpp"
#include "rfmstat/iface_device.hpp"
#include "rfmstat/sniffer.hpp"
#include "rfmstat/utils.hpp"

int main(int argc, char** argv) {
  char errbuf[PCAP_ERRBUF_SIZE];

  CLI::App app{"RFMstat -- Wi-Fi broadcast passive statistics collector"};

  std::string iface = "";
  std::string raw_channels_24;
  std::string raw_channels_5;
  std::string raw_channels_6;

  std::vector<rfmstat::ChannelRange> channels;
  channels[0].freq = rfmstat::WiFiFreqs::FREQ_24GHz;
  channels[1].freq = rfmstat::WiFiFreqs::FREQ_5GHz;
  channels[2].freq = rfmstat::WiFiFreqs::FREQ_6GHz;

  uint32_t timeout = 5000;

  app.add_option("-i,--iface", iface, "Network interface to monitor");
  app.add_option("-2,--2_4ghz", raw_channels_24,
                 "Range of channels to scan (2.4 GHz)");
  app.add_option("-5,--5ghz", raw_channels_5,
                 "Range of channels to scan (5 GHz)");
  app.add_option("-6,--6ghz", raw_channels_6,
                 "Range of channels to scan (6 GHz)");
  app.add_option("-t,--timeout", timeout, "Dwell time per channel (ms)");

  for (int i = 1; i < argc; ++i) {
    if (std::string(argv[i]) == "-h" || std::string(argv[i]) == "--help") {
      std::cerr << kBanner << std::endl;
      break;
    }
  }

  CLI11_PARSE(app, argc, argv);

  // Validating iface
  pcap_if_t* ifaces_list = nullptr;

  int res = pcap_findalldevs(&ifaces_list, errbuf);

  if (res == 0 && ifaces_list != nullptr) {
    bool is_iface_valid = false;

    if (iface.empty()) {
      iface = ifaces_list->name;
      is_iface_valid = true;
    }
    for (pcap_if_t* current = ifaces_list; current != nullptr;
         current = current->next) {
      if (std::string(current->name) == iface) {
        is_iface_valid = true;
        break;
      }
    }
    pcap_freealldevs(ifaces_list);

    if (!is_iface_valid) {
      std::cerr << std::format("Failed to locate interface '{}' in system",
                               iface)
                << std::endl;
      return 1;
    }
  }

  // Parsing channels
  channels[0].channels_range = rfmstat::parse_raw_channels(raw_channels_24);
  channels[1].channels_range = rfmstat::parse_raw_channels(raw_channels_5);
  channels[2].channels_range = rfmstat::parse_raw_channels(raw_channels_6);

  // Validating channels
  if (!std::includes(rfmstat::kCh2_4GHz.begin(), rfmstat::kCh2_4GHz.end(),
                     channels.begin(), channels.end())) {
    std::cerr << "Incorrect 6GHz channels range" << std::endl;
    return 1;
  }
  if (!std::includes(rfmstat::kCh5GHz.begin(), rfmstat::kCh5GHz.end(),
                     channels.begin(), channels.end())) {
    std::cerr << "Incorrect 6GHz channels range" << std::endl;
    return 1;
  }
  if (!std::includes(rfmstat::kCh6GHz.begin(), rfmstat::kCh6GHz.end(),
                     channels.begin(), channels.end())) {
    std::cerr << "Incorrect 6GHz channels range" << std::endl;
    return 1;
  }

  // Validating timeout
  if (timeout == 0) {
    std::cerr << std::format("Timeout can not be '{}'", timeout) << std::endl;
    return 1;
  }

  std::unique_ptr<rfmstat::IfaceDev> iface_dev = nullptr;
  std::unique_ptr<rfmstat::ChannelSniffer> sniffer =
      std::make_unique<rfmstat::ChannelSniffer>(1, iface, timeout);

// Hint
#ifndef _WIN32
  const std::string kHint =
      geteuid() == 0 ? "" : ", try run with root rights (sudo)";
#endif

#ifdef _WIN32
  const std::string kHint = ", try run with admin rights";
#endif

  try {
    iface_dev = std::make_unique<rfmstat::IfaceDev>();
  } catch (std::runtime_error& e) {
    std::cerr << e.what() << std::endl;
    return 1;
  }

  iface_dev->if_index = iface_dev->get_if_index(iface);
  if (!iface_dev->is_rfmon()) {
    std::cerr << std::format(
                     "Current Wi-Fi adapter ({}) is not in monitore mode",
                     iface)
              << std::endl;
    return 1;
  }

  try {
    sniffer->start_sniff();
    if (!sniffer->is_sniffing()) {
      std::cerr << "Failed to create sniffer" << std::endl;
      return 1;
    }
  } catch (std::exception& e) {
    std::cerr << std::format("Failed to start sniffing: {}", e.what())
              << std::endl;
  }

  uint64_t hidden_channels = 0;
  uint64_t incorrect_channels = 0;
  try {
    // For some reason, the first channel change call is ignored, so ballast has
    // been added
    iface_dev->set_rfmon_channel(rfmstat::channel_to_mhz(1));
  } catch (std::exception& e) {
    std::cerr << e.what()
              << ": ballast was worked ! Delete 118 and 119 strings in main.cpp"
              << std::endl;
    return 1;
  }

  for (auto ch : channels) {
    sniffer->channel = ch - 1;
    uint32_t mhz_channel = 0;
    try {
      mhz_channel = rfmstat::channel_to_mhz(ch);
    } catch (std::invalid_argument& e) {
      std::cerr << "\r" << e.what()
                << "                                           ";
      ++incorrect_channels;
      continue;
    }

    // Trying to change channel
    try {
      iface_dev->set_rfmon_channel(mhz_channel);
    } catch (const std::runtime_error& e) {
      if (ch == 1) {
        std::cerr << std::format("{}{}", e.what(), kHint) << std::endl;

      } else {
        std::cerr << std::endl << std::format("{}{}", e.what(), kHint);
      }
      break;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    sniffer->sniff_current_channel();
  }
  std::cerr << std::endl;

  for (auto ch : channels) {
    const auto& cinfo = sniffer->channels_info()[ch - 1];
    if (cinfo.packets == 0) {
      hidden_channels++;
      continue;
    } else {
      uint32_t freq_mhz = 0;
      try {
        freq_mhz = rfmstat::channel_to_mhz(ch);
      } catch (std::invalid_argument& e) {
        hidden_channels++;
        continue;
      }
      std::cout << std::format("Channel {:>2} ({:4} MHz) report:", ch, freq_mhz)
                << std::endl;
      std::cout << rfmstat::get_channel_audit(sniffer->channels_info()[ch - 1],
                                              timeout)
                << std::endl;
    }
  }

  if (hidden_channels - incorrect_channels > 0) {
    std::cout << std::format("{} channel(s) hidden, (no packets captured)",
                             hidden_channels - incorrect_channels)
              << std::endl;
  }
  return 0;
}
