//TODO: Catching exception: operation not permitted, invalid channel and other...
#include <pcap.h>
#include <CLI/CLI.hpp>
#include <array>
#include <chrono>
#include <format>
#include <iostream>
#include <thread>
#include <utility>

#include "rfmstat/formatter.hpp"
#include "rfmstat/iface_device.hpp"
#include "rfmstat/sniffer.hpp"
#include "rfmstat/utils.hpp"

int main(int argc, char** argv) {
  char errbuf[PCAP_ERRBUF_SIZE];

  CLI::App app{"RFMstat -- Wi-Fi statistics collector"};

  std::string iface = "";
  uint8_t channels = 14;
  uint32_t timeout = 5000;

  app.add_option("-i,--iface", iface, "Network interface to sniff");
  app.add_option("-c,--channels", channels, "Quantity of available channels");
  app.add_option("-t,--timeout", timeout,
                 "Timeout in milliseconds to sniff every channel");

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

  // Validating channels
  if (channels == 0 || channels > 233) {
    std::cerr << std::format(
                     "Incorrect channels range ('{}'), format: from 1 to 233",
                     channels)
              << std::endl;
    return 1;
  }

  // Validating timeout
  if (timeout == 0) {
    std::cerr << std::format("Timeout can not be '{}'", timeout) << std::endl;
    return 1;
  }

  rfmstat::IfaceDev iface_dev;
  iface_dev.if_index = iface_dev.get_if_index(iface);
  if (!iface_dev.is_rfmon()) {
    std::cerr << std::format(
                     "Current Wi-Fi adapter ({}) is not in monitore mode",
                     iface)
              << std::endl;
    return 1;
  }

  rfmstat::ChannelSniffer sniffer(channels, iface, timeout);

  // sniffer.channel = channels;
  try {
    sniffer.start_sniff();
    if (!sniffer.is_sniffing())
      throw std::runtime_error("failed to create sniffer");
  } catch (std::exception& e) {
    std::cerr << std::format("Failed to start sniffing: {}", e.what())
              << std::endl;
  }

  uint64_t hidden_channels = 0;

  for (int i = 0; i < channels; i++) {
    // std::cout << std::format("Monitoring on channel {}, interface {}", i,
    // iface)
    // << std::endl;
    sniffer.channel = i;
    uint32_t mhz_channel = rfmstat::channel_to_mhz(i + 1);
    iface_dev.set_rfmon_channel(mhz_channel);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    // TODO: final with incorrect channel exception
    try {
      sniffer.sniff_current_channel();
    } catch (std::invalid_argument& e) {
      std::cerr << e.what() << std::endl;
    }
  }
  std::cerr << std::endl;

  for (int i = 0; i < channels; i++) {
    const auto& cinfo = sniffer.channels_info()[i];
    if (cinfo.packets == 0) {
      hidden_channels++;
      continue;
    } else {
      uint32_t freq_mhz = rfmstat::channel_to_mhz(i + 1);
      std::cout << std::format("Channel {:>2} ({:4} MHz) report:", i + 1,
                               freq_mhz)
                << std::endl;
      std::cout << rfmstat::get_channel_audit(sniffer.channels_info()[i],
                                              timeout)
                << std::endl;
    }
  }

  if (hidden_channels > 0) {
    std::cout << std::format("{} channel(s) hidden, (no packets captured)",
                             hidden_channels)
              << std::endl;
  }
  return 0;
}
