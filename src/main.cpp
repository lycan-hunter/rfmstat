// TODO: Catching exception: operation not permitted, invalid channel and
// other...
#include <pcap.h>

#include <CLI/CLI.hpp>
#include <array>
#include <chrono>
#include <format>
#include <iostream>
#include <memory>
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
                     "Incorrect channels range '{}', format: from 1 to 233",
                     channels)
              << std::endl;
    return 1;
  }

  // Validating timeout
  if (timeout == 0) {
    std::cerr << std::format("Timeout can not be '{}'", timeout) << std::endl;
    return 1;
  }

  std::unique_ptr<rfmstat::IfaceDev> iface_dev = nullptr;
  std::unique_ptr<rfmstat::ChannelSniffer> sniffer =
      std::make_unique<rfmstat::ChannelSniffer>(channels, iface, timeout);

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
    std::cerr << e.what() << ": ballast was worked ! Delete 118 and 119 strings in main.cpp" << std::endl;
    return 1;
  }

  for (int i = 0; i < channels; i++) {
    sniffer->channel = i;
    uint32_t mhz_channel = 0;
    try {
      mhz_channel = rfmstat::channel_to_mhz(i + 1);
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
      if (i == 0){
      std::cerr << std::format("{}, try run with root rights (sudo)", e.what())
                << std::endl;

      } else {
      std::cerr << std::endl << std::format("{}, try run with root rights (sudo)", e.what());
      }
      break;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    sniffer->sniff_current_channel();
  }
  std::cerr << std::endl;

  for (int i = 0; i < channels; i++) {
    const auto& cinfo = sniffer->channels_info()[i];
    if (cinfo.packets == 0) {
      hidden_channels++;
      continue;
    } else {
      uint32_t freq_mhz = 0;
      try {
        freq_mhz = rfmstat::channel_to_mhz(i + 1);
      } catch (std::invalid_argument& e) {
        hidden_channels++;
        continue;
      }
      std::cout << std::format("Channel {:>2} ({:4} MHz) report:", i + 1,
                               freq_mhz)
                << std::endl;
      std::cout << rfmstat::get_channel_audit(sniffer->channels_info()[i],
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
