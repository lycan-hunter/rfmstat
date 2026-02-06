#include <pcap.h>

#include <CLI/CLI.hpp>
#include <format>
#include <iostream>
#include <chrono>

#include "rfmstat/sniffer.hpp"

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
      std::cerr << std::format("Failed to locale interface '{}' in system",
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

  for (int i = 1; i <= channels; i++) {
    std::cout << std::format("Monitoring on channel {}, interface {}", i, iface)
              << std::endl;
  }
  return 0;
}
