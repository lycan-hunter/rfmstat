#include <pcap.h>

#include <CLI/CLI.hpp>
#include <iostream>

int main(int argc, char** argv) {
  CLI::App app{"RFMstat -- Wi-Fi statistics collector"};

  std::string interface = "wlan0";
  uint8_t channels = 14;

  app.add_option("-i,--iface", interface, "Network interface to sniff");
  app.add_option("-c,--channels", channels, "Quantity of available channels");

  CLI11_PARSE(app, argc, argv);

  if (handle == nullptr) {
    std::cerr << "Couldn't open device: " << errbuf << std::endl;
    return 1;
  }

  for (int i = 1; i <= channels; i++) {
    std::cout << "Monitoring on channel " << i << " of " << channels
              << std::endl;
  }

  std::cout << "Sniffing on interface: " << interface << std::endl;
  pcap_close(handle);
  return 0;
}
