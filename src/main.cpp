#include <pcap.h>
#include <CLI/CLI.hpp>
#include <iostream>

int main(int argc, char** argv) {
  CLI::App app{"Packet Sniffer using libpcap"};

  std::string interface = "eth0";
  app.add_option("-i,--interface", interface, "Network interface to sniff");

  CLI11_PARSE(app, argc, argv);

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);

  if (handle == nullptr) {
    std::cerr << "Couldn't open device: " << errbuf << std::endl;
    return 1;
  }

  std::cout << "Sniffing on interface: " << interface << std::endl;
  pcap_close(handle);
  return 0;
}
