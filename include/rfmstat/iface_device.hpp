#pragma once
#include <cstdint>
#include <string>

struct nl_sock;

namespace rfmstat {
class IfaceDev {
 public:
  IfaceDev();
  ~IfaceDev();

  IfaceDev(const IfaceDev&) = delete;
  IfaceDev& operator=(const IfaceDev&) = delete;

  const uint8_t& current_channel() const { return _current_channel; };
  void set_rfmon_channel(const uint32_t& freq_mhz);
  uint32_t if_index = 0;
  bool is_rfmon();

  uint32_t get_if_index(const std::string& iface);

 private:
  uint8_t _current_channel = 0;
  struct nl_sock* _sk = nullptr;
  int _nl80211_id = -1;
};
}  // namespace rfmstat
