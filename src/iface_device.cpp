#include "rfmstat/iface_device.hpp"

#include <linux/nl80211.h>
#include <net/if.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>

#include <cstring>
#include <format>
#include <stdexcept>

namespace rfmstat {

IfaceDev::IfaceDev() : if_index(0), _current_channel(0) {
  _sk = nl_socket_alloc();
  if (!_sk) {
    throw std::runtime_error("Failed to allocate netlink socket");
  }

  if (genl_connect(_sk) < 0) {
    nl_socket_free(_sk);
    throw std::runtime_error("Failed to connect to generic netlink");
  }

  _nl80211_id = genl_ctrl_resolve(_sk, "nl80211");
  if (_nl80211_id < 0) {
    nl_socket_free(_sk);
    throw std::runtime_error(
        "nl80211 family not found. Ensure Wi-Fi is enabled.");
  }
}

IfaceDev::~IfaceDev() {
  if (_sk) {
    nl_socket_free(_sk);
  }
}

uint32_t IfaceDev::get_if_index(const std::string& iface) {
  unsigned int index = if_nametoindex(iface.c_str());
  if (index == 0) {
    throw std::runtime_error(std::format("Interface {} not found: {}", iface,
                                         std::string(strerror(errno))));
  }
  this->if_index = index;
  return index;
}

void IfaceDev::set_rfmon_channel(const uint32_t& freq_mhz) {
  if (this->if_index == 0) {
    throw std::logic_error(
        "interface index is not set. Call get_if_index() first.");
  }

  struct nl_msg* msg = nlmsg_alloc();
  if (!msg) throw std::runtime_error("Failed to allocate nl_msg");

  genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, _nl80211_id, 0, 0,
              NL80211_CMD_SET_WIPHY, 0);

  nla_put_u32(msg, NL80211_ATTR_IFINDEX, this->if_index);
  nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ, freq_mhz);

  int err = nl_send_sync(_sk, msg);
  if (err < 0) {
    throw std::runtime_error(std::format("Failed to set {} MHz channel: {}",
                                         freq_mhz,
                                         std::string(nl_geterror(err))));
  }
}

bool IfaceDev::is_rfmon() {
  if (this->if_index == 0) return false;

  struct nl_msg* msg = nlmsg_alloc();
  if (!msg) return false;

  genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, _nl80211_id, 0, 0,
              NL80211_CMD_GET_INTERFACE, 0);
  nla_put_u32(msg, NL80211_ATTR_IFINDEX, this->if_index);

  auto callback = [](struct nl_msg* msg, void* arg) -> int {
    auto* is_monitor = static_cast<bool*>(arg);
    struct genlmsghdr* gnlh =
        static_cast<struct genlmsghdr*>(nlmsg_data(nlmsg_hdr(msg)));
    struct nlattr* tb[NL80211_ATTR_MAX + 1];

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);

    if (tb[NL80211_ATTR_IFTYPE]) {
      uint32_t type = nla_get_u32(tb[NL80211_ATTR_IFTYPE]);
      if (type == NL80211_IFTYPE_MONITOR) {
        *is_monitor = true;
      }
    }
    return NL_SKIP;
  };

  bool is_monitor = false;
  nl_socket_modify_cb(_sk, NL_CB_VALID, NL_CB_CUSTOM, callback, &is_monitor);

  int err = nl_send_sync(_sk, msg);
  if (err < 0) return false;

  // nl_socket_modify_cb(_sk, NL_CB_VALID, NL_CB_DEFAULT, NULL, NULL);
  return is_monitor;
}

}  // namespace rfmstat
