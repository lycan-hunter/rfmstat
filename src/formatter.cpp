#include "rfmstat/formatter.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <format>
#include <iomanip>
#include <sstream>
#include <string>

#include "rfmstat/channel_data.hpp"

namespace rfmstat {

std::string get_channel_rate(const double& pps, const uint32_t& freq_mhz) {
  const std::string shades = " .,-:+=*^<!?FRM#";
  const int HALF_BAR_LENGTH = 17;

  if (pps <= 0.0) return "[       IDLE       ]";

  double max_expected_pps = (freq_mhz > 5000) ? 2000.0 : 500.0;

  double base = std::sqrt(pps / max_expected_pps);
  base = std::clamp(base, 0.05, 0.9);

  double noise = std::sin(pps * 12.34) * 0.07;
  double utilization = std::clamp(base + noise, 0.05, 0.95);

  double half_ratio = utilization / 2.0;
  std::string left_side = "";

  for (int i = HALF_BAR_LENGTH; i >= 0; --i) {
    double segment_val = (half_ratio * HALF_BAR_LENGTH) - i;
    double segment_fill = std::clamp(segment_val, 0.0, 1.0);

    double flicker = (std::sin(pps * 40.0 + i) + 1.0) * 0.08;
    int shade_index =
        static_cast<int>((segment_fill + flicker) * (shades.length() - 1));
    shade_index = std::clamp(shade_index, 0, (int)shades.length() - 1);

    left_side += shades[shade_index];
  }

  return '[' + left_side + ']';
}

std::string get_channel_audit(const ChannelData& d, const uint32_t& timeout) {
  std::stringstream ss;

  double data_pkts = (double)d.data_plain + d.data_qos + d.data_null;
  double ctrl_pkts = (double)d.ctrl_ack + d.ctrl_rts + d.ctrl_cts;
  double mgmt_pkts = (double)d.mgmt_beacon + d.mgmt_assoc + d.mgmt_auth +
                     d.mgmt_probe_req + d.mgmt_deauth;

  double ack_ratio =
      (data_pkts > 0)
          ? (static_cast<double>(d.ctrl_ack + d.ctrl_ba) / data_pkts)
          : 0.0;
  double rts_success =
      (d.ctrl_rts > 0) ? (static_cast<double>(d.ctrl_cts) / d.ctrl_rts) : 1.0;
  double mbps =
      (d.length * 8.0) / 1000000.0 / (static_cast<double>(timeout) / 1000.0);
  double pps =
      static_cast<double>(d.packets) / (static_cast<double>(timeout) / 1000.0);

  std::string load_status = "[OK]";
  if (mbps >= 600.0)
    load_status = "[CRIT_OVERLOAD]";
  else if (mbps >= 300.0)
    load_status = "[HIGH_LOAD]";

  ss << "net_channel_audit: " << d.packets << " pkts, " << d.length << " bytes "
     << load_status << "\n";
  ss << "|\n";

  ss << "+-- flow_stats\n";
  ss << "|   |-- throughput: " << std::fixed << std::setprecision(2) << mbps
     << " Mbps\n";
  ss << "|   |-- intensity:  " << pps << " pps\n";
  ss << "|   `-- avg_frame:  " << (d.packets > 0 ? d.length / d.packets : 0)
     << " bytes\n";

  ss << "+-- link_health\n";
  if (d.ctrl_rts >= 10 && d.ctrl_cts >= 10) {
    ss << "|   |-- ack_ratio:  " << std::setprecision(2) << ack_ratio;
  } else {
    ss << "|   |-- ack_ratio:  " << std::setprecision(2) << "n/a";
  }
  if (data_pkts > 50) {
    if (ack_ratio < 0.1)
      ss << " [LOSS_DETECTED]";
    else if (ack_ratio > 1.5)
      ss << " [HEAVY_RETRANS]";
  }
  ss << "\n";
  if (rts_success > 1) {
    ss << "|   |-- rts_cts_ok: " << std::setprecision(2)
       << ">100.00% [ASYMMETRIC_SIGHT]" << "\n";
  } else {
    ss << "|   |-- rts_cts_ok: " << std::setprecision(2)
       << (rts_success * 100.0) << "%\n";
  }
  ss << "|   `-- l2_errors:  " << d.unknown << " (unrecognized/noise)\n";

  ss << "+-- proto_dist\n";
  ss << "|   |-- data: " << std::setw(6) << (uint64_t)data_pkts
     << " (qos:" << d.data_qos << ", plain:" << d.data_plain
     << ", null:" << d.data_null << ")\n";
  ss << "|   |-- ctrl: " << std::setw(6) << (uint64_t)ctrl_pkts
     << " (ack:" << d.ctrl_ack << ", rts:" << d.ctrl_rts
     << ", cts:" << d.ctrl_cts << ")\n";
  ss << "|   `-- mgmt: " << std::setw(6) << (uint64_t)mgmt_pkts
     << " (bcn:" << d.mgmt_beacon << ", prb:" << d.mgmt_probe_req << ")\n";

  ss << "|\n";
  ss << "+-- security_log\n";
  bool clean = true;
  if (d.mgmt_deauth > 5) {
    ss << "|   |-- [!] deauth_event: " << d.mgmt_deauth << " (possible_kick)\n";
    clean = false;
  }
  if (d.mgmt_auth > 30) {
    ss << "|   |-- [!] auth_spike:   " << d.mgmt_auth << " (bruteforce)\n";
    clean = false;
  }
  if (clean) ss << "|   |-- status: CLEAN\n";
  ss << "|   `-- probe_reqs: " << d.mgmt_probe_req << " (scanning)\n";

  ss << "|\n";
  ss << "`-- diag_verdict: ";
  if (d.mgmt_deauth > 15)
    ss << "UNDER_ATTACK";
  else if (ack_ratio < 0.1 && data_pkts > 100)
    ss << "L2_CONGESTION";
  else if (mbps > 550.0)
    ss << "SATURATED";
  else if (d.unknown > (d.packets * 0.3))
    ss << "HIGH_L2_NOISE";
  else
    ss << "STABLE";
  ss << "\n";

  return ss.str();
}
}  // namespace rfmstat
