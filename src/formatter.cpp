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
  ss << std::fixed << std::setprecision(2);

  double duration_sec = std::max(0.001, static_cast<double>(timeout) / 1000.0);
  
  double data_pkts = (double)d.data_plain + d.data_qos;
  double ctrl_pkts = (double)d.ctrl_ack + d.ctrl_rts + d.ctrl_cts + d.ctrl_ba;
  double mgmt_pkts = (double)d.mgmt_beacon + d.mgmt_assoc + d.mgmt_auth +
                     d.mgmt_probe_req + d.mgmt_deauth;

  double deauth_eps = static_cast<double>(d.mgmt_deauth) / duration_sec;
  double auth_eps = static_cast<double>(d.mgmt_auth) / duration_sec;
  double mbps = (d.length * 8.0) / 1'000'000.0 / duration_sec;
  double pps = static_cast<double>(d.packets) / duration_sec;

  double total_acks = static_cast<double>(d.ctrl_ack + d.ctrl_ba);
  double ack_ratio = (data_pkts > 0) ? (total_acks / data_pkts) : 0.0;
  double rts_raw = (d.ctrl_rts > 0) ? (static_cast<double>(d.ctrl_cts) / d.ctrl_rts) : 0.0;

  ss << "net_channel_audit: " << d.packets << " pkts, " << d.length << " bytes [OK]\n";
  ss << "|\n";

  ss << "+-- flow_stats\n";
  ss << "|   |-- throughput: " << mbps << " Mbps\n";
  ss << "|   |-- intensity:  " << pps << " pps\n";
  ss << "|   `-- avg_frame:  " << (d.packets > 0 ? d.length / d.packets : 0) << " bytes\n";

  ss << "+-- link_health\n";
  ss << "|   |-- ack_ratio:  " << ack_ratio;
  if (ack_ratio > 1.5) ss << " [DATA_LOSS_OR_PHY_MISMATCH]";
  else if (data_pkts > 50 && ack_ratio < 0.1) ss << " [HIGH_PACKET_LOSS]";
  ss << "\n";

  ss << "|   |-- rts_cts_ok: " << (std::min(1.0, rts_raw) * 100.0) << " %";
  if (rts_raw > 1.05) ss << " [ASYMMETRIC_SIGHT]";
  ss << "\n";
  ss << "|   `-- l2_errors:  " << d.unknown << " (unrecognized/noise)\n";

  ss << "+-- proto_dist\n";
  ss << "|   |-- data: " << std::setw(6) << (uint64_t)(data_pkts + d.data_null) << "\n";
  ss << "|   |-- ctrl: " << std::setw(6) << (uint64_t)ctrl_pkts << "\n";
  ss << "|   `-- mgmt: " << std::setw(6) << (uint64_t)mgmt_pkts << "\n";

  ss << "|\n";
  ss << "+-- security_log\n";
  bool clean = true;
  if (deauth_eps > 1.0) {
    ss << "|   |-- deauth_flood: " << deauth_eps << " eps [KICK_ATTACK]\n";
    clean = false;
  }
  if (auth_eps > 5.0) {
    ss << "|   |-- auth_spike:   " << auth_eps << " eps [BRUTEFORCE]\n";
    clean = false;
  }
  if (clean) ss << "|   |-- status: CLEAN\n";
  ss << "|   `-- probe_reqs: " << d.mgmt_probe_req << " (scanning)\n";

  ss << "|\n";
  ss << "`-- diag_verdict: ";
  if (deauth_eps > 1.0) ss << "UNDER_ATTACK";
  else if (mbps > 400.0) ss << "SATURATED";
  else if (ack_ratio > 2.0 && total_acks > 20) ss << "INCOMPLETE_CAPTURE";
  else if (d.unknown > (d.packets * 0.4)) ss << "HIGH_L2_NOISE";
  else ss << "STABLE";
  ss << "\n";

  return ss.str();
}

}  // namespace rfmstat
