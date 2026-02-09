#include <string>
#include <cstdint>
#include <algorithm>
#include <format>

#include <sstream>

#include <iomanip>
#include "rfmstat/channel_data.hpp"

namespace rfmstat {
std::string get_channel_rate(const uint64_t& packets, const uint64_t length, const uint64_t& freq_mhz ) {
    const std::string shades = " .-=+*FRM#"; // " ░▒▓" -- not supported by UTF-8 !
    const int NUM_SHADES = 10;
    const uint64_t MAX_BYTES_PER_SEC = freq_mhz > 5000 ? 37500000 : 75000000;
    const int HALF_BAR_LENGTH = 10;
    
    double utilization_ratio = std::min(1.0, std::max(0.0, static_cast<double>(length) / MAX_BYTES_PER_SEC));
    double half_ratio = utilization_ratio / 2.0; 

    std::string right_side = "";

    for (int i = 0; i < HALF_BAR_LENGTH; ++i) {
        double segment_fill_ratio = std::max(0.0, std::min(1.0, (half_ratio * HALF_BAR_LENGTH) - i));
        int shade_index = static_cast<int>(segment_fill_ratio * NUM_SHADES);
        shade_index = std::min(shade_index, NUM_SHADES - 1);
        right_side += shades[shade_index];
    }

    std::string left_side = right_side;

    std::reverse(left_side.begin(), left_side.end());

    return left_side + right_side;
}


std::string get_channel_audit(const ChannelData& d) {
    std::stringstream ss;

    // Derived Metrics Calculations
    double data_pkts = (double)d.data_plain + d.data_qos + d.data_null;
    double ctrl_pkts = (double)d.ctrl_ack + d.ctrl_rts + d.ctrl_cts;
    double mgmt_pkts = (double)d.mgmt_beacon + d.mgmt_assoc + d.mgmt_auth + d.mgmt_probe_req + d.mgmt_deauth;
    
    double ack_ratio = (data_pkts > 0) ? (static_cast<double>(d.ctrl_ack) / data_pkts) : 0.0;
    double rts_success = (d.ctrl_rts > 0) ? (static_cast<double>(d.ctrl_cts) / d.ctrl_rts) : 1.0;
    double mbps = (d.length * 8.0) / 1000000.0;

    // Load Status Logic (Based on 300Mb/600Mb thresholds)
    std::string load_status = "[OK]";
    if (d.length >= 75000000)      load_status = "[CRIT_OVERLOAD]"; // > 600 Mbps
    else if (d.length >= 37500000) load_status = "[HIGH_LOAD]";     // > 300 Mbps

    // Main Header
    ss << "net_channel_audit: " << d.packets << " pkts, " << d.length << " bytes " << load_status << "\n";
    ss << "|\n";

    // Section 1: Physical Flow
    ss << "+-- flow_stats\n";
    ss << "|   |-- throughput: " << std::fixed << std::setprecision(2) << mbps << " Mbps\n";
    ss << "|   |-- intensity:  " << d.pps << " pps\n";
    ss << "|   `-- avg_frame:  " << (d.packets > 0 ? d.length / d.packets : 0) << " bytes\n";

    // Section 2: Link Health
    ss << "+-- link_health\n";
    ss << "|   |-- ack_ratio:  " << std::setprecision(2) << ack_ratio;
    if (data_pkts > 50) {
        if (ack_ratio < 0.6)      ss << " [LOSS_DETECTED]";
        else if (ack_ratio > 1.3) ss << " [HEAVY_RETRANS]";
    }
    ss << "\n";
    ss << "|   |-- rts_cts_ok: " << std::setprecision(2) << (rts_success * 100.0) << "%\n";
    ss << "|   `-- l2_errors:  " << d.unknown << " (malformed/noise)\n";

    // Section 3: Protocol Distribution
    ss << "+-- proto_dist\n";
    ss << "|   |-- data: " << (uint64_t)data_pkts << " (qos:" << d.data_qos << ", plain:" << d.data_plain << ", null:" << d.data_null << ")\n";
    ss << "|   |-- ctrl: " << (uint64_t)ctrl_pkts << " (ack:" << d.ctrl_ack << ", rts:" << d.ctrl_rts << ", cts:" << d.ctrl_cts << ")\n";
    ss << "|   `-- mgmt: " << (uint64_t)mgmt_pkts << " (bcn:" << d.mgmt_beacon << ", prb:" << d.mgmt_probe_req << ")\n";

    // Section 4: Security Events
    ss << "|\n";
    ss << "+-- security_log\n";
    bool clean = true;
    if (d.mgmt_deauth > 5) {
        ss << "|   |-- [!] deauth_event: " << d.mgmt_deauth << " (possible_kick_attack)\n";
        clean = false;
    }
    if (d.mgmt_auth > 30) {
        ss << "|   |-- [!] auth_spike:   " << d.mgmt_auth << " (bruteforce_attempt)\n";
        clean = false;
    }
    if (clean) ss << "|   |-- status: CLEAN\n";
    ss << "|   `-- probe_reqs: " << d.mgmt_probe_req << " (scanning_activity)\n";

    // Section 5: Diagnostic Verdict
    ss << "|\n";
    ss << "`-- diag_verdict: ";
    if (d.mgmt_deauth > 15) ss << "UNDER_ATTACK";
    else if (ack_ratio < 0.5 && data_pkts > 100) ss << "L2_CONGESTION";
    else if (mbps > 550.0) ss << "SATURATED";
    else if (d.pps > 6000) ss << "HIGH_PPS_FLOOD";
    else ss << "STABLE";
    ss << "\n";

    return ss.str();
}



}
