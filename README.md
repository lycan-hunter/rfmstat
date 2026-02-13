# RFMstat

**RFMstat** (Radio Frequency Monitor Statistics) is a high-performance Wi-Fi broadcast passive statistics collector and auditor. It performs deep-packet analysis of 802.11 frames in monitor mode to diagnose link health, detect network anomalies, and log security events in real-time.

![C++](https://img.shields.io/badge/C++-00599C?style=flat-square&logo=C%2B%2B&logoColor=white)
![License](https://img.shields.io/pypi/l/scapy-gptp)
![Platform](https://img.shields.io/badge/-Linux-grey?logo=linux)

---

## ❓ Help

```

  ___ ___ __  __    _        _   
 | _ \ __|  \/  |__| |_ __ _| |_ 
 |   / _|| |\/| (_-<  _/ _` |  _|
 |_|_\_| |_|  |_/__/\__\__,_|\__| 

RFMstat v1.0.0 -- Wi-Fi broadcast passive statistics collector 


rfmstat [OPTIONS]


OPTIONS:
  -h,     --help              Print this help message and exit 
  -i,     --iface TEXT        Network interface to monitor. Default: default interface 
  -2,     --2_4ghz TEXT       Range of channels to scan (2.4 GHz). Default: all 
  -5,     --5ghz TEXT         Range of channels to scan (5 GHz). Default: all 
  -6,     --6ghz TEXT         Range of channels to scan (6 GHz). Default: all 
  -t,     --timeout UINT      Dwell time per channel (ms). Default: 5 sec 
  -s,     --silent            Output only final reports 
  -V,     --version           Display program version information and exit 


EXAMPLES: 
sudo rfmstat -i wlan0 -2 1-11 -t 1000 
sudo rfmstat -i wlan0 -5 36,48 -s 

Project home: <https://github.com/lycan-hunter/rfmstat> 
```

---

## 🚀 Features

*   **Multi-Band Support:** Full scanning for 2.4 GHz, 5 GHz, and 6 GHz (Wi-Fi 6E/7) bands.
*   **Intelligent Diagnostics:** Smart "Verdicts" that summarize channel states based on traffic intensity (EPS/PPS).

---

## 🛠 Prerequisites & Dependencies

To build and run **RFMstat**, you need:

*   **Operating System:** Linux (Kernel 5.10+ recommended).
*   **Libraries:** 
    *   `libpcap` (packet capture)
    *   `libnl-3` & `libnl-genl-3` (interface management via Netlink)
*   **Compiler:** GCC 10+ or Clang 11+ (C++20 support required).
*   **Hardware:** A Wi-Fi adapter that supports **Monitor Mode**.

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com
cd rfmstat

# Build the project
mkdir build && cd build
cmake ..
make
```

## 🚩 Run
```bash
# Run (requires root for raw socket access)
sudo ./bin/rfmstat -i wlan0
```

---

## 🔍 Diagnostic Reference

### Status Tags (Indicators)
These tags appear in `[]` brackets within the report sections to highlight specific anomalies.

| Tag | Section | Condition | Meaning |
| :--- | :--- | :--- | :--- |
| **DATA_LOSS_OR_PHY_MISMATCH** | Link Health | `ack_ratio > 1.5` | You see ACKs but miss Data. Likely due to unsupported modulation (e.g., Wi-Fi 6 traffic on a Wi-Fi 4 card). |
| **HIGH_PACKET_LOSS** | Link Health | `ack_ratio < 0.1` | High data volume but almost no ACKs. Extreme interference or client out of range. |
| **ASYMMETRIC_SIGHT** | Link Health | `rts_raw > 1.05` | CTS responses outnumber RTS requests. You hear the Access Point well, but the Client poorly. |
| **KICK_ATTACK** | Security | `deauth_eps > 1.0` | Over 1 Deauth packet per second. Active attempt to disconnect clients. |
| **BRUTEFORCE** | Security | `auth_eps > 5.0` | Over 5 Auth attempts per second. Possible WPA-handshake brute-force or flood. |

### Diagnostic Verdicts
The final verdict is the overall assessment of the channel state, selected by priority.

| Verdict | Priority | Description |
| :--- | :---: | :--- |
| **UNDER_ATTACK** |  1 | Security threat detected (Deauth/Auth flood). Network stability is at risk. |
| **SATURATED** |  2 | Throughput exceeds 400 Mbps. Channel is fully utilized by data transfer. |
| **INCOMPLETE_CAPTURE** |  3 | High `ack_ratio` with sufficient ACKs. Sensor is "blind" to high-speed Data frames. |
| **HIGH_L2_NOISE** |  4 | Over 40% of packets are marked as unknown. High radio interference, noise or unknown standart. |
| **STABLE** |  5 | No anomalies detected. Channel is operating normally. |

---

## 📖 Usage Examples

*   **Quick check on 2.4GHZ band channels 1, 6 and 11:**
    ```bash
    sudo ./rfmstat -i wlan0 -2 1,6,11 -t 1000
    ```
*   **Deep audit of 5GHz band (channels 36) with 5s dwell time:**
    ```bash
    sudo ./rfmstat -i wlan0 -5 36 -t 5000
    ```
*   **Silent mode (output only final audit reports):**
    ```bash
    sudo ./rfmstat -i wlan0 -2 1-13 -s
    ```

---

---

## ℹ️ Other Information

### 📊 Detection Logic (EPS-based)
**RFMstat** calculates **Events Per Second (EPS)** for critical network frames (Deauth, Auth, Action). 
*   The engine compares real-time intensity against a built-in **sensitivity table**.
*   This approach allows the tool to detect attacks accurately regardless of whether you scan for 1 second or 1 hour.
*   The dynamic diagnostic engine will notify you of any L2 anomalies (asymmetry, packet loss, or flood) immediately in the audit report.

### ⏱️ Dwell Time vs. Accuracy
The `timeout` (dwell time) parameter significantly impacts the quality of the audit:
*   **Deep Scan (5000ms+):** Recommended for professional auditing. Provides stable throughput (Mbps) metrics and highly accurate security verdicts.
*   **Fast Check (100ms - 500ms):** Best for quick discovery of active channels. Note that PPS and link health metrics may be "noisy" due to small sample sizes.

### 📡 Interface Requirements
*   **Monitor Mode:** The selected network interface **must** be manually switched to monitor mode (e.g., via `iw` or `airmon-ng`) before starting the tool.
*   **Root Privileges:** Accessing raw 802.11 frames and controlling the interface via Netlink requires `sudo` or `CAP_NET_RAW` capabilities.
*   **Hardware Limits:** The accuracy of the `INCOMPLETE_CAPTURE` verdict depends on your Wi-Fi chip. Cheap adapters might not "hear" high-speed 802.11ac/ax data frames, even if they successfully capture management traffic.

### 📂 Operational Notes
*   **Standard Streams:** Operational logs and errors are sent to `stderr`, while final audit reports are sent to `stdout`. This allows for easy redirection: `sudo rfmstat -i wlan1 > report.txt`.
*   **Resource Usage:** RFMstat is written in Modern C++20 with a focus on low CPU overhead, making it suitable for single-board computers like Raspberry Pi or Pine64.

---

**Author:** [lycan-hunter](https://github.com/lycan-hunter)  
**Project Home:** [RFMstat](https://github.com/lycan-hunter/rfmstat)