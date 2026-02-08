#pragma once

#include <cstdint>

namespace rfmstat {
enum class FrameType : uint8_t {
  // Management (Type 0)`
  MgmtAssocReq = 0x00,
  MgmtBeacon = 0x08,  // 0 << 4 | 8
  MgmtProbeReq = 0x04,
  MgmtAuth = 0xB0,  // (11 << 4) | 0
  MgmtDeauth = 0x0C,

  // Control (Type 1)
  CtrlRTS = 0x1B,  // 1 << 4 | 11 (0xB)
  CtrlCTS = 0x1C,  // 1 << 4 | 12 (0xC)
  CtrlAck = 0x1D,  // 1 << 4 | 13 (0xD)

  // Data (Type 2)
  DataPlain = 0x20,  // 2 << 4 | 0
  DataQoS = 0x28,    // 2 << 4 | 8
  DataNull = 0x24,   // 2 << 4 | 4

  Unknown = 0xFF
};

struct ChannelData {
  uint64_t packets = 0;
  uint64_t length = 0;
  uint64_t pps = 0;

  uint64_t mgmt_beacon = 0;
  uint64_t mgmt_assoc = 0;
  uint64_t mgmt_auth = 0;
  uint64_t mgmt_probe_req = 0;
  uint64_t mgmt_deauth = 0;
  uint64_t ctrl_rts = 0;
  uint64_t ctrl_cts = 0;
  uint64_t ctrl_ack = 0;
  uint64_t data_plain = 0;
  uint64_t data_qos = 0;
  uint64_t data_null = 0;
  uint64_t unknown = 0;
};

}  // namespace rfmstat
