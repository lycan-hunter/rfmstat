#pragma once

#include <cstdint>

namespace rfmstat {
enum class FrameType : uint8_t {
  // Management (Type 00)
  MgmtAssocReq = 0x00,
  MgmtProbeReq = 0x10,
  MgmtProbeRes = 0x14,  // Sub 5, Type 0 -> 0101 00
  MgmtBeacon = 0x20,
  MgmtAuth = 0x2C,
  MgmtDeauth = 0x30,
  MgmtAction = 0x34,  // Sub 13, Type 0 -> 1101 00

  // Control (Type 01)
  CtrlBA_Req = 0x21,  // Sub 8, Type 1 -> 1000 01
  CtrlBA = 0x25,      // Sub 9, Type 1 -> 1001 01
  CtrlRTS = 0x2D,
  CtrlCTS = 0x31,
  CtrlAck = 0x35,

  // Data (Type 10)
  DataPlain = 0x02,
  DataNull = 0x12,
  DataQoS = 0x22,
};

struct ChannelData {
  uint64_t packets = 0;
  uint64_t length = 0;
  // double pps = 0;

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
  uint64_t ctrl_ba = 0;      // Block Ack
  uint64_t ctrl_ba_req = 0;  // Block Ack Request
  uint64_t mgmt_probe_res = 0;
  uint64_t mgmt_action = 0;
};

}  // namespace rfmstat
