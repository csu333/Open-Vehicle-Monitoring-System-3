/*
;    Project:       Open Vehicle Monitor System
;    Date:          2025
;
;    Changes:
;    1.0  Initial release
;
;    (C) 2025       csu333
;
;    CAN Bus Frame Monitor web page.
;    Uses the built-in RE (reverse-engineering) framework to capture CAN
;    frames.  The user selects a bus and an optional ID range, clicks
;    "Start" to launch the RE framework, and the table updates live via
;    a dedicated WebSocket connection (/ws/canmonitor).
;
; Permission is hereby granted, free of charge, to any person obtaining a copy
; of this software and associated documentation files (the "Software"), to deal
; in the Software without restriction, including without limitation the rights
; to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
; copies of the Software, and to permit persons to whom the Software is
; furnished to do so, subject to the following conditions:
;
; The above copyright notice and this permission notice shall be included in
; all copies or substantial portions of the Software.
;
; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
; FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
; AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
; LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
; OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
; THE SOFTWARE.
*/

#include "ovms_log.h"
static const char *TAG = "webcanmon";

#include <cstring>
#include <cstdio>
#include <deque>
#include <map>
#include <string>
#include <vector>
#include "ovms_webserver.h"
#include "ovms_config.h"
#include "retools.h"
#include "can.h"
#include "dbc_app.h"

// MyRE is defined in retools.cpp; NULL when RE framework is not running.
extern re* MyRE;

#ifdef CONFIG_OVMS_COMP_RE_TOOLS_PID
#include "retools_pid.h"
#endif


// ── Per-frame accumulator ────────────────────────────────────────────────────
// We register directly with MyCan to receive every frame in real-time so that
// ISO 15765-2 multi-frame messages (FF + CFs) can be reassembled.
// s_frame_store holds one entry per (ID, Type, PID) display key.

struct CanMonHistEntry
  {
  std::string hex;  // formatted payload at time of capture
  uint32_t    cnt;  // update count at time of capture
  };

struct CanMonFrameEntry
  {
  CAN_frame_t          meta;          // first/only frame: bus ptr, MsgID, FF flag
  std::vector<uint8_t> payload;       // data bytes ONLY (after type + PID)
  std::string          hex;           // cached "XX XX XX" string; rebuilt on change
  char                 typestr[4];    // type byte as 2-digit hex
  char                 pidstr[6];     // PID as 2- or 4-digit hex
  bool                 pid16;         // true when PID is 16-bit (type 0x22/0x62)
  bool                 multi;         // true when reassembled from FF+CF sequence
  uint32_t             cnt;
  };

// ISO 15765-2 reassembly state, one entry per (bus, CAN ID) sender.
struct ReassemblyState
  {
  CAN_frame_t          meta;          // the First Frame (for bus/id/ext info)
  std::vector<uint8_t> payload;       // accumulates [type, pid..., data...]
  uint16_t             expected_len;  // total payload length from FF header
  uint8_t              next_seq;      // next expected CF sequence counter
  };

// Memory limits to protect ESP32 heap on busy buses
static const size_t MAX_CANMON_STORE = 250;
static const size_t MAX_CANMON_REASSEMBLY = 50;

static std::map<std::string, CanMonFrameEntry>             s_frame_store;
static std::map<uint64_t, ReassemblyState>                 s_reassembly;
static std::map<std::string, std::deque<CanMonHistEntry>>  s_history;

// CAN listener queue — registered with MyCan once and kept for the session.
static QueueHandle_t s_can_queue = NULL;


// ── OBDII scan state ──────────────────────────────────────────────────────────
// Set true when a pidscan is started, cleared when stopped or completed.
// Written from the mongoose task (start/stop commands) and from the
// "retools.pidscan.stop" event handler; reading is in BuildCanMonJson.
// A plain bool is sufficient — worst case is one stale 500 ms snapshot.
static bool s_scanning = false;


// Validate decimal string (digits only).  allow_empty=true makes an empty string acceptable.
static bool is_valid_decimal(const std::string& s, bool allow_empty = false)
  {
  if (s.empty()) return allow_empty;
  for (unsigned char ch : s)
    if (!isdigit(ch)) return false;
  return true;
  }

// Validate hex string.  allow_empty=true makes an empty string acceptable
// (used for optional query parameters).
static bool is_valid_hex(const std::string& s, bool allow_empty = false)
  {
  if (s.empty()) return allow_empty;
  for (unsigned char ch : s)
    if (!isxdigit(ch)) return false;
  return true;
  }

// Validate a RE filter string: one or more space-separated tokens of the form
// [<bus>:]<id>[-[<id>]] where bus is a digit and IDs are hex.
// Allowed characters: hex digits, ':', '-', and spaces only.
static bool is_valid_re_filter(const std::string& s, bool allow_empty = false)
  {
  if (s.empty()) return allow_empty;
  for (unsigned char ch : s)
    if (!isxdigit(ch) && ch != ':' && ch != '-' && ch != ' ') return false;
  return true;
  }




// ── FormatInt64Fields ─────────────────────────────────────────────────────────
// Interprets up to 8 payload bytes as little- and big-endian int64 JSON strings.
// i64le and i64be must each be at least 24 bytes.
static void FormatInt64Fields(const uint8_t* payload, uint8_t plen,
    char i64le[24], char i64be[24])
  {
  if (plen > 8) plen = 8;
  uint8_t buf_le[8] = {}, buf_be[8] = {};
  memcpy(buf_le, payload, plen);
  for (int i = 0; i < plen; i++) buf_be[i] = payload[plen - 1 - i];
  { int64_t v = 0; memcpy(&v, buf_le, 8); snprintf(i64le, 24, "\"%lld\"", (long long)v); }
  { int64_t v = 0; memcpy(&v, buf_be, 8); snprintf(i64be, 24, "\"%lld\"", (long long)v); }
  }


// ── StoreCompleteMessage ─────────────────────────────────────────────────────
// Called once a full ISO 15765-2 payload is available (either a single frame
// or a fully reassembled FF+CF sequence).  raw[] = [type, pid..., data...].

static void StoreCompleteMessage(const CAN_frame_t& meta,
    const uint8_t* raw, uint16_t raw_len, bool multi)
  {
  if (raw_len == 0) return;

  char typestr[4] = "--";
  char pidstr[6]  = "--";
  // 16-bit PID for UDS ReadDataByIdentifier (0x22 request, 0x62 response).
  bool pid16 = (raw_len >= 1 && (raw[0] == 0x22 || raw[0] == 0x62));
  uint16_t data_off = 1;
  if (raw_len >= 1) snprintf(typestr, sizeof(typestr), "%02X", raw[0]);
  if (pid16 && raw_len >= 3)
    { snprintf(pidstr, sizeof(pidstr), "%02X%02X", raw[1], raw[2]); data_off = 3; }
  else if (raw_len >= 2)
    { snprintf(pidstr, sizeof(pidstr), "%02X", raw[1]); data_off = 2; }

  // Store only the data bytes (after type+PID) for both single and multi-frame.
  // Multi-frame payloads may be many bytes long; no length cap is applied so
  // the full reassembled message is visible in the Hex data column.
  std::vector<uint8_t> payload;
  if (raw_len > data_off) payload.assign(raw + data_off, raw + raw_len);

  // Skip all-zero payloads — no data received for this PID.
  bool all_zero = true;
  for (uint8_t b : payload) if (b) { all_zero = false; break; }
  if (all_zero) return;

  // Display key: one row per (ID, Type, PID).
  char id_hex[12];
  if (meta.FIR.B.FF == CAN_frame_std)
    snprintf(id_hex, sizeof(id_hex), "%03X", (unsigned)meta.MsgID);
  else
    snprintf(id_hex, sizeof(id_hex), "%08X", (unsigned)meta.MsgID);
  char dkey_buf[26];
  snprintf(dkey_buf, sizeof(dkey_buf), "%s/%s/%s", id_hex, typestr, pidstr);
  std::string dkey(dkey_buf);

  // Prevent memory exhaustion on very busy buses without filters
  if (s_frame_store.size() >= MAX_CANMON_STORE && s_frame_store.find(dkey) == s_frame_store.end())
    {
    return;
    }

  // Build hex string (variable length for multi-frame).
  std::string hexstr;
  hexstr.reserve(payload.size() * 3);
  for (size_t i = 0; i < payload.size(); i++)
    {
    char tmp[4];
    snprintf(tmp, sizeof(tmp), "%s%02X", i ? " " : "", (unsigned)payload[i]);
    hexstr += tmp;
    }

  auto& entry = s_frame_store[dkey];
  entry.meta  = meta;
  memcpy(entry.typestr, typestr, sizeof(typestr));
  memcpy(entry.pidstr,  pidstr,  sizeof(pidstr));
  entry.pid16   = pid16;
  entry.payload = payload;
  entry.hex     = hexstr;
  entry.multi   = multi;
  entry.cnt++;

  auto& dq = s_history[dkey];
  if (dq.empty() || dq.back().hex != hexstr)
    {
    CanMonHistEntry h;
    h.hex = hexstr;
    h.cnt = entry.cnt;
    dq.push_back(h);
    if (dq.size() > 10) dq.pop_front();
    }
  }


// ── ProcessCanFrame ───────────────────────────────────────────────────────────
// Parses ISO 15765-2 PCI byte and dispatches to StoreCompleteMessage or the
// reassembly state machine.  FC (flow-control) frames are discarded.

static void ProcessCanFrame(const CAN_frame_t& f)
  {
  if (f.FIR.B.DLC == 0) return;

  uint8_t pci      = f.data.u8[0];
  uint8_t pci_type = pci >> 4;

  // Reassembly key: unique per (bus pointer, CAN ID).
  uint64_t rkey = ((uint64_t)(uintptr_t)f.origin << 32) | (uint64_t)f.MsgID;

  switch (pci_type)
    {
    case 0x0: // Single Frame — payload length in low nibble
      {
      uint8_t sf_len = pci & 0x0F;
      if (sf_len == 0 || sf_len > 7) break;
      // Cap to the actual number of data bytes present in the frame.
      uint8_t avail = f.FIR.B.DLC - 1;
      if (sf_len > avail) sf_len = avail;
      if (sf_len == 0) break;
      // raw = bytes 1..sf_len: [type, pid..., data...]
      StoreCompleteMessage(f, &f.data.u8[1], sf_len, false);
      s_reassembly.erase(rkey);   // discard any stale FF state for this ID
      break;
      }

    case 0x1: // First Frame — 12-bit total length in low nibble + next byte
      {
      if (f.FIR.B.DLC < 8) break;
      uint16_t total = ((uint16_t)(pci & 0x0F) << 8) | f.data.u8[1];
      if (total <= 7) break;  // SF should have handled this
      // Enforce map size limit; always allow updates to existing entries.
      if (s_reassembly.find(rkey) == s_reassembly.end() &&
          s_reassembly.size() >= MAX_CANMON_REASSEMBLY)
        break;
      ReassemblyState& st = s_reassembly[rkey];
      st.meta = f;
      st.payload.clear();
      st.payload.reserve(total);
      // FF carries data in bytes 2..DLC-1.
      for (int i = 2; i < f.FIR.B.DLC; i++) st.payload.push_back(f.data.u8[i]);
      st.expected_len = total;
      st.next_seq = 1;
      break;
      }

    case 0x2: // Consecutive Frame — sequence counter in low nibble
      {
      auto it = s_reassembly.find(rkey);
      if (it == s_reassembly.end()) break;
      ReassemblyState& st = it->second;
      if ((pci & 0x0F) != st.next_seq) { s_reassembly.erase(it); break; }
      st.next_seq = (st.next_seq + 1) & 0x0F;
      for (int i = 1; i < f.FIR.B.DLC && (uint16_t)st.payload.size() < st.expected_len; i++)
        st.payload.push_back(f.data.u8[i]);
      if ((uint16_t)st.payload.size() >= st.expected_len)
        {
        StoreCompleteMessage(st.meta,
            st.payload.data(), (uint16_t)st.payload.size(), true);
        s_reassembly.erase(it);
        }
      break;
      }

    // case 0x3: Flow Control — discard (protocol overhead, not data)
    default: break;
    }
  }


// ── DrainCanQueue ─────────────────────────────────────────────────────────────
// Consume all pending frames from the CAN listener queue and feed them through
// the reassembler.  Called at the start of BuildCanMonJson so both the
// WebSocket push path and the legacy HTTP GET path stay up to date.

static void DrainCanQueue()
  {
  if (!s_can_queue) return;
  CAN_frame_t frame;
  while (xQueueReceive(s_can_queue, &frame, 0) == pdTRUE)
    ProcessCanFrame(frame);
  }


// ── BuildDbcJson ─────────────────────────────────────────────────────────────
// Serialises all loaded DBC signal definitions to JSON so the browser can
// decode signals client-side.  Uses the same MyDBC global as the dbc command.

static double DbcNumVal(const dbcNumber& n)
  {
  if (n.IsDouble())          return n.GetDouble();
  if (n.IsSignedInteger())   return (double)n.GetSignedInteger();
  return (double)n.GetUnsignedInteger();
  }

static void DbcJsonEsc(std::string& out, const std::string& s)
  {
  for (char c : s) { if (c=='"'||c=='\\') out+='\\'; out+=c; }
  }

// Maximum size for the DBC JSON payload.  Keeps heap use bounded on ESP32.
static constexpr size_t DBC_JSON_MAX = 48 * 1024;

static std::string BuildDbcJson()
  {
  OvmsMutexLock lock(&MyDBC.m_mutex);
  std::string json;
  json.reserve(4096);
  json += "{\"dbc_signals\":{";
  bool first = true;
  bool truncated = false;
  for (const auto& fkv : MyDBC.m_dbclist)
    {
    if (truncated) break;
    const dbcfile* df = fkv.second;
    for (const auto& mkv : df->m_messages.m_entrymap)
      {
      if (truncated) break;
      const dbcMessage* msg = mkv.second;
      if (msg->m_signals.empty()) continue;
      uint32_t raw_id = msg->GetID() & 0x1FFFFFFFu;
      if (!first) json += ",";
      first = false;
      char idbuf[24];
      snprintf(idbuf, sizeof(idbuf), "\"%u\":[", (unsigned)raw_id);
      json += idbuf;
      bool fsig = true;
      for (const auto* sig : msg->m_signals)
        {
        if (!fsig) json += ",";
        fsig = false;
        std::string name, unit;
        DbcJsonEsc(name, sig->GetName());
        DbcJsonEsc(unit, sig->GetUnit());
        // Numeric/boolean fields are bounded; string fields (name, unit) are not,
        // so they are appended separately to avoid a fixed-buffer overflow.
        char fixed[128];
        snprintf(fixed, sizeof(fixed),
          "\",\"s\":%d,\"l\":%d,\"be\":%s,\"sg\":%s"
          ",\"f\":%.10g,\"o\":%.10g,\"mn\":%.10g,\"mx\":%.10g,\"u\":\"",
          sig->GetStartBit(), sig->GetSignalSize(),
          (sig->GetByteOrder()==DBC_BYTEORDER_BIG_ENDIAN) ? "true" : "false",
          (sig->GetValueType()==DBC_VALUETYPE_SIGNED)     ? "true" : "false",
          DbcNumVal(sig->GetFactor()),  DbcNumVal(sig->GetOffset()),
          DbcNumVal(sig->GetMinimum()), DbcNumVal(sig->GetMaximum()));
        json += "{\"n\":\""; json += name;
        json += fixed;
        json += unit;
        json += "\"}";
        if (json.size() > DBC_JSON_MAX)
          { truncated = true; break; }
        }
      json += "]";
      }
    }
  if (truncated)
    ESP_LOGW(TAG, "DBC JSON truncated at %zu bytes", json.size());
  json += "}}";
  return json;
  }


// ── BuildCanMonJson ───────────────────────────────────────────────────────────
// Builds the complete JSON snapshot: RE captured frames + OBD poll results.
// Called from both the WebSocket push and the legacy HTTP GET endpoint.

static std::string BuildCanMonJson()
  {
  // Drain the CAN listener queue before building the snapshot so all pending
  // frames (including multi-frame sequences) are ingested first.
  DrainCanQueue();

  bool running  = (MyRE != NULL);
  bool scanning = s_scanning;

#ifdef CONFIG_OVMS_COMP_RE_TOOLS_PID
  int scan_pid = scanning ? OvmsReToolsPidScannerCurrentPid() : -1;
#else
  int scan_pid = -1;
#endif

  std::string json;
  json.reserve(4096);
  json += running  ? "{\"running\":true,"  : "{\"running\":false,";
  if (scanning)
    {
    char spbuf[48];
    if (scan_pid >= 0)
      snprintf(spbuf, sizeof(spbuf), "\"scanning\":true,\"scan_pid\":\"%04X\",\"frames\":[",
               (unsigned)scan_pid);
    else
      strcpy(spbuf, "\"scanning\":true,\"frames\":[");
    json += spbuf;
    }
  else
    {
    json += "\"scanning\":false,\"frames\":[";
    }

  bool first = true;

  for (const auto& kv : s_frame_store)
    {
    const std::string&      dkey  = kv.first;
    const CanMonFrameEntry& entry = kv.second;
    const CAN_frame_t&      f     = entry.meta;

    const char* busname = f.origin ? f.origin->GetName() : "?";

    // Use cached hex string (rebuilt by StoreCompleteMessage on each change).
    const std::string& hexstr = entry.hex;

    // Int64 fields: use first ≤8 data bytes, strip trailing padding.
    size_t plen_num = entry.payload.size();
    if (plen_num > 8) plen_num = 8;
    const uint8_t* num_data = entry.payload.data();
    while (plen_num > 0 &&
           (num_data[plen_num-1] == 0x00 ||
            num_data[plen_num-1] == 0x55 ||
            num_data[plen_num-1] == 0xAA))
      plen_num--;

    char i64le[24], i64be[24];
    FormatInt64Fields(num_data, (uint8_t)plen_num, i64le, i64be);

    char fixed[256];
    snprintf(fixed, sizeof(fixed),
      "{\"key\":\"%s\","
      "\"bus\":\"%s\",\"id\":%u,\"ext\":%s,"
      "\"type\":\"%s\",\"pid\":\"%s\","
      "\"multi\":%s,"
      "\"i64le\":%s,\"i64be\":%s,"
      "\"cnt\":%u",
      dkey.c_str(),
      busname,
      (unsigned)f.MsgID,
      (f.FIR.B.FF == CAN_frame_ext) ? "true" : "false",
      entry.typestr, entry.pidstr,
      entry.multi ? "true" : "false",
      i64le, i64be,
      entry.cnt
    );

    if (!first) json += ",";
    first = false;
    json += fixed;

    // hex is appended separately because it can be arbitrarily long.
    json += ",\"hex\":\"";
    json += hexstr;
    json += "\"";

    json += ",\"hist\":[";
      {
      auto hit = s_history.find(dkey);
      if (hit != s_history.end())
        {
        bool hfirst = true;
        for (const auto& h : hit->second)
          {
          if (!hfirst) json += ",";
          hfirst = false;
          char cntbuf[32];
          snprintf(cntbuf, sizeof(cntbuf), "{\"cnt\":%u,\"hex\":\"", (unsigned)h.cnt);
          json += cntbuf;
          json += h.hex;
          json += "\"}";
          }
        }
      }
    json += "]}";
    }

  json += "]}";
  return json;
  }


// ── CanMonWsHandler ──────────────────────────────────────────────────────────
// Lightweight WebSocket handler for the CAN monitor.  One instance per
// connected browser tab.
//
// Lifecycle within the Mongoose event loop (all events run in the NetManager
// task — no extra locking needed between HandleEvent calls):
//
//   HANDSHAKE_REQUEST  → CreateCanMonWsHandler() attaches this to nc->user_data
//   HANDSHAKE_DONE     → send initial snapshot; return 0 so the framework does
//                        NOT replace us with the standard WebSocketHandler
//   POLL (every ~1 ms) → push a snapshot every 500 ms
//   WEBSOCKET_FRAME    → parse JSON command, execute action
//   CLOSE              → self-delete; return 0 so the framework does NOT call
//                        DestroyWebSocketHandler() with our non-slot pointer

// Simple JSON string-value extractor for incoming command frames.
// Handles \" escape sequences inside string values; ignores other escapes.
static std::string json_get_str(const std::string& json, const std::string& key)
  {
  std::string needle = "\"" + key + "\":\"";
  size_t pos = json.find(needle);
  if (pos == std::string::npos) return "";
  pos += needle.size();
  std::string result;
  while (pos < json.size())
    {
    char ch = json[pos];
    if (ch == '\\' && pos + 1 < json.size())
      { pos += 2; continue; }   // skip any escape sequence
    if (ch == '"') break;
    result += ch;
    pos++;
    }
  return result;
  }

class CanMonWsHandler : public MgHandler
  {
  public:
    CanMonWsHandler(mg_connection* nc) : MgHandler(nc), m_last_push(0) {}
    ~CanMonWsHandler() = default;

    int HandleEvent(int ev, void* p) override;

  private:
    void HandleCommand(const std::string& msg);
    void PushFrameData();

    TickType_t m_last_push;
  };

int CanMonWsHandler::HandleEvent(int ev, void* p)
  {
  switch (ev)
    {
    case MG_EV_WEBSOCKET_HANDSHAKE_DONE:
      // Push initial state immediately and prevent the framework from
      // overwriting nc->user_data with a standard WebSocketHandler.
      m_last_push = xTaskGetTickCount();
      PushFrameData();
      return 0;

    case MG_EV_WEBSOCKET_FRAME:
      {
      websocket_message* wm = (websocket_message*) p;
      if (wm->size > 512) return 0;   // reject oversized frames
      std::string msg;
      msg.assign((char*) wm->data, wm->size);
      HandleCommand(msg);
      return 0;
      }

    case MG_EV_POLL:
      {
      TickType_t now = xTaskGetTickCount();
      if ((now - m_last_push) >= pdMS_TO_TICKS(500))
        {
        m_last_push = now;
        PushFrameData();
        }
      return ev;
      }

    case MG_EV_CLOSE:
      // Self-delete: ~MgHandler() sets nc->user_data = NULL.
      // Return 0 so the framework does not call DestroyWebSocketHandler()
      // with our non-slot pointer.
      delete this;
      return 0;
    }

  return ev;
  }

void CanMonWsHandler::PushFrameData()
  {
  if (!m_nc) return;
  std::string json = BuildCanMonJson();
  mg_send_websocket_frame(m_nc, WEBSOCKET_OP_TEXT, json.data(), json.size());
  }

void CanMonWsHandler::HandleCommand(const std::string& msg)
  {
  std::string action = json_get_str(msg, "action");

  if (action == "start")
    {
    std::string filter = json_get_str(msg, "filter");
    if (filter.size() > 64 || !is_valid_re_filter(filter, true)) return;
    std::string cmd = "re start";
    if (!filter.empty()) { cmd += " "; cmd += filter; }
    OvmsWebServer::ExecuteCommand(cmd);
    }
  else if (action == "stop")
    {
    OvmsWebServer::ExecuteCommand("re stop");
    }
  else if (action == "clear")
    {
    OvmsWebServer::ExecuteCommand("re clear");
    if (s_can_queue) xQueueReset(s_can_queue);
    s_frame_store.clear();
    s_reassembly.clear();
    s_history.clear();
    }
  else if (action == "query")
    {
    // Required: bus (1-5), txid (hex), pidfrom (hex), pidto (hex).
    // Optional: mode (hex poll type), respfrom/respto (hex ECU ID range).
    std::string bus      = json_get_str(msg, "bus");
    std::string txid     = json_get_str(msg, "txid");
    std::string pidfrom  = json_get_str(msg, "pidfrom");
    std::string pidto    = json_get_str(msg, "pidto");
    std::string mode     = json_get_str(msg, "mode");      // optional
    std::string respfrom = json_get_str(msg, "respfrom");  // optional
    std::string respto   = json_get_str(msg, "respto");    // optional
    std::string timeout  = json_get_str(msg, "timeout");   // optional, 1-10 s

    if (bus.size() != 1 || !isdigit((unsigned char)bus[0]) ||
        !is_valid_hex(txid)              ||
        !is_valid_hex(pidfrom)           || !is_valid_hex(pidto) ||
        !is_valid_hex(mode,     true)    ||
        !is_valid_hex(respfrom, true)    || !is_valid_hex(respto, true) ||
        !is_valid_decimal(timeout, true))
      return;

    std::string cmd = "re obdii scan start " + bus + " " + txid + " " +
                      pidfrom + " " + pidto;
    if (!respfrom.empty())
      {
      cmd += " -r" + respfrom;
      if (!respto.empty()) cmd += "-" + respto;
      }
    if (!mode.empty())    cmd += " -t" + mode;
    if (!timeout.empty()) cmd += " -x" + timeout;
    OvmsWebServer::ExecuteCommand(cmd);
    s_scanning = true;
    }
  else if (action == "stopquery")
    {
    OvmsWebServer::ExecuteCommand("re obdii scan stop");
    s_scanning = false;
    }
  else if (action == "cantx")
    {
    std::string bus_s  = json_get_str(msg, "bus");
    std::string id_s   = json_get_str(msg, "id");
    std::string data_s = json_get_str(msg, "data");

    // Strip spaces from data, keep only hex digits
    std::string clean;
    for (unsigned char ch : data_s)
      if (isxdigit(ch)) clean += (char)ch;

    auto send_err = [&](const char* e)
      {
      std::string r = "{\"cantx_result\":\"";
      r += e; r += "\"}";
      mg_send_websocket_frame(m_nc, WEBSOCKET_OP_TEXT, r.data(), r.size());
      };

    if (bus_s.size() != 1 || !isdigit((unsigned char)bus_s[0]) ||
        id_s.empty() || !is_valid_hex(id_s) || id_s.size() > 8 ||
        clean.size() % 2 != 0 || clean.size() > 16)
      { send_err("error: bad parameters"); return; }

    // GetBus() is 0-indexed: GetBus(0)=can1, GetBus(1)=can2, ...
    canbus* cbus = MyCan.GetBus(bus_s[0] - '1');
    if (!cbus) { send_err("error: bus not found"); return; }
    if (cbus->m_mode != CAN_MODE_ACTIVE)
      { send_err("error: bus not in active mode (read-only)"); return; }

    uint32_t can_id = 0;
    sscanf(id_s.c_str(), "%x", &can_id);

    uint8_t dlc = (uint8_t)(clean.size() / 2);
    uint8_t data[8] = {};
    for (uint8_t i = 0; i < dlc; i++)
      { unsigned int v = 0; sscanf(clean.c_str() + i*2, "%02x", &v); data[i] = (uint8_t)v; }

    esp_err_t res = (can_id > 0x7FF)
      ? cbus->WriteExtended(can_id, dlc, data)
      : cbus->WriteStandard((uint16_t)can_id, dlc, data);

    std::string resp = (res == ESP_OK)
      ? "{\"cantx_result\":\"ok\"}"
      : "{\"cantx_result\":\"error: write failed\"}";
    mg_send_websocket_frame(m_nc, WEBSOCKET_OP_TEXT, resp.data(), resp.size());
    }
  else if (action == "get_dbc")
    {
    std::string json = BuildDbcJson();
    mg_send_websocket_frame(m_nc, WEBSOCKET_OP_TEXT, json.data(), json.size());
    }
  }


/**
 * CreateCanMonWsHandler: called from EventHandler on HANDSHAKE_REQUEST
 * for /ws/canmonitor.  Checks session auth then attaches a CanMonWsHandler.
 */
void OvmsWebServer::CreateCanMonWsHandler(mg_connection* nc, http_message* hm)
  {
  // Require session auth if a module password is configured.
  if (!MyConfig.GetParamValue("password", "module").empty() &&
      MyWebServer.GetSession(hm) == NULL)
    {
    mg_http_send_error(nc, 401, "Unauthorized");
    nc->flags |= MG_F_SEND_AND_CLOSE;
    return;
    }
  new CanMonWsHandler(nc);
  }


/**
 * HandleCanMonitor: serve the CAN monitor HTML/JS page
 */
void OvmsWebServer::HandleCanMonitor(PageEntry_t& p, PageContext_t& c)
  {
  // One-time setup: CAN listener queue and pidscan stop event.
  static bool s_registered = false;
  if (!s_registered)
    {
    s_registered = true;
    // Register a CAN listener so we receive every frame for ISO 15765-2 reassembly.
    s_can_queue = xQueueCreate(100, sizeof(CAN_frame_t));
    if (s_can_queue) MyCan.RegisterListener(s_can_queue, false);
#ifdef CONFIG_OVMS_COMP_RE_TOOLS_PID
    auto clear_scanning = [](std::string, void*) { s_scanning = false; };
    MyEvents.RegisterEvent(TAG,              "retools.pidscan.stop", clear_scanning);
    MyEvents.RegisterEvent("webcanmon.done", "retools.pidscan.done", clear_scanning);
#endif
    }

  c.head(200);
  PAGE_HOOK("body.pre");

  // ── OBDII query panel ────────────────────────────────────────────────
  c.print(
    "<div class=\"panel panel-warning\">"
      "<div class=\"panel-heading\">OBDII PID Query</div>"
      "<div class=\"panel-body\">"
        "<div style=\"display:flex;flex-wrap:wrap;gap:4px;align-items:center;margin-bottom:8px\">"
          "<button id=\"canmon-startbtn\" type=\"button\""
            " class=\"btn btn-sm btn-success\">RE&nbsp;Start</button>"
          "<button id=\"canmon-stopbtn\" type=\"button\""
            " class=\"btn btn-sm btn-danger\" style=\"display:none\">RE&nbsp;Stop</button>"
          "<button id=\"canmon-clearbtn\" type=\"button\""
            " class=\"btn btn-sm btn-default\">Clear</button>"
          "<button id=\"canmon-freezebtn\" type=\"button\""
            " class=\"btn btn-sm btn-default\">Freeze</button>"
          "<button id=\"canmon-currcsvbtn\" type=\"button\""
            " class=\"btn btn-sm btn-default\">Export&nbsp;CSV</button>"
          "<button id=\"canmon-crtdbtn\" type=\"button\""
            " class=\"btn btn-sm btn-default\">&#x23fa;&nbsp;CRTD</button>"
          "<span id=\"canmon-log-status\""
            " style=\"font-size:11px;margin-left:2px\"></span>"
          "<div id=\"canmon-spark-tip\" style=\"display:none;position:fixed;"
            "background:#fff;border:1px solid #ccc;padding:6px 10px;"
            "border-radius:4px;pointer-events:none;z-index:1000\"></div>"
          "<span id=\"canmon-status\" class=\"text-muted\""
            " style=\"margin-left:4px\"></span>"
        "</div>"
        "<form id=\"canmon-qform\""
          " style=\"display:flex;flex-wrap:wrap;gap:6px;align-items:flex-end\">"
          "<div>"
            "<div class=\"canmon-qlabel\">Bus</div>"
            "<select name=\"qbus\" class=\"form-control input-sm\">"
              "<option value=\"1\">can1</option>"
              "<option value=\"2\">can2</option>"
              "<option value=\"3\">can3</option>"
              "<option value=\"4\">can4</option>"
              "<option value=\"5\">can5</option>"
            "</select>"
          "</div>"
          "<div>"
            "<div class=\"canmon-qlabel\">TX&nbsp;ID</div>"
            "<input name=\"qtxid\" type=\"text\" class=\"form-control input-sm\""
              " style=\"width:6em\" placeholder=\"7DF\" value=\"7DF\">"
          "</div>"
          "<div>"
            "<div class=\"canmon-qlabel\">Mode&nbsp;<small class=\"text-muted\">(opt)</small></div>"
            "<input name=\"qmode\" type=\"text\" class=\"form-control input-sm\""
              " style=\"width:5em\" placeholder=\"01\">"
          "</div>"
          "<div>"
            "<div class=\"canmon-qlabel\">PID&nbsp;range</div>"
            "<div style=\"display:flex;align-items:center;gap:4px\">"
              "<input name=\"pidfrom\" type=\"text\" class=\"form-control input-sm\""
                " style=\"width:5em\" placeholder=\"0000\" value=\"0000\">"
              "<span>&ndash;</span>"
              "<input name=\"pidto\" type=\"text\" class=\"form-control input-sm\""
                " style=\"width:5em\" placeholder=\"FFFF\" value=\"FFFF\">"
            "</div>"
          "</div>"
          "<div>"
            "<div class=\"canmon-qlabel\">Resp&nbsp;<small class=\"text-muted\">(opt)</small></div>"
            "<div style=\"display:flex;align-items:center;gap:4px\">"
              "<input name=\"respfrom\" type=\"text\" class=\"form-control input-sm\""
                " style=\"width:5em\" placeholder=\"7E8\">"
              "<span>&ndash;</span>"
              "<input name=\"respto\" type=\"text\" class=\"form-control input-sm\""
                " style=\"width:5em\" placeholder=\"7EF\">"
            "</div>"
          "</div>"
          "<div>"
            "<div class=\"canmon-qlabel\">Timeout&nbsp;<small class=\"text-muted\">(s)</small></div>"
            "<input name=\"qtimeout\" type=\"number\" class=\"form-control input-sm\""
              " style=\"width:4em\" value=\"3\" min=\"1\" max=\"10\">"
          "</div>"
          "<div style=\"display:flex;align-items:center;gap:6px;flex-wrap:wrap\">"
            "<button id=\"canmon-querybtn\" type=\"submit\""
              " class=\"btn btn-sm btn-warning\">Start&nbsp;Query</button>"
            "<button id=\"canmon-stopqbtn\" type=\"button\""
              " class=\"btn btn-sm btn-danger\" style=\"display:none\">Stop&nbsp;Query</button>"
            "<span id=\"canmon-qstatus\" class=\"text-muted\"></span>"
            "<button id=\"canmon-qhistbtn\" type=\"button\""
              " class=\"btn btn-sm btn-default\" title=\"Query history\""
              ">&#x1F551;&nbsp;History</button>"
          "</div>"
        "</form>"
      "</div>"
    "</div>"
  );

  // ── CAN TX panel ─────────────────────────────────────────────────────
  c.print(
    "<div class=\"panel panel-default\">"
      "<div class=\"panel-heading\">CAN TX</div>"
      "<div class=\"panel-body\">"
        "<form id=\"canmon-txform\""
          " style=\"display:flex;flex-wrap:wrap;gap:6px;align-items:flex-end\">"
          "<div>"
            "<div class=\"canmon-qlabel\">Bus</div>"
            "<select name=\"txbus\" class=\"form-control input-sm\">"
              "<option value=\"1\">can1</option>"
              "<option value=\"2\">can2</option>"
              "<option value=\"3\">can3</option>"
              "<option value=\"4\">can4</option>"
              "<option value=\"5\">can5</option>"
            "</select>"
          "</div>"
          "<div>"
            "<div class=\"canmon-qlabel\">CAN&nbsp;ID"
              "<small class=\"text-muted\">&nbsp;(&gt;7FF&rarr;ext)</small>"
            "</div>"
            "<input name=\"txid\" type=\"text\" class=\"form-control input-sm\""
              " style=\"width:7em\" placeholder=\"7DF\">"
          "</div>"
          "<div>"
            "<div class=\"canmon-qlabel\">Data&nbsp;<small class=\"text-muted\">(hex bytes, max&nbsp;8)</small></div>"
            "<input name=\"txdata\" type=\"text\" class=\"form-control input-sm\""
              " style=\"width:22em;max-width:100%\" placeholder=\"02 21 01 00 00 00 00 00\">"
          "</div>"
          "<div style=\"display:flex;align-items:center;gap:6px\">"
            "<button type=\"submit\" class=\"btn btn-sm btn-primary\">Send</button>"
            "<button id=\"canmon-txhistbtn\" type=\"button\""
              " class=\"btn btn-sm btn-default\" title=\"TX history\""
              ">&#x1F551;&nbsp;History</button>"
            "<span id=\"canmon-txstatus\" class=\"text-muted\"></span>"
          "</div>"
        "</form>"
      "</div>"
    "</div>"
  );

  // ── Results table ────────────────────────────────────────────────────
  c.print(
    "<div class=\"panel panel-primary\">"
      "<div class=\"panel-heading\""
        " style=\"display:flex;justify-content:space-between;align-items:center\">"
        "<span>Captured Frames</span>"
        "<button id=\"canmon-colsbtn\" type=\"button\""
          " class=\"btn btn-xs btn-default canmon-sm-only\">More&nbsp;cols</button>"
      "</div>"
      "<div class=\"panel-body\">"
        "<p class=\"text-muted small\">"
          "Trailing padding bytes (0x00&nbsp;and&nbsp;0x55) are stripped for Int64. "
          "<strong>LE</strong>&nbsp;= data[0] is LSB; "
          "<strong>BE</strong>&nbsp;= data[0] is MSB. "
          "Multi-frame rows (yellow) show the full reassembled data payload."
        "</p>"
        "<div class=\"table-responsive\">"
          "<table class=\"table table-bordered table-condensed table-striped\">"
            "<thead>"
              "<tr>"
                "<th>Bus</th>"
                "<th>ID</th>"
                "<th>Type</th>"
                "<th>PID</th>"
                "<th>Hex&nbsp;data</th>"
                "<th class=\"canmon-col-sm-hide\">Int64&nbsp;LE</th>"
                "<th class=\"canmon-col-sm-hide\">Int64&nbsp;BE</th>"
                "<th>Count</th>"
                "<th class=\"canmon-col-sm-hide\">Rate</th>"
                "<th class=\"canmon-col-sm-hide\">Label</th>"
                "<th class=\"canmon-col-sm-hide\">Formula</th>"
                "<th></th>"
              "</tr>"
            "</thead>"
            "<tbody id=\"canmon-tbody\"></tbody>"
          "</table>"
        "</div>"
      "</div>"
    "</div>"
  );

  // ── History modal ────────────────────────────────────────────────────
  c.print(
    "<div id=\"canmon-hist-modal\" class=\"modal fade\" role=\"dialog\">"
      "<div class=\"modal-dialog\">"
        "<div class=\"modal-content\">"
          "<div class=\"modal-header\">"
            "<button type=\"button\" class=\"close\""
              " data-dismiss=\"modal\">&times;</button>"
            "<h4 class=\"modal-title\">"
              "History &mdash; <code id=\"canmon-hist-key\"></code>"
            "</h4>"
          "</div>"
          "<div class=\"modal-body\">"
            "<table class=\"table table-condensed table-bordered"
                          " table-striped\">"
              "<thead><tr>"
                "<th>Count</th>"
                "<th>Hex data</th>"
              "</tr></thead>"
              "<tbody id=\"canmon-hist-tbody\"></tbody>"
            "</table>"
          "</div>"
        "</div>"
      "</div>"
    "</div>"
  );

  // ── Query-history modal ──────────────────────────────────────────────
  c.print(
    "<div id=\"canmon-qhist-modal\" class=\"modal fade\" role=\"dialog\">"
      "<div class=\"modal-dialog\">"
        "<div class=\"modal-content\">"
          "<div class=\"modal-header\">"
            "<button type=\"button\" class=\"close\""
              " data-dismiss=\"modal\">&times;</button>"
            "<h4 class=\"modal-title\">Query History</h4>"
          "</div>"
          "<div class=\"modal-body\" style=\"padding:0\">"
            "<table class=\"table table-condensed table-bordered"
                          " table-striped\" style=\"margin:0\">"
              "<thead><tr>"
                "<th>Parameters</th>"
                "<th style=\"width:40px\"></th>"
              "</tr></thead>"
              "<tbody id=\"canmon-qhist-tbody\"></tbody>"
            "</table>"
          "</div>"
          "<div class=\"modal-footer\" style=\"padding:8px 12px\">"
            "<small class=\"text-muted\">Click a row to restore the form fields.</small>"
            "<button type=\"button\" class=\"btn btn-default btn-sm pull-right\""
              " data-dismiss=\"modal\">Close</button>"
          "</div>"
        "</div>"
      "</div>"
    "</div>"
  );

  // ── CAN TX history modal ─────────────────────────────────────────────
  c.print(
    "<div id=\"canmon-txhist-modal\" class=\"modal fade\" role=\"dialog\">"
      "<div class=\"modal-dialog\">"
        "<div class=\"modal-content\">"
          "<div class=\"modal-header\">"
            "<button type=\"button\" class=\"close\""
              " data-dismiss=\"modal\">&times;</button>"
            "<h4 class=\"modal-title\">CAN TX History</h4>"
          "</div>"
          "<div class=\"modal-body\" style=\"padding:0\">"
            "<table class=\"table table-condensed table-bordered"
                          " table-striped\" style=\"margin:0\">"
              "<thead><tr>"
                "<th>Frame</th>"
                "<th style=\"width:40px\"></th>"
              "</tr></thead>"
              "<tbody id=\"canmon-txhist-tbody\"></tbody>"
            "</table>"
          "</div>"
          "<div class=\"modal-footer\" style=\"padding:8px 12px\">"
            "<small class=\"text-muted\">Click a row to restore the form fields.</small>"
            "<button type=\"button\" class=\"btn btn-default btn-sm pull-right\""
              " data-dismiss=\"modal\">Close</button>"
          "</div>"
        "</div>"
      "</div>"
    "</div>"
  );

  // ── Byte-inspector bar ───────────────────────────────────────────────
  c.print(
    "<div id=\"canmon-sel-panel\" class=\"canmon-sel-bar\""
      " style=\"display:none;position:fixed;bottom:0;left:0;right:0;"
               "background:#f0f4f8;border-top:2px solid #337ab7;"
               "border-radius:12px 12px 0 0;"
               "padding:6px 12px;z-index:1050;font-family:monospace;font-size:13px\">"
      "<button type=\"button\" id=\"canmon-sel-close\""
        " class=\"close\" style=\"float:right;margin-left:12px\">&times;</button>"
      "<div><strong>Sel:</strong>&nbsp;"
        "<span id=\"canmon-sel-bytes\"></span>&nbsp;"
        "<span id=\"canmon-sel-nbytes\" class=\"text-muted\"></span>"
      "</div>"
      "<div style=\"display:flex;flex-wrap:wrap;gap:12px;margin-top:2px\">"
        "<span><strong>LE</strong>&nbsp;"
          "u:&nbsp;<span id=\"canmon-sel-le-u\"></span>"
          "&nbsp;s:&nbsp;<span id=\"canmon-sel-le-s\"></span>"
        "</span>"
        "<span><strong>BE</strong>&nbsp;"
          "u:&nbsp;<span id=\"canmon-sel-be-u\"></span>"
          "&nbsp;s:&nbsp;<span id=\"canmon-sel-be-s\"></span>"
        "</span>"
        "<span><strong>ASCII</strong>&nbsp;"
          "<span id=\"canmon-sel-ascii\" style=\"color:#555\"></span>"
        "</span>"
      "</div>"
      "<div id=\"canmon-sel-f32row\" style=\"display:none;margin-top:2px\">"
        "<strong>f32</strong>&nbsp;"
        "<span id=\"canmon-sel-f32\" style=\"color:#555\"></span>"
      "</div>"
    "</div>"
  );

  // ── JavaScript ───────────────────────────────────────────────────────
  c.print(
    "\n<script>\n"
    "(function(){\n"
    "  var tbody   = document.getElementById('canmon-tbody');\n"
    "  var $status  = $('#canmon-status');\n"
    "  var $qstatus = $('#canmon-qstatus');\n"
    "  var lastFrames = {};\n"
    "  var ws = null;\n"
    "  var reRunning = false;\n"
    "  var snapshotFrames = null;\n"
    "  var LABEL_PFX = 'canmon_lbl_';\n"
    "  function getLabel(key) {\n"
    "    try { return localStorage.getItem(LABEL_PFX+key) || ''; } catch(e) { return ''; }\n"
    "  }\n"
    "  function setLabel(key, val) {\n"
    "    try {\n"
    "      if (val) localStorage.setItem(LABEL_PFX+key, val);\n"
    "      else localStorage.removeItem(LABEL_PFX+key);\n"
    "    } catch(e) {}\n"
    "  }\n"
    "  var FORMULA_PFX = 'canmon_fml_';\n"
    "  function getFormula(key) {\n"
    "    try { return localStorage.getItem(FORMULA_PFX+key)||''; } catch(e) { return ''; }\n"
    "  }\n"
    "  function setFormula(key, val) {\n"
    "    try {\n"
    "      if (val) localStorage.setItem(FORMULA_PFX+key, val);\n"
    "      else localStorage.removeItem(FORMULA_PFX+key);\n"
    "    } catch(e) {}\n"
    "  }\n"
    "  var rateHistory    = {};\n"
    "  var sparkData      = {};\n"
    "  var dbcDefs        = {};\n"
    "  var dbcVersion     = 0;\n"
    "  var byteChangeTimes = {};\n"
    "  var crtdWriter  = null;\n"       /* File System Access API writable stream */
    "  var crtdFrameCount = 0;\n"
    "  var crtdBytesWritten = 0;\n"
    "  var idbDb     = null;\n"          /* IndexedDB fallback */
    "  var idbActive = false;\n"
    "  var idbCount  = 0;\n"
    "  var idbHeader = '';\n"
    "\n"
    "  function fmtId(id, ext) {\n"
    "    var s = id.toString(16).toUpperCase();\n"
    "    var pad = ext ? 8 : 3;\n"
    "    while (s.length < pad) s = '0' + s;\n"
    "    return '0x' + s;\n"
    "  }\n"
    "\n"
    // ── Byte-selection state ────────────────────────────────────────────
    "  var sel = { row: null, s: -1, e: -1 };\n"
    "  var mouseSelActive = false;\n"
    "\n"
    "  function applySelHL() {\n"
    "    document.querySelectorAll('#canmon-tbody .cb.sel').forEach(function(el) {\n"
    "      el.classList.remove('sel');\n"
    "    });\n"
    "    if (!sel.row || sel.s < 0) return;\n"
    "    var rid = 'rk_' + sel.row.replace(/[^a-zA-Z0-9]/g, '_');\n"
    "    var row = document.getElementById(rid);\n"
    "    if (!row) return;\n"
    "    var mn = Math.min(sel.s, sel.e), mx = Math.max(sel.s, sel.e);\n"
    "    [].forEach.call(row.cells[4].querySelectorAll('.cb'), function(el) {\n"
    "      var i = parseInt(el.dataset.i, 10);\n"
    "      if (i >= mn && i <= mx) el.classList.add('sel');\n"
    "    });\n"
    "  }\n"
    "\n"
    "  function updateRowSnapDiff(row, f) {\n"
    "    var cbs = row.cells[4].querySelectorAll('.cb');\n"
    "    if (!snapshotFrames) {\n"
    "      [].forEach.call(cbs, function(el) { el.classList.remove('canmon-byte-snap-diff'); });\n"
    "      return;\n"
    "    }\n"
    "    var snap = snapshotFrames[f.key];\n"
    "    if (!snap) return;\n"
    "    var snapParts = snap.hex ? snap.hex.split(' ') : [];\n"
    "    var curParts  = (f.hex || '').split(' ');\n"
    "    [].forEach.call(cbs, function(el) {\n"
    "      var i = parseInt(el.dataset.i, 10);\n"
    "      el.classList.toggle('canmon-byte-snap-diff',\n"
    "        snapParts[i] !== undefined && snapParts[i] !== curParts[i]);\n"
    "    });\n"
    "  }\n"
    "\n"
    // ── DBC client-side bit extraction (mirrors dbc.cpp algorithms)
    "  function extractBitsLE(b, bpos, bits) {\n"
    "    var val=0, pos=0;\n"
    "    while(bits>0){\n"
    "      var align=bpos&7, shift=Math.min(8-align,bits);\n"
    "      val|=((b[bpos>>3]>>align)&((1<<shift)-1))<<pos;\n"
    "      pos+=shift; bpos+=shift; bits-=shift;\n"
    "    }\n"
    "    return val;\n"
    "  }\n"
    "  function extractBitsBE(b, bpos, bits) {\n"
    "    var pos=bits, val=0;\n"
    "    while(bits>0){\n"
    "      var sl=Math.min((bpos&7)+1,bits), al=((bpos&7)+1)-sl;\n"
    "      pos-=sl;\n"
    "      val|=((b[bpos>>3]>>al)&((1<<sl)-1))<<pos;\n"
    "      bpos=((bpos>>3)+1)*8+7; bits-=sl;\n"
    "    }\n"
    "    return val;\n"
    "  }\n"
    "  function decodeSig(b, sig) {\n"
    "    var raw = sig.be ? extractBitsBE(b,sig.s,sig.l) : extractBitsLE(b,sig.s,sig.l);\n"
    "    if (sig.sg) {\n"
    "      var sb = sig.l-1;\n"
    "      if (raw&(1<<sb)) raw = (raw|(~((1<<sb)-1)))|0;\n"
    "    }\n"
    "    return Math.round((raw*sig.f+sig.o)*10000)/10000;\n"
    "  }\n"
    "  function decodeDbcRow(hexStr, id) {\n"
    "    var sigs = dbcDefs[id];\n"
    "    if (!sigs||!sigs.length||!hexStr) return '';\n"
    "    var b = hexStr.split(' ').map(function(h){return parseInt(h,16)||0;});\n"
    "    return sigs.map(function(s){\n"
    "      return s.n+'=<b>'+decodeSig(b,s)+'</b>'+(s.u?'&thinsp;'+s.u:'');\n"
    "    }).join('&nbsp;&nbsp;');\n"
    "  }\n"
    "  function updateRate(key, val) {\n"
    "    var now = Date.now()/1000;\n"
    "    if (isNaN(val)) { delete rateHistory[key]; delete sparkData[key]; return ''; }\n"
    "    if (!sparkData[key]) sparkData[key]=[];\n"
    "    sparkData[key].push(val);\n"
    "    if (sparkData[key].length>30) sparkData[key].splice(0,sparkData[key].length-30);\n"
    "    if (!rateHistory[key]) { rateHistory[key]=[{v:val,t:now}]; return ''; }\n"
    "    var h = rateHistory[key];\n"
    "    h.push({v:val,t:now});\n"
    "    if (h.length>6) h.splice(0,h.length-6);\n"
    "    var dt = h[h.length-1].t-h[0].t;\n"
    "    if (dt<0.3) return '';\n"
    "    var dv = h[h.length-1].v-h[0].v, r = dv/dt;\n"
    "    if (r===0) return '0';\n"
    "    return (Math.abs(r)<10?r.toFixed(2):r.toFixed(1))+'/s';\n"
    "  }\n"
    "  function makeSparkSvg(arr) {\n"
    "    if (!arr||arr.length<2) return '';\n"
    "    var mn=Math.min.apply(null,arr), mx=Math.max.apply(null,arr);\n"
    "    var range=mx-mn||1, w=80, h=24;\n"
    "    var pts=arr.map(function(v,i){\n"
    "      return (i/(arr.length-1)*w).toFixed(1)+','+(h-(v-mn)/range*h).toFixed(1);\n"
    "    }).join(' ');\n"
    "    return '<svg width=\"'+w+'\" height=\"'+h+'\" style=\"overflow:visible;display:block\">'\n"
    "         + '<polyline points=\"'+pts+'\" fill=\"none\" stroke=\"#337ab7\" stroke-width=\"1.5\"/>'\n"
    "         + '</svg><div style=\"font-size:10px;color:#888\">'+mn.toFixed(3)\n"
    "         + '&nbsp;&hellip;&nbsp;'+mx.toFixed(3)+'</div>';\n"
    "  }\n"
    "  function evalFormula(fml, hexStr) {\n"
    "    try {\n"
    "      var b = hexStr.split(' ').map(function(h){return parseInt(h,16);});\n"
    "      var v = new Function('b','return ('+fml+')')(b);\n"
    "      return v===undefined?'':String(Math.round(v*10000)/10000);\n"
    "    } catch(e) { return 'err'; }\n"
    "  }\n"
    "  function csvCell(v) { return '\"'+String(v==null?'':v).replace(/\"/g,'\"\"')+'\"'; }\n"
    "  function triggerDownload(content, filename) {\n"
    "    var a = document.createElement('a');\n"
    "    a.href = URL.createObjectURL(new Blob([content],{type:'text/csv'}));\n"
    "    a.download = filename;\n"
    "    a.click();\n"
    "    setTimeout(function(){ URL.revokeObjectURL(a.href); }, 1000);\n"
    "  }\n"
    "  function updateLogStatus() {\n"
    "    var el = document.getElementById('canmon-log-status');\n"
    "    if (!el) return;\n"
    "    var parts = [];\n"
    "    if (crtdWriter || idbActive) {\n"
    "      var mb = (crtdBytesWritten/1048576).toFixed(1);\n"
    "      var mode = crtdWriter ? '\u2192file' : '\u2192IDB';\n"
    "      parts.push('\u23fa ' + crtdFrameCount + ' frames \u00b7 ' + mb + ' MB ' + mode);\n"
    "    }\n"
    "    el.textContent = parts.join('  ');\n"
    "    el.style.color = idbActive ? '#e67e22' : '#337ab7';\n"
    "    if (!crtdWriter && !idbActive) el.textContent = '';\n"
    "  }\n"
    "  // ── CRTD frame reconstruction ──────────────────────────────────────\n"
    "  function crtdLineFromEntry(r) {\n"
    "    var sec = Math.floor(r.tsMs/1000);\n"
    "    var us  = String((r.tsMs%1000)*1000).padStart(6,'0');\n"
    "    var ts  = sec+'.'+us;\n"
    "    var busNum = (r.bus.match(/\\d+/)||['1'])[0];\n"
    "    var ft  = r.ext ? '29' : '11';\n"
    "    var idP = r.ext ? 8 : 3;\n"
    "    var idH = r.id.toString(16).toUpperCase().padStart(idP,'0');\n"
    "    function h2(n){ return ('0'+(n&0xFF).toString(16).toUpperCase()).slice(-2); }\n"
    "    var pl = [];\n"
    "    if (r.type && r.type!=='--') pl.push(parseInt(r.type,16));\n"
    "    if (r.pid  && r.pid !=='--') {\n"
    "      for (var i=0;i+1<r.pid.length;i+=2)\n"
    "        pl.push(parseInt(r.pid.slice(i,i+2),16));\n"
    "    }\n"
    "    if (r.hex) r.hex.split(' ').filter(Boolean).forEach(function(h){\n"
    "      pl.push(parseInt(h,16));\n"
    "    });\n"
    "    var out='';\n"
    "    if (pl.length===0) return out;\n"
    "    if (pl.length<=7) {\n"
    "      var f=[pl.length].concat(pl);\n"
    "      while(f.length<8) f.push(0);\n"
    "      out=ts+' '+busNum+'R'+ft+' '+idH+' '+f.map(h2).join(' ')+'\\n';\n"
    "    } else {\n"
    "      var tot=pl.length;\n"
    "      var ff=[0x10|((tot>>8)&0x0F),tot&0xFF].concat(pl.slice(0,6));\n"
    "      while(ff.length<8) ff.push(0);\n"
    "      out=ts+' '+busNum+'R'+ft+' '+idH+' '+ff.map(h2).join(' ')+'\\n';\n"
    "      var off=6,seq=1;\n"
    "      while(off<pl.length){\n"
    "        var cf=[0x20|(seq&0x0F)].concat(pl.slice(off,off+7));\n"
    "        while(cf.length<8) cf.push(0);\n"
    "        out+=ts+' '+busNum+'R'+ft+' '+idH+' '+cf.map(h2).join(' ')+'\\n';\n"
    "        off+=7; seq=(seq+1)&0x0F;\n"
    "      }\n"
    "    }\n"
    "    return out;\n"
    "  }\n"
    "  function crtdMakeHeader() {\n"
    "    var now=Date.now(), sec=Math.floor(now/1000);\n"
    "    var us=String((now%1000)*1000).padStart(6,'0');\n"
    "    return sec+'.'+us+' CXX OVMS CRTD\\n'+sec+'.'+us+' CVR 3.1\\n';\n"
    "  }\n"
    "  function crtdSetActive(active, buffered) {\n"
    "    if (active) {\n"
    "      var lbl = buffered ? '&#x23f9;&nbsp;Export&nbsp;CRTD' : '&#x23f9;&nbsp;Stop&nbsp;CRTD';\n"
    "      $('#canmon-crtdbtn').html(lbl)\n"
    "        .removeClass('btn-default')\n"
    "        .addClass(buffered ? 'btn-warning' : 'btn-danger');\n"
    "    } else {\n"
    "      $('#canmon-crtdbtn').html('&#x23fa;&nbsp;CRTD')\n"
    "        .removeClass('btn-danger btn-warning').addClass('btn-default');\n"
    "    }\n"
    "    updateLogStatus();\n"
    "  }\n"
    "\n"
    // ── IndexedDB helpers (fallback for browsers without File System Access API)
    "  function idbOpen(cb) {\n"
    "    var req = indexedDB.open('canmon_crtd', 1);\n"
    "    req.onupgradeneeded = function(e) {\n"
    "      e.target.result.createObjectStore('frames', {autoIncrement:true});\n"
    "    };\n"
    "    req.onsuccess = function(e) { idbDb = e.target.result; cb(); };\n"
    "    req.onerror   = function()  { alert('IndexedDB unavailable.'); };\n"
    "  }\n"
    "  function idbAppendLines(text) {\n"
    "    if (!idbDb || !idbActive || !text) return;\n"
    "    idbDb.transaction('frames','readwrite').objectStore('frames').add(text);\n"
    "    idbCount++;\n"
    "    updateLogStatus();\n"
    "  }\n"
    "  function idbClear() {\n"
    "    idbCount = 0;\n"
    "    if (idbDb)\n"
    "      idbDb.transaction('frames','readwrite').objectStore('frames').clear();\n"
    "  }\n"
    // Read all IDB records via cursor, prepend header, build Blob, trigger download
    "  function idbExportAndStop() {\n"
    "    if (!idbDb) { stopCrtdCapture(); return; }\n"
    "    var btn = $('#canmon-crtdbtn');\n"
    "    btn.prop('disabled', true).html('&#x23f3;&nbsp;Exporting\u2026');\n"
    "    var chunks = [idbHeader];\n"
    "    var tx  = idbDb.transaction('frames','readonly');\n"
    "    var cur = tx.objectStore('frames').openCursor();\n"
    "    cur.onsuccess = function(e) {\n"
    "      var c = e.target.result;\n"
    "      if (c) { chunks.push(c.value); c.continue(); }\n"
    "      else {\n"
    "        idbActive = false;\n"
    "        idbClear();\n"
    "        var blob = new Blob(chunks, {type:'text/plain'});\n"
    "        var url  = URL.createObjectURL(blob);\n"
    "        var a = document.createElement('a');\n"
    "        var ts = new Date().toISOString().slice(0,19).replace(/[:T]/g,'-');\n"
    "        a.href = url; a.download = 'canmon_'+ts+'.crtd'; a.click();\n"
    "        setTimeout(function(){ URL.revokeObjectURL(url); }, 5000);\n"
    "        btn.prop('disabled', false);\n"
    "        crtdSetActive(false, false);\n"
    "      }\n"
    "    };\n"
    "    cur.onerror = function() {\n"
    "      btn.prop('disabled', false);\n"
    "      stopCrtdCapture();\n"
    "    };\n"
    "  }\n"
    "\n"
    "  function writeCrtdEntry(r) {\n"
    "    var lines = crtdLineFromEntry(r);\n"
    "    if (!lines) return;\n"
    "    if (crtdWriter) {\n"
    "      crtdWriter.write(lines).then(function(){\n"
    "        crtdBytesWritten += lines.length;\n"
    "        crtdFrameCount++;\n"
    "        updateLogStatus();\n"
    "      }).catch(function(){ stopCrtdCapture(); });\n"
    "    } else if (idbActive) {\n"
    "      crtdBytesWritten += lines.length;\n"
    "      crtdFrameCount++;\n"
    "      idbAppendLines(lines);\n"
    "    }\n"
    "  }\n"
    "  function stopCrtdCapture() {\n"
    "    if (crtdWriter) {\n"
    "      var w = crtdWriter; crtdWriter = null;\n"
    "      w.close().catch(function(){});\n"
    "      crtdSetActive(false, false);\n"
    "    } else if (idbActive) {\n"
    "      idbExportAndStop();\n"          /* export triggers its own cleanup */
    "    }\n"
    "  }\n"
    "  function startCrtdCapture() {\n"
    "    crtdFrameCount = 0; crtdBytesWritten = 0;\n"
    "    if (window.showSaveFilePicker) {\n"
    "      /* ── Stream mode: File System Access API (Chrome / Edge) ── */\n"
    "      var ts = new Date().toISOString().slice(0,19).replace(/[:T]/g,'-');\n"
    "      window.showSaveFilePicker({\n"
    "        suggestedName: 'canmon_'+ts+'.crtd',\n"
    "        types:[{description:'CRTD CAN log',accept:{'text/plain':['.crtd']}}]\n"
    "      }).then(function(fh){ return fh.createWritable(); })\n"
    "        .then(function(w){\n"
    "          crtdWriter = w;\n"
    "          var hdr = crtdMakeHeader();\n"
    "          return w.write(hdr).then(function(){\n"
    "            crtdBytesWritten += hdr.length;\n"
    "            crtdSetActive(true, false);\n"
    "          });\n"
    "        }).catch(function(e){\n"
    "          if (e.name !== 'AbortError') alert('CRTD: '+e.message);\n"
    "        });\n"
    "    } else {\n"
    "      /* ── Buffer mode: IndexedDB (Firefox / Safari / all others) ── */\n"
    "      idbOpen(function(){\n"
    "        idbClear();\n"
    "        idbHeader  = crtdMakeHeader();\n"
    "        idbActive  = true;\n"
    "        crtdSetActive(true, true);\n"
    "      });\n"
    "    }\n"
    "  }\n"
    "  function exportCsvCurrent() {\n"
    "    var hdr = 'Bus,ID,Type,PID,Hex Data,Label,Formula,Count\\n';\n"
    "    var rows = Object.keys(lastFrames).sort().map(function(k) {\n"
    "      var f = lastFrames[k];\n"
    "      return [f.bus, '0x'+f.id.toString(16).toUpperCase(), f.type, f.pid,\n"
    "              f.hex, getLabel(k), getFormula(k), f.cnt\n"
    "             ].map(csvCell).join(',');\n"
    "    }).join('\\n');\n"
    "    triggerDownload(hdr+rows,\n"
    "      'canmon_'+new Date().toISOString().slice(0,19).replace(/[:T]/g,'-')+'.csv');\n"
    "  }\n"
    "\n"
    // ── Query history ──────────────────────────────────────────────────
    "  var QHIST_KEY = 'canmon_qhist';\n"
    "  var MAX_QHIST = 10;\n"
    "  function loadQHist() {\n"
    "    try { return JSON.parse(localStorage.getItem(QHIST_KEY)||'[]'); }\n"
    "    catch(e) { return []; }\n"
    "  }\n"
    "  function saveQHist(arr) {\n"
    "    try { localStorage.setItem(QHIST_KEY, JSON.stringify(arr)); } catch(e) {}\n"
    "  }\n"
    "  function pushQHist(entry) {\n"
    "    var arr = loadQHist();\n"
    "    var es = JSON.stringify(entry);\n"
    "    arr = arr.filter(function(e){ return JSON.stringify(e) !== es; });\n"
    "    arr.unshift(entry);\n"
    "    if (arr.length > MAX_QHIST) arr = arr.slice(0, MAX_QHIST);\n"
    "    saveQHist(arr);\n"
    "  }\n"
    "  function fmtQHistEntry(e) {\n"
    "    var s = 'CAN' + e.bus + '  TX\u202f0x' + e.txid.toUpperCase();\n"
    "    if (e.mode) s += '  Mode\u202f0x' + e.mode.toUpperCase();\n"
    "    s += '  PIDs\u202f0x' + e.pidfrom.toUpperCase()\n"
    "           + '\u2013' + '0x' + e.pidto.toUpperCase();\n"
    "    if (e.respfrom) {\n"
    "      s += '  Resp\u202f0x' + e.respfrom.toUpperCase();\n"
    "      if (e.respto) s += '\u20130x' + e.respto.toUpperCase();\n"
    "    }\n"
    "    s += '  t\u202f' + e.timeout + '\u202fs';\n"
    "    return s;\n"
    "  }\n"
    "  function restoreQHist(e) {\n"
    "    $('[name=qbus]').val(e.bus);\n"
    "    $('[name=qtxid]').val(e.txid);\n"
    "    $('[name=qmode]').val(e.mode||'');\n"
    "    $('[name=pidfrom]').val(e.pidfrom);\n"
    "    $('[name=pidto]').val(e.pidto);\n"
    "    $('[name=respfrom]').val(e.respfrom||'');\n"
    "    $('[name=respto]').val(e.respto||'');\n"
    "    $('[name=qtimeout]').val(e.timeout);\n"
    "    $('#canmon-qhist-modal').modal('hide');\n"
    "  }\n"
    "  function renderQHistModal() {\n"
    "    var arr = loadQHist();\n"
    "    var tb = document.getElementById('canmon-qhist-tbody');\n"
    "    if (!tb) return;\n"
    "    tb.innerHTML = '';\n"
    "    if (arr.length === 0) {\n"
    "      tb.innerHTML = '<tr><td colspan=\"2\" class=\"text-muted text-center\"'\n"
    "        +' style=\"padding:10px\">No history yet</td></tr>';\n"
    "      return;\n"
    "    }\n"
    "    arr.forEach(function(e, idx) {\n"
    "      var tr  = document.createElement('tr');\n"
    "      tr.style.cursor = 'pointer';\n"
    "      tr.title = 'Click to restore';\n"
    "      var td1 = document.createElement('td');\n"
    "      td1.style.fontFamily = 'monospace';\n"
    "      td1.style.fontSize   = '12px';\n"
    "      td1.style.wordBreak  = 'break-all';\n"
    "      td1.textContent = fmtQHistEntry(e);\n"
    "      var td2 = document.createElement('td');\n"
    "      td2.style.textAlign = 'center';\n"
    "      var del = document.createElement('button');\n"
    "      del.className   = 'btn btn-xs btn-danger';\n"
    "      del.textContent = '\u00d7';\n"
    "      del.title = 'Delete';\n"
    "      (function(i){\n"
    "        tr.onclick  = function(ev){\n"
    "          if (ev.target === del) return;\n"
    "          restoreQHist(arr[i]);\n"
    "        };\n"
    "        del.onclick = function(ev){\n"
    "          ev.stopPropagation();\n"
    "          var a = loadQHist(); a.splice(i,1); saveQHist(a);\n"
    "          renderQHistModal();\n"
    "        };\n"
    "      })(idx);\n"
    "      td2.appendChild(del);\n"
    "      tr.appendChild(td1); tr.appendChild(td2);\n"
    "      tb.appendChild(tr);\n"
    "    });\n"
    "  }\n"
    "\n"
    // ── CAN TX history ────────────────────────────────────────────────────
    "  var TXHIST_KEY = 'canmon_txhist';\n"
    "  var MAX_TXHIST = 10;\n"
    "  function loadTxHist() {\n"
    "    try { return JSON.parse(localStorage.getItem(TXHIST_KEY)||'[]'); }\n"
    "    catch(e) { return []; }\n"
    "  }\n"
    "  function saveTxHist(arr) {\n"
    "    try { localStorage.setItem(TXHIST_KEY, JSON.stringify(arr)); } catch(e) {}\n"
    "  }\n"
    "  function pushTxHist(e) {\n"
    "    var arr = loadTxHist();\n"
    "    var es  = JSON.stringify(e);\n"
    "    arr = arr.filter(function(x){ return JSON.stringify(x) !== es; });\n"
    "    arr.unshift(e);\n"
    "    if (arr.length > MAX_TXHIST) arr = arr.slice(0, MAX_TXHIST);\n"
    "    saveTxHist(arr);\n"
    "  }\n"
    "  function fmtTxHistEntry(e) {\n"
    "    return 'CAN' + e.bus + '  ID\u202f0x' + e.id.toUpperCase()\n"
    "         + '  Data\u202f' + e.data.toUpperCase();\n"
    "  }\n"
    "  function restoreTxHist(e) {\n"
    "    $('[name=txbus]').val(e.bus);\n"
    "    $('[name=txid]').val(e.id);\n"
    "    $('[name=txdata]').val(e.data);\n"
    "    $('#canmon-txhist-modal').modal('hide');\n"
    "  }\n"
    "  function renderTxHistModal() {\n"
    "    var arr = loadTxHist();\n"
    "    var tb = document.getElementById('canmon-txhist-tbody');\n"
    "    if (!tb) return;\n"
    "    tb.innerHTML = '';\n"
    "    if (arr.length === 0) {\n"
    "      tb.innerHTML = '<tr><td colspan=\"2\" class=\"text-muted text-center\"'\n"
    "        +' style=\"padding:10px\">No history yet</td></tr>';\n"
    "      return;\n"
    "    }\n"
    "    arr.forEach(function(e, idx) {\n"
    "      var tr  = document.createElement('tr');\n"
    "      tr.style.cursor = 'pointer';\n"
    "      tr.title = 'Click to restore';\n"
    "      var td1 = document.createElement('td');\n"
    "      td1.style.fontFamily = 'monospace';\n"
    "      td1.style.fontSize   = '12px';\n"
    "      td1.style.wordBreak  = 'break-all';\n"
    "      td1.textContent = fmtTxHistEntry(e);\n"
    "      var td2 = document.createElement('td');\n"
    "      td2.style.textAlign = 'center';\n"
    "      var del = document.createElement('button');\n"
    "      del.className   = 'btn btn-xs btn-danger';\n"
    "      del.textContent = '\u00d7';\n"
    "      del.title = 'Delete';\n"
    "      (function(i){\n"
    "        tr.onclick  = function(ev){\n"
    "          if (ev.target === del) return;\n"
    "          restoreTxHist(arr[i]);\n"
    "        };\n"
    "        del.onclick = function(ev){\n"
    "          ev.stopPropagation();\n"
    "          var a = loadTxHist(); a.splice(i,1); saveTxHist(a);\n"
    "          renderTxHistModal();\n"
    "        };\n"
    "      })(idx);\n"
    "      td2.appendChild(del);\n"
    "      tr.appendChild(td1); tr.appendChild(td2);\n"
    "      tb.appendChild(tr);\n"
    "    });\n"
    "  }\n"
    "\n"
    "  function bytesToInt(bytes, be) {\n"
    "    var arr = be ? bytes.slice().reverse() : bytes.slice();\n"
    "    if (typeof BigInt !== 'undefined' && bytes.length > 6) {\n"
    "      var n = BigInt(0);\n"
    "      for (var i = arr.length-1; i >= 0; i--)\n"
    "        n = (n << BigInt(8)) | BigInt(arr[i]);\n"
    "      var sb = BigInt(1) << BigInt(bytes.length*8 - 1);\n"
    "      return { u: n.toString(), s: (n >= sb ? n-(sb<<BigInt(1)) : n).toString() };\n"
    "    }\n"
    "    var n = 0;\n"
    "    for (var i = arr.length-1; i >= 0; i--) n = n*256 + arr[i];\n"
    "    var max = Math.pow(2, bytes.length*8);\n"
    "    return { u: n.toString(), s: (n >= max/2 ? n-max : n).toString() };\n"
    "  }\n"
    "\n"
    "  function updateSelPanel() {\n"
    "    var panel = document.getElementById('canmon-sel-panel');\n"
    "    if (!sel.row || sel.s < 0) { panel.style.display = 'none'; return; }\n"
    "    var frame = lastFrames[sel.row];\n"
    "    if (!frame || !frame.hex) { panel.style.display = 'none'; return; }\n"
    "    var parts = frame.hex.split(' ');\n"
    "    var mn = Math.min(sel.s, sel.e);\n"
    "    var mx = Math.min(Math.max(sel.s, sel.e), parts.length-1);\n"
    "    var chosen = parts.slice(mn, mx+1);\n"
    "    var bytes  = chosen.map(function(h) { return parseInt(h, 16); });\n"
    "    var le = bytesToInt(bytes, false), be = bytesToInt(bytes, true);\n"
    "    var nb = bytes.length;\n"
    "    document.getElementById('canmon-sel-bytes').textContent   = chosen.join(' ');\n"
    "    document.getElementById('canmon-sel-nbytes').textContent  = '('+nb+' byte'+(nb!==1?'s':'')+')';\n"
    "    document.getElementById('canmon-sel-le-u').textContent    = le.u;\n"
    "    document.getElementById('canmon-sel-le-s').textContent    = le.s;\n"
    "    document.getElementById('canmon-sel-be-u').textContent    = be.u;\n"
    "    document.getElementById('canmon-sel-be-s').textContent    = be.s;\n"
    "    var ascii = bytes.map(function(b) {\n"
    "      return (b >= 0x20 && b <= 0x7E) ? String.fromCharCode(b) : '.';\n"
    "    }).join('');\n"
    "    document.getElementById('canmon-sel-ascii').textContent = ascii;\n"
    "    var f32row = document.getElementById('canmon-sel-f32row');\n"
    "    if (bytes.length >= 4) {\n"
    "      var f32parts = [];\n"
    "      var buf = new ArrayBuffer(4);\n"
    "      var view = new DataView(buf);\n"
    "      for (var g = 0; g + 4 <= bytes.length; g += 4) {\n"
    "        for (var k = 0; k < 4; k++) view.setUint8(k, bytes[g+k]);\n"
    "        var fle = view.getFloat32(0, true);\n"
    "        var fbe = view.getFloat32(0, false);\n"
    "        var prefix = bytes.length > 4 ? '[' + (g/4) + '] ' : '';\n"
    "        var fmt = function(v) {\n"
    "          if (!isFinite(v)) return v.toString();\n"
    "          var s = v.toPrecision(6);\n"
    "          return parseFloat(s).toString();\n"
    "        };\n"
    "        f32parts.push(prefix + 'LE\u00a0' + fmt(fle) + '\u2002BE\u00a0' + fmt(fbe));\n"
    "      }\n"
    "      document.getElementById('canmon-sel-f32').textContent = f32parts.join('  |  ');\n"
    "      f32row.style.display = '';\n"
    "    } else {\n"
    "      f32row.style.display = 'none';\n"
    "    }\n"
    "    panel.style.display = '';\n"
    "  }\n"
    "\n"
    // ── UDS decode tables ───────────────────────────────────────────────\n"
    "  var UDS_TYPE = {\n"
    "    '10':['DSC','DiagnosticSessionControl','req'],\n"
    "    '11':['Reset','ECUReset','req'],\n"
    "    '19':['ReadDTC','ReadDTCInformation','req'],\n"
    "    '22':['RDBI','ReadDataByIdentifier','req'],\n"
    "    '23':['RdMem','ReadMemoryByAddress','req'],\n"
    "    '27':['SecAcc','SecurityAccess','req'],\n"
    "    '28':['CommCtrl','CommunicationControl','req'],\n"
    "    '2E':['WDBI','WriteDataByIdentifier','req'],\n"
    "    '2F':['IOCTRL','IOControlByIdentifier','req'],\n"
    "    '31':['RtnCtrl','RoutineControl','req'],\n"
    "    '3E':['TstPres','TesterPresent','req'],\n"
    "    '50':['DSC \u2713','DiagnosticSessionControl OK','pos'],\n"
    "    '51':['Reset \u2713','ECUReset OK','pos'],\n"
    "    '59':['DTC \u2713','ReadDTCInformation OK','pos'],\n"
    "    '61':['RdLocal \u2713','ReadDataByLocalIdentifier OK','pos'],\n"
    "    '62':['RDBI \u2713','ReadDataByIdentifier OK','pos'],\n"
    "    '67':['SecAcc \u2713','SecurityAccess OK','pos'],\n"
    "    '6E':['WDBI \u2713','WriteDataByIdentifier OK','pos'],\n"
    "    '6F':['IOCTRL \u2713','IOControlByIdentifier OK','pos'],\n"
    "    '71':['RtnCtrl \u2713','RoutineControl OK','pos'],\n"
    "    '7E':['TstPres \u2713','TesterPresent OK','pos'],\n"
    "    '7F':['NEG \u2717','Negative Response','neg'],\n"
    "  };\n"
    "  var UDS_NRC = {\n"
    "    '10':'generalReject','11':'serviceNotSupported',\n"
    "    '12':'subFunctionNotSupported','13':'invalidFormat',\n"
    "    '22':'conditionsNotCorrect','24':'requestSequenceError',\n"
    "    '31':'requestOutOfRange','33':'securityAccessDenied',\n"
    "    '35':'invalidKey','36':'exceededAttempts',\n"
    "    '37':'requiredTimeDelayNotExpired',\n"
    "    '78':'responsePending',\n"
    "    '7E':'notSupportedInActiveSession',\n"
    "    '7F':'serviceNotSupportedInActiveSession',\n"
    "  };\n"
    "  var UDS_SID = {\n"
    "    '10':'DiagnosticSessionControl','11':'ECUReset',\n"
    "    '19':'ReadDTCInformation','22':'ReadDataByIdentifier',\n"
    "    '23':'ReadMemoryByAddress','27':'SecurityAccess',\n"
    "    '28':'CommunicationControl','2E':'WriteDataByIdentifier',\n"
    "    '2F':'IOControlByIdentifier','31':'RoutineControl','3E':'TesterPresent',\n"
    "  };\n"
    "  var UDS_SESSION = {'01':'default','02':'programming','03':'extended','04':'safetySystem'};\n"
    "  var UDS_RTCTRL  = {'01':'startRoutine','02':'stopRoutine','03':'requestResult'};\n"
    "\n"
    "  function udsTypeHtml(type, pid, hex) {\n"
    "    var t = type.toUpperCase();\n"
    "    var info = UDS_TYPE[t];\n"
    "    if (!info) return null;\n"
    "    var tip = info[1];\n"
    "    if (t === '7F') {\n"
    "      var svc = UDS_SID[pid.toUpperCase()] || ('svc 0x'+pid);\n"
    "      var nrcByte = hex ? hex.split(' ')[0].toUpperCase() : '';\n"
    "      var nrc = nrcByte ? (UDS_NRC[nrcByte] || ('NRC 0x'+nrcByte)) : '';\n"
    "      tip = 'Rejected: ' + svc + (nrc ? ' \u2014 ' + nrc : '');\n"
    "    }\n"
    "    var clr = info[2]==='pos'?'#3c763d':info[2]==='neg'?'#a94442':'#31708f';\n"
    "    return '<span class=\"canmon-uds\" style=\"background:'+clr+'\" title=\"'+tip+'\">'+info[0]+'</span>';\n"
    "  }\n"
    "\n"
    "  function udsPidHtml(type, pid) {\n"
    "    var t = type.toUpperCase(), p = pid.toUpperCase();\n"
    "    var tip = '';\n"
    "    if (t === '50' || t === '10') tip = UDS_SESSION[p] ? 'session: '+UDS_SESSION[p] : '';\n"
    "    else if (t === '71' || t === '31') tip = UDS_RTCTRL[p] ? UDS_RTCTRL[p] : '';\n"
    "    else if (t === '67' || t === '27') {\n"
    "      var n = parseInt(p,16);\n"
    "      tip = n % 2 === 1 ? 'requestSeed' : 'sendKey';\n"
    "    } else if (t === '7F') {\n"
    "      tip = UDS_SID[p] || '';\n"
    "    }\n"
    "    if (!tip) return null;\n"
    "    return '<span title=\"'+tip+'\" class=\"canmon-pid-tip\">'+pid+'</span>';\n"
    "  }\n"
    "\n"
    "  function render(data) {\n"
    "    var frames = data.frames;\n"
    "    var running = data.running;\n"
    "    reRunning = running;\n"
    "    $status.text(running ? 'RE running' : 'RE stopped');\n"
    "    $status.css('color', running ? '#3c763d' : '#a94442');\n"
    "    $('#canmon-startbtn').toggle(!running);\n"
    "    $('#canmon-stopbtn').toggle(running);\n"
    "    var scanning = data.scanning;\n"
    "    if (scanning) {\n"
    "      var sp = data.scan_pid ? ' PID 0x' + data.scan_pid : '';\n"
    "      $qstatus.text('Scanning\u2026' + sp);\n"
    "    } else {\n"
    "      $qstatus.text('Idle');\n"
    "    }\n"
    "    $qstatus.css('color', scanning ? '#8a6d3b' : '#777');\n"
    "    $('#canmon-querybtn').toggle(!scanning);\n"
    "    $('#canmon-stopqbtn').toggle(scanning);\n"
    "\n"
    "    frames.sort(function(a,b){\n"
    "      if (a.bus < b.bus) return -1;\n"
    "      if (a.bus > b.bus) return  1;\n"
    "      if (a.id !== b.id) return a.id - b.id;\n"
    "      if (a.type < b.type) return -1;\n"
    "      if (a.type > b.type) return  1;\n"
    "      if (a.pid < b.pid) return -1;\n"
    "      if (a.pid > b.pid) return  1;\n"
    "      return 0;\n"
    "    });\n"
    "    lastFrames = {};\n"
    "    var seen = Object.create(null);\n"
    "    frames.forEach(function(f) {\n"
    "      lastFrames[f.key] = f;\n"
    "      var rid = 'rk_' + f.key.replace(/[^a-zA-Z0-9]/g,'_');\n"
    "      seen[rid] = true;\n"
    "      var row = document.getElementById(rid);\n"
    "      if (!row) {\n"
    "        row = document.createElement('tr');\n"
    "        row.id = rid;\n"
    "        row.dataset.key  = f.key;\n"
    "        row.dataset.bus  = f.bus;\n"
    "        row.dataset.id   = f.id;\n"
    "        row.dataset.type = f.type;\n"
    "        row.dataset.pid  = f.pid;\n"
    "        row.innerHTML = '<td></td><td></td><td></td><td></td>"  /* bus id type pid */
    "<td></td>"                                                       /* hex */
    "<td class=\"canmon-col-sm-hide\"></td>"                          /* i64 le */
    "<td class=\"canmon-col-sm-hide\"></td>"                          /* i64 be */
    "<td></td>"                                                       /* cnt */
    "<td class=\"canmon-rate-cell canmon-col-sm-hide\"></td>"         /* rate */
    "<td class=\"canmon-col-sm-hide\">"                               /* label */
         "<input class=\"canmon-label-input\" type=\"text\""
         " maxlength=\"40\" placeholder=\"label\u2026\"></td>"
    "<td class=\"canmon-col-sm-hide\">"                               /* formula */
         "<input class=\"canmon-formula-input\" type=\"text\""
         " maxlength=\"100\" placeholder=\"b[0]*0.1\">"
         "<div class=\"canmon-formula-result\"></div></td>"
    "<td><button class=\"btn btn-xs btn-default canmon-histbtn\""
         " title=\"History\">&#x1F4DC;</button></td>';\n"            /* hist button */
    "        row.cells[9].firstChild.value  = getLabel(f.key);\n"
    "        row.cells[10].firstChild.value = getFormula(f.key);\n"
    "        row.classList.add('canmon-new');\n"
    "        var inserted = false, rows = tbody.rows;\n"
    "        for (var i = 0; i < rows.length; i++) {\n"
    "          var rb = rows[i].dataset.bus;\n"
    "          var ri = parseInt(rows[i].dataset.id, 10);\n"
    "          var rt = rows[i].dataset.type;\n"
    "          var rp = rows[i].dataset.pid;\n"
    "          if (rb > f.bus ||\n"
    "             (rb === f.bus && ri > f.id) ||\n"
    "             (rb === f.bus && ri === f.id && rt > f.type) ||\n"
    "             (rb === f.bus && ri === f.id && rt === f.type && rp > f.pid)) {\n"
    "            tbody.insertBefore(row, rows[i]);\n"
    "            inserted = true; break;\n"
    "          }\n"
    "        }\n"
    "        if (!inserted) tbody.appendChild(row);\n"
    "      }\n"
    "      row.dataset.multi = f.multi ? '1' : '';\n"
    "      if (!row.classList.contains('canmon-new'))\n"
    "        row.classList.toggle('canmon-multi', !!f.multi);\n"
    "      var cl = row.cells;\n"
    "      cl[0].textContent  = f.bus;\n"
    "      cl[1].textContent  = fmtId(f.id, f.ext);\n"
    "      var typeHtml = udsTypeHtml(f.type, f.pid, f.hex);\n"
    "      if (typeHtml) cl[2].innerHTML = typeHtml; else cl[2].textContent = f.type;\n"
    "      var pidHtml = udsPidHtml(f.type, f.pid);\n"
    "      if (pidHtml) cl[3].innerHTML = pidHtml; else cl[3].textContent = f.pid;\n"
    "      var newHex = f.hex || '';\n"
    "      var oldHex = cl[4].dataset.hex || '';\n"
    "      if (oldHex !== newHex) {\n"
    "        cl[4].dataset.hex = newHex;\n"
    "        if (newHex && (crtdWriter || idbActive))\n"
    "          writeCrtdEntry({tsMs:Date.now(), key:f.key, bus:f.bus, id:f.id, ext:f.ext,\n"
    "                          type:f.type, pid:f.pid, hex:newHex, cnt:f.cnt});\n"
    "        var hparts = newHex.split(' ');\n"
    "        var oldParts = oldHex ? oldHex.split(' ') : [];\n"
    "        var nowMs = Date.now();\n"
    "        if (!byteChangeTimes[f.key]) byteChangeTimes[f.key] = {};\n"
    "        var hhml = '';\n"
    "        hparts.forEach(function(b,i){\n"
    "          if (i > 0) {\n"
    "            if (i%4===0) hhml += '<span class=\"cb-br\"></span><span class=\"cb-sep\">|</span>';\n"
    "            else hhml += ' ';\n"
    "          }\n"
    "          var cls = 'cb';\n"
    "          if (oldHex && oldParts[i] !== undefined && oldParts[i] !== b) {\n"
    "            cls += ' canmon-byte-changed';\n"
    "            byteChangeTimes[f.key][i] = nowMs;\n"
    "          }\n"
    "          hhml += '<span class=\"'+cls+'\" data-i=\"'+i+'\">'+b+'</span>';\n"
    "        });\n"
    "        cl[4].innerHTML = hhml;\n"
    "        if (sel.row === f.key) applySelHL();\n"
    "        row.classList.remove('canmon-multi');\n"
    "        row.classList.remove('canmon-new');\n"
    "        void row.offsetWidth;\n"  /* force reflow to restart animation */
    "        row.classList.add('canmon-new');\n"
    "      }\n"
    "      updateRowSnapDiff(row, f);\n"
    "      if (oldHex !== newHex || cl[4].dataset.dbcVer !== dbcVersion) {\n"
    "        cl[4].dataset.dbcVer = dbcVersion;\n"
    "        var dbcHtml = decodeDbcRow(newHex, f.id);\n"
    "        var dbcDiv  = cl[4].querySelector('.canmon-dbc-decoded');\n"
    "        if (dbcHtml) {\n"
    "          if (!dbcDiv) {\n"
    "            dbcDiv = document.createElement('div');\n"
    "            dbcDiv.className = 'canmon-dbc-decoded';\n"
    "            cl[4].appendChild(dbcDiv);\n"
    "          }\n"
    "          dbcDiv.innerHTML = dbcHtml;\n"
    "        } else if (dbcDiv) { cl[4].removeChild(dbcDiv); }\n"
    "      }\n"
    "      cl[5].textContent  = f.multi ? '' : f.i64le;\n"
    "      cl[6].textContent  = f.multi ? '' : f.i64be;\n"
    "      cl[7].textContent  = f.cnt;\n"
    "      cl[8].textContent  = updateRate(f.key, f.multi ? NaN : parseFloat(f.i64le));\n"
    "      if (!f.multi && f.hex) {\n"
    "        var fmlInput = cl[10].firstChild;\n"
    "        if (fmlInput.value)\n"
    "          cl[10].querySelector('.canmon-formula-result').textContent =\n"
    "            evalFormula(fmlInput.value, f.hex);\n"
    "      }\n"
    "      cl[11].firstChild.disabled = !(f.hist && f.hist.length > 0);\n"
    "    });\n"
    "    var allRows = Array.prototype.slice.call(tbody.rows);\n"
    "    allRows.forEach(function(row){\n"
    "      if (!seen[row.id]) {\n"
    "        var k = row.dataset.key;\n"
    "        delete rateHistory[k]; delete sparkData[k]; delete byteChangeTimes[k];\n"
    "        tbody.removeChild(row);\n"
    "      }\n"
    "    });\n"
    "  }\n"
    "\n"
    "  $('#canmon-tbody').on('animationend', '.canmon-new', function() {\n"
    "    this.classList.remove('canmon-new');\n"
    "    if (this.dataset.multi === '1') this.classList.add('canmon-multi');\n"
    "  });\n"
    "\n"
    // History modal: opened by clicking the history button on a row
    "  $('#canmon-tbody').on('click', '.canmon-histbtn', function(e) {\n"
    "    e.stopPropagation();\n"
    "    var key   = $(this).closest('tr')[0].dataset.key;\n"
    "    var frame = lastFrames[key];\n"
    "    if (!frame || !frame.hist || frame.hist.length === 0) return;\n"
    "    document.getElementById('canmon-hist-key').textContent = key;\n"
    "    var htbody = document.getElementById('canmon-hist-tbody');\n"
    "    htbody.innerHTML = '';\n"
    "    frame.hist.forEach(function(h) {\n"
    "      var tr  = document.createElement('tr');\n"
    "      var td0 = document.createElement('td');\n"
    "      td0.textContent = h.cnt;\n"
    "      var td1 = document.createElement('td');\n"
    "      td1.style.fontFamily = 'monospace';\n"
    "      td1.textContent = h.hex || '(empty)';\n"
    "      tr.appendChild(td0);\n"
    "      tr.appendChild(td1);\n"
    "      htbody.appendChild(tr);\n"
    "    });\n"
    "    $('#canmon-hist-modal').modal('show');\n"
    "  });\n"
    "\n"
    // Byte-selection: mousedown starts selection, mouseover extends while button held
    "  $('#canmon-tbody').on('mousedown', '.cb', function(e) {\n"
    "    var row = $(this).closest('tr')[0];\n"
    "    sel.row = row.dataset.key;\n"
    "    sel.s = sel.e = parseInt(this.dataset.i, 10);\n"
    "    mouseSelActive = true;\n"
    "    applySelHL();\n"
    "    updateSelPanel();\n"
    "    e.preventDefault();\n"   /* prevent text-selection drag */
    "    e.stopPropagation();\n"
    "  });\n"
    "  $('#canmon-tbody').on('mouseover', '.cb', function(e) {\n"
    "    if (!mouseSelActive) return;\n"
    "    var row = $(this).closest('tr')[0];\n"
    "    if (row.dataset.key !== sel.row) return;\n"
    "    sel.e = parseInt(this.dataset.i, 10);\n"
    "    applySelHL();\n"
    "    updateSelPanel();\n"
    "  });\n"
    "  $(document).on('mouseup touchend', function() { mouseSelActive = false; });\n"
    "  $('#canmon-tbody').on('touchstart', '.cb', function(e) {\n"
    "    var row = $(this).closest('tr')[0];\n"
    "    sel.row = row.dataset.key;\n"
    "    sel.s = sel.e = parseInt(this.dataset.i, 10);\n"
    "    mouseSelActive = true;\n"
    "    applySelHL();\n"
    "    updateSelPanel();\n"
    "    e.preventDefault();\n"
    "    e.stopPropagation();\n"
    "  });\n"
    "  $(document).on('touchmove', function(e) {\n"
    "    if (!mouseSelActive) return;\n"
    "    var t = e.originalEvent.touches[0];\n"
    "    var el = document.elementFromPoint(t.clientX, t.clientY);\n"
    "    if (!el || !el.classList.contains('cb')) return;\n"
    "    var row = $(el).closest('tr')[0];\n"
    "    if (!row || row.dataset.key !== sel.row) return;\n"
    "    sel.e = parseInt(el.dataset.i, 10);\n"
    "    applySelHL();\n"
    "    updateSelPanel();\n"
    "    e.preventDefault();\n"
    "  });\n"
    "  $('#canmon-sel-close').on('click', function() {\n"
    "    sel.row = null; sel.s = sel.e = -1;\n"
    "    applySelHL();\n"
    "    document.getElementById('canmon-sel-panel').style.display = 'none';\n"
    "  });\n"
    "\n"
    // WebSocket connection management
    "  function wsSend(obj) {\n"
    "    if (ws && ws.readyState === 1)\n"
    "      ws.send(JSON.stringify(obj));\n"
    "  }\n"
    "\n"
    "  function wsConnect() {\n"
    "    var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';\n"
    "    ws = new WebSocket(proto + '//' + location.host + '/ws/canmonitor');\n"
    "    ws.onopen = function() { wsSend({action:'get_dbc'}); };\n"
    "    ws.onmessage = function(e) {\n"
    "      try {\n"
    "        var d = JSON.parse(e.data);\n"
    "        if (d.cantx_result !== undefined) {\n"
    "          var ok = d.cantx_result === 'ok';\n"
    "          $('#canmon-txstatus').text(ok ? 'Sent \u2713' : d.cantx_result)\n"
    "            .css('color', ok ? '#3c763d' : '#a94442');\n"
    "        } else if (d.dbc_signals !== undefined) {\n"
    "          dbcDefs = d.dbc_signals; dbcVersion++;\n"
    "        } else { render(d); }\n"
    "      } catch(ex) {}\n"
    "    };\n"
    "    ws.onclose = function() {\n"
    "      $status.text('Disconnected').css('color','#a94442');\n"
    "      setTimeout(wsConnect, 2000);\n"
    "    };\n"
    "    ws.onerror = function() { ws.close(); };\n"
    "  }\n"
    "\n"
    "  wsConnect();\n"
    "\n"
    "  $('#canmon-startbtn').on('click', function(){\n"
    "    wsSend({action:'start', filter:''});\n"
    "  });\n"
    "  $('#canmon-stopbtn').on('click', function(){\n"
    "    wsSend({action:'stop'});\n"
    "  });\n"
    "  $('#canmon-clearbtn').on('click', function(){\n"
    "    wsSend({action:'clear'});\n"
    "    if (crtdWriter || idbActive) stopCrtdCapture();\n"
    "    idbClear();\n"
    "    updateLogStatus();\n"
    "  });\n"
    "  $('#canmon-freezebtn').on('click', function() {\n"
    "    if (snapshotFrames) {\n"
    "      snapshotFrames = null;\n"
    "      $(this).text('Freeze').removeClass('btn-warning').addClass('btn-default');\n"
    "      document.querySelectorAll('#canmon-tbody .canmon-byte-snap-diff').forEach(function(el) {\n"
    "        el.classList.remove('canmon-byte-snap-diff');\n"
    "      });\n"
    "    } else {\n"
    "      snapshotFrames = {};\n"
    "      Object.keys(lastFrames).forEach(function(k) {\n"
    "        snapshotFrames[k] = { hex: lastFrames[k].hex || '' };\n"
    "      });\n"
    "      $(this).text('Unfreeze').removeClass('btn-default').addClass('btn-warning');\n"
    "      [].forEach.call(document.querySelectorAll('#canmon-tbody tr'), function(row) {\n"
    "        var f = lastFrames[row.dataset.key];\n"
    "        if (f) updateRowSnapDiff(row, f);\n"
    "      });\n"
    "    }\n"
    "  });\n"
    "  $('#canmon-tbody').on('input', '.canmon-label-input', function() {\n"
    "    setLabel($(this).closest('tr')[0].dataset.key, this.value.trim());\n"
    "  });\n"
    "  $('#canmon-tbody').on('input', '.canmon-formula-input', function() {\n"
    "    setFormula($(this).closest('tr')[0].dataset.key, this.value.trim());\n"
    "  });\n"
    "  $('#canmon-currcsvbtn').on('click', exportCsvCurrent);\n"
    "  $('#canmon-crtdbtn').on('click', function(){\n"
    "    if (crtdWriter || idbActive) stopCrtdCapture(); else startCrtdCapture();\n"
    "  });\n"
    "  $('#canmon-qhistbtn').on('click', function(){\n"
    "    renderQHistModal();\n"
    "    $('#canmon-qhist-modal').modal('show');\n"
    "  });\n"
    "  $('#canmon-txhistbtn').on('click', function(){\n"
    "    renderTxHistModal();\n"
    "    $('#canmon-txhist-modal').modal('show');\n"
    "  });\n"
  "  var colsExpanded = false;\n"
  "  $('#canmon-colsbtn').on('click', function() {\n"
  "    colsExpanded = !colsExpanded;\n"
  "    document.body.classList.toggle('canmon-cols-expanded', colsExpanded);\n"
  "    $(this).text(colsExpanded ? 'Less cols' : 'More cols')\n"
  "           .toggleClass('btn-info', colsExpanded)\n"
  "           .toggleClass('btn-default', !colsExpanded);\n"
  "  });\n"
    "  $('#canmon-tbody').on('mouseenter', '.canmon-rate-cell', function(e) {\n"
    "    var key=$(this).closest('tr')[0].dataset.key;\n"
    "    var svg=makeSparkSvg(sparkData[key]);\n"
    "    if (!svg) return;\n"
    "    var tip=document.getElementById('canmon-spark-tip');\n"
    "    tip.innerHTML=svg; tip.style.display='block';\n"
    "    tip.style.left=(e.clientX+15)+'px'; tip.style.top=(e.clientY-10)+'px';\n"
    "  }).on('mouseleave','.canmon-rate-cell',function(){\n"
    "    document.getElementById('canmon-spark-tip').style.display='none';\n"
    "  }).on('mousemove','.canmon-rate-cell',function(e){\n"
    "    var tip=document.getElementById('canmon-spark-tip');\n"
    "    if(tip.style.display!=='none'){\n"
    "      tip.style.left=(e.clientX+15)+'px'; tip.style.top=(e.clientY-10)+'px';\n"
    "    }\n"
    "  });\n"
    "  setInterval(function() {\n"
    "    var now=Date.now();\n"
    "    [].forEach.call(document.querySelectorAll('#canmon-tbody tr'),function(row){\n"
    "      var key=row.dataset.key; if (!key) return;\n"
    "      var times=byteChangeTimes[key]||{};\n"
    "      [].forEach.call(row.cells[4].querySelectorAll('.cb'),function(el){\n"
    "        var age=(now-(times[el.dataset.i]||now))/1000;\n"
    "        el.style.opacity=age<3?'':age<10?'0.65':'0.35';\n"
    "      });\n"
    "    });\n"
    "  }, 2000);\n"
    "\n"
    "  $('#canmon-qform').on('submit', function(e) {\n"
    "    e.preventDefault();\n"
    "    var qe = {\n"
    "      bus:      $('[name=qbus]').val(),\n"
    "      txid:     $('[name=qtxid]').val().trim(),\n"
    "      mode:     $('[name=qmode]').val().trim(),\n"
    "      pidfrom:  $('[name=pidfrom]').val().trim(),\n"
    "      pidto:    $('[name=pidto]').val().trim(),\n"
    "      respfrom: $('[name=respfrom]').val().trim(),\n"
    "      respto:   $('[name=respto]').val().trim(),\n"
    "      timeout:  $('[name=qtimeout]').val().trim()\n"
    "    };\n"
    "    if (qe.txid && qe.pidfrom && qe.pidto) pushQHist(qe);\n"
    "    if (!reRunning) wsSend({action:'start', filter:''});\n"
    "    wsSend(Object.assign({action:'query'}, qe));\n"
    "  });\n"
    "  $('#canmon-stopqbtn').on('click', function(){\n"
    "    wsSend({action:'stopquery'});\n"
    "  });\n"
    "\n"
    "  $('#canmon-txform').on('submit', function(e) {\n"
    "    e.preventDefault();\n"
    "    var id   = $('[name=txid]').val().trim().toUpperCase();\n"
    "    var data = $('[name=txdata]').val().trim();\n"
    "    var bus  = $('[name=txbus]').val();\n"
    "    if (!id) return;\n"
    "    pushTxHist({ bus: bus, id: id, data: data });\n"
    "    $('#canmon-txstatus').text('Sending\u2026').css('color','#777');\n"
    "    wsSend({ action:'cantx', bus:bus, id:id, data:data });\n"
    "  });\n"
    "\n"
    "  $(window).on('beforeunload', function(){\n"
    "    if (ws) { ws.onclose = null; ws.close(); }\n"
    "    if (crtdWriter) { var w=crtdWriter; crtdWriter=null; w.close().catch(function(){}); }\n"
    "    if (idbActive)  { idbActive=false; idbClear(); }\n"
    "  });\n"
    "})();\n"
    "</script>\n"
    "<style>\n"
    ".canmon-multi{background-color:#fffbe6!important}\n"
    ".canmon-qlabel{font-size:11px;font-weight:bold;margin-bottom:2px}\n"
    "body{padding-bottom:calc(80px + env(safe-area-inset-bottom,0px))}\n"
    "@keyframes canmon-highlight{"
      "0%{background-color:#d4edda}"
      "100%{background-color:transparent}}\n"
    ".canmon-new{animation:canmon-highlight 3s ease-out forwards}\n"
    ".cb{cursor:pointer;padding:0 2px;border-radius:2px;user-select:none;"
        "-webkit-user-select:none}\n"
    ".cb-br{display:none}\n"
    ".cb-sep{color:#ccc;padding:0 3px;user-select:none;-webkit-user-select:none}\n"
    /* ── Mobile: hide secondary columns by default, show toggle button ── */
    "@media(max-width:767px){\n"
      ".cb-br{display:block}.cb-sep{display:none}\n"
      ".canmon-col-sm-hide{display:none!important}\n"
      ".canmon-cols-expanded .canmon-col-sm-hide{display:table-cell!important}\n"
      ".canmon-sm-only{display:inline-block}\n"
      ".table-condensed>tbody>tr>td,.table-condensed>thead>tr>th"
        "{padding:4px 5px}\n"
      "#canmon-sel-panel{font-size:12px;padding:4px 8px 0;"
        "padding-bottom:calc(4px + env(safe-area-inset-bottom,0px))}\n"
      "#canmon-sel-close{font-size:18px}\n"
    "}\n"
    /* ── On wider screens hide the mobile-only toggle button ── */
    "@media(min-width:768px){.canmon-sm-only{display:none!important}}\n"
    ".cb:hover{background:#d0e8ff}\n"
    ".cb.sel{background:#337ab7;color:#fff!important}\n"
    "@keyframes canmon-byte-flash{0%{background:#fc6}100%{background:transparent}}\n"
    ".canmon-byte-changed{animation:canmon-byte-flash 1.5s ease-out forwards}\n"
    ".canmon-byte-snap-diff{background:#c8e6c9!important;color:#1b5e20!important}\n"
    ".canmon-label-input{width:90px;border:none;background:transparent;"
                        "font-size:12px;outline:none;color:inherit}\n"
    ".canmon-label-input:focus{background:#fff;border-bottom:1px solid #337ab7}\n"
    ".canmon-formula-input{width:90px;border:none;background:transparent;"
                          "font-size:12px;outline:none;color:inherit}\n"
    ".canmon-formula-input:focus{background:#fff;border-bottom:1px solid #e67e22}\n"
    ".canmon-formula-result{font-size:11px;color:#e67e22;font-weight:bold;"
                           "min-height:1em}\n"
    ".canmon-rate-cell{font-size:11px;color:#555;white-space:nowrap;cursor:default}\n"
    ".canmon-dbc-decoded{font-size:11px;color:#286090;margin-top:3px;"
                        "line-height:1.6;word-break:break-word}\n"
    ".canmon-uds{color:#fff;border-radius:3px;padding:1px 5px;font-size:11px;"
               "font-weight:bold;white-space:nowrap;cursor:default}\n"
    ".canmon-pid-tip{border-bottom:1px dotted #888;cursor:default}\n"
    /* ── dark-mode (body.night) overrides ─────────────────────────────── */
    ".night .canmon-multi{background-color:#2b2700!important}\n"
    ".night .canmon-rate-cell{color:#999}\n"
    ".night .canmon-dbc-decoded{color:#5b9bd5}\n"
    ".night .canmon-formula-result{color:#f0a840}\n"
    ".night .canmon-label-input:focus{background:#2a2a2a;border-bottom-color:#5294c8}\n"
    ".night .canmon-formula-input:focus{background:#2a2a2a;border-bottom-color:#c0873a}\n"
    ".night .canmon-byte-snap-diff{background:#1a3a1a!important;color:#7ec87e!important}\n"
    ".night .cb:hover{background:#1a3a5c}\n"
    ".night #canmon-spark-tip{background:#1e1e1e!important;border-color:#555!important;color:#ccc}\n"
    ".night .canmon-sel-bar{background:#1a1d2e!important;border-top-color:#4a7aab!important;color:#ccc}\n"
    "#canmon-qhist-tbody tr:hover td:first-child{background:#f0f8ff;cursor:pointer}\n"
    ".night #canmon-qhist-tbody tr:hover td:first-child{background:#1a2a3a}\n"
    "</style>\n"
  );

  PAGE_HOOK("body.post");
  c.done();
  }


////////////////////////////////////////////////////////////////////////
// HandleCanMonitorData — legacy HTTP JSON endpoint (kept for CLI/script use)
//   GET  → { "running": bool, "scanning": bool, "frames": [...] }
//   POST → action=start|stop|clear|query|stopquery
////////////////////////////////////////////////////////////////////////

void OvmsWebServer::HandleCanMonitorData(PageEntry_t& p, PageContext_t& c)
  {
  if (c.method == "POST")
    {
    std::string action = c.getvar("action");
    if (action == "start")
      {
      std::string filter = c.getvar("filter");
      std::string cmd = "re start";
      if (!filter.empty()) { cmd += " "; cmd += filter; }
      ExecuteCommand(cmd);
      }
    else if (action == "stop")
      {
      ExecuteCommand("re stop");
      }
    else if (action == "clear")
      {
      ExecuteCommand("re clear");
      if (s_can_queue) xQueueReset(s_can_queue);
      s_frame_store.clear();
      s_reassembly.clear();
      s_history.clear();
      }
    else if (action == "query")
      {
      std::string bus      = c.getvar("bus");
      std::string txid     = c.getvar("txid");
      std::string pidfrom  = c.getvar("pidfrom");
      std::string pidto    = c.getvar("pidto");
      std::string mode     = c.getvar("mode");      // optional
      std::string respfrom = c.getvar("respfrom");  // optional
      std::string respto   = c.getvar("respto");    // optional
      std::string timeout  = c.getvar("timeout");   // optional, 1-10 s

      if (bus.size() != 1 || !isdigit((unsigned char)bus[0]) ||
          !is_valid_hex(txid)              ||
          !is_valid_hex(pidfrom)           || !is_valid_hex(pidto) ||
          !is_valid_hex(mode,     true)    ||
          !is_valid_hex(respfrom, true)    || !is_valid_hex(respto, true) ||
          !is_valid_decimal(timeout, true))
        {
        c.head(400, "Content-Type: application/json\r\nCache-Control: no-cache");
        c.print("{\"error\":\"invalid parameter\"}");
        c.done();
        return;
        }

      std::string cmd = "re obdii scan start " + bus + " " + txid + " " +
                        pidfrom + " " + pidto;
      if (!respfrom.empty())
        {
        cmd += " -r" + respfrom;
        if (!respto.empty()) cmd += "-" + respto;
        }
      if (!mode.empty())    cmd += " -t" + mode;
      if (!timeout.empty()) cmd += " -x" + timeout;
      ExecuteCommand(cmd);
      s_scanning = true;
      }
    else if (action == "stopquery")
      {
      ExecuteCommand("re obdii scan stop");
      s_scanning = false;
      }
    else if (action == "cantx")
      {
      std::string bus_s  = c.getvar("bus");
      std::string id_s   = c.getvar("id");
      std::string data_s = c.getvar("data");

      std::string clean;
      for (unsigned char ch : data_s)
        if (isxdigit(ch)) clean += (char)ch;

      if (bus_s.size() != 1 || !isdigit((unsigned char)bus_s[0]) ||
          id_s.empty() || !is_valid_hex(id_s) || id_s.size() > 8 ||
          clean.size() % 2 != 0 || clean.size() > 16)
        {
        c.head(400, "Content-Type: application/json\r\nCache-Control: no-cache");
        c.print("{\"error\":\"bad parameters\"}");
        c.done(); return;
        }

      canbus* cbus = MyCan.GetBus(bus_s[0] - '1');
      if (!cbus || cbus->m_mode != CAN_MODE_ACTIVE)
        {
        c.head(400, "Content-Type: application/json\r\nCache-Control: no-cache");
        c.print(cbus ? "{\"error\":\"bus not in active mode\"}" : "{\"error\":\"bus not found\"}");
        c.done(); return;
        }

      uint32_t can_id = 0;
      sscanf(id_s.c_str(), "%x", &can_id);

      uint8_t dlc = (uint8_t)(clean.size() / 2);
      uint8_t data[8] = {};
      for (uint8_t i = 0; i < dlc; i++)
        { unsigned int v = 0; sscanf(clean.c_str() + i*2, "%02x", &v); data[i] = (uint8_t)v; }

      esp_err_t res = (can_id > 0x7FF)
        ? cbus->WriteExtended(can_id, dlc, data)
        : cbus->WriteStandard((uint16_t)can_id, dlc, data);

      c.head(200, "Content-Type: application/json\r\nCache-Control: no-cache");
      c.print(res == ESP_OK ? "{\"ok\":true}" : "{\"ok\":false}");
      c.done(); return;
      }
    c.head(200, "Content-Type: application/json\r\nCache-Control: no-cache");
    c.print("{}");
    c.done();
    return;
    }

  // GET — return current snapshot
  c.head(200, "Content-Type: application/json\r\nCache-Control: no-cache");
  c.print(BuildCanMonJson());
  c.done();
  }
