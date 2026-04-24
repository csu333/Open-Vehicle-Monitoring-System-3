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
#include "web_canmonitor_ui.inc"

// MyRE is defined in retools.cpp; NULL when RE framework is not running.
extern re* MyRE;

#ifdef CONFIG_OVMS_COMP_RE_TOOLS_PID
#include "retools_pid.h"
#endif


// ── Threading model ──────────────────────────────────────────────────────────
// All module-local state (s_frame_store, s_reassembly, s_history, s_scanning,
// s_can_queue, s_ws_clients) is mutated exclusively from the mongoose
// (NetManager) task: WebSocket event callbacks, the HTTP page/data handlers,
// and the BuildCanMonJson drain path all run there.  The one exception is the
// pidscan done/stop event callback, which runs on the events task but touches
// only s_scanning (bool, tolerant of one stale 500 ms snapshot).
// No explicit locking is required as long as this invariant holds.


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

// Memory limits to protect ESP32 heap on busy buses.
// MAX_CANMON_PAYLOAD caps each stored entry so that, combined with the store
// cap, worst-case heap use is bounded (≈ MAX_CANMON_STORE × MAX_CANMON_PAYLOAD
// plus the 10-deep per-key history).
static const size_t MAX_CANMON_STORE = 250;
static const size_t MAX_CANMON_REASSEMBLY = 50;
static const size_t MAX_CANMON_PAYLOAD = 256;

static std::map<std::string, CanMonFrameEntry>             s_frame_store;
static std::map<uint64_t, ReassemblyState>                 s_reassembly;
static std::map<std::string, std::deque<CanMonHistEntry>>  s_history;

// CAN listener queue — created and registered with MyCan when the first
// WebSocket client connects, deregistered when the last one closes.  Kept
// NULL between sessions so idle frames aren't consuming queue space.
static QueueHandle_t s_can_queue = NULL;
static unsigned int  s_ws_clients = 0;

// Attach the CAN listener (lazy, called on first WS client).
static void CanMonAttachListener()
  {
  if (s_can_queue) return;
  s_can_queue = xQueueCreate(100, sizeof(CAN_frame_t));
  if (s_can_queue) MyCan.RegisterListener(s_can_queue, false);
  }

// Detach and free the CAN listener (called when last WS client closes).
static void CanMonDetachListener()
  {
  if (!s_can_queue) return;
  MyCan.DeregisterListener(s_can_queue);
  vQueueDelete(s_can_queue);
  s_can_queue = NULL;
  }


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
  // Cap per-entry size to MAX_CANMON_PAYLOAD so a long ISO 15765-2 reassembly
  // can't blow the ESP32 heap.  Truncated entries still show the leading bytes
  // of the message in the Hex data column.
  std::vector<uint8_t> payload;
  if (raw_len > data_off)
    {
    size_t plen = raw_len - data_off;
    if (plen > MAX_CANMON_PAYLOAD) plen = MAX_CANMON_PAYLOAD;
    payload.assign(raw + data_off, raw + data_off + plen);
    }

  // Display key: one row per (ID, Type, PID).
  char id_hex[12];
  if (meta.FIR.B.FF == CAN_frame_std)
    snprintf(id_hex, sizeof(id_hex), "%03X", (unsigned)meta.MsgID);
  else
    snprintf(id_hex, sizeof(id_hex), "%08X", (unsigned)meta.MsgID);
  char dkey_buf[26];
  snprintf(dkey_buf, sizeof(dkey_buf), "%s/%s/%s", id_hex, typestr, pidstr);
  std::string dkey(dkey_buf);

  auto existing = s_frame_store.find(dkey);
  bool is_new_key = (existing == s_frame_store.end());

  // Suppress all-zero payloads ONLY on first arrival — a PID that responds
  // with all zeros from the start is likely "no data", but once we've seen
  // real data for the key, transitions back to all-zero are meaningful.
  if (is_new_key)
    {
    bool all_zero = true;
    for (uint8_t b : payload) if (b) { all_zero = false; break; }
    if (all_zero) return;
    }

  // Prevent memory exhaustion on very busy buses without filters
  if (is_new_key && s_frame_store.size() >= MAX_CANMON_STORE)
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
  for (unsigned char c : s)
    {
    switch (c)
      {
      case '"':  out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\b': out += "\\b";  break;
      case '\f': out += "\\f";  break;
      case '\n': out += "\\n";  break;
      case '\r': out += "\\r";  break;
      case '\t': out += "\\t";  break;
      default:
        if (c < 0x20)
          {
          char u[8];
          snprintf(u, sizeof(u), "\\u%04x", (unsigned)c);
          out += u;
          }
        else
          out += (char)c;
      }
    }
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
    CanMonWsHandler(mg_connection* nc) : MgHandler(nc), m_last_push(0)
      {
      // Attach CAN listener on first client; runs in NetManager task.
      if (s_ws_clients == 0) CanMonAttachListener();
      s_ws_clients++;
      }
    ~CanMonWsHandler()
      {
      if (s_ws_clients > 0) s_ws_clients--;
      if (s_ws_clients == 0)
        {
        CanMonDetachListener();
        s_frame_store.clear();
        s_reassembly.clear();
        s_history.clear();
        }
      }

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
 * for /ws/canmonitor.  Rejects cross-origin handshakes (CSRF defence for
 * the `cantx`/`query` commands that drive the vehicle bus), then checks
 * session auth, then attaches a CanMonWsHandler.
 */
void OvmsWebServer::CreateCanMonWsHandler(mg_connection* nc, http_message* hm)
  {
  // ── Same-origin check ──────────────────────────────────────────────────
  // Browsers send the Origin header on every WebSocket handshake, but the
  // same-origin policy does NOT auto-reject cross-origin WS connections
  // the way it does XHR — we must enforce it here.  A cross-origin page
  // that reached a logged-in user's browser could otherwise open a WS to
  // OVMS with the session cookie attached and send arbitrary CAN TX frames.
  //
  // Rule: Origin must exist, be non-"null", and its host[:port] must match
  //       the Host header byte-for-byte.
  struct mg_str* origin = mg_get_http_header(hm, "Origin");
  struct mg_str* host   = mg_get_http_header(hm, "Host");
  bool origin_ok = false;
  if (origin != NULL && origin->len > 0 && host != NULL && host->len > 0)
    {
    const char* op = origin->p;
    size_t      ol = origin->len;
    // Strip "scheme://" prefix (http:// or https:// or ws:// or wss://).
    // memmem is a GNU extension and not guaranteed in ESP-IDF newlib, so
    // we do a small inline search here.
    for (size_t i = 0; i + 3 <= ol; i++)
      {
      if (op[i] == ':' && op[i+1] == '/' && op[i+2] == '/')
        {
        size_t off = i + 3;
        op += off;
        ol -= off;
        break;
        }
      }
    if (ol == host->len && memcmp(op, host->p, ol) == 0)
      origin_ok = true;
    }
  if (!origin_ok)
    {
    ESP_LOGW(TAG, "/ws/canmonitor rejected: cross-origin or missing Origin header");
    mg_http_send_error(nc, 403, "Forbidden");
    nc->flags |= MG_F_SEND_AND_CLOSE;
    return;
    }

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
  // One-time pidscan event wiring.  The CAN listener itself is attached
  // lazily per-WS-client in CanMonWsHandler (see CanMonAttachListener).
  static bool s_events_registered = false;
  if (!s_events_registered)
    {
    s_events_registered = true;
#ifdef CONFIG_OVMS_COMP_RE_TOOLS_PID
    auto clear_scanning = [](std::string, void*) { s_scanning = false; };
    MyEvents.RegisterEvent(TAG,              "retools.pidscan.stop", clear_scanning);
    MyEvents.RegisterEvent("webcanmon.done", "retools.pidscan.done", clear_scanning);
#endif
    }

  c.head(200);
  PAGE_HOOK("body.pre");

  // ── OBDII query panel ────────────────────────────────────────────────
  c.print(canmon_ui_obdii_panel);

  // ── CAN TX panel ─────────────────────────────────────────────────────
  c.print(canmon_ui_cantx_panel);

  // ── Results table ────────────────────────────────────────────────────
  c.print(canmon_ui_results_table);

  // ── History modal ────────────────────────────────────────────────────
  c.print(canmon_ui_hist_modal);

  // ── Query-history modal ──────────────────────────────────────────────
  c.print(canmon_ui_qhist_modal);

  // ── CAN TX history modal ─────────────────────────────────────────────
  c.print(canmon_ui_txhist_modal);

  // ── Byte-inspector bar ───────────────────────────────────────────────
  c.print(canmon_ui_sel_panel);

  // ── JavaScript ───────────────────────────────────────────────────────
  c.print(canmon_ui_script_css);

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
