#!/usr/bin/env python3
"""
zea_decode.py - decode binary Zone Evacuation Alarm broadcast messages from
bridge pcap captures.
This is the ad hoc broadcast message defined by the ZEA spec, carried in raw
Ethernet frames of ethertype 0x4d54. It is a different message from the JSON
tag-status payload ({"MMC_ID":...,"EVAC":...}) that zea_merge.py handles: this
one is the alarm command itself, 23 bytes, no JSON.
Wire format (all big-endian):
   off  size  field
   0x00   2   Message Type          constant 0x0006 BROADCAST_DATA
   0x02   2   Length                bytes remaining after this field
   0x04   1   Time To Live          >=1, decremented on receive
   0x05   3   Packet ID             24-bit, duplicates rejected by receivers
   0x08   6   Source Address        MAC of the ORIGINATING device
   0x0E   2   SubType               constant 0x0002 WIRELESS_APP_PACKET
   0x10   2   Length                bytes remaining
   0x12   2   Message ID / Port     0x8051 Zone Evacuation Alarm Status
   0x14   2   Length                bytes remaining
   0x16   1   Alarm State           0x01 Off/Deactivate, 0x02 On/Activate
Note: captured firmware emits Message ID 0x8061 where the spec document says
0x8051. Both are accepted; --strict rejects anything but the spec value.
No external dependencies. Reads pcap and pcapng, plain or .gz.
Usage:
   ./zea_decode.py caps/*.pcap                 state timeline (default)
   ./zea_decode.py caps/*.pcap --packets       every decoded frame
   ./zea_decode.py caps/*.pcap --flood         packet-ID propagation
   ./zea_decode.py caps/*.pcap --csv out.csv
"""
import argparse
import glob
import gzip
import os
import struct
import sys
from datetime import datetime, timedelta
ETHERTYPE_ZEA = 0x4D54
MSG_TYPE_BROADCAST_DATA = 0x0006
SUBTYPE_WIRELESS_APP_PACKET = 0x0002
MSG_ID_ZEA_STATUS = 0x8051          # per spec document
MSG_ID_ZEA_OBSERVED = 0x8061        # per captured firmware
ZEA_LEN = 0x17                      # 23 bytes
STATE_NAMES = {0x01: "OFF", 0x02: "ON"}

# ---------------------------------------------------------------------------
# pcap / pcapng readers
# ---------------------------------------------------------------------------
def _open(path):
   return gzip.open(path, "rb") if path.endswith(".gz") else open(path, "rb")

def read_pcap(fh, endian, nano):
   if len(fh.read(20)) < 20:
       return
   while True:
       hdr = fh.read(16)
       if len(hdr) < 16:
           return
       ts_sec, ts_frac, incl, _orig = struct.unpack(endian + "IIII", hdr)
       data = fh.read(incl)
       if len(data) < incl:
           return
       yield ts_sec + (ts_frac / 1e9 if nano else ts_frac / 1e6), data

def read_pcapng(fh):
   fh.seek(0)
   endian = "<"
   tsresol = {}
   iface_id = 0
   while True:
       head = fh.read(8)
       if len(head) < 8:
           return
       btype = struct.unpack("<I", head[0:4])[0]
       if btype == 0x0A0D0D0A:
           bom = fh.read(4)
           if len(bom) < 4:
               return
           endian = "<" if struct.unpack("<I", bom)[0] == 0x1A2B3C4D else ">"
           blen = struct.unpack(endian + "I", head[4:8])[0]
           if blen < 12:
               return
           fh.read(blen - 12)
           iface_id = 0
           tsresol = {}
           continue
       blen = struct.unpack(endian + "I", head[4:8])[0]
       if blen < 12:
           return
       body = fh.read(blen - 12)
       fh.read(4)
       if btype == 0x00000001:
           res = 6
           opts = body[8:]
           i = 0
           while i + 4 <= len(opts):
               ocode, olen = struct.unpack(endian + "HH", opts[i:i + 4])
               oval = opts[i + 4:i + 4 + olen]
               if ocode == 0:
                   break
               if ocode == 9 and olen >= 1:
                   raw = oval[0]
                   res = ("pow2", raw & 0x7F) if raw & 0x80 else (raw & 0x7F)
               i += 4 + olen + ((4 - olen % 4) % 4)
           tsresol[iface_id] = res
           iface_id += 1
       elif btype == 0x00000006:
           if len(body) < 20:
               continue
           ifid, tsh, tsl, incl, _o = struct.unpack(endian + "IIIII", body[:20])
           data = body[20:20 + incl]
           raw_ts = (tsh << 32) | tsl
           res = tsresol.get(ifid, 6)
           if isinstance(res, tuple):
               yield raw_ts / float(2 ** res[1]), data
           else:
               yield raw_ts / float(10 ** res), data

def read_capture(path):
   fh = _open(path)
   magic = fh.read(4)
   if len(magic) < 4:
       fh.close()
       return
   m_le = struct.unpack("<I", magic)[0]
   m_be = struct.unpack(">I", magic)[0]
   try:
       if m_le == 0x0A0D0D0A or m_be == 0x0A0D0D0A:
           for item in read_pcapng(fh):
               yield item
       elif m_le in (0xA1B2C3D4, 0xA1B23C4D):
           for item in read_pcap(fh, "<", m_le == 0xA1B23C4D):
               yield item
       elif m_be in (0xA1B2C3D4, 0xA1B23C4D):
           for item in read_pcap(fh, ">", m_be == 0xA1B23C4D):
               yield item
       else:
           sys.stderr.write("[WARN] %s: unrecognised magic, skipped\n" % path)
   finally:
       fh.close()

# ---------------------------------------------------------------------------
# ZEA message decoding
# ---------------------------------------------------------------------------
def mac(b):
   return ":".join("%02x" % x for x in b)

def decode_zea(payload, strict):
   """Decode a 23-byte ZEA broadcast. Returns dict or (None, reason)."""
   if len(payload) < ZEA_LEN:
       return None, "short (%d < %d bytes)" % (len(payload), ZEA_LEN)
   msg_type = struct.unpack(">H", payload[0x00:0x02])[0]
   if msg_type != MSG_TYPE_BROADCAST_DATA:
       return None, "msg_type 0x%04x" % msg_type
   ln1 = struct.unpack(">H", payload[0x02:0x04])[0]
   ttl = payload[0x04]
   pkt_id = int.from_bytes(payload[0x05:0x08], "big")
   src = mac(payload[0x08:0x0E])
   subtype = struct.unpack(">H", payload[0x0E:0x10])[0]
   if subtype != SUBTYPE_WIRELESS_APP_PACKET:
       return None, "subtype 0x%04x" % subtype
   ln2 = struct.unpack(">H", payload[0x10:0x12])[0]
   msg_id = struct.unpack(">H", payload[0x12:0x14])[0]
   accepted = (MSG_ID_ZEA_STATUS,) if strict else (MSG_ID_ZEA_STATUS,
                                                   MSG_ID_ZEA_OBSERVED)
   if msg_id not in accepted:
       return None, "msg_id 0x%04x" % msg_id
   ln3 = struct.unpack(">H", payload[0x14:0x16])[0]
   state = payload[0x16]
   warn = []
   # length fields count the bytes remaining after themselves
   if ln1 != ZEA_LEN - 0x04:
       warn.append("len1=%d expected %d" % (ln1, ZEA_LEN - 0x04))
   if ln2 != ZEA_LEN - 0x12:
       warn.append("len2=%d expected %d" % (ln2, ZEA_LEN - 0x12))
   if ln3 != ZEA_LEN - 0x16:
       warn.append("len3=%d expected %d" % (ln3, ZEA_LEN - 0x16))
   if ttl < 1:
       warn.append("ttl=0 (spec requires >=1)")
   if state not in STATE_NAMES:
       warn.append("state 0x%02x undefined" % state)
   return {
       "ttl": ttl,
       "pkt_id": pkt_id,
       "origin": src,
       "msg_id": msg_id,
       "state": state,
       "state_name": STATE_NAMES.get(state, "UNDEFINED(0x%02x)" % state),
       "warn": warn,
   }, None

def frame_payload(data, require_ethertype):
   """Return (payload, eth_src) or (None, None)."""
   if len(data) >= 14 and struct.unpack(">H", data[12:14])[0] == ETHERTYPE_ZEA:
       return data[14:], mac(data[6:12])
   if not require_ethertype:
       return data, ""
   return None, None

def bridge_name(path):
   base = os.path.basename(path)
   import re
   m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", base)
   if m:
       return m.group(1)
   for ext in (".gz", ".pcapng", ".pcap", ".cap"):
       if base.endswith(ext):
           base = base[:-len(ext)]
   return base

def collect(paths, strict, require_ethertype):
   records = []
   stats = {}
   for path in paths:
       bname = bridge_name(path)
       st = {"frames": 0, "zea": 0, "rejected": 0, "reasons": {}}
       for ts, data in read_capture(path):
           st["frames"] += 1
           payload, eth_src = frame_payload(data, require_ethertype)
           if payload is None:
               continue
           rec, why = decode_zea(payload, strict)
           if rec is None:
               st["rejected"] += 1
               st["reasons"][why.split()[0]] = \
                   st["reasons"].get(why.split()[0], 0) + 1
               continue
           rec["ts"] = ts
           rec["bridge"] = bname
           rec["eth_src"] = eth_src
           records.append(rec)
           st["zea"] += 1
       stats[bname] = st
   records.sort(key=lambda r: r["ts"])
   return records, stats

# ---------------------------------------------------------------------------
# output
# ---------------------------------------------------------------------------
RULE_W = 78

def section(title):
   head = "---- %s " % title.upper()
   return head + "-" * max(0, RULE_W - len(head))

def table(headers, rows, aligns=None, indent=2):
   if not rows:
       return " " * indent + "(none)"
   n = len(headers)
   aligns = aligns or ["l"] * n
   w = [len(h) for h in headers]
   for r in rows:
       for i in range(n):
           w[i] = max(w[i], len(str(r[i])))
   def line(cells):
       out = []
       for i, c in enumerate(cells):
           c = str(c)
           out.append(c.rjust(w[i]) if aligns[i] == "r" else c.ljust(w[i]))
       return " " * indent + "  ".join(out).rstrip()
   lines = [line(headers), " " * indent + "  ".join("-" * x for x in w)]
   for r in rows:
       lines.append(line(r))
   return "\n".join(lines)

def fmt_time(epoch, tz):
   return (datetime(1970, 1, 1) +
           timedelta(seconds=epoch + tz * 3600.0)).strftime(
               "%Y-%m-%d %H:%M:%S")

def fmt_time_ms(epoch, tz):
   return (datetime(1970, 1, 1) +
           timedelta(seconds=epoch + tz * 3600.0)).strftime(
               "%Y-%m-%d %H:%M:%S.%f")[:-3]

def print_summary(records, stats, tz):
   print(section("sources"))
   rows = []
   for b in sorted(stats):
       s = stats[b]
       top = sorted(s["reasons"].items(), key=lambda kv: -kv[1])[:2]
       note = ", ".join("%s x%d" % (k, v) for k, v in top)
       rows.append([b, s["frames"], s["zea"], s["rejected"], note[:34]])
   print(table(["BRIDGE", "FRAMES", "ZEA MSGS", "REJECTED", "TOP REJECT"],
               rows, ["l", "r", "r", "r", "l"]))
   print()
   if not records:
       return
   ids = set(r["msg_id"] for r in records)
   if MSG_ID_ZEA_OBSERVED in ids and MSG_ID_ZEA_STATUS not in ids:
       print("  note: firmware uses Message ID 0x8061; spec document "
             "says 0x8051")
       print()
   bad = [r for r in records if r["warn"]]
   if bad:
       print("  %d message(s) failed a field consistency check, e.g. %s"
             % (len(bad), "; ".join(bad[0]["warn"])[:60]))
       print()

def print_timeline(records, tz, min_dwell):
   """Collapse the per-origin stream into alarm state intervals."""
   by_origin = {}
   for r in records:
       by_origin.setdefault(r["origin"], []).append(r)
   rows = []
   for origin in sorted(by_origin):
       seq = by_origin[origin]
       cur = None
       start = None
       bridges = set()
       for r in seq:
           if cur is None:
               cur, start = r["state_name"], r["ts"]
               bridges = {r["bridge"]}
               continue
           if r["state_name"] == cur:
               bridges.add(r["bridge"])
               continue
           dur = r["ts"] - start
           if dur >= min_dwell:
               rows.append([origin, cur, fmt_time(start, tz),
                            fmt_time(r["ts"], tz), "%.3f" % dur,
                            len(bridges)])
           cur, start = r["state_name"], r["ts"]
           bridges = {r["bridge"]}
       if cur is not None:
           rows.append([origin, cur, fmt_time(start, tz), "", "",
                        len(bridges)])
   print(section("alarm state timeline"))
   print(table(["ORIGIN MAC", "STATE", "START", "END", "DURATION", "SEEN BY"],
               rows, ["l", "l", "l", "l", "r", "r"]))
   print()
   on = sum(1 for r in rows if r[1] == "ON")
   print("  %d interval(s) over %d originator(s), %d ON"
         % (len(rows), len(by_origin), on))
   print("  rows with a blank END were still in that state at capture end")

def print_packets(records, tz):
   rows = [[fmt_time_ms(r["ts"], tz), r["bridge"], r["origin"],
            "0x%06x" % r["pkt_id"], r["ttl"], "0x%04x" % r["msg_id"],
            r["state_name"], ";".join(r["warn"])[:24]] for r in records]
   print(section("decoded messages"))
   print(table(["TIME", "BRIDGE", "ORIGIN MAC", "PACKET ID", "TTL",
                "MSG ID", "STATE", "WARN"], rows,
               ["l", "l", "l", "r", "r", "l", "l", "l"]))
   print()
   print("  %d message(s)" % len(rows))

def print_flood(records, tz):
   """Group by Packet ID: the spec says receivers reject duplicates, so the
   same ID arriving at several bridges maps the broadcast's reach."""
   by_id = {}
   for r in records:
       by_id.setdefault((r["origin"], r["pkt_id"]), []).append(r)
   rows = []
   for (origin, pid), seq in sorted(by_id.items(),
                                    key=lambda kv: kv[1][0]["ts"]):
       seq.sort(key=lambda r: r["ts"])
       bridges = sorted(set(r["bridge"] for r in seq))
       ttls = sorted(set(r["ttl"] for r in seq))
       spread = seq[-1]["ts"] - seq[0]["ts"]
       rows.append([fmt_time_ms(seq[0]["ts"], tz), origin,
                    "0x%06x" % pid, seq[0]["state_name"],
                    len(bridges), "%.3f" % spread,
                    ",".join(str(t) for t in ttls)])
   print(section("broadcast propagation"))
   print(table(["FIRST SEEN", "ORIGIN MAC", "PACKET ID", "STATE",
                "BRIDGES", "SPREAD(s)", "TTLS"], rows,
               ["l", "l", "r", "l", "r", "r", "l"]))
   print()
   if rows:
       multi = [r for r in rows if r[4] > 1]
       print("  %d unique broadcast(s); %d reached more than one bridge"
             % (len(rows), len(multi)))
       if multi:
           worst = max(multi, key=lambda r: float(r[5]))
           print("  widest spread between first and last reception: %ss (%s)"
                 % (worst[5], worst[2]))

def write_csv(records, tz, path):
   with open(path, "w") as fh:
       fh.write("time,bridge,origin_mac,packet_id,ttl,msg_id,state,"
                "state_raw,warnings\n")
       for r in records:
           fh.write("%s,%s,%s,0x%06x,%d,0x%04x,%s,0x%02x,%s\n" % (
               fmt_time_ms(r["ts"], tz), r["bridge"], r["origin"],
               r["pkt_id"], r["ttl"], r["msg_id"], r["state_name"],
               r["state"], ";".join(r["warn"])))

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
   ap = argparse.ArgumentParser(
       description="Decode binary Zone Evacuation Alarm broadcasts from "
                   "bridge pcaps.")
   ap.add_argument("captures", nargs="+", help="pcap/pcapng files (globs ok)")
   ap.add_argument("--tz", type=float, default=9.0,
                   help="hours to add to UTC for display (default 9)")
   ap.add_argument("--packets", action="store_true",
                   help="list every decoded message")
   ap.add_argument("--flood", action="store_true",
                   help="group by Packet ID to show broadcast reach")
   ap.add_argument("--csv", metavar="FILE", help="write decoded messages here")
   ap.add_argument("--min-dwell", type=float, default=0.0, metavar="S",
                   help="suppress timeline intervals shorter than this")
   ap.add_argument("--strict", action="store_true",
                   help="accept only Message ID 0x8051 (spec value); by "
                        "default 0x8061 as emitted by firmware is also taken")
   ap.add_argument("--any-ethertype", action="store_true",
                   help="do not require ethertype 0x4d54")
   args = ap.parse_args()
   paths = []
   for pat in args.captures:
       hits = sorted(glob.glob(pat))
       paths.extend(hits if hits else [pat])
   paths = [p for p in paths if os.path.isfile(p)]
   if not paths:
       sys.stderr.write("[ERROR] no capture files found\n")
       return 2
   records, stats = collect(paths, args.strict, not args.any_ethertype)
   print_summary(records, stats, args.tz)
   if not records:
       sys.stderr.write(
           "[ERROR] no ZEA broadcasts decoded. These are 23-byte binary "
           "messages, distinct from the JSON tag payloads handled by "
           "zea_merge.py. If the captures have no link header, try "
           "--any-ethertype\n")
       return 1
   if args.packets:
       print_packets(records, args.tz)
   elif args.flood:
       print_flood(records, args.tz)
   else:
       print_timeline(records, args.tz, args.min_dwell)
   if args.csv:
       write_csv(records, args.tz, args.csv)
       sys.stderr.write("[OK] wrote %s (%d messages)\n"
                        % (args.csv, len(records)))
   return 0

if __name__ == "__main__":
   try:
       sys.exit(main())
   except KeyboardInterrupt:
       os._exit(0)