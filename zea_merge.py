#!/usr/bin/env python3
"""
zea_merge.py - merge ZEA alarm captures from multiple bridge units and emit
per-tag state intervals (tag, state, start, end, duration).
One pcap per bridge. Bridges have overlapping coverage, so the same tag
broadcast is heard by several bridges. Merging is done on STATE CHANGES,
not on packets: all observations for a tag are put on one timeline, then
consecutive identical states are collapsed. Duplicates disappear for free
and coverage becomes the union of all bridges.
No external dependencies. Reads classic pcap and pcapng, plain or .gz.
Usage:
   ./zea_merge.py zea-*.pcap
   ./zea_merge.py caps/*.pcap --tz 9 --csv intervals.csv
   ./zea_merge.py caps/*.pcap --skew
   ./zea_merge.py caps/*.pcap --per-bridge
"""
import argparse
import binascii
import glob
import gzip
import os
import re
import struct
import sys
from datetime import datetime, timedelta
# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------
ETHERTYPE_ZEA = 0x4D54          # "MT"
JSON_RE = re.compile(rb'\{"MMC_ID":"([^"]{1,32})","EVAC":"([^"]{1,32})"\}')
# tolerate the reverse key order / extra whitespace some firmwares emit
JSON_RE_LOOSE = re.compile(
   rb'\{[^{}]{0,120}"MMC_ID"\s*:\s*"([^"]{1,32})"[^{}]{0,80}'
   rb'"EVAC"\s*:\s*"([^"]{1,32})"[^{}]{0,40}\}'
)
TRUNC_RE = re.compile(rb'\{"MMC_ID":"([^"]{1,32})"')   # snaplen cut the frame
KNOWN_STATES = ("INACTIVE", "ACTIVE_ON", "ACTIVE_SIL")

# ---------------------------------------------------------------------------
# pcap / pcapng readers -> yield (epoch_float, frame_bytes)
# ---------------------------------------------------------------------------
def _open(path):
   if path.endswith(".gz"):
       return gzip.open(path, "rb")
   return open(path, "rb")

def read_pcap(fh, endian, nano):
   rest = fh.read(20)
   if len(rest) < 20:
       return
   # vmaj, vmin, thiszone, sigfigs, snaplen, network
   _, _, _, _, _snaplen, _network = struct.unpack(endian + "HHiIII", rest)
   while True:
       hdr = fh.read(16)
       if len(hdr) < 16:
           return
       ts_sec, ts_frac, incl, _orig = struct.unpack(endian + "IIII", hdr)
       data = fh.read(incl)
       if len(data) < incl:
           return
       ts = ts_sec + (ts_frac / 1e9 if nano else ts_frac / 1e6)
       yield ts, data

def read_pcapng(fh):
   fh.seek(0)
   tsresol = {}          # interface id -> resolution divisor
   iface_id = 0
   endian = "<"
   while True:
       head = fh.read(8)
       if len(head) < 8:
           return
       btype = struct.unpack(endian + "I", head[0:4])[0]
       if btype == 0x0A0D0D0A:
           # section header: the byte-order magic defines the endianness
           bom = fh.read(4)
           if len(bom) < 4:
               return
           endian = "<" if struct.unpack("<I", bom)[0] == 0x1A2B3C4D else ">"
           blen = struct.unpack(endian + "I", head[4:8])[0]
           if blen < 12:
               return
           fh.read(blen - 12)   # rest of block incl. trailing length
           iface_id = 0
           tsresol = {}
           continue
       blen = struct.unpack(endian + "I", head[4:8])[0]
       if blen < 12:
           return
       body = fh.read(blen - 12)
       fh.read(4)  # trailing length
       if btype == 0x00000001:              # interface description
           res = 6
           opts = body[8:]
           i = 0
           while i + 4 <= len(opts):
               ocode, olen = struct.unpack(endian + "HH", opts[i:i + 4])
               oval = opts[i + 4:i + 4 + olen]
               if ocode == 0:
                   break
               if ocode == 9 and olen >= 1:      # if_tsresol
                   raw = oval[0]
                   res = raw & 0x7F
                   if raw & 0x80:
                       res = ("pow2", res)
               i += 4 + olen + ((4 - olen % 4) % 4)
           tsresol[iface_id] = res
           iface_id += 1
       elif btype == 0x00000006:            # enhanced packet block
           if len(body) < 20:
               continue
           ifid, tsh, tsl, incl, _orig = struct.unpack(endian + "IIIII", body[:20])
           data = body[20:20 + incl]
           raw_ts = (tsh << 32) | tsl
           res = tsresol.get(ifid, 6)
           if isinstance(res, tuple):
               ts = raw_ts / float(2 ** res[1])
           else:
               ts = raw_ts / float(10 ** res)
           yield ts, data
       elif btype == 0x00000003:            # simple packet block
           continue

def read_capture(path):
   fh = _open(path)
   magic_raw = fh.read(4)
   if len(magic_raw) < 4:
       fh.close()
       return
   m_le = struct.unpack("<I", magic_raw)[0]
   m_be = struct.unpack(">I", magic_raw)[0]
   try:
       if m_le == 0x0A0D0D0A or m_be == 0x0A0D0D0A:
           for item in read_pcapng(fh):
               yield item
       elif m_le in (0xA1B2C3D4, 0xA1B23C4D):
           # magic reads correctly as little-endian -> file is little-endian
           for item in read_pcap(fh, "<", m_le == 0xA1B23C4D):
               yield item
       elif m_be in (0xA1B2C3D4, 0xA1B23C4D):
           for item in read_pcap(fh, ">", m_be == 0xA1B23C4D):
               yield item
       else:
           sys.stderr.write(
               "[WARN] %s: unrecognised magic 0x%08x, skipped\n"
               % (path, m_le)
           )
   finally:
       fh.close()

# ---------------------------------------------------------------------------
# frame -> observation
# ---------------------------------------------------------------------------
def parse_frame(data, require_ethertype):
   """Return (tag, state, src_mac) or None.
   The JSON is located by scanning the whole frame rather than by fixed
   offset: payload length varies (68 vs 69 bytes seen live) and some
   captures include the link header while others do not.
   """
   if require_ethertype:
       if len(data) < 14:
           return None
       if struct.unpack(">H", data[12:14])[0] != ETHERTYPE_ZEA:
           return None
   m = JSON_RE.search(data)
   if m is None:
       m = JSON_RE_LOOSE.search(data)
   if m is None:
       return None
   try:
       tag = m.group(1).decode("ascii")
       state = m.group(2).decode("ascii")
   except UnicodeDecodeError:
       return None
   src = ""
   if len(data) >= 12:
       src = ":".join(
           binascii.hexlify(data[6:12][i:i + 1]).decode() for i in range(6)
       )
   return tag, state, src

def median(vals):
   if not vals:
       return 0.0
   s = sorted(vals)
   n = len(s)
   return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2.0

IP_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

def bridge_name(path):
   """Label a capture by its bridge IP when the filename carries one.
   172.16.41.113_zea-test.pcap -> 172.16.41.113
   Anything without an IP falls back to the basename minus extension.
   """
   base = os.path.basename(path)
   m = IP_RE.search(base)
   if m:
       return m.group(1)
   for ext in (".gz", ".pcapng", ".pcap", ".cap"):
       if base.endswith(ext):
           base = base[: -len(ext)]
   return base

def short_bridges(bridges, limit):
   """Render a bridge list, collapsing the tail to '+N'."""
   if limit <= 0 or len(bridges) <= limit:
       return "|".join(bridges)
   return "|".join(bridges[:limit]) + "|+%d" % (len(bridges) - limit)

# ---------------------------------------------------------------------------
# collection
# ---------------------------------------------------------------------------
def collect(paths, require_ethertype):
   """-> obs[tag] = list of (ts, state, bridge, src_mac), plus stats."""
   obs = {}
   stats = {}
   for path in paths:
       bname = bridge_name(path)
       n_frames = 0
       n_hits = 0
       n_trunc = 0
       first_ts = None
       last_ts = None
       for ts, data in read_capture(path):
           n_frames += 1
           if first_ts is None or ts < first_ts:
               first_ts = ts
           if last_ts is None or ts > last_ts:
               last_ts = ts
           got = parse_frame(data, require_ethertype)
           if got is None:
               if TRUNC_RE.search(data):
                   n_trunc += 1
               continue
           tag, state, src = got
           n_hits += 1
           obs.setdefault(tag, []).append((ts, state, bname, src))
       stats[bname] = {
           "path": path,
           "frames": n_frames,
           "records": n_hits,
           "truncated": n_trunc,
           "first": first_ts,
           "last": last_ts,
       }
   for tag in obs:
       obs[tag].sort(key=lambda r: r[0])
   return obs, stats

def drop_bad_clocks(obs, stats, max_dev):
   """Discard records whose timestamp is absurd relative to the bulk.
   A bridge with an unset or corrupt RTC emits packets dated years away.
   A single such packet poisons capture_end and every open interval in the
   run, so these are removed before any interval is built.
   """
   all_ts = []
   for recs in obs.values():
       all_ts.extend(r[0] for r in recs)
   if not all_ts:
       return 0, {}
   ref = median(all_ts)
   dropped = 0
   per_bridge = {}
   for tag in list(obs):
       keep = []
       for r in obs[tag]:
           if abs(r[0] - ref) > max_dev:
               dropped += 1
               per_bridge[r[2]] = per_bridge.get(r[2], 0) + 1
           else:
               keep.append(r)
       if keep:
           obs[tag] = keep
       else:
           del obs[tag]
   # recompute per-bridge spans from surviving records
   span = {}
   for recs in obs.values():
       for ts, _st, b, _src in recs:
           lo, hi = span.get(b, (ts, ts))
           span[b] = (min(lo, ts), max(hi, ts))
   for b in stats:
       if b in span:
           stats[b]["first"], stats[b]["last"] = span[b]
       elif per_bridge.get(b):
           stats[b]["first"] = stats[b]["last"] = None
   return dropped, per_bridge

# ---------------------------------------------------------------------------
# clock skew estimate
# ---------------------------------------------------------------------------
def skew_report(obs, window):
   """For each state change, compare per-bridge first-observation times.
   Reference is the earliest bridge to report that change. A bridge that is
   consistently late by a constant amount has a clock offset, not a radio
   problem.
   """
   deltas = {}
   for tag, records in obs.items():
       prev = None
       i = 0
       n = len(records)
       while i < n:
           ts, state, bname, _src = records[i]
           if state != prev:
               # gather all bridges reporting this same state within window
               seen = {}
               j = i
               while j < n and records[j][0] - ts <= window:
                   t2, s2, b2, _ = records[j]
                   if s2 == state and b2 not in seen:
                       seen[b2] = t2
                   j += 1
               if len(seen) > 1:
                   base = min(seen.values())
                   for b, t in seen.items():
                       deltas.setdefault(b, []).append(t - base)
               prev = state
           i += 1
   rows = []
   for b in sorted(deltas):
       d = sorted(deltas[b])
       n = len(d)
       med = d[n // 2] if n % 2 else (d[n // 2 - 1] + d[n // 2]) / 2.0
       rows.append((b, n, med, d[0], d[-1]))
   return rows

def coverage(obs, stats, gap_factor, expected_tags):
   """Estimate whether enough packets were captured to trust the intervals.
   Per tag: infer the broadcast period from the median inter-arrival of each
   bridge that heard it, measure the largest hole in the MERGED timeline, and
   flag holes big enough to hide a state change.
   """
   win_start = min(s["first"] for s in stats.values() if s["first"] is not None)
   win_end = max(s["last"] for s in stats.values() if s["last"] is not None)
   bridge_rows = []
   for b in sorted(stats):
       s = stats[b]
       if s["first"] is None:
           bridge_rows.append((b, 0, 0.0, 0.0, 0.0, s["truncated"]))
           continue
       bridge_rows.append((
           b, s["records"],
           s["last"] - s["first"],
           s["first"] - win_start,        # late start
           win_end - s["last"],           # early stop
           s["truncated"],
       ))
   tag_rows = []
   for tag in sorted(obs):
       recs = obs[tag]
       bridges = sorted(set(r[2] for r in recs))
       # broadcast period: median inter-arrival within a single bridge
       periods = []
       for b in bridges:
           ts = [r[0] for r in recs if r[2] == b]
           if len(ts) > 2:
               periods.append(median([ts[i + 1] - ts[i]
                                      for i in range(len(ts) - 1)]))
       period = median(periods)
       merged = [r[0] for r in recs]
       gaps = [merged[i + 1] - merged[i] for i in range(len(merged) - 1)]
       max_gap = max(gaps) if gaps else 0.0
       span = merged[-1] - merged[0]
       # delivery ratio against the best-case single-bridge expectation
       if period > 0:
           expected = span / period
           best = max(
               (sum(1 for r in recs if r[2] == b) for b in bridges),
               default=0,
           )
           ratio = best / expected if expected > 0 else 0.0
       else:
           ratio = 0.0
       blind = 0
       if period > 0:
           blind = sum(1 for g in gaps if g > gap_factor * period)
       tag_rows.append({
           "tag": tag,
           "records": len(recs),
           "bridges": bridges,
           "period": period,
           "max_gap": max_gap,
           "ratio": ratio,
           "blind": blind,
           "first_gap": merged[0] - win_start,
           "last_gap": win_end - merged[-1],
       })
   missing = sorted(expected_tags - set(obs)) if expected_tags else []
   return bridge_rows, tag_rows, missing, win_start, win_end

def print_coverage(bridge_rows, tag_rows, missing, win_start, win_end,
                  gap_factor, tz_hours, stats, skew_rows):
   total_frames = sum(s["frames"] for s in stats.values())
   total_recs = sum(s["records"] for s in stats.values())
   print(rule("="))
   print(" ZEA CAPTURE COVERAGE")
   print(rule("="))
   print("  window    %s  ->  %s   (%.1fs)"
         % (fmt_time(win_start, tz_hours), fmt_time(win_end, tz_hours),
            win_end - win_start))
   print("  timezone  UTC%+g" % tz_hours)
   print("  sources   %d capture(s)   %d frames   %d ZEA records   %d tags"
         % (len(stats), total_frames, total_recs, len(tag_rows)))
   print()
   # ---- bridges ----------------------------------------------------------
   b_body = []
   for b, n, span, late, early, trunc in bridge_rows:
       if n == 0 or trunc > 0:
           st = "fail"
       elif late > 5.0 or early > 5.0:
           st = "warn"
       else:
           st = "ok"
       b_body.append([b, "%d" % n, "%.1f" % span, "%.1f" % late,
                      "%.1f" % early, "%d" % trunc, status_tag(st)])
   print(section("bridges"))
   print(table(
       ["BRIDGE", "RECORDS", "SPAN(s)", "LATE START", "EARLY STOP",
        "TRUNC", "STATUS"],
       b_body, ["l", "r", "r", "r", "r", "r", "l"]))
   print()
   # ---- clock skew -------------------------------------------------------
   print(section("clock skew"))
   if skew_rows:
       s_body = []
       for b, n, med, lo, hi in skew_rows:
           st = "ok" if abs(med) <= 1.0 else ("warn" if abs(med) <= 3.0
                                              else "fail")
           s_body.append([b, "%d" % n, "%+.3f" % med, "%+.3f" % lo,
                          "%+.3f" % hi, status_tag(st)])
       print(table(
           ["BRIDGE", "SAMPLES", "MEDIAN(s)", "MIN(s)", "MAX(s)", "STATUS"],
           s_body, ["l", "r", "r", "r", "r", "l"]))
   else:
       print("  no overlapping state changes - bridges share no tags, "
             "skew cannot be measured")
   print()
   # ---- tags -------------------------------------------------------------
   t_body = []
   for t in tag_rows:
       if t["blind"] > 0 or t["ratio"] < 0.5:
           st = "fail"
       elif len(t["bridges"]) == 1 or t["ratio"] < 0.9 \
               or t["first_gap"] > 10.0 or t["last_gap"] > 10.0:
           st = "warn"
       else:
           st = "ok"
       t_body.append([
           t["tag"], "%d" % t["records"], "%d" % len(t["bridges"]),
           "%.2f" % t["period"], "%.2f" % t["max_gap"],
           "%.2f" % t["ratio"], "%d" % t["blind"],
           "%.1f" % t["first_gap"], "%.1f" % t["last_gap"],
           status_tag(st),
       ])
   print(section("tags"))
   print(table(
       ["TAG", "RECS", "BRDG", "PERIOD", "MAX GAP", "DELIV", "BLIND",
        "HEAD(s)", "TAIL(s)", "STATUS"],
       t_body, ["l", "r", "r", "r", "r", "r", "r", "r", "r", "l"]))
   print()
   # ---- findings ---------------------------------------------------------
   findings = []
   solo = [t["tag"] for t in tag_rows if len(t["bridges"]) == 1]
   if solo:
       findings.append(("warn",
                        "%d tag(s) heard by one bridge only, no redundancy: %s"
                        % (len(solo), ", ".join(solo[:12]))))
   blind = [t for t in tag_rows if t["blind"] > 0]
   if blind:
       worst = max(blind, key=lambda t: t["max_gap"])
       findings.append(("fail",
                        "%d tag(s) have a hole > %.0fx the broadcast period; "
                        "a state change could hide there (worst %s, %.1fs)"
                        % (len(blind), gap_factor, worst["tag"],
                           worst["max_gap"])))
   inflated = [t for t in tag_rows if t["ratio"] < 0.9]
   if inflated:
       findings.append(("warn",
                        "%d tag(s) below 0.9 delivery; inferred period is "
                        "likely inflated by loss" % len(inflated)))
   late = [b for b in bridge_rows if b[3] > 5.0]
   if late:
       findings.append(("warn",
                        "%d bridge(s) started >5s after the earliest "
                        "capture: %s" % (len(late),
                                         ", ".join(b[0] for b in late))))
   early = [b for b in bridge_rows if b[4] > 5.0]
   if early:
       findings.append(("warn",
                        "%d bridge(s) stopped >5s before the latest "
                        "capture: %s" % (len(early),
                                         ", ".join(b[0] for b in early))))
   trunc = [b for b in bridge_rows if b[5] > 0]
   if trunc:
       findings.append(("fail",
                        "%d bridge(s) have snaplen-truncated frames, "
                        "re-capture with -s 0: %s"
                        % (len(trunc), ", ".join(b[0] for b in trunc))))
   if skew_rows:
       bad = [r for r in skew_rows if abs(r[2]) > 1.0]
       if bad:
           worst = max(abs(r[2]) for r in bad)
           findings.append(("fail",
                            "clock offset up to %.3fs between bridges; "
                            "merged intervals may contain phantom "
                            "transitions. Sync NTP or pass --settle %.0f"
                            % (worst, max(2.0, worst * 2))))
   if missing:
       findings.append(("fail",
                        "%d expected tag(s) never appeared in any capture: %s"
                        % (len(missing), ", ".join(missing[:12]))))
   print(section("findings"))
   if findings:
       order = {"fail": 0, "warn": 1, "ok": 2}
       for lvl, msg in sorted(findings, key=lambda f: order[f[0]]):
           prefix = "  [%s] " % status_tag(lvl)
           pad = " " * len(prefix)
           words = msg.split()
           line = prefix
           for w in words:
               if len(line) + len(w) + 1 > RULE_W:
                   print(line)
                   line = pad + w
               else:
                   line += ("" if line.endswith(" ") else " ") + w
           print(line)
   else:
       print("  [OK] no coverage gaps detected")
   print(rule("="))

def intervals(obs, capture_end, settle):
   """Collapse each tag's merged timeline into state intervals.
   An interval ends at the FIRST observation of the next state, not at the
   last observation of the current state. `settle` suppresses a flip that is
   contradicted within that many seconds by a bridge still reporting the old
   state (guards against residual clock skew and stale rebroadcasts).
   """
   out = []
   for tag, records in obs.items():
       cur_state = None
       cur_start = None
       cur_bridges = set()
       pending = None          # (ts, state, bridges) candidate change
       for idx, (ts, state, bname, _src) in enumerate(records):
           if cur_state is None:
               cur_state = state
               cur_start = ts
               cur_bridges = {bname}
               continue
           if state == cur_state:
               cur_bridges.add(bname)
               # a same-state report inside the settle window kills a pending flip
               if pending is not None and ts - pending[0] <= settle:
                   pending = None
               continue
           # differing state
           if pending is None or pending[1] != state:
               pending = (ts, state, {bname})
           else:
               pending[2].add(bname)
           confirmed = (
               settle <= 0
               or ts - pending[0] > settle
               or idx == len(records) - 1
           )
           if confirmed:
               out.append({
                   "tag": tag,
                   "state": cur_state,
                   "start": cur_start,
                   "end": pending[0],
                   "closed": True,
                   "bridges": sorted(cur_bridges),
               })
               cur_state = pending[1]
               cur_start = pending[0]
               cur_bridges = set(pending[2])
               pending = None
       if cur_state is not None:
           out.append({
               "tag": tag,
               "state": cur_state,
               "start": cur_start,
               "end": capture_end,
               "closed": False,
               "bridges": sorted(cur_bridges),
           })
   out.sort(key=lambda r: (r["start"], r["tag"]))
   return out

# ---------------------------------------------------------------------------
# output
# ---------------------------------------------------------------------------
def fmt_time(epoch, tz_hours):
   dt = datetime(1970, 1, 1) + timedelta(seconds=epoch + tz_hours * 3600.0)
   return dt.strftime("%Y-%m-%d %H:%M:%S")

# ---- dashboard rendering ---------------------------------------------------
RULE_W = 78

def rule(char="="):
   return char * RULE_W

def section(title):
   head = "---- %s " % title.upper()
   return head + "-" * max(0, RULE_W - len(head))

def table(headers, rows, aligns=None, indent=2):
   """Render an aligned fixed-width table. rows are lists of str."""
   if not rows:
       return " " * indent + "(none)"
   ncol = len(headers)
   aligns = aligns or ["l"] * ncol
   widths = [len(h) for h in headers]
   for r in rows:
       for i in range(ncol):
           widths[i] = max(widths[i], len(r[i]))
   def line(cells):
       out = []
       for i, c in enumerate(cells):
           out.append(c.rjust(widths[i]) if aligns[i] == "r"
                      else c.ljust(widths[i]))
       return " " * indent + "  ".join(out).rstrip()
   lines = [line(headers),
            " " * indent + "  ".join("-" * w for w in widths)]
   for r in rows:
       lines.append(line(r))
   return "\n".join(lines)

def status_tag(level):
   return {"ok": "OK", "warn": "WARN", "fail": "FAIL"}[level]

def emit_csv(rows, tz_hours, states, out_fh, show_bridges):
   header = "tag,state,start,end,duration,closed"
   if show_bridges:
       header += ",bridges"
   out_fh.write(header + "\n")
   for r in rows:
       if states and r["state"] not in states:
           continue
       end_s = fmt_time(r["end"], tz_hours) if r["closed"] else ""
       dur_s = "%.3f" % (r["end"] - r["start"]) if r["closed"] else ""
       line = "%s,%s,%s,%s,%s,%s" % (
           r["tag"], r["state"],
           fmt_time(r["start"], tz_hours), end_s, dur_s,
           "Y" if r["closed"] else "N",
       )
       if show_bridges:
           line += "," + "|".join(r["bridges"])
       out_fh.write(line + "\n")

def emit_table(rows, tz_hours, states, out_fh, show_bridges,
              max_bridges=3):
   sel = [r for r in rows if not states or r["state"] in states]
   headers = ["TAG", "STATE", "START", "END", "DURATION", "END?"]
   aligns = ["l", "l", "l", "l", "r", "l"]
   if show_bridges:
       headers.append("SEEN BY")
       aligns.append("l")
   body = []
   for r in sel:
       # an open interval never ended; showing a time there would be invented
       end_s = fmt_time(r["end"], tz_hours) if r["closed"] else ""
       dur_s = "%.3f" % (r["end"] - r["start"]) if r["closed"] else ""
       cells = [
           r["tag"], r["state"],
           fmt_time(r["start"], tz_hours), end_s, dur_s,
           "closed" if r["closed"] else "OPEN",
       ]
       if show_bridges:
           cells.append(short_bridges(r["bridges"], max_bridges))
       body.append(cells)
   out_fh.write(section("intervals") + "\n")
   out_fh.write(table(headers, body, aligns) + "\n")
   n_open = sum(1 for r in sel if not r["closed"])
   by_state = {}
   for r in sel:
       by_state[r["state"]] = by_state.get(r["state"], 0) + 1
   parts = ["%s=%d" % (k, by_state[k]) for k in sorted(by_state)]
   out_fh.write("\n  %d intervals over %d tags   %s\n"
                % (len(sel), len(set(r["tag"] for r in sel)),
                   "  ".join(parts)))
   if n_open:
       out_fh.write("  %d still open at capture end (END?=OPEN) - those "
                    "durations are lower bounds\n" % n_open)
   # rapid oscillation usually means one bridge disagrees with the rest
   short = [r for r in sel if r["closed"] and (r["end"] - r["start"]) < 1.0]
   if len(short) > max(10, len(sel) // 20):
       solo = {}
       for r in short:
           if len(r["bridges"]) == 1:
               solo[r["bridges"][0]] = solo.get(r["bridges"][0], 0) + 1
       out_fh.write("  %d interval(s) under 1s - likely bridge disagreement, "
                    "not real transitions\n" % len(short))
       if solo:
           top = sorted(solo.items(), key=lambda kv: -kv[1])[:3]
           out_fh.write("  odd-one-out: %s\n"
                        % ", ".join("%s (%d solo intervals)" % (b, n)
                                    for b, n in top))

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
   ap = argparse.ArgumentParser(
       description="Merge multi-bridge ZEA captures into per-tag state intervals."
   )
   ap.add_argument("captures", nargs="+",
                   help="pcap/pcapng files, one per bridge (globs ok)")
   ap.add_argument("--tz", type=float, default=9.0,
                   help="hours to add to UTC for display (default 9, mine-local)")
   ap.add_argument("--csv", metavar="FILE",
                   help="write CSV here instead of stdout")
   ap.add_argument("--state", action="append", metavar="S",
                   help="only emit this state (repeatable), e.g. --state ACTIVE_ON")
   ap.add_argument("--settle", type=float, default=0.0,
                   help="seconds a state change must survive unchallenged "
                        "before it is accepted (default 0 = accept first report)")
   ap.add_argument("--skew", action="store_true",
                   help="report inter-bridge clock offsets and exit")
   ap.add_argument("--coverage", action="store_true",
                   help="report capture completeness per bridge and per tag, "
                        "then exit")
   ap.add_argument("--gap-factor", type=float, default=3.0,
                   help="a hole larger than this many broadcast periods is "
                        "flagged as a blind window (default 3)")
   ap.add_argument("--expect", metavar="FILE",
                   help="file of expected tag IDs, one per line; report any "
                        "that never appeared")
   ap.add_argument("--skew-window", type=float, default=15.0,
                   help="window for matching the same state change across "
                        "bridges during skew analysis (default 15s)")
   ap.add_argument("--per-bridge", action="store_true",
                   help="also write unmerged per-bridge intervals")
   ap.add_argument("--max-bridges", type=int, default=3, metavar="N",
                   help="show at most N bridges in the SEEN BY column, "
                        "then '+K' (0 = show all; CSV always has all)")
   ap.add_argument("--max-clock-dev", type=float, default=86400.0,
                   metavar="S",
                   help="discard packets whose timestamp is more than S "
                        "seconds from the bulk of the capture, guarding "
                        "against bridges with an unset RTC (default 86400)")
   ap.add_argument("--raw", action="store_true",
                   help="print plain CSV to stdout instead of the table")
   ap.add_argument("--no-bridges", action="store_true",
                   help="omit the trailing bridges column")
   ap.add_argument("--any-ethertype", action="store_true",
                   help="do not require ethertype 0x4d54 (use if the capture "
                        "has no link header)")
   ap.add_argument("--summary", action="store_true",
                   help="print per-file parse stats to stderr")
   args = ap.parse_args()
   paths = []
   for pat in args.captures:
       hits = sorted(glob.glob(pat))
       paths.extend(hits if hits else [pat])
   paths = [p for p in paths if os.path.isfile(p)]
   if not paths:
       sys.stderr.write("[ERROR] no capture files found\n")
       return 2
   obs, stats = collect(paths, require_ethertype=not args.any_ethertype)
   n_bad, bad_by_bridge = drop_bad_clocks(obs, stats, args.max_clock_dev)
   if n_bad:
       worst = sorted(bad_by_bridge.items(), key=lambda kv: -kv[1])[:5]
       sys.stderr.write(
           "[WARN] discarded %d record(s) with a timestamp more than %.0fs "
           "from the rest of the capture\n" % (n_bad, args.max_clock_dev))
       for b, n in worst:
           sys.stderr.write("       %-18s %d record(s) - check this "
                            "bridge's clock\n" % (b, n))
   if args.summary or not obs:
       for b in sorted(stats):
           s = stats[b]
           sys.stderr.write(
               "[STAT] %-24s frames=%-8d records=%-7d truncated=%-5d span=%s\n"
               % (b, s["frames"], s["records"], s["truncated"],
                  ("%.1fs" % (s["last"] - s["first"]))
                  if s["first"] is not None else "-")
           )
   if not obs:
       sys.stderr.write(
           "[ERROR] no ZEA records decoded. If the captures have no link "
           "header, retry with --any-ethertype\n"
       )
       return 1
   unknown = set()
   for recs in obs.values():
       for _, st, _, _ in recs:
           if st not in KNOWN_STATES:
               unknown.add(st)
   if unknown:
       sys.stderr.write("[WARN] unexpected EVAC values: %s\n"
                        % ", ".join(sorted(unknown)))
   if args.coverage:
       expected = set()
       if args.expect:
           with open(args.expect) as fh:
               expected = set(
                   ln.strip() for ln in fh
                   if ln.strip() and not ln.startswith("#")
               )
       br, tr, missing, ws, we = coverage(
           obs, stats, args.gap_factor, expected)
       sk = skew_report(obs, args.skew_window)
       print_coverage(br, tr, missing, ws, we, args.gap_factor, args.tz,
                      stats, sk)
       return 0
   if args.skew:
       rows = skew_report(obs, args.skew_window)
       if not rows:
           sys.stderr.write("[WARN] no overlapping state changes found; "
                            "bridges may not share any tags\n")
           return 1
       print(section("clock skew"))
       body = []
       for b, n, med, lo, hi in rows:
           st = "ok" if abs(med) <= 1.0 else ("warn" if abs(med) <= 3.0
                                              else "fail")
           body.append([b, "%d" % n, "%+.3f" % med, "%+.3f" % lo,
                        "%+.3f" % hi, status_tag(st)])
       print(table(["BRIDGE", "SAMPLES", "MEDIAN(s)", "MIN(s)", "MAX(s)",
                    "STATUS"], body, ["l", "r", "r", "r", "r", "l"]))
       worst = max(r[2] for r in rows)
       if worst > 1.0:
           sys.stderr.write(
               "[WARN] median offset up to %.3fs. Merged intervals will "
               "contain phantom transitions. Sync the bridges or pass "
               "--settle %.0f\n" % (worst, max(2.0, worst * 2))
           )
       return 0
   capture_end = max(
       r[0] for recs in obs.values() for r in recs
   )
   rows = intervals(obs, capture_end, args.settle)
   states = set(args.state or [])
   show_b = not args.no_bridges
   if args.csv:
       with open(args.csv, "w") as fh:
           emit_csv(rows, args.tz, states, fh, show_b)
       sys.stderr.write("[OK] wrote %s (%d intervals)\n"
                        % (args.csv, len(rows)))
   elif args.raw:
       emit_csv(rows, args.tz, states, sys.stdout, show_b)
   else:
       emit_table(rows, args.tz, states, sys.stdout, show_b,
                  max_bridges=args.max_bridges)
   if args.per_bridge:
       for b in sorted(stats):
           sub = {}
           for tag, recs in obs.items():
               keep = [r for r in recs if r[2] == b]
               if keep:
                   sub[tag] = keep
           if not sub:
               continue
           end_b = stats[b]["last"]
           rows_b = intervals(sub, end_b, args.settle)
           fn = "%s.intervals.csv" % b
           with open(fn, "w") as fh:
               emit_csv(rows_b, args.tz, set(args.state or []), fh,
                        show_bridges=not args.no_bridges)
           sys.stderr.write("[OK] wrote %s (%d intervals)\n" % (fn, len(rows_b)))
   if args.csv or args.raw:
       n_open = sum(1 for r in rows if not r["closed"])
       if n_open:
           sys.stderr.write(
               "[WARN] %d interval(s) still open at capture end (closed=N); "
               "their durations are lower bounds\n" % n_open
           )
   return 0

if __name__ == "__main__":
   try:
       sys.exit(main())
   except KeyboardInterrupt:
       os._exit(0)