#!/usr/bin/env python3
"""
zea_capture.py - start, monitor and collect ZEA captures across bridge units.
Runs on MineOffice. Talks to each bridge over ssh (sshpass), launches a
detached, filtered tcpdump, then pulls the pcap back named by bridge IP so
zea_merge.py can consume it directly.
Subcommands:
   start     launch capture on every bridge (parallel)
   status    is it running, how big is the file
   stop      terminate capture early
   collect   pull pcaps back to the local directory
   clean     remove remote pcap and pid files
   run       start, wait for the duration, then collect
Typical use:
   ./zea_capture.py run --hosts bridges.txt --duration 300 --outdir ~/zea-pcaps
Host list is one IP per line; blank lines and # comments ignored.
"""
import argparse
import concurrent.futures
import gzip
import os
import re
import subprocess
import sys
import time
DEFAULT_USER = "root"
DEFAULT_PASS = "minetec2018!"
REMOTE_PCAP = "/tmp/zea-test.pcap"
REMOTE_PID = "/tmp/zea-test.pid"
DEFAULT_FILTER = "ether proto 0x4d54"
SSH_OPTS = [
   "-T",                       # no pty: a pty mangles binary with CRLF
   "-o", "StrictHostKeyChecking=no",
   "-o", "UserKnownHostsFile=/dev/null",
   "-o", "LogLevel=ERROR",
   "-o", "ConnectTimeout=8",
   "-o", "BatchMode=no",
   "-o", "PubkeyAuthentication=no",
]
IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# ---------------------------------------------------------------------------
# ssh plumbing
# ---------------------------------------------------------------------------
def ssh(host, user, password, command, timeout=30, binary_out=False):
   """Run a command on a bridge. Returns (rc, stdout, stderr)."""
   argv = ["sshpass", "-p", password, "ssh"] + SSH_OPTS + \
          ["%s@%s" % (user, host), command]
   try:
       p = subprocess.run(argv, timeout=timeout,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
   except subprocess.TimeoutExpired:
       return 255, b"" if binary_out else "", "timeout after %ds" % timeout
   except FileNotFoundError:
       # never sys.exit here: this runs inside a worker thread
       return 254, b"" if binary_out else "", "sshpass not found"
   out = p.stdout if binary_out else p.stdout.decode("utf-8", "replace")
   err = p.stderr.decode("utf-8", "replace").strip()
   return p.returncode, out, err

def load_hosts(args):
   hosts = []
   if args.hosts:
       with open(args.hosts) as fh:
           for ln in fh:
               ln = ln.split("#", 1)[0].strip()
               if ln:
                   hosts.append(ln)
   hosts.extend(args.host or [])
   if getattr(args, "leases", None) and args.action != "discover":
       hosts.extend(r["ip"] for r in read_leases(
           args.leases, getattr(args, "name_filter", None),
           getattr(args, "mac_prefix", None)) if not r["expired"])
   if getattr(args, "subnet", None):
       hosts.extend(expand_subnets(args.subnet))
   seen = set()
   ordered = []
   for h in hosts:
       if h not in seen:
           seen.add(h)
           ordered.append(h)
   bad = [h for h in ordered if not IP_RE.match(h)]
   if bad:
       sys.stderr.write("[WARN] not IP-shaped, kept anyway: %s\n"
                        % ", ".join(bad))
   return ordered

def expand_subnets(specs):
   """Accept 172.16.41.0/24, 172.16.41.0/25 ... or 172.16.41.10-60."""
   out = []
   for spec in specs:
       spec = spec.strip()
       if "-" in spec:
           base, last = spec.rsplit(".", 1)[0], spec.rsplit(".", 1)[1]
           lo, hi = last.split("-", 1)
           for i in range(int(lo), int(hi) + 1):
               out.append("%s.%d" % (base, i))
           continue
       if "/" in spec:
           net, bits = spec.split("/", 1)
           bits = int(bits)
           if bits < 22:
               sys.stderr.write("[ERROR] %s is too large to sweep; use /22 "
                                "or smaller\n" % spec)
               sys.exit(2)
           octs = [int(o) for o in net.split(".")]
           base = (octs[0] << 24) | (octs[1] << 16) | (octs[2] << 8) | octs[3]
           size = 1 << (32 - bits)
           base = base & ~(size - 1)
           for i in range(1, size - 1):
               v = base + i
               out.append("%d.%d.%d.%d" % ((v >> 24) & 255, (v >> 16) & 255,
                                           (v >> 8) & 255, v & 255))
           continue
       out.append(spec)
   seen = set()
   uniq = []
   for h in out:
       if h not in seen:
           seen.add(h)
           uniq.append(h)
   return uniq

def median(vals):
   if not vals:
       return 0.0
   v = sorted(vals)
   n = len(v)
   return v[n // 2] if n % 2 else (v[n // 2 - 1] + v[n // 2]) / 2.0

def ping_once(host, timeout=1):
   return subprocess.call(
       ["ping", "-c", "1", "-W", str(timeout), host],
       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

def read_leases(path, name_filter=None, mac_prefix=None):
   """Parse a dnsmasq lease file.
   Format: <expiry> <mac> <ip> <hostname> <client-id>
   Returns list of dicts. name_filter and mac_prefix narrow the result to
   bridges; on this site both Minetec-BR-* hostnames and the c4:93:00 OUI
   identify them, and either alone is enough.
   """
   out = []
   now = time.time()
   try:
       with open(path) as fh:
           for ln in fh:
               parts = ln.split()
               if len(parts) < 4 or not IP_RE.match(parts[2]):
                   continue
               exp, mac, ip, name = parts[0], parts[1], parts[2], parts[3]
               if name_filter and name_filter.lower() not in name.lower():
                   continue
               if mac_prefix and not mac.lower().startswith(
                       mac_prefix.lower()):
                   continue
               try:
                   expiry = int(exp)
               except ValueError:
                   expiry = 0
               out.append({
                   "ip": ip, "mac": mac, "name": name,
                   "expiry": expiry,
                   "expired": 0 < expiry < now,
               })
   except IOError as e:
       sys.stderr.write("[ERROR] cannot read %s: %s\n" % (path, e))
   # a bridge that re-leased keeps only its newest entry
   best = {}
   for r in out:
       prev = best.get(r["mac"])
       if prev is None or r["expiry"] > prev["expiry"]:
           best[r["mac"]] = r
   return sorted(best.values(), key=lambda r: [int(o) for o in
                                               r["ip"].split(".")])

def parallel(hosts, fn, workers):
   """Run fn(host) across hosts, preserving input order in the results."""
   results = {}
   with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
       futs = {ex.submit(fn, h): h for h in hosts}
       for f in concurrent.futures.as_completed(futs):
           h = futs[f]
           try:
               results[h] = f.result()
           except Exception as e:                     # noqa: BLE001
               results[h] = (False, "exception: %s" % e)
   return [(h, results[h]) for h in hosts]

# ---------------------------------------------------------------------------
# remote commands (BusyBox ash safe: no bashisms, no nested if inside for)
# ---------------------------------------------------------------------------
def build_start_cmd(iface, duration, bpf, snaplen, maxfiles):
   """Detached, filtered, size-capped capture that self-terminates.
   setsid detaches from the ssh session so the capture survives disconnect;
   if setsid is missing we fall back to a plain background subshell, which
   BusyBox keeps alive because the parent sh exits immediately.
   """
   inner = (
       "tcpdump -ni %s -s %d -w %s %s >/dev/null 2>&1 & "
       "echo $! > %s; "
       "sleep %d; "
       "kill $(cat %s) 2>/dev/null; "
       "sleep 1; "
       "kill -9 $(cat %s) 2>/dev/null"
       % (iface, snaplen, REMOTE_PCAP, bpf, REMOTE_PID,
          duration, REMOTE_PID, REMOTE_PID)
   )
   inner = inner.replace("'", "'\\''")
   return (
       "rm -f %s %s; "
       "if command -v setsid >/dev/null 2>&1; then "
       "setsid /bin/sh -c '%s' >/dev/null 2>&1 & "
       "else /bin/sh -c '%s' >/dev/null 2>&1 & "
       "fi; "
       "sleep 2; "
       "P=$(cat %s 2>/dev/null); "
       "if [ -n \"$P\" ] && kill -0 $P 2>/dev/null; then echo $P; "
       "else echo NOPID; fi"
       % (REMOTE_PCAP, REMOTE_PID, inner, inner, REMOTE_PID)
   )

PREFLIGHT_CMD = (
   "echo CLOCK=$(date +%s); "
   "echo TCPDUMP=$(command -v tcpdump || echo missing); "
   "echo IFACES=$(ls /sys/class/net 2>/dev/null | tr '\\n' ',');"
   "echo TMPFREE=$(df -k /tmp 2>/dev/null | awk 'NR==2{print $4}')"
)
STATUS_CMD = (
   "P=$(cat %s 2>/dev/null); "
   "if [ -n \"$P\" ] && kill -0 $P 2>/dev/null; then echo RUN=yes; "
   "else echo RUN=no; fi; "
   "echo SIZE=$(ls -l %s 2>/dev/null | awk '{print $5}'); "
   "echo CLOCK=$(date +%%s)"
   % (REMOTE_PID, REMOTE_PCAP)
)
SIZE_CMD = "echo SIZE=$(ls -l %s 2>/dev/null | awk '{print $5}')" % REMOTE_PCAP
STOP_CMD = (
   "P=$(cat %s 2>/dev/null); "
   "if [ -n \"$P\" ]; then kill $P 2>/dev/null; sleep 1; "
   "kill -9 $P 2>/dev/null; echo STOPPED; else echo NOTRUNNING; fi"
   % REMOTE_PID
)
CLEAN_CMD = "rm -f %s %s && echo CLEANED" % (REMOTE_PCAP, REMOTE_PID)

def parse_kv(text):
   out = {}
   for ln in text.splitlines():
       if "=" in ln:
           k, v = ln.split("=", 1)
           out[k.strip()] = v.strip()
   return out

# ---------------------------------------------------------------------------
# actions
# ---------------------------------------------------------------------------
PROBE_CMD = (
   "echo IFACES=$(ls /sys/class/net 2>/dev/null | tr '\\n' ',');"
   "echo TCPDUMP=$(command -v tcpdump || echo missing);"
   "echo MODEL=$(cat /tmp/sysinfo/model 2>/dev/null || uname -n)"
)

def write_hosts(path, hosts):
   with open(os.path.expanduser(path), "w") as fh:
       fh.write("# discovered %s\n" % time.strftime("%Y-%m-%d %H:%M:%S"))
       for h in hosts:
           fh.write(h + "\n")

def act_discover(hosts, args):
   """Sweep candidate IPs, then confirm each is really a bridge over ssh.
   Reachability alone is not enough: VPCs and servers answer ping too. A
   host only counts as a bridge if it has the capture interface AND tcpdump.
   """
   leases = []
   if args.leases:
       leases = read_leases(args.leases, args.name_filter, args.mac_prefix)
       print(section("dhcp leases"))
       print("  %s   filter: name~%s  mac~%s"
             % (args.leases, args.name_filter or "*",
                args.mac_prefix or "*"))
       stale = [r for r in leases if r["expired"]]
       if args.list:
           rows = [[r["ip"], r["name"], r["mac"],
                    "EXPIRED" if r["expired"] else "current"]
                   for r in leases]
           print(table(["IP", "HOSTNAME", "MAC", "LEASE"], rows,
                       ["l", "l", "l", "l"]))
       elif stale:
           # the healthy bulk is noise; expired leases are actionable
           rows = [[r["ip"], r["name"], r["mac"]] for r in stale]
           print(table(["EXPIRED IP", "HOSTNAME", "MAC"], rows,
                       ["l", "l", "l"]))
       print()
       print("  %d bridge lease(s), %d expired%s"
             % (len(leases), len(stale),
                "" if args.list else "   (--list for the full table)"))
       print()
       if not args.verify:
           fresh = [r["ip"] for r in leases if not r["expired"]]
           if args.save_hosts and fresh:
               write_hosts(args.save_hosts, fresh)
               print("  wrote %s (%d bridges)"
                     % (args.save_hosts, len(fresh)))
               print()
               print("  next: zea_capture.py run --hosts %s"
                     % args.save_hosts)
           elif fresh:
               print("  re-run with --save-hosts bridges.txt to keep this "
                     "list, or --verify to ssh-check each one first")
           return 0 if fresh else 1
       hosts = [r["ip"] for r in leases if not r["expired"]]
   if not hosts:
       sys.stderr.write("[ERROR] discover needs --leases, --subnet or "
                        "--hosts to define the search space\n")
       return 2
   print(section("sweep"))
   print("  probing %d address(es)" % len(hosts))
   alive = [h for h, up in parallel(hosts, ping_once, args.workers) if up]
   print("  %d responded to ping" % len(alive))
   if not alive:
       return 1
   print()
   def probe(h):
       rc, out, err = ssh(h, args.user, args.password, PROBE_CMD,
                          timeout=args.timeout)
       if rc != 0:
           return (False, {"why": err or "ssh rc=%d" % rc})
       return (True, parse_kv(out))
   print(section("identify"))
   res = parallel(alive, probe, args.workers)
   rows = []
   bridges = []
   for h, (good, d) in res:
       if not good:
           rows.append([h, "-", "-", "no", d.get("why", "")[:30]])
           continue
       ifaces = [i for i in d.get("IFACES", "").split(",") if i]
       has_if = args.iface in ifaces
       has_td = d.get("TCPDUMP", "missing") != "missing"
       is_bridge = has_if and has_td
       if is_bridge:
           bridges.append(h)
       rows.append([h, d.get("MODEL", "?")[:22],
                    "yes" if has_if else "no",
                    "yes" if is_bridge else "no",
                    "" if is_bridge else
                    ("no tcpdump" if has_if else "no %s" % args.iface)])
   shown = rows if args.list else [r for r in rows if r[3] != "yes"]
   if shown:
       print(table(["HOST", "MODEL", "IFACE", "BRIDGE", "NOTE"], shown,
                   ["l", "l", "l", "l", "l"]))
       print()
   print("  %d bridge(s) identified out of %d reachable%s"
         % (len(bridges), len(alive),
            "" if args.list else "   (--list for the full table)"))
   if args.save_hosts and bridges:
       write_hosts(args.save_hosts, bridges)
       print("  wrote %s" % args.save_hosts)
       print()
       print("  next: zea_capture.py run --hosts %s" % args.save_hosts)
   elif bridges:
       print()
       print("  re-run with --save-hosts bridges.txt to keep this list")
   return 0 if bridges else 1

CLOCK_CMD = "echo EPOCH=$(date -u +%s); echo HUMAN=$(date -u '+%Y-%m-%d %H:%M:%S'); echo UP=$(cut -d. -f1 /proc/uptime 2>/dev/null)"

def act_clock(hosts, args):
   """Survey bridge clocks against this server.
   Offset is measured against the midpoint of the ssh round trip rather than
   against the time the reply was parsed, so a slow mesh hop does not get
   mistaken for clock drift. RTT/2 is the residual uncertainty.
   """
   def one(h):
       t0 = time.time()
       rc, out, err = ssh(h, args.user, args.password, CLOCK_CMD,
                          timeout=args.timeout)
       t1 = time.time()
       if rc != 0:
           return (False, err or "ssh rc=%d" % rc, 0.0, 0.0, "")
       kv = parse_kv(out)
       try:
           remote = float(kv.get("EPOCH", "0"))
       except ValueError:
           return (False, "unparsable date output", 0.0, t1 - t0, "")
       if remote <= 0:
           return (False, "date returned nothing", 0.0, t1 - t0, "")
       mid = (t0 + t1) / 2.0
       return (True, kv.get("HUMAN", ""), remote - mid, t1 - t0,
               kv.get("UP", ""))
   res = parallel(hosts, one, args.workers)
   rows = []
   offsets = []
   bad = 0
   unreachable = 0
   for h, (good, human, off, rtt, up) in res:
       if not good:
           unreachable += 1
           rows.append([h, "-", "-", "%.2f" % rtt, "-", "UNREACHABLE",
                        human[:26]])
           continue
       offsets.append(off)
       a = abs(off)
       if a > args.clock_warn * 10:
           st = "FAIL"
           bad += 1
       elif a > args.clock_warn:
           st = "WARN"
           bad += 1
       else:
           st = "OK"
       note = ""
       if a > 86400:
           note = "RTC unset?"
       elif up and up.isdigit() and int(up) < 300:
           note = "rebooted %ss ago" % up
       rows.append([h, human, "%+.3f" % off, "%.2f" % rtt,
                    up or "-", st, note])
   rows.sort(key=lambda r: -abs(float(r[2])) if r[2] != "-" else -1e18)
   shown = rows if args.list else [r for r in rows if r[5] != "OK"]
   if shown:
       print(table(["BRIDGE", "BRIDGE TIME (UTC)", "OFFSET(s)", "RTT(s)",
                    "UPTIME(s)", "STATUS", "NOTE"], shown,
                   ["l", "l", "r", "r", "r", "l", "l"]))
       print()
   print("  server time (UTC)  %s"
         % time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()))
   print("  %d bridge(s) queried, %d unreachable, %d beyond %.1fs"
         % (len(hosts), unreachable, bad, args.clock_warn))
   if offsets:
       med = median(offsets)
       spread = max(offsets) - min(offsets)
       print("  median offset %+.3fs   spread across bridges %.3fs"
             % (med, spread))
       if spread > 1.0:
           print("  spread above 1s will distort merged intervals; "
                 "zea_merge.py --skew measures the effect on real data")
   if not args.list and not shown:
       print("  all clocks within tolerance   (--list for the full table)")
   if args.set_clock:
       print()
       print(section("set clock"))
       return set_clocks(hosts, args)
   return 0
   
def set_clocks(hosts, args):
   """Push this server's UTC time to each bridge, then verify."""
   def one(h):
       # add half the previous RTT so the bridge lands near true time
       stamp = time.strftime("%Y-%m-%d %H:%M:%S",
                             time.gmtime(time.time() + args.set_lead))
       cmd = ("date -u -s '%s' >/dev/null 2>&1; "
              "hwclock -w >/dev/null 2>&1; "
              "echo EPOCH=$(date -u +%%s)" % stamp)
       t0 = time.time()
       rc, out, err = ssh(h, args.user, args.password, cmd,
                          timeout=args.timeout)
       t1 = time.time()
       if rc != 0:
           return (False, err or "ssh rc=%d" % rc)
       try:
           remote = float(parse_kv(out).get("EPOCH", "0"))
       except ValueError:
           return (False, "unparsable verify")
       off = remote - (t0 + t1) / 2.0
       return (abs(off) <= max(2.0, args.clock_warn), "%+.3f" % off)
   res = parallel(hosts, one, args.workers)
   rows = [[h, d, "OK" if good else "FAIL"] for h, (good, d) in res]
   ok = sum(1 for _, (g, _) in res if g)
   shown = rows if args.list else [r for r in rows if r[2] != "OK"]
   if shown:
       print(table(["BRIDGE", "NEW OFFSET(s)", "STATUS"], shown,
                   ["l", "r", "l"]))
       print()
   print("  %d/%d bridges now within tolerance" % (ok, len(hosts)))
   return 0 if ok == len(hosts) else 1

def act_preflight(hosts, args):
   local_clock = int(time.time())
   def one(h):
       rc, out, err = ssh(h, args.user, args.password, PREFLIGHT_CMD,
                          timeout=args.timeout)
       if rc != 0:
           return (False, err or "ssh rc=%d" % rc)
       kv = parse_kv(out)
       return (True, kv)
   res = parallel(hosts, one, args.workers)
   rows = []
   ok = 0
   for h, (good, data) in res:
       if not good:
           rows.append([h, "-", "-", "-", "-", "UNREACHABLE", data[:28]])
           continue
       skew = int(data.get("CLOCK", "0") or 0) - local_clock
       tmpfree = data.get("TMPFREE", "?")
       td = data.get("TCPDUMP", "missing")
       ifaces = data.get("IFACES", "")
       has_if = args.iface in [i for i in ifaces.split(",") if i]
       note = []
       st = "OK"
       if td == "missing":
           st = "FAIL"
           note.append("no tcpdump")
       if not has_if:
           st = "FAIL"
           note.append("no %s" % args.iface)
       try:
           free_mb = int(tmpfree) / 1024.0
       except ValueError:
           free_mb = -1.0
       if 0 <= free_mb < 5:
           st = "FAIL"
           note.append("/tmp %.1fMB" % free_mb)
       if abs(skew) > 5 and st == "OK":
           st = "WARN"
           note.append("clock %+ds" % skew)
       rows.append([h, "yes" if td != "missing" else "no",
                    "yes" if has_if else "no",
                    "%.1f" % free_mb if free_mb >= 0 else "?",
                    "%+d" % skew, st, ",".join(note)])
       if st != "FAIL":
           ok += 1
   print(table(["BRIDGE", "TCPDUMP", "IFACE", "/tmp MB", "SKEW(s)",
                "STATUS", "NOTE"], rows,
               ["l", "l", "l", "r", "r", "l", "l"]))
   print()
   print("  %d/%d bridges ready" % (ok, len(hosts)))
   big = [r for r in rows if r[4] not in ("-",) and abs(int(r[4])) > 5]
   if big:
       print("  %d bridge(s) more than 5s off this server's clock - merged "
             "intervals will be distorted" % len(big))
   return 0 if ok else 1

def act_start(hosts, args):
   cmd = build_start_cmd(args.iface, args.duration, args.filter,
                         args.snaplen, args.maxfiles)
   def one(h):
       rc, out, err = ssh(h, args.user, args.password, cmd,
                          timeout=args.timeout)
       if rc != 0:
           return (False, err or "ssh rc=%d" % rc)
       pid = out.strip().splitlines()[-1] if out.strip() else "NOPID"
       if pid == "NOPID" or not pid.isdigit():
           return (False, "tcpdump did not start")
       return (True, pid)
   res = parallel(hosts, one, args.workers)
   rows = [[h, d if good else "-", "STARTED" if good else "FAIL",
            "" if good else d[:36]] for h, (good, d) in res]
   print(table(["BRIDGE", "PID", "STATUS", "NOTE"], rows,
               ["l", "r", "l", "l"]))
   started = sum(1 for _, (g, _) in res if g)
   print()
   print("  %d/%d started, capturing %ds on %s, filter: %s"
         % (started, len(hosts), args.duration, args.iface, args.filter))
   return 0 if started else 1

def act_status(hosts, args):
   def one(h):
       rc, out, err = ssh(h, args.user, args.password, STATUS_CMD,
                          timeout=args.timeout)
       if rc != 0:
           return (False, err or "ssh rc=%d" % rc)
       return (True, parse_kv(out))
   res = parallel(hosts, one, args.workers)
   rows = []
   running = 0
   for h, (good, d) in res:
       if not good:
           rows.append([h, "-", "-", "UNREACHABLE"])
           continue
       size = d.get("SIZE", "") or "0"
       try:
           kb = int(size) / 1024.0
       except ValueError:
           kb = 0.0
       run = d.get("RUN") == "yes"
       if run:
           running += 1
       st = "capturing" if run else ("done" if kb > 0 else "NO FILE")
       rows.append([h, "yes" if run else "no", "%.1f" % kb, st])
   print(table(["BRIDGE", "RUNNING", "SIZE KB", "STATE"], rows,
               ["l", "l", "r", "l"]))
   print()
   print("  %d/%d still capturing" % (running, len(hosts)))
   return 0

def act_stop(hosts, args):
   def one(h):
       rc, out, err = ssh(h, args.user, args.password, STOP_CMD,
                          timeout=args.timeout)
       if rc != 0:
           return (False, err or "ssh rc=%d" % rc)
       return (True, out.strip())
   res = parallel(hosts, one, args.workers)
   rows = [[h, d if good else d[:40]] for h, (good, d) in res]
   print(table(["BRIDGE", "RESULT"], rows, ["l", "l"]))
   return 0

def act_collect(hosts, args):
   outdir = os.path.expanduser(args.outdir)
   if not os.path.isdir(outdir):
       os.makedirs(outdir)
   def one(h):
       # remote size first, so a short read can be detected rather than
       # written out as a silently truncated pcap
       rc, out, err = ssh(h, args.user, args.password, SIZE_CMD,
                          timeout=args.timeout)
       remote_size = 0
       if rc == 0:
           try:
               remote_size = int(parse_kv(out).get("SIZE", "0") or 0)
           except ValueError:
               remote_size = 0
       if rc == 0 and remote_size == 0:
           return (False, 0, 0, "no pcap on bridge")
       cmd = ("cat %s" % REMOTE_PCAP if args.no_compress
              else "gzip -c %s 2>/dev/null || cat %s"
                   % (REMOTE_PCAP, REMOTE_PCAP))
       rc, data, err = ssh(h, args.user, args.password, cmd,
                           timeout=args.collect_timeout, binary_out=True)
       if rc != 0:
           return (False, 0, remote_size, err or "ssh rc=%d" % rc)
       if not data:
           return (False, 0, remote_size, "empty or missing pcap")
       wire = len(data)
       if data[:2] == b"\x1f\x8b":              # bridge had gzip
           try:
               data = gzip.decompress(data)
           except Exception as e:                # noqa: BLE001
               return (False, wire, remote_size, "bad gzip: %s" % e)
       if len(data) < 24 or data[:4] not in (
               b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
               b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",
               b"\x0a\x0d\x0d\x0a"):
           return (False, wire, remote_size, "not a pcap (bad magic)")
       if remote_size and len(data) != remote_size:
           return (False, wire, remote_size,
                   "size mismatch: got %d of %d" % (len(data), remote_size))
       path = os.path.join(outdir, "%s_zea-test.pcap" % h)
       with open(path, "wb") as fh:
           fh.write(data)
       return (True, wire, len(data), path)
   res = parallel(hosts, one, args.workers)
   rows = []
   got = 0
   total = 0
   wire_total = 0
   for h, r in res:
       good, wire, size, note = r
       if good:
           got += 1
           total += size
           wire_total += wire
           rows.append([h, "%.1f" % (size / 1024.0),
                        "%.1f" % (wire / 1024.0), "OK", ""])
       else:
           rows.append([h, "%.1f" % (size / 1024.0),
                        "%.1f" % (wire / 1024.0), "FAIL", note[:40]])
   shown = rows if args.list else [r for r in rows if r[3] != "OK"]
   if shown:
       print(table(["BRIDGE", "SIZE KB", "WIRE KB", "STATUS", "NOTE"],
                   shown, ["l", "r", "r", "l", "l"]))
       print()
   saved = ""
   if wire_total and total and wire_total < total:
       saved = "   (%.0f%% saved by gzip on the wire)" % (
           100.0 * (1 - wire_total / float(total)))
   print("  %d/%d collected, %.1f MB total -> %s%s"
         % (got, len(hosts), total / 1048576.0, outdir, saved))
   if not args.list and got == len(hosts):
       print("  (--list for the full table)")
   if got:
       print()
       print("  next: zea_merge.py %s/*_zea-test.pcap --coverage" % outdir)
   return 0 if got else 1

def act_clean(hosts, args):
   def one(h):
       rc, out, err = ssh(h, args.user, args.password, CLEAN_CMD,
                          timeout=args.timeout)
       return (rc == 0, out.strip() or err)
   res = parallel(hosts, one, args.workers)
   rows = [[h, d if good else d[:40]] for h, (good, d) in res]
   print(table(["BRIDGE", "RESULT"], rows, ["l", "l"]))
   return 0

def act_run(hosts, args):
   print(section("preflight"))
   act_preflight(hosts, args)
   print()
   print(section("start"))
   rc = act_start(hosts, args)
   if rc != 0:
       sys.stderr.write("[FATAL] nothing started, aborting\n")
       return 1
   print()
   wait = args.duration + args.grace
   print(section("capturing"))
   t0 = time.time()
   while True:
       left = wait - (time.time() - t0)
       if left <= 0:
           break
       sys.stdout.write("\r  %d seconds remaining   " % int(left))
       sys.stdout.flush()
       time.sleep(min(5, left))
   sys.stdout.write("\r" + " " * 40 + "\r")
   print("  capture window complete")
   print()
   print(section("collect"))
   return act_collect(hosts, args)

# ---------------------------------------------------------------------------
# output helpers
# ---------------------------------------------------------------------------
RULE_W = 78

def section(title):
   head = "---- %s " % title.upper()
   return head + "-" * max(0, RULE_W - len(head))

def table(headers, rows, aligns=None, indent=2):
   if not rows:
       return " " * indent + "(none)"
   ncol = len(headers)
   aligns = aligns or ["l"] * ncol
   widths = [len(h) for h in headers]
   for r in rows:
       for i in range(ncol):
           widths[i] = max(widths[i], len(str(r[i])))
   def line(cells):
       out = []
       for i, c in enumerate(cells):
           c = str(c)
           out.append(c.rjust(widths[i]) if aligns[i] == "r"
                      else c.ljust(widths[i]))
       return " " * indent + "  ".join(out).rstrip()
   lines = [line(headers), " " * indent + "  ".join("-" * w for w in widths)]
   for r in rows:
       lines.append(line(r))
   return "\n".join(lines)

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
   ap = argparse.ArgumentParser(
       description="Start and collect ZEA captures across bridge units.")
   ap.add_argument("action",
                   choices=["discover", "clock", "preflight", "start",
                            "status", "stop", "collect", "clean", "run"])
   ap.add_argument("--hosts", metavar="FILE",
                   help="file of bridge IPs, one per line")
   ap.add_argument("--host", action="append", metavar="IP",
                   help="single bridge IP (repeatable)")
   ap.add_argument("--subnet", action="append", metavar="CIDR",
                   help="range to sweep for the discover action, e.g. "
                        "172.16.41.0/24 or 172.16.41.10-60 (repeatable)")
   ap.add_argument("--leases", metavar="FILE", nargs="?",
                   const="/var/lib/misc/dnsmasq.leases",
                   help="seed candidates from a dnsmasq lease file "
                        "(default /var/lib/misc/dnsmasq.leases)")
   ap.add_argument("--name-filter", default="Minetec-BR", metavar="STR",
                   help="lease hostname must contain this (default "
                        "Minetec-BR; pass '' to disable)")
   ap.add_argument("--mac-prefix", default="", metavar="STR",
                   help="lease MAC must start with this, e.g. c4:93:00")
   ap.add_argument("--clock-warn", type=float, default=1.0, metavar="S",
                   help="offset above this is WARN, 10x is FAIL "
                        "(default 1.0)")
   ap.add_argument("--set-clock", action="store_true",
                   help="after reporting, push this server's UTC time to "
                        "every bridge (writes to the device)")
   ap.add_argument("--set-lead", type=float, default=0.3, metavar="S",
                   help="seconds added when setting, to cover ssh latency")
   ap.add_argument("--list", action="store_true",
                   help="print every bridge found; by default discover "
                        "shows only problems and a count")
   ap.add_argument("--verify", action="store_true",
                   help="after reading leases, ping and ssh-probe each "
                        "bridge instead of trusting the lease")
   ap.add_argument("--save-hosts", metavar="FILE",
                   help="write discovered bridges to this file")
   ap.add_argument("--user", default=DEFAULT_USER)
   ap.add_argument("--password", default=os.environ.get(
       "ZEA_BRIDGE_PASS", DEFAULT_PASS),
       help="bridge password (or set ZEA_BRIDGE_PASS)")
   ap.add_argument("--iface", default="wlan0")
   ap.add_argument("--duration", type=int, default=300,
                   help="capture length in seconds (default 300)")
   ap.add_argument("--filter", default=DEFAULT_FILTER,
                   help="BPF filter; default limits to ZEA ethertype so "
                        "/tmp does not fill. Pass '' for everything.")
   ap.add_argument("--snaplen", type=int, default=0,
                   help="tcpdump -s value; 0 = full frame (default)")
   ap.add_argument("--maxfiles", type=int, default=1,
                   help="reserved for -W rotation")
   ap.add_argument("--outdir", default="/home/minetec/zea-pcaps",
                   help="local directory for collected pcaps")
   ap.add_argument("--no-compress", action="store_true",
                   help="do not gzip on the bridge before transfer")
   ap.add_argument("--workers", type=int, default=16,
                   help="parallel ssh sessions (default 16)")
   ap.add_argument("--timeout", type=int, default=30)
   ap.add_argument("--collect-timeout", type=int, default=180)
   ap.add_argument("--grace", type=int, default=10,
                   help="extra seconds to wait after duration before "
                        "collecting (default 10)")
   args = ap.parse_args()
   for tool in ("sshpass", "ssh"):
       if subprocess.call(["sh", "-c", "command -v %s >/dev/null" % tool]):
           sys.stderr.write(
               "[FATAL] %s not found. On MineOffice: apt-get install "
               "sshpass\n" % tool)
           return 2
   hosts = load_hosts(args)
   if not hosts and not (args.action == "discover" and args.leases):
       if args.action == "discover":
           sys.stderr.write("[ERROR] discover needs --subnet or --leases\n")
       else:
           sys.stderr.write(
               "[ERROR] no hosts. Use --hosts FILE or --host IP, or run "
               "'discover --subnet 172.16.41.0/24 --save-hosts bridges.txt' "
               "first\n")
       return 2
   fn = {
       "discover": act_discover,
       "clock": act_clock,
       "preflight": act_preflight,
       "start": act_start,
       "status": act_status,
       "stop": act_stop,
       "collect": act_collect,
       "clean": act_clean,
       "run": act_run,
   }[args.action]
   return fn(hosts, args)

if __name__ == "__main__":
   try:
       sys.exit(main())
   except KeyboardInterrupt:
       os._exit(0)