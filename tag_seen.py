#!/usr/bin/env python3

# Author: Nguyen Tran

"""

tag_seen.py - which tag was first seen, when, and by which bridge.

Merges every capture into one timeline per tag, so "first seen" is the first

time ANY bridge heard it. Bridge name comes from the IP in the filename.

    ./tag_seen.py ~/zea-pcaps/*.pcap

    ./tag_seen.py ~/zea-pcaps/*.pcap --tag UGM205

"""

import argparse

import glob

import os

import re

import struct

import sys

from datetime import datetime, timedelta

ET = 0x4D54

JSON = re.compile(rb'"MMC_ID"\s*:\s*"([^"]{1,32})"[^{}]{0,80}"EVAC"\s*:\s*"([^"]{1,32})"')

IP = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")


def frames(path):

    fh = open(path, "rb")

    try:

        hdr = fh.read(24)

        if len(hdr) < 24:

            return

        magic = struct.unpack("<I", hdr[:4])[0]

        if magic in (0xA1B2C3D4, 0xA1B23C4D):

            end = "<"

        elif struct.unpack(">I", hdr[:4])[0] in (0xA1B2C3D4, 0xA1B23C4D):

            end = ">"

            magic = struct.unpack(">I", hdr[:4])[0]

        else:

            sys.stderr.write("[WARN] %s: not a classic pcap, skipped\n" % path)

            return

        nano = magic == 0xA1B23C4D

        while True:

            ph = fh.read(16)

            if len(ph) < 16:

                return

            sec, frac, incl, _orig = struct.unpack(end + "IIII", ph)

            data = fh.read(incl)

            if len(data) < incl:

                return

            yield sec + (frac / 1e9 if nano else frac / 1e6), data

    finally:

        fh.close()


def decode(data, any_et):

    if not any_et:

        if len(data) < 14:

            return None

        if struct.unpack(">H", data[12:14])[0] != ET:

            return None

    m = JSON.search(data)

    if not m:

        return None

    try:

        return m.group(1).decode("ascii"), m.group(2).decode("ascii")

    except UnicodeDecodeError:

        return None


def label(path):

    base = os.path.basename(path)

    m = IP.search(base)

    if m:

        return m.group(1)

    return base.rsplit(".", 1)[0]


def when(epoch, tz):

    d = datetime(1970, 1, 1) + timedelta(seconds=epoch + tz * 3600.0)

    return d.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def detail(e, t0, end):

    """Per-bridge sightings around the window, as offsets from T0.

    For a tag heard during the window this shows which bridges had it and in

    what state - that is what makes a FAIL a real one. For a tag that went

    quiet it shows the silent gap either side, which is the coverage hole.

    """

    hits = sorted(e["hits"])

    inwin = [h for h in hits if t0 <= h[0] <= end]

    if inwin:

        per = {}

        for ts, st, b in inwin:

            d = per.setdefault(b, {"first": ts, "last": ts, "n": 0,

                                   "states": set()})

            d["last"] = ts

            d["n"] += 1

            d["states"].add(st)

        for b in sorted(per, key=lambda x: per[x]["first"]):

            d = per[b]

            print("       %-15s  %+6.1fs .. %+6.1fs  %3d msg  %s"

                  % (b, d["first"] - t0, d["last"] - t0, d["n"],

                     ",".join(sorted(d["states"]))))

    else:

        before = [h for h in hits if h[0] < t0]

        after = [h for h in hits if h[0] > end]

        if before:

            ts, st, b = before[-1]

            print("       last before window  %+6.1fs  %-15s  %s"

                  % (ts - t0, b, st))

        else:

            print("       never heard before the window")

        if after:

            ts, st, b = after[0]

            print("       next after window   %+6.1fs  %-15s  %s"

                  % (ts - t0, b, st))

        else:

            print("       never heard again")

        if before and after:

            print("       silent gap          %6.1fs"

                  % (after[0][0] - before[-1][0]))


def judge(seen, order, args):

    """Did each tag reach ACTIVE_ON in time, and was it even reachable?

    The reference is T0, when the alarm fired - not when the tag was first

    seen. A tag can be first seen minutes earlier and still activate on time.

    What separates a real failure from a coverage gap is whether the tag was

    being heard DURING the window: heard-and-still-inactive is a failure,

    not-heard-at-all means it was out of range and cannot be judged.

    """

    if args.t0:

        t0 = None

        for f in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%H:%M:%S"):

            try:

                d = datetime.strptime(args.t0, f)

                t0 = (d - datetime(1970, 1, 1)).total_seconds()

                t0 -= args.tz * 3600.0

                break

            except ValueError:

                continue

        if t0 is None:

            sys.stderr.write("[ERROR] cannot parse --t0\n")

            return

        src = "supplied"

    else:

        acts = [e["act_ts"] for e in seen.values() if e["act_ts"] is not None]

        if not acts:

            sys.stderr.write("[ERROR] no ACTIVE_ON anywhere; pass --t0\n")

            return

        t0 = min(acts)

        src = "earliest ACTIVE_ON"

    end = t0 + args.window

    print()

    print("T0 %s (%s)   deadline %s (+%.0fs)"

          % (when(t0, args.tz), src, when(end, args.tz), args.window))

    print()

    rows = []

    for t in order:

        e = seen[t]

        lat = None if e["act_ts"] is None else e["act_ts"] - t0

        # was the tag heard at all inside the window, and how?

        inwin = [h for h in e["hits"] if t0 <= h[0] <= end]

        if lat is not None and lat <= args.window:

            v, note = "OK", ""

        elif not inwin:

            gap = "never" if lat is None else "%.0fs" % lat

            v = "NO COVERAGE"

            note = "not heard during the window (activated %s)" % gap

        elif lat is None:

            v = "FAIL"

            note = "heard %d time(s) in window, never activated" % len(inwin)

        else:

            v = "FAIL"

            note = ("heard %d time(s) in window still inactive, "

                    "activated at +%.1fs" % (len(inwin), lat))

        rows.append((t, "-" if lat is None else "%.1f" % lat, v, note, e))

    bad = [r for r in rows if r[2] != "OK"]

    if bad:

        w = max(len(r[0]) for r in bad)

        print("%-*s  %8s  %-11s  %s" % (w, "TAG", "LATENCY", "VERDICT", "NOTE"))

        print("%s  %s  %s  %s" % ("-" * w, "-" * 8, "-" * 11, "-" * 40))

        for t, lat, v, note, e in bad:

            print("%-*s  %8s  %-11s  %s" % (w, t, lat, v, note))

            if not args.no_detail:

                detail(e, t0, end)

        print()

    ok = sum(1 for r in rows if r[2] == "OK")

    fail = sum(1 for r in rows if r[2] == "FAIL")

    nocov = sum(1 for r in rows if r[2] == "NO COVERAGE")

    print("%d within %.0fs, %d failed, %d had no coverage in the window"

          % (ok, args.window, fail, nocov))

    if nocov:

        print("NO COVERAGE tags were not heard by any bridge while the alarm "

              "was live, so the window cannot be applied to them")


def main():

    ap = argparse.ArgumentParser(description="First sighting of each tag.")

    ap.add_argument("captures", nargs="+")

    ap.add_argument("--tz", type=float, default=9.0,

                    help="hours to add to UTC (default 9)")

    ap.add_argument("--tag", action="append",

                    help="only these tags; wildcards ok, repeatable")

    ap.add_argument("--window", type=float, metavar="S",

                    help="also judge each tag: it must reach ACTIVE_ON "

                         "within S seconds of T0")

    ap.add_argument("--t0", metavar="TIME",

                    help="alarm start 'YYYY-MM-DD HH:MM:SS' in display tz; "

                         "default is the earliest ACTIVE_ON of any tag")

    ap.add_argument("--no-detail", action="store_true",

                    help="with --window, suppress the per-bridge sightings "

                         "printed under each failing tag")

    ap.add_argument("--any-ethertype", action="store_true")

    ap.add_argument("--csv")

    args = ap.parse_args()

    paths = []

    for pat in args.captures:

        hits = sorted(glob.glob(pat))

        paths.extend(hits if hits else [pat])

    paths = [p for p in paths if os.path.isfile(p)]

    if not paths:

        sys.stderr.write("[ERROR] no capture files found\n")

        return 2

    seen = {}

    for path in paths:

        b = label(path)

        for ts, data in frames(path):

            got = decode(data, args.any_ethertype)

            if not got:

                continue

            tag, state = got

            e = seen.get(tag)

            if e is None:

                e = {"ts": ts, "by": b, "brd": set([b]), "n": 0,

                     "act": False, "act_ts": None, "hits": []}

                seen[tag] = e

            e["brd"].add(b)

            e["n"] += 1

            e["hits"].append((ts, state, b))

            if state == "ACTIVE_ON":

                e["act"] = True

                if e["act_ts"] is None or ts < e["act_ts"]:

                    e["act_ts"] = ts

            if ts < e["ts"]:

                e["ts"] = ts

                e["by"] = b

    if args.tag:

        import fnmatch

        pats = [t.upper() for t in args.tag]

        seen = {t: v for t, v in seen.items()

                if any(fnmatch.fnmatch(t.upper(), p) for p in pats)}

    if not seen:

        sys.stderr.write("[ERROR] no tags decoded. If the captures have no "

                         "link header try --any-ethertype\n")

        return 1

    order = sorted(seen, key=lambda t: seen[t]["ts"])

    w = max(len(t) for t in order)

    print("%-*s  %-23s  %-15s  %4s  %6s  %s"

          % (w, "TAG", "FIRST SEEN", "FIRST BY", "BRDG", "MSGS", "ACTIVE"))

    print("%s  %s  %s  %s  %s  %s"

          % ("-" * w, "-" * 23, "-" * 15, "-" * 4, "-" * 6, "-" * 6))

    for t in order:

        e = seen[t]

        print("%-*s  %-23s  %-15s  %4d  %6d  %s"

              % (w, t, when(e["ts"], args.tz), e["by"], len(e["brd"]),

                 e["n"], "yes" if e["act"] else "no"))

    first = seen[order[0]]

    print()

    print("%d tag(s) over %d capture(s)" % (len(order), len(paths)))

    print("earliest: %s at %s by %s"

          % (order[0], when(first["ts"], args.tz), first["by"]))

    if args.window:

        judge(seen, order, args)

    if args.csv:

        with open(args.csv, "w") as fh:

            fh.write("tag,first_seen,first_by,bridges,messages,went_active\n")

            for t in order:

                e = seen[t]

                fh.write("%s,%s,%s,%d,%d,%s\n"

                         % (t, when(e["ts"], args.tz), e["by"],

                            len(e["brd"]), e["n"],

                            "yes" if e["act"] else "no"))

        sys.stderr.write("[OK] wrote %s\n" % args.csv)

    return 0


if __name__ == "__main__":

    sys.exit(main())
 