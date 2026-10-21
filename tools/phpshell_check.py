#!/usr/bin/env python3
"""phpshell_check.py — PHP2Shell (CVE-2026-109618 / CVE-2026-109619) exposure checker.

Answers one question per host: *is this runtime exposed to the PHP2Shell bug
class, and what exactly should be done?* Built to be run across a fleet of sites
you are responsible for.

Design rules (deliberate, do not "improve" them away):

  * Sequential only. No threads, no loops, no retries. One host at a time.
  * Stage 1 (default) is passive: two requests, ~2 KB.
  * Stage 2 is a body-cap probe that sends *no body at all*: it declares a
    Content-Length and waits for the edge to accept or reject it
    (`Expect: 100-continue`). Costs a few hundred bytes.
  * Stage 3 (opt-in, `--with-producer`) sends ONE oversized multipart request to
    see whether request startup can be made to die. This is a memory-pressure
    probe against a production host. It requires an explicit authorisation
    statement on the command line, and it never repeats.
  * No exploitation. Nothing here crafts a heap layout, chains requests, or
    attempts code execution. It is an exposure classifier, not a weapon.

Verdicts
  PATCH_NOW            vulnerable PHP release answering directly
  PATCH_NOW_TOO        vulnerable release, but only reachable behind a redirect we followed
  EXPOSED_EDGE         version hidden, but the edge will accept an arm-sized body
  LIKELY_SAFE_CAP      version hidden, but the body cap is below the arm size
  SAFE_PATCHED         release is >= the first fixed release for its branch
  NOT_PHP / UNKNOWN

Usage
  python3 phpshell_check.py --targets sites.txt               # passive only
  python3 phpshell_check.py --targets sites.txt --cap        # + body-cap probe
  python3 phpshell_check.py --targets sites.txt --with-producer \\
      --authorized-owner "Acme Ltd (signed SOW 2026-10)" --json out.json

sites.txt: one URL per line, `#` comments allowed:
  https://www.example.com/
  https://shop.example.com/      # owner: Acme, authorisation: email 2026-10-21
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.parse

# First fixed release per branch, per php.net / GHSA-6wmf-4rv5-p3rp.
FIXED = {"8.2": (35, "8.2.35"), "8.3": (36, "8.3.36"),
         "8.4": (27, "8.4.27"), "8.5": (12, "8.5.12")}
EOL = {"8.2": "2026-12-31"}
ARM_SIZE = 70_000_000          # inside the 68-88 MB orphan band at memory_limit=256M
UA = "phpshell-check/1.0 (authorised exposure check; single request; no exploit)"


# --------------------------------------------------------------------------- http
def _connect(url: str, timeout: float):
    u = urllib.parse.urlsplit(url)
    host = u.hostname
    tls = u.scheme == "https"
    port = u.port or (443 if tls else 80)
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE          # we classify, we don't trust
        sock = socket.create_connection((host, port), timeout=timeout)
        sock = ctx.wrap_socket(sock, server_hostname=host)
    else:
        sock = socket.create_connection((host, port), timeout=timeout)
    return sock, host, port, tls


def request(url: str, method="GET", body: bytes | None = None,
            headers: dict | None = None, timeout: float = 20.0,
            max_body: int = 400_000) -> dict:
    """One request, no redirect following, body truncated. Returns a dict."""
    u = urllib.parse.urlsplit(url)
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    hdrs = {"Host": u.netloc, "User-Agent": UA, "Accept": "*/*",
            "Connection": "close"}
    hdrs.update(headers or {})
    if body is not None:
        hdrs["Content-Length"] = str(len(body))
    out = {"url": url, "status": None, "headers": {}, "body": b"", "error": None,
           "ms": 0, "truncated": False}
    t0 = time.time()
    try:
        sock, host, port, tls = _connect(url, timeout)
        try:
            head = f"{method} {path} HTTP/1.1\r\n" + "".join(
                f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
            sock.sendall(head.encode() + (body or b""))
            raw = b""
            while b"\r\n\r\n" not in raw:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                raw += chunk
            hpart, _, rest = raw.partition(b"\r\n\r\n")
            lines = hpart.decode("iso-8859-1", "replace").split("\r\n")
            m = re.match(r"HTTP/\d\.\d (\d{3})", lines[0] or "")
            out["status"] = int(m.group(1)) if m else None
            for ln in lines[1:]:
                if ":" in ln:
                    k, v = ln.split(":", 1)
                    out["headers"][k.strip().lower()] = v.strip()
            data = rest
            while len(data) < max_body:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
            if len(data) > max_body:
                data, out["truncated"] = data[:max_body], True
            out["body"] = data
        finally:
            sock.close()
    except Exception as exc:                      # noqa: BLE001 - report, never raise
        out["error"] = f"{type(exc).__name__}: {exc}"
    out["ms"] = int((time.time() - t0) * 1000)
    return out


# ------------------------------------------------------------------- fingerprint
def php_version(headers: dict) -> str | None:
    xp = headers.get("x-powered-by", "")
    m = re.search(r"PHP/(\d+\.\d+\.\d+)", xp, re.I)
    return m.group(1) if m else None


def version_verdict(ver: str) -> tuple[str, str]:
    major_minor = ".".join(ver.split(".")[:2])
    patch = int(ver.split(".")[2])
    if major_minor not in FIXED:
        return "UNKNOWN", f"branch {major_minor} not covered by this advisory"
    fixed_patch, fixed_name = FIXED[major_minor]
    if patch >= fixed_patch:
        return "SAFE_PATCHED", f"{ver} >= {fixed_name}"
    return "PATCH_NOW", f"{ver} < {fixed_name}"


def memory_limit_from(body: bytes) -> int | None:
    """A display_errors=On host tells us its limit in the fatal text."""
    m = re.search(rb"Allowed memory size of (\d+) bytes exhausted", body)
    return int(m.group(1)) if m else None


def cap_probe(url: str, size: int, timeout: float = 12.0) -> str:
    """Declare a Content-Length of `size` and send no body.

    `100 Continue` / silence  -> the edge will let `size` through
    `413`                     -> the edge refuses `size`
    anything else             -> the server answered without reading the body
    """
    u = urllib.parse.urlsplit(url)
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    head = (f"POST {path} HTTP/1.1\r\nHost: {u.netloc}\r\nUser-Agent: {UA}\r\n"
            f"Content-Type: multipart/form-data; boundary=probe\r\n"
            f"Content-Length: {size}\r\nExpect: 100-continue\r\n"
            f"Connection: close\r\n\r\n")
    try:
        sock, *_ = _connect(url, timeout)
        try:
            sock.sendall(head.encode())
            sock.settimeout(4.0)
            try:
                raw = sock.recv(4096)
            except socket.timeout:
                return "accepted"                 # waiting for the body
            if not raw:
                return "closed"
            if b" 100 " in raw.split(b"\r\n")[0] or raw.startswith(b"HTTP/1.1 100"):
                return "accepted"
            m = re.match(rb"HTTP/\d\.\d (\d{3})", raw)
            code = int(m.group(1)) if m else 0
            if code in (413, 414, 431):
                return "refused"
            return f"answered:{code}"
        finally:
            sock.close()
    except Exception as exc:                      # noqa: BLE001
        return f"error:{type(exc).__name__}"


def measure_cap(url: str, verbose=print) -> dict:
    """Ladder probe. Returns {'cap': bytes|None, 'notes': [...]}."""
    ladder = [1, 2, 8, 32, 64, 96, 128, 200, 256]
    ok, notes, refused_at = 0, [], None
    for mb in ladder:
        size = mb * 1024 * 1024
        r = cap_probe(url, size)
        verbose(f"      cap {mb:>4}MB -> {r}")
        notes.append(f"{mb}MB:{r}")
        if r == "refused":
            refused_at = size
            break
        if r.startswith("answered:"):
            notes.append(f"server answered without body at {mb}MB")
            break
        ok = size
    return {"cap": refused_at or (ok if ok else None),
            "refused_at": refused_at, "last_accepted": ok, "notes": notes}


# ----------------------------------------------------------------------- probes
def multipart(field: str, filename: str, size: int, boundary: str) -> bytes:
    return (f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
            f"p\r\n--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n").encode() + \
        (b"A" * size) + f"\r\n--{boundary}--\r\n".encode()


def producer_probe(url: str, arm: int, timeout: float = 180.0, verbose=print) -> dict:
    """Baseline small upload, then ONE arm-sized upload. Look for 'startup death'."""
    boundary = "pc" + os.urandom(6).hex()
    base = request(url, "POST", multipart("f", "small.bin", 64, boundary),
                   {"Content-Type": f"multipart/form-data; boundary={boundary}"},
                   timeout=timeout)
    verbose(f"      baseline POST      -> {base['status']} {len(base['body'])}B "
            f"({base['ms']} ms)")
    boundary = "pc" + os.urandom(6).hex()
    arm_body = multipart("f", "A" * arm, 64, boundary)
    big = request(url, "POST", arm_body,
                  {"Content-Type": f"multipart/form-data; boundary={boundary}"},
                  timeout=timeout, max_body=200_000)
    verbose(f"      arm POST {arm/1e6:.0f}MB fn -> {big['status']} {len(big['body'])}B "
            f"({big['ms']} ms) err={big['error']}")
    mem = memory_limit_from(big["body"]) or memory_limit_from(base["body"])
    snippet = big["body"][:200].decode("iso-8859-1", "replace").strip()
    died = False
    if big["error"] and ("Reset" in big["error"] or "timed out" in big["error"]):
        died = True
    if mem:
        died = True                       # fatal text == request startup died
    if base["status"] and big["status"] and base["status"] != big["status"]:
        died = died or (big["status"] in (200, 204) and len(big["body"]) < 64)
    if (big["status"] == base["status"] and len(base["body"]) > 512
            and len(big["body"]) < 512):
        died = True                       # the app answer vanished
    if (big["status"] or 0) in (500, 502, 503, 504) and (base["status"] or 0) < 500:
        died = True                       # the worker died and the proxy said so
    return {"baseline": {k: base[k] for k in ("status", "ms", "error")},
            "arm": {k: big[k] for k in ("status", "ms", "error")},
            "arm_bytes_body": len(big["body"]), "startup_died": died,
            "memory_limit": mem, "arm_body_snippet": snippet}


# Cookies and headers that only a PHP runtime (or a framework running on it)
# emits. `expose_php=Off` hides x-powered-by, these survive.
PHP_COOKIES = re.compile(
    r"\b(PHPSESSID|PHPSESS|php_session|laravel_session|XSRF-TOKEN|"
    r"private_content_version|X-Magento-Vary|adminhtml|form_key|"
    r"wp-settings|wordpress_|wp_|SSESS|SimpleSAML|CAKEPHP|cakephp|"
    r"symfony|joomla|drupal)", re.I)
PHP_HEADERS = re.compile(r"^(x-magento-|x-litespeed-|x-debug-token|x-laravel)", re.I)
PHP_SERVER = re.compile(r"(PHP|LiteSpeed)", re.I)


def php_markers(headers: dict) -> list[str]:
    """Every PHP fingerprint visible in one response."""
    hits = []
    if php_version(headers):
        hits.append("x-powered-by")
    cookies = headers.get("set-cookie", "") + headers.get("cookie", "")
    for m in PHP_COOKIES.finditer(cookies):
        hits.append(f"cookie:{m.group(0)}")
    for k in headers:
        if PHP_HEADERS.match(k):
            hits.append(f"header:{k}")
    if PHP_SERVER.search(headers.get("server", "")):
        hits.append(f"server:{headers['server']}")
    return sorted(set(hits))


def detect_session(headers: dict) -> bool:
    return bool(re.search(r"\b(PHPSESSID|phpsession)", headers.get("set-cookie", ""),
                          re.I))


def php_extension_probe(url: str, timeout: float = 20.0) -> dict:
    """Ask for `/x.php` and `/x` and compare.

    A static file server answers both alike. A PHP host usually hands `.php` to
    the interpreter, which returns its own 404, its own content type, or a
    different status. Two requests, no payload.
    """
    base = urllib.parse.urlsplit(url)
    seed = os.urandom(4).hex()
    root = f"{base.scheme}://{base.netloc}"
    a = request(f"{root}/__pc_probe_{seed}.php", timeout=timeout, max_body=20_000)
    b = request(f"{root}/__pc_probe_{seed}", timeout=timeout, max_body=20_000)
    same_status = a["status"] == b["status"]
    same_body = a["body"] == b["body"]
    same_ct = (a["headers"].get("content-type") == b["headers"].get("content-type"))
    differs = not (same_status and same_body and same_ct)
    return {"php_path": a["status"], "plain_path": b["status"],
            "differs": differs,
            "content_type": a["headers"].get("content-type"),
            "verdict": "php-handler" if differs and a["status"] not in (None, 0)
                       else "indistinct"}


# ------------------------------------------------------------------------ report
def analyse(url: str, cap_ceil: int, with_producer: bool, verbose=print) -> dict:
    r = {"url": url, "verdict": "UNKNOWN", "why": "", "facts": {}, "probe": None}
    res = request(url, timeout=25)
    facts = r["facts"]
    facts["status"] = res["status"]
    facts["server"] = res["headers"].get("server")
    facts["x_powered_by"] = res["headers"].get("x-powered-by")
    facts["error"] = res["error"]

    if res["error"] and res["status"] is None:
        r["verdict"] = "UNREACHABLE"
        r["why"] = res["error"]
        return r

    # If the base request redirected, follow once: the app host is the real target.
    if res["status"] in (301, 302, 303, 307, 308):
        loc = res["headers"].get("location", "")
        nxt = urllib.parse.urljoin(url, loc)
        verbose(f"      redirect -> {nxt}")
        facts["redirect_to"] = nxt
        res2 = request(nxt, timeout=25)
        facts["followed_status"] = res2["status"]
        facts["followed_server"] = res2["headers"].get("server")
        facts["followed_x_powered_by"] = res2["headers"].get("x-powered-by")
        if not facts["server"]:
            facts["server"] = facts["followed_server"]
        facts["php_version_followed"] = None
        if resp_ver := php_version(res2["headers"]):
            facts["php_version"] = resp_ver
        facts["markers_followed"] = php_markers(res2["headers"])
        res = res2

    ver = php_version(res["headers"]) or facts.get("php_version")
    facts["php_version"] = ver
    facts["php_session_cookie"] = detect_session(res["headers"])
    facts["php_markers"] = sorted(set(php_markers(res["headers"])) |
                                  set(facts.get("markers_followed", [])))

    # x-powered-by is often suppressed. Two more requests settle whether PHP is
    # behind this hostname at all; without it a body-cap number means nothing.
    if not facts["php_markers"]:
        ext = php_extension_probe(url)
        facts["php_extension_probe"] = ext
        if ext["verdict"] == "php-handler":
            facts["php_markers"].append("extension-handler")
    php_seen = bool(facts["php_markers"])
    facts["php_present"] = php_seen

    if ver:
        verdict, why = version_verdict(ver)
        r["verdict"], r["why"] = verdict, why
    elif php_seen:
        r["verdict"] = "PHP_PRESENT_VERSION_HIDDEN"
        r["why"] = ("PHP runtime present (" + ", ".join(facts["php_markers"]) +
                    ") but the release is not disclosed (expose_php=Off)")
    elif res["status"] is None:
        r["verdict"], r["why"] = "UNREACHABLE", "no response"
    else:
        r["verdict"] = "NOT_PHP_DETECTED"
        r["why"] = f"no PHP marker on {url} and .php is not handled differently"

    if cap_ceil and php_seen:
        cap = measure_cap(url, verbose)
        facts["edge_accepts"] = cap
        if cap["cap"] is None:
            r["why"] += "; body limit not established by the edge"
        elif cap["cap"] >= ARM_SIZE:
            if r["verdict"] == "PHP_PRESENT_VERSION_HIDDEN":
                r["verdict"] = "EXPOSED_EDGE"
                r["why"] = (f"edge accepts a {cap['cap']/1e6:.0f}MB declared body, at/above "
                            f"the {ARM_SIZE/1e6:.0f}MB arm size; release undisclosed")
        elif r["verdict"] == "PHP_PRESENT_VERSION_HIDDEN":
            r["verdict"] = "LIKELY_SAFE_CAP"
            r["why"] = (f"edge refuses above {cap['refused_at']:,}B, below the "
                        f"{ARM_SIZE:,}B arm needed for the OOM producer")
    elif cap_ceil and not php_seen:
        facts["edge_accepts"] = {"skipped": "no PHP backend, a body cap here is irrelevant"}

    if with_producer and r["verdict"] not in ("UNREACHABLE", "NOT_PHP_DETECTED"):
        measured = (r["facts"].get("edge_accepts") or {}).get("cap")
        arm = min(ARM_SIZE, int(measured * 0.95)) if measured else ARM_SIZE
        if arm < 8_000_000:
            verbose(f"      producer probe skipped: body cap {arm:,}B is too small to arm")
            r["probe"] = {"skipped": "body cap below 8MB"}
        else:
            r["probe"] = producer_probe(url, arm, verbose=verbose)
            if r["probe"].get("startup_died") and r["verdict"] in (
                    "PHP_PRESENT_VERSION_HIDDEN", "UNKNOWN", "EXPOSED_EDGE"):
                r["verdict"] = "PATCH_NOW"
                r["why"] = ("request startup dies on an oversized upload: the OOM "
                            "producer of CVE-2026-109618 is reachable")
    return r


ACTION = {
    "PATCH_NOW": "Upgrade PHP to the first fixed release for its branch; restart FPM/Apache workers.",
    "SAFE_PATCHED": f"No action for this bug class. Keep the release current. PHP 8.2 is EOL {EOL['8.2']}.",
    "EXPOSED_EDGE": "Version hidden. Identify the runtime before assuming safety; a 70MB body is accepted.",
    "LIKELY_SAFE_CAP": "Edge cap blocks the arm path. Re-check if client_max_body_size is ever raised.",
    "PHP_PRESENT_VERSION_HIDDEN": "PHP present, version hidden. Run with --cap (and --with-producer on staging).",
    "NOT_PHP_DETECTED": "No PHP marker. Verify the real backend hostname before closing.",
    "UNREACHABLE": "Fix reachability (DNS/TLS/firewall) and re-run.",
    "UNKNOWN": "Manual review.",
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--targets", required=True, help="file with one URL per line")
    ap.add_argument("--cap", action="store_true", help="stage 2: body-cap probe (no body sent)")
    ap.add_argument("--with-producer", action="store_true",
                    help="stage 3: one oversized multipart POST per host (memory pressure)")
    ap.add_argument("--authorized-owner", default="",
                    help="who authorised stage 3, e.g. 'Acme Ltd (SOW 2026-10)'. Required.")
    ap.add_argument("--json", default="", help="write machine-readable results here")
    ap.add_argument("--delay", type=float, default=1.5, help="seconds between requests")
    ap.add_argument("--timeout", type=float, default=25.0)
    ap.add_argument("--limit", type=int, default=0, help="only the first N targets")
    a = ap.parse_args()

    if a.with_producer and not a.authorized_owner.strip():
        print("refusing: --with-producer sends an oversized body. Provide "
              "--authorized-owner \"<who signed off>\" so the run is attributable.",
              file=sys.stderr)
        return 2

    targets = []
    for line in open(a.targets, encoding="utf-8"):
        line = line.split("#")[0].strip()
        if line:
            targets.append(line)
    if a.limit:
        targets = targets[:a.limit]
    if not targets:
        print("no targets", file=sys.stderr)
        return 2

    print(f"phpshell_check  targets={len(targets)}  cap={a.cap}  "
          f"producer={a.with_producer}  owner={a.authorized_owner or '-'}")
    if a.with_producer:
        print("note: stage 3 applies memory pressure. One request per host, no retries.")
    print()

    results = []
    for i, url in enumerate(targets, 1):
        print(f"[{i}/{len(targets)}] {url}")
        r = analyse(url, a.cap, a.with_producer)
        print(f"      => {r['verdict']}: {r['why']}")
        print(f"      do: {ACTION.get(r['verdict'], '-')}")
        pr = r.get("probe") or {}
        if pr and not pr.get("skipped"):
            print(f"      probe: startup_died={pr.get('startup_died')} "
                  f"memory_limit={pr.get('memory_limit')} "
                  f"arm_body={pr.get('arm_bytes_body')}B")
            if pr.get("arm_body_snippet"):
                print(f"      said: {pr['arm_body_snippet'][:120]!r}")
        if a.authorized_owner:
            r["authorized_owner"] = a.authorized_owner
        results.append(r)
        if i < len(targets):
            time.sleep(a.delay)

    print("\n=== summary ===")
    width = max((len(r["url"]) for r in results), default=10)
    for r in results:
        print(f"{r['url']:<{width}}  {r['verdict']}")
    counts = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    print("\n" + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))

    if a.json:
        with open(a.json, "w", encoding="utf-8") as fh:
            json.dump({"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                       "authorized_owner": a.authorized_owner or None,
                       "stages": {"cap": a.cap, "producer": a.with_producer},
                       "results": results}, fh, indent=2)
        print(f"\njson -> {a.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
