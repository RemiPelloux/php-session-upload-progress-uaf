#!/usr/bin/env python3
"""PHP endpoint discovery and vulnerability pre-check for CVE-2026-109619.

Probes any URL (no --allow-remote required — all requests are safe GET/HEAD).
Reports PHP version, server type, upload_progress status, and an exploitability
verdict before you run the scanner or exploit.

Usage:
    python tools/discover.py --url https://api.openpro.ai
    python tools/discover.py --url https://api.openpro.ai --path /api/v1/status
    python tools/discover.py --url https://example.com --deep
"""

from __future__ import annotations

import argparse
import http.client
import os
import re
import socket
import ssl
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Terminal UI
# ---------------------------------------------------------------------------

class C:
    RST  = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED  = "\033[31m"; GRN = "\033[32m"; YLW = "\033[33m"
    CYN  = "\033[36m"; WHT = "\033[97m"; MAG = "\033[35m"

    @staticmethod
    def ok() -> bool:
        return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str, text: str) -> str:
    return f"{code}{text}{C.RST}" if C.ok() else text


def banner() -> None:
    lines = [
        "╔══════════════════════════════════════════════════╗",
        "║  OpenPro · php-upload-rce  /  discover           ║",
        "║  PHP endpoint prober — CVE-2026-109619           ║",
        "╚══════════════════════════════════════════════════╝",
    ]
    print()
    for line in lines:
        print(" " + _c(C.CYN + C.BOLD, line))
    print()


def ok(label: str, msg: str) -> None:
    print(f" [{_c(C.GRN,'✓')}] {_c(C.BOLD,f'{label:<14}')} {msg}", flush=True)

def fail(label: str, msg: str) -> None:
    print(f" [{_c(C.RED,'✗')}] {_c(C.BOLD,f'{label:<14}')} {msg}", flush=True)

def warn(label: str, msg: str) -> None:
    print(f" [{_c(C.YLW,'!')}] {_c(C.BOLD,f'{label:<14}')} {msg}", flush=True)

def info(label: str, msg: str) -> None:
    print(f" [{_c(C.CYN,'·')}] {_c(C.DIM,f'{label:<14}')} {msg}", flush=True)

def section(title: str) -> None:
    print("\n " + _c(C.BOLD + C.WHT, title), flush=True)

def verdict_box(result: "DiscoveryResult") -> None:
    print()
    v = result.verdict
    if v == "VULNERABLE":
        colour = C.RED + C.BOLD
        icon   = "⚠"
    elif v == "NOT VULNERABLE":
        colour = C.GRN + C.BOLD
        icon   = "✓"
    else:
        colour = C.YLW + C.BOLD
        icon   = "?"

    lines = [
        f"  Verdict : {_c(colour, f'{icon}  {v}')}",
        f"  PHP     : {result.php_version or 'unknown'}",
        f"  Server  : {result.server or 'unknown'}",
        f"  Handler : {result.handler or 'unknown'}",
        f"  upload_progress : {result.upload_progress}",
        f"  PHP-S CLI server : {result.php_cli_server}",
    ]
    if result.notes:
        lines.append(f"  Notes   : {' | '.join(result.notes)}")
    if result.next_step:
        lines.append("")
        lines.append(f"  Next    : {_c(C.CYN, result.next_step)}")

    width = max(len(re.sub(r'\033\[[^m]*m', '', l)) for l in lines) + 4
    border = "─" * width
    print(f" ╭{border}╮")
    for l in lines:
        raw = re.sub(r'\033\[[^m]*m', '', l)
        pad = width - len(raw)
        print(f" │ {l}{' ' * pad} │")
    print(f" ╰{border}╯")
    print()


# ---------------------------------------------------------------------------
# HTTP helpers (stdlib only)
# ---------------------------------------------------------------------------

TIMEOUT = 10

def _connect(scheme: str, host: str, port: int) -> socket.socket:
    tcp = socket.create_connection((host, port), timeout=TIMEOUT)
    if scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        try:
            tcp = ctx.wrap_socket(tcp, server_hostname=host)
        except ssl.SSLError:
            # fall back to unverified for self-signed certs in a lab
            tcp.close()
            tcp = socket.create_connection((host, port), timeout=TIMEOUT)
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            tcp = ctx2.wrap_socket(tcp, server_hostname=host)
    tcp.settimeout(TIMEOUT)
    return tcp


def _raw_get(scheme: str, host: str, port: int, path: str,
             host_hdr: str) -> tuple[int, dict[str, str], bytes]:
    sock = _connect(scheme, host, port)
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_hdr}\r\n"
        f"Connection: close\r\n"
        f"User-Agent: Mozilla/5.0 (security-research)\r\n"
        f"\r\n"
    ).encode()
    sock.sendall(req)
    buf = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            if len(buf) > 512_000:
                break
    finally:
        sock.close()
    # parse
    header_end = buf.find(b"\r\n\r\n")
    if header_end == -1:
        return 0, {}, buf
    raw_hdrs = buf[:header_end].decode(errors="replace")
    body = buf[header_end + 4:]
    lines = raw_hdrs.split("\r\n")
    status = int(lines[0].split()[1]) if len(lines[0].split()) >= 2 else 0
    hdrs: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            hdrs[k.strip().lower()] = v.strip()
    return status, hdrs, body


# ---------------------------------------------------------------------------
# Discovery result
# ---------------------------------------------------------------------------

@dataclass
class DiscoveryResult:
    php_version: Optional[str] = None
    server: Optional[str] = None
    handler: Optional[str] = None          # php-fpm, php-cli, apache-mod, unknown
    upload_progress: str = "unknown"       # on / off / unknown
    php_cli_server: str = "unknown"        # yes / no / unknown
    phpinfo_found: bool = False
    working_path: Optional[str] = None
    verdict: str = "UNKNOWN"               # VULNERABLE / NOT VULNERABLE / UNKNOWN
    notes: list[str] = field(default_factory=list)
    next_step: Optional[str] = None


# ---------------------------------------------------------------------------
# Probe logic
# ---------------------------------------------------------------------------

# Common paths to try when no PHP is detected on the given URL
CANDIDATE_PATHS = [
    "/",
    "/index.php",
    "/phpinfo.php",
    "/info.php",
    "/php-version.php",
    "/api",
    "/api/v1",
    "/api/health",
    "/health",
    "/status",
    "/ping",
    "/version",
]

PHP_CLI_SIGNALS = [
    "development server",
    "php development",
    "php -s",
    "php built-in",
]


def _extract_php(hdrs: dict, body: bytes, path: str) -> Optional[str]:
    for h in ("x-powered-by", "server"):
        m = re.search(r"PHP/([\d.]+)", hdrs.get(h, ""), re.I)
        if m:
            return m.group(1)
    m = re.search(rb"PHP/([\d.]+)", body[:2000])
    if m:
        return m.group(1).decode()
    return None


def _detect_handler(hdrs: dict, body: bytes) -> str:
    server = hdrs.get("server", "").lower()
    powered = hdrs.get("x-powered-by", "").lower()
    # php-fpm via X-Powered-By or server header
    if "fpm" in powered or "fpm" in server:
        return "php-fpm"
    # Apache mod_php
    if "apache" in server and "php" in powered:
        return "apache-mod_php"
    # PHP CLI built-in server emits "PHP <version> Development Server"
    body_text = body[:4000].decode(errors="replace").lower()
    if any(s in body_text for s in PHP_CLI_SIGNALS):
        return "php-cli"
    # Nginx + PHP — could be fpm or cli behind proxy
    if "nginx" in server:
        return "nginx+php (fpm likely)"
    return "unknown"


def _check_upload_progress(hdrs: dict, body: bytes) -> str:
    # phpinfo() output exposes this directly
    body_text = body[:200_000].decode(errors="replace")
    if "session.upload_progress.enabled" in body_text:
        if re.search(r"session\.upload_progress\.enabled\s+On", body_text, re.I):
            return "on"
        if re.search(r"session\.upload_progress\.enabled\s+Off", body_text, re.I):
            return "off"
    return "unknown"


def _is_cli_server(hdrs: dict, body: bytes) -> str:
    body_text = body[:200_000].decode(errors="replace").lower()
    # phpinfo reveals Server API: Built-in HTTP server
    if "built-in http server" in body_text or "server api" in body_text:
        if "built-in" in body_text:
            return "yes"
    # Server header "PHP/8.x.x Development Server"
    srv = hdrs.get("server", "")
    if re.search(r"PHP/[\d.]+ Development Server", srv, re.I):
        return "yes"
    handler = _detect_handler(hdrs, body)
    if handler == "php-cli":
        return "yes"
    if "fpm" in handler or "apache" in handler:
        return "no"
    return "unknown"


def probe_url(scheme: str, host: str, port: int, path: str,
              host_hdr: str) -> Optional[tuple[int, dict, bytes, str]]:
    try:
        status, hdrs, body = _raw_get(scheme, host, port, path, host_hdr)
        if status in (200, 301, 302, 403, 500):
            return status, hdrs, body, path
        return None
    except Exception:
        return None


def run_discovery(scheme: str, host: str, port: int,
                  explicit_path: Optional[str], deep: bool) -> DiscoveryResult:
    default_port = 443 if scheme == "https" else 80
    host_hdr = host if port == default_port else f"{host}:{port}"
    res = DiscoveryResult()

    # ── Phase 0: try the explicit path first ──────────────────────────────
    section("Probing PHP endpoints")
    paths_to_try = ([explicit_path] if explicit_path else []) + CANDIDATE_PATHS
    seen: set[str] = set()

    found_hdrs: dict = {}
    found_body: bytes = b""

    for path in paths_to_try:
        if path in seen:
            continue
        seen.add(path)

        r = probe_url(scheme, host, port, path, host_hdr)
        if r is None:
            info("skip", f"{path}  (no response / error)")
            continue

        status, hdrs, body, _ = r
        php_ver = _extract_php(hdrs, body, path)

        if php_ver:
            ok("php found", f"PHP/{php_ver}  at {path}  status={status}")
            res.php_version = php_ver
            res.working_path = path
            found_hdrs = hdrs
            found_body = body
            break
        else:
            info("probe", f"{path}  status={status}  no PHP sig")

        if not deep and len(seen) >= 4:
            break

    # ── Phase 1: collect server info ──────────────────────────────────────
    section("Analysing headers")
    if found_hdrs:
        res.server   = found_hdrs.get("server") or found_hdrs.get("x-powered-by") or "—"
        res.handler  = _detect_handler(found_hdrs, found_body)
        res.php_cli_server    = _is_cli_server(found_hdrs, found_body)
        res.upload_progress   = _check_upload_progress(found_hdrs, found_body)

        ok("server",  res.server)
        ok("handler", res.handler)
        (ok if res.php_cli_server == "yes" else info)("php-cli", res.php_cli_server)

        if res.upload_progress != "unknown":
            (ok if res.upload_progress == "on" else fail)("upload_progress", res.upload_progress)
        else:
            warn("upload_progress", "unknown (not exposed — try /phpinfo.php or --deep)")
    else:
        warn("server", "no PHP endpoint found — check the URL or add --path")

    # ── Phase 2: phpinfo hunt (--deep) ────────────────────────────────────
    if deep and not res.phpinfo_found:
        section("phpinfo hunt (--deep)")
        phpinfo_paths = ["/phpinfo.php", "/info.php", "/?phpinfo=1",
                         "/public/phpinfo.php", "/api/phpinfo.php"]
        for pp in phpinfo_paths:
            r = probe_url(scheme, host, port, pp, host_hdr)
            if r and b"phpinfo" in r[2][:10000].lower():
                ok("phpinfo", f"found at {pp}")
                res.phpinfo_found = True
                status, hdrs, body, _ = r
                res.upload_progress = _check_upload_progress(hdrs, body)
                res.php_cli_server  = _is_cli_server(hdrs, body)
                info("upload_progress", res.upload_progress)
                break
        if not res.phpinfo_found:
            info("phpinfo", "not found (that's normal — move on)")

    # ── Phase 3: verdict ──────────────────────────────────────────────────
    section("Verdict")
    _compute_verdict(res)
    return res


def _compute_verdict(res: DiscoveryResult) -> None:
    points: list[str] = []
    deductions: list[str] = []

    if not res.php_version:
        res.verdict = "UNKNOWN"
        res.notes.append("no PHP endpoint found — wrong URL?")
        res.next_step = "re-run with --path /your/php/endpoint  or  --deep"
        return

    # PHP CLI server is the primary prerequisite
    if res.php_cli_server == "yes":
        points.append("PHP CLI built-in server detected (+)")
    elif res.php_cli_server == "no":
        deductions.append("php-fpm / mod_php detected — stale PS(id) path unlikely (-)")
    else:
        res.notes.append("CLI vs FPM handler unknown — run scanner to confirm")

    if res.upload_progress == "on":
        points.append("session.upload_progress.enabled=On (+)")
    elif res.upload_progress == "off":
        deductions.append("session.upload_progress.enabled=Off — exploit disabled (-)")
    else:
        res.notes.append("upload_progress state unknown — scanner will confirm")

    if res.php_version:
        major, minor, patch = (int(x) for x in (res.php_version + ".0.0").split(".")[:3])
        vulnerable_range = (
            (major == 8 and minor == 4 and patch <= 26) or
            (major == 8 and minor == 3 and patch <= 35) or
            (major == 8 and minor == 2 and patch <= 34)
        )
        if vulnerable_range:
            points.append(f"PHP/{res.php_version} in vulnerable range (+)")
        else:
            deductions.append(f"PHP/{res.php_version} may be patched — check changelog")

    if deductions:
        res.verdict = "NOT VULNERABLE"
        res.notes += deductions
        res.next_step = "review deductions above — or run scanner to be sure"
    elif len(points) >= 2:
        res.verdict = "VULNERABLE"
        res.notes += points
        url_hint = f"https://github.com/RemiPelloux/php-upload-rce"
        res.next_step = f"python tools/scanner.py --url <same-url> --allow-remote"
    else:
        res.verdict = "UNKNOWN"
        res.notes += points
        res.next_step = "python tools/scanner.py --url <same-url> --allow-remote"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--url", required=True,
                        help="Target base URL (e.g. https://api.openpro.ai)")
    parser.add_argument("--path",
                        help="Explicit PHP endpoint path (e.g. /api/version)")
    parser.add_argument("--deep", action="store_true",
                        help="Also hunt for /phpinfo.php and similar pages")
    parser.add_argument("--delay", type=float, default=0.2,
                        help="Seconds between requests (default 0.2)")
    args = parser.parse_args()

    banner()

    parsed = urllib.parse.urlsplit(args.url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        print("  Error: --url must be an absolute http(s) URL", file=sys.stderr)
        return 1

    scheme = parsed.scheme
    host   = parsed.hostname
    port   = parsed.port or (443 if scheme == "https" else 80)
    # if the base URL has a path component, use it as default
    base_path = parsed.path or "/"
    explicit_path = args.path or (base_path if base_path != "/" else None)

    info("target", f"{scheme}://{host}:{port}")
    if explicit_path:
        info("path",   explicit_path)

    result = run_discovery(scheme, host, port, explicit_path, args.deep)
    verdict_box(result)
    return 0 if result.verdict == "VULNERABLE" else 1


if __name__ == "__main__":
    sys.exit(main())
