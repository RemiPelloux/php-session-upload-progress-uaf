#!/usr/bin/env python3
"""PHP endpoint discovery and vulnerability pre-check for CVE-2026-109619.

Safe read-only prober — works on any URL without --allow-remote.
Reports PHP version, server handler, upload_progress status, and an
exploitability verdict before you run the scanner or exploit.

Usage:
    python tools/discover.py --url https://api.openpro.ai
    python tools/discover.py --url https://api.openpro.ai --path /api/v1/status
    python tools/discover.py --url https://example.com --deep --no-anim
"""

from __future__ import annotations

import argparse
import http.client
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Colour + TTY helpers
# ---------------------------------------------------------------------------

class C:
    RST   = "\033[0m"
    BOLD  = "\033[1m"
    DIM   = "\033[2m"
    ITAL  = "\033[3m"
    RED   = "\033[38;5;196m"
    GRN   = "\033[38;5;82m"
    YLW   = "\033[38;5;220m"
    CYN   = "\033[38;5;51m"
    BLU   = "\033[38;5;69m"
    MAG   = "\033[38;5;171m"
    WHT   = "\033[97m"
    GREY  = "\033[38;5;245m"
    DGRN  = "\033[38;5;28m"
    ORAN  = "\033[38;5;208m"
    BGRED = "\033[41m"
    BGGRN = "\033[42m"

    @staticmethod
    def on() -> bool:
        return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

ANIM = True   # global toggle, set by --no-anim

def _c(code: str, text: str) -> str:
    return f"{code}{text}{C.RST}" if C.on() else text

def _strip(text: str) -> str:
    return re.sub(r"\033\[[^m]*m", "", text)

def _len(text: str) -> int:
    return len(_strip(text))

def _pad(text: str, width: int, char: str = " ") -> str:
    return text + char * max(0, width - _len(text))


# ---------------------------------------------------------------------------
# Spinner (thread-based, braille)
# ---------------------------------------------------------------------------

BRAILLE = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

class Spinner:
    def __init__(self, label: str):
        self._label = label
        self._stop  = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _run(self) -> None:
        i = 0
        while not self._stop.is_set():
            if C.on():
                ch = _c(C.CYN, BRAILLE[i % len(BRAILLE)])
                sys.stdout.write(f"\r  {ch} {_c(C.DIM, self._label)} ")
                sys.stdout.flush()
            i += 1
            time.sleep(0.08)

    def __enter__(self):
        if C.on() and ANIM:
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
        return self

    def __exit__(self, *_):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=0.3)
        if C.on():
            sys.stdout.write("\r" + " " * 60 + "\r")
            sys.stdout.flush()


# ---------------------------------------------------------------------------
# Line-by-line animated print
# ---------------------------------------------------------------------------

def _aprint(lines: list[str], delay: float = 0.025) -> None:
    for line in lines:
        print(line)
        if ANIM and C.on():
            time.sleep(delay)


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

LOGO = [
    r"   ██████╗ ██████╗ ███████╗███╗   ██╗",
    r"  ██╔═══██╗██╔══██╗██╔════╝████╗  ██║",
    r"  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║",
    r"  ██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║",
    r"  ╚██████╔╝██║     ███████╗██║ ╚████║",
    r"   ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝",
    r"  ██████╗ ██████╗  ██████╗ ",
    r"  ██╔══██╗██╔══██╗██╔═══██╗",
    r"  ██████╔╝██████╔╝██║   ██║",
    r"  ██╔═══╝ ██╔══██╗██║   ██║",
    r"  ██║     ██║  ██║╚██████╔╝",
    r"  ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ",
]

LOGO_COLORS = [C.CYN, C.CYN, C.BLU, C.BLU, C.MAG, C.MAG,
               C.MAG, C.MAG, C.BLU, C.BLU, C.CYN, C.CYN]

def banner(target_url: Optional[str] = None) -> None:
    print()
    coloured_logo = [_c(LOGO_COLORS[i] + C.BOLD, LOGO[i]) for i in range(len(LOGO))]
    _aprint(coloured_logo, delay=0.03)

    pad = "  "
    sep = _c(C.GREY, "─" * 36)
    print(f"{pad}{sep}")
    _aprint([
        f"{pad}{_c(C.GREY, 'Security Research')}  ·  {_c(C.WHT+C.BOLD, 'php-upload-rce')}",
        f"{pad}{_c(C.GREY, 'CVE-2026-109619')}  ·  {_c(C.DIM, 'PHP session.upload_progress')}",
        f"{pad}{_c(C.GREY, 'Discover')}  ·  {_c(C.DIM, 'endpoint prober + vuln check')}",
    ], delay=0.04)
    print(f"{pad}{sep}")

    if target_url:
        print()
        print(f"  {_c(C.GREY,'target')}  {_c(C.WHT, target_url)}")
    print()

    if ANIM and C.on():
        time.sleep(0.15)


# ---------------------------------------------------------------------------
# Print helpers
# ---------------------------------------------------------------------------

def _icon(kind: str) -> str:
    return _c({"ok": C.GRN, "fail": C.RED, "warn": C.YLW,
               "info": C.CYN, "dim": C.GREY}[kind],
              {"ok": "✓", "fail": "✗", "warn": "!", "info": "·", "dim": "·"}[kind])

def ok  (label: str, msg: str) -> None: print(f"  [{_icon('ok'  )}] {_c(C.BOLD,f'{label:<18}')} {msg}", flush=True)
def fail(label: str, msg: str) -> None: print(f"  [{_icon('fail')}] {_c(C.BOLD,f'{label:<18}')} {msg}", flush=True)
def warn(label: str, msg: str) -> None: print(f"  [{_icon('warn')}] {_c(C.YLW+C.BOLD,f'{label:<18}')} {_c(C.YLW,msg)}", flush=True)
def info(label: str, msg: str) -> None: print(f"  [{_icon('info')}] {_c(C.DIM,f'{label:<18}')} {msg}", flush=True)
def dim (label: str, msg: str) -> None: print(f"  [{_icon('dim' )}] {_c(C.GREY,f'{label:<18}')} {_c(C.GREY,msg)}", flush=True)

def section(title: str) -> None:
    print()
    bar = _c(C.CYN, "▸")
    print(f"  {bar} {_c(C.BOLD+C.WHT, title)}", flush=True)
    print(f"  {_c(C.GREY, '─' * 52)}", flush=True)


# ---------------------------------------------------------------------------
# Verdict box
# ---------------------------------------------------------------------------

VERDICT_ART = {
    "VULNERABLE": [
        " ██╗   ██╗██╗   ██╗██╗     ███╗  ██╗███████╗",
        " ██║   ██║██║   ██║██║     ████╗ ██║╚════██║",
        " ██║   ██║██║   ██║██║     ██╔██╗██║    ██╔╝",
        " ╚██╗ ██╔╝██║   ██║██║     ██║╚████║   ██╔╝ ",
        "  ╚████╔╝ ╚██████╔╝███████╗██║ ╚███║   ██║  ",
        "   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚══╝   ╚═╝  ",
    ],
    "NOT VULNERABLE": [
        "  ███████╗ █████╗ ███████╗███████╗",
        "  ██╔════╝██╔══██╗██╔════╝██╔════╝",
        "  ███████╗███████║█████╗  █████╗  ",
        "  ╚════██║██╔══██║██╔══╝  ██╔══╝  ",
        "  ███████║██║  ██║██║     ███████╗",
        "  ╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝",
    ],
    "UNKNOWN": [
        "  ██╗   ██╗███╗  ██╗██╗  ██╗███╗  ██╗ ██████╗ ██╗    ██╗███╗  ██╗",
        "  ██║   ██║████╗ ██║██║ ██╔╝████╗ ██║██╔═══██╗██║    ██║████╗ ██║",
        "  ██║   ██║██╔██╗██║█████╔╝ ██╔██╗██║██║   ██║██║ █╗ ██║██╔██╗██║",
        "  ██║   ██║██║╚████║██╔═██╗ ██║╚████║██║   ██║██║███╗██║██║╚████║",
        "  ╚██████╔╝██║ ╚███║██║  ██╗██║ ╚███║╚██████╔╝╚███╔███╔╝██║ ╚███║",
        "   ╚═════╝ ╚═╝  ╚══╝╚═╝  ╚═╝╚═╝  ╚══╝ ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚══╝",
    ],
}

VERDICT_COLOR = {
    "VULNERABLE":     C.RED   + C.BOLD,
    "NOT VULNERABLE": C.GRN   + C.BOLD,
    "UNKNOWN":        C.YLW   + C.BOLD,
}

def verdict_box(result: "DiscoveryResult") -> None:
    v      = result.verdict
    color  = VERDICT_COLOR.get(v, C.WHT + C.BOLD)
    art    = VERDICT_ART.get(v, [])

    print()
    print(f"  {_c(C.GREY, '━' * 60)}")
    print()

    if ANIM and C.on():
        time.sleep(0.1)

    for line in art:
        print(_c(color, line))
        if ANIM and C.on():
            time.sleep(0.025)

    print()

    # Details panel
    rows = [
        ("PHP version",   result.php_version   or _c(C.GREY, "unknown")),
        ("Server",        result.server        or _c(C.GREY, "unknown")),
        ("Handler",       result.handler       or _c(C.GREY, "unknown")),
        ("upload_prog",   _status_badge(result.upload_progress)),
        ("php -S CLI",    _bool_badge(result.php_cli_server)),
        ("Endpoint",      result.working_path  or _c(C.GREY, "none found")),
    ]

    panel_w = 52
    top    = f"  ╭{'─' * panel_w}╮"
    bot    = f"  ╰{'─' * panel_w}╯"
    print(_c(C.GREY, top))
    for key, val in rows:
        label = _c(C.GREY, f"{key:<14}")
        inner = f"  {label}  {val}"
        raw_len = _len(inner) - 2   # subtract leading "  "
        pad = panel_w - raw_len - 1
        line  = f"  {_c(C.GREY,'│')} {label}  {val}{' ' * max(0, pad)}{_c(C.GREY,'│')}"
        print(line)

    if result.notes:
        print(_c(C.GREY, f"  │{'─' * panel_w}│"))
        for note in result.notes[:4]:
            bare  = _strip(note)
            pad   = panel_w - len(bare) - 2
            print(f"  {_c(C.GREY,'│')} {note}{' ' * max(0,pad)}{_c(C.GREY,'│')}")

    print(_c(C.GREY, bot))

    if result.next_step:
        print()
        print(f"  {_c(C.CYN+C.BOLD,'Next ▸')}  {_c(C.WHT, result.next_step)}")

    print()


def _status_badge(s: str) -> str:
    if s == "on":   return _c(C.RED  + C.BOLD, "● ON")
    if s == "off":  return _c(C.GRN  + C.BOLD, "● OFF")
    return _c(C.GREY, "● unknown")

def _bool_badge(s: str) -> str:
    if s == "yes":  return _c(C.RED  + C.BOLD, "● YES")
    if s == "no":   return _c(C.GRN  + C.BOLD, "● NO")
    return _c(C.GREY, "● unknown")


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

TIMEOUT = 10

def _connect(scheme: str, host: str, port: int) -> socket.socket:
    tcp = socket.create_connection((host, port), timeout=TIMEOUT)
    if scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        try:
            return ctx.wrap_socket(tcp, server_hostname=host)
        except ssl.SSLError:
            tcp.close()
            tcp = socket.create_connection((host, port), timeout=TIMEOUT)
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            return ctx2.wrap_socket(tcp, server_hostname=host)
    tcp.settimeout(TIMEOUT)
    return tcp


def _raw_get(scheme: str, host: str, port: int,
             path: str, host_hdr: str) -> tuple[int, dict[str, str], bytes]:
    sock = _connect(scheme, host, port)
    req  = (f"GET {path} HTTP/1.1\r\nHost: {host_hdr}\r\n"
            f"Connection: close\r\nUser-Agent: Mozilla/5.0 (security-research)\r\n\r\n"
            ).encode()
    sock.sendall(req)
    buf = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk: break
            buf += chunk
            if len(buf) > 512_000: break
    finally:
        sock.close()
    sep = buf.find(b"\r\n\r\n")
    if sep == -1:
        return 0, {}, buf
    raw_h = buf[:sep].decode(errors="replace")
    body  = buf[sep + 4:]
    lines = raw_h.split("\r\n")
    status = int(lines[0].split()[1]) if len(lines[0].split()) >= 2 else 0
    hdrs: dict[str, str] = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, _, v = ln.partition(":")
            hdrs[k.strip().lower()] = v.strip()
    return status, hdrs, body


def probe_url(scheme: str, host: str, port: int,
              path: str, host_hdr: str) -> Optional[tuple[int, dict, bytes]]:
    try:
        s, h, b = _raw_get(scheme, host, port, path, host_hdr)
        if s in (200, 301, 302, 403, 405, 500):
            return s, h, b
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Analysis helpers
# ---------------------------------------------------------------------------

def _php_version(hdrs: dict, body: bytes) -> Optional[str]:
    for h in ("x-powered-by", "server"):
        m = re.search(r"PHP/([\d.]+)", hdrs.get(h, ""), re.I)
        if m: return m.group(1)
    m = re.search(rb"PHP/([\d.]+)", body[:4000])
    return m.group(1).decode() if m else None


def _handler(hdrs: dict, body: bytes) -> str:
    srv  = hdrs.get("server", "").lower()
    pwby = hdrs.get("x-powered-by", "").lower()
    if "fpm" in pwby or "fpm" in srv:   return "php-fpm"
    if "apache" in srv and "php" in pwby: return "apache/mod_php"
    btxt = body[:4000].decode(errors="replace").lower()
    if "built-in http server" in btxt or "development server" in btxt: return "php-cli"
    if re.search(r"PHP/[\d.]+ Development Server", hdrs.get("server", ""), re.I): return "php-cli"
    if "nginx" in srv: return "nginx + php (fpm likely)"
    return "unknown"


def _upload_progress(body: bytes) -> str:
    t = body[:200_000].decode(errors="replace")
    if "session.upload_progress.enabled" in t:
        if re.search(r"session\.upload_progress\.enabled\s+On",  t, re.I): return "on"
        if re.search(r"session\.upload_progress\.enabled\s+Off", t, re.I): return "off"
    return "unknown"


def _cli_server(hdrs: dict, body: bytes, h: str) -> str:
    srv  = hdrs.get("server", "")
    if re.search(r"PHP/[\d.]+ Development Server", srv, re.I): return "yes"
    hname = _handler(hdrs, body)
    if hname == "php-cli": return "yes"
    if "fpm" in hname or "apache" in hname: return "no"
    return "unknown"


# ---------------------------------------------------------------------------
# Discovery result + verdict
# ---------------------------------------------------------------------------

CANDIDATE_PATHS = [
    "/", "/index.php", "/phpinfo.php", "/info.php",
    "/php-version.php", "/api", "/api/v1",
    "/api/health", "/health", "/status", "/ping", "/version",
]

@dataclass
class DiscoveryResult:
    php_version:    Optional[str] = None
    server:         Optional[str] = None
    handler:        Optional[str] = None
    upload_progress: str = "unknown"
    php_cli_server:  str = "unknown"
    phpinfo_found:   bool = False
    working_path:   Optional[str] = None
    verdict: str = "UNKNOWN"
    notes: list[str] = field(default_factory=list)
    next_step: Optional[str] = None


def _compute_verdict(res: DiscoveryResult) -> None:
    if not res.php_version:
        res.verdict   = "UNKNOWN"
        res.notes.append("No PHP endpoint found — try --path or --deep")
        res.next_step = "python tools/discover.py --url <url> --path /your/endpoint --deep"
        return

    good, bad = [], []

    if res.php_cli_server == "yes":   good.append(_c(C.GRN, "✓") + " PHP -S CLI server detected")
    elif res.php_cli_server == "no":  bad.append( _c(C.RED, "✗") + " php-fpm/mod_php — stale PS(id) path unlikely")
    else:                             res.notes.append(_c(C.YLW,"!") + " CLI vs FPM unknown — scanner will confirm")

    if res.upload_progress == "on":   good.append(_c(C.GRN, "✓") + " session.upload_progress=On")
    elif res.upload_progress == "off":bad.append( _c(C.RED, "✗") + " session.upload_progress=Off — exploit disabled")
    else:                             res.notes.append(_c(C.YLW,"!") + " upload_progress unknown — scanner will confirm")

    if res.php_version:
        mj, mn, pt = (int(x) for x in (res.php_version + ".0.0").split(".")[:3])
        vuln = ((mj==8 and mn==4 and pt<=26) or
                (mj==8 and mn==3 and pt<=35) or
                (mj==8 and mn==2 and pt<=34))
        if vuln:   good.append(_c(C.GRN,"✓") + f" PHP/{res.php_version} in vulnerable range")
        else:      bad.append( _c(C.RED,"✗") + f" PHP/{res.php_version} may be patched")

    if bad:
        res.verdict = "NOT VULNERABLE"
        res.notes   = bad + res.notes
        res.next_step = "Review the deductions above — or confirm with scanner"
    elif len(good) >= 2:
        res.verdict = "VULNERABLE"
        res.notes   = good + res.notes
        res.next_step = (f"python tools/php-upload-rce-scanner.py "
                         f"--url <url> --allow-remote")
    else:
        res.verdict = "UNKNOWN"
        res.notes   = good + res.notes
        res.next_step = (f"python tools/php-upload-rce-scanner.py "
                         f"--url <url> --allow-remote")


def run_discovery(scheme: str, host: str, port: int,
                  explicit_path: Optional[str], deep: bool) -> DiscoveryResult:
    default_port = 443 if scheme == "https" else 80
    host_hdr = host if port == default_port else f"{host}:{port}"
    res = DiscoveryResult()

    # ── Phase 0 — endpoint hunt ───────────────────────────────────────────
    section("Endpoint hunt")
    paths = ([explicit_path] if explicit_path else []) + CANDIDATE_PATHS
    seen: set[str] = set()
    found_h: dict = {}
    found_b: bytes = b""

    for path in paths:
        if path in seen: continue
        seen.add(path)
        with Spinner(f"GET {path}"):
            r = probe_url(scheme, host, port, path, host_hdr)
        if r is None:
            dim("skip", path)
            continue
        status, hdrs, body = r
        php_ver = _php_version(hdrs, body)
        if php_ver:
            ok("php found", f"PHP/{php_ver}  at {_c(C.WHT+C.BOLD, path)}  status={status}")
            res.php_version = php_ver
            res.working_path = path
            found_h, found_b = hdrs, body
            break
        else:
            info("probe", f"{_c(C.WHT,path)}  status={status}  no PHP sig")
        if not deep and len(seen) >= 5:
            break

    # ── Phase 1 — header analysis ─────────────────────────────────────────
    section("Header analysis")
    if found_h:
        res.server          = found_h.get("server") or found_h.get("x-powered-by") or "—"
        res.handler         = _handler(found_h, found_b)
        res.php_cli_server  = _cli_server(found_h, found_b, host)
        res.upload_progress = _upload_progress(found_b)

        ok("server",          res.server)
        ok("handler",         res.handler)
        fn = ok if res.php_cli_server == "yes" else info
        fn("php-cli",         res.php_cli_server)
        if   res.upload_progress == "on":  ok  ("upload_progress", "On")
        elif res.upload_progress == "off": fail ("upload_progress", "Off — exploit blocked")
        else:                              warn ("upload_progress", "unknown — need phpinfo")
    else:
        warn("endpoints", "no PHP endpoint detected — check URL or try --path /your/route")

    # ── Phase 2 — phpinfo hunt (--deep) ───────────────────────────────────
    if deep:
        section("phpinfo hunt  (--deep)")
        phpinfo_paths = ["/phpinfo.php", "/info.php", "/?phpinfo=1",
                         "/public/phpinfo.php", "/api/phpinfo.php"]
        for pp in phpinfo_paths:
            with Spinner(f"GET {pp}"):
                r = probe_url(scheme, host, port, pp, host_hdr)
            if r and b"phpinfo" in r[2][:10000].lower():
                ok("phpinfo", f"found at {_c(C.WHT+C.BOLD, pp)}")
                _, hdrs, body = r
                res.upload_progress = _upload_progress(body)
                res.php_cli_server  = _cli_server(hdrs, body, host)
                info("upload_progress", res.upload_progress)
                res.phpinfo_found = True
                break
        if not res.phpinfo_found:
            info("phpinfo", "not found (normal on hardened servers)")

    # ── Phase 3 — verdict ─────────────────────────────────────────────────
    section("Verdict")
    _compute_verdict(res)
    return res


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    global ANIM
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--url",     required=True,
                        help="Target base URL  (e.g. https://api.openpro.ai)")
    parser.add_argument("--path",
                        help="Explicit PHP endpoint path  (e.g. /api/version)")
    parser.add_argument("--deep",    action="store_true",
                        help="Also hunt for /phpinfo.php and similar pages")
    parser.add_argument("--no-anim", action="store_true",
                        help="Disable animations and spinner (CI / pipe mode)")
    args = parser.parse_args()

    if args.no_anim or not C.on():
        ANIM = False

    parsed = urllib.parse.urlsplit(args.url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        print("  Error: --url must be an absolute http(s) URL", file=sys.stderr)
        return 1

    scheme = parsed.scheme
    host   = parsed.hostname
    port   = parsed.port or (443 if scheme == "https" else 80)
    base   = parsed.path or "/"
    explicit_path = args.path or (base if base != "/" else None)

    banner(target_url=f"{scheme}://{host}:{port}")
    result = run_discovery(scheme, host, port, explicit_path, args.deep)
    verdict_box(result)
    return 0 if result.verdict == "VULNERABLE" else 1


if __name__ == "__main__":
    sys.exit(main())
