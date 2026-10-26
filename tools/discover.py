#!/usr/bin/env python3
"""PHP framework discovery, fingerprinting, and CVE-2026-109619 pre-check.

Detects Laravel, Magento, WordPress, Symfony, Drupal, and generic PHP.
Checks sensitive files, security headers, PHP recon prerequisites for
CVE-2026-109619 (session.upload_progress stale PS(id) RCE).

Usage:
    python tools/discover.py --url https://api.openpro.ai
    python tools/discover.py --url https://shop.example.com --deep
    python tools/discover.py --url https://example.com --analyze --base-url https://codex-everywhere.com/v1 --key $KEY --model deepseek-flash
"""

from __future__ import annotations

import argparse
import concurrent.futures
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
# Colour
# ---------------------------------------------------------------------------

class C:
    RST  = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED  = "\033[38;5;196m"; GRN  = "\033[38;5;82m";  YLW = "\033[38;5;220m"
    CYN  = "\033[38;5;51m";  BLU  = "\033[38;5;69m";  MAG = "\033[38;5;171m"
    WHT  = "\033[97m";       GREY = "\033[38;5;245m";  ORAN = "\033[38;5;208m"
    DRED = "\033[38;5;124m"; DGRN = "\033[38;5;28m"

    @staticmethod
    def on() -> bool:
        return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

ANIM = True

def _c(code: str, text: str) -> str:
    return f"{code}{text}{C.RST}" if C.on() else text

def _strip(t: str) -> str:
    return re.sub(r"\033\[[^m]*m", "", t)

def _len(t: str) -> int:
    return len(_strip(t))

# ---------------------------------------------------------------------------
# Tree UI helpers
# ---------------------------------------------------------------------------

def tree_start(title: str, subtitle: str = "") -> None:
    sub = f"  {_c(C.GREY, subtitle)}" if subtitle else ""
    print(f"\n  {_c(C.CYN+C.BOLD,'╭─')} {_c(C.WHT+C.BOLD, title)}{sub}", flush=True)

def tree_row(key: str, val: str) -> None:
    print(f"  {_c(C.GREY,'│')}  {_c(C.DIM, f'{key:<16}')} {val}", flush=True)

def tree_warn(key: str, val: str) -> None:
    print(f"  {_c(C.GREY,'│')}  {_c(C.YLW+C.BOLD, f'{key:<16}')} {_c(C.YLW, val)}  {_c(C.YLW,'⚠')}", flush=True)

def tree_end(msg: str = "") -> None:
    tail = f"  {_c(C.GREY, msg)}" if msg else ""
    print(f"  {_c(C.CYN,'╰─')}{tail}", flush=True)

def tick(v: str)  -> str: return _c(C.GRN, "✓") + " " + v
def cross(v: str) -> str: return _c(C.RED, "✗") + " " + v
def qmark(v: str) -> str: return _c(C.YLW, "?") + " " + v

SEV_COLOR = {
    "critical": C.RED+C.BOLD, "high": C.ORAN+C.BOLD,
    "medium": C.YLW+C.BOLD,  "low": C.CYN+C.BOLD, "info": C.GREY,
}
SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3,"info":4}

# ---------------------------------------------------------------------------
# Spinner
# ---------------------------------------------------------------------------

BRAILLE = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

class Spinner:
    def __init__(self, label: str):
        self._label = label
        self._stop  = threading.Event()
        self._t: Optional[threading.Thread] = None

    def _run(self) -> None:
        i = 0
        while not self._stop.is_set():
            if C.on():
                sys.stdout.write(f"\r  {_c(C.CYN, BRAILLE[i%len(BRAILLE)])} {_c(C.DIM, self._label)}  ")
                sys.stdout.flush()
            i += 1
            time.sleep(0.08)

    def __enter__(self):
        if C.on() and ANIM:
            self._t = threading.Thread(target=self._run, daemon=True)
            self._t.start()
        return self

    def __exit__(self, *_):
        self._stop.set()
        if self._t: self._t.join(timeout=0.3)
        if C.on():
            sys.stdout.write("\r" + " " * 64 + "\r")
            sys.stdout.flush()

def _aprint(lines: list[str], delay: float = 0.025) -> None:
    for line in lines:
        print(line)
        if ANIM and C.on(): time.sleep(delay)

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
LOGO_COLORS = [C.CYN,C.CYN,C.BLU,C.BLU,C.MAG,C.MAG,C.MAG,C.MAG,C.BLU,C.BLU,C.CYN,C.CYN]

def banner(target_url: Optional[str] = None) -> None:
    print()
    _aprint([_c(LOGO_COLORS[i]+C.BOLD, LOGO[i]) for i in range(len(LOGO))], delay=0.025)
    sep = _c(C.GREY, "─" * 38)
    print(f"  {sep}")
    _aprint([
        f"  {_c(C.GREY,'Security Research')}  ·  {_c(C.WHT+C.BOLD,'php-upload-rce')}",
        f"  {_c(C.GREY,'Framework recon + CVE-2026-109619 check')}",
    ], delay=0.04)
    print(f"  {sep}")
    if target_url:
        print()
        print(f"  {_c(C.GREY,'target')}  {_c(C.WHT+C.BOLD, target_url)}")
    print()
    if ANIM and C.on(): time.sleep(0.1)

# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

TIMEOUT = 8

def _connect(scheme: str, host: str, port: int) -> socket.socket:
    tcp = socket.create_connection((host, port), timeout=TIMEOUT)
    if scheme == "https":
        ctx = ssl.create_default_context()
        try:
            return ctx.wrap_socket(tcp, server_hostname=host)
        except ssl.SSLError:
            tcp.close()
            tcp = socket.create_connection((host, port), timeout=TIMEOUT)
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False; ctx2.verify_mode = ssl.CERT_NONE
            return ctx2.wrap_socket(tcp, server_hostname=host)
    tcp.settimeout(TIMEOUT)
    return tcp

def _get(scheme: str, host: str, port: int,
         path: str, host_hdr: str) -> tuple[int, dict[str, str], bytes]:
    sock = _connect(scheme, host, port)
    req  = (f"GET {path} HTTP/1.1\r\nHost: {host_hdr}\r\n"
            f"Connection: close\r\nUser-Agent: Mozilla/5.0 (security-research)\r\n\r\n").encode()
    sock.sendall(req)
    buf = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk: break
            buf += chunk
            if len(buf) > 262_144: break
    finally:
        sock.close()
    sep = buf.find(b"\r\n\r\n")
    if sep == -1: return 0, {}, buf
    raw_h = buf[:sep].decode(errors="replace")
    body  = buf[sep+4:]
    lines = raw_h.split("\r\n")
    status = int(lines[0].split()[1]) if len(lines[0].split()) >= 2 else 0
    hdrs: dict[str,str] = {}
    for ln in lines[1:]:
        if ":" in ln:
            k,_,v = ln.partition(":"); hdrs[k.strip().lower()] = v.strip()
    return status, hdrs, body

def probe(scheme: str, host: str, port: int,
          path: str, host_hdr: str) -> Optional[tuple[int, dict, bytes]]:
    try:
        s, h, b = _get(scheme, host, port, path, host_hdr)
        return (s, h, b) if s else None
    except Exception:
        return None

# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    severity: str
    title: str
    detail: str
    path: str = ""

# ---------------------------------------------------------------------------
# Framework signatures
# ---------------------------------------------------------------------------

FRAMEWORKS: dict[str, dict] = {
    "laravel": {
        "name": "Laravel", "color": C.RED,
        "body_patterns": [rb'csrf-token', rb'laravel_session', rb'Illuminate\\',
                          rb'XSRF-TOKEN', rb'"message":"Unauthenticated"'],
        "cookie_patterns": ["laravel_session", "XSRF-TOKEN"],
        "header_patterns": {"x-powered-by": r"PHP"},
        "confirm_paths": ["/login", "/register", "/api/user", "/api"],
        "sensitive_paths": [
            ("/.env",                     "critical", ".env exposed — DB creds, APP_KEY"),
            ("/.env.backup",              "critical", ".env backup exposed"),
            ("/.env.local",               "high",     ".env.local exposed"),
            ("/storage/logs/laravel.log", "high",     "Laravel log exposed"),
            ("/telescope",                "high",     "Laravel Telescope — full request history"),
            ("/horizon",                  "medium",   "Laravel Horizon — queue dashboard"),
            ("/nova",                     "medium",   "Laravel Nova admin"),
            ("/_debugbar/open",           "medium",   "Laravel Debugbar exposed"),
            ("/composer.json",            "low",      "composer.json exposed"),
            ("/composer.lock",            "low",      "composer.lock exposed"),
        ],
        "version_pattern": rb'laravel/framework["\s:]+v?([\d.]+)',
    },
    "magento": {
        "name": "Magento", "color": C.ORAN,
        "body_patterns": [rb'Mage\.Cookies', rb'mage/frontend_compatibility',
                          rb'window\.checkout', rb'Magento_Ui', rb'mage-cache-sessid'],
        "cookie_patterns": ["mage-cache-sessid", "mage-cache-storage", "adminhtml"],
        "header_patterns": {"x-magento-cache-control": r".*", "x-magento-tags": r".*"},
        "confirm_paths": ["/", "/index.php"],
        "sensitive_paths": [
            ("/app/etc/local.xml",        "critical", "Magento local.xml — DB creds"),
            ("/app/etc/env.php",          "critical", "env.php — DB creds"),
            ("/admin",                    "high",     "Magento admin panel"),
            ("/backend",                  "high",     "Magento backend"),
            ("/downloader",               "high",     "Magento downloader"),
            ("/var/log/system.log",       "medium",   "Magento system log"),
            ("/var/log/exception.log",    "medium",   "Magento exception log"),
            ("/api/rest/products?limit=1","low",      "Magento REST API"),
            ("/magento_version",          "info",     "Magento version endpoint"),
        ],
        "version_pattern": rb'Magento[/\s]+([\d.]+)',
    },
    "wordpress": {
        "name": "WordPress", "color": C.BLU,
        "body_patterns": [rb'/wp-content/', rb'/wp-includes/', rb'wp-json', rb'WordPress'],
        "cookie_patterns": ["wordpress_", "wp-settings-", "wordpress_logged_in"],
        "header_patterns": {"link": r"wp-json"},
        "confirm_paths": ["/", "/wp-login.php"],
        "sensitive_paths": [
            ("/wp-login.php",             "medium",   "WordPress login — brute-force vector"),
            ("/wp-admin/",                "medium",   "WordPress admin"),
            ("/xmlrpc.php",               "high",     "XML-RPC enabled — brute-force/SSRF"),
            ("/wp-json/wp/v2/users",      "medium",   "User enumeration via REST API"),
            ("/wp-content/debug.log",     "high",     "WordPress debug log"),
            ("/.env",                     "critical", ".env exposed"),
            ("/wp-config.php.bak",        "critical", "wp-config backup"),
        ],
        "version_pattern": rb'content="WordPress ([\d.]+)"',
    },
    "symfony": {
        "name": "Symfony", "color": C.DGRN,
        "body_patterns": [rb'Symfony', rb'sf-toolbar', rb'_token'],
        "cookie_patterns": ["sf_redirect"],
        "header_patterns": {"x-debug-token": r".*", "x-debug-token-link": r".*"},
        "confirm_paths": ["/", "/_profiler/"],
        "sensitive_paths": [
            ("/_profiler/",               "critical", "Symfony profiler — full debug info"),
            ("/_wdt/",                    "high",     "Symfony web debug toolbar"),
            ("/.env",                     "critical", ".env exposed"),
            ("/var/log/dev.log",          "medium",   "Symfony dev log"),
            ("/composer.json",            "low",      "composer.json exposed"),
        ],
        "version_pattern": rb'symfony/symfony["\s:]+v?([\d.]+)',
    },
    "drupal": {
        "name": "Drupal", "color": C.MAG,
        "body_patterns": [rb'Drupal', rb'drupal.js', rb'/sites/default/files/'],
        "cookie_patterns": ["SESS"],
        "header_patterns": {"x-generator": r"Drupal", "x-drupal-cache": r".*"},
        "confirm_paths": ["/", "/user/login"],
        "sensitive_paths": [
            ("/CHANGELOG.txt",            "medium",   "Drupal version in CHANGELOG"),
            ("/update.php",               "high",     "Drupal update.php accessible"),
            ("/sites/default/settings.php","critical","settings.php — DB creds"),
            ("/sites/default/files/",     "medium",   "Files directory listable"),
            ("/admin/",                   "medium",   "Drupal admin"),
        ],
        "version_pattern": rb'Drupal ([\d.]+)',
    },
}

GENERIC_PATHS = [
    ("/phpinfo.php",       "high",     "phpinfo() exposed"),
    ("/info.php",          "high",     "phpinfo() exposed"),
    ("/test.php",          "medium",   "test.php exposed"),
    ("/.env",              "critical", ".env exposed — may contain secrets"),
    ("/.git/HEAD",         "critical", "Git repo exposed — source disclosure"),
    ("/.git/config",       "critical", "Git config exposed"),
    ("/composer.json",     "low",      "composer.json exposed"),
    ("/composer.lock",     "low",      "composer.lock exposed"),
    ("/config.php",        "high",     "config.php exposed"),
    ("/backup.sql",        "critical", "SQL dump exposed"),
    ("/dump.sql",          "critical", "SQL dump exposed"),
    ("/db.sql",            "critical", "SQL dump exposed"),
    ("/.htaccess",         "low",      ".htaccess exposed"),
    ("/server-status",     "medium",   "Apache mod_status exposed"),
    ("/.well-known/security.txt", "info", "security.txt present"),
    ("/robots.txt",        "info",     "robots.txt — check Disallow entries"),
]

SECURITY_HEADERS = [
    ("strict-transport-security", "HSTS missing",                   "medium"),
    ("x-content-type-options",    "X-Content-Type-Options missing", "low"),
    ("x-frame-options",           "X-Frame-Options missing",        "low"),
    ("content-security-policy",   "CSP missing",                    "medium"),
    ("referrer-policy",           "Referrer-Policy missing",        "low"),
    ("permissions-policy",        "Permissions-Policy missing",     "low"),
]

PHP_VULN_RANGES = [
    (8, 4, 0, 8, 4, 26),
    (8, 3, 0, 8, 3, 35),
    (8, 2, 0, 8, 2, 34),
]

# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

def _detect_framework(hdrs: dict, cookies_str: str, body: bytes) -> Optional[str]:
    for fw, sig in FRAMEWORKS.items():
        score = 0
        body_slice = body[:20000]
        body_hits = sum(1 for pat in sig.get("body_patterns", [])
                        if re.search(pat, body_slice, re.I))
        if body_hits >= 2:   score += 2
        elif body_hits == 1: score += 1
        for ck in sig.get("cookie_patterns", []):
            if ck.lower() in cookies_str.lower():
                score += 2
                break
        for hk, hpat in sig.get("header_patterns", {}).items():
            if re.search(hpat, hdrs.get(hk, ""), re.I):
                score += 2
                break
        if score >= 2:
            return fw
    return None

def _php_version(hdrs: dict, body: bytes) -> Optional[str]:
    for h in ("x-powered-by", "server"):
        m = re.search(r"PHP/([\d.]+)", hdrs.get(h, ""), re.I)
        if m: return m.group(1)
    m = re.search(rb"PHP/([\d.]+)", body[:4000])
    return m.group(1).decode() if m else None

def _fw_version(fw: str, body: bytes) -> Optional[str]:
    pat = FRAMEWORKS[fw].get("version_pattern")
    if not pat: return None
    m = re.search(pat, body[:40000], re.I)
    return m.group(1).decode(errors="replace") if m else None

def _handler(hdrs: dict, body: bytes) -> str:
    srv  = hdrs.get("server", "").lower()
    pwby = hdrs.get("x-powered-by", "").lower()
    if "fpm" in pwby or "fpm" in srv: return "php-fpm"
    if "apache" in srv and "php" in pwby: return "apache/mod_php"
    if re.search(r"PHP/[\d.]+ Development Server", hdrs.get("server",""), re.I): return "php-cli"
    if "nginx" in srv: return "nginx+php"
    return "unknown"

def _upload_progress_from_body(body: bytes) -> str:
    t = body[:200_000].decode(errors="replace")
    if "session.upload_progress.enabled" in t:
        if re.search(r"session\.upload_progress\.enabled\s+On",  t, re.I): return "on"
        if re.search(r"session\.upload_progress\.enabled\s+Off", t, re.I): return "off"
    return "unknown"

def _is_vuln_version(php_ver: Optional[str]) -> bool:
    if not php_ver: return False
    try:
        mj, mn, pt = (int(x) for x in (php_ver + ".0.0").split(".")[:3])
        return any(amj==mj and amn==mn and apt<=pt<=bpt
                   for amj,amn,apt,bmj,bmn,bpt in PHP_VULN_RANGES)
    except ValueError:
        return False

# ---------------------------------------------------------------------------
# PHP recon phase
# ---------------------------------------------------------------------------

def phase_php_recon(scheme: str, host: str, port: int,
                    host_hdr: str, handler_hint: str,
                    php_ver_hint: Optional[str],
                    findings: list[Finding]) -> dict:
    result = {
        "php_version":    php_ver_hint,
        "handler":        handler_hint,
        "upload_progress":"unknown",
        "memory_limit":   "unknown",
        "workers":        "unknown",
        "cli_server":     "yes" if handler_hint == "php-cli" else "unknown",
    }

    tree_start("php recon", "[CVE-2026-109619 prerequisites]")

    # 1. PHP version from 404 error pages
    if not result["php_version"]:
        for trial in ["/___nxfile_" + "x"*8, "/index.php/___404test"]:
            with Spinner(f"404 probe {trial}"):
                r = probe(scheme, host, port, trial, host_hdr)
            if r:
                s, h, b = r
                ver = _php_version(h, b)
                if ver:
                    result["php_version"] = ver
                    break
                srv = h.get("server", "")
                if re.search(r"PHP/[\d.]+ Development Server", srv, re.I):
                    result["cli_server"] = "yes"
                    result["handler"]    = "php-cli"
                    m2 = re.search(r"PHP/([\d.]+)", srv, re.I)
                    if m2: result["php_version"] = m2.group(1)
                    break

    # 2. Mini OOM probe — tiny multipart, harmless
    try:
        name = "a" + "[b"*20 + "]"*20
        boundary = b"OOM-PROBE-MINI"
        parts = []
        for _ in range(200):
            parts.append(
                b"--" + boundary + b"\r\n"
                b'Content-Disposition: form-data; name="' + name.encode() + b'"\r\n\r\n'
                b"x\r\n"
            )
        parts.append(b"--" + boundary + b"--\r\n")
        oom_body = b"".join(parts)
        sock = _connect(scheme, host, port)
        req = (
            f"POST / HTTP/1.1\r\nHost: {host_hdr}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
            f"Content-Length: {len(oom_body)}\r\n"
            f"Connection: close\r\nUser-Agent: Mozilla/5.0 (security-research)\r\n\r\n"
        ).encode() + oom_body
        sock.settimeout(8)
        sock.sendall(req)
        buf = b""
        try:
            while True:
                c = sock.recv(4096)
                if not c: break
                buf += c
                if len(buf) > 65536: break
        finally:
            sock.close()
        if b"Allowed memory size" in buf or b"exhausted" in buf:
            result["upload_progress"] = "on"
            m = re.search(rb"Allowed memory size of (\d+) bytes", buf)
            if m:
                result["memory_limit"] = f"{int(m.group(1))//1048576}M"
    except Exception:
        pass

    # 3. Worker count heuristic — 4 parallel requests
    def _quick():
        t0 = time.monotonic()
        probe(scheme, host, port, "/", host_hdr)
        return time.monotonic() - t0
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            times = [f.result(timeout=6) for f in [ex.submit(_quick) for _ in range(4)]]
        result["workers"] = ("≥4 parallel" if max(times) < 2*min(times)+0.5
                             else "1 (serial?)")
    except Exception:
        pass

    # Display rows
    ver = result["php_version"]
    tree_row("php version",    tick(ver) if ver else qmark("unknown"))

    h = result["handler"]
    cli = result["cli_server"] == "yes" or "cli" in h
    if cli:        tree_row("handler", tick(h))
    elif "fpm" in h or "apache" in h: tree_row("handler", cross(h))
    else:          tree_row("handler", qmark(h))

    up = result["upload_progress"]
    if up == "on":   tree_row("upload_progress", tick("on"))
    elif up == "off": tree_row("upload_progress", cross("off"))
    else:             tree_row("upload_progress", qmark("unknown"))

    tree_row("memory_limit",   result["memory_limit"])
    tree_row("workers",        result["workers"])

    # CVE verdict
    vuln_ver = _is_vuln_version(ver)
    if cli and up == "on" and vuln_ver:
        tree_row("CVE verdict",  _c(C.RED+C.BOLD, "⚠ LIKELY VULNERABLE"))
        findings.append(Finding("critical", "CVE-2026-109619 — likely exploitable",
                                f"php-cli + upload_progress=on + PHP/{ver}", "/"))
    elif "fpm" in h or "apache" in h:
        tree_row("CVE verdict",  _c(C.GRN, "safe") + _c(C.GREY, "  (php-fpm/mod_php — not php -S)"))
    elif ver and not vuln_ver:
        tree_row("CVE verdict",  _c(C.GRN, "safe") + _c(C.GREY, f"  (PHP/{ver} patched)"))
    else:
        tree_row("CVE verdict",  qmark("unknown — run scanner to confirm"))

    tree_end()
    return result

# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------

def run(scheme: str, host: str, port: int,
        explicit_path: Optional[str], deep: bool) -> list[Finding]:

    default_port = 443 if scheme == "https" else 80
    host_hdr = host if port == default_port else f"{host}:{port}"
    findings: list[Finding] = []

    # ── Phase 0: fingerprint ──────────────────────────────────────────────
    root = explicit_path or "/"
    with Spinner(f"GET {root}"):
        r = probe(scheme, host, port, root, host_hdr)
    if not r:
        tree_start("fingerprint"); tree_row("error", cross(f"no response from {host}")); tree_end()
        return findings

    status, hdrs, body = r
    cookies_str = hdrs.get("set-cookie","") + hdrs.get("cookie","")
    php_ver  = _php_version(hdrs, body)
    handler  = _handler(hdrs, body)
    fw_key   = _detect_framework(hdrs, cookies_str, body)
    server   = hdrs.get("server","—")

    tree_start("fingerprint")
    tree_row("status",   f"{status}  {_c(C.GREY, root)}")
    tree_row("server",   server)
    tree_row("php",      php_ver or _c(C.GREY, "not visible"))
    tree_row("handler",  handler)

    if fw_key:
        fw = FRAMEWORKS[fw_key]; fw_ver = _fw_version(fw_key, body)
        tree_row("framework", _c(fw["color"]+C.BOLD, fw["name"]) + (f"  v{fw_ver}" if fw_ver else ""))
        findings.append(Finding("info", f"{fw['name']} detected",
                                fw["name"] + (f" v{fw_ver}" if fw_ver else ""), root))
    else:
        tree_row("framework", _c(C.GREY, "unknown — probing…"))

    tree_end()

    # ── Phase 0b: framework confirm ───────────────────────────────────────
    if not fw_key:
        for fw_k, fw_sig in FRAMEWORKS.items():
            for cp in fw_sig["confirm_paths"][:2]:
                with Spinner(f"confirm {cp}"):
                    r2 = probe(scheme, host, port, cp, host_hdr)
                if r2:
                    s2, h2, b2 = r2
                    c2 = h2.get("set-cookie","") + h2.get("cookie","")
                    if _detect_framework(h2, c2, b2) == fw_k:
                        fw_key = fw_k; fw = FRAMEWORKS[fw_key]; fw_ver = _fw_version(fw_key, b2)
                        tree_start("framework detect")
                        tree_row("framework", _c(fw["color"]+C.BOLD, fw["name"]) + (f"  v{fw_ver}" if fw_ver else "") + f"  {_c(C.GREY, cp)}")
                        tree_end()
                        findings.append(Finding("info", f"{fw['name']} detected", f"at {cp}", cp))
                        break
            if fw_key: break

    # ── Phase 1: security headers ─────────────────────────────────────────
    tree_start("security headers")
    for hname, msg, sev in SECURITY_HEADERS:
        if hname not in hdrs:
            tree_warn(hname[:16], "missing")
            findings.append(Finding(sev, msg, f"Header '{hname}' absent", root))
        else:
            tree_row(hname[:16], _c(C.GREY, hdrs[hname][:50]))
    tree_end()

    # ── Phase 2: generic sensitive files ─────────────────────────────────
    tree_start("sensitive files")
    for path, sev, title in GENERIC_PATHS:
        with Spinner(f"GET {path}"):
            r3 = probe(scheme, host, port, path, host_hdr)
        if not r3 or r3[0] not in (200, 403):
            continue
        s3, _, b3 = r3
        snippet = b3[:80].decode(errors="replace").replace("\n"," ").strip()
        if s3 == 200:
            tree_warn(f"200 {path[:20]}", title)
            findings.append(Finding(sev, title, snippet, path))
        else:
            bump = "high" if sev in ("critical","high") else "medium"
            tree_warn(f"403 {path[:20]}", f"EXISTS — {title}")
            findings.append(Finding(bump, f"{title} (403)", "Resource exists, access denied", path))
    tree_end()

    # ── Phase 3: framework checks ─────────────────────────────────────────
    if fw_key:
        fw = FRAMEWORKS[fw_key]
        tree_start(f"{fw['name']} checks")
        for path, sev, title in fw["sensitive_paths"]:
            with Spinner(f"GET {path}"):
                r4 = probe(scheme, host, port, path, host_hdr)
            if not r4 or r4[0] not in (200, 403, 500):
                continue
            s4, _, b4 = r4
            snippet = b4[:80].decode(errors="replace").replace("\n"," ").strip()
            if s4 == 200:
                tree_warn(f"200 {path[:20]}", title)
                findings.append(Finding(sev, title, snippet, path))
            elif s4 == 403:
                bump = "high" if sev in ("critical","high") else "medium"
                tree_warn(f"403 {path[:20]}", f"EXISTS — {title}")
                findings.append(Finding(bump, f"{title} (403)", "Resource exists, access denied", path))
            else:
                tree_row(f"500 {path[:20]}", _c(C.GREY, "server error"))
        tree_end()

    # ── Phase 4: PHP recon (CVE prerequisites) ────────────────────────────
    phase_php_recon(scheme, host, port, host_hdr, handler, php_ver, findings)

    return findings

# ---------------------------------------------------------------------------
# Findings summary
# ---------------------------------------------------------------------------

def print_summary(findings: list[Finding]) -> None:
    if not findings: return
    ordered = sorted(findings, key=lambda f: SEV_ORDER.get(f.severity, 9))
    counts: dict[str,int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    summary_parts = "  ·  ".join(
        _c(SEV_COLOR[s], f"{counts[s]} {s}") for s in ("critical","high","medium","low","info") if s in counts
    )
    W = 62
    print(f"\n  {_c(C.CYN+C.BOLD,'╭─')} {_c(C.BOLD+C.WHT,'findings')}  {summary_parts}")
    print(f"  {_c(C.GREY,'│'+'─'*W+'│')}")
    for f in ordered:
        col  = SEV_COLOR.get(f.severity, C.GREY)
        sev  = _c(col, f"{f.severity[:4].upper():<5}")
        path = _c(C.GREY, f" {f.path}") if f.path else ""
        line = f"{f.title[:42]}{path}"
        print(f"  {_c(C.GREY,'│')} {sev}  {line}")
    print(f"  {_c(C.CYN,'╰─')}")
    print()

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    global ANIM
    import json, dataclasses as _dc, pathlib as _pl

    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url",      required=True)
    p.add_argument("--path",     help="Explicit starting path")
    p.add_argument("--deep",     action="store_true")
    p.add_argument("--no-anim",  action="store_true")
    p.add_argument("--json",     action="store_true", help="Print findings JSON to stdout")
    p.add_argument("--json-out", metavar="FILE",      help="Save findings JSON to FILE")
    p.add_argument("--analyze",  action="store_true", help="Run LLM after scan")
    p.add_argument("--provider", default="deepseek",
                   choices=["deepseek","openai","claude","ollama"])
    p.add_argument("--base-url", dest="base_url",
                   help="Custom LLM base URL (e.g. https://codex-everywhere.com/v1)")
    p.add_argument("--key",      default=os.environ.get("LLM_API_KEY",""))
    p.add_argument("--model",    help="LLM model (e.g. deepseek-flash)")
    args = p.parse_args()

    if args.no_anim or not C.on(): ANIM = False

    parsed = urllib.parse.urlsplit(args.url)
    if parsed.scheme not in ("http","https") or not parsed.hostname:
        print("Error: --url must be an absolute http(s) URL", file=sys.stderr); return 1

    scheme = parsed.scheme; host = parsed.hostname
    port   = parsed.port or (443 if scheme=="https" else 80)
    base   = parsed.path or "/"
    explicit_path = args.path or (base if base != "/" else None)

    if not args.json: banner(target_url=f"{scheme}://{host}:{port}")

    findings = run(scheme, host, port, explicit_path, args.deep)
    findings_dict = {"target": args.url, "findings": [_dc.asdict(f) for f in findings]}

    if args.json:
        print(json.dumps(findings_dict, indent=2)); return 0

    if args.json_out:
        _pl.Path(args.json_out).write_text(json.dumps(findings_dict, indent=2))

    print_summary(findings)

    if args.analyze:
        import subprocess as _sp, tempfile
        analyze_script = str(_pl.Path(__file__).parent / "analyze.py")
        cmd = [sys.executable, analyze_script, "--provider", args.provider, "--target", args.url]
        if args.key:      cmd += ["--key",      args.key]
        if args.model:    cmd += ["--model",    args.model]
        if args.base_url: cmd += ["--base-url", args.base_url]
        if args.json_out:
            cmd += ["--findings", args.json_out]; _sp.run(cmd)
        else:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
                json.dump(findings_dict, tf); tf.flush(); cmd += ["--findings", tf.name]
            _sp.run(cmd)

    return 1 if any(f.severity in ("critical","high") for f in findings) else 0

if __name__ == "__main__":
    sys.exit(main())
