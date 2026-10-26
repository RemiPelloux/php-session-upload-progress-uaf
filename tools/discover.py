#!/usr/bin/env python3
"""PHP framework discovery, fingerprinting, and vulnerability pre-check.

Detects Laravel, Magento, WordPress, Symfony, Drupal, and generic PHP.
Checks for common misconfigurations, exposed sensitive files, and the
CVE-2026-109619 session.upload_progress RCE condition.

Safe read-only prober — all requests are GET/HEAD, no --allow-remote required.

Usage:
    python tools/discover.py --url https://api.openpro.ai
    python tools/discover.py --url https://shop.example.com --deep
    python tools/discover.py --url https://example.com --path /app --no-anim
"""

from __future__ import annotations

import argparse
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
# Colour helpers
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

def _pad(t: str, w: int) -> str:
    return t + " " * max(0, w - _len(t))

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
# Print helpers
# ---------------------------------------------------------------------------

SEV_COLOR = {
    "critical": C.RED+C.BOLD, "high": C.ORAN+C.BOLD,
    "medium": C.YLW+C.BOLD,  "low": C.CYN+C.BOLD, "info": C.GREY,
}
SEV_ICON  = {"critical":"⛔","high":"🔴","medium":"🟡","low":"🔵","info":"ℹ"}

def ok  (l,m): print(f"  [{_c(C.GRN,'✓')}] {_c(C.BOLD,f'{l:<20}')} {m}", flush=True)
def fail(l,m): print(f"  [{_c(C.RED,'✗')}] {_c(C.BOLD,f'{l:<20}')} {m}", flush=True)
def warn(l,m): print(f"  [{_c(C.YLW,'!')}] {_c(C.YLW+C.BOLD,f'{l:<20}')} {_c(C.YLW,m)}", flush=True)
def info(l,m): print(f"  [{_c(C.CYN,'·')}] {_c(C.DIM,f'{l:<20}')} {m}", flush=True)
def dim (l,m): print(f"  [{_c(C.GREY,'·')}] {_c(C.GREY,f'{l:<20}')} {_c(C.GREY,m)}", flush=True)

def section(title: str) -> None:
    print()
    print(f"  {_c(C.CYN,'▸')} {_c(C.BOLD+C.WHT, title)}")
    print(f"  {_c(C.GREY,'─'*54)}")

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
            c = sock.recv(4096)
            if not c: break
            buf += c
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
    severity: str    # critical / high / medium / low / info
    title: str
    detail: str
    path: str = ""
    evidence: str = ""

# ---------------------------------------------------------------------------
# Framework signatures + probes
# ---------------------------------------------------------------------------

FRAMEWORKS: dict[str, dict] = {
    "laravel": {
        "name": "Laravel", "color": C.RED,
        "body_patterns": [rb'csrf-token', rb'laravel', rb'Illuminate\\', rb'XSRF-TOKEN'],
        "cookie_patterns": ["laravel_session", "XSRF-TOKEN"],
        "header_patterns": {"x-powered-by": r"PHP"},
        "confirm_paths": ["/login", "/register", "/api/user", "/api"],
        "sensitive_paths": [
            ("/.env",                         "critical", ".env file exposed — DB credentials, APP_KEY"),
            ("/.env.backup",                  "critical", ".env backup exposed"),
            ("/.env.local",                   "high",     ".env.local exposed"),
            ("/storage/logs/laravel.log",     "high",     "Laravel log file exposed"),
            ("/telescope",                    "high",     "Laravel Telescope exposed — full request history"),
            ("/horizon",                      "medium",   "Laravel Horizon exposed — queue dashboard"),
            ("/nova",                         "medium",   "Laravel Nova admin exposed"),
            ("/composer.json",                "low",      "composer.json exposed — dependency versions"),
            ("/composer.lock",                "low",      "composer.lock exposed"),
            ("/_debugbar/open",               "medium",   "Laravel Debugbar exposed"),
            ("/phpinfo.php",                  "high",     "phpinfo() exposed"),
        ],
        "version_pattern": rb'laravel/framework["\s:]+v?([\d.]+)',
    },
    "magento": {
        "name": "Magento", "color": C.ORAN,
        "body_patterns": [rb'Mage\.Cookies', rb'mage/', rb'Magento', rb'window\.checkout'],
        "cookie_patterns": ["frontend", "adminhtml", "mage-cache-sessid", "mage-cache-storage"],
        "header_patterns": {"x-magento-cache-control": r".*"},
        "confirm_paths": ["/", "/index.php"],
        "sensitive_paths": [
            ("/app/etc/local.xml",           "critical", "Magento local.xml exposed — DB credentials"),
            ("/app/etc/env.php",             "critical", "env.php exposed — DB credentials"),
            ("/admin",                        "high",     "Magento admin panel accessible"),
            ("/backend",                      "high",     "Magento backend accessible"),
            ("/downloader",                   "high",     "Magento downloader accessible"),
            ("/var/log/system.log",          "medium",   "Magento system log exposed"),
            ("/var/log/exception.log",       "medium",   "Magento exception log exposed"),
            ("/api/rest/products?limit=1",   "low",      "Magento REST API accessible"),
            ("/magento_version",             "info",     "Magento version endpoint"),
            ("/composer.json",               "low",      "composer.json exposed"),
        ],
        "version_pattern": rb'Magento[/\s]+([\d.]+)',
    },
    "wordpress": {
        "name": "WordPress", "color": C.BLU,
        "body_patterns": [rb'/wp-content/', rb'/wp-includes/', rb'wp-json', rb'WordPress'],
        "cookie_patterns": ["wordpress_", "wp-settings-", "wordpress_logged_in"],
        "header_patterns": {"x-powered-by": r"PHP", "link": r"wp-json"},
        "confirm_paths": ["/", "/wp-login.php"],
        "sensitive_paths": [
            ("/wp-login.php",                 "medium",   "WordPress login page — brute-force vector"),
            ("/wp-admin/",                    "medium",   "WordPress admin exposed"),
            ("/xmlrpc.php",                   "high",     "XML-RPC enabled — brute-force / SSRF vector"),
            ("/wp-json/wp/v2/users",          "medium",   "User enumeration via REST API"),
            ("/wp-content/debug.log",         "high",     "WordPress debug log exposed"),
            ("/.env",                         "critical", ".env file exposed"),
            ("/wp-config.php.bak",            "critical", "wp-config backup exposed"),
            ("/wp-config-sample.php",         "info",     "wp-config sample (check for real one nearby)"),
            ("/wp-json/wp/v2/posts",          "info",     "WP REST API posts accessible"),
        ],
        "version_pattern": rb'content="WordPress ([\d.]+)"',
    },
    "symfony": {
        "name": "Symfony", "color": C.DGRN,
        "body_patterns": [rb'Symfony', rb'sf-toolbar', rb'_token'],
        "cookie_patterns": ["PHPSESSID", "sf_redirect"],
        "header_patterns": {"x-debug-token": r".*", "x-debug-token-link": r".*"},
        "confirm_paths": ["/", "/_profiler/"],
        "sensitive_paths": [
            ("/_profiler/",                   "critical", "Symfony profiler exposed — full app debug info"),
            ("/_wdt/",                        "high",     "Symfony web debug toolbar exposed"),
            ("/.env",                         "critical", ".env exposed"),
            ("/config/secrets/",             "high",     "Symfony secrets directory exposed"),
            ("/var/log/dev.log",             "medium",   "Symfony dev log exposed"),
            ("/composer.json",               "low",      "composer.json exposed"),
        ],
        "version_pattern": rb'symfony/symfony["\s:]+v?([\d.]+)',
    },
    "drupal": {
        "name": "Drupal", "color": C.MAG,
        "body_patterns": [rb'Drupal', rb'drupal.js', rb'/sites/default/files/'],
        "cookie_patterns": ["SESS", "Drupal"],
        "header_patterns": {"x-generator": r"Drupal", "x-drupal-cache": r".*"},
        "confirm_paths": ["/", "/user/login"],
        "sensitive_paths": [
            ("/CHANGELOG.txt",               "medium",   "Drupal version exposed via CHANGELOG"),
            ("/INSTALL.txt",                 "info",     "INSTALL.txt accessible"),
            ("/update.php",                  "high",     "Drupal update.php accessible"),
            ("/sites/default/settings.php",  "critical", "settings.php exposed — DB credentials"),
            ("/sites/default/files/",        "medium",   "Files directory listable"),
            ("/admin/",                      "medium",   "Drupal admin accessible"),
            ("/user/1",                      "low",      "User 1 (admin) profile accessible"),
        ],
        "version_pattern": rb'Drupal ([\d.]+)',
    },
}

# Generic PHP checks applied to all targets
GENERIC_PATHS = [
    ("/phpinfo.php",          "high",    "phpinfo() exposed — full server config"),
    ("/info.php",             "high",    "phpinfo() exposed"),
    ("/test.php",             "medium",  "test.php exposed"),
    ("/.env",                 "critical","'.env' file exposed — may contain secrets"),
    ("/.git/HEAD",            "critical","Git repository exposed — source code disclosure"),
    ("/.git/config",          "critical","Git config exposed"),
    ("/composer.json",        "low",     "composer.json exposed — dependency info"),
    ("/composer.lock",        "low",     "composer.lock exposed"),
    ("/config.php",           "high",    "config.php exposed"),
    ("/configuration.php",    "high",    "configuration.php exposed (Joomla?)"),
    ("/backup.sql",           "critical","SQL dump exposed"),
    ("/dump.sql",             "critical","SQL dump exposed"),
    ("/db.sql",               "critical","SQL dump exposed"),
    ("/.htaccess",            "low",     ".htaccess exposed — rewrite rules visible"),
    ("/server-status",        "medium",  "Apache mod_status exposed"),
    ("/server-info",          "medium",  "Apache mod_info exposed"),
    ("/.well-known/security.txt", "info","security.txt present"),
    ("/robots.txt",           "info",    "robots.txt — check Disallow entries"),
]

SECURITY_HEADERS = [
    ("strict-transport-security",    "HSTS missing — HTTPS not enforced",           "medium"),
    ("x-content-type-options",       "X-Content-Type-Options missing — MIME sniff", "low"),
    ("x-frame-options",              "X-Frame-Options missing — clickjacking risk",  "low"),
    ("content-security-policy",      "CSP missing — XSS mitigation absent",         "medium"),
    ("referrer-policy",              "Referrer-Policy missing",                      "low"),
    ("permissions-policy",           "Permissions-Policy missing",                   "low"),
]

PHP_VERSIONS_VULNERABLE_TO_CVE = [
    (8, 4, 0, 8, 4, 26),
    (8, 3, 0, 8, 3, 35),
    (8, 2, 0, 8, 2, 34),
]

# ---------------------------------------------------------------------------
# Detection logic
# ---------------------------------------------------------------------------

def _detect_framework(hdrs: dict, cookies_str: str, body: bytes) -> Optional[str]:
    for fw, sig in FRAMEWORKS.items():
        for pat in sig.get("body_patterns", []):
            if re.search(pat, body[:20000], re.I):
                return fw
        for ck in sig.get("cookie_patterns", []):
            if ck.lower() in cookies_str.lower():
                return fw
        for hk, hpat in sig.get("header_patterns", {}).items():
            if re.search(hpat, hdrs.get(hk, ""), re.I):
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
    if "nginx" in srv: return "nginx + php"
    return "unknown"

def _upload_progress(body: bytes) -> str:
    t = body[:200_000].decode(errors="replace")
    if "session.upload_progress.enabled" in t:
        if re.search(r"session\.upload_progress\.enabled\s+On",  t, re.I): return "on"
        if re.search(r"session\.upload_progress\.enabled\s+Off", t, re.I): return "off"
    return "unknown"

def _cve_vuln(php_version: Optional[str], handler: str) -> str:
    if not php_version: return "unknown"
    try:
        mj, mn, pt = (int(x) for x in (php_version + ".0.0").split(".")[:3])
    except ValueError:
        return "unknown"
    vuln_ver = any(
        amj == mj and amn == mn and apt <= pt <= bpt
        for amj, amn, apt, bmj, bmn, bpt in PHP_VERSIONS_VULNERABLE_TO_CVE
    )
    if not vuln_ver: return "no — PHP version patched"
    if "fpm" in handler or "apache" in handler: return "no — php-fpm/mod_php (stale PS(id) path requires php -S)"
    if handler == "php-cli": return "LIKELY — php-S + vulnerable version"
    return "unknown — version vulnerable, confirm handler"

# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------

def run(scheme: str, host: str, port: int,
        explicit_path: Optional[str], deep: bool) -> list[Finding]:

    default_port = 443 if scheme == "https" else 80
    host_hdr = host if port == default_port else f"{host}:{port}"
    findings: list[Finding] = []

    # ── Phase 0: root fingerprint ─────────────────────────────────────────
    section("Server fingerprint")
    root = explicit_path or "/"
    with Spinner(f"GET {root}"):
        r = probe(scheme, host, port, root, host_hdr)
    if not r:
        fail("connect", f"no response from {host}")
        return findings

    status, hdrs, body = r
    cookies_str = hdrs.get("set-cookie", "") + hdrs.get("cookie", "")

    php_ver  = _php_version(hdrs, body)
    handler  = _handler(hdrs, body)
    fw_key   = _detect_framework(hdrs, cookies_str, body)
    server   = hdrs.get("server", "—")

    ok ("status",  f"{status}  {root}")
    ok ("server",  server)
    (ok if php_ver else info)("php", php_ver or "not visible in headers/body")
    ok ("handler", handler)

    if fw_key:
        fw = FRAMEWORKS[fw_key]
        fw_ver = _fw_version(fw_key, body)
        ok("framework", _c(fw["color"]+C.BOLD, fw["name"]) +
                        (f"  v{fw_ver}" if fw_ver else ""))
        findings.append(Finding("info", f"{fw['name']} detected",
                                f"Framework: {fw['name']}" + (f" v{fw_ver}" if fw_ver else ""),
                                root))
    else:
        info("framework", "not detected from root — trying confirm paths")

    # ── Phase 1: framework confirm (if not found on root) ─────────────────
    if not fw_key and not deep:
        for fw_k, fw_sig in FRAMEWORKS.items():
            for cp in fw_sig["confirm_paths"][:2]:
                with Spinner(f"confirm {cp}"):
                    r2 = probe(scheme, host, port, cp, host_hdr)
                if r2:
                    s2, h2, b2 = r2
                    c2 = h2.get("set-cookie","") + h2.get("cookie","")
                    if _detect_framework(h2, c2, b2) == fw_k:
                        fw_key = fw_k
                        fw = FRAMEWORKS[fw_key]
                        fw_ver = _fw_version(fw_key, b2)
                        ok("framework", _c(fw["color"]+C.BOLD, fw["name"]) +
                                        (f"  v{fw_ver}" if fw_ver else ""))
                        findings.append(Finding("info", f"{fw['name']} detected",
                                                f"Found at {cp}", cp))
                        break
            if fw_key: break

    # ── Phase 2: security headers ─────────────────────────────────────────
    section("Security headers")
    for hname, msg, sev in SECURITY_HEADERS:
        if hname not in hdrs:
            warn("missing", msg)
            findings.append(Finding(sev, msg, f"Response header '{hname}' absent", root))
        else:
            info(hname[:20], hdrs[hname][:60])

    # ── Phase 3: generic sensitive paths ──────────────────────────────────
    section("Generic sensitive files")
    for path, sev, title in GENERIC_PATHS:
        with Spinner(f"GET {path}"):
            r3 = probe(scheme, host, port, path, host_hdr)
        if r3 and r3[0] in (200, 403):
            snippet = r3[2][:120].decode(errors="replace").replace("\n"," ").strip()
            label = f"{r3[0]}  {path}"
            if r3[0] == 200:
                warn(sev.upper(), f"{title}  [{_c(C.GREY, snippet[:60])}]")
                findings.append(Finding(sev, title, snippet, path))
            else:  # 403 — exists but blocked
                info("403", f"{path}  (exists, access denied)")
        else:
            dim("ok", path)

    # ── Phase 4: framework-specific checks ────────────────────────────────
    if fw_key:
        fw = FRAMEWORKS[fw_key]
        section(f"{fw['name']} checks")
        for path, sev, title in fw["sensitive_paths"]:
            with Spinner(f"GET {path}"):
                r4 = probe(scheme, host, port, path, host_hdr)
            if r4 and r4[0] in (200, 403, 500):
                snippet = r4[2][:120].decode(errors="replace").replace("\n"," ").strip()
                if r4[0] == 200:
                    warn(sev.upper(), f"{title}")
                    findings.append(Finding(sev, title, snippet, path))
                elif r4[0] == 500 and "critical" in sev:
                    info("500", f"{path}  (error — may still be relevant)")
                else:
                    info("403", f"{path}  (exists, access denied)")
            else:
                dim("ok", path)

    # ── Phase 5: CVE-2026-109619 check ────────────────────────────────────
    section("CVE-2026-109619  (session.upload_progress RCE)")
    upload_prog = "unknown"
    if b"phpinfo" in body[:10000].lower() or b"upload_progress" in body:
        upload_prog = _upload_progress(body)
    cve_status = _cve_vuln(php_ver, handler)

    (ok if "LIKELY" in cve_status else
     fail if cve_status.startswith("no") else warn)(
        "verdict", cve_status)
    info("php version",    php_ver or "unknown")
    info("handler",        handler)
    info("upload_progress", upload_prog)

    if "LIKELY" in cve_status:
        findings.append(Finding("critical", "CVE-2026-109619 — PHP session upload RCE likely",
                                f"PHP/{php_ver} + {handler} + upload_progress={upload_prog}",
                                root))
        info("next", "python tools/php-upload-rce-scanner.py --url <url> --allow-remote")

    return findings

# ---------------------------------------------------------------------------
# Findings summary table
# ---------------------------------------------------------------------------

SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3,"info":4}

def print_summary(findings: list[Finding]) -> None:
    if not findings:
        return
    section("Findings summary")
    ordered = sorted(findings, key=lambda f: SEV_ORDER.get(f.severity, 9))

    W = 58
    print(f"  {_c(C.GREY,'╭'+'─'*W+'╮')}")
    print(f"  {_c(C.GREY,'│')} {_c(C.BOLD,'Sev     ')}  {_c(C.BOLD,'Finding'):<{W-12}} {_c(C.GREY,'│')}")
    print(f"  {_c(C.GREY,'│'+'─'*W+'│')}")

    for f in ordered:
        col  = SEV_COLOR.get(f.severity, C.GREY)
        sev  = _c(col, f"{f.severity.upper():<8}")
        title = f.title[:W-12]
        pad  = W - 10 - _len(title)
        print(f"  {_c(C.GREY,'│')} {sev}  {title}{' '*max(0,pad)}{_c(C.GREY,'│')}")
        if f.path:
            path_line = f"           {_c(C.GREY, f.path)}"
            pad2 = W - _len(path_line) + 2
            print(f"  {_c(C.GREY,'│')}{path_line}{' '*max(0,pad2)}{_c(C.GREY,'│')}")

    print(f"  {_c(C.GREY,'╰'+'─'*W+'╯')}")

    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    parts = []
    for sev in ("critical","high","medium","low","info"):
        if sev in counts:
            parts.append(_c(SEV_COLOR[sev], f"{counts[sev]} {sev}"))
    print()
    print(f"  {_c(C.BOLD,'Total:')}  " + "  ·  ".join(parts))
    print()

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    global ANIM
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url",     required=True,
                   help="Target base URL  (e.g. https://api.openpro.ai)")
    p.add_argument("--path",    help="Explicit starting path  (e.g. /app)")
    p.add_argument("--deep",    action="store_true",
                   help="Try more paths and phpinfo hunting")
    p.add_argument("--no-anim", action="store_true",
                   help="Disable animations / spinner")
    args = p.parse_args()

    if args.no_anim or not C.on():
        ANIM = False

    parsed = urllib.parse.urlsplit(args.url)
    if parsed.scheme not in ("http","https") or not parsed.hostname:
        print("Error: --url must be an absolute http(s) URL", file=sys.stderr)
        return 1

    scheme = parsed.scheme
    host   = parsed.hostname
    port   = parsed.port or (443 if scheme=="https" else 80)
    base   = parsed.path or "/"
    explicit_path = args.path or (base if base != "/" else None)

    banner(target_url=f"{scheme}://{host}:{port}")

    findings = run(scheme, host, port, explicit_path, args.deep)
    print_summary(findings)

    crit = sum(1 for f in findings if f.severity in ("critical","high"))
    return 1 if crit else 0

if __name__ == "__main__":
    sys.exit(main())
