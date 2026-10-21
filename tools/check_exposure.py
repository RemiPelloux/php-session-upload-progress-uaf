#!/usr/bin/env python3
"""
check_exposure.py — is this PHP install exposed to the session.upload_progress
cross-request UAF?

Reads php.ini files (yours, or ones you point it at) and explains, in operator
terms, whether the vulnerable combination is present and what to change.

    # check the ini files the local PHP CLI actually loads
    python3 check_exposure.py

    # check a specific set of files (e.g. the ones a container ships)
    python3 check_exposure.py /etc/php/8.4/fpm/php.ini
    python3 check_exposure.py --ini-dir /etc/php/8.4/fpm

    # use the local PHP binary's own view instead of parsing files
    python3 check_exposure.py --from-php

    # machine-readable
    python3 check_exposure.py --json

Exit codes: 0 = mitigated, 1 = exposed, 2 = could not determine.

Caveat that matters: CLI and FPM/Apache usually load *different* ini files, and
vhost-level `php_value` / `.user.ini` override both. If you are not sure, check
the SAPI you actually serve traffic with.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys

RELEVANT = (
    "session.upload_progress.enabled",
    "session.upload_progress.cleanup",
    "session.upload_progress.freq",
    "session.upload_progress.min_freq",
    "session.upload_progress.name",
    "memory_limit",
    "post_max_size",
    "upload_max_filesize",
    "max_file_uploads",
    "max_input_vars",
)

FALSY = {"off", "0", "false", "no", "none", ""}
TRUTHY = {"on", "1", "true", "yes"}


def parse_ini_value(raw: str) -> str:
    v = raw.strip()
    if "#" in v or ";" in v:
        v = re.split(r"[;#]", v, 1)[0].strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1]
    return v


def boolish(raw: str) -> bool | None:
    v = parse_ini_value(raw).lower()
    if v in TRUTHY:
        return True
    if v in FALSY:
        return False
    return None


def to_bytes(raw: str) -> int | None:
    v = parse_ini_value(raw).lower().rstrip("b").strip()
    if v in ("-1", "0"):
        return int(v)
    m = re.fullmatch(r"(\d+)\s*([kmg]?)", v)
    if not m:
        return None
    n = int(m.group(1))
    return n * {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}[m.group(2)]


def human(n: int | None) -> str:
    if n is None:
        return "?"
    if n < 0:
        return "unlimited"
    for unit, size in (("G", 1024**3), ("M", 1024**2), ("K", 1024)):
        if n >= size and n % size == 0:
            return f"{n // size}{unit}"
    return f"{n}B"


def from_ini_files(paths: list[str]) -> tuple[dict[str, str], list[str]]:
    vals: dict[str, str] = {}
    read: list[str] = []
    for path in paths:
        try:
            with open(path, "r", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        read.append(path)
        for line in text.splitlines():
            s = line.strip()
            if not s or s[0] in ";#[":
                continue
            if "=" not in s:
                continue
            key, raw = s.split("=", 1)
            key = key.strip().lower()
            if key in RELEVANT:
                vals[key] = parse_ini_value(raw)   # later files win
    return vals, read


def from_php_binary(binary: str) -> tuple[dict[str, str], list[str]]:
    try:
        out = subprocess.run([binary, "-i"], capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return {}, []
    vals: dict[str, str] = {}
    for line in out.splitlines():
        if "=>" not in line:
            continue
        parts = [p.strip() for p in line.split("=>")]
        key = parts[0].lower()
        if key in RELEVANT and len(parts) >= 2:
            vals[key] = parse_ini_value(parts[-1])
    return vals, [f"{binary} -i"]


def default_ini_paths() -> list[str]:
    paths: list[str] = []
    for binary in ("php", "php8.5", "php8.4", "php8.3", "php8.2"):
        if not shutil.which(binary):
            continue
        try:
            out = subprocess.run([binary, "--ini"], capture_output=True, text=True, timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        for line in out.splitlines():
            if ":" in line and "/" in line:
                candidate = line.split(":", 1)[1].strip()
                if candidate and os.path.isfile(candidate):
                    paths.append(candidate)
        break
    return paths


def main() -> int:
    ap = argparse.ArgumentParser(description="Check a PHP config for the session.upload_progress UAF exposure")
    ap.add_argument("ini", nargs="*", help="php.ini files to inspect (last one wins)")
    ap.add_argument("--ini-dir", help="inspect every .ini file directly inside this directory")
    ap.add_argument("--php-bin", default="php", help="PHP binary used with --from-php")
    ap.add_argument("--from-php", action="store_true", help="ask a PHP binary for its effective values")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    if args.from_php:
        vals, sources = from_php_binary(args.php_bin)
    else:
        paths = list(args.ini)
        if args.ini_dir:
            paths += sorted(glob.glob(os.path.join(args.ini_dir, "*.ini")))
        if not paths:
            paths = default_ini_paths()
        vals, sources = from_ini_files(paths)

    if not sources:
        print("could not find a php.ini (pass one explicitly, or use --from-php)", file=sys.stderr)
        return 2

    enabled = boolish(vals.get("session.upload_progress.enabled", "1"))   # upstream default: On
    mem = to_bytes(vals.get("memory_limit", "-1")) if "memory_limit" in vals else None
    post = to_bytes(vals.get("post_max_size", "8M"))
    up = to_bytes(vals.get("upload_max_filesize", "2M"))

    exposed = enabled is True
    verdict = "EXPOSED" if exposed else "MITIGATED"

    if args.json:
        print(json.dumps({
            "verdict": verdict,
            "upload_progress_enabled": enabled,
            "memory_limit": vals.get("memory_limit"),
            "post_max_size": vals.get("post_max_size"),
            "upload_max_filesize": vals.get("upload_max_filesize"),
            "sources": sources,
            "settings": vals,
        }, indent=2))
        return 1 if exposed else 0

    print("sources:")
    for s in sources:
        print(f"  {s}")
    print()
    print(f"  session.upload_progress.enabled = {vals.get('session.upload_progress.enabled', '(unset -> On by default)')}")
    print(f"  memory_limit                    = {vals.get('memory_limit', '(unset -> 128M default)')}")
    print(f"  post_max_size                   = {vals.get('post_max_size', '(unset -> 8M)')}")
    print(f"  upload_max_filesize             = {vals.get('upload_max_filesize', '(unset -> 2M)')}")
    print()

    if exposed:
        print("VERDICT: EXPOSED")
        print()
        print("  The upload-progress handler is on. If this host also runs a SAPI whose")
        print("  worker survives a request-startup out-of-memory (php-fpm, mod_php prefork,")
        print("  `php -S`), an attacker can abort one worker per attempt, and corrupt heap")
        print("  state they may be able to shape. Memory pressure is the only remaining gate.")
        print()
        if mem is not None and mem > 0 and up is not None and post is not None:
            headroom = mem - post
            print(f"  headroom between post_max_size ({human(post)}) and memory_limit ({human(mem)}): "
                  f"{human(headroom)}")
            print("  A single multipart part can add megabytes of *filename* on top of the")
            print("  body, so that headroom is not the real margin. Raising memory_limit")
            print("  alone is not a fix.")
            print()
        print("  Fix (30 seconds):")
        print("    php.ini / .user.ini / vhost:")
        print("      session.upload_progress.enabled = Off")
        print("    then reload the SAPI:")
        print("      systemctl reload php8.4-fpm    # or: apachectl graceful")
        print()
        print("  Verify:")
        print("      python3 check_exposure.py     # expect VERDICT: MITIGATED")
        print("      php -i | grep session.upload_progress.enabled")
        print()
        print("  Full guidance: REMEDIATION.md")
        return 1

    print("VERDICT: MITIGATED")
    print()
    print("  session.upload_progress.enabled is off, so the handler returns before it can")
    print("  start a session during request startup. That removes this path.")
    print()
    print("  Still worth doing:")
    print("    - confirm every SAPI and every vhost inherits this (CLI, FPM pool, .user.ini)")
    print("    - keep memory_limit above your accepted worst case for multipart parsing")
    print("    - watch logs for the pre-RINIT OOM fingerprint: 'in Unknown on line 0'")
    print("      followed by 'zend_mm_heap corrupted' on the same worker")
    return 0


if __name__ == "__main__":
    sys.exit(main())
