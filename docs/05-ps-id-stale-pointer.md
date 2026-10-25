# 05 — The second path: `PS(id)` stale pointer and OOB session-cookie read

This document covers the **second vulnerability** (CVE-2026-109619).
The first (`BG(serialize)` orphan, doc 01) and this one share the same
pre-`RINIT` window but are otherwise independent: different globals, different
OOM sites, different primitives.

---

## 5.1 What survives the OOM

The key global is `PS(id)` — `ps_globals.id`, a `zend_string *` at
`PS_GLOBALS + 0x10`. Its lifecycle under normal execution:

| Event | PS(id) |
|---|---|
| `php_rinit_session_globals()` (session RINIT) | set to `NULL` without releasing — intentional; previous request already freed it |
| `MULTIPART_EVENT_FILE_START` | `php_rinit_session(0)` → then `PS(id) = zend_string_init(sid, ...)` |
| `MULTIPART_EVENT_END` | `php_rshutdown_session_globals()` → release and null |
| `PHP_RSHUTDOWN_FUNCTION(session)` | `php_rshutdown_session_globals()` if `session_status == php_session_active` |

The invariant breaks when OOM fires between `FILE_START` and `MULTIPART_EVENT_END`.

```c
/* main.c, php_request_startup() */
PG(modules_activated) = 0;         /* line 1831 */
zend_activate();
sapi_activate();
php_hash_environment();            /* line 1873 — multipart + rfc1867 fires here */
zend_activate_modules();           /* line 1874 — session RINIT is in here */
PG(modules_activated) = 1;        /* line 1875 */
```

If OOM fires at line 1873, the `zend_catch` handler catches the longjmp and
`zend_activate_modules()` never runs. Because `PG(modules_activated) == 0`,
`php_request_shutdown()` skips every module's RSHUTDOWN, including session's.
`php_rshutdown_session_globals()` therefore never runs. `PS(id)` is left
non-null — a dangling pointer to a freed `zend_string`.

### The precise OOM site

The 4 096-byte allocation that terminates request A:

```
php_session_send_cookie()
  → php_session_remove_cookie()
    → smart_string_appendc()   [formatting "Set-Cookie: PHPSESSID="]
      → smart_string_realloc() → emalloc(4096)  ← OOM here
```

This allocation is reached from `php_session_reset_id()`, called inside
`php_session_initialize()`, called from `php_session_rfc1867_update()`, called
from `MULTIPART_EVENT_FILE_START`. The OOM fires **after** `FILE_START` has set
`PS(id)` but **before** `MULTIPART_EVENT_END` clears it.

Post-conditions after a correctly-shaped A request:

| Global | Value |
|---|---|
| `PS(id)` | non-null — pointer into freed Zend MM page |
| `PS(send_cookie)` | `1` (set in `php_session_initialize()` before OOM) |
| `PS(session_status)` | `php_session_none` (never reached `php_session_active`) |
| `PG(modules_activated)` | `0` |

Measured on PHP 8.4.26 CLI (ASLR off, GDB):
```
fatal=4096  cookie=False  id=0x7fffed1fe000  sc=1  st=2
```
100 % stable across runs with `parts=874, fillers128=30, progress_last=1,
progress_before_file=1`.

---

## 5.2 The stale-pointer address — Zend MM chunk layout

`PS(id)` at `0x7fffed1fe000` is not arbitrary. Zend MM allocates in 2 MB chunks
(`ZEND_MM_CHUNK_SIZE = 0x200000`). The chunk base is `0x7fffed000000`.

```
chunk base  = stale_id & ~0x1fffff  = 0x7fffed000000
page_idx    = (stale_id - chunk_base) >> 12  = 0x1fe
```

`zend_string_init` for the short session-id string is a **small** allocation
(< 4 096 B), but the zend_string pointer itself was placed in page 0x1fe.
That page offset is deterministic for a given heap layout — it matches the
heap state after the exact allocation sequence of a correctly-shaped A body.

---

## 5.3 How the OOB read works — request B

With `PS(id)` dangling at `0x7fffed1fe000` and `PS(send_cookie) = 1`, the
next request that triggers `php_session_initialize()` will:

1. Not replace `PS(id)` — the check at line 443 of session.c:
   ```c
   if (!PS(id) || !ZSTR_VAL(PS(id))[0]) {
       PS(id) = PS(mod)->s_create_sid(...);   /* skipped when val[0] != '\0' */
   }
   ```
2. Call `php_session_reset_id()` → `php_session_send_cookie()` which reads
   `ZSTR_LEN(PS(id))` and `ZSTR_VAL(PS(id))` to format the Set-Cookie header.

If a **forge value** has been placed in memory at `0x7fffed1fe000` before that
read, the fake `zend_string` header controls `len` and the cookie value is
`len` bytes read from `0x7fffed1fe018` — an attacker-controlled OOB read.

### Forge value layout

A POST field value allocated as a **large** Zend MM object (size
`1 ≤ s ≤ ZEND_MM_MAX_LARGE_SIZE = 0x1ff000`) lands at `chunk + 0x1000` for its
`zend_string` struct. The string data (`val[]`) starts at `chunk + 0x1018`.

To place the fake header at `chunk + page_idx * 0x1000`:

```python
hdr = page_idx * 0x1000 - 0x1018   # data-relative offset of fake header
L   = hdr + 0x18 + 8               # value length (header + 8 sentinel bytes)
```

For `page_idx = 0x1fe`:

```
hdr = 0x1fe000 - 0x1018 = 0x1fcfe8
L   = 0x1fcfe8 + 0x18 + 8 = 0x1fd008
```

`0x1fd008 < 0x1ff000` → large allocation → data at `chunk + 0x1018` → fake
header at `chunk + 0x1018 + 0x1fcfe8 = chunk + 0x1fe000`. ✓

Fake `zend_string` header written at offset `hdr` in the value bytes:

| Offset | Field | Value |
|---|---|---|
| `hdr + 0x00` | `gc.refcount` | `0` (prevents `zend_string_release` from freeing) |
| `hdr + 0x04` | `gc.type_info` | `0x16` (`IS_STRING \| GC_NOT_COLLECTABLE`) |
| `hdr + 0x08` | `h` | `0` |
| `hdr + 0x10` | `len` | `fake_len` (attacker-chosen OOB read size) |
| `hdr + 0x18` | `val[0..]` | first bytes of heap data that become the cookie |

### Trigger: `session.upload_progress.cleanup`

`php_session_initialize()` fires in the B request via the cleanup path at
`MULTIPART_EVENT_END`. The ini `session.upload_progress.cleanup` defaults to
`1`, which means:

```c
case MULTIPART_EVENT_END:
    if (Z_TYPE(progress->sid) && progress->key.s) {
        if (PS(rfc1867_cleanup)) {
            php_session_rfc1867_cleanup(progress);   // → php_session_initialize()
        }
        php_rshutdown_session_globals();
    }
```

`php_session_rfc1867_cleanup()` always calls `php_session_initialize()`.
`MULTIPART_EVENT_END` fires **after** all multipart fields have been parsed —
so all forge values are already allocated when this runs. No file-upload field
is needed in B.

### Timing summary

```
B: php_hash_environment() begins
  MULTIPART_EVENT_FORMDATA for PHPSESSID=<sid>      → progress->sid set
  MULTIPART_EVENT_FORMDATA for PHP_SESSION_UPLOAD_PROGRESS=k0 → progress->key set
  MULTIPART_EVENT_FORMDATA for forge field 1        → large alloc in ZMM chunk
  MULTIPART_EVENT_FORMDATA for forge field 2..N     → more chunks
  MULTIPART_EVENT_END
    → php_session_rfc1867_cleanup()
      → php_session_initialize()
        → php_session_reset_id()
          → php_session_send_cookie()   ← reads PS(id) = 0x7fffed1fe000
                                          with our fake header → OOB Set-Cookie
```

---

## 5.4 Two bugs that blocked the exploit during research

**Bug 1 — null first byte in session ID.**

Request A used `PHPSESSID = b'\x00'` (one null byte). After A's OOM the
original `zend_string` at `0x7fffed1fe000` may still have `val[0] = '\x00'`.
In B's `php_session_initialize()` (line 443):

```c
if (!PS(id) || !ZSTR_VAL(PS(id))[0])   /* val[0] == '\0' → TRUE */
    PS(id) = PS(mod)->s_create_sid(...); /* stale pointer replaced! */
```

The stale pointer is discarded and a fresh session ID is generated. No OOB
read occurs. Fix: use any non-null byte — `PHPSESSID = b'a'`.

**Bug 2 — forge values not reaching the target chunk.**

`A:0x1fe` forge items (size `0x1fd008`) are large allocations that ZMM
places in arbitrary free chunks. With N copies, one *might* land in
`0x7fffed000000`, but it is not guaranteed.

The `G:511:page` item (`forge_fill_value`) fills all 511 usable pages of a
chunk (alloc size `= 511 * 0x1000 - 25 = 0x1fefe7`, just under `MAX_LARGE_SIZE`).
Because the entire chunk is filled, **any** chunk that receives a `G:511:0x1fe`
item will have the fake header at `chunk + 0x1fe000`. The particular physical
chunk does not matter — one of the spray items will land in
`0x7fffed000000`.

The correct B spec for CLI page 0x1fe:

```
G:511:0x1fe G:511:0x1fe G:511:0x1fe ...   (repeated until free chunks exhausted)
```

Each `G:511` item is ~2 MB. The heap reservation after request A holds ~27
chunks; a spray of 20–30 items covers them all.

---

## 5.5 Difference from the `BG(serialize)` path (doc 01)

| | `BG(serialize)` orphan (CVE-2026-109618) | `PS(id)` stale pointer (CVE-2026-109619) |
|---|---|---|
| Global orphaned | `basic_globals.serialize` (64-byte context) | `ps_globals.id` (pointer to `zend_string`) |
| OOM site | `smart_str` growth inside `php_var_serialize()` | `smart_string_appendc` in `php_session_send_cookie()` |
| OOM size | 1–4 KB (variable, body-dependent) | **4 096 B** (fixed — the `smart_string` slab) |
| Trigger for the bug | R2 progress request, pre-RINIT | R2 large-multipart POST with forge values |
| Primitive | dangling HashTable write → heap corruption | **OOB heap read** via fake `zend_string` length |
| Impact | availability (SIGABRT) | **information disclosure → full RCE chain** |
| Mitigation | `session.upload_progress.enabled=Off` | same; also `session.upload_progress.cleanup=Off` removes the trigger in B |

---

## 5.6 Source references (PHP 8.4.26)

```
main.c:1831                    PG(modules_activated) = 0
main.c:1873                    php_hash_environment()
main.c:1874                    zend_activate_modules()
main.c:1875                    PG(modules_activated) = 1
ext/session/session.c:108      php_rinit_session_globals  — sets PS(id)=NULL
ext/session/session.c:136      php_rshutdown_session_globals — releases PS(id)
ext/session/session.c:419      php_session_initialize — uses PS(id), sends cookie
ext/session/session.c:443      !PS(id) || !ZSTR_VAL(PS(id))[0] guard
ext/session/session.c:475      php_session_reset_id → php_session_send_cookie
ext/session/session.c:3308     MULTIPART_EVENT_FILE_START: php_rinit_session + PS(id)=...
ext/session/session.c:3315     PS(send_cookie) = 0
ext/session/session.c:3335     php_session_rfc1867_update (first call)
ext/session/session.c:3370     MULTIPART_EVENT_END: rfc1867_cleanup path
ext/session/session.c:3374     if (PS(rfc1867_cleanup)) php_session_rfc1867_cleanup()
ext/session/session.c:3384     php_rshutdown_session_globals()
Zend/zend_alloc.c:1498         size <= ZEND_MM_MAX_LARGE_SIZE → large alloc path
Zend/zend_alloc.c:1123         zend_mm_alloc_large_ex — returns chunk+0x1000
```
