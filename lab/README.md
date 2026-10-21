# Lab

Reproducer for the pre-RINIT session-encode OOM → orphaned `BG(serialize)` →
next-request use-after-free. Measured on **PHP 8.5.11 (Arch, cli-server)**.

Loopback only. See the top-level `README.md` for the mechanism.

## Files

| File | Role |
|---|---|
| `probe.php` | Victim endpoint. Deliberately inert — the bug is in request startup, before it is compiled. |
| `poc.py` | Arm + fire, prints PASS/FAIL. Portable. |
| `trace.sh` + `trace.gdb` | Deterministic half: show `BG(serialize)` surviving the request boundary. |
| `matrix.sh` | Control matrix (handler off, no OOM, wrong docroot length). |
| `sweep_docroot.py` | Maps the abort against docroot length (the 64-byte bin). |

## Run

```bash
./matrix.sh          # 2 FIRED, 4 survived
./trace.sh           # gdb proof, no allocator luck needed
python3 poc.py       # single run, tuned docroot (len 28)
python3 poc.py --handler 0     # control
python3 sweep_docroot.py --reps 2
```

## The three ingredients

1. `session.upload_progress.enabled=1` — otherwise the callback returns before
   touching the session (`session.c`, 8.4 `:3239`).
2. `memory_limit` low enough that the ~2 MB filename inside `progress->data`
   cannot be serialised. The fatal fires in `php_hash_environment()`, i.e.
   before `PHP_RINIT_FUNCTION(basic)`.
3. A docroot of **22..29** characters, so the freed 64-byte `php_serialize_data`
   is recycled by the `SCRIPT_FILENAME` zend_string
   (`25 + len(docroot) + 10` bytes → 64-byte class).

`poc.py` pins (3) automatically and spawns the server with `cwd = docroot`,
because a competing cwd string of the "right" size otherwise steals the block
and the crash silently disappears.

## Expected output

`poc.py`:

```
docroot      : len=28  (tuned)
R1 arm       : HTTP/1.1 200 OK  oom=limit=8388608 alloc=2002944
R2 fire      : <connection died>
worker       : died (exit -6, signal 6)
log          : zend_mm_heap corrupted
VERDICT      : FIRED — heap corrupted by the reused serialize context
```

`trace.sh`:

```
HIT init    level=0 data=(nil)            R1 fresh
HIT init    level=1 data=0x...1080        R1 nested
HIT destroy level=2 data=0x...1080        R1 → level 1, never freed
HIT init    level=1 data=0x...1080        R2 SAME pointer, no zend_hash_init
HIT destroy level=2 data=0x...1080
HIT init    level=0 data=(nil)            RINIT finally clears it
```

## Gotcha

Run with `php -n`. With xdebug loaded the SIGSEGV comes from
`xdebug_hash_destroy` ← `zm_post_zend_deactivate_xdebug` — xdebug's own
teardown, not this bug.
