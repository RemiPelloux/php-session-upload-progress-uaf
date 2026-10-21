# Live demo — watch one request kill a PHP worker

A small local app that reproduces the bug in a browser, with the pieces labelled.

```bash
python3 uaf_demo.py            # dashboard :8080, victim site :8081
# then open http://127.0.0.1:8080/ and press "Run the whole demo"
```

Headless check (no browser):

```bash
python3 selftest.py
```

Expected, and reproduced on PHP 8.5.11 / Arch x86_64:

```
FIRE GET /                        -> HTTP/1.1 200 OK       survives
ARM  POST filename=2,000,000 B    -> HTTP/1.1 200 OK       (memory_limit fatal inside php_var_serialize)
FIRE upload (10-byte filename)    -> connection died       zend_mm_heap corrupted, SIGABRT
```

## What the three steps actually do

1. **`GET /` survives.** The bug lives in `php_var_serialize_init()`. A plain
   read of the session never gets there: it only *unserializes*. This is why the
   second request has to be something that writes to the session.
2. **Arm.** One multipart POST with `PHP_SESSION_UPLOAD_PROGRESS` and a
   2,000,000-byte filename. PHP's rfc1867 handler serialises the upload progress
   into the session during `php_request_startup()`. `memory_limit` (8M here) is
   hit *inside* `php_var_serialize()`, `zend_bailout()` longjmps out, and
   `PHP_RINIT_FUNCTION(basic)` — the memset that would have reset
   `BG(serialize)` — never runs. `level` stays 1 and `data` points at a 64-byte
   block that `zend_mm_shutdown` has already freed.
3. **Victim upload.** Any small upload, 10-byte filename. `php_var_serialize_init()`
   sees `level != 0`, takes the reuse branch, skips `zend_hash_init()`, and
   `php_add_var_hash()` increments `data->n` at `+0x38` inside the freed block.
   `zend_mm` notices and aborts: `zend_mm_heap corrupted`.

## Why the docroot is 25 characters and lives in /tmp

The freed block is reclaimed by the `zend_string` holding `SCRIPT_FILENAME`,
allocated at `25 + len(path)`. It lands in the same 64-byte bin only when that
path is 32..39 characters, i.e. docroot 22..29. That is an accident of *this*
lab, not of the bug — on a real deployment the recycling block is whichever
startup allocation happens to be 57..64 bytes, which is why the crash is
gambling and the corruption is not.

This script is the only thing you need to read; it creates a short directory in
`/tmp` because a 70-character path under `Projects/` cannot abort, and deletes it
on exit. `--keep` leaves it for inspection.

## Knobs

| flag | default | meaning |
|---|---|---|
| `--port` | 8080 | dashboard |
| `--victim-port` | 8081 | `php -S` |
| `--keep` | off | keep the generated docroot |

Constants at the top of `uaf_demo.py`: `ARM_FILENAME` (2,000,000 at
`memory_limit=8M`; scale it with the limit — see `lab/sweep_arm.py`),
`MEM_LIMIT`, `TARGET_DOCROOT_LEN`.

## Honest limits

This shows **availability** impact: one worker, killed. It does not show code
execution. Reaching `system()` requires controlling the contents of the recycled
block, which no public writeup demonstrates either — see
`docs/03-validation.md` §"What is not proven".
