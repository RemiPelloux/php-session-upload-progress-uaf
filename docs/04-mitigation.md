# 04 — Mitigation, detection, hardening

The bug is in request startup, so there is no application-level code fix. What
follows is ordered by how quickly it can be deployed, not by elegance.

## 4.1 Stopgap — turn the feature off

```ini
; php.ini, .user.ini, or a per-vhost include
session.upload_progress.enabled = Off
```

```apache
# Apache
php_value session.upload_progress.enabled Off
```

Reload the SAPI after the change (`systemctl reload php-fpm`, `apachectl
graceful`, …).

Why it works: `php_session_rfc1867_callback()` returns before it can reach
`php_session_initialize()` / `php_session_flush()`
(`ext/session/session.c`, 8.4 `:3239`). No pre-RINIT serialisation, no orphaned
state, nothing to reuse.

Verified here: with the handler off, the arm request still exhausts
`memory_limit`, and the worker survives (`evidence/matrix.txt`). So the setting
removes *this* path, not the OOM.

Cost: the upload progress bar stops working. If you need it, see 4.2 and 4.3.

## 4.2 Make the pre-RINIT fatal impossible

The OOM comes from serialising an array that contains the uploaded **filename**.
The filename length is chosen by the client, so the peak size is unbounded:

```ini
; raise the ceiling above the worst case you will accept
memory_limit = 256M

; and bound the input so the ceiling is actually a bound
upload_max_filesize = 8M
post_max_size       = 16M
max_file_uploads    = 5
```

Note the asymmetry: `upload_max_filesize` limits the *file*, while the progress
array carries the *name*, which can be megabytes by itself. Cap both, and cap
the number of parts at the edge (WAF / reverse proxy) if you can.

This is a mitigation, not a fix — a large enough filename still reaches the
bailout, it just costs the attacker more bytes.

## 4.3 Detect exploitation attempts

Two log lines, in this order, on the same worker:

```
PHP Fatal error:  Allowed memory size of 8388608 bytes exhausted
                  (tried to allocate 2002944 bytes) in Unknown on line 0
zend_mm_heap corrupted
```

Signature notes:

- `in Unknown on line 0` — no script was compiled; the failure is in request
  startup. Any `memory_limit` fatal with a real filename is ordinary
  application behaviour.
- `zend_mm_heap corrupted` — the Zend allocator's consistency check, followed by
  `SIGABRT`. In a container this shows up as exit code 134 or `signal 6` on the
  worker.
- A single `Unknown on line 0` OOM is a probe; the abort usually follows on the
  **next** upload-progress request to the same process.

Useful greps:

```bash
journalctl -u php-fpm --since -1h | grep -E 'in Unknown on line 0|zend_mm_heap corrupted'
grep -E 'Unknown on line 0' /var/log/php*-fpm.log
```

Count them per worker PID. One is noise; a rising count is someone probing.

## 4.4 Reduce blast radius

- Prefer SAPIs that reap the worker on a startup bailout. The public writeup
  reports php-fpm and LiteSpeed exit on the arm request, which contains the
  damage. **Not verified in this lab** — test your own build before relying on
  it.
- Run pools with a low `pm.max_requests`, so a compromised heap is short-lived.
- Do not rely on seccomp/AppArmor alone: the impact here is memory corruption in
  the interpreter itself, before any application code runs.

## 4.5 Upstream fix shape

Two reasonable fixes, either is sufficient:

1. **Clean up on bailout.** Whatever path resets `BG(serialize)` /
   `BG(unserialize)` should also run when a request is aborted before RINIT, or
   the rfc1867 callback should refuse to serialise before the request is
   properly started.
2. **Make the cache self-validating.** `php_var_serialize_init()` should not
   trust `level != 0`; a context that is not provably live for *this* request
   must be re-initialised (`zend_hash_init`) rather than reused.

While waiting: keep `session.upload_progress.enabled = Off` unless the feature
is genuinely needed, and pin your PHP packages so the fix arrives with a
deliberate upgrade.

## 4.6 Verification checklist after applying the stopgap

```bash
php -i | grep 'session.upload_progress.enabled'    # expect Off
curl -s -o /dev/null -w '%{http_code}\n' https://your-host/   # sanity
```

Then run `lab/poc.py --handler 0` against a staging copy of your config: it
should report `survived` while still printing the `memory_limit` fatal.
