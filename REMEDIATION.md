# Remediation

For anyone who arrived here because a PHP host is aborting workers, or because
a scanner told them something vague. Start at step 1; it is one line.

**The fix:** `session.upload_progress.enabled = Off`.

That is not a workaround for a symptom, it is the removal of the vulnerable
path. The bug lives in the upload-progress handler's session cycle, which runs
during request startup. Turn the handler off and the code never runs
(`ext/session/session.c`, 8.4 `:3239` returns before `php_session_initialize()`).

---

## 1. Am I affected?

Affected means all three are true:

| # | Condition | Check |
|---|---|---|
| 1 | `session.upload_progress.enabled` is `On` | `php -i \| grep session.upload_progress` |
| 2 | `memory_limit` is low enough that a multipart part can exhaust it during request startup | see `tools/check_exposure.py` |
| 3 | the SAPI keeps the worker alive after that startup fatal (php-fpm, mod_php prefork, `php -S`) | not verifiable from outside; test on staging |

One command that checks 1 and 2 against your ini:

```bash
python3 tools/check_exposure.py                       # the ini PHP actually loads
python3 tools/check_exposure.py /etc/php/8.4/fpm/php.ini
python3 tools/check_exposure.py --ini-dir /etc/php/8.4/fpm
```

It prints `EXPOSED` or `MITIGATED` and exits `1` / `0`, so it drops into a
config check or a pipeline:

```bash
python3 tools/check_exposure.py || echo "PHP upload-progress exposure: fix me"
```

**Which SAPI you check matters.** CLI and FPM load different ini files, and
`php_value` in a vhost or a `.user.ini` overrides both. Check the SAPI that
serves traffic.

## 2. Fix it

```ini
; php.ini — or .user.ini in the document root, or a vhost include
session.upload_progress.enabled = Off
```

```apache
# Apache vhost
php_value session.upload_progress.enabled Off
```

Reload:

```bash
systemctl reload php8.4-fpm          # Debian/Ubuntu FPM
systemctl reload php-fpm             # RHEL/Fedora
apachectl graceful                   # mod_php
```

Verify:

```bash
python3 tools/check_exposure.py      # expect MITIGATED, exit 0
php -i | grep 'session.upload_progress.enabled'   # expect => Off
```

What breaks: the upload progress bar. Nothing else. File uploads, sessions and
`$_SESSION` are unaffected — `session.upload_progress` only powers the
`uploadprogress` extension's XHR progress events.

Restart the pool once after the change so you know every worker is running the
new config:

```bash
systemctl restart php8.4-fpm
```

## 3. If you cannot turn it off

Ordered by how much they actually help:

1. **Raise `memory_limit`** above your accepted worst case for multipart parsing.
   The filename inside a part is attacker-chosen and can be megabytes, so leave
   real headroom — a few hundred MB, not 16 MB.
   ```ini
   memory_limit = 256M
   ```
2. **Bound input at the edge** so a single request cannot build a huge progress
   array:
   ```ini
   upload_max_filesize = 8M
   post_max_size       = 16M
   max_file_uploads    = 5
   ```
   plus a body-size limit and a header-size limit in nginx/Apache/your CDN.
3. **Recycle workers often** so a corrupted heap is short-lived:
   ```ini
   ; php-fpm pool
   pm.max_requests = 500
   ```
4. **Test your SAPI on staging.** The public writeup reports php-fpm and
   LiteSpeed exit on the arm request, which contains the damage. Unverified
   here; confirm before relying on it.

None of these is a fix. They raise the cost of reaching the bailout or shorten
the window after it. Only step 2 does both.

## 4. Was I hit?

```bash
./tools/scan_logs.sh                                  # last 24h of journals
./tools/scan_logs.sh /var/log/php8.4-fpm.log
./tools/scan_logs.sh --since "-7 days"
```

Two lines matter, in this order, on the same worker:

```
PHP Fatal error:  Allowed memory size of 8388608 bytes exhausted
                  (tried to allocate 2002944 bytes) in Unknown on line 0
zend_mm_heap corrupted
```

- `in Unknown on line 0` — the fatal came from request startup, before any
  script was compiled. Normal application OOMs name a real file.
- `zend_mm_heap corrupted` — the Zend allocator's consistency check, followed by
  `SIGABRT` (container exit code 134, or `signal 6` in the unit log).

Read it carefully:

| What you see | What it probably means |
|---|---|
| both lines, same worker, seconds apart | the arm-then-fire sequence |
| a single `in Unknown on line 0` OOM | probe, or a legitimate huge upload |
| `zend_mm_heap corrupted` alone | usually something else — extension bug, xdebug teardown, bad opcache build |
| worker restarts with no log lines | could be OOM-killer or a supervisor, unrelated |

The tool reports counts, not conclusions. Do not open an incident on one line.

## 5. If you think you were hit

1. Apply step 2 first. It costs nothing and stops the path.
2. Preserve logs and any core files before rotation:
   `coredumpctl list php`, `coredumpctl dump php -o /var/tmp/php.core`.
3. Restart the pool so you know what is running.
4. Remember what this bug can and cannot do: **memory corruption with an
   availability effect**. There is no demonstrated code execution, no credential
   theft, no data exfiltration. If you are seeing those, look elsewhere.

## 6. Answers to the obvious questions

**Is this a CVE?** The IDs `CVE-2026-109618` / `CVE-2026-109619` are cited by a
published by the PHP security team in an advance notice dated 2026-10-20 (CVSS
v4.0 9.2 each, release 2026-10-21 14:00 UTC). Absence from NVD/MITRE only reflects
the advisory still being reserved — it is not evidence against the vulnerability.
Note also that vendor guidance says configuration alone does not neutralise both
issues; the settings below reduce exposure to the `session.upload_progress` path
specifically.

**Is it RCE?** No evidence. The writeup that describes it retracted its own RCE
chain. What is reproducible is a use-after-free that aborts a worker.

**Is my application code at fault?** No. This is request startup, before your
code runs. Patching your app will not help; the setting will.

**Does turning it off hurt performance?** No. The setting only enables the
progress-feedback feature for uploads.

**Is my PHP version affected?** The code path is old and the releases the
writeup names are 8.2.34, 8.3.35, 8.4.26 and 8.5.11. Whether *your* host is
exposed still depends on the three conditions in §1 — version alone decides
nothing.

**What should I tell my hosting provider?** Send them §1 and §2 of this file:
the setting name, the reload command, and the two log lines to grep. That is
enough for them to act without reading the exploit.

**Where is the upstream fix?** Two shapes work: clear the serializer globals when
a request is aborted before `RINIT`, or make `php_var_serialize_init()` refuse to
reuse a context it cannot prove is live. Until then, the setting is the fix.
