# 03 — Validation: what was run, what it proves, what would falsify it

Methodology first, claims second. Everything here is reproducible from `lab/`.

## 3.1 Environment

```
PHP 8.5.11 (cli) (built: Sep 23 2026 17:41:29) (NTS)
Linux 7.2.8-9-omarchy x86_64
php -n   (no php.ini, no extensions — xdebug excluded, see §3.6)
```

Server flags used for every run:

```
php -n -d post_max_size=64M -d upload_max_filesize=32M \
       -d session.save_path=<docroot>/sess -d memory_limit=8M \
       -d session.upload_progress.enabled=1 -d display_errors=1 \
       -S 127.0.0.1:<port> -t <docroot>      # with cwd = <docroot>
```

## 3.2 Claim → evidence table

| # | Claim | Evidence | Strength |
|---|---|---|---|
| 1 | the upload-progress session cycle runs before `RINIT(basic)` | source (`main.c:1873-1874`) + fatal message `in Unknown on line 0` | strong |
| 2 | an OOM there leaves `BG(serialize).level = 1` with a stale `data` | gdb trace, `evidence/trace-8.5.11.txt` | strong |
| 3 | the next request reuses that exact pointer without `zend_hash_init()` | same trace, same address across the boundary | strong |
| 4 | the reuse is one request wide (RINIT clears it) | trace shows a third request back at `level=0` | strong |
| 5 | the reuse can abort the worker | `evidence/poc-run.txt`, 6/6 and 2/2 repeats | medium (layout dependent) |
| 6 | the abort requires `session.upload_progress.enabled=1` | `evidence/matrix.txt` row 3 | strong |
| 7 | the abort requires the pre-RINIT fatal | `evidence/matrix.txt` rows 4-5 | strong |
| 8 | the abort depends on the 64-byte bin being recycled | `evidence/docroot-window.txt` | medium (correlational but sharp-edged) |

## 3.3 The decisive experiment

The single most convincing artefact is the gdb trace, because it needs no
allocator luck:

```
HIT init    level=0 data=(nil)            R1: fresh
HIT init    level=1 data=0x7ffff4601080   R1: nested
HIT destroy level=2 data=0x7ffff4601080   R1: → 1, never freed
HIT init    level=1 data=0x7ffff4601080   R2: SAME POINTER
HIT destroy level=2 data=0x7ffff4601080
HIT init    level=0 data=(nil)            R3: RINIT cleared it
```

If line 4 ever printed a *different* address, the mechanism would be wrong.
It does not.

How it is collected (`lab/trace.gdb`), and why those offsets:

```
basic_globals+848  BG(serialize_lock)
basic_globals+856  BG(serialize).data
basic_globals+864  BG(serialize).level
```

Offsets were derived by disassembling `php_var_serialize_init` in `/usr/bin/php`
and confirmed by observing the 0 → 1 → 2 progression during a single request.

## 3.4 Controls and what each one kills

| Control | Observed | Kills the hypothesis that… |
|---|---|---|
| `session.upload_progress.enabled=0` | arm OOMs, worker survives | …the OOM alone is enough |
| `memory_limit=64M`/`1G` | no OOM, survives | …any multipart POST triggers it |
| R2 = `GET` | survives | …any second request triggers it |
| docroot outside 22..29 | survives | …the crash is layout independent (it is not) |
| `php -n` vs default ini | different crash with xdebug | see §3.6 |

## 3.5 Falsification criteria

This finding should be considered **wrong** if any of the following is shown:

1. `BG(serialize).level` is 0 at the start of R2 (i.e. something else clears it
   earlier than `RINIT(basic)` on the tested build).
2. The pointer at R2's `php_var_serialize_init` differs from R1's.
3. `php_var_serialize_init` does call `zend_hash_init()` on the reuse branch.
4. With `session.upload_progress.enabled=1`, `memory_limit=8M` and a 2 MB
   filename, the fatal is reported against a real script filename rather than
   `Unknown on line 0` (that would mean it is not a startup bailout).
5. `session.upload_progress.enabled=0` still aborts the worker.

## 3.6 The xdebug false positive

With the distribution's php.ini (xdebug loaded), the same requests produce a
SIGSEGV whose backtrace is:

```
xdebug_hash_destroy
  ← xdebug_debugger_post_deactivate
  ← zend_post_deactivate_modules
  ← php_request_shutdown
```

That is xdebug freeing its own hash during teardown, and it is **not** this bug.
Anyone reproducing this must use `php -n` or disable xdebug, or they will
publish the wrong stack.

## 3.7 What was *not* done

- No ASAN build. No `valgrind` on the box, no PHP dev headers. The public
  writeup's "ASAN hit at `var.c:756`" could not be verified; the equivalent
  claim here rests on inspecting the reused context, not on a sanitizer report.
- No `BG(unserialize)` path. A 4 MB serialised session value was planted so the
  *decode* would OOM; R2 survived in that layout. Inconclusive.
- No php-fpm, no LiteSpeed. The writeup says those workers exit on R1; untested.
- No code execution attempt. Nothing in this path reaches a call primitive, and
  the writeup retracts that claim itself.
- No CVE coordination. The IDs are unregistered; no vendor was contacted.

## 3.8 Reproducing from scratch

```bash
cd lab
./trace.sh                                        # expect the 5 HIT lines
python3 poc.py                                    # expect FIRED
python3 poc.py --handler 0                        # expect survived
python3 sweep_docroot.py --reps 2                 # expect the 22..29 window
```

If (4) holds but `poc.py` says `survived`, you are on a build with a different
bin layout — see `02-heap-layout.md` §2.7. The trace is still valid evidence.
