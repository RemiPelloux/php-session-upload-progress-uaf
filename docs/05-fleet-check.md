# Checking a fleet of hosts

`tools/phpshell_check.py` classifies a list of hostnames against the PHP2Shell
bug class (CVE-2026-109618 / CVE-2026-109619). Written for people who are
responsible for the sites they point it at.

```bash
python3 tools/phpshell_check.py --targets sites.txt                 # passive, ~4 KB
python3 tools/phpshell_check.py --targets sites.txt --cap           # + body-limit probe
python3 tools/phpshell_check.py --targets sites.txt --with-producer \
    --authorized-owner "Acme Ltd (SOW 2026-10)" --json out.json
```

`sites.txt`, one URL per line, `#` starts a note:

```
https://www.example.com/
https://shop.example.com/       # owner: Acme, authorisation: email 2026-10-21
```

## Stages

| stage | flag | requests | what it does |
|---|---|---|---|
| 1 fingerprint | default | 2–4 | headers, PHP cookies, and `/<rand>.php` vs `/<rand>` to see if a PHP handler answers |
| 2 body limit | `--cap` | 2–10 | declares `Content-Length` and waits: `Expect: 100-continue` with **no body sent** |
| 3 producer | `--with-producer` | 2 | one small upload, then one arm-sized upload; looks for "request startup died" |

Stage 3 is memory pressure against a live host. It refuses to run without
`--authorized-owner`, sends exactly one oversized request per host, never
retries, and never runs in parallel. Stage 1+2 are a few kilobytes in total and
are safe to run anywhere you can run `curl`.

## Verdicts

| verdict | meaning | action |
|---|---|---|
| `PATCH_NOW` | vulnerable release answering, or startup dies on an oversized upload | upgrade to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12, restart FPM/Apache |
| `SAFE_PATCHED` | release `>=` first fixed for its branch | none for this bug class; PHP 8.2 is EOL 2026-12-31 |
| `EXPOSED_EDGE` | PHP present, release hidden, edge accepts >= 70 MB | identify the runtime, then patch or treat as vulnerable |
| `LIKELY_SAFE_CAP` | PHP present, release hidden, edge refuses bodies below the arm size | keep the limit; re-check if `client_max_body_size` is raised |
| `PHP_PRESENT_VERSION_HIDDEN` | PHP detected, no limit information | run `--cap`, then `--with-producer` on staging |
| `NOT_PHP_DETECTED` | no PHP marker and `.php` is not handled differently | find the real backend host before closing |
| `UNREACHABLE` | DNS/TLS/connection failure | fix and re-run |

## Reading stage 3

Three outcomes, all meaningful:

1. **Fatal text returned** (`Allowed memory size of N bytes exhausted`) — the
   request startup died and the host prints its limit. Worst case: also an
   information-disclosure finding. The tool extracts `N`.
2. **`502`/`503`/connection reset after the arm** — the worker was killed
   mid-request. The OOM producer is reachable and one request per attempt can
   take a child down. This alone is an availability finding.
3. **Normal application answer** — startup survived at that size. Either the
   limit is higher than the arm, the body limit is below it, or the build is
   patched. Not proof of absence: at a higher `memory_limit` the arm must scale
   (`~0.3 x memory_limit`, measured band 68–88 MB at 256 MB).

A patched host can also die at the new hard limit, so "worker died" is a
*producer reachable* signal, not a version signal. Version beats behaviour.

## Notes from real runs

| target | stage 1–2 | stage 3 | verdict |
|---|---|---|---|
| static Next.js site (Vercel) | no PHP marker, `.php` handled identically | skipped | `NOT_PHP_DETECTED` |
| Magento on nginx, 1 MiB body cap | PHP present, 2 MiB refused | skipped (arm impossible) | `LIKELY_SAFE_CAP` |
| Laravel on FPM behind envoy, 256 MB cap | PHP present via `laravel_session` cookie, `expose_php=Off` | 70 MB filename -> `502 Bad Gateway` | `PATCH_NOW` |
| local PHP 8.5.11, 256 MB | version disclosed | 70 MB filename -> fatal text with `268435456` | `PATCH_NOW` |

Two lessons baked into the tool:

- `x-powered-by` is usually off in production. Cookies (`laravel_session`,
  `PHPSESSID`, `private_content_version`, `XSRF-TOKEN`, `wordpress_*`) and
  `.php`-vs-plain extension handling are what actually identify PHP.
- A body-limit probe only means something when a PHP backend is behind the
  edge. Static hosts answer `100 Continue` for any declared length.
