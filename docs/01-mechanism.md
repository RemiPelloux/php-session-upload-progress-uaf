# 01 — Mechanism, from source

Every line reference below was read from `php-src` branches **PHP-8.4** and
**PHP-8.5**. Where they differ, both are given (8.4 first).

Everything here is one causal chain:

> the multipart parser runs before `RINIT` → the upload-progress handler
> serialises a session there → the serialiser can OOM there → the bailout skips
> the only cleanup → the next request reuses the freed context.

---

## 1.1 Request startup order

`main.c`, `php_request_startup()`:

```c
1803: zend_result php_request_startup(void)
...
1871:  if (PG(auto_globals_jit)) { ... }        /* not yet */
1873:      php_hash_environment();
1874:      zend_activate_modules();
```

`php_hash_environment()` is where `multipart/form-data` is parsed and where
`php_rfc1867_callback` is invoked. `zend_activate_modules()` is where every
module's `RINIT` runs — including the one that clears the serialiser.

The window between 1873 and 1874 is therefore a window in which arbitrary
session work can happen while the serialiser globals are still **uninitialised
or stale**.

| Step | Who | Serializer globals |
|---|---|---|
| process start | `php_module_startup` | zeroed once |
| request 1 startup, `php_hash_environment` | rfc1867 callback | **stale from the previous request, if any** |
| request 1 startup, `zend_activate_modules` → `RINIT(basic)` | basic_functions | `memset` → clean |
| request 1 body | user script | in use, balanced |
| request 1 end | `RSHUTDOWN`/`zend_deactivate` | destroy, level → 0 |

The interesting line is the second one: at that moment the globals carry
whatever the previous request left behind. Normally `RSHUTDOWN` leaves them
clean, so nobody notices. The bailout path is what breaks that invariant.

## 1.2 The handler does a full session cycle inside the parser

`ext/session/session.c`, `php_session_rfc1867_callback()` (8.4 `:3231`,
8.5 `:3006`):

```c
if (php_session_rfc1867_orig_callback) {
    retval = php_session_rfc1867_orig_callback(event, event_data, extra);
}
if (!PS(rfc1867_enabled)) {
    return retval;                       /* ← the stopgap, see ch. 04 */
}
progress = PS(rfc1867_progress);
switch (event) {
...
case MULTIPART_EVENT_FILE_START: {
    ...
    if (Z_ISUNDEF(progress->data)) {
        array_init(&progress->data);
        array_init(&progress->files);
        add_assoc_long_ex(&progress->data, "start_time", ...);
        add_assoc_long_ex(&progress->data, "content_length", ...);
        add_assoc_long_ex(&progress->data, "bytes_processed", ...);
        add_assoc_bool_ex(&progress->data, "done", ...);
        add_assoc_zval_ex(&progress->data, "files", ..., &progress->files);
        ...
        php_rinit_session(0);            /* session subsystem init, pre-RINIT */
        PS(id) = zend_string_init(...);
```

and later, once the file's name is known:

```c
php_session_initialize();                /* decode the existing session file */
PS(session_status) = php_session_active;
IF_SESSION_VARS() {
    zval *sess_var = Z_REFVAL(PS(http_session_vars));
    SEPARATE_ARRAY(sess_var);
    progress->cancel_upload |= php_check_cancel_upload(progress);
    Z_TRY_ADDREF(progress->data);        /* 8.4 :3213 / 8.5 :2988 */
    zend_hash_update(Z_ARRVAL_P(sess_var), progress->key.s, &progress->data);
}
php_session_flush(1);                    /* → php_session_encode() */
```

Two observations:

1. `php_session_flush(1)` **writes** the session, so an encode happens here.
2. `php_session_initialize()` **reads** the session, so a decode happens here too.

Both are `php_var_serialize_*` operations executed before `RINIT(basic)`.

The array being encoded contains the progress structure, which includes the
uploaded file's name. That name is attacker-chosen and, in this PoC, ~2 MB.

## 1.3 The encode path

`php_session_encode()` (8.4 `:255`) walks `$_SESSION` and calls
`php_var_serialize()`, which calls `php_var_serialize_init()` (`var.c`):

```c
PHPAPI void php_var_serialize_init(void)
{
    if (basic_globals->serialize_lock || basic_globals->serialize.level) {
        return;                                  /* reuse the cached context */
    }
    basic_globals->serialize.data = emalloc(sizeof(php_serialize_data));
    zend_hash_init(&basic_globals->serialize.data->ht, 16, NULL,
                   ZVAL_PTR_DTOR, 0);
    basic_globals->serialize.level = 1;
}
```

So the first (outer) serialisation allocates a 64-byte `php_serialize_data`
and initialises its `HashTable` with 16 buckets and `ZVAL_PTR_DTOR`.
Nested serialisations reuse it and bump `level`.

`php_var_serialize()` then encodes every value. For arrays and objects it calls
`php_add_var_hash()` (`var.c`, 8.4 `:750`), whose first statement is:

```c
data->n += 1;                                   /* 8.4 :756 */
```

`data` is the context from above. `n` lives at offset `0x38`.

When the value does not fit, `smart_str` growth runs into `memory_limit` and
`zend_error_noreturn(E_ERROR, …)` fires — a `zend_bailout`, i.e. `longjmp`.

## 1.4 The cleanup that never runs

`ext/standard/basic_functions.c`:

```c
8.4 :389 / 8.5 :390   PHP_RINIT_FUNCTION(basic)
8.4 :393 / 8.5 :394   {
8.4 :394 / 8.5 :395       memset(&BG(serialize),   0, sizeof(BG(serialize)));
8.4 :395 / 8.5 :396       memset(&BG(unserialize), 0, sizeof(BG(unserialize)));
```

Because the bailout happens **before** `zend_activate_modules()`, this `memset`
never executes for that request, and because it is a `longjmp` out of the
serialiser, `php_var_serialize_destroy()` never runs either.

End state after R1:

| Global | Value |
|---|---|
| `BG(serialize).level` | `1` (never decremented, never zeroed) |
| `BG(serialize).data` | pointer to a 64-byte block |
| the block | released by `zend_mm_shutdown()` at request end |

## 1.5 The next request reuses it

R2 startup, same order: `php_hash_environment()` → rfc1867 callback →
`php_session_flush(1)` → `php_var_serialize_init()`:

```c
if (basic_globals->serialize_lock || basic_globals->serialize.level) {
    return;                    /* level == 1 → stale pointer returned as-is */
}
```

No `emalloc`, and crucially no `zend_hash_init()`. The caller then writes
through `data->ht`: `nNumUsed`, `arData`, `pDestructor` are whatever the freed
block now contains.

Three outcomes are possible, all observed or reasoned:

| Reclaimed by | Result |
|---|---|
| the `SCRIPT_FILENAME` string of R2 | path bytes become HashTable fields → allocator trips (`zend_mm_heap corrupted`) |
| a similar-size allocation with benign bytes | silent UAF read/write, no crash |
| nothing yet (block still intact) | silently "works" on freed memory |

## 1.6 Why exactly one request

`RINIT(basic)` of R2 runs **after** `php_hash_environment()`, but it does run.
So it memsets the globals at the end of the vulnerable window. R3 is clean:

```
R2 init level=1  ← exploited
R2 RINIT        ← memset, level=0
R3 init level=0  ← fresh allocation, normal
```

This is why the writeup calls it "one shot", and why the PoC needs no loop.

## 1.7 Where the public writeup differs

| Public claim | This lab |
|---|---|
| "ASAN-confirmed at `var.c:756`" | not reproducible here (no ASAN build); the same defect is shown by inspecting the reused context in gdb |
| "prefork-only; `php -S` untested" | `php -S` reproduces both the reuse and the abort |
| Bug U = `BG(unserialize)` orphan | the `BG(serialize)` orphan is what reproduces; the unserialize half did not crash here |
| kill receipt = SIGSEGV | `zend_mm_heap corrupted` → SIGABRT (exit 134 / -6) |
| "cached-pointer chain" = RCE | retracted by the writeup itself (`Z_TRY_ADDREF` at `session.c:3213` keeps the array alive). Consistent with source; not re-tested |
| two CVE IDs | assigned and reserved; announced by the PHP security team 2026-10-20, so absent from NVD until publication |

## 1.8 Reading list

```
main.c:1873                          php_hash_environment before zend_activate_modules
ext/session/session.c:3231 (8.4)     php_session_rfc1867_callback
ext/session/session.c:3213 (8.4)     Z_TRY_ADDREF(progress->data)
ext/session/session.c:3239 (8.4)     rfc1867_enabled stopgap
ext/session/session.c:255  (8.4)     php_session_encode
ext/standard/basic_functions.c:389   PHP_RINIT_FUNCTION(basic) memset
ext/standard/var.c:750               php_add_var_hash, n += 1 at :756
```
