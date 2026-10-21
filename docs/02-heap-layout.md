# 02 — Heap layout: the 64-byte bin

The UAF always happens. The **abort** only happens when the freed block is
recycled by something whose bytes make a plausible-looking HashTable fail
sanity checks. This chapter is the measured map of that.

## 2.1 Sizes

```
sizeof(php_serialize_data) = sizeof(HashTable) + 4
                           = 56 + 4 = 60  →  Zend MM size class 64
```

`zend_hash_init(…, 16, …)` also allocates the bucket array:
`16 * sizeof(Bucket)` = `16 * 32` = 512 bytes, plus the 16-byte `arHash` index.
Both are freed at `php_var_serialize_destroy()` — which never runs — and then
released by the memory manager at request shutdown along with the context.

## 2.2 What competes for the 64-byte bin in R2

R2 is a fresh request. Before `php_hash_environment()` runs, PHP CLI/server
startup has already allocated strings derived from the paths involved:

| Allocation | Size | Depends on |
|---|---|---|
| `SCRIPT_FILENAME` zend_string | `25 + len(docroot) + 10` | docroot path |
| cwd string (`getcwd`, ini search) | `25 + len(cwd)` | where the server was launched |
| the `-t` value, router path, etc. | small | command line |

A `zend_string` of payload length `L` costs `24 (header) + L + 1 (NUL)`, rounded
up to the class: `25 + L`.

For `SCRIPT_FILENAME = docroot + "/probe.php"` (10 extra chars):

```
25 + len(docroot) + 10 ∈ (56, 64]   ⟺   len(docroot) ∈ [22, 29]
```

So a docroot of 22..29 characters allocates **exactly 64 bytes** for that
string, and it is allocated early enough to take the freed context.

## 2.3 Why the path bytes are fatal

A `zend_string` writes `gc`, `h`, `len` into the first 24 bytes, then the
characters. Mapped onto `php_serialize_data`:

```
offset 0x00 .. 0x17   gc + h + len        (allocator metadata, not text)
offset 0x18 ..        "…/probe.php"       → nNumUsed, nNumOfElements, nTableSize,
                                            nInternalPointer, nNextFreeElement, pDestructor
```

`pDestructor` (0x30) becomes four ASCII characters — a wild function pointer —
and `arData` (0x10) is the string's hash field. Any `zend_hash_*` call then
walks nonsense. In practice the allocator notices first and calls
`zend_mm_panic("zend_mm_heap corrupted")`.

## 2.4 Measured window

`lab/sweep_docroot.py`, PHP 8.5.11, 2 runs per length, `cwd = docroot`:

```
# docroot sweep — base=/tmp/phpuaf-window reps=2
   20       0/2
   21       0/2
   22       2/2
   23       2/2
   24       2/2
   25       2/2
   26       2/2
   27       2/2
   28       2/2
   29       2/2
   30       0/2
   31       0/2
   32       0/2
```

Sharp on both edges, exactly one size class wide. That edge behaviour is the
strongest evidence that the mechanism is the bin, not a coincidence.

## 2.5 The cwd trap

Before the PoC was fixed, the *same code* fired from one directory and not from
another. Reason: the cwd string (`/path/to/wherever`) also competes for the bin,
so a launch directory of the wrong length pre-empts `SCRIPT_FILENAME`.

Fix, in `poc.py`:

```python
proc = subprocess.Popen(cmd, ..., cwd=docroot)
```

With the server started **inside** the docroot, the two paths are tied together
and the result is a function of `len(docroot)` alone. Any tool that claims a
reliable abort without pinning this is measuring its own launch directory.

## 2.6 Why "no abort" is not "no bug"

Layouts outside the window still produce a silent UAF:

- the context is reused without `zend_hash_init()` (gdb-visible, always),
- `data->n += 1` writes into whatever now owns the block,
- for references and shared objects, `zend_hash_index_find(&data->ht, …)` walks
  an `arData` that belongs to someone else.

That is memory corruption with no detector attached. Whether it aborts, silently
corrupts, or is inert is decided by the allocator, not by the bug.

## 2.7 Reproducing the abort on another build

1. Build/obtain PHP with `session.upload_progress` enabled.
2. Confirm the pre-RINIT fatal (`in Unknown on line 0`).
3. Run `lab/sweep_docroot.py` — if no length aborts, the allocator's bin layout
   differs; try adjusting `-d post_max_size` or the filename size so the fatal
   lands at a different point, and re-sweep.
4. If nothing aborts, fall back to `lab/trace.sh`: the reuse is the finding, the
   abort is the demo.

The public writeup reports the same shape of problem ("per-build heap grooming,
glibc 2.39 vs 2.36"), which is consistent with what is measured here.
