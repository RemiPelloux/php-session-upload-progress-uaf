#!/usr/bin/env python3
"""selftest.py — run the demo headlessly and print what the dashboard shows.

    python3 selftest.py

Starts the same two servers `uaf_demo.py` starts, drives the scripted sequence
over HTTP (not by calling functions), and prints the dashboard's log. Used to
prove the app works without a browser.
"""
import json
import threading
import time
import urllib.request
from http.server import ThreadingHTTPServer

import uaf_demo as d


def post(path):
    req = urllib.request.Request(f"http://127.0.0.1:{d_port}{path}", data=b"", method="POST")
    return json.loads(urllib.request.urlopen(req, timeout=120).read())


def get_state():
    return json.loads(urllib.request.urlopen(f"http://127.0.0.1:{d_port}/api/state", timeout=10).read())


d_port = 8099
d.start_php(8098, keep=False)
srv = ThreadingHTTPServer(("127.0.0.1", d_port), d.Handler)
threading.Thread(target=srv.serve_forever, daemon=True).start()
time.sleep(0.5)

try:
    print("initial:", {k: v for k, v in get_state().items() if k != "log"})
    print("scripted ->", post("/api/scripted"))
    time.sleep(1.2)
    s = get_state()
    print("after   :", {k: v for k, v in s.items() if k != "log"})
    print("\n--- dashboard log ---")
    print("\n".join(s["log"]))
finally:
    srv.shutdown()
    d.stop_php()
