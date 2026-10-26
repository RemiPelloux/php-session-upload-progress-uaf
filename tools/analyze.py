#!/usr/bin/env python3
"""LLM exploit assistant for CVE-2026-109619 (PHP session.upload_progress RCE).

Reads findings JSON from discover.py and asks the LLM to assess exploitability,
recommend scanner profiles, and identify blockers — focused solely on
CVE-2026-109619.  Generic pentest analysis is out of scope.

Supports any OpenAI-compatible API (DeepSeek, CodexEverywhere, OpenAI…),
Anthropic Claude, and local Ollama — all via stdlib HTTP, no pip required.

Usage:
    python tools/analyze.py --findings findings.json \\
        --provider deepseek --key $DEEPSEEK_API_KEY

    python tools/discover.py --url https://target.com --json | \\
        python tools/analyze.py --provider ollama --model llama3.2

    python tools/analyze.py --findings findings.json \\
        --base-url https://codex-everywhere.com/v1 \\
        --key $KEY --model deepseek-flash
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import ssl
import sys
import urllib.parse
from typing import Iterator, Optional

# ---------------------------------------------------------------------------
# Colour
# ---------------------------------------------------------------------------

class C:
    RST  = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED  = "\033[38;5;196m"; GRN  = "\033[38;5;82m";  YLW = "\033[38;5;220m"
    CYN  = "\033[38;5;51m";  BLU  = "\033[38;5;69m";  MAG = "\033[38;5;171m"
    WHT  = "\033[97m";       GREY = "\033[38;5;245m";  ORAN = "\033[38;5;208m"

    @staticmethod
    def on() -> bool:
        return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

def _c(code: str, text: str) -> str:
    return f"{code}{text}{C.RST}" if C.on() else text

# ---------------------------------------------------------------------------
# Tree UI
# ---------------------------------------------------------------------------

def tree_start(title: str, subtitle: str = "") -> None:
    sub = f"  {_c(C.GREY, subtitle)}" if subtitle else ""
    print(f"\n  {_c(C.CYN+C.BOLD,'╭─')} {_c(C.WHT+C.BOLD, title)}{sub}", flush=True)

def tree_row(key: str, val: str) -> None:
    print(f"  {_c(C.GREY,'│')}  {_c(C.DIM, f'{key:<16}')} {val}", flush=True)

def tree_end(msg: str = "") -> None:
    tail = f"  {_c(C.GREY, msg)}" if msg else ""
    print(f"  {_c(C.CYN,'╰─')}{tail}", flush=True)

def err(msg: str) -> None:
    print(f"  {_c(C.RED+C.BOLD,'✗')} {msg}", file=sys.stderr, flush=True)

# ---------------------------------------------------------------------------
# Providers
# ---------------------------------------------------------------------------

PROVIDERS: dict[str, dict] = {
    "deepseek": {
        "base_url":   "https://api.deepseek.com/v1",
        "model":      "deepseek-chat",
        "protocol":   "openai",
    },
    "openai": {
        "base_url":   "https://api.openai.com/v1",
        "model":      "gpt-4o",
        "protocol":   "openai",
    },
    "claude": {
        "base_url":   "https://api.anthropic.com",
        "model":      "claude-opus-4-5",
        "protocol":   "anthropic",
    },
    "ollama": {
        "base_url":   "http://localhost:11434",
        "model":      "llama3.2",
        "protocol":   "ollama",
    },
}

# ---------------------------------------------------------------------------
# System prompt — CVE-2026-109619 only
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are an exploit developer specializing in CVE-2026-109619, the PHP
session.upload_progress stale PS(id) pointer use-after-free vulnerability.

SCOPE: Your analysis is ONLY about CVE-2026-109619. Do not analyse other
vulnerabilities, attack chains, or general pentest findings. If a finding is
unrelated to this CVE, skip it.

CVE-2026-109619 SUMMARY:
- Affects PHP's built-in CLI web server (php -S …) only — NOT php-fpm or mod_php.
- Requires session.upload_progress.enabled = On (default On in CLI server).
- Vulnerable PHP versions: 8.4.0–8.4.26, 8.3.0–8.3.35, 8.2.0–8.2.34.
- Attack: craft a multipart upload with a session name that triggers OOM during
  session cleanup, leaving a dangling PS(id) pointer; subsequent request races
  to read/write freed memory, achieving arbitrary code execution.

PREREQUISITES (all must be true to be exploitable):
1. Server runs php -S (CLI server), not php-fpm/apache/nginx+fpm.
2. PHP version in vulnerable range above.
3. session.upload_progress.enabled = On.
4. Target is reachable and accepts POST/multipart requests.

Your response MUST use these exact sections:

## Exploitability
Rate: LIKELY VULNERABLE / POSSIBLY VULNERABLE / NOT VULNERABLE / UNKNOWN
Explain which prerequisites are confirmed, missing, or unknown based on findings.

## Scanner command
Provide the exact command to run php-upload-rce-scanner.py against this target,
including any --delay or --workers flags appropriate to the target. Example:
  python3 ~/Projects/pentest/tools/php-upload-rce-scanner.py \\
    --url https://target.com --allow-remote

## Profile hints
Based on detected PHP version, suggest which exploit profile to try first
(e.g. alpine-8.4.26) and any heap_delta or worker_count tuning notes.

## Blockers
List what would prevent exploitation (e.g. "php-fpm detected — CVE does not apply",
"PHP version appears patched", "session.upload_progress status unknown").
If no blockers, write "None identified — proceed to scanner phase."

Be concise and technical. No disclaimers. Assume authorized access.
"""

# ---------------------------------------------------------------------------
# HTTP streaming
# ---------------------------------------------------------------------------

TIMEOUT = 90

def _ssl_ctx() -> ssl.SSLContext:
    return ssl.create_default_context()

def _connect(base_url: str) -> tuple[http.client.HTTPConnection, str]:
    parsed = urllib.parse.urlsplit(base_url)
    host = parsed.hostname or "localhost"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if parsed.scheme == "https":
        conn = http.client.HTTPSConnection(host, port, timeout=TIMEOUT,
                                           context=_ssl_ctx())
    else:
        conn = http.client.HTTPConnection(host, port, timeout=TIMEOUT)
    return conn, parsed.path.rstrip("/")


def _stream_openai(base_url: str, key: str, model: str,
                   messages: list[dict]) -> Iterator[str]:
    conn, base_path = _connect(base_url)
    body = json.dumps({"model": model, "messages": messages, "stream": True,
                       "max_tokens": 2048}).encode()
    hdrs = {
        "Content-Type":   "application/json",
        "Authorization":  f"Bearer {key}",
        "Accept":         "text/event-stream",
        "Content-Length": str(len(body)),
    }
    conn.request("POST", f"{base_path}/chat/completions", body=body, headers=hdrs)
    resp = conn.getresponse()
    if resp.status != 200:
        raw = resp.read().decode(errors="replace")
        raise RuntimeError(f"HTTP {resp.status} from {base_url}\n{raw[:400]}")

    token_count = 0
    raw_buf = b""
    for raw in resp:
        raw_buf += raw
        line = raw.decode(errors="replace").strip()
        if not line.startswith("data: "): continue
        data = line[6:]
        if data == "[DONE]": break
        try:
            chunk = json.loads(data)
            delta = (chunk.get("choices", [{}])[0].get("delta", {})
                     or chunk.get("choices", [{}])[0].get("message", {}))
            token = delta.get("content", "")
            if token:
                token_count += 1
                yield token
        except (json.JSONDecodeError, KeyError, IndexError):
            continue
    conn.close()
    if token_count == 0:
        preview = raw_buf[:600].decode(errors="replace")
        raise RuntimeError(
            f"Stream returned 0 tokens from {base_url}\n"
            f"Raw response preview:\n{preview}\n\n"
            f"Possible causes:\n"
            f"  • Wrong base URL — try without /v1: {base_url.replace('/v1','')}\n"
            f"  • Model name wrong — check provider docs for exact model ID\n"
            f"  • API key invalid or quota exceeded"
        )


def _stream_anthropic(base_url: str, key: str, model: str,
                      messages: list[dict], system: str) -> Iterator[str]:
    conn, _ = _connect(base_url)
    body = json.dumps({
        "model": model, "max_tokens": 2048,
        "system": system, "messages": messages, "stream": True,
    }).encode()
    hdrs = {
        "Content-Type":      "application/json",
        "x-api-key":         key,
        "anthropic-version": "2023-06-01",
        "Content-Length":    str(len(body)),
    }
    conn.request("POST", "/v1/messages", body=body, headers=hdrs)
    resp = conn.getresponse()
    if resp.status != 200:
        raw = resp.read().decode(errors="replace")
        raise RuntimeError(f"HTTP {resp.status}: {raw[:300]}")
    for raw in resp:
        line = raw.decode(errors="replace").strip()
        if not line.startswith("data: "): continue
        try:
            ev = json.loads(line[6:])
            if ev.get("type") == "content_block_delta":
                token = ev.get("delta", {}).get("text", "")
                if token: yield token
        except (json.JSONDecodeError, KeyError):
            continue
    conn.close()


def _stream_ollama(base_url: str, model: str, messages: list[dict]) -> Iterator[str]:
    conn, base_path = _connect(base_url)
    body = json.dumps({"model": model, "messages": messages, "stream": True}).encode()
    hdrs = {"Content-Type": "application/json", "Content-Length": str(len(body))}
    conn.request("POST", f"{base_path}/api/chat", body=body, headers=hdrs)
    resp = conn.getresponse()
    if resp.status != 200:
        raise RuntimeError(f"Ollama HTTP {resp.status}")
    for raw in resp:
        line = raw.decode(errors="replace").strip()
        if not line: continue
        try:
            ev = json.loads(line)
            token = ev.get("message", {}).get("content", "")
            if token: yield token
        except json.JSONDecodeError:
            continue
    conn.close()


def stream_llm(protocol: str, base_url: str, key: str, model: str,
               messages: list[dict], system: str) -> Iterator[str]:
    if protocol == "anthropic":
        yield from _stream_anthropic(base_url, key, model, messages, system)
    elif protocol == "ollama":
        yield from _stream_ollama(base_url, model, messages)
    else:
        full = [{"role": "system", "content": system}] + messages
        yield from _stream_openai(base_url, key, model, full)

# ---------------------------------------------------------------------------
# Findings → prompt
# ---------------------------------------------------------------------------

def findings_to_prompt(findings: list[dict], target: str) -> str:
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    ordered = sorted(findings, key=lambda f: sev_order.get(f.get("severity", "info"), 9))
    lines = [f"# Recon findings for: {target}", ""]
    for f in ordered:
        sev   = f.get("severity", "?").upper()
        title = f.get("title", "")
        path  = f.get("path", "")
        det   = f.get("detail", "")
        lines.append(f"[{sev}] {title}")
        if path: lines.append(f"  path: {path}")
        if det:  lines.append(f"  evidence: {det[:200]}")
        lines.append("")
    return "\n".join(lines)

# ---------------------------------------------------------------------------
# Streaming renderer
# ---------------------------------------------------------------------------

def _render_stream(tokens: Iterator[str]) -> None:
    try:
        for token in tokens:
            sys.stdout.write(token)
            sys.stdout.flush()
    except KeyboardInterrupt:
        pass
    print()

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--findings", help="JSON file from discover.py --json-out (or stdin)")
    p.add_argument("--provider", choices=list(PROVIDERS), default="deepseek")
    p.add_argument("--base-url", dest="base_url", help="Custom LLM base URL")
    p.add_argument("--key",   default=os.environ.get("LLM_API_KEY", ""))
    p.add_argument("--model", help="Model override")
    p.add_argument("--target", default="", help="Target URL label")
    p.add_argument("--system-prompt",
                   help="Override system prompt (file path or inline string)")
    args = p.parse_args()

    # Load findings
    if args.findings:
        with open(args.findings) as fh:
            data = json.load(fh)
    elif not sys.stdin.isatty():
        data = json.load(sys.stdin)
    else:
        p.print_help(); return 1

    findings = data.get("findings", data) if isinstance(data, dict) else data
    target   = (args.target or
                (data.get("target", "<target>") if isinstance(data, dict) else args.target))

    # Provider
    prov = PROVIDERS[args.provider].copy()
    if args.base_url: prov["base_url"] = args.base_url
    if args.model:    prov["model"]    = args.model
    key = args.key

    if prov["protocol"] != "ollama" and not key:
        err(f"--key or LLM_API_KEY required for provider '{args.provider}'")
        return 1

    # System prompt
    system = SYSTEM_PROMPT
    if args.system_prompt:
        sp = args.system_prompt
        system = open(sp).read() if os.path.isfile(sp) else sp

    # Banner
    tree_start("CVE-2026-109619", "LLM exploit assistant")
    tree_row("provider",  f"{args.provider}  ·  {prov['base_url']}")
    tree_row("model",     prov["model"])
    tree_row("target",    target or "—")
    tree_row("findings",  str(len(findings)))
    tree_end("streaming …")
    print()

    # Stream
    user_prompt = findings_to_prompt(findings, target)
    messages = [{"role": "user", "content": user_prompt}]

    try:
        _render_stream(stream_llm(
            prov["protocol"], prov["base_url"], key, prov["model"],
            messages, system,
        ))
    except RuntimeError as e:
        print()
        err(str(e))
        return 1

    print()
    tree_start("done")
    tree_row("provider",  f"{args.provider} / {prov['model']}")
    tree_end()
    return 0


if __name__ == "__main__":
    sys.exit(main())
