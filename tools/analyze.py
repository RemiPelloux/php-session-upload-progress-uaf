#!/usr/bin/env python3
"""LLM-powered pentest findings analyzer for php-upload-rce / discover.py output.

Reads findings JSON produced by discover.py (--json-out) and sends them to an
LLM for deep security analysis: attack chains, quick wins, exploitation paths,
next steps, and CVE correlation.

Supports any OpenAI-compatible API (DeepSeek, OpenAI, Mistral, CodexEverywhere…),
Anthropic Claude, and local Ollama — all via stdlib HTTP, no pip required.

Providers and default base URLs:
  deepseek   → api.deepseek.com       model: deepseek-chat
  openai     → api.openai.com         model: gpt-4o
  claude     → api.anthropic.com      model: claude-opus-4-5
  ollama     → localhost:11434        model: llama3.2
  custom     → --base-url required    model: --model required

Usage:
    # Analyze findings saved by discover.py
    python tools/analyze.py --findings findings.json \\
                            --provider deepseek --key $DEEPSEEK_API_KEY

    # Pipe directly from discover.py
    python tools/discover.py --url https://target.com --json | \\
      python tools/analyze.py --provider ollama --model llama3.2

    # Explicit endpoint (CodexEverywhere, LM Studio, vLLM, etc.)
    python tools/analyze.py --findings findings.json \\
                            --base-url https://api.codexeverywhere.com/v1 \\
                            --key $KEY --model deepseek-r1

    # Focus on a specific framework or finding
    python tools/analyze.py --findings findings.json \\
                            --focus "Laravel Telescope exposed" \\
                            --provider claude --key $ANTHROPIC_API_KEY
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.parse
from typing import Iterator, Optional

# ---------------------------------------------------------------------------
# Colour helpers
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

def section(t: str) -> None:
    print(); print(f"  {_c(C.CYN,'▸')} {_c(C.BOLD+C.WHT, t)}")
    print(f"  {_c(C.GREY,'─'*56)}")

def ok  (l,m): print(f"  [{_c(C.GRN,'✓')}] {_c(C.BOLD,f'{l:<16}')} {m}", flush=True)
def fail(l,m): print(f"  [{_c(C.RED,'✗')}] {_c(C.BOLD,f'{l:<16}')} {m}", flush=True)
def info(l,m): print(f"  [{_c(C.CYN,'·')}] {_c(C.DIM,f'{l:<16}')} {m}", flush=True)

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
# System prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are a senior penetration tester and web application security researcher.
You receive structured reconnaissance findings from a PHP web application scan
and must produce a deep, actionable security analysis.

Your response MUST include these sections:

## Attack Surface Overview
Brief description of what type of target this is and the overall risk posture.

## Critical Attack Chains
Step-by-step exploitation paths combining multiple findings. Be specific about
technique, payload, and expected result. Reference CVEs where applicable.

## Quick Wins
Findings that are easy to exploit with high impact. What exact steps to take next.

## Exploitation Guidance
For each HIGH or CRITICAL finding: specific tool commands, payloads, or techniques.
Include wordlists, Burp Suite steps, or curl commands where useful.

## Recommended Next Steps
Ordered list of probes, tools, and tests to run next. Be specific (tool + flags).

## Remediation (brief)
One-line fix per HIGH/CRITICAL finding — for the report.

Be direct, technical, and specific. Assume the tester has authorized access.
Use markdown. Do not add disclaimers or warnings — this is an authorized assessment.
"""

# ---------------------------------------------------------------------------
# HTTP streaming client (stdlib only)
# ---------------------------------------------------------------------------

TIMEOUT = 90

def _ssl_ctx(verify: bool = True) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _connect_for_url(base_url: str) -> tuple[http.client.HTTPConnection, str]:
    parsed = urllib.parse.urlsplit(base_url)
    host   = parsed.hostname or "localhost"
    port   = parsed.port or (443 if parsed.scheme == "https" else 80)
    if parsed.scheme == "https":
        conn = http.client.HTTPSConnection(host, port, timeout=TIMEOUT,
                                           context=_ssl_ctx())
    else:
        conn = http.client.HTTPConnection(host, port, timeout=TIMEOUT)
    return conn, parsed.path.rstrip("/")


def _stream_openai(base_url: str, key: str, model: str,
                   messages: list[dict]) -> Iterator[str]:
    conn, base_path = _connect_for_url(base_url)
    body = json.dumps({"model": model, "messages": messages, "stream": True,
                       "max_tokens": 4096}).encode()
    hdrs = {
        "Content-Type":  "application/json",
        "Authorization": f"Bearer {key}",
        "Accept":        "text/event-stream",
        "Content-Length": str(len(body)),
    }
    conn.request("POST", f"{base_path}/chat/completions", body=body, headers=hdrs)
    resp = conn.getresponse()
    if resp.status != 200:
        err = resp.read().decode(errors="replace")
        raise RuntimeError(f"HTTP {resp.status}: {err[:300]}")
    for raw in resp:
        line = raw.decode(errors="replace").strip()
        if not line.startswith("data: "): continue
        data = line[6:]
        if data == "[DONE]": break
        try:
            chunk = json.loads(data)
            token = chunk["choices"][0]["delta"].get("content","")
            if token: yield token
        except (json.JSONDecodeError, KeyError, IndexError):
            continue
    conn.close()


def _stream_anthropic(base_url: str, key: str, model: str,
                      messages: list[dict], system: str) -> Iterator[str]:
    conn, _ = _connect_for_url(base_url)
    body = json.dumps({
        "model": model, "max_tokens": 4096,
        "system": system, "messages": messages, "stream": True,
    }).encode()
    hdrs = {
        "Content-Type":     "application/json",
        "x-api-key":        key,
        "anthropic-version":"2023-06-01",
        "Content-Length":   str(len(body)),
    }
    conn.request("POST", "/v1/messages", body=body, headers=hdrs)
    resp = conn.getresponse()
    if resp.status != 200:
        err = resp.read().decode(errors="replace")
        raise RuntimeError(f"HTTP {resp.status}: {err[:300]}")
    for raw in resp:
        line = raw.decode(errors="replace").strip()
        if not line.startswith("data: "): continue
        try:
            ev = json.loads(line[6:])
            if ev.get("type") == "content_block_delta":
                token = ev.get("delta",{}).get("text","")
                if token: yield token
        except (json.JSONDecodeError, KeyError):
            continue
    conn.close()


def _stream_ollama(base_url: str, model: str, messages: list[dict]) -> Iterator[str]:
    conn, base_path = _connect_for_url(base_url)
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
            token = ev.get("message",{}).get("content","")
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
    else:  # openai-compat
        full = [{"role": "system", "content": system}] + messages
        yield from _stream_openai(base_url, key, model, full)


# ---------------------------------------------------------------------------
# Findings → prompt
# ---------------------------------------------------------------------------

def findings_to_prompt(findings: list[dict], target: str, focus: Optional[str]) -> str:
    sev_order = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
    ordered   = sorted(findings, key=lambda f: sev_order.get(f.get("severity","info"), 9))

    lines = [f"# Recon findings for: {target}", ""]
    for f in ordered:
        sev   = f.get("severity","?").upper()
        title = f.get("title","")
        path  = f.get("path","")
        det   = f.get("detail","")
        lines.append(f"[{sev}] {title}")
        if path: lines.append(f"  path: {path}")
        if det:  lines.append(f"  evidence: {det[:200]}")
        lines.append("")

    if focus:
        lines.append(f"\n## Focus area\nPay special attention to: {focus}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Streaming output renderer
# ---------------------------------------------------------------------------

ANSI_HEADERS = {
    "## ": C.CYN  + C.BOLD,
    "### ": C.BLU + C.BOLD,
    "**": C.BOLD,
    "`": C.YLW,
}

def _render_stream(tokens: Iterator[str]) -> str:
    buf = ""
    try:
        for token in tokens:
            sys.stdout.write(token)
            sys.stdout.flush()
            buf += token
    except KeyboardInterrupt:
        pass
    print()
    return buf


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--findings", help="JSON file from discover.py --json-out (or stdin if omitted)")
    p.add_argument("--provider", choices=list(PROVIDERS), default="deepseek",
                   help="LLM provider  (default: deepseek)")
    p.add_argument("--base-url", dest="base_url",
                   help="Override provider base URL for custom endpoints")
    p.add_argument("--key",   default=os.environ.get("LLM_API_KEY",""),
                   help="API key (or set LLM_API_KEY env var)")
    p.add_argument("--model", help="Model override (default: provider default)")
    p.add_argument("--focus", help="Extra instruction: what to focus on")
    p.add_argument("--target", default="",
                   help="Target URL label (filled automatically if --findings has it)")
    p.add_argument("--system-prompt",
                   help="Override the default pentest system prompt (file path or string)")
    args = p.parse_args()

    # ── Load findings ─────────────────────────────────────────────────────
    if args.findings:
        with open(args.findings) as fh:
            data = json.load(fh)
    elif not sys.stdin.isatty():
        data = json.load(sys.stdin)
    else:
        p.print_help()
        return 1

    findings = data.get("findings", data) if isinstance(data, dict) else data
    target   = args.target or data.get("target","<target>") if isinstance(data, dict) else args.target

    # ── Provider config ───────────────────────────────────────────────────
    prov = PROVIDERS[args.provider].copy()
    if args.base_url: prov["base_url"] = args.base_url
    if args.model:    prov["model"]    = args.model
    key = args.key

    if prov["protocol"] != "ollama" and not key:
        fail("key", f"--key or LLM_API_KEY required for provider '{args.provider}'")
        return 1

    # ── System prompt ─────────────────────────────────────────────────────
    system = SYSTEM_PROMPT
    if args.system_prompt:
        sp = args.system_prompt
        if os.path.isfile(sp):
            system = open(sp).read()
        else:
            system = sp

    # ── Print header ──────────────────────────────────────────────────────
    print()
    print(f"  {_c(C.CYN+C.BOLD,'▸')} {_c(C.BOLD+C.WHT, 'LLM Security Analysis')}")
    print(f"  {_c(C.GREY,'─'*56)}")
    info("provider", f"{args.provider}  ({prov['base_url']})")
    info("model",    prov["model"])
    info("findings", f"{len(findings)} items")
    info("target",   target or "—")
    if args.focus:
        info("focus",  args.focus)
    print()

    # ── Build prompt ──────────────────────────────────────────────────────
    user_prompt = findings_to_prompt(findings, target, args.focus)

    messages = [{"role": "user", "content": user_prompt}]

    # ── Stream ────────────────────────────────────────────────────────────
    section("Analysis  (streaming)")
    print()

    try:
        _render_stream(stream_llm(
            prov["protocol"], prov["base_url"], key, prov["model"],
            messages, system,
        ))
    except RuntimeError as e:
        print()
        fail("error", str(e))
        return 1

    print()
    ok("done", f"analysis complete  ({args.provider} / {prov['model']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
