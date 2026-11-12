#!/usr/bin/env python3
"""Ollama-API facade in front of the local llama.cpp server.

Why: the IoT-Platform services (vulnerability-scanner, log-llm-analyzer) only
speak Ollama's `/api/generate`. llama.cpp exposes an OpenAI-compatible
`/v1/chat/completions` instead. This bridge accepts the Ollama calls and
translates them, so no upstream code has to change.

Listens on the docker0 gateway (172.17.0.1) only: containers reach it through
`host.docker.internal:host-gateway`, and it is not routable from the LAN.
"""

import json
import os
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LLAMA_URL = os.getenv("LLAMA_URL", "http://127.0.0.1:8080").rstrip("/")
BIND_HOST = os.getenv("BIND_HOST", "172.17.0.1")
BIND_PORT = int(os.getenv("BIND_PORT", "11434"))
MODEL_ALIAS = os.getenv("MODEL_ALIAS", "qwen3.5-9b")
DEFAULT_MAX_TOKENS = int(os.getenv("DEFAULT_MAX_TOKENS", "700"))
READ_TIMEOUT = int(os.getenv("READ_TIMEOUT_SECONDS", "600"))
ENABLE_THINKING = os.getenv("ENABLE_THINKING", "0") == "1"


def log(msg):
    print(f"[llm-bridge] {time.strftime('%H:%M:%S')} {msg}", flush=True)


def llama_chat(messages, temperature, max_tokens, top_p=None, stop=None):
    payload = {
        "model": MODEL_ALIAS,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": False,
        "chat_template_kwargs": {"enable_thinking": ENABLE_THINKING},
    }
    if top_p is not None:
        payload["top_p"] = top_p
    if stop:
        payload["stop"] = stop

    req = urllib.request.Request(
        f"{LLAMA_URL}/v1/chat/completions",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=READ_TIMEOUT) as resp:
        return json.loads(resp.read().decode())


def extract_text(result):
    choice = (result.get("choices") or [{}])[0]
    msg = choice.get("message") or {}
    text = (msg.get("content") or "").strip()
    if not text:
        text = (msg.get("reasoning_content") or "").strip()
    return text, choice.get("finish_reason"), (result.get("usage") or {})


class Handler(BaseHTTPRequestHandler):
    server_version = "ollama-shim/1.0"

    def log_message(self, format, *args):  # silence default per-request stderr noise
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw.decode() or "{}")

    def do_GET(self):
        if self.path in ("/health", "/api/health"):
            try:
                with urllib.request.urlopen(f"{LLAMA_URL}/health", timeout=5) as r:
                    ok = r.getcode() == 200
                self._send(200 if ok else 503, {"status": "ok" if ok else "upstream_unhealthy"})
            except Exception as exc:
                self._send(503, {"status": "upstream_down", "error": str(exc)})
            return
        if self.path == "/api/tags":
            self._send(200, {
                "models": [{
                    "name": MODEL_ALIAS, "model": MODEL_ALIAS, "modified_at": "",
                    "size": 0, "digest": "", "details": {"format": "gguf", "family": "qwen"},
                }]
            })
            return
        if self.path == "/api/version":
            self._send(200, {"version": "0.0.0-llama-cpp-bridge"})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path not in ("/api/generate", "/api/chat"):
            self._send(404, {"error": "not found"})
            return
        try:
            req = self._read_json()
            options = req.get("options") or {}
            temperature = float(options.get("temperature", 0.1))
            max_tokens = int(options.get("num_predict") or DEFAULT_MAX_TOKENS)
            max_tokens = max(32, min(max_tokens, 4096))
            top_p = options.get("top_p")
            stop = options.get("stop")

            if self.path == "/api/chat":
                messages = req.get("messages") or []
                if not any(m.get("role") == "user" for m in messages):
                    messages = messages + [{"role": "user", "content": "Continue."}]
            else:
                messages = [{"role": "user", "content": str(req.get("prompt") or "")}]

            requested_model = req.get("model") or MODEL_ALIAS
            started = time.time()
            result = llama_chat(messages, temperature, max_tokens, top_p, stop)
            text, finish, usage = extract_text(result)

            # Qwen sometimes spends the whole budget on reasoning and returns an
            # empty content field. One retry with a larger budget fixes that.
            if not text and finish == "length" and max_tokens < 4096:
                result = llama_chat(messages, temperature, min(max_tokens * 2, 4096), top_p, stop)
                text, finish, usage = extract_text(result)

            took = time.time() - started
            log(f"{self.path} model={requested_model} -> {MODEL_ALIAS} "
                f"tokens={usage.get('completion_tokens')} {took:.1f}s finish={finish}")

            if not text:
                self._send(502, {"error": "empty completion from llama.cpp"})
                return

            if self.path == "/api/generate":
                self._send(200, {
                    "model": requested_model, "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "response": text, "done": True, "done_reason": finish or "stop",
                    "eval_count": usage.get("completion_tokens"),
                })
            else:
                self._send(200, {
                    "model": requested_model, "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "message": {"role": "assistant", "content": text},
                    "done": True, "done_reason": finish or "stop",
                    "eval_count": usage.get("completion_tokens"),
                })
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:300]
            log(f"upstream HTTP {exc.code}: {detail}")
            self._send(502, {"error": f"llama.cpp HTTP {exc.code}", "detail": detail})
        except Exception as exc:
            log(f"error: {exc}")
            self._send(502, {"error": str(exc)})


if __name__ == "__main__":
    log(f"listening on {BIND_HOST}:{BIND_PORT} -> {LLAMA_URL} (model {MODEL_ALIAS}, thinking={ENABLE_THINKING})")
    ThreadingHTTPServer((BIND_HOST, BIND_PORT), Handler).serve_forever()
