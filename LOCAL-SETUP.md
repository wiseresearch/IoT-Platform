# Local run notes (Jetson AGX Orin)

Everything runs from this checkout via `docker compose`, with local fixes kept in
`docker-compose.override.yml` (upstream files stay close to pristine).

## URLs

| What | URL |
|---|---|
| Dashboard | http://localhost:8090/ |
| API gateway | http://localhost:8000/ (`/health`, `/api/...`) |
| Kibana | http://localhost:5601/ |
| Elasticsearch | http://localhost:9200/ |

## Start / stop

```bash
cd ~/IoT-Platform
docker compose up -d          # start everything
docker compose ps             # status + health
docker compose down           # stop (keeps volumes/data)
docker compose down -v        # stop and wipe DB / Elasticsearch data
```

Docker is enabled at boot, and the services use `restart: always`, so the stack
comes back by itself after a reboot.

## Why the override file exists

1. **Port 8080 was already taken** by the local llama.cpp server. The API gateway
   is published on **8000** instead (`ports: !override`).
2. **Healthchecks called `curl`, which is not installed** in any of the service
   images, so every container reported `unhealthy` while being perfectly fine.
   The override swaps them for `python -c "urllib.request..."` probes.
3. **Dashboard healthcheck** probed `localhost`, which resolves to `::1` first
   while nginx only listens on IPv4 → pinned to `127.0.0.1`.
4. **Celery worker** has no HTTP port, so its inherited check could never pass →
   replaced with `celery inspect ping`.

## LLM backend (local llama.cpp instead of Ollama/gemma)

The stack expects an Ollama server at `http://host.docker.internal:11434` and
calls `/api/generate`. No Ollama daemon or models are installed here; the local
model is **qwen3.5-9b** served by llama.cpp on `127.0.0.1:8080` (OpenAI API,
loopback-only).

`local-llm-bridge/app.py` is a stdlib-only Ollama→OpenAI facade:

- `llm_bridge` container runs with `network_mode: host` (needed to reach
  llama.cpp's loopback bind) and listens on `172.17.0.1:11434` — the address
  containers already resolve as `host.docker.internal`, and it is not routable
  from the LAN.
- Upstream code is untouched: both consumers keep `LLM_PROVIDER=ollama` and
  `LLM_BASE_URL=http://host.docker.internal:11434`; the override only sets
  `LLM_MODEL=qwen3.5-9b` on `vulnerability-scanner` and `log-llm-analyzer`.
- Thinking mode is disabled (`ENABLE_THINKING=0`) so the token budget goes to
  the answer.
- Per-request output cap defaults to 700 tokens; generation takes ~10–20 s on the
  Orin, so the gateway's device-report proxy timeout was raised from 8 s to
  `LLM_REPORT_TIMEOUT_SECONDS` (default 180) in `api-gateway/app.py`.

Verify:

```bash
curl -s http://172.17.0.1:11434/health
curl -s http://172.17.0.1:11434/api/tags
curl -s -X POST http://127.0.0.1:8000/api/vulnerabilities/general-report?include_llm=1 \
  -H 'Content-Type: application/json' \
  -d '{"ip_address":"192.168.0.1","hostname":"puma7-atom","os":"Linux","os_version":"5.X"}'
```

The response's `llm_report` should show `"provider": "ollama"`,
`"model": "qwen3.5-9b"`. CVE remediation is `GET /api/cve/<CVE-ID>/remediation`
and caches results in `cve_remediation_cache`.

## Other local patches

- `web-dashboard/index.html` — `API_BASE` was hardcoded to
  `http://localhost:8080/api`, which broke every dashboard call once the gateway
  moved off 8080 (and blocked remote access). Now relative (`/api`) so it goes
  through the nginx proxy.
- `web-dashboard/index.html` — added an `onopen` handler so the event stream
  label flips from "Connecting…" to "Connected".
- `web-dashboard/nginx.conf` — `proxy_buffering off` on `/api/` so Server-Sent
  Events are not buffered.
- `api-gateway/app.py` — the SSE generator now yields an initial
  `: connected` comment so headers flush immediately.
- `services/vulnerability-scanner/requirements.txt` — `redis==5.0.1` →
  `redis==6.4.0`. With 5.0.1, kombu raises
  `TypeError: AbstractConnection.__init__() got an unexpected keyword argument 'loop'`
  and the Celery worker dies with `exit code 1` on boot.
- `.env` — `FALLBACK_SUBNET=192.168.0.0/24` to match the actual LAN.

## Known limitations (upstream design, not fixed)

- `host_scanner_api.py` (:5555) and `host_traffic_monitor_tshark.py` (:5556) are
  Windows/WSL2 host-side helpers; they are not running here, so device discovery
  falls back to nmap from inside `network_scanner`. Result: IP + hostname + OS
  guesses work, **MAC addresses / vendors do not**, and one quiet host may be
  missed. `tshark` is also not installed on the host.
- `wsl2_scan.sh` prints logs while the API expects JSON on stdout, so even with
  `/var/run/docker.sock` mounted the "dedicated nmap container" path would not
  parse; the nmap fallback is what is in use.
