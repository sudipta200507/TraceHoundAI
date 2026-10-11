# TraceHoundAI

Authorized laboratory reconnaissance-to-report platform: enter one root
domain, confirm authorization, and the pipeline discovers assets, live
hosts, ports, services, technologies, endpoints, screenshots, and
vulnerability observations — then Qwen3 8B (local Ollama) analyzes the
evidence and produces validated Markdown + PDF reports.

## Quick start (Windows, PowerShell)

```powershell
# From the project root — starts backend (127.0.0.1:8100) and frontend:
.\start-tracehound.ps1
```

Then open the printed frontend URL (usually http://localhost:5173),
enter the authorized root domain, check the authorization box, and click
START SCAN. Track progress on the scan page and download the reports
when it completes.

> Port 8000 is reserved by Windows on this machine, so the backend uses
> port 8100 and the Vite dev proxy already forwards to it.

## Manual start

Backend (project root, virtualenv Python):

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8100
```

Frontend (second terminal):

```powershell
cd frontend
npm run dev
```

Health checks:

```powershell
Invoke-RestMethod http://127.0.0.1:8100/health
.\.venv\Scripts\python.exe scripts/health_check.py
```

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest tests/ -q   # backend (mocked tools + live Ollama test)
cd frontend
npm test      # frontend (mocked API)
npm run lint
npm run build
```

## Safety model (short version)

- Every scan gets an **ephemeral scope**: the entered root domain plus its
  subdomains only. `scope.yaml` is never edited per scan.
- Active stages (ports, services, Nuclei) run only for explicitly
  authorized scans; exploitation is never available.
- The LLM analyzes evidence only — it cannot run tools, invent evidence,
  or mark findings verified. Deterministic validators enforce this.
- Only scan targets you are explicitly authorized to assess.
