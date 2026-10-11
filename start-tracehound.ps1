<#
.SYNOPSIS
  Start TraceHoundAI locally: backend API (127.0.0.1:8100) + Vite frontend.
.NOTES
  Port 8000 is reserved by Windows on this machine, so the backend uses 8100
  and frontend/vite.config.js already proxies /api and /health there.
  Run from the project root. Existing servers on those ports are left alone.
#>
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $root

function Test-PortFree($port) {
  -not (Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue)
}

# --- backend ---------------------------------------------------------------
$backendPort = 8100
if (Test-PortFree $backendPort) {
  Write-Output "Starting backend on 127.0.0.1:$backendPort ..."
  Start-Process -FilePath "$root\.venv\Scripts\python.exe" `
    -ArgumentList "-m", "uvicorn", "backend.main:app",
      "--host", "127.0.0.1", "--port", "$backendPort" `
    -WorkingDirectory $root -WindowStyle Minimized
  Start-Sleep -Seconds 8
} else {
  Write-Output "Port $backendPort already in use - reusing the running backend."
}
try {
  $health = Invoke-RestMethod -Uri "http://127.0.0.1:$backendPort/health" -TimeoutSec 15
  Write-Output ("Backend: " + $health.status + " at http://127.0.0.1:$backendPort/health")
} catch {
  Write-Output "WARNING: backend did not answer. Check the Python window for errors."
}

# --- frontend --------------------------------------------------------------
$vite = Get-Process -Name node -ErrorAction SilentlyContinue | Where-Object {
  (Get-CimInstance Win32_Process -Filter ("ProcessId = " + $_.Id) -ErrorAction SilentlyContinue).CommandLine -match "vite"
}
if ($vite) {
  Write-Output "A Vite frontend is already running - reusing it."
} else {
  Write-Output "Starting frontend (npm run dev) ..."
  Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "npm run dev" `
    -WorkingDirectory "$root\frontend" -WindowStyle Minimized
  Start-Sleep -Seconds 12
}

Write-Output ""
Write-Output "TraceHoundAI is ready:"
Write-Output "  Backend:  http://127.0.0.1:$backendPort/health"
Write-Output "  Frontend: http://localhost:5173/ (or the port Vite printed)"
Write-Output "Enter the authorized root domain, check the box, and click START SCAN."
