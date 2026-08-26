# start-ui.ps1 -- one-command launch of the Governed Clinical Agent web UI.
# Run from anywhere:  .\scripts\start-ui.ps1   (or right-click -> Run with PowerShell)
# It boots the API, waits until it's healthy, opens http://localhost:8000/ui in your
# browser, and streams the server log. Press Ctrl+C to stop.
#
# Requires a .env with API_KEY (and a planner key, e.g. GROQ_API_KEY) at the repo root.

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$py = ".\venv311\Scripts\python.exe"
if (-not (Test-Path $py)) { $py = "python" }   # fall back to whatever python is on PATH

Write-Host "Starting Governed Clinical Agent UI -> http://localhost:8000/ui" -ForegroundColor Cyan
Write-Host "(Press Ctrl+C to stop the server)" -ForegroundColor DarkGray

# Open the browser once the server answers /health (runs in the background).
Start-Job -ArgumentList "http://localhost:8000" {
    param($base)
    for ($i = 0; $i -lt 40; $i++) {
        try { Invoke-WebRequest "$base/health" -UseBasicParsing -TimeoutSec 2 | Out-Null; Start-Process "$base/ui"; break }
        catch { Start-Sleep -Milliseconds 750 }
    }
} | Out-Null

& $py -m uvicorn app:app --host 127.0.0.1 --port 8000
