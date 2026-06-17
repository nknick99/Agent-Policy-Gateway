# KiroGate Dev Startup Script
# Starts both the Python backend and Next.js frontend

Write-Host "Starting KiroGate development environment..." -ForegroundColor Cyan
Write-Host ""

# Set environment variables
$env:KIROGATE_AGENT_TOKEN = "test-token"
$env:KIROGATE_OPERATOR_EMAIL = "admin@kirogate.dev"
$env:KIROGATE_OPERATOR_PASSWORD = "kirogate-demo"
$env:KIROGATE_OPERATOR_WORKSPACE = "kirogate"

Write-Host "[Backend] Starting FastAPI on http://localhost:8000" -ForegroundColor Green
Start-Process -NoNewWindow powershell -ArgumentList "-Command", "cd '$PSScriptRoot'; `$env:KIROGATE_AGENT_TOKEN='test-token'; python -m uvicorn kirogate.main:app --host 0.0.0.0 --port 8000 --reload"

Start-Sleep -Seconds 2

Write-Host "[Frontend] Starting Next.js on http://localhost:3000" -ForegroundColor Green
Write-Host ""
Write-Host "Login credentials:" -ForegroundColor Yellow
Write-Host "  Workspace: kirogate"
Write-Host "  Email:     admin@kirogate.dev"
Write-Host "  Password:  kirogate-demo"
Write-Host ""

Set-Location "$PSScriptRoot\frontend"
npm run dev
