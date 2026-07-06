# Agent Policy Gateway Dev Startup Script
# Starts both the Python backend and Next.js frontend

Write-Host "Starting Agent Policy Gateway development environment..." -ForegroundColor Cyan
Write-Host ""

# Set environment variables
$env:APG_AGENT_TOKEN = "test-token"
$env:APG_OPERATOR_EMAIL = "admin@apg.dev"
$env:APG_OPERATOR_PASSWORD = "apg-demo"
$env:APG_OPERATOR_WORKSPACE = "apg"

Write-Host "[Backend] Starting FastAPI on http://localhost:8000" -ForegroundColor Green
Start-Process -NoNewWindow powershell -ArgumentList "-Command", "cd '$PSScriptRoot'; `$env:APG_AGENT_TOKEN='test-token'; python -m uvicorn agent_policy_gateway.main:app --host 0.0.0.0 --port 8000 --reload"

Start-Sleep -Seconds 2

Write-Host "[Frontend] Starting Next.js on http://localhost:3000" -ForegroundColor Green
Write-Host ""
Write-Host "Login credentials:" -ForegroundColor Yellow
Write-Host "  Workspace: apg"
Write-Host "  Email:     admin@apg.dev"
Write-Host "  Password:  apg-demo"
Write-Host ""

Set-Location "$PSScriptRoot\frontend"
npm run dev
