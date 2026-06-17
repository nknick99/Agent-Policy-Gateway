# KiroGate Deployment Script
# Usage:
#   ./deploy.ps1 local    → docker compose up (local development)
#   ./deploy.ps1 build    → build all Docker images
#   ./deploy.ps1 push     → push images to container registry
#   ./deploy.ps1 aks      → deploy to AKS

param(
    [Parameter(Position=0)]
    [ValidateSet("local", "build", "push", "aks")]
    [string]$Action = "local"
)

$REGISTRY = $env:CONTAINER_REGISTRY ?? "kirogate.azurecr.io"
$TAG = $env:IMAGE_TAG ?? "latest"

function Build-Images {
    Write-Host "Building Docker images..." -ForegroundColor Cyan

    docker build -t "${REGISTRY}/kirogate-gateway:${TAG}" -f services/gateway/Dockerfile .
    docker build -t "${REGISTRY}/kirogate-auth:${TAG}" -f services/auth/Dockerfile .
    docker build -t "${REGISTRY}/kirogate-agent:${TAG}" -f services/agent/Dockerfile .
    docker build -t "${REGISTRY}/kirogate-frontend:${TAG}" -f services/frontend/Dockerfile .

    Write-Host "All images built." -ForegroundColor Green
}

function Push-Images {
    Write-Host "Pushing images to $REGISTRY..." -ForegroundColor Cyan

    docker push "${REGISTRY}/kirogate-gateway:${TAG}"
    docker push "${REGISTRY}/kirogate-auth:${TAG}"
    docker push "${REGISTRY}/kirogate-agent:${TAG}"
    docker push "${REGISTRY}/kirogate-frontend:${TAG}"

    Write-Host "All images pushed." -ForegroundColor Green
}

function Deploy-AKS {
    Write-Host "Deploying to AKS..." -ForegroundColor Cyan

    kubectl apply -f k8s/namespace.yaml
    kubectl apply -f k8s/secrets.yaml
    kubectl apply -f k8s/gateway-deployment.yaml
    kubectl apply -f k8s/auth-deployment.yaml
    kubectl apply -f k8s/frontend-deployment.yaml
    kubectl apply -f k8s/ingress.yaml

    Write-Host ""
    Write-Host "Deployment complete. Checking rollout status..." -ForegroundColor Green
    kubectl -n kirogate rollout status deployment/gateway --timeout=120s
    kubectl -n kirogate rollout status deployment/auth --timeout=60s
    kubectl -n kirogate rollout status deployment/frontend --timeout=60s

    Write-Host ""
    Write-Host "All services deployed:" -ForegroundColor Green
    kubectl -n kirogate get pods
}

switch ($Action) {
    "local" {
        Write-Host "Starting local development stack..." -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Services:" -ForegroundColor Yellow
        Write-Host "  Frontend:  http://localhost:3000"
        Write-Host "  Gateway:   http://localhost:8000"
        Write-Host "  Auth:      http://localhost:8001"
        Write-Host "  Agent:     http://localhost:8002"
        Write-Host "  Floci STS: http://localhost:4566"
        Write-Host "  Postgres:  localhost:5432"
        Write-Host ""
        Write-Host "Credentials:" -ForegroundColor Yellow
        Write-Host "  Email:     admin@kirogate.dev"
        Write-Host "  Password:  kirogate-demo"
        Write-Host "  Workspace: kirogate"
        Write-Host ""
        docker compose up --build
    }
    "build" { Build-Images }
    "push" { Push-Images }
    "aks" { Deploy-AKS }
}
