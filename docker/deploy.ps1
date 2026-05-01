# Asterion - Interactive Deployment Script (Windows PowerShell)
# Helps users deploy the network security scanner

$ErrorActionPreference = "Stop"

# Colors for output
function Write-Info { Write-Host "[INFO] $args" -ForegroundColor Blue }
function Write-Success { Write-Host "[SUCCESS] $args" -ForegroundColor Green }
function Write-Warning { Write-Host "[WARNING] $args" -ForegroundColor Yellow }
function Write-Error { Write-Host "[ERROR] $args" -ForegroundColor Red }

# Print banner
Write-Host ""
Write-Host "========================================"
Write-Host "  Asterion - Network Security Auditor"
Write-Host "  Docker Deployment Helper"
Write-Host "========================================"
Write-Host ""

# Check if Docker is installed
try {
    $null = docker --version
    Write-Success "Docker is available"
} catch {
    Write-Error "Docker is not installed. Please install Docker Desktop first."
    Write-Host "Download from: https://www.docker.com/products/docker-desktop"
    exit 1
}

# Check if Docker Compose is available
try {
    $null = docker compose version
    Write-Success "Docker Compose is available"
} catch {
    Write-Error "Docker Compose is not available. Please update Docker Desktop."
    exit 1
}

Write-Host ""

# Ask user what they want to deploy
Write-Host "What would you like to deploy?"
Write-Host ""
Write-Host "  1) Production - Asterion Scanner (for network security auditing)"
Write-Host "  2) Stop all services"
Write-Host "  3) Remove all containers and data (reset)"
Write-Host ""
$choice = Read-Host "Enter your choice (1-3)"

switch ($choice) {
    "1" {
        Write-Info "Deploying Asterion Scanner (Production)..."
        Write-Host ""

        $scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
        Set-Location $scriptPath

        # Create directories
        $dirs = @("./reports", "./data", "./logs", "./workspace", "./consent-proofs")
        foreach ($dir in $dirs) {
            if (-not (Test-Path $dir)) {
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
            }
        }

        # Check for .env file
        if (-not (Test-Path ".env")) {
            Write-Warning ".env file not found. Creating from .env.example..."
            if (Test-Path ".env.example") {
                Copy-Item ".env.example" ".env"
                Write-Info "Please edit .env file with your API keys if you plan to use AI features"
            }
        }

        docker compose up -d

        Write-Host ""
        Write-Success "Asterion Scanner deployed successfully!"
        Write-Host ""
        Write-Info "Usage:"
        Write-Host "  docker compose exec asterion dotnet /app/ast.dll scan --target <IP/CIDR/DOMAIN>"
        Write-Host ""
        Write-Info "Examples:"
        Write-Host "  docker compose exec asterion dotnet /app/ast.dll scan --target 192.168.1.0/24"
        Write-Host "  docker compose exec asterion dotnet /app/ast.dll scan --target 10.0.0.5 --output html"
        Write-Host "  docker compose exec asterion dotnet /app/ast.dll scan --target corp.local --auth `"DOMAIN\user:pass`""
        Write-Host ""
        Write-Info "View logs:"
        Write-Host "  docker compose logs -f asterion"
        Write-Host ""
        Write-Info "Reports will be saved to: .\reports\"
        Write-Info "Database location: .\data\argos.db"
        Write-Host ""
        Write-Warning "IMPORTANT: Only scan networks you own or have written permission to test!"
    }

    "2" {
        Write-Info "Stopping all services..."
        Write-Host ""

        $scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
        Set-Location $scriptPath

        $running = docker compose ps -q 2>$null
        if ($running) {
            Write-Info "Stopping Asterion..."
            docker compose down
        } else {
            Write-Info "No running services found"
        }

        Write-Host ""
        Write-Success "All services stopped"
    }

    "3" {
        Write-Warning "WARNING: This will remove ALL containers and data!"
        Write-Warning "Reports and database will be PERMANENTLY DELETED!"
        Write-Host ""
        $confirm = Read-Host "Are you sure? Type 'DELETE' to confirm"

        if ($confirm -ne "DELETE") {
            Write-Info "Reset cancelled."
            exit 0
        }

        Write-Info "Removing all containers and data..."
        Write-Host ""

        $scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
        Set-Location $scriptPath

        # Remove containers and volumes
        $containers = docker compose ps -a -q 2>$null
        if ($containers) {
            Write-Info "Removing Asterion containers..."
            docker compose down -v
        }

        # Remove data directories
        $dirs = @("./data", "./reports", "./logs", "./workspace")
        foreach ($dir in $dirs) {
            if (Test-Path $dir) {
                Write-Info "Removing $dir directory..."
                Remove-Item -Path $dir -Recurse -Force
            }
        }

        Write-Host ""
        Write-Success "All containers and data removed"
    }

    default {
        Write-Error "Invalid choice. Please run the script again."
        exit 1
    }
}

Write-Host ""
Write-Host "========================================"
Write-Host ""
