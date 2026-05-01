# ============================================================================
# Asterion Network Security Auditor - Windows Setup Script
# PowerShell 5.1+
# ============================================================================

$ErrorActionPreference = "Continue"

# Display ASCII Art Banner
Write-Host ""
$asciiPath = "assets\ascii.txt"
if (Test-Path $asciiPath) {
    Get-Content $asciiPath | ForEach-Object { Write-Host $_ }
} else {
    Write-Host "============================================================"
    Write-Host "      ASTERION - Network Security Auditor Setup v0.2.0" -ForegroundColor Magenta
    Write-Host "           The Minotaur of the Argos Suite" -ForegroundColor Magenta
    Write-Host "============================================================"
}
Write-Host ""

# Check prerequisites
Write-Host "[1/6] Checking prerequisites..." -ForegroundColor Blue

# Check Python
$pythonOk = $false
try {
    $pythonVersion = python --version 2>&1
    Write-Host "  + Python detected: $pythonVersion" -ForegroundColor Green
    $pythonOk = $true
}
catch {
    Write-Host "  X Python 3 is required but not installed" -ForegroundColor Red
    Write-Host "    Install from: https://www.python.org/downloads/" -ForegroundColor Yellow
}

# Check .NET
$dotnetOk = $false
try {
    $dotnetVersion = dotnet --version 2>&1
    Write-Host "  + .NET detected: $dotnetVersion" -ForegroundColor Green
    $dotnetOk = $true
}
catch {
    Write-Host "  X .NET 8 SDK is required but not installed" -ForegroundColor Red
    Write-Host "    Install from: https://dotnet.microsoft.com/download/dotnet/8.0" -ForegroundColor Yellow
}

if (-not $pythonOk -or -not $dotnetOk) {
    Write-Host ""
    Write-Host "X Prerequisites missing. Please install required software." -ForegroundColor Red
    exit 1
}

Write-Host ""

# Install Python dependencies
Write-Host "[2/6] Installing Python dependencies..." -ForegroundColor Blue
pip install -r scripts\requirements.txt
if ($LASTEXITCODE -eq 0) {
    Write-Host "  + Python packages installed" -ForegroundColor Green
}
else {
    Write-Host "  X Failed to install Python packages" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Setup database
Write-Host "[3/6] Setting up shared database..." -ForegroundColor Blue
python scripts\db_migrate.py
if ($LASTEXITCODE -eq 0) {
    Write-Host "  + Database setup complete" -ForegroundColor Green
}
else {
    Write-Host "  X Database setup failed" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Build Asterion
Write-Host "[4/6] Building Asterion (Release mode)..." -ForegroundColor Blue
dotnet build -c Release --nologo
if ($LASTEXITCODE -eq 0) {
    Write-Host "  + Build successful" -ForegroundColor Green
}
else {
    Write-Host "  X Build failed" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Create directories
Write-Host "[5/6] Creating configuration directories..." -ForegroundColor Blue
$userProfile = $env:USERPROFILE
New-Item -ItemType Directory -Force -Path "$userProfile\.asterion\reports" | Out-Null
New-Item -ItemType Directory -Force -Path "$userProfile\.asterion\consent-proofs" | Out-Null
New-Item -ItemType Directory -Force -Path "$userProfile\.argos" | Out-Null
Write-Host "  + Created $userProfile\.asterion\reports" -ForegroundColor Green
Write-Host "  + Created $userProfile\.asterion\consent-proofs" -ForegroundColor Green
Write-Host "  + Created $userProfile\.argos" -ForegroundColor Green
Write-Host ""

# Verify installation
Write-Host "[6/7] Verifying installation..." -ForegroundColor Blue
$binaryPath = "src\Asterion\bin\Release\net8.0\ast.exe"
if (Test-Path $binaryPath) {
    Write-Host "  + Binary found: $binaryPath" -ForegroundColor Green
}
else {
    Write-Host "  ! Binary not found, build may have failed" -ForegroundColor Yellow
}
Write-Host ""

# Add to PATH (Step 7)
Write-Host "[7/7] Adding Asterion to system PATH..." -ForegroundColor Blue

$BinPath = "$(pwd)\src\Asterion\bin\Release\net8.0"
$CurrentPath = [Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::Machine)

if ($CurrentPath -notlike "*$BinPath*") {
    [Environment]::SetEnvironmentVariable(
        "Path",
        "$CurrentPath;$BinPath",
        [System.EnvironmentVariableTarget]::Machine
    )
    Write-Host "  + Asterion added to system PATH" -ForegroundColor Green
    Write-Host "  ⚠  Please restart PowerShell/CMD for changes to take effect" -ForegroundColor Yellow
}
else {
    Write-Host "  + Asterion already in PATH" -ForegroundColor Green
}
Write-Host ""

# Completion message
Write-Host "============================================================" -ForegroundColor Red
Write-Host "+ INSTALLATION COMPLETE!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Red
Write-Host ""
Write-Host "Quick Start:" -ForegroundColor Magenta
Write-Host ""
Write-Host "  1. Restart PowerShell (important!)" -ForegroundColor White
Write-Host ""
Write-Host "  2. Test localhost scan:" -ForegroundColor White
Write-Host "     ast scan --target localhost --output html" -ForegroundColor Yellow
Write-Host ""
Write-Host "  3. Scan local network:" -ForegroundColor White
Write-Host "     ast scan --target 192.168.1.0/24 --output html" -ForegroundColor Yellow
Write-Host ""
Write-Host "  4. View help:" -ForegroundColor White
Write-Host "     ast --help" -ForegroundColor Yellow
Write-Host ""
Write-Host "Documentation: README.md, docs/" -ForegroundColor White
Write-Host ""
Write-Host "============================================================" -ForegroundColor Red