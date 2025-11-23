#!/bin/bash
# Asterion - Interactive Deployment Script
# Helps users deploy the network security scanner

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Print banner
echo ""
echo "========================================"
echo "  Asterion - Network Security Auditor"
echo "  Docker Deployment Helper"
echo "========================================"
echo ""

# Function to print colored messages
print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is available
if ! docker compose version &> /dev/null; then
    print_error "Docker Compose is not available. Please install Docker Compose."
    exit 1
fi

print_success "Docker and Docker Compose are available"
echo ""

# Ask user what they want to deploy
echo "What would you like to deploy?"
echo ""
echo "  1) Production - Asterion Scanner (for network security auditing)"
echo "  2) Stop all services"
echo "  3) Remove all containers and data (reset)"
echo ""
read -p "Enter your choice (1-3): " choice

case $choice in
    1)
        print_info "Deploying Asterion Scanner (Production)..."
        echo ""

        cd "$(dirname "$0")"
        mkdir -p ./reports ./data ./logs ./workspace ./consent-proofs

        # Check for .env file
        if [ ! -f .env ]; then
            print_warning ".env file not found. Creating from .env.example..."
            if [ -f .env.example ]; then
                cp .env.example .env
                print_info "Please edit .env file with your API keys if you plan to use AI features"
            fi
        fi

        docker compose up -d

        echo ""
        print_success "Asterion Scanner deployed successfully!"
        echo ""
        print_info "Usage:"
        echo "  docker compose exec asterion dotnet /app/ast.dll scan --target <IP/CIDR/DOMAIN>"
        echo ""
        print_info "Examples:"
        echo "  docker compose exec asterion dotnet /app/ast.dll scan --target 192.168.1.0/24"
        echo "  docker compose exec asterion dotnet /app/ast.dll scan --target 10.0.0.5 --output html"
        echo "  docker compose exec asterion dotnet /app/ast.dll scan --target corp.local --auth \"DOMAIN\\user:pass\""
        echo ""
        print_info "View logs:"
        echo "  docker compose logs -f asterion"
        echo ""
        print_info "Reports will be saved to: ./reports/"
        print_info "Database location: ./data/argos.db"
        echo ""
        print_warning "IMPORTANT: Only scan networks you own or have written permission to test!"
        ;;

    2)
        print_info "Stopping all services..."
        echo ""

        cd "$(dirname "$0")"

        if docker compose ps -q 2>/dev/null | grep -q .; then
            print_info "Stopping Asterion..."
            docker compose down
        else
            print_info "No running services found"
        fi

        echo ""
        print_success "All services stopped"
        ;;

    3)
        print_warning "WARNING: This will remove ALL containers and data!"
        print_warning "Reports and database will be PERMANENTLY DELETED!"
        echo ""
        read -p "Are you sure? Type 'DELETE' to confirm: " confirm

        if [ "$confirm" != "DELETE" ]; then
            print_info "Reset cancelled."
            exit 0
        fi

        print_info "Removing all containers and data..."
        echo ""

        cd "$(dirname "$0")"

        # Remove containers and volumes
        if docker compose ps -q 2>/dev/null | grep -q . || docker compose ps -a -q 2>/dev/null | grep -q .; then
            print_info "Removing Asterion containers..."
            docker compose down -v
        fi

        # Remove data directories
        if [ -d "./data" ]; then
            print_info "Removing ./data directory..."
            rm -rf ./data
        fi

        if [ -d "./reports" ]; then
            print_info "Removing ./reports directory..."
            rm -rf ./reports
        fi

        if [ -d "./logs" ]; then
            print_info "Removing ./logs directory..."
            rm -rf ./logs
        fi

        if [ -d "./workspace" ]; then
            print_info "Removing ./workspace directory..."
            rm -rf ./workspace
        fi

        echo ""
        print_success "All containers and data removed"
        ;;

    *)
        print_error "Invalid choice. Please run the script again."
        exit 1
        ;;
esac

echo ""
echo "========================================"
echo ""
