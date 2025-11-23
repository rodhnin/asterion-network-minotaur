#!/bin/bash
# Diagnostic script for Asterion build issues
# This helps identify why dotnet build might be failing silently

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== Asterion Build Diagnostics ===${NC}"
echo ""

# Change to project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

echo -e "${BLUE}1. Environment Check${NC}"
echo "Working directory: $(pwd)"
echo "User: $(whoami)"
echo "Shell: $SHELL"
echo ""

# Check .NET
echo -e "${BLUE}2. .NET Detection${NC}"

# Try to find dotnet
DOTNET_CMD=""
if command -v dotnet &> /dev/null; then
    DOTNET_CMD="$(command -v dotnet)"
    echo -e "${GREEN}✓${NC} dotnet found in PATH: $DOTNET_CMD"
elif [ -x "$HOME/.dotnet/dotnet" ]; then
    DOTNET_CMD="$HOME/.dotnet/dotnet"
    export DOTNET_ROOT="$HOME/.dotnet"
    export PATH="$DOTNET_ROOT:$PATH"
    echo -e "${GREEN}✓${NC} dotnet found at: $DOTNET_CMD"
else
    echo -e "${RED}✗${NC} dotnet not found"
    exit 1
fi

# Test dotnet works
echo ""
echo "Testing dotnet executable..."
if "$DOTNET_CMD" --version > /dev/null 2>&1; then
    VERSION=$("$DOTNET_CMD" --version)
    echo -e "${GREEN}✓${NC} dotnet version: $VERSION"
else
    echo -e "${RED}✗${NC} dotnet executable failed to run"
    exit 1
fi

# Check DOTNET_ROOT
echo ""
if [ -n "$DOTNET_ROOT" ]; then
    echo -e "${GREEN}✓${NC} DOTNET_ROOT: $DOTNET_ROOT"
else
    echo -e "${YELLOW}⚠${NC}  DOTNET_ROOT not set (may cause issues)"
    export DOTNET_ROOT="$(dirname "$DOTNET_CMD")"
    echo "  Setting to: $DOTNET_ROOT"
fi

echo ""
echo -e "${BLUE}3. Project Files Check${NC}"

if [ -f "Asterion.sln" ]; then
    echo -e "${GREEN}✓${NC} Solution file exists: Asterion.sln"
    echo "  Size: $(stat -f%z Asterion.sln 2>/dev/null || stat -c%s Asterion.sln 2>/dev/null) bytes"
else
    echo -e "${RED}✗${NC} Asterion.sln not found"
    exit 1
fi

if [ -f "src/Asterion/Asterion.csproj" ]; then
    echo -e "${GREEN}✓${NC} Project file exists: src/Asterion/Asterion.csproj"
else
    echo -e "${RED}✗${NC} src/Asterion/Asterion.csproj not found"
    exit 1
fi

echo ""
echo -e "${BLUE}4. NuGet Restore${NC}"
echo "Running: dotnet restore..."

RESTORE_OUTPUT=$("$DOTNET_CMD" restore 2>&1)
RESTORE_EXIT=$?

if [ $RESTORE_EXIT -eq 0 ]; then
    echo -e "${GREEN}✓${NC} Restore successful"
    # Show last few lines
    echo "$RESTORE_OUTPUT" | tail -5 | sed 's/^/  /'
else
    echo -e "${RED}✗${NC} Restore failed (exit code: $RESTORE_EXIT)"
    echo ""
    echo "Full output:"
    echo "$RESTORE_OUTPUT"
    exit 1
fi

echo ""
echo -e "${BLUE}5. Build Test${NC}"
echo "Running: dotnet build -c Release -v detailed"
echo ""

# Redirect to file and terminal
BUILD_LOG="/tmp/asterion-build-$(date +%s).log"
echo "Build log will be saved to: $BUILD_LOG"
echo ""

"$DOTNET_CMD" build -c Release -v detailed 2>&1 | tee "$BUILD_LOG"
BUILD_EXIT=${PIPESTATUS[0]}

echo ""
if [ $BUILD_EXIT -eq 0 ]; then
    echo -e "${GREEN}✓${NC} Build succeeded (exit code: 0)"
else
    echo -e "${RED}✗${NC} Build failed (exit code: $BUILD_EXIT)"
fi

echo ""
echo -e "${BLUE}6. Output Files Check${NC}"

FOUND_FILES=0
for dll in "src/Asterion/bin/Release/net8.0/ast.dll" "src/Asterion/bin/Release/net8.0/Asterion.dll"; do
    if [ -f "$dll" ]; then
        echo -e "${GREEN}✓${NC} Found: $dll"
        ls -lh "$dll"
        FOUND_FILES=$((FOUND_FILES + 1))
    else
        echo -e "${RED}✗${NC} Not found: $dll"
    fi
done

echo ""
if [ $FOUND_FILES -gt 0 ]; then
    echo -e "${GREEN}=== BUILD SUCCESSFUL ===${NC}"
    echo ""
    echo "You can run Asterion with:"
    echo "  dotnet src/Asterion/bin/Release/net8.0/ast.dll --help"
else
    echo -e "${RED}=== BUILD PRODUCED NO OUTPUT FILES ===${NC}"
    echo ""
    echo "Check the build log for details: $BUILD_LOG"
fi

echo ""
echo -e "${BLUE}7. Directory Structure${NC}"
echo "Checking bin directory structure..."
find src/Asterion -type d -name "bin" -o -name "obj" | head -20
