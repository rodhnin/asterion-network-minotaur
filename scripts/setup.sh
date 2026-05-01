#!/bin/bash
# ============================================================================
# Asterion Network Security Auditor - Installation Script
# Part of the Argos Security Suite
#
# Author: Rodney Dhavid Jimenez Chacin (rodhnin)
# License: MIT
# ============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# ============================================================================
# CHANGE TO PROJECT ROOT IF RUNNING FROM scripts/
# ============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Change to project root
cd "$PROJECT_ROOT"

echo -e "${BLUE}[Setup]${NC} Running from: $PROJECT_ROOT"
echo ""

# ============================================================================
# DISPLAY BANNER
# ============================================================================
display_banner() {
    # Try to load ASCII art from file
    if [ -f "assets/ascii.txt" ]; then
        cat assets/ascii.txt
    else
        echo ""
        echo "════════════════════════════════════════════════════════════════"
        echo -e "${PURPLE}            Network Security Auditor - Setup v0.2.0 ${NC}"
        echo -e "${PURPLE}              The Minotaur of the Argos Suite${NC}"
        echo "════════════════════════════════════════════════════════════════"
    fi
    echo ""
}

# Display banner
display_banner

# Detect OS
OS="unknown"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    echo -e "${GREEN}✓${NC} Detected OS: Linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    echo -e "${GREEN}✓${NC} Detected OS: macOS"
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
    OS="windows"
    echo -e "${GREEN}✓${NC} Detected OS: Windows (Git Bash/Cygwin)"
else
    echo -e "${RED}✗${NC} Unknown OS: $OSTYPE"
    echo "This script supports Linux, macOS, and Windows (via Git Bash)"
    exit 1
fi

echo ""

# ============================================================================
# STEP 1: Check Prerequisites
# ============================================================================
echo -e "${BLUE}[1/8]${NC} Checking prerequisites..."

# Check Python 3
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}✗${NC} Python 3 is required but not installed"
    echo "  Install from: https://www.python.org/downloads/"
    exit 1
fi
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo -e "${GREEN}✓${NC} Python 3 detected: $PYTHON_VERSION"

# Check pip
if ! command -v pip3 &> /dev/null; then
    echo -e "${RED}✗${NC} pip3 is required but not installed"
    exit 1
fi
echo -e "${GREEN}✓${NC} pip3 detected"

# Check .NET 8 and configure DOTNET_ROOT if needed
DOTNET_CONFIGURED=false
DOTNET_EXEC=""

# First check if dotnet is in PATH
if command -v dotnet &> /dev/null; then
    DOTNET_EXEC="$(command -v dotnet)"
    # Resolve symlinks to get the real path
    if [ -L "$DOTNET_EXEC" ]; then
        DOTNET_EXEC="$(readlink -f "$DOTNET_EXEC")"
    fi

    # Verify the executable is not empty/corrupted
    if [ ! -s "$DOTNET_EXEC" ]; then
        echo -e "${RED}✗${NC} .NET executable found but is empty or corrupted: $DOTNET_EXEC"
        echo "  File size: $(stat -c%s "$DOTNET_EXEC" 2>/dev/null || stat -f%z "$DOTNET_EXEC" 2>/dev/null) bytes"
        echo ""
        echo "  The dotnet executable appears to be corrupted."
        echo "  Please reinstall .NET SDK:"
        echo ""
        echo "    rm -rf ~/.dotnet"
        echo "    wget https://dot.net/v1/dotnet-install.sh"
        echo "    chmod +x dotnet-install.sh"
        echo "    ./dotnet-install.sh --channel 8.0"
        echo "    export DOTNET_ROOT=\$HOME/.dotnet"
        echo "    export PATH=\$DOTNET_ROOT:\$PATH"
        exit 1
    fi

    # Test that it actually works
    if ! "$DOTNET_EXEC" --version &> /dev/null; then
        echo -e "${RED}✗${NC} .NET executable found but doesn't work: $DOTNET_EXEC"
        echo "  Please reinstall .NET SDK (see above)"
        exit 1
    fi

    # Set DOTNET_ROOT based on the executable location
    export DOTNET_ROOT="$(dirname "$DOTNET_EXEC")"
    echo -e "${GREEN}✓${NC} .NET found in PATH: $DOTNET_EXEC"
    echo "  DOTNET_ROOT set to: $DOTNET_ROOT"
else
    # Try common .NET installation paths
    echo "  Searching for .NET in common locations..."
    DOTNET_PATHS=(
        "$HOME/.dotnet/dotnet"
        "/usr/share/dotnet/dotnet"
        "/usr/local/share/dotnet/dotnet"
        "/opt/dotnet/dotnet"
    )

    for DOTNET_PATH in "${DOTNET_PATHS[@]}"; do
        if [ -x "$DOTNET_PATH" ]; then
            # Verify the executable is not empty/corrupted
            if [ ! -s "$DOTNET_PATH" ]; then
                echo -e "${YELLOW}⚠${NC}  Found dotnet at $DOTNET_PATH but it's empty (0 bytes), skipping..."
                continue
            fi

            # Test that it works
            if ! "$DOTNET_PATH" --version &> /dev/null; then
                echo -e "${YELLOW}⚠${NC}  Found dotnet at $DOTNET_PATH but it doesn't work, skipping..."
                continue
            fi

            export DOTNET_ROOT="$(dirname "$DOTNET_PATH")"
            # Put DOTNET_ROOT first in PATH so it takes precedence
            export PATH="$DOTNET_ROOT:$DOTNET_ROOT/tools:$PATH"
            DOTNET_CONFIGURED=true
            DOTNET_EXEC="$DOTNET_PATH"
            echo -e "${GREEN}✓${NC} .NET found at: $DOTNET_ROOT"
            break
        fi
    done

    # If still not found, do a comprehensive system search (slower but thorough)
    if [ -z "$DOTNET_EXEC" ]; then
        echo "  Performing deep search for dotnet..."

        # Search in common SDK locations
        for sdk_path in "$HOME/.dotnet/sdk"/*/ "/usr/share/dotnet/sdk"/*/ "/usr/local/share/dotnet/sdk"/*/; do
            if [ -d "$sdk_path" ]; then
                # Found SDK, check for dotnet executable in parent
                parent_dir="$(dirname "$(dirname "$sdk_path")")"
                if [ -x "$parent_dir/dotnet" ]; then
                    # Verify not empty/corrupted
                    if [ ! -s "$parent_dir/dotnet" ]; then
                        echo -e "${YELLOW}⚠${NC}  Found SDK at $sdk_path but dotnet is empty, skipping..."
                        continue
                    fi

                    # Test that it works
                    if ! "$parent_dir/dotnet" --version &> /dev/null; then
                        echo -e "${YELLOW}⚠${NC}  Found SDK at $sdk_path but dotnet doesn't work, skipping..."
                        continue
                    fi

                    DOTNET_EXEC="$parent_dir/dotnet"
                    export DOTNET_ROOT="$parent_dir"
                    export PATH="$DOTNET_ROOT:$DOTNET_ROOT/tools:$PATH"
                    DOTNET_CONFIGURED=true
                    echo -e "${GREEN}✓${NC} .NET found via SDK search: $DOTNET_ROOT"
                    break
                fi
            fi
        done
    fi

    if [ -z "$DOTNET_EXEC" ]; then
        echo -e "${RED}✗${NC} .NET 8 SDK is required but not installed"
        echo ""
        echo "  Install from: https://dotnet.microsoft.com/download/dotnet/8.0"
        echo ""
        echo "  Quick install for Linux:"
        echo "    wget https://dot.net/v1/dotnet-install.sh"
        echo "    chmod +x dotnet-install.sh"
        echo "    ./dotnet-install.sh --channel 8.0"
        echo "    export DOTNET_ROOT=\$HOME/.dotnet"
        echo "    export PATH=\$DOTNET_ROOT:\$DOTNET_ROOT/tools:\$PATH"
        echo ""
        echo "  After installation, add to ~/.bashrc:"
        echo "    echo 'export DOTNET_ROOT=\$HOME/.dotnet' >> ~/.bashrc"
        echo "    echo 'export PATH=\$DOTNET_ROOT:\$PATH' >> ~/.bashrc"
        echo "    source ~/.bashrc"
        exit 1
    fi
fi

# Get .NET version using the detected executable
if [ -n "$DOTNET_EXEC" ]; then
    # Set DOTNET_ROOT for this invocation if not already set
    if [ -z "$DOTNET_ROOT" ]; then
        export DOTNET_ROOT="$(dirname "$DOTNET_EXEC")"
    fi

    # Get version with proper environment
    DOTNET_VERSION=$("$DOTNET_EXEC" --version 2>&1 | grep -E '^[0-9]' | head -1 | tr -d '\r\n' | xargs)

    # If that failed, try getting SDK version
    if [ -z "$DOTNET_VERSION" ] || [[ ! "$DOTNET_VERSION" =~ ^[0-9] ]]; then
        # Try to extract from SDK directory
        if [ -d "$DOTNET_ROOT/sdk" ]; then
            DOTNET_VERSION=$(ls "$DOTNET_ROOT/sdk" 2>/dev/null | grep -E '^[0-9]' | sort -V | tail -1)
        fi
    fi
else
    DOTNET_VERSION=$(dotnet --version 2>&1 | grep -E '^[0-9]' | head -1 | tr -d '\r\n' | xargs)
fi

# Extract just the version number if possible
if [[ $DOTNET_VERSION =~ ([0-9]+\.[0-9]+\.[0-9]+) ]]; then
    DOTNET_VERSION="${BASH_REMATCH[1]}"
fi

if [ -n "$DOTNET_VERSION" ] && [[ "$DOTNET_VERSION" =~ ^[0-9] ]]; then
    echo -e "${GREEN}✓${NC} .NET version: $DOTNET_VERSION"

    # Check if .NET 8 specifically (version starts with 8)
    if [[ ! $DOTNET_VERSION =~ ^8\. ]]; then
        echo -e "${YELLOW}⚠${NC}  .NET version is not 8.x, some features may not work"
        echo "  Recommended: .NET 8.0.x"
    fi
else
    echo -e "${YELLOW}⚠${NC}  Could not detect .NET version"
    echo "  Continuing anyway, but build may fail if not .NET 8.x"
fi

# Configure DOTNET_ROOT permanently if we just set it
if [ "$DOTNET_CONFIGURED" = true ]; then
    echo ""
    echo -e "${BLUE}[Config]${NC} Configuring .NET environment variables..."

    # Add to ~/.bashrc if not already there
    if ! grep -q "DOTNET_ROOT" ~/.bashrc 2>/dev/null; then
        echo "" >> ~/.bashrc
        echo "# .NET Configuration (added by Asterion installer)" >> ~/.bashrc
        echo "export DOTNET_ROOT=\$HOME/.dotnet" >> ~/.bashrc
        echo "export PATH=\$DOTNET_ROOT:\$DOTNET_ROOT/tools:\$PATH" >> ~/.bashrc
        echo -e "${GREEN}✓${NC} Added DOTNET_ROOT to ~/.bashrc"
        echo -e "${YELLOW}⚠${NC}  Run 'source ~/.bashrc' or restart your terminal to apply changes"
    else
        echo -e "${GREEN}✓${NC} DOTNET_ROOT already configured in ~/.bashrc"
    fi
fi

echo ""

# ============================================================================
# STEP 2: Install Python Dependencies
# ============================================================================
echo -e "${BLUE}[2/8]${NC} Installing Python dependencies..."

if [ -f "scripts/requirements.txt" ]; then
    # Check if virtual environment is active
    if [ -n "$VIRTUAL_ENV" ]; then
        echo -e "${GREEN}✓${NC} Virtual environment detected: $VIRTUAL_ENV"
        
        # Install packages (show output if fails)
        if pip install -r scripts/requirements.txt > /tmp/asterion_pip_install.log 2>&1; then
            echo -e "${GREEN}✓${NC} Python packages installed successfully"
        else
            echo -e "${RED}✗${NC} Failed to install Python packages"
            echo ""
            echo "Installation log:"
            cat /tmp/asterion_pip_install.log
            echo ""
            echo "Try manually:"
            echo "  pip install langchain langchain-openai langchain-anthropic langchain-community"
            exit 1
        fi
    else
        echo -e "${YELLOW}⚠${NC}  No virtual environment active"
        echo "  Creating virtual environment..."

        # Create venv if it doesn't exist
        if [ ! -d ".venv" ]; then
            if python3 -m venv .venv 2>&1; then
                echo -e "${GREEN}✓${NC} Virtual environment created: .venv"
            else
                echo -e "${RED}✗${NC} Failed to create virtual environment"
                echo ""
                echo "This may be due to missing python3-venv package."
                echo "Install with:"
                echo "  sudo apt install python3-venv  # Debian/Ubuntu"
                echo "  sudo dnf install python3-venv  # Fedora"
                echo "  sudo yum install python3-venv  # RHEL/CentOS"
                exit 1
            fi
        fi

        # Activate and install (use venv's pip directly)
        if [ -f ".venv/bin/pip" ]; then
            # Use the venv's pip directly to avoid externally-managed-environment errors
            if .venv/bin/pip install -r scripts/requirements.txt > /tmp/asterion_pip_install.log 2>&1; then
                echo -e "${GREEN}✓${NC} Python packages installed successfully"
            else
                echo -e "${RED}✗${NC} Failed to install Python packages"
                echo ""
                echo "Installation log:"
                cat /tmp/asterion_pip_install.log
                echo ""
                exit 1
            fi

            # Activate the venv for subsequent commands
            source .venv/bin/activate
        else
            echo -e "${RED}✗${NC} Virtual environment pip not found"
            echo "  Expected: .venv/bin/pip"
            exit 1
        fi
    fi
    
    # Verify critical packages
    echo "  Verifying installations..."
    
    # Determine which python to use for verification
    if [ -n "$VIRTUAL_ENV" ]; then
        PYTHON_CMD="python3"  # venv is active, use python3
    elif [ -f ".venv/bin/python3" ]; then
        PYTHON_CMD=".venv/bin/python3"  # Use venv python directly
    else
        PYTHON_CMD="python3"  # Fallback to system python
    fi
    
    # Silent verification - install missing packages without noise
    VERIFY_FAILED=false
    
    for pkg_check in "langchain" "langchain_openai" "langchain_anthropic" "jinja2"; do
        if ! "$PYTHON_CMD" -c "import ${pkg_check//-/_}" 2>/dev/null; then
            # Silently install missing package
            pip install "${pkg_check}" > /dev/null 2>&1 || VERIFY_FAILED=true
        fi
    done
    
    # Final verification
    if "$PYTHON_CMD" -c "import langchain; import langchain_core" 2>/dev/null; then
        echo -e "${GREEN}✓${NC} All packages verified"
    else
        echo -e "${RED}✗${NC} Package verification failed"
        echo ""
        echo "Debug info:"
        echo "  Python: $PYTHON_CMD"
        echo "  pip: $(which pip)"
        echo "  Virtual env: $VIRTUAL_ENV"
        echo ""
        echo "Try manually:"
        echo "  source .venv/bin/activate"
        echo "  pip install --upgrade pip"
        echo "  pip install langchain langchain-openai langchain-anthropic"
        exit 1
    fi
else
    echo -e "${YELLOW}⚠${NC}  requirements.txt not found, skipping Python dependencies"
fi

echo ""

# ============================================================================
# STEP 3: Setup Shared Database
# ============================================================================
echo -e "${BLUE}[3/8]${NC} Setting up shared Argos Suite database..."

if [ -f "scripts/db_migrate.py" ]; then
    python3 scripts/db_migrate.py
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓${NC} Database setup complete: ~/.argos/argos.db"
    else
        echo -e "${RED}✗${NC} Database setup failed"
        exit 1
    fi
else
    echo -e "${YELLOW}⚠${NC}  db_migrate.py not found, skipping database setup"
    echo "  You may need to create ~/.argos/argos.db manually"
fi

echo ""

# ============================================================================
# STEP 4: Fix LDAP Libraries (Linux only)
# ============================================================================
echo -e "${BLUE}[4/8]${NC} Configuring LDAP libraries..."

if [ "$OS" == "linux" ]; then
    # Detect architecture
    ARCH=$(uname -m)
    
    if [ "$ARCH" == "x86_64" ]; then
        LIB_DIR="/usr/lib/x86_64-linux-gnu"
    elif [ "$ARCH" == "aarch64" ] || [ "$ARCH" == "arm64" ]; then
        LIB_DIR="/usr/lib/aarch64-linux-gnu"
    else
        LIB_DIR="/usr/lib"
    fi
    
    # Check if symlinks already exist
    LDAP_TARGET="${LIB_DIR}/libldap-2.5.so.0"
    LBER_TARGET="${LIB_DIR}/liblber-2.5.so.0"
    
    NEEDS_FIX=false
    
    if [ ! -e "$LDAP_TARGET" ]; then
        NEEDS_FIX=true
    fi
    
    if [ ! -e "$LBER_TARGET" ]; then
        NEEDS_FIX=true
    fi
    
    if [ "$NEEDS_FIX" = false ]; then
        echo -e "${GREEN}✓${NC} LDAP libraries already configured"
    else
        echo -e "${YELLOW}⚠${NC}  LDAP library symlinks needed for .NET compatibility"
        
        # Find existing libldap versions
        LDAP_SOURCE=""
        LBER_SOURCE=""
        
        for version in "libldap.so.2" "libldap-2.4.so.2" "libldap.so"; do
            if [ -f "${LIB_DIR}/${version}" ]; then
                LDAP_SOURCE="${LIB_DIR}/${version}"
                break
            fi
        done
        
        for version in "liblber.so.2" "liblber-2.4.so.2" "liblber.so"; do
            if [ -f "${LIB_DIR}/${version}" ]; then
                LBER_SOURCE="${LIB_DIR}/${version}"
                break
            fi
        done
        
        if [ -z "$LDAP_SOURCE" ]; then
            echo -e "${RED}✗${NC} libldap not found. Installing..."
            
            # Detect package manager and install
            if command -v apt &> /dev/null; then
                sudo apt update -qq
                sudo apt install -y libldap-2.5-0 libldap-common 2>&1 | grep -v "^Reading" || true
                LDAP_SOURCE="${LIB_DIR}/libldap.so.2"
                LBER_SOURCE="${LIB_DIR}/liblber.so.2"
            elif command -v dnf &> /dev/null; then
                sudo dnf install -y openldap &> /dev/null
                LDAP_SOURCE="${LIB_DIR}/libldap.so.2"
                LBER_SOURCE="${LIB_DIR}/liblber.so.2"
            elif command -v yum &> /dev/null; then
                sudo yum install -y openldap &> /dev/null
                LDAP_SOURCE="${LIB_DIR}/libldap.so.2"
                LBER_SOURCE="${LIB_DIR}/liblber.so.2"
            elif command -v pacman &> /dev/null; then
                sudo pacman -Sy --noconfirm libldap &> /dev/null
                LDAP_SOURCE="${LIB_DIR}/libldap.so.2"
                LBER_SOURCE="${LIB_DIR}/liblber.so.2"
            else
                echo -e "${RED}✗${NC} Could not detect package manager"
                echo "  Please install libldap manually and re-run setup"
                exit 1
            fi
        fi
        
        # Create symlinks
        if [ -n "$LDAP_SOURCE" ] && [ ! -e "$LDAP_TARGET" ]; then
            echo "  Creating symlink: $LDAP_TARGET -> $LDAP_SOURCE"
            if sudo ln -sf "$LDAP_SOURCE" "$LDAP_TARGET" 2>/dev/null; then
                echo -e "${GREEN}✓${NC} libldap symlink created"
            else
                echo -e "${YELLOW}⚠${NC}  Could not create libldap symlink (requires sudo)"
                echo "  LDAP/AD checks may fail without this fix"
                echo "  Run manually: sudo ln -s $LDAP_SOURCE $LDAP_TARGET"
            fi
        fi
        
        if [ -n "$LBER_SOURCE" ] && [ ! -e "$LBER_TARGET" ]; then
            echo "  Creating symlink: $LBER_TARGET -> $LBER_SOURCE"
            if sudo ln -sf "$LBER_SOURCE" "$LBER_TARGET" 2>/dev/null; then
                echo -e "${GREEN}✓${NC} liblber symlink created"
            else
                echo -e "${YELLOW}⚠${NC}  Could not create liblber symlink (requires sudo)"
                echo "  Run manually: sudo ln -s $LBER_SOURCE $LBER_TARGET"
            fi
        fi
        
        # Verify
        if [ -e "$LDAP_TARGET" ] && [ -e "$LBER_TARGET" ]; then
            echo -e "${GREEN}✓${NC} LDAP libraries configured successfully"
        else
            echo -e "${YELLOW}⚠${NC}  LDAP configuration incomplete (LDAP/AD checks may fail)"
        fi
    fi
elif [ "$OS" == "macos" ]; then
    # macOS uses different paths, usually no issues with .NET
    echo -e "${GREEN}✓${NC} macOS detected - LDAP libraries not required"
else
    echo -e "${YELLOW}⚠${NC}  Windows detected - LDAP configuration not needed"
fi

echo ""

# ============================================================================
# STEP 5: Build Asterion
# ============================================================================
echo -e "${BLUE}[5/8]${NC} Building Asterion (Release mode)..."

if [ -f "Asterion.sln" ]; then
    # Determine which dotnet command to use
    DOTNET_BUILD_CMD=""

    if [ -n "$DOTNET_EXEC" ]; then
        DOTNET_BUILD_CMD="$DOTNET_EXEC"
    elif command -v dotnet &> /dev/null; then
        DOTNET_BUILD_CMD="dotnet"
    else
        # Last resort: search for dotnet in common locations
        for DOTNET_PATH in "$HOME/.dotnet/dotnet" "/usr/share/dotnet/dotnet" "/usr/local/share/dotnet/dotnet"; do
            if [ -x "$DOTNET_PATH" ]; then
                DOTNET_BUILD_CMD="$DOTNET_PATH"
                export DOTNET_ROOT="$(dirname "$DOTNET_PATH")"
                break
            fi
        done
    fi

    if [ -z "$DOTNET_BUILD_CMD" ]; then
        echo -e "${RED}✗${NC} Cannot find dotnet executable"
        echo "  Install .NET SDK 8.0 from: https://dotnet.microsoft.com/download"
        exit 1
    fi

    echo "  Using: $DOTNET_BUILD_CMD"
    echo "  DOTNET_ROOT: ${DOTNET_ROOT:-not set}"

    # Execute build with explicit DOTNET_ROOT and capture full output
    # Remove --nologo and add verbosity for debugging
    BUILD_OUTPUT=$("$DOTNET_BUILD_CMD" build -c Release -v minimal 2>&1)
    BUILD_EXIT_CODE=$?

    # Show a preview of build output (first 10 and last 10 lines)
    if [ -n "$BUILD_OUTPUT" ]; then
        echo "  Build output preview:"
        echo "$BUILD_OUTPUT" | head -3 | sed 's/^/    /'
        LINE_COUNT=$(echo "$BUILD_OUTPUT" | wc -l)
        if [ "$LINE_COUNT" -gt 6 ]; then
            echo "    ..."
            echo "$BUILD_OUTPUT" | tail -3 | sed 's/^/    /'
        fi
    else
        echo -e "${YELLOW}  ⚠ Build produced no output${NC}"
    fi

    if [ $BUILD_EXIT_CODE -eq 0 ]; then
        # Verify that output files were actually created
        if [ -f "src/Asterion/bin/Release/net8.0/ast.dll" ] || [ -f "src/Asterion/bin/Release/net8.0/Asterion.dll" ]; then
            echo -e "${GREEN}✓${NC} Build successful"
        else
            echo -e "${RED}✗${NC} Build completed but no output files generated"
            echo ""
            echo "Full build output:"
            echo "$BUILD_OUTPUT"
            echo ""
            echo "Checked for:"
            echo "  - src/Asterion/bin/Release/net8.0/ast.dll"
            echo "  - src/Asterion/bin/Release/net8.0/Asterion.dll"
            echo ""
            echo "Debugging info:"
            echo "  Working directory: $(pwd)"
            echo "  Solution file: $(ls -la Asterion.sln 2>&1)"
            echo "  DOTNET_ROOT: ${DOTNET_ROOT:-not set}"
            echo "  Build command: $DOTNET_BUILD_CMD build -c Release -v minimal"
            exit 1
        fi
    else
        echo -e "${RED}✗${NC} Build failed (exit code: $BUILD_EXIT_CODE)"
        echo ""
        echo "Full build output:"
        echo "$BUILD_OUTPUT"
        exit 1
    fi
else
    echo -e "${RED}✗${NC} Asterion.sln not found"
    echo "  Run this script from the project root directory"
    exit 1
fi

echo ""

# ============================================================================
# STEP 6: Create Configuration Directories
# ============================================================================
echo -e "${BLUE}[6/8]${NC} Creating configuration directories..."

mkdir -p ~/.asterion/reports
mkdir -p ~/.asterion/consent-proofs
mkdir -p ~/.argos

echo -e "${GREEN}✓${NC} Created ~/.asterion/reports"
echo -e "${GREEN}✓${NC} Created ~/.asterion/consent-proofs"
echo -e "${GREEN}✓${NC} Created ~/.argos (shared with Argos Suite)"

echo ""

# ============================================================================
# STEP 7: Install Binary (Always use intelligent wrapper)
# ============================================================================
echo -e "${BLUE}[7/8]${NC} Installing binary..."

DLL_PATH=""

# Search for .dll assembly (cross-platform wrapper approach)
DLL_PATHS=(
    "src/Asterion/bin/Release/net8.0/ast.dll"
    "src/Asterion/bin/Release/net8.0/Asterion.dll"
)

# Search for .dll assembly (ALWAYS use wrapper for robustness)
for path in "${DLL_PATHS[@]}"; do
    if [ -f "$path" ]; then
        DLL_PATH="$(cd "$(dirname "$path")" && pwd)/$(basename "$path")"
        echo -e "${GREEN}✓${NC} Found .NET assembly: $DLL_PATH"
        break
    fi
done

if [ -z "$DLL_PATH" ]; then
    echo -e "${YELLOW}⚠${NC}  .NET assembly not found, skipping installation"
    echo "  Searched in:"
    for path in "${DLL_PATHS[@]}"; do
        echo "    - $path"
    done
else
    if [ "$OS" == "windows" ]; then
        echo -e "${YELLOW}⚠${NC}  On Windows, add to PATH manually:"
        echo "    $DLL_PATH"
    else
        # ALWAYS create a wrapper script (handles multiple .NET versions robustly)
        if [ -n "$DLL_PATH" ]; then
            echo "  Creating wrapper script for .NET assembly..."

            # Create wrapper script in project directory
            WRAPPER_SCRIPT="$PROJECT_ROOT/ast"
            cat > "$WRAPPER_SCRIPT" << EOF
#!/bin/bash
# Asterion launcher script
# Auto-generated by setup.sh

# Determine dotnet command (prioritize .NET 8+)
DOTNET_CMD=""

# Priority 1: User-installed .NET in ~/.dotnet (usually newest)
if [ -x "\$HOME/.dotnet/dotnet" ]; then
    DOTNET_VERSION="\$(\$HOME/.dotnet/dotnet --version 2>/dev/null | cut -d. -f1)"
    if [ "\$DOTNET_VERSION" -ge 8 ] 2>/dev/null; then
        DOTNET_CMD="\$HOME/.dotnet/dotnet"
        export DOTNET_ROOT="\$HOME/.dotnet"
    fi
fi

# Priority 2: System dotnet if version is 8+
if [ -z "\$DOTNET_CMD" ] && command -v dotnet &> /dev/null; then
    DOTNET_VERSION="\$(dotnet --version 2>/dev/null | cut -d. -f1)"
    if [ "\$DOTNET_VERSION" -ge 8 ] 2>/dev/null; then
        DOTNET_CMD="dotnet"
    fi
fi

# Priority 3: System dotnet in /usr/share if version is 8+
if [ -z "\$DOTNET_CMD" ] && [ -x "/usr/share/dotnet/dotnet" ]; then
    DOTNET_VERSION="\$(/usr/share/dotnet/dotnet --version 2>/dev/null | cut -d. -f1)"
    if [ "\$DOTNET_VERSION" -ge 8 ] 2>/dev/null; then
        DOTNET_CMD="/usr/share/dotnet/dotnet"
        export DOTNET_ROOT="/usr/share/dotnet"
    fi
fi

# Fallback: Use any dotnet found (may cause version errors)
if [ -z "\$DOTNET_CMD" ]; then
    if [ -x "\$HOME/.dotnet/dotnet" ]; then
        DOTNET_CMD="\$HOME/.dotnet/dotnet"
        export DOTNET_ROOT="\$HOME/.dotnet"
    elif command -v dotnet &> /dev/null; then
        DOTNET_CMD="dotnet"
    elif [ -x "/usr/share/dotnet/dotnet" ]; then
        DOTNET_CMD="/usr/share/dotnet/dotnet"
        export DOTNET_ROOT="/usr/share/dotnet"
    else
        echo "Error: .NET 8.0 or higher not found" >&2
        echo "Install from: https://dotnet.microsoft.com/download/dotnet/8.0" >&2
        exit 1
    fi
fi

# Execute Asterion
exec "\$DOTNET_CMD" "$DLL_PATH" "\$@"
EOF
            chmod +x "$WRAPPER_SCRIPT"
            echo -e "${GREEN}✓${NC} Wrapper script created: $WRAPPER_SCRIPT"

            echo ""
            read -p "  Create symlink /usr/local/bin/ast? [y/N] " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                if [ -w "/usr/local/bin" ]; then
                    ln -sf "$WRAPPER_SCRIPT" /usr/local/bin/ast
                    echo -e "${GREEN}✓${NC} Symlink created: /usr/local/bin/ast"
                else
                    sudo ln -sf "$WRAPPER_SCRIPT" /usr/local/bin/ast
                    echo -e "${GREEN}✓${NC} Symlink created: /usr/local/bin/ast (with sudo)"
                fi
            else
                echo -e "${YELLOW}⚠${NC}  Skipped symlink creation"
                echo "  To run Asterion:"
                echo "    - Use the wrapper: $WRAPPER_SCRIPT <command>"
                echo "    - Or use dotnet: dotnet run --project src/Asterion -- <command>"
            fi
        fi
    fi
fi

echo ""

# ============================================================================
# STEP 8: Verify Installation
# ============================================================================
echo -e "${BLUE}[8/8]${NC} Verifying installation..."

# Test if ast command works
if command -v ast &> /dev/null; then
    VERSION=$(ast version 2>&1 | grep -i "version" | head -1 || echo "unknown")
    echo -e "${GREEN}✓${NC} Asterion installed successfully"
    echo -e "${GREEN}✓${NC} Command 'ast' is available in PATH"
    if [[ ! "$VERSION" =~ "unknown" ]]; then
        echo "  $VERSION"
    fi
elif [ -n "$DLL_PATH" ] && [ -f "$PROJECT_ROOT/ast" ]; then
    echo -e "${YELLOW}⚠${NC}  Wrapper script created but not in PATH"
    echo "  Wrapper location: $PROJECT_ROOT/ast"
    echo ""
    echo "  To use Asterion:"
    echo "    1. Run directly: $PROJECT_ROOT/ast <command>"
    echo "    2. Add to PATH: export PATH=\"$PROJECT_ROOT:\$PATH\""
    echo "    3. Or use: dotnet \"$DLL_PATH\" <command>"
elif [ -n "$DLL_PATH" ]; then
    echo -e "${YELLOW}⚠${NC}  .NET assembly available: $DLL_PATH"
    echo "  Use: dotnet \"$DLL_PATH\" <command>"
    echo "  Or:  dotnet run --project src/Asterion -- <command>"
else
    echo -e "${YELLOW}⚠${NC}  Command 'ast' not in PATH"
    echo "  Use: dotnet run --project src/Asterion -- <command>"
fi

# ============================================================================
# VIRTUAL ENVIRONMENT REMINDER
# ============================================================================
echo ""
echo -e "${RED}════════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}⚠  IMPORTANT: Activate the virtual environment${NC}"
echo -e "${RED}════════════════════════════════════════════════════════════════${NC}"
echo ""
echo "  The Python virtual environment was created but is not active."
echo "  To activate it NOW, run:"
echo ""
echo -e "     ${GREEN}source .venv/bin/activate${NC}"
echo ""
echo -e "  You'll know it's active when you see ${GREEN}(.venv)${NC} in your prompt:"
echo -e "     ${GREEN}(.venv)${NC} user@machine:/your/path/asterion-network-minotaur$"
echo ""
echo -e "${RED}════════════════════════════════════════════════════════════════${NC}"
echo ""

echo ""

# ============================================================================
# COMPLETION MESSAGE
# ============================================================================
echo -e "${RED}════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ INSTALLATION COMPLETE!${NC}"
echo -e "${RED}════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${PURPLE}Quick Start:${NC}"
echo ""
echo "  1. Basic scan (safe mode):"
echo -e "     ${YELLOW}ast scan --target 192.168.1.0/24 --output json${NC}"
echo ""
echo "  2. Generate consent token:"
echo -e "     ${YELLOW}ast consent generate --domain corp.local${NC}"
echo ""
echo "  3. Verify consent:"
echo -e "     ${YELLOW}ast consent verify --method http --domain corp.local --token <token>${NC}"
echo ""
echo "  4. Scan with AI analysis:"
echo -e "     ${YELLOW}export AI_API_KEY=sk-...${NC}"
echo -e "     ${YELLOW}ast scan --target 10.0.0.0/24 --use-ai${NC}"
echo ""
echo -e "${PURPLE}Documentation:${NC}"
echo "  - README.md"
echo "  - docs/CONSENT.md"
echo "  - docs/NETWORK_CHECKS.md"
echo "  - docs/AI_INTEGRATION.md"
echo ""
echo -e "${RED}════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${PURPLE}Part of the Argos Security Suite:${NC}"
echo "  1. Argus     - WordPress scanner"
echo "  2. Hephaestus - Server auditor"
echo "  3. Pythia    - SQL injection scanner"
echo -e "  4. Asterion  - Network auditor ${GREEN}← You are here${NC}"
echo ""
echo -e "${RED}════════════════════════════════════════════════════════════════${NC}"