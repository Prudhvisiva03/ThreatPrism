#!/usr/bin/env bash
# ThreatPrism Automated Installer for Linux / Kali / macOS
# https://github.com/Prudhvisiva03/ThreatPrism

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
RESET='\033[0m'

echo -e "${CYAN}${BOLD}"
echo "  _____ _hre__ ___  ___ _____ ___  ___  ___ ____ __  __"
echo " |_   _| | | | _ \/ __|_   _| _ \/0  \/ __||  _ \  \/  |"
echo "   | | | |_| |   /\__ \ | | |  _/ /\  \__ \| |_) | |\/| |"
echo "   |_|  \___/|_|_\|___/ |_| |_|  /_/\_\___/|  __/|_|  |_|"
echo "                                           |_|"
echo -e "${RESET}"
echo -e "${YELLOW}Autonomous Attack Surface Intelligence Platform Installer${RESET}\n"

# 1. Check Root / Sudo Availability
SUDO=""
if [ "$EUID" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        echo -e "${RED}[!] Please run as root or install sudo.${RESET}"
        exit 1
    fi
fi

# 2. Check Package Manager & Install System Dependencies
echo -e "${CYAN}[*] Checking system dependencies...${RESET}"
if command -v apt-get >/dev/null 2>&1; then
    $SUDO apt-get update -qq
    echo -e "${CYAN}[*] Installing required packages (golang, git, make, curl)...${RESET}"
    $SUDO apt-get install -y -qq golang git make curl ca-certificates >/dev/null
elif command -v yum >/dev/null 2>&1; then
    $SUDO yum install -y golang git make curl >/dev/null
elif command -v brew >/dev/null 2>&1; then
    brew install go git make curl
fi

# 3. Verify Go Installation
if ! command -v go >/dev/null 2>&1; then
    echo -e "${RED}[!] Go installation failed. Please install Go (1.25+) manually.${RESET}"
    exit 1
fi

GO_VERSION=$(go version | awk '{print $3}')
echo -e "${GREEN}[✓] Detected Go version: ${GO_VERSION}${RESET}"

# 4. Optional Chromium check for headless screenshots
if command -v chromium >/dev/null 2>&1 || command -v google-chrome >/dev/null 2>&1; then
    echo -e "${GREEN}[✓] Headless Chromium/Chrome detected for screenshot module.${RESET}"
else
    echo -e "${YELLOW}[!] Chromium not detected. Installing Chromium for screenshot engine...${RESET}"
    if command -v apt-get >/dev/null 2>&1; then
        $SUDO apt-get install -y -qq chromium-browser || $SUDO apt-get install -y -qq chromium || true
    fi
fi

# 5. Build ThreatPrism Binary
echo -e "${CYAN}[*] Building ThreatPrism binary (CGO-free pure Go)...${RESET}"
make build || CGO_ENABLED=0 go build -ldflags "-s -w" -o bin/threatprism ./cmd/threatprism

if [ ! -f "bin/threatprism" ]; then
    echo -e "${RED}[!] Build failed. Executable bin/threatprism not found.${RESET}"
    exit 1
fi

# 6. Global Installation to /usr/local/bin
echo -e "${CYAN}[*] Installing threatprism binary to /usr/local/bin/threatprism...${RESET}"
$SUDO cp bin/threatprism /usr/local/bin/threatprism
$SUDO chmod +x /usr/local/bin/threatprism

echo -e "\n${GREEN}${BOLD}[✓] ThreatPrism installed successfully!${RESET}"
echo -e "${CYAN}Run ${BOLD}threatprism${CYAN} or ${BOLD}threatprism --help${CYAN} to launch the platform.${RESET}\n"
