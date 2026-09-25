#!/usr/bin/env bash
# Mailent — Unified Email Security & Forensic Platform
# Linux x86_64 Automated Installer Script

set -euo pipefail

BOLD="\033[1m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
BLUE="\033[0;34m"
RED="\033[0;31m"
NC="\033[0m"

echo -e "${BOLD}${BLUE}"
cat << "EOF"
  __  __       _ _            _   
 |  \/  |     (_) |          | |  
 | \  / | __ _ _| | ___ _ __ | |_ 
 | |\/| |/ _` | | |/ _ \ '_ \| __|
 | |  | | (_| | | |  __/ | | | |_ 
 |_|  |_|\__,_|_|_|\___|_| |_|\__|
EOF
echo -e "${NC}${BOLD}Unified Email Security & Forensic Platform${NC}\n"

# 1. Architecture and OS Verification
OS="$(uname -s)"
ARCH="$(uname -m)"

if [ "$OS" != "Linux" ]; then
    echo -e "${RED}[ERROR] Mailent installer currently supports Linux.${NC}"
    echo -e "Detected OS: $OS"
    exit 1
fi

if [ "$ARCH" != "x86_64" ]; then
    echo -e "${RED}[ERROR] Mailent pre-built packages target Linux x86_64.${NC}"
    echo -e "Detected Architecture: $ARCH"
    exit 1
fi

echo -e "${GREEN}[✓] System verified:${NC} Linux x86_64"

# 2. Determine installation target directory
INSTALL_DIR=""
if [ -w "/usr/local/bin" ]; then
    INSTALL_DIR="/usr/local/bin"
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    INSTALL_DIR="/usr/local/bin"
else
    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "$INSTALL_DIR"
fi

TARGET_BIN="${INSTALL_DIR}/mailent"
echo -e "${BLUE}[*] Target binary path:${NC} ${TARGET_BIN}"

# 3. Locate or build mailent binary
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "${SCRIPT_DIR}/Cargo.toml" ]; then
    REPO_DIR="${SCRIPT_DIR}"
elif [ -f "${SCRIPT_DIR}/../Cargo.toml" ]; then
    REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
else
    REPO_DIR="${SCRIPT_DIR}"
fi

SOURCE_BIN=""
if [ -f "${REPO_DIR}/target/release/mailent" ]; then
    SOURCE_BIN="${REPO_DIR}/target/release/mailent"
elif [ -f "${REPO_DIR}/target/debug/mailent" ]; then
    SOURCE_BIN="${REPO_DIR}/target/debug/mailent"
elif command -v cargo >/dev/null 2>&1 && [ -f "${REPO_DIR}/Cargo.toml" ]; then
    echo -e "${BLUE}[*] Compiling Mailent binary (cargo build --release -p mailent)...${NC}"
    cargo build --release -p mailent --manifest-path "${REPO_DIR}/Cargo.toml"
    SOURCE_BIN="${REPO_DIR}/target/release/mailent"
fi

if [ -n "$SOURCE_BIN" ] && [ -f "$SOURCE_BIN" ]; then
    echo -e "${BLUE}[*] Installing binary from:${NC} ${SOURCE_BIN}"
    if [ -w "$(dirname "$TARGET_BIN")" ]; then
        cp -f "$SOURCE_BIN" "$TARGET_BIN"
        chmod +x "$TARGET_BIN"
    else
        sudo cp -f "$SOURCE_BIN" "$TARGET_BIN"
        sudo chmod +x "$TARGET_BIN"
    fi
else
    echo -e "${RED}[ERROR] Could not locate or build mailent binary.${NC}"
    exit 1
fi

echo -e "${GREEN}[✓] Mailent installed successfully:${NC} $("${TARGET_BIN}" --version)"

# 4. PATH Verification
if [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
    echo -e "${YELLOW}[!] Warning: ${INSTALL_DIR} is not in your current PATH.${NC}"
    echo -e "    Add it to your shell profile (~/.bashrc or ~/.zshrc):"
    echo -e "    ${BOLD}export PATH=\"${INSTALL_DIR}:\$PATH\"${NC}"
fi

# 5. Zeek Forensics Engine Inspection & Guidance
echo -e "\n${BOLD}Inspecting Network Forensic Engines:${NC}"
ZEEK_PATH="$(command -v zeek || true)"
if [ -n "$ZEEK_PATH" ]; then
    ZEEK_VER="$("$ZEEK_PATH" --version 2>&1 | head -n1)"
    echo -e "${GREEN}[✓] Zeek detected:${NC} ${ZEEK_VER}"
    echo -e "    • Local PCAP protocol forensic inspection is fully available."
else
    echo -e "${YELLOW}[INFO] Zeek was not found in PATH.${NC}"
    echo -e "       • Infrastructure scanning (${BOLD}mailent scan <domain>${NC}) and scheduled"
    echo -e "         monitoring agent jobs ${BOLD}do NOT require Zeek${NC} and are ready to run."
    echo -e "       • Offline PCAP capture analysis (${BOLD}mailent analyze <file.pcap>${NC}) requires Zeek."
    echo -e "       • To install Zeek on Debian/Ubuntu: ${BOLD}sudo apt-get install -y zeek${NC}"
fi

# 6. Next Steps Guidance
echo -e "\n╔══════════════════════════════════════════════════════════════╗"
echo -e "║                      GETTING STARTED                         ║"
echo -e "╚══════════════════════════════════════════════════════════════╝"
echo -e "1. Connect this machine to your Mailent workspace:"
echo -e "   ${BOLD}${GREEN}mailent login${NC}"
echo -e ""
echo -e "2. Install and launch the local companion service:"
echo -e "   ${BOLD}${GREEN}mailent companion install${NC}"
echo -e ""
echo -e "3. Verify companion status and local execution listener:"
echo -e "   ${BOLD}${GREEN}mailent companion status${NC}"
echo -e ""
echo -e "4. Check system diagnostics anytime:"
echo -e "   ${BOLD}${GREEN}mailent doctor${NC}"
echo -e ""
