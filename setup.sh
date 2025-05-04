#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' 

TOOL_NAME="riwhois"
INSTALL_DIR="/usr/local/$TOOL_NAME" 
BIN_DIR="/usr/local/bin"            
SCRIPT_NAME="main.py"

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    RIWHOIS  INSTALLATION                     ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${YELLOW}[!] This installation requires root privileges.${NC}"
    echo -e "${YELLOW}[!] Please run with 'sudo' or log in as root.${NC}"
    exit 1
fi

REQUIRED_PKGS=("python3" "python3-pip")
MISSING_PKGS=()

echo -e "${YELLOW}[*] Checking required packages...${NC}"

for pkg in "${REQUIRED_PKGS[@]}"; do
    if ! dpkg -l | grep -q "^ii  $pkg "; then
        MISSING_PKGS+=("$pkg")
    fi
done

if [ ${#MISSING_PKGS[@]} -ne 0 ]; then
    echo -e "${YELLOW}[!] Missing packages detected: ${MISSING_PKGS[*]}${NC}"
    echo -e "${YELLOW}[*] Installing packages...${NC}"
    apt-get update
    apt-get install -y "${MISSING_PKGS[@]}"
    if [ $? -ne 0 ]; then
        echo -e "${RED}[!] Error installing packages!${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}[+] All required packages are already installed.${NC}"
fi

REQUIRED_MODULES=("whois" "colorama" "requests")
MISSING_MODULES=()

echo -e "${YELLOW}[*] Checking Python modules...${NC}"

for module in "${REQUIRED_MODULES[@]}"; do
    if ! python3 -c "import $module" 2>/dev/null; then
        MISSING_MODULES+=("$module")
    fi
done

if [ ${#MISSING_MODULES[@]} -ne 0 ]; then
    echo -e "${YELLOW}[!] Missing Python modules: ${MISSING_MODULES[*]}${NC}"
    echo -e "${YELLOW}[*] Installing with pip...${NC}"
    pip3 install "${MISSING_MODULES[@]}"
    if [ $? -ne 0 ]; then
        echo -e "${RED}[!] Error installing Python modules!${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}[+] All required Python modules are installed.${NC}"
fi

if [ ! -f "$SCRIPT_NAME" ]; then
    echo -e "${RED}[!] Error: $SCRIPT_NAME file not found!${NC}"
    echo -e "${YELLOW}[!] Please make sure you're running this from the script directory.${NC}"
    exit 1
fi

echo -e "${YELLOW}[*] Preparing installation directory...${NC}"
mkdir -p "$INSTALL_DIR"

echo -e "${YELLOW}[*] Copying files...${NC}"
cp "$SCRIPT_NAME" "$INSTALL_DIR/"
if [ -f "requirements.txt" ]; then
    cp "requirements.txt" "$INSTALL_DIR/"
fi

echo -e "${YELLOW}[*] Creating system command...${NC}"
cat > "$BIN_DIR/$TOOL_NAME" <<EOF
#!/bin/bash
python3 "$INSTALL_DIR/$SCRIPT_NAME" "\$@"
EOF

chmod +x "$BIN_DIR/$TOOL_NAME"
chmod +x "$INSTALL_DIR/$SCRIPT_NAME"

if [ -f "$BIN_DIR/$TOOL_NAME" ]; then
    echo -e "${GREEN}[+] Command successfully created at $BIN_DIR/$TOOL_NAME${NC}"
else
    echo -e "${RED}[!] Failed to create command at $BIN_DIR/$TOOL_NAME${NC}"
    exit 1
fi

echo -e "\n${GREEN}[+] Installation completed successfully!${NC}"
echo -e "${GREEN}[+] You can now use '${TOOL_NAME} example.com' in your terminal.${NC}"

echo -e "\n${YELLOW}[?] Would you like to test it? (will perform whois lookup for google.com) [y/N]${NC} "
read -r answer
if [ "$answer" != "${answer#[Yy]}" ] ;then
    echo -e "\n${BLUE}=== TEST RESULT ===${NC}"
    $TOOL_NAME google.com
fi

exit 0
