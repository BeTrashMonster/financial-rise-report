#!/bin/bash
# Completely fix Node.js in WSL using nvm
# This removes all traces of old Node.js and installs fresh via nvm

set -e

echo "=================================================="
echo "Complete Node.js Fix for WSL"
echo "=================================================="
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${CYAN}Step 1: Completely removing all old Node.js installations...${NC}"
# Nuclear option - remove everything Node.js related
sudo apt purge -y nodejs npm node 2>/dev/null || true
sudo apt autoremove -y
sudo rm -rf /usr/local/bin/npm /usr/local/bin/node /usr/local/lib/node_modules /usr/local/include/node /usr/local/share/man/man1/node.1
sudo rm -rf /usr/bin/node /usr/bin/npm /usr/lib/node_modules
sudo rm -rf ~/.npm ~/.node-gyp

echo -e "${GREEN}✓ Old Node.js removed${NC}"

echo ""
echo -e "${CYAN}Step 2: Installing nvm (Node Version Manager)...${NC}"
# Install nvm
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash

# Load nvm into current shell
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"

echo -e "${GREEN}✓ nvm installed${NC}"

echo ""
echo -e "${CYAN}Step 3: Installing Node.js 20 LTS via nvm...${NC}"
nvm install 20
nvm use 20
nvm alias default 20

echo ""
echo -e "${GREEN}Node.js installation complete:${NC}"
which node
node --version
which npm
npm --version

echo ""
echo -e "${CYAN}Step 4: Navigating to project directory...${NC}"
PROJECT_PATH="/mnt/c/Users/Admin/src/financial-rise-frontend"
cd "$PROJECT_PATH"
echo -e "${GREEN}Current directory: $(pwd)${NC}"

echo ""
echo -e "${CYAN}Step 5: Cleaning old dependencies...${NC}"
rm -rf node_modules package-lock.json
npm cache clean --force

echo ""
echo -e "${CYAN}Step 6: Installing project dependencies...${NC}"
npm install

echo ""
echo -e "${CYAN}Step 7: Running tests...${NC}"
npm test

echo ""
echo "=================================================="
echo -e "${GREEN}SUCCESS!${NC}"
echo "=================================================="
echo ""
echo -e "${YELLOW}IMPORTANT: Add this to your ~/.bashrc for permanent fix:${NC}"
echo ""
echo "Run these commands once:"
echo -e "${CYAN}"
cat << 'EOF'
cat >> ~/.bashrc << 'BASHRC_EOF'

# Load nvm
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
[ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion"

# Quick alias to project
alias fr='cd /mnt/c/Users/Admin/src/financial-rise-frontend'
BASHRC_EOF

source ~/.bashrc
EOF
echo -e "${NC}"
echo ""
echo -e "${GREEN}Then close and reopen your WSL terminal.${NC}"
echo ""
