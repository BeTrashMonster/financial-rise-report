#!/bin/bash
# Make nvm permanent in WSL
# This adds nvm to .bashrc so it loads automatically

set -e

echo "=================================================="
echo "Making nvm Permanent"
echo "=================================================="
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}Step 1: Adding nvm to .bashrc...${NC}"

# Check if nvm is already in .bashrc
if grep -q "NVM_DIR" ~/.bashrc; then
    echo -e "${YELLOW}nvm already configured in .bashrc${NC}"
else
    cat >> ~/.bashrc << 'EOF'

# Load nvm (Node Version Manager)
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/bash_completion"

# Quick alias to project
alias fr='cd /mnt/c/Users/Admin/src/financial-rise-frontend'
EOF
    echo -e "${GREEN}✓ nvm added to .bashrc${NC}"
fi

echo ""
echo -e "${CYAN}Step 2: Loading nvm now...${NC}"
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"

nvm use 20

echo ""
echo -e "${GREEN}Node.js version: $(node --version)${NC}"
echo -e "${GREEN}npm version: $(npm --version)${NC}"

echo ""
echo "=================================================="
echo -e "${GREEN}nvm is now permanent!${NC}"
echo "=================================================="
echo ""
echo -e "${YELLOW}From now on:${NC}"
echo "  • Every new WSL terminal will automatically load Node.js 20"
echo "  • Type 'fr' to quickly jump to the project"
echo ""
echo -e "${CYAN}Testing by running the fix-tests script...${NC}"
echo ""

# Now run the fix-tests script
cd /mnt/c/Users/Admin/src
bash fix-tests.sh
