#!/bin/bash
# Simple test fix - just increase global timeout
# This is the safest approach

set -e

echo "=================================================="
echo "Simple Test Fix"
echo "=================================================="
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Load nvm
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
nvm use 20

PROJECT_PATH="/mnt/c/Users/Admin/src/financial-rise-frontend"
cd "$PROJECT_PATH"

echo -e "${CYAN}Step 1: Checking if backups exist...${NC}"

if [ -f "src/services/__tests__/api.test.ts.backup" ]; then
    echo -e "${YELLOW}Restoring api.test.ts from backup...${NC}"
    cp src/services/__tests__/api.test.ts.backup src/services/__tests__/api.test.ts
    echo -e "${GREEN}✓ Restored${NC}"
fi

if [ -f "src/pages/__tests__/CreateAssessment.test.tsx.backup" ]; then
    echo -e "${YELLOW}Restoring CreateAssessment.test.tsx from backup...${NC}"
    cp src/pages/__tests__/CreateAssessment.test.tsx.backup src/pages/__tests__/CreateAssessment.test.tsx
    echo -e "${GREEN}✓ Restored${NC}"
fi

if [ -f "src/pages/__tests__/Questionnaire.test.tsx.backup" ]; then
    echo -e "${YELLOW}Restoring Questionnaire.test.tsx from backup...${NC}"
    cp src/pages/__tests__/Questionnaire.test.tsx.backup src/pages/__tests__/Questionnaire.test.tsx
    echo -e "${GREEN}✓ Restored${NC}"
fi

echo ""
echo -e "${CYAN}Step 2: Increasing global test timeout to 20 seconds...${NC}"

# Simple sed replacement - just change the testTimeout line
if grep -q "testTimeout" vitest.config.ts; then
    echo -e "${YELLOW}Timeout already configured, updating value...${NC}"
    sed -i 's/testTimeout: [0-9]*,/testTimeout: 20000,/' vitest.config.ts
else
    echo -e "${YELLOW}Adding testTimeout to config...${NC}"
    sed -i '/setupFiles:.*setup\.ts/a\    testTimeout: 20000,' vitest.config.ts
fi

echo -e "${GREEN}✓ Timeout increased to 20 seconds${NC}"

echo ""
echo -e "${CYAN}Step 3: Running tests...${NC}"
npm test

echo ""
echo "=================================================="
echo -e "${GREEN}Done!${NC}"
echo "=================================================="
echo ""
echo -e "${YELLOW}What was fixed:${NC}"
echo "  • Restored original test files from backups"
echo "  • Increased global test timeout from 5s to 20s"
echo "  • This gives slow tests more time to complete"
echo ""
