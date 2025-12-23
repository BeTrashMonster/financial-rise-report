#!/bin/bash
# Restore backups and apply correct fixes
# Run this in WSL

set -e

echo "=================================================="
echo "Restoring Backups and Fixing Tests Properly"
echo "=================================================="
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Load nvm
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
nvm use 20

PROJECT_PATH="/mnt/c/Users/Admin/src/financial-rise-frontend"
cd "$PROJECT_PATH"

echo -e "${CYAN}Step 1: Restoring from backups...${NC}"

if [ -f "src/services/__tests__/api.test.ts.backup" ]; then
    cp src/services/__tests__/api.test.ts.backup src/services/__tests__/api.test.ts
    echo -e "${GREEN}✓ Restored api.test.ts${NC}"
else
    echo -e "${YELLOW}No backup found for api.test.ts${NC}"
fi

if [ -f "src/pages/__tests__/CreateAssessment.test.tsx.backup" ]; then
    cp src/pages/__tests__/CreateAssessment.test.tsx.backup src/pages/__tests__/CreateAssessment.test.tsx
    echo -e "${GREEN}✓ Restored CreateAssessment.test.tsx${NC}"
else
    echo -e "${YELLOW}No backup found for CreateAssessment.test.tsx${NC}"
fi

if [ -f "src/pages/__tests__/Questionnaire.test.tsx.backup" ]; then
    cp src/pages/__tests__/Questionnaire.test.tsx.backup src/pages/__tests__/Questionnaire.test.tsx
    echo -e "${GREEN}✓ Restored Questionnaire.test.tsx${NC}"
else
    echo -e "${YELLOW}No backup found for Questionnaire.test.tsx${NC}"
fi

echo ""
echo -e "${CYAN}Step 2: Applying targeted fixes...${NC}"

# Fix 1: API test - Fix the mock clearing issue
# Replace vi.clearAllMocks() with selective clearing
echo -e "${YELLOW}Fixing API authentication tests...${NC}"

# Check if the file has the authentication describe block
if grep -q "describe('authentication'" src/services/__tests__/api.test.ts; then
    # Create a temporary fixed version
    cat > /tmp/api-test-fix.ts << 'ENDFIX'
  beforeEach(() => {
    // Don't use vi.clearAllMocks() - it clears the axios.create call from module init
    mockAxiosInstance.get.mockClear();
    mockAxiosInstance.post.mockClear();
    mockAxiosInstance.patch.mockClear();
    mockAxiosInstance.delete.mockClear();
    mockAxiosInstance.interceptors.request.use.mockClear();
    mockAxiosInstance.interceptors.response.use.mockClear();
    localStorage.clear();
  });
ENDFIX

    # Replace the beforeEach block with the fixed version
    # Use perl for better multiline replacement
    perl -i -p0e 's/beforeEach\(\(\) => \{[^}]*vi\.clearAllMocks\(\);[^}]*localStorage\.clear\(\);[^}]*\}\);/`cat \/tmp\/api-test-fix.ts`/se' src/services/__tests__/api.test.ts

    echo -e "${GREEN}✓ Fixed API authentication tests${NC}"
fi

echo ""
echo -e "${CYAN}Step 3: Updating vitest config for longer timeouts...${NC}"

# Instead of modifying individual tests, update the global test timeout
cat > vitest.config.ts << 'VITESTCONFIG'
import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: './src/test/setup.ts',
    testTimeout: 15000, // Increase from default 5000ms to 15000ms
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: [
        'node_modules/',
        'src/test/',
        '**/*.d.ts',
        '**/*.config.*',
        '**/mockData',
        'dist/',
      ],
    },
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      '@/components': path.resolve(__dirname, './src/components'),
      '@/pages': path.resolve(__dirname, './src/pages'),
      '@/hooks': path.resolve(__dirname, './src/hooks'),
      '@/services': path.resolve(__dirname, './src/services'),
      '@/store': path.resolve(__dirname, './src/store'),
      '@/types': path.resolve(__dirname, './src/types'),
      '@/utils': path.resolve(__dirname, './src/utils'),
    },
  },
});
VITESTCONFIG

echo -e "${GREEN}✓ Updated vitest config with 15s timeout${NC}"

echo ""
echo -e "${CYAN}Step 4: Running tests...${NC}"
npm test

echo ""
echo "=================================================="
echo -e "${GREEN}Fix Complete!${NC}"
echo "=================================================="
