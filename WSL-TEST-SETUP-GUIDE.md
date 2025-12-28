# WSL Test Setup & Execution Guide

## Quick Start (Copy & Paste into WSL)

Open WSL and run these commands:

```bash
# Navigate to project directory (adjust path if needed)
cd /mnt/c/Users/Admin/src

# Make script executable
chmod +x setup-and-run-tests.sh

# Run the complete test setup and execution
./setup-and-run-tests.sh
```

That's it! The script will:
1. ✅ Check your Node.js environment
2. ✅ Set up test directories
3. ✅ Generate test files from specifications
4. ✅ Install dependencies
5. ✅ Run all tests with coverage
6. ✅ Generate summary reports

---

## What Gets Created

### Test Files Generated

**Backend (Jest):** ~29 test files
```
financial-rise-backend/src/__tests__/
├── unit/
│   ├── auth/
│   │   ├── authentication.test.ts
│   │   └── authorization.test.ts
│   ├── assessment/
│   │   ├── assessment-crud.test.ts
│   │   └── questionnaire.test.ts
│   ├── disc/
│   │   ├── disc-algorithm.test.ts
│   │   └── secondary-traits.test.ts
│   ├── phase/
│   │   ├── phase-determination.test.ts
│   │   └── multi-phase.test.ts
│   ├── reports/
│   │   ├── report-generation.test.ts
│   │   └── pdf-export.test.ts
│   ├── checklist/
│   ├── scheduler/
│   ├── analytics/
│   ├── shareable/
│   ├── monitoring/
│   └── logging/
└── integration/
```

**Frontend (Vitest):** ~25 test files
```
financial-rise-frontend/src/__tests__/
├── components/
│   ├── Auth/
│   │   ├── Login.test.tsx
│   │   └── Register.test.tsx
│   ├── Assessment/
│   │   ├── AssessmentList.test.tsx
│   │   └── CreateAssessment.test.tsx
│   ├── Questions/
│   │   └── Questionnaire.test.tsx
│   ├── Reports/
│   │   ├── ClientReport.test.tsx
│   │   └── ConsultantReport.test.tsx
│   ├── Dashboard/
│   ├── Checklist/
│   ├── Analytics/
│   ├── ShareableLinks/
│   └── Admin/
├── hooks/
├── services/
└── e2e/
```

### Output Files

- `backend-test-results.txt` - Complete Jest output
- `frontend-test-results.txt` - Complete Vitest output
- `TEST-SUMMARY.md` - Summary report with next steps
- `financial-rise-backend/coverage/` - Backend coverage reports
- `financial-rise-frontend/coverage/` - Frontend coverage reports

---

## Step-by-Step Manual Setup (If You Prefer)

### Step 1: Navigate to Project

```bash
cd /mnt/c/Users/Admin/src
```

### Step 2: Install Node.js (if needed)

```bash
# Install NVM
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash

# Restart terminal or run:
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"

# Install Node.js 18
nvm install 18
nvm use 18

# Verify
node -v  # Should show v18.x.x
npm -v   # Should show 9.x.x or higher
```

### Step 3: Setup Backend Tests

```bash
cd financial-rise-backend

# Install dependencies
npm install

# Run tests
npm test

# Run tests in watch mode (for development)
npm run test:watch

# Run only integration tests
npm run test:integration
```

### Step 4: Setup Frontend Tests

```bash
cd ../financial-rise-frontend

# Install dependencies
npm install

# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Run tests in watch mode (for development)
npm run test:watch

# Run tests with UI
npm run test:ui

# Run E2E tests (requires backend running)
npm run test:e2e
```

---

## Common Commands

### Backend (Jest)

```bash
cd financial-rise-backend

# Run all tests
npm test

# Run tests in watch mode (development)
npm run test:watch

# Run with coverage
npm test -- --coverage

# Run specific test file
npm test -- authentication.test.ts

# Run tests matching pattern
npm test -- --testNamePattern="should authenticate user"

# Update snapshots
npm test -- -u

# See test coverage in browser
npm test -- --coverage
# Then open: coverage/lcov-report/index.html
```

### Frontend (Vitest)

```bash
cd financial-rise-frontend

# Run all tests
npm test

# Run in watch mode (development)
npm run test:watch

# Run with coverage
npm run test:coverage

# Run with UI dashboard
npm run test:ui

# Run specific test file
npm test -- Login.test.tsx

# Run E2E tests
npm run test:e2e

# Run E2E with UI
npm run test:e2e:ui

# Run E2E in headed mode (see browser)
npm run test:e2e:headed
```

---

## View Coverage Reports

### Backend Coverage

```bash
cd financial-rise-backend

# Run tests with coverage
npm test

# Open coverage report in browser (from Windows)
explorer.exe coverage/lcov-report/index.html

# Or view text summary
cat coverage/coverage-summary.json
```

### Frontend Coverage

```bash
cd financial-rise-frontend

# Run tests with coverage
npm run test:coverage

# Open coverage report in browser (from Windows)
explorer.exe coverage/index.html

# Or view in terminal
npm run test:coverage -- --reporter=verbose
```

---

## Writing Actual Tests

The generated test files are **placeholders**. You need to implement them based on the specifications in the `docs/` directory.

### Example: Backend Test

```typescript
// financial-rise-backend/src/__tests__/unit/auth/authentication.test.ts

import { AuthService } from '../../../services/authService';
import { User } from '../../../models/User';

describe('Authentication Service', () => {
  let authService: AuthService;

  beforeEach(() => {
    authService = new AuthService();
  });

  describe('login', () => {
    it('should authenticate user with valid credentials', async () => {
      // Arrange
      const email = 'test@example.com';
      const password = 'Password123!';

      // Act
      const result = await authService.login(email, password);

      // Assert
      expect(result.token).toBeDefined();
      expect(result.user.email).toBe(email);
    });

    it('should reject invalid credentials', async () => {
      // Test based on AUTH-BACKEND-SPEC.md
      await expect(
        authService.login('test@example.com', 'wrongpassword')
      ).rejects.toThrow('Invalid credentials');
    });
  });

  describe('password requirements', () => {
    it('should enforce minimum 8 characters', async () => {
      // Test based on specification: REQ-AUTH-002
      const result = authService.validatePassword('short');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Password must be at least 8 characters');
    });
  });
});
```

### Example: Frontend Test

```typescript
// financial-rise-frontend/src/__tests__/components/Auth/Login.test.tsx

import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Login } from '../../../components/Auth/Login';

describe('Login Component', () => {
  it('should render login form', () => {
    render(<Login />);

    expect(screen.getByLabelText(/email/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /login/i })).toBeInTheDocument();
  });

  it('should validate email format', async () => {
    render(<Login />);
    const user = userEvent.setup();

    const emailInput = screen.getByLabelText(/email/i);
    await user.type(emailInput, 'invalid-email');
    await user.tab(); // Trigger blur validation

    await waitFor(() => {
      expect(screen.getByText(/invalid email format/i)).toBeInTheDocument();
    });
  });

  it('should submit form with valid credentials', async () => {
    const mockOnSubmit = vi.fn();
    render(<Login onSubmit={mockOnSubmit} />);
    const user = userEvent.setup();

    await user.type(screen.getByLabelText(/email/i), 'test@example.com');
    await user.type(screen.getByLabelText(/password/i), 'Password123!');
    await user.click(screen.getByRole('button', { name: /login/i }));

    await waitFor(() => {
      expect(mockOnSubmit).toHaveBeenCalledWith({
        email: 'test@example.com',
        password: 'Password123!'
      });
    });
  });

  it('should be keyboard accessible', async () => {
    render(<Login />);
    const user = userEvent.setup();

    // Tab through form fields
    await user.tab();
    expect(screen.getByLabelText(/email/i)).toHaveFocus();

    await user.tab();
    expect(screen.getByLabelText(/password/i)).toHaveFocus();

    await user.tab();
    expect(screen.getByRole('button', { name: /login/i })).toHaveFocus();
  });
});
```

---

## Troubleshooting

### "npm: command not found"

Install Node.js via NVM (see Step 2 above).

### "Jest encountered an unexpected token"

Make sure TypeScript is configured:
```bash
cd financial-rise-backend
npm install --save-dev ts-jest @types/jest
```

### "Cannot find module" errors

Install dependencies:
```bash
npm install
```

### Tests timing out

Increase timeout in jest.config.js or vitest.config.ts:
```javascript
// jest.config.js
module.exports = {
  testTimeout: 10000 // 10 seconds
};
```

### Coverage not showing

Make sure coverage is enabled:
```bash
# Backend
npm test -- --coverage

# Frontend
npm run test:coverage
```

### WSL can't find Windows files

Use `/mnt/c/` prefix:
```bash
cd /mnt/c/Users/Admin/src
```

---

## Continuous Integration

### Running Tests in CI/CD

```yaml
# .github/workflows/test.yml
name: Tests

on: [push, pull_request]

jobs:
  backend-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
      - name: Install dependencies
        run: cd financial-rise-backend && npm ci
      - name: Run tests
        run: cd financial-rise-backend && npm test
      - name: Upload coverage
        uses: codecov/codecov-action@v3

  frontend-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
      - name: Install dependencies
        run: cd financial-rise-frontend && npm ci
      - name: Run tests
        run: cd financial-rise-frontend && npm test
      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

---

## Next Steps

1. **Run the setup script**
   ```bash
   ./setup-and-run-tests.sh
   ```

2. **Review generated test files**
   - Check what tests were created
   - Identify which specifications they map to

3. **Implement actual tests**
   - Replace placeholder tests with real implementations
   - Reference specification documents in `docs/`
   - Aim for 80%+ coverage

4. **Run tests continuously**
   ```bash
   # Terminal 1: Backend watch mode
   cd financial-rise-backend && npm run test:watch

   # Terminal 2: Frontend watch mode
   cd financial-rise-frontend && npm run test:watch
   ```

5. **Review coverage reports**
   - Open in browser to see what's covered
   - Focus on critical paths first (auth, DISC, reports)

6. **Set up pre-commit hooks** (optional)
   ```bash
   npm install --save-dev husky lint-staged
   npx husky install
   npx husky add .husky/pre-commit "npm test"
   ```

---

## Resources

- **Jest Documentation:** https://jestjs.io/
- **Vitest Documentation:** https://vitest.dev/
- **React Testing Library:** https://testing-library.com/react
- **Playwright (E2E):** https://playwright.dev/

- **Project Specifications:** See `docs/` directory
- **Roadmap:** See `plans/roadmap.md`
- **Requirements:** See `plans/requirements.md`
