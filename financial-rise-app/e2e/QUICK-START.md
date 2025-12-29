# Quick Start Guide - Playwright E2E Tests

## First Time Setup

### 1. Install Dependencies

```bash
cd financial-rise-app/e2e
npm install
npx playwright install
```

### 2. Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Edit .env with your configuration
# Update TEST_USER_EMAIL and TEST_USER_PASSWORD
```

### 3. Start Your Application

Make sure both backend and frontend are running:

```bash
# Terminal 1 - Backend
cd financial-rise-app/backend
npm run start:dev

# Terminal 2 - Frontend
cd financial-rise-app/frontend
npm run dev
```

### 4. Run Your First Test

```bash
cd financial-rise-app/e2e
npm test
```

## Common Commands

| Command | Description |
|---------|-------------|
| `npm test` | Run all tests |
| `npm run test:ui` | Open Playwright UI (recommended for development) |
| `npm run test:headed` | Run tests in headed mode (see browser) |
| `npm run test:debug` | Debug mode with Playwright Inspector |
| `npm run test:chromium` | Run only in Chromium |
| `npm run report` | View HTML test report |
| `npm run codegen` | Generate test code by recording actions |

## Development Workflow

### 1. Write Tests with UI Mode (Recommended)

```bash
npm run test:ui
```

This opens an interactive UI where you can:
- Run individual tests
- See live browser preview
- Debug with time-travel
- Generate locators

### 2. Record Tests with Codegen

```bash
npm run codegen http://localhost:5173
```

Interact with your app, and Playwright generates test code.

### 3. Debug Failed Tests

```bash
npm run test:debug
```

Or add `await page.pause()` in your test to pause execution.

## Test Structure Example

```typescript
import { test, expect } from '@playwright/test';
import { TestHelpers } from './helpers/fixtures';

test.describe('My Feature', () => {
  let helpers: TestHelpers;

  test.beforeEach(async ({ page }) => {
    helpers = new TestHelpers(page);
    await helpers.loginAsConsultant();
  });

  test('should do something', async ({ page }) => {
    // Your test code
    await page.goto('/feature');
    await expect(page.getByText('Expected text')).toBeVisible();
  });
});
```

## Tips

1. **Use Test Helpers**: Import from `./helpers/fixtures` for common operations
2. **Use Custom Matchers**: Import from `./helpers/matchers` for assertions
3. **Authentication**: Use `test.use({ storageState: 'tests/.auth/consultant.json' })` instead of logging in every time
4. **Parallel Tests**: Tests run in parallel by default - keep them independent
5. **Debugging**: Use `await page.pause()` to pause execution during test

## Troubleshooting

### Tests timeout
- Check if backend/frontend are running
- Increase timeout in playwright.config.ts
- Look for slow network requests

### Can't find elements
- Use `npx playwright codegen` to find correct selectors
- Check if element is in an iframe or shadow DOM
- Verify element is visible (not hidden by CSS)

### Authentication fails
- Update credentials in `.env`
- Delete `tests/.auth/` directory and re-run setup
- Check if login flow changed

## Next Steps

- Read the full [README.md](./README.md)
- Explore example tests in `tests/` directory
- Customize `playwright.config.ts` for your needs
- Add more test coverage
- Set up CI/CD with the provided GitHub Actions workflow
