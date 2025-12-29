# Financial RISE E2E Tests

End-to-end tests for the Financial RISE application using Playwright.

## Setup

### Prerequisites

- Node.js 18+ and npm 9+
- Backend and Frontend applications running (or configured to auto-start)

### Installation

```bash
# Install dependencies
npm install

# Install Playwright browsers
npx playwright install
```

### Environment Configuration

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

Edit `.env` with your test configuration:
- `BASE_URL` - Frontend URL (default: http://localhost:5173)
- `API_BASE_URL` - Backend API URL (default: http://localhost:3000)
- `TEST_USER_EMAIL` - Test consultant email
- `TEST_USER_PASSWORD` - Test consultant password

## Running Tests

### All Tests

```bash
npm test
```

### Interactive UI Mode

```bash
npm run test:ui
```

### Headed Mode (see browser)

```bash
npm run test:headed
```

### Debug Mode

```bash
npm run test:debug
```

### Specific Browser

```bash
npm run test:chromium
npm run test:firefox
npm run test:webkit
```

### Mobile Tests

```bash
npm run test:mobile
```

### View Test Report

```bash
npm run report
```

## Test Structure

```
e2e/
├── tests/
│   ├── setup/
│   │   └── auth.setup.ts       # Authentication setup
│   ├── example.spec.ts         # Basic navigation tests
│   ├── auth.spec.ts            # Authentication flow tests
│   └── assessment.spec.ts      # Assessment workflow tests
├── playwright.config.ts        # Playwright configuration
├── package.json
└── README.md
```

## Writing Tests

### Basic Test

```typescript
import { test, expect } from '@playwright/test';

test('my test', async ({ page }) => {
  await page.goto('/');
  await expect(page).toHaveTitle(/Financial RISE/);
});
```

### Authenticated Tests

Use the authentication setup:

```typescript
import { test, expect } from '@playwright/test';

test.describe('Protected Feature', () => {
  test.use({
    storageState: 'tests/.auth/consultant.json',
  });

  test('can access dashboard', async ({ page }) => {
    await page.goto('/dashboard');
    // Your test here
  });
});
```

### API Tests

```typescript
test('API endpoint', async ({ request }) => {
  const response = await request.get('/api/health');
  expect(response.ok()).toBeTruthy();
});
```

## Code Generation

Use Playwright's codegen to record tests:

```bash
npm run codegen
```

This opens a browser where you can interact with your app, and Playwright will generate test code.

## CI/CD Integration

Tests are configured to run in CI with:
- Retries (2 attempts)
- Sequential execution
- HTML, JSON, and JUnit reports
- Screenshots on failure
- Videos on failure

## Accessibility Testing

Playwright can be extended with axe-core for accessibility testing:

```bash
npm install -D @axe-core/playwright
```

## Performance Testing

Consider adding lighthouse tests:

```bash
npm install -D playwright-lighthouse
```

## Best Practices

1. **Use data-testid attributes** for reliable selectors
2. **Set up authentication state** instead of logging in for every test
3. **Use Page Object Model** for complex pages
4. **Keep tests independent** - each test should work in isolation
5. **Use appropriate waits** - leverage auto-waiting, avoid hard sleeps
6. **Clean up test data** - use beforeEach/afterEach hooks

## Troubleshooting

### Tests fail locally but pass in CI

- Check environment variables
- Ensure backend/frontend are running
- Clear browser cache: `npx playwright cache clear`

### Timeout errors

- Increase timeout in `playwright.config.ts`
- Check if backend/frontend are slow to start
- Verify network conditions

### Cannot find elements

- Use `await page.pause()` to debug
- Check if element is in shadow DOM
- Use Playwright Inspector: `npm run test:debug`

## Resources

- [Playwright Documentation](https://playwright.dev)
- [Best Practices](https://playwright.dev/docs/best-practices)
- [Debugging Guide](https://playwright.dev/docs/debug)
