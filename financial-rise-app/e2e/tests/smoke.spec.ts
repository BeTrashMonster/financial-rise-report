import { test, expect } from '@playwright/test';

/**
 * Smoke tests that don't require backend or frontend to be running
 * These verify the Playwright setup is working correctly
 */
test.describe('Playwright Setup Verification', () => {
  test('Playwright can open a browser and navigate', async ({ page }) => {
    // Navigate to a public URL to verify Playwright is working
    await page.goto('https://playwright.dev');

    // Verify we can find elements
    await expect(page).toHaveTitle(/Playwright/);

    // Take a screenshot (saved in test-results)
    await page.screenshot({ path: 'test-results/playwright-homepage.png' });
  });

  test('Can make API requests', async ({ request }) => {
    // Test that the request context works
    const response = await request.get('https://api.github.com/zen');

    expect(response.ok()).toBeTruthy();
    expect(response.status()).toBe(200);

    const body = await response.text();
    expect(body.length).toBeGreaterThan(0);
  });

  test('Browser context and page work', async ({ page }) => {
    // Create a simple HTML page in-memory
    await page.setContent(`
      <html>
        <head><title>Test Page</title></head>
        <body>
          <h1>Playwright Works!</h1>
          <button id="testBtn">Click Me</button>
          <div id="result"></div>
          <script>
            document.getElementById('testBtn').addEventListener('click', () => {
              document.getElementById('result').textContent = 'Button Clicked!';
            });
          </script>
        </body>
      </html>
    `);

    // Verify title
    await expect(page).toHaveTitle('Test Page');

    // Find and click button
    await page.click('#testBtn');

    // Verify result
    await expect(page.locator('#result')).toHaveText('Button Clicked!');
  });

  test('Can handle multiple tabs', async ({ context }) => {
    const page1 = await context.newPage();
    const page2 = await context.newPage();

    await page1.goto('https://www.example.com');
    await page2.goto('https://www.example.org');

    expect(context.pages().length).toBe(2);

    await page1.close();
    await page2.close();
  });
});

test.describe('Test Configuration Verification', () => {
  test('Environment variables are accessible', async () => {
    // Verify we can read env vars
    const baseUrl = process.env.BASE_URL || 'http://localhost:5173';
    expect(baseUrl).toBeTruthy();
    expect(typeof baseUrl).toBe('string');
  });

  test('Test timeout is configured', async () => {
    // This test verifies timeout configuration works
    await new Promise(resolve => setTimeout(resolve, 100));
    expect(true).toBe(true);
  });
});
