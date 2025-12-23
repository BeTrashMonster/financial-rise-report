import { test, expect } from '@playwright/test';

/**
 * E2E Tests: Performance Testing
 * Tests page load times, report generation speed, and concurrent user handling
 */

test.describe('Performance Testing', () => {
  test('login page should load within 3 seconds', async ({ page }) => {
    const startTime = Date.now();

    await page.goto('/');

    await page.waitForLoadState('networkidle');

    const loadTime = Date.now() - startTime;

    // REQ-PERF-001: < 3 second page loads
    expect(loadTime).toBeLessThan(3000);

    console.log(`Login page load time: ${loadTime}ms`);
  });

  test('dashboard should load within 3 seconds after login', async ({ page }) => {
    // Login first
    await page.goto('/');
    await page.getByLabel(/email/i).fill('consultant@test.com');
    await page.getByLabel(/password/i).fill('Test123!');
    await page.getByRole('button', { name: /sign in/i }).click();

    const startTime = Date.now();

    await page.waitForURL(/\/dashboard/);
    await page.waitForLoadState('networkidle');

    const loadTime = Date.now() - startTime;

    expect(loadTime).toBeLessThan(3000);

    console.log(`Dashboard load time: ${loadTime}ms`);
  });

  test('assessment page should load within 3 seconds', async ({ page }) => {
    // Login and create assessment
    await page.goto('/');
    await page.getByLabel(/email/i).fill('consultant@test.com');
    await page.getByLabel(/password/i).fill('Test123!');
    await page.getByRole('button', { name: /sign in/i }).click();
    await page.waitForURL(/\/dashboard/);

    await page.getByRole('button', { name: /new assessment/i }).click();
    await page.getByLabel(/client name/i).fill('Perf Test');
    await page.getByLabel(/client email/i).fill('perf@test.com');
    await page.getByLabel(/business name/i).fill('Perf LLC');

    const startTime = Date.now();

    await page.getByRole('button', { name: /create/i }).click();
    await page.waitForURL(/\/assessment\/\d+/);
    await page.waitForLoadState('networkidle');

    const loadTime = Date.now() - startTime;

    expect(loadTime).toBeLessThan(3000);

    console.log(`Assessment page load time: ${loadTime}ms`);
  });

  test('report generation should complete within 5 seconds', async ({ page }) => {
    // Login
    await page.goto('/');
    await page.getByLabel(/email/i).fill('consultant@test.com');
    await page.getByLabel(/password/i).fill('Test123!');
    await page.getByRole('button', { name: /sign in/i }).click();
    await page.waitForURL(/\/dashboard/);

    // Create and complete assessment (simplified)
    await page.getByRole('button', { name: /new assessment/i }).click();
    const timestamp = Date.now();
    await page.getByLabel(/client name/i).fill(`Report Perf ${timestamp}`);
    await page.getByLabel(/client email/i).fill(`reportperf${timestamp}@test.com`);
    await page.getByLabel(/business name/i).fill('Report Perf LLC');
    await page.getByRole('button', { name: /create/i }).click();

    // Complete assessment quickly
    for (let i = 0; i < 10; i++) {
      try {
        await page.getByRole('radio').first().check({ timeout: 2000 });
        const submit = page.getByRole('button', { name: /submit/i });
        if (await submit.count() > 0) {
          await submit.click();
          break;
        }
        await page.getByRole('button', { name: /next/i }).click();
      } catch (e) {
        break;
      }
    }

    // Generate report
    const startTime = Date.now();

    const generateButton = page.getByRole('button', { name: /generate.*report/i });
    if (await generateButton.count() > 0) {
      await generateButton.click();

      await page.waitForSelector(':text("success", "ready", "generated")', { timeout: 10000 });

      const generationTime = Date.now() - startTime;

      // REQ-PERF-002: < 5 second report generation
      expect(generationTime).toBeLessThan(5000);

      console.log(`Report generation time: ${generationTime}ms`);
    }
  });

  test('PDF download should start within 2 seconds', async ({ page }) => {
    // Setup: login, create assessment, complete it, generate report
    await page.goto('/');
    await page.getByLabel(/email/i).fill('consultant@test.com');
    await page.getByLabel(/password/i).fill('Test123!');
    await page.getByRole('button', { name: /sign in/i }).click();
    await page.waitForURL(/\/dashboard/);

    await page.getByRole('button', { name: /new assessment/i }).click();
    const timestamp = Date.now();
    await page.getByLabel(/client name/i).fill(`PDF Perf ${timestamp}`);
    await page.getByLabel(/client email/i).fill(`pdfperf${timestamp}@test.com`);
    await page.getByLabel(/business name/i).fill('PDF Perf LLC');
    await page.getByRole('button', { name: /create/i }).click();

    // Complete quickly
    for (let i = 0; i < 5; i++) {
      try {
        await page.getByRole('radio').first().check({ timeout: 2000 });
        const submit = page.getByRole('button', { name: /submit/i });
        if (await submit.count() > 0) {
          await submit.click();
          break;
        }
        await page.getByRole('button', { name: /next/i }).click();
      } catch (e) {
        break;
      }
    }

    await page.waitForTimeout(2000);

    // Download PDF
    const downloadButton = page.getByRole('button', { name: /download/i }).first();

    if (await downloadButton.count() > 0) {
      const startTime = Date.now();

      const downloadPromise = page.waitForEvent('download', { timeout: 5000 });

      await downloadButton.click();

      await downloadPromise;

      const downloadTime = Date.now() - startTime;

      expect(downloadTime).toBeLessThan(2000);

      console.log(`PDF download start time: ${downloadTime}ms`);
    }
  });

  test('auto-save should respond within 1 second', async ({ page }) => {
    // Login and create assessment
    await page.goto('/');
    await page.getByLabel(/email/i).fill('consultant@test.com');
    await page.getByLabel(/password/i).fill('Test123!');
    await page.getByRole('button', { name: /sign in/i }).click();
    await page.waitForURL(/\/dashboard/);

    await page.getByRole('button', { name: /new assessment/i }).click();
    await page.getByLabel(/client name/i).fill('AutoSave Perf Test');
    await page.getByLabel(/client email/i).fill('autosaveperf@test.com');
    await page.getByLabel(/business name/i).fill('AutoSave LLC');
    await page.getByRole('button', { name: /create/i }).click();

    const startTime = Date.now();

    // Answer question
    await page.getByRole('radio').first().check();

    // Wait for save indicator
    await page.waitForSelector(':text("saving", "saved")', { timeout: 3000 });

    const saveTime = Date.now() - startTime;

    expect(saveTime).toBeLessThan(1000);

    console.log(`Auto-save response time: ${saveTime}ms`);
  });

  test('navigation between pages should be instant', async ({ page }) => {
    await page.goto('/');
    await page.getByLabel(/email/i).fill('consultant@test.com');
    await page.getByLabel(/password/i).fill('Test123!');
    await page.getByRole('button', { name: /sign in/i }).click();
    await page.waitForURL(/\/dashboard/);

    const navLinks = [
      { name: /dashboard/i, url: /\/dashboard/ },
      { name: /settings|profile/i, url: /\/settings|\/profile/ }
    ];

    for (const link of navLinks) {
      const navLink = page.getByRole('link', { name: link.name });

      if (await navLink.count() > 0) {
        const startTime = Date.now();

        await navLink.click();
        await page.waitForURL(link.url);

        const navTime = Date.now() - startTime;

        // Navigation should be < 500ms for cached pages
        expect(navTime).toBeLessThan(500);

        console.log(`Navigation to ${link.name} time: ${navTime}ms`);
      }
    }
  });

  test('bundle size should be optimized', async ({ page }) => {
    // Measure total JS bundle size
    const responses: number[] = [];

    page.on('response', (response) => {
      if (response.url().includes('.js') && response.status() === 200) {
        response.body().then(buffer => {
          responses.push(buffer.length);
        }).catch(() => {});
      }
    });

    await page.goto('/');
    await page.waitForLoadState('networkidle');

    const totalBundleSize = responses.reduce((sum, size) => sum + size, 0);
    const totalMB = totalBundleSize / (1024 * 1024);

    console.log(`Total JS bundle size: ${totalMB.toFixed(2)} MB`);

    // Main bundle should be under 2MB (best practice)
    expect(totalMB).toBeLessThan(2);
  });

  test('images should be optimized', async ({ page }) => {
    const imageSizes: number[] = [];

    page.on('response', async (response) => {
      const contentType = response.headers()['content-type'];
      if (contentType && contentType.includes('image') && response.status() === 200) {
        try {
          const buffer = await response.body();
          imageSizes.push(buffer.length);
        } catch (e) {
          // Ignore errors
        }
      }
    });

    await page.goto('/');
    await page.waitForLoadState('networkidle');

    // Individual images should be under 500KB
    for (const size of imageSizes) {
      const sizeKB = size / 1024;
      console.log(`Image size: ${sizeKB.toFixed(2)} KB`);
      expect(sizeKB).toBeLessThan(500);
    }
  });

  test('API response times should be under 500ms', async ({ page }) => {
    const apiTimes: { url: string; time: number }[] = [];

    page.on('request', (request) => {
      if (request.url().includes('/api/')) {
        request.timing().then(timing => {
          if (timing) {
            apiTimes.push({
              url: request.url(),
              time: timing.responseEnd - timing.requestStart
            });
          }
        });
      }
    });

    await page.goto('/');
    await page.getByLabel(/email/i).fill('consultant@test.com');
    await page.getByLabel(/password/i).fill('Test123!');
    await page.getByRole('button', { name: /sign in/i }).click();
    await page.waitForURL(/\/dashboard/);
    await page.waitForLoadState('networkidle');

    for (const api of apiTimes) {
      console.log(`API ${api.url}: ${api.time}ms`);
      expect(api.time).toBeLessThan(500);
    }
  });

  test('concurrent users should not degrade performance', async ({ browser }) => {
    const contexts = await Promise.all([
      browser.newContext(),
      browser.newContext(),
      browser.newContext()
    ]);

    const pages = await Promise.all(contexts.map(ctx => ctx.newPage()));

    const loginTasks = pages.map(async (page, index) => {
      const startTime = Date.now();

      await page.goto('/');
      await page.getByLabel(/email/i).fill('consultant@test.com');
      await page.getByLabel(/password/i).fill('Test123!');
      await page.getByRole('button', { name: /sign in/i }).click();
      await page.waitForURL(/\/dashboard/);
      await page.waitForLoadState('networkidle');

      const loadTime = Date.now() - startTime;

      console.log(`Concurrent user ${index + 1} login time: ${loadTime}ms`);

      return loadTime;
    });

    const times = await Promise.all(loginTasks);

    // All concurrent users should login within 5 seconds
    for (const time of times) {
      expect(time).toBeLessThan(5000);
    }

    // Cleanup
    for (const page of pages) {
      await page.close();
    }
    for (const context of contexts) {
      await context.close();
    }
  });
});
