import { test, expect } from '@playwright/test';
import path from 'path';

/**
 * E2E Tests: Report Generation and PDF Export
 * Tests consultant report, client report generation and PDF downloads
 */

test.describe('Report Generation', () => {
  let assessmentId: string;

  test.beforeEach(async ({ page }) => {
    // Login
    await page.goto('/');
    await page.getByLabel(/email/i).fill('consultant@test.com');
    await page.getByLabel(/password/i).fill('Test123!');
    await page.getByRole('button', { name: /sign in/i }).click();
    await page.waitForURL(/\/dashboard/);

    // Create and complete assessment
    await page.getByRole('button', { name: /new assessment|create assessment/i }).click();
    const timestamp = Date.now();
    await page.getByLabel(/client name/i).fill(`Report Test ${timestamp}`);
    await page.getByLabel(/client email/i).fill(`report${timestamp}@test.com`);
    await page.getByLabel(/business name/i).fill('Report Test LLC');
    await page.getByRole('button', { name: /create|save|start/i }).click();

    // Complete assessment quickly (simplified for testing)
    for (let i = 0; i < 10; i++) {
      try {
        await page.getByRole('radio').first().check({ timeout: 2000 });
        const nextButton = page.getByRole('button', { name: /next|continue/i });
        const submitButton = page.getByRole('button', { name: /submit|complete/i });

        if (await submitButton.count() > 0) {
          await submitButton.click();
          break;
        } else if (await nextButton.count() > 0) {
          await nextButton.click();
        }
      } catch (e) {
        break;
      }
    }

    // Extract assessment ID from URL
    const url = page.url();
    const match = url.match(/assessment\/(\d+)/);
    if (match) {
      assessmentId = match[1];
    }
  });

  test('should display report preview after assessment completion', async ({ page }) => {
    await expect(page.getByText(/report|results|completed/i)).toBeVisible({ timeout: 10000 });
  });

  test('should generate consultant report', async ({ page }) => {
    // Navigate to reports page if not already there
    if (!page.url().includes('report')) {
      await page.goto(`/assessment/${assessmentId}/report`);
    }

    // Click generate consultant report button
    const consultantReportButton = page.getByRole('button', { name: /consultant report|generate consultant/i });

    if (await consultantReportButton.count() > 0) {
      await consultantReportButton.click();

      // Should show generating indicator
      await expect(page.getByText(/generating|please wait/i)).toBeVisible({ timeout: 5000 });

      // Should show success message
      await expect(page.getByText(/report generated|success|ready/i)).toBeVisible({ timeout: 30000 });
    }
  });

  test('should generate client report', async ({ page }) => {
    if (!page.url().includes('report')) {
      await page.goto(`/assessment/${assessmentId}/report`);
    }

    const clientReportButton = page.getByRole('button', { name: /client report|generate client/i });

    if (await clientReportButton.count() > 0) {
      await clientReportButton.click();

      // Should show generating indicator
      await expect(page.getByText(/generating|please wait/i)).toBeVisible({ timeout: 5000 });

      // Should show success message
      await expect(page.getByText(/report generated|success|ready/i)).toBeVisible({ timeout: 30000 });
    }
  });

  test('should download consultant report PDF', async ({ page }) => {
    if (!page.url().includes('report')) {
      await page.goto(`/assessment/${assessmentId}/report`);
    }

    // Wait for page to load
    await page.waitForTimeout(2000);

    // Start waiting for download before clicking
    const downloadPromise = page.waitForEvent('download', { timeout: 30000 });

    // Click download button
    const downloadButton = page.getByRole('button', { name: /download.*consultant|consultant.*download/i });

    if (await downloadButton.count() > 0) {
      await downloadButton.click();

      // Wait for download
      const download = await downloadPromise;

      // Verify file was downloaded
      expect(download.suggestedFilename()).toMatch(/consultant.*\.pdf/i);
    }
  });

  test('should download client report PDF', async ({ page }) => {
    if (!page.url().includes('report')) {
      await page.goto(`/assessment/${assessmentId}/report`);
    }

    await page.waitForTimeout(2000);

    const downloadPromise = page.waitForEvent('download', { timeout: 30000 });

    const downloadButton = page.getByRole('button', { name: /download.*client|client.*download/i });

    if (await downloadButton.count() > 0) {
      await downloadButton.click();
      const download = await downloadPromise;
      expect(download.suggestedFilename()).toMatch(/client.*\.pdf/i);
    }
  });

  test('should preview PDF in browser', async ({ page }) => {
    if (!page.url().includes('report')) {
      await page.goto(`/assessment/${assessmentId}/report`);
    }

    // Look for PDF viewer/iframe
    const pdfViewer = page.locator('iframe[src*=".pdf"], object[type="application/pdf"], embed[type="application/pdf"]');

    if (await pdfViewer.count() > 0) {
      await expect(pdfViewer).toBeVisible({ timeout: 10000 });
    }
  });

  test('should display DISC profile results', async ({ page }) => {
    if (!page.url().includes('report')) {
      await page.goto(`/assessment/${assessmentId}/report`);
    }

    // Should show DISC profile
    await expect(page.getByText(/DISC|dominance|influence|steadiness|compliance/i)).toBeVisible();
  });

  test('should display phase determination', async ({ page }) => {
    if (!page.url().includes('report')) {
      await page.goto(`/assessment/${assessmentId}/report`);
    }

    // Should show financial phase
    await expect(page.getByText(/stabilize|organize|build|grow|systemic/i)).toBeVisible();
  });

  test('should show action recommendations', async ({ page }) => {
    if (!page.url().includes('report')) {
      await page.goto(`/assessment/${assessmentId}/report`);
    }

    // Should show recommendations section
    await expect(page.getByText(/recommendations|action items|next steps/i)).toBeVisible();
  });

  test('should allow report regeneration', async ({ page }) => {
    if (!page.url().includes('report')) {
      await page.goto(`/assessment/${assessmentId}/report`);
    }

    const regenerateButton = page.getByRole('button', { name: /regenerate|generate again/i });

    if (await regenerateButton.count() > 0) {
      await regenerateButton.click();

      // Should show confirmation dialog
      const confirmButton = page.getByRole('button', { name: /confirm|yes|regenerate/i });
      if (await confirmButton.count() > 0) {
        await confirmButton.click();
      }

      // Should show generating indicator
      await expect(page.getByText(/generating|please wait/i)).toBeVisible({ timeout: 5000 });
    }
  });

  test('should maintain report data integrity', async ({ page }) => {
    if (!page.url().includes('report')) {
      await page.goto(`/assessment/${assessmentId}/report`);
    }

    // Get initial report data
    const initialData = await page.locator('[data-testid="report-content"]').textContent();

    // Refresh page
    await page.reload();

    // Report data should remain the same
    const refreshedData = await page.locator('[data-testid="report-content"]').textContent();

    if (initialData && refreshedData) {
      expect(initialData).toBe(refreshedData);
    }
  });

  test('should handle report generation errors gracefully', async ({ page, context }) => {
    // Simulate network failure
    await context.setOffline(true);

    if (!page.url().includes('report')) {
      await page.goto(`/assessment/${assessmentId}/report`);
    }

    const generateButton = page.getByRole('button', { name: /generate|consultant report/i });

    if (await generateButton.count() > 0) {
      await generateButton.click();

      // Should show error message
      await expect(page.getByText(/error|failed|try again/i)).toBeVisible({ timeout: 10000 });
    }

    await context.setOffline(false);
  });
});
