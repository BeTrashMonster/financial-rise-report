import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

// Check if auth state file exists
const authStatePath = path.join(__dirname, '.auth', 'consultant.json');
const hasAuthState = fs.existsSync(authStatePath);

test.describe('Assessment Flow', () => {
  // Setup authenticated state if it exists
  test.use({
    storageState: hasAuthState ? 'tests/.auth/consultant.json' : undefined,
  });

  test.beforeEach(async ({ page }) => {
    // Skip tests if no auth state
    test.skip(!hasAuthState, 'Requires authenticated state - run auth setup first');
    await page.goto('/assessments');
  });

  test('should create new assessment', async ({ page }) => {
    // Click create new assessment button
    await page.getByRole('button', { name: /new assessment|create assessment/i }).click();

    // Fill in client information
    await page.getByLabel(/client name|company name/i).fill('Test Company Inc');
    await page.getByLabel(/email/i).fill('client@testcompany.com');

    // Submit
    await page.getByRole('button', { name: /create|start/i }).click();

    // Should navigate to assessment questionnaire
    await expect(page).toHaveURL(/.*assessment\/.*questionnaire.*/);
  });

  test('should answer assessment questions', async ({ page }) => {
    // Navigate to an existing assessment
    // This assumes you have test data or create one first
    await page.goto('/assessment/test-assessment-id/questionnaire');

    // Answer first question (adapt based on your actual questions)
    const firstQuestion = page.locator('[data-testid="question-0"]');
    await expect(firstQuestion).toBeVisible();

    // Select an answer
    await page.getByRole('radio').first().check();

    // Navigate to next question
    await page.getByRole('button', { name: /next/i }).click();

    // Verify we moved to next question
    const secondQuestion = page.locator('[data-testid="question-1"]');
    await expect(secondQuestion).toBeVisible();
  });

  test('should generate report after completing assessment', async ({ page }) => {
    // This test would go through the entire assessment flow
    // and verify report generation

    // Navigate to assessment
    await page.goto('/assessment/test-assessment-id/questionnaire');

    // Answer all questions (simplified - you'd loop through actual questions)
    // ... answer questions logic here ...

    // Submit assessment
    await page.getByRole('button', { name: /submit|complete/i }).click();

    // Should see report generation
    await expect(page.getByText(/generating report|processing/i)).toBeVisible();

    // Wait for report to be ready (with timeout)
    await expect(page.getByText(/report ready|view report/i)).toBeVisible({ timeout: 10000 });
  });
});
