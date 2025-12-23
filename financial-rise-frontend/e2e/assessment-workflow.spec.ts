import { test, expect } from '@playwright/test';

/**
 * E2E Tests: Assessment Workflow
 * Tests the complete assessment creation and completion workflow
 */

test.describe('Assessment Workflow', () => {
  test.beforeEach(async ({ page }) => {
    // Login before each test
    await page.goto('/');
    await page.getByLabel(/email/i).fill('consultant@test.com');
    await page.getByLabel(/password/i).fill('Test123!');
    await page.getByRole('button', { name: /sign in/i }).click();
    await page.waitForURL(/\/dashboard/);
  });

  test('should display dashboard with assessments list', async ({ page }) => {
    await expect(page.getByRole('heading', { name: /dashboard|assessments/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /new assessment|create assessment/i })).toBeVisible();
  });

  test('should create new assessment', async ({ page }) => {
    await page.getByRole('button', { name: /new assessment|create assessment/i }).click();

    // Fill in assessment details
    await page.getByLabel(/client name/i).fill('Test Client');
    await page.getByLabel(/client email/i).fill('client@test.com');
    await page.getByLabel(/business name/i).fill('Test Business LLC');

    await page.getByRole('button', { name: /create|save|start/i }).click();

    // Should navigate to questionnaire
    await expect(page).toHaveURL(/\/assessment\/\d+/);
    await expect(page.getByText(/questionnaire|assessment/i)).toBeVisible();
  });

  test('should complete full assessment workflow', async ({ page }) => {
    // Create new assessment
    await page.getByRole('button', { name: /new assessment|create assessment/i }).click();

    const timestamp = Date.now();
    await page.getByLabel(/client name/i).fill(`Client ${timestamp}`);
    await page.getByLabel(/client email/i).fill(`client${timestamp}@test.com`);
    await page.getByLabel(/business name/i).fill('Test Business LLC');
    await page.getByRole('button', { name: /create|save|start/i }).click();

    // Answer questions in the assessment
    // Note: This assumes a multi-step questionnaire
    const totalQuestions = 25; // Approximate number based on requirements

    for (let i = 0; i < totalQuestions; i++) {
      // Wait for question to load
      await page.waitForSelector('[data-testid="question"]', { timeout: 5000 });

      // Check question type and answer accordingly
      const hasRadio = await page.getByRole('radio').count() > 0;
      const hasSelect = await page.getByRole('combobox').count() > 0;
      const hasInput = await page.getByRole('textbox').count() > 0;

      if (hasRadio) {
        // Select first radio option
        await page.getByRole('radio').first().check();
      } else if (hasSelect) {
        // Select an option from dropdown
        const select = page.getByRole('combobox').first();
        await select.click();
        await page.keyboard.press('ArrowDown');
        await page.keyboard.press('Enter');
      } else if (hasInput) {
        // Fill text input
        await page.getByRole('textbox').first().fill('Test response');
      }

      // Click Next or Submit button
      const nextButton = page.getByRole('button', { name: /next|continue/i });
      const submitButton = page.getByRole('button', { name: /submit|complete/i });

      const hasNext = await nextButton.count() > 0;
      const hasSubmit = await submitButton.count() > 0;

      if (hasSubmit) {
        await submitButton.click();
        break;
      } else if (hasNext) {
        await nextButton.click();
      }
    }

    // Should show completion message
    await expect(page.getByText(/assessment complete|thank you|submitted/i)).toBeVisible({ timeout: 10000 });
  });

  test('should navigate back and forth between questions', async ({ page }) => {
    // Create assessment
    await page.getByRole('button', { name: /new assessment|create assessment/i }).click();
    await page.getByLabel(/client name/i).fill('Nav Test Client');
    await page.getByLabel(/client email/i).fill('navtest@test.com');
    await page.getByLabel(/business name/i).fill('Test Business LLC');
    await page.getByRole('button', { name: /create|save|start/i }).click();

    // Answer first question
    await page.getByRole('radio').first().check();
    await page.getByRole('button', { name: /next/i }).click();

    // Answer second question
    await page.getByRole('radio').first().check();

    // Go back
    const backButton = page.getByRole('button', { name: /back|previous/i });
    if (await backButton.count() > 0) {
      await backButton.click();

      // Should be on first question again
      await expect(page.getByText(/question 1|1 of/i)).toBeVisible();
    }
  });

  test('should show progress indicator', async ({ page }) => {
    // Create assessment
    await page.getByRole('button', { name: /new assessment|create assessment/i }).click();
    await page.getByLabel(/client name/i).fill('Progress Test Client');
    await page.getByLabel(/client email/i).fill('progress@test.com');
    await page.getByLabel(/business name/i).fill('Test Business LLC');
    await page.getByRole('button', { name: /create|save|start/i }).click();

    // Check for progress indicator
    await expect(page.locator('[role="progressbar"], .progress, .MuiLinearProgress-root')).toBeVisible();
  });

  test('should save draft and continue later', async ({ page }) => {
    // Create assessment
    await page.getByRole('button', { name: /new assessment|create assessment/i }).click();

    const timestamp = Date.now();
    await page.getByLabel(/client name/i).fill(`Draft Client ${timestamp}`);
    await page.getByLabel(/client email/i).fill(`draft${timestamp}@test.com`);
    await page.getByLabel(/business name/i).fill('Test Business LLC');
    await page.getByRole('button', { name: /create|save|start/i }).click();

    // Answer a few questions
    await page.getByRole('radio').first().check();
    await page.getByRole('button', { name: /next/i }).click();
    await page.getByRole('radio').first().check();

    // Save and exit
    const saveButton = page.getByRole('button', { name: /save|save draft/i });
    if (await saveButton.count() > 0) {
      await saveButton.click();
    }

    // Navigate to dashboard
    await page.getByRole('link', { name: /dashboard/i }).click();

    // Should see draft assessment
    await expect(page.getByText(/draft|in progress/i)).toBeVisible();
  });

  test('should validate required fields', async ({ page }) => {
    // Create assessment
    await page.getByRole('button', { name: /new assessment|create assessment/i }).click();
    await page.getByLabel(/client name/i).fill('Validation Test');
    await page.getByLabel(/client email/i).fill('validation@test.com');
    await page.getByLabel(/business name/i).fill('Test Business LLC');
    await page.getByRole('button', { name: /create|save|start/i }).click();

    // Try to proceed without answering required question
    const nextButton = page.getByRole('button', { name: /next/i });
    if (await nextButton.count() > 0) {
      await nextButton.click();

      // Should show validation error
      await expect(page.getByText(/required|please select|answer required/i)).toBeVisible();
    }
  });
});
