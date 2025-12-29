import { Page } from '@playwright/test';

/**
 * Test data fixtures
 */
export const testData = {
  consultant: {
    email: 'test-consultant@example.com',
    password: 'TestPassword123!',
    firstName: 'Test',
    lastName: 'Consultant',
  },
  client: {
    email: 'test-client@example.com',
    companyName: 'Test Company Inc',
    firstName: 'John',
    lastName: 'Doe',
  },
};

/**
 * Common helper functions
 */
export class TestHelpers {
  constructor(private page: Page) {}

  /**
   * Login as a consultant
   */
  async loginAsConsultant(email?: string, password?: string) {
    await this.page.goto('/login');
    await this.page.getByLabel(/email|username/i).fill(email || testData.consultant.email);
    await this.page.getByLabel(/password/i).fill(password || testData.consultant.password);
    await this.page.getByRole('button', { name: /sign in|login/i }).click();
    await this.page.waitForURL(/.*dashboard|home.*/);
  }

  /**
   * Logout
   */
  async logout() {
    const logoutButton = this.page.getByRole('button', { name: /logout|sign out/i });
    await logoutButton.click();
    await this.page.waitForURL(/.*login|^\/$|\/$/);
  }

  /**
   * Navigate to a specific section
   */
  async navigateTo(section: 'dashboard' | 'assessments' | 'clients' | 'reports') {
    const navLink = this.page.getByRole('link', { name: new RegExp(section, 'i') });
    await navLink.click();
    await this.page.waitForURL(new RegExp(`.*${section}.*`));
  }

  /**
   * Wait for API response
   */
  async waitForApiResponse(urlPattern: string | RegExp, options?: { timeout?: number }) {
    return await this.page.waitForResponse(
      (response) => {
        const url = response.url();
        const pattern = typeof urlPattern === 'string' ? new RegExp(urlPattern) : urlPattern;
        return pattern.test(url);
      },
      options
    );
  }

  /**
   * Create a new assessment
   */
  async createAssessment(clientName: string, clientEmail: string) {
    await this.navigateTo('assessments');
    await this.page.getByRole('button', { name: /new assessment|create assessment/i }).click();
    await this.page.getByLabel(/client name|company name/i).fill(clientName);
    await this.page.getByLabel(/email/i).fill(clientEmail);
    await this.page.getByRole('button', { name: /create|start/i }).click();
  }

  /**
   * Answer an assessment question
   */
  async answerQuestion(questionIndex: number, answerIndex: number) {
    const question = this.page.locator(`[data-testid="question-${questionIndex}"]`);
    const answer = question.locator('input[type="radio"]').nth(answerIndex);
    await answer.check();
  }

  /**
   * Navigate to next question
   */
  async nextQuestion() {
    await this.page.getByRole('button', { name: /next/i }).click();
  }

  /**
   * Submit assessment
   */
  async submitAssessment() {
    await this.page.getByRole('button', { name: /submit|complete/i }).click();
  }

  /**
   * Take a screenshot with a descriptive name
   */
  async screenshot(name: string) {
    await this.page.screenshot({ path: `test-results/screenshots/${name}.png`, fullPage: true });
  }
}

/**
 * API helper functions
 */
export class ApiHelpers {
  constructor(private baseUrl: string = 'http://localhost:3000') {}

  /**
   * Create a test user
   */
  async createTestUser(userData: any) {
    const response = await fetch(`${this.baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(userData),
    });
    return response.json();
  }

  /**
   * Get auth token
   */
  async getAuthToken(email: string, password: string) {
    const response = await fetch(`${this.baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    const data = await response.json();
    return data.accessToken;
  }

  /**
   * Clean up test data
   */
  async cleanupTestData(token: string) {
    // Implement cleanup logic
    // This would delete test users, assessments, etc.
  }
}
