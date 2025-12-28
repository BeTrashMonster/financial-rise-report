import axios, { AxiosInstance, AxiosError } from 'axios';
import type {
  Assessment,
  AssessmentDetail,
  CreateAssessmentRequest,
  UpdateAssessmentRequest,
  Questionnaire,
  GenerateReportsResponse,
  GenerateSingleReportResponse,
} from '@/types';
import { handleApiError, ApiError } from './apiErrors';

/**
 * Real API Client for Financial RISE Backend
 * Implements API-CONTRACT.md v1.0 specification
 *
 * Features:
 * - JWT authentication with token refresh
 * - Automatic token management (access + refresh)
 * - Request/response interceptors
 * - Standardized error handling
 * - CSRF token support (if enabled on backend)
 */

interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

interface User {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  role: 'consultant' | 'admin';
  status: 'active' | 'inactive' | 'locked';
  createdAt: string;
  lastLoginAt?: string;
}

interface LoginResponse {
  user: User;
  tokens: AuthTokens;
}

interface RegisterRequest {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
}

class RealApiClient {
  private client: AxiosInstance;
  private accessToken: string | null = null;
  private refreshToken: string | null = null;
  private isRefreshing = false;
  private failedQueue: Array<{
    resolve: (value?: unknown) => void;
    reject: (reason?: unknown) => void;
  }> = [];

  constructor() {
    const baseURL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3000/api/v1';

    this.client = axios.create({
      baseURL,
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      withCredentials: true, // Enable cookies for CSRF tokens
      timeout: 30000, // 30 second timeout
    });

    // Load tokens from localStorage on initialization
    this.loadTokensFromStorage();

    // Request interceptor: Add auth token and CSRF token
    this.client.interceptors.request.use(
      (config) => {
        if (this.accessToken && config.headers) {
          config.headers.Authorization = `Bearer ${this.accessToken}`;
        }

        // Add CSRF token from cookie to header (double-submit cookie pattern)
        // Work Stream 63 (MED-002) - Global CSRF Protection
        const csrfToken = this.getCsrfTokenFromCookie();
        if (csrfToken && config.headers) {
          config.headers['X-CSRF-Token'] = csrfToken;
        }

        return config;
      },
      (error) => Promise.reject(error)
    );

    // Response interceptor: Handle 401 and refresh token
    this.client.interceptors.response.use(
      (response) => response,
      async (error: AxiosError) => {
        const originalRequest = error.config as any;

        // Handle 401 Unauthorized - try to refresh token
        if (error.response?.status === 401 && !originalRequest._retry) {
          if (this.isRefreshing) {
            // Queue this request while refresh is in progress
            return new Promise((resolve, reject) => {
              this.failedQueue.push({ resolve, reject });
            })
              .then(() => {
                originalRequest.headers.Authorization = `Bearer ${this.accessToken}`;
                return this.client.request(originalRequest);
              })
              .catch((err) => Promise.reject(err));
          }

          originalRequest._retry = true;
          this.isRefreshing = true;

          // Try to refresh the token
          if (this.refreshToken) {
            try {
              const tokens = await this.refreshAccessToken(this.refreshToken);
              this.setTokens(tokens.accessToken, tokens.refreshToken);

              // Retry all queued requests
              this.processQueue(null);

              // Retry original request
              originalRequest.headers.Authorization = `Bearer ${this.accessToken}`;
              return this.client.request(originalRequest);
            } catch (refreshError) {
              // Refresh failed - logout user
              this.processQueue(refreshError);
              this.logout();
              window.location.href = '/login';
              return Promise.reject(refreshError);
            } finally {
              this.isRefreshing = false;
            }
          } else {
            // No refresh token - logout
            this.logout();
            window.location.href = '/login';
            return Promise.reject(error);
          }
        }

        // Handle other errors
        throw handleApiError(error);
      }
    );
  }

  /**
   * Process queued requests after token refresh
   */
  private processQueue(error: any) {
    this.failedQueue.forEach((promise) => {
      if (error) {
        promise.reject(error);
      } else {
        promise.resolve();
      }
    });
    this.failedQueue = [];
  }

  /**
   * Load tokens from localStorage
   */
  private loadTokensFromStorage() {
    this.accessToken = localStorage.getItem('accessToken');
    this.refreshToken = localStorage.getItem('refreshToken');
  }

  /**
   * Save tokens to localStorage
   */
  private setTokens(accessToken: string, refreshToken: string) {
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
    localStorage.setItem('accessToken', accessToken);
    localStorage.setItem('refreshToken', refreshToken);
  }

  /**
   * Clear tokens from memory and storage
   */
  private clearTokens() {
    this.accessToken = null;
    this.refreshToken = null;
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
  }

  /**
   * Get CSRF token from cookie
   * Work Stream 63 (MED-002) - Global CSRF Protection
   * Implements double-submit cookie pattern client-side logic
   */
  private getCsrfTokenFromCookie(): string | null {
    // Parse document.cookie to find XSRF-TOKEN
    const cookieName = 'XSRF-TOKEN';
    const cookies = document.cookie.split(';');

    for (const cookie of cookies) {
      const [name, value] = cookie.trim().split('=');
      if (name === cookieName) {
        return decodeURIComponent(value);
      }
    }

    return null;
  }

  // ==========================================
  // AUTHENTICATION ENDPOINTS (Section 2)
  // ==========================================

  /**
   * Register new user
   * POST /auth/register
   */
  async register(data: RegisterRequest): Promise<LoginResponse> {
    const response = await this.client.post<LoginResponse>('/auth/register', data);
    this.setTokens(response.data.tokens.accessToken, response.data.tokens.refreshToken);
    return response.data;
  }

  /**
   * Login
   * POST /auth/login
   */
  async login(email: string, password: string): Promise<LoginResponse> {
    const response = await this.client.post<LoginResponse>('/auth/login', {
      email,
      password,
    });
    this.setTokens(response.data.tokens.accessToken, response.data.tokens.refreshToken);
    return response.data;
  }

  /**
   * Refresh access token
   * POST /auth/refresh
   */
  private async refreshAccessToken(refreshToken: string): Promise<AuthTokens> {
    const response = await this.client.post<AuthTokens>('/auth/refresh', {
      refreshToken,
    });
    return response.data;
  }

  /**
   * Logout
   * POST /auth/logout
   */
  async logout(): Promise<void> {
    try {
      if (this.refreshToken) {
        await this.client.post('/auth/logout', {
          refreshToken: this.refreshToken,
        });
      }
    } finally {
      this.clearTokens();
    }
  }

  /**
   * Request password reset
   * POST /auth/forgot-password
   */
  async forgotPassword(email: string): Promise<{ message: string }> {
    const response = await this.client.post<{ message: string }>('/auth/forgot-password', {
      email,
    });
    return response.data;
  }

  /**
   * Reset password with token
   * POST /auth/reset-password
   */
  async resetPassword(token: string, newPassword: string): Promise<{ message: string }> {
    const response = await this.client.post<{ message: string }>('/auth/reset-password', {
      token,
      newPassword,
    });
    return response.data;
  }

  // ==========================================
  // ASSESSMENT ENDPOINTS (Section 3)
  // ==========================================

  /**
   * List assessments with pagination and filtering
   * GET /assessments
   */
  async listAssessments(params?: {
    page?: number;
    limit?: number;
    status?: string;
    search?: string;
    sortBy?: string;
    sortOrder?: 'asc' | 'desc';
  }): Promise<{
    data: Assessment[];
    meta: {
      page: number;
      limit: number;
      total: number;
      totalPages: number;
    };
  }> {
    const response = await this.client.get('/assessments', { params });
    return response.data;
  }

  /**
   * Get single assessment with full details
   * GET /assessments/:id
   */
  async getAssessment(assessmentId: string): Promise<AssessmentDetail> {
    const response = await this.client.get<AssessmentDetail>(`/assessments/${assessmentId}`);
    return response.data;
  }

  /**
   * Create new assessment
   * POST /assessments
   */
  async createAssessment(data: CreateAssessmentRequest): Promise<Assessment> {
    const response = await this.client.post<Assessment>('/assessments', data);
    return response.data;
  }

  /**
   * Update assessment
   * PATCH /assessments/:id
   */
  async updateAssessment(
    assessmentId: string,
    data: UpdateAssessmentRequest
  ): Promise<{
    assessmentId: string;
    status: string;
    progress: number;
    updatedAt: string;
    savedResponses: number;
  }> {
    const response = await this.client.patch(`/assessments/${assessmentId}`, data);
    return response.data;
  }

  /**
   * Delete assessment (soft delete)
   * DELETE /assessments/:id
   */
  async deleteAssessment(assessmentId: string): Promise<void> {
    await this.client.delete(`/assessments/${assessmentId}`);
  }

  // ==========================================
  // QUESTIONNAIRE ENDPOINTS (Section 4)
  // ==========================================

  /**
   * Get questionnaire questions
   * GET /questionnaire/questions
   */
  async getQuestionnaire(assessmentId?: string): Promise<Questionnaire> {
    const params = assessmentId ? { assessmentId } : undefined;
    const response = await this.client.get<Questionnaire>('/questionnaire/questions', { params });
    return response.data;
  }

  /**
   * Submit questionnaire response
   * POST /questionnaire/responses
   */
  async submitResponse(data: {
    assessmentId: string;
    questionId: string;
    answer: any;
    notApplicable?: boolean;
    consultantNotes?: string;
  }): Promise<{
    id: string;
    assessmentId: string;
    questionId: string;
    answer: any;
    notApplicable: boolean;
    consultantNotes?: string;
    answeredAt: string;
    progress: number;
  }> {
    const response = await this.client.post('/questionnaire/responses', data);
    return response.data;
  }

  /**
   * Update questionnaire response
   * PATCH /questionnaire/responses/:id
   */
  async updateResponse(
    responseId: string,
    data: {
      answer?: any;
      consultantNotes?: string;
    }
  ): Promise<{
    id: string;
    assessmentId: string;
    questionId: string;
    answer: any;
    notApplicable: boolean;
    consultantNotes?: string;
    answeredAt: string;
  }> {
    const response = await this.client.patch(`/questionnaire/responses/${responseId}`, data);
    return response.data;
  }

  // ==========================================
  // REPORT ENDPOINTS (Section 5)
  // ==========================================

  /**
   * Calculate DISC profile
   * POST /reports/disc-profile
   */
  async calculateDiscProfile(assessmentId: string): Promise<{
    id: string;
    assessmentId: string;
    dScore: number;
    iScore: number;
    sScore: number;
    cScore: number;
    primaryType: 'D' | 'I' | 'S' | 'C';
    secondaryType: 'D' | 'I' | 'S' | 'C' | null;
    confidenceLevel: 'high' | 'moderate' | 'low';
    calculatedAt: string;
  }> {
    const response = await this.client.post('/reports/disc-profile', { assessmentId });
    return response.data;
  }

  /**
   * Calculate phase result
   * POST /reports/phase-result
   */
  async calculatePhaseResult(assessmentId: string): Promise<{
    id: string;
    assessmentId: string;
    stabilizeScore: number;
    organizeScore: number;
    buildScore: number;
    growScore: number;
    systemicScore: number;
    primaryPhase: string;
    secondaryPhases: string[];
    transitionState: boolean;
    calculatedAt: string;
  }> {
    const response = await this.client.post('/reports/phase-result', { assessmentId });
    return response.data;
  }

  /**
   * Generate consultant report
   * POST /reports/generate/consultant
   */
  async generateConsultantReport(assessmentId: string): Promise<{
    reportId: string;
    status: 'generating' | 'completed' | 'failed';
    message: string;
    estimatedCompletionTime: number;
  }> {
    const response = await this.client.post('/reports/generate/consultant', { assessmentId });
    return response.data;
  }

  /**
   * Generate client report
   * POST /reports/generate/client
   */
  async generateClientReport(assessmentId: string): Promise<{
    reportId: string;
    status: 'generating' | 'completed' | 'failed';
    message: string;
    estimatedCompletionTime: number;
  }> {
    const response = await this.client.post('/reports/generate/client', { assessmentId });
    return response.data;
  }

  /**
   * Generate both reports (for backwards compatibility with mockApi)
   */
  async generateBothReports(assessmentId: string): Promise<GenerateReportsResponse> {
    // Generate both reports in parallel
    const [consultantResponse, clientResponse] = await Promise.all([
      this.generateConsultantReport(assessmentId),
      this.generateClientReport(assessmentId),
    ]);

    // Wait for both reports to complete
    const [consultantReport, clientReport] = await Promise.all([
      this.pollReportStatus(consultantResponse.reportId),
      this.pollReportStatus(clientResponse.reportId),
    ]);

    return {
      success: true,
      data: {
        consultantReport: {
          reportId: consultantReport.reportId,
          reportType: 'consultant',
          assessmentId,
          pdfUrl: consultantReport.fileUrl || '',
          generatedAt: consultantReport.generatedAt || new Date().toISOString(),
        },
        clientReport: {
          reportId: clientReport.reportId,
          reportType: 'client',
          assessmentId,
          pdfUrl: clientReport.fileUrl || '',
          generatedAt: clientReport.generatedAt || new Date().toISOString(),
        },
      },
    };
  }

  /**
   * Get report status
   * GET /reports/status/:reportId
   */
  async getReportStatus(reportId: string): Promise<{
    reportId: string;
    assessmentId?: string;
    reportType?: 'consultant' | 'client';
    status: 'generating' | 'completed' | 'failed';
    fileUrl?: string;
    fileSizeBytes?: number;
    generatedAt?: string;
    expiresAt?: string;
    progress?: number;
    message?: string;
    error?: string;
    estimatedTimeRemaining?: number;
  }> {
    const response = await this.client.get(`/reports/status/${reportId}`);
    return response.data;
  }

  /**
   * Download report
   * GET /reports/download/:reportId
   */
  async downloadReport(reportId: string): Promise<{ pdfUrl: string }> {
    const response = await this.client.get(`/reports/download/${reportId}`);
    return response.data;
  }

  /**
   * Poll report status until complete
   * Helper method for waiting on async report generation
   */
  private async pollReportStatus(
    reportId: string,
    maxAttempts = 30,
    interval = 2000
  ): Promise<any> {
    for (let i = 0; i < maxAttempts; i++) {
      const status = await this.getReportStatus(reportId);

      if (status.status === 'completed') {
        return status;
      }

      if (status.status === 'failed') {
        throw new Error(status.error || 'Report generation failed');
      }

      // Wait before next poll
      await new Promise((resolve) => setTimeout(resolve, interval));
    }

    throw new Error('Report generation timeout - exceeded maximum polling attempts');
  }

  // ==========================================
  // USER MANAGEMENT ENDPOINTS (Section 6)
  // ==========================================

  /**
   * Get current user profile
   * GET /users/me
   */
  async getCurrentUser(): Promise<User> {
    const response = await this.client.get<User>('/users/me');
    return response.data;
  }

  /**
   * Update current user profile
   * PATCH /users/me
   */
  async updateCurrentUser(data: {
    firstName?: string;
    lastName?: string;
    email?: string;
  }): Promise<User> {
    const response = await this.client.patch<User>('/users/me', data);
    return response.data;
  }

  /**
   * Change password
   * POST /users/me/change-password
   */
  async changePassword(
    currentPassword: string,
    newPassword: string
  ): Promise<{ message: string }> {
    const response = await this.client.post<{ message: string }>('/users/me/change-password', {
      currentPassword,
      newPassword,
    });
    return response.data;
  }
}

// Export singleton instance
export const realApi = new RealApiClient();
export default realApi;
