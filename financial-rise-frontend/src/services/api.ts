import axios, { AxiosInstance, AxiosError } from 'axios';
import type {
  Assessment,
  AssessmentDetail,
  CreateAssessmentRequest,
  UpdateAssessmentRequest,
  Questionnaire,
  ApiError,
} from '@/types';

/**
 * API Service
 * Connects to Financial RISE Backend API (Work Stream 6)
 */

class ApiService {
  private client: AxiosInstance;

  constructor() {
    this.client = axios.create({
      baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:3000/api/v1',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Request interceptor to add JWT token
    this.client.interceptors.request.use(
      (config) => {
        const token = this.getToken();
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    // Response interceptor for error handling
    this.client.interceptors.response.use(
      (response) => response,
      (error: AxiosError<ApiError>) => {
        if (error.response?.status === 401) {
          // Token expired or invalid
          this.clearToken();
          window.location.href = '/login';
        }
        return Promise.reject(error);
      }
    );
  }

  private getToken(): string | null {
    return localStorage.getItem('auth_token');
  }

  private clearToken(): void {
    localStorage.removeItem('auth_token');
  }

  public setToken(token: string): void {
    localStorage.setItem('auth_token', token);
  }

  // Assessment endpoints

  async createAssessment(data: CreateAssessmentRequest): Promise<Assessment> {
    const response = await this.client.post<Assessment>('/assessments', data);
    return response.data;
  }

  async listAssessments(params?: {
    status?: string;
    limit?: number;
    offset?: number;
    sortBy?: string;
    sortOrder?: string;
  }): Promise<{ assessments: Assessment[]; total: number; limit: number; offset: number }> {
    const response = await this.client.get('/assessments', { params });
    return response.data;
  }

  async getAssessment(assessmentId: string): Promise<AssessmentDetail> {
    const response = await this.client.get<AssessmentDetail>(`/assessments/${assessmentId}`);
    return response.data;
  }

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

  async deleteAssessment(assessmentId: string): Promise<void> {
    await this.client.delete(`/assessments/${assessmentId}`);
  }

  // Questionnaire endpoint

  async getQuestionnaire(): Promise<Questionnaire> {
    const response = await this.client.get<Questionnaire>('/questionnaire');
    return response.data;
  }
}

export const apiService = new ApiService();
export default apiService;
