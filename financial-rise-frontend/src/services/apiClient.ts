import { apiService as realApi } from './api';
import { mockApi } from './mockApi';
import type {
  Assessment,
  AssessmentDetail,
  CreateAssessmentRequest,
  UpdateAssessmentRequest,
  Questionnaire,
  GenerateReportsResponse,
  GenerateSingleReportResponse,
} from '@/types';

/**
 * API Client Facade
 * Toggles between mock and real API based on environment variable
 * VITE_USE_MOCK_API=true -> use mock data
 * VITE_USE_MOCK_API=false -> use real backend
 */

const USE_MOCK_API = import.meta.env.VITE_USE_MOCK_API === 'true';

console.log(`[API Client] Using ${USE_MOCK_API ? 'MOCK' : 'REAL'} API`);

/**
 * Unified API interface
 */
interface IApiClient {
  createAssessment(data: CreateAssessmentRequest): Promise<Assessment>;
  listAssessments(params?: {
    status?: string;
    limit?: number;
    offset?: number;
    sortBy?: string;
    sortOrder?: string;
  }): Promise<{ assessments: Assessment[]; total: number; limit: number; offset: number }>;
  getAssessment(assessmentId: string): Promise<AssessmentDetail>;
  updateAssessment(
    assessmentId: string,
    data: UpdateAssessmentRequest
  ): Promise<{
    assessmentId: string;
    status: string;
    progress: number;
    updatedAt: string;
    savedResponses: number;
  }>;
  deleteAssessment(assessmentId: string): Promise<void>;
  getQuestionnaire(): Promise<Questionnaire>;
  generateBothReports(assessmentId: string): Promise<GenerateReportsResponse>;
  generateConsultantReport(assessmentId: string): Promise<GenerateSingleReportResponse>;
  generateClientReport(assessmentId: string): Promise<GenerateSingleReportResponse>;
  downloadReport(reportId: string): Promise<{ pdfUrl: string }>;
}

/**
 * Export the appropriate API implementation
 */
export const apiClient: IApiClient = USE_MOCK_API ? mockApi : realApi;

export default apiClient;
