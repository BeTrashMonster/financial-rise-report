import { realApi } from './realApi';
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
 *
 * Usage:
 * - Development with mock data: Set VITE_USE_MOCK_API=true in .env
 * - Development with real backend: Set VITE_USE_MOCK_API=false in .env
 * - Production: Always uses real API (VITE_USE_MOCK_API=false)
 */

const USE_MOCK_API = import.meta.env.VITE_USE_MOCK_API === 'true';

console.log(`[API Client] Using ${USE_MOCK_API ? 'MOCK' : 'REAL'} API`);
console.log(`[API Client] Base URL: ${import.meta.env.VITE_API_BASE_URL || 'http://localhost:3000/api/v1'}`);

/**
 * Unified API interface
 * Both mock and real API must implement this interface
 */
interface IApiClient {
  // Assessment endpoints
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

  // Questionnaire endpoints
  getQuestionnaire(): Promise<Questionnaire>;

  // Report endpoints
  generateBothReports(assessmentId: string): Promise<GenerateReportsResponse>;
  generateConsultantReport(assessmentId: string): Promise<GenerateSingleReportResponse>;
  generateClientReport(assessmentId: string): Promise<GenerateSingleReportResponse>;
  downloadReport(reportId: string): Promise<{ pdfUrl: string }>;
}

/**
 * Export the appropriate API implementation
 * This is the single source of truth for all API calls in the application
 */
export const apiClient: IApiClient = USE_MOCK_API ? mockApi : realApi;

/**
 * Export realApi for direct access to authentication methods
 * (not available in mockApi interface)
 */
export { realApi };

export default apiClient;
