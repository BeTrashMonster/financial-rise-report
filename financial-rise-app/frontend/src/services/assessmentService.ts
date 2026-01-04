import api from './api';
import { Assessment, Question, Answer } from '@store/slices/assessmentSlice';
import type { QuestionsResponse, QuestionResponse } from '@/types/question';
import type { DISCProfileWithSummary, PhaseResultsWithDetails } from '@/types/results';
import type {
  GenerateReportRequest,
  ReportAccepted,
  ReportStatusResponse,
  ReportDownloadResponse,
} from '@/types/reports';

/**
 * Assessment Service
 * Handles all assessment-related API calls
 */

export interface CreateAssessmentRequest {
  clientName: string;
  businessName: string;
  clientEmail: string;
  notes?: string;
}

export interface GenerateReportResponse {
  reportUrl: string;
  reportId: string;
}

export const assessmentService = {
  /**
   * Get all questions for the assessment
   */
  getQuestions: async (assessmentId?: string): Promise<QuestionsResponse> => {
    const params = assessmentId ? `?assessmentId=${assessmentId}` : '';
    const response = await api.get<QuestionsResponse>(`/questionnaire/questions${params}`);
    return response.data;
  },

  /**
   * Submit response to a question
   */
  submitResponse: async (data: QuestionResponse): Promise<QuestionResponse> => {
    const response = await api.post<QuestionResponse>('/questionnaire/responses', data);
    return response.data;
  },

  /**
   * Update existing response
   */
  updateResponse: async (
    responseId: string,
    data: Partial<QuestionResponse>
  ): Promise<QuestionResponse> => {
    const response = await api.patch<QuestionResponse>(
      `/questionnaire/responses/${responseId}`,
      data
    );
    return response.data;
  },

  /**
   * Create a new assessment
   */
  createAssessment: async (data: CreateAssessmentRequest): Promise<Assessment> => {
    const response = await api.post<Assessment>('/assessments', data);
    return response.data;
  },

  /**
   * Get all assessments for the current user
   */
  getAssessments: async (): Promise<Assessment[]> => {
    const response = await api.get<Assessment[]>('/assessments');
    return response.data;
  },

  /**
   * Get a specific assessment by ID
   */
  getAssessment: async (id: string): Promise<Assessment> => {
    const response = await api.get<Assessment>(`/assessments/${id}`);
    return response.data;
  },

  /**
   * Save an answer to an assessment
   */
  saveAnswer: async (assessmentId: string, answer: Answer): Promise<Assessment> => {
    const response = await api.post<Assessment>(
      `/assessments/${assessmentId}/answers`,
      answer
    );
    return response.data;
  },

  /**
   * Save multiple answers at once
   */
  saveAnswers: async (assessmentId: string, answers: Answer[]): Promise<Assessment> => {
    const response = await api.post<Assessment>(
      `/assessments/${assessmentId}/answers/bulk`,
      { answers }
    );
    return response.data;
  },

  /**
   * Submit assessment for completion
   */
  submitAssessment: async (assessmentId: string): Promise<Assessment> => {
    const response = await api.post<Assessment>(`/assessments/${assessmentId}/submit`);
    return response.data;
  },

  /**
   * Delete an assessment
   */
  deleteAssessment: async (assessmentId: string): Promise<void> => {
    await api.delete(`/assessments/${assessmentId}`);
  },

  /**
   * Generate reports for a completed assessment
   */
  generateReports: async (assessmentId: string): Promise<GenerateReportResponse> => {
    const response = await api.post<GenerateReportResponse>(
      `/assessments/${assessmentId}/reports`
    );
    return response.data;
  },

  /**
   * Download consultant report
   */
  downloadConsultantReport: async (assessmentId: string): Promise<Blob> => {
    const response = await api.get(`/assessments/${assessmentId}/reports/consultant`, {
      responseType: 'blob',
    });
    return response.data;
  },

  /**
   * Download client report
   */
  downloadClientReport: async (assessmentId: string): Promise<Blob> => {
    const response = await api.get(`/assessments/${assessmentId}/reports/client`, {
      responseType: 'blob',
    });
    return response.data;
  },

  /**
   * Get DISC profile for an assessment
   */
  getDISCProfile: async (assessmentId: string): Promise<DISCProfileWithSummary> => {
    const response = await api.get<DISCProfileWithSummary>(
      `/assessments/${assessmentId}/disc-profile`
    );
    return response.data;
  },

  /**
   * Get phase results for an assessment
   */
  getPhaseResults: async (assessmentId: string): Promise<PhaseResultsWithDetails> => {
    const response = await api.get<PhaseResultsWithDetails>(
      `/assessments/${assessmentId}/phase-results`
    );
    return response.data;
  },

  /**
   * Generate consultant report for an assessment
   */
  generateConsultantReport: async (assessmentId: string): Promise<ReportAccepted> => {
    const response = await api.post<ReportAccepted>('/reports/generate/consultant', {
      assessmentId,
    });
    return response.data;
  },

  /**
   * Generate client report for an assessment
   */
  generateClientReport: async (assessmentId: string): Promise<ReportAccepted> => {
    const response = await api.post<ReportAccepted>('/reports/generate/client', {
      assessmentId,
    });
    return response.data;
  },

  /**
   * Get report generation status
   */
  getReportStatus: async (reportId: string): Promise<ReportStatusResponse> => {
    const response = await api.get<ReportStatusResponse>(`/reports/status/${reportId}`);
    return response.data;
  },

  /**
   * Get report download URL
   */
  getReportDownloadUrl: async (reportId: string): Promise<ReportDownloadResponse> => {
    const response = await api.get<ReportDownloadResponse>(`/reports/download/${reportId}`);
    return response.data;
  },
};

export default assessmentService;
