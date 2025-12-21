import api from './api';
import { Assessment, Question, Answer } from '@store/slices/assessmentSlice';

/**
 * Assessment Service
 * Handles all assessment-related API calls
 */

export interface CreateAssessmentRequest {
  clientName: string;
}

export interface GenerateReportResponse {
  reportUrl: string;
  reportId: string;
}

export const assessmentService = {
  /**
   * Get all questions for the assessment
   */
  getQuestions: async (): Promise<Question[]> => {
    const response = await api.get<Question[]>('/questions');
    return response.data;
  },

  /**
   * Create a new assessment
   */
  createAssessment: async (clientName: string): Promise<Assessment> => {
    const response = await api.post<Assessment>('/assessments', { clientName });
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
};

export default assessmentService;
