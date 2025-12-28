import type {
  Assessment,
  AssessmentDetail,
  AssessmentResponse,
  AssessmentStatus,
  CreateAssessmentRequest,
  UpdateAssessmentRequest,
  Questionnaire,
  QuestionType,
  FinancialPhase,
  GenerateReportsResponse,
  GenerateSingleReportResponse,
  ReportType,
} from '@/types';

/**
 * Mock API Service
 * Implements API-CONTRACT.md v1.0 exactly for parallel development
 * Toggle with VITE_USE_MOCK_API environment variable
 */

// Delay helper to simulate network latency
const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

// Mock data storage (simulates backend database)
class MockDataStore {
  private assessments: Map<string, AssessmentDetail> = new Map();
  private questionnaireData: Questionnaire;
  private nextAssessmentId = 1;

  constructor() {
    this.questionnaireData = this.createMockQuestionnaire();
    this.seedMockAssessments();
  }

  private createMockQuestionnaire(): Questionnaire {
    return {
      version: '1.0',
      sections: [
        {
          sectionId: 'stabilize-section',
          title: 'Stabilize Phase',
          description: 'Basic financial order and compliance',
          phase: FinancialPhase.STABILIZE,
          order: 1,
          questions: [
            {
              questionId: 'FIN-001',
              text: 'How frequently do you review your financial statements?',
              type: QuestionType.SINGLE_CHOICE,
              required: true,
              order: 1,
              options: [
                {
                  optionId: 'weekly',
                  text: 'Weekly',
                  value: 'weekly',
                  discMapping: { D: 15, I: 5, S: 0, C: 20 },
                  phaseMapping: { stabilize: 20, organize: 15, build: 10, grow: 5, systemic: 15 },
                },
                {
                  optionId: 'monthly',
                  text: 'Monthly',
                  value: 'monthly',
                  discMapping: { D: 10, I: 10, S: 10, C: 15 },
                  phaseMapping: { stabilize: 15, organize: 10, build: 5, grow: 0, systemic: 10 },
                },
                {
                  optionId: 'quarterly',
                  text: 'Quarterly',
                  value: 'quarterly',
                  discMapping: { D: 5, I: 15, S: 15, C: 5 },
                  phaseMapping: { stabilize: 10, organize: 5, build: 0, grow: 0, systemic: 5 },
                },
                {
                  optionId: 'annually',
                  text: 'Annually or less',
                  value: 'annually',
                  discMapping: { D: 0, I: 20, S: 20, C: 0 },
                  phaseMapping: { stabilize: 5, organize: 0, build: 0, grow: 0, systemic: 0 },
                },
              ],
            },
            {
              questionId: 'FIN-002',
              text: 'Do you have a documented chart of accounts?',
              type: QuestionType.SINGLE_CHOICE,
              required: true,
              order: 2,
              options: [
                {
                  optionId: 'yes_custom',
                  text: 'Yes, customized for my business',
                  value: 'yes_custom',
                  discMapping: { D: 15, I: 5, S: 10, C: 20 },
                  phaseMapping: { stabilize: 10, organize: 20, build: 15, grow: 10, systemic: 10 },
                },
                {
                  optionId: 'yes_default',
                  text: 'Yes, using the default from my accounting software',
                  value: 'yes_default',
                  discMapping: { D: 5, I: 10, S: 15, C: 10 },
                  phaseMapping: { stabilize: 5, organize: 10, build: 5, grow: 0, systemic: 5 },
                },
                {
                  optionId: 'no',
                  text: 'No',
                  value: 'no',
                  discMapping: { D: 0, I: 20, S: 20, C: 0 },
                  phaseMapping: { stabilize: 0, organize: 0, build: 0, grow: 0, systemic: 0 },
                },
              ],
            },
            {
              questionId: 'FIN-003',
              text: 'How well do you understand your business tax obligations?',
              type: QuestionType.RATING,
              required: true,
              order: 3,
              options: [
                {
                  optionId: '1',
                  text: 'Not at all',
                  value: 1,
                  discMapping: { D: 0, I: 15, S: 20, C: 0 },
                  phaseMapping: { stabilize: 0, organize: 0, build: 0, grow: 0, systemic: 0 },
                },
                {
                  optionId: '2',
                  text: 'Slightly',
                  value: 2,
                  discMapping: { D: 5, I: 10, S: 15, C: 5 },
                  phaseMapping: { stabilize: 5, organize: 5, build: 0, grow: 0, systemic: 5 },
                },
                {
                  optionId: '3',
                  text: 'Moderately',
                  value: 3,
                  discMapping: { D: 10, I: 10, S: 10, C: 10 },
                  phaseMapping: { stabilize: 10, organize: 10, build: 5, grow: 0, systemic: 10 },
                },
                {
                  optionId: '4',
                  text: 'Well',
                  value: 4,
                  discMapping: { D: 15, I: 5, S: 5, C: 15 },
                  phaseMapping: { stabilize: 15, organize: 15, build: 10, grow: 5, systemic: 15 },
                },
                {
                  optionId: '5',
                  text: 'Very well',
                  value: 5,
                  discMapping: { D: 20, I: 0, S: 0, C: 20 },
                  phaseMapping: { stabilize: 20, organize: 20, build: 15, grow: 10, systemic: 20 },
                },
              ],
            },
          ],
        },
        {
          sectionId: 'organize-section',
          title: 'Organize Phase',
          description: 'Foundational systems and processes',
          phase: FinancialPhase.ORGANIZE,
          order: 2,
          questions: [
            {
              questionId: 'FIN-004',
              text: 'Do you have a budget for your business?',
              type: QuestionType.SINGLE_CHOICE,
              required: true,
              order: 4,
              options: [
                {
                  optionId: 'detailed',
                  text: 'Yes, detailed budget with regular reviews',
                  value: 'detailed',
                  discMapping: { D: 15, I: 5, S: 10, C: 20 },
                  phaseMapping: { stabilize: 15, organize: 20, build: 15, grow: 10, systemic: 15 },
                },
                {
                  optionId: 'basic',
                  text: 'Yes, basic budget',
                  value: 'basic',
                  discMapping: { D: 10, I: 10, S: 15, C: 10 },
                  phaseMapping: { stabilize: 10, organize: 15, build: 10, grow: 5, systemic: 10 },
                },
                {
                  optionId: 'no',
                  text: 'No budget',
                  value: 'no',
                  discMapping: { D: 0, I: 20, S: 20, C: 0 },
                  phaseMapping: { stabilize: 5, organize: 0, build: 0, grow: 0, systemic: 0 },
                },
              ],
            },
            {
              questionId: 'FIN-005',
              text: 'Which accounting systems do you use?',
              type: QuestionType.MULTIPLE_CHOICE,
              required: true,
              order: 5,
              options: [
                {
                  optionId: 'quickbooks',
                  text: 'QuickBooks',
                  value: 'quickbooks',
                  discMapping: { D: 10, I: 10, S: 10, C: 10 },
                  phaseMapping: { stabilize: 10, organize: 15, build: 10, grow: 5, systemic: 10 },
                },
                {
                  optionId: 'xero',
                  text: 'Xero',
                  value: 'xero',
                  discMapping: { D: 10, I: 10, S: 10, C: 10 },
                  phaseMapping: { stabilize: 10, organize: 15, build: 10, grow: 5, systemic: 10 },
                },
                {
                  optionId: 'freshbooks',
                  text: 'FreshBooks',
                  value: 'freshbooks',
                  discMapping: { D: 5, I: 15, S: 15, C: 5 },
                  phaseMapping: { stabilize: 5, organize: 10, build: 5, grow: 0, systemic: 5 },
                },
                {
                  optionId: 'spreadsheet',
                  text: 'Spreadsheets (Excel/Google Sheets)',
                  value: 'spreadsheet',
                  discMapping: { D: 0, I: 10, S: 10, C: 15 },
                  phaseMapping: { stabilize: 5, organize: 5, build: 0, grow: 0, systemic: 5 },
                },
                {
                  optionId: 'none',
                  text: 'None',
                  value: 'none',
                  discMapping: { D: 0, I: 20, S: 20, C: 0 },
                  phaseMapping: { stabilize: 0, organize: 0, build: 0, grow: 0, systemic: 0 },
                },
              ],
            },
          ],
        },
        {
          sectionId: 'build-section',
          title: 'Build Phase',
          description: 'Robust operational systems',
          phase: FinancialPhase.BUILD,
          order: 3,
          questions: [
            {
              questionId: 'FIN-006',
              text: 'Do you have documented financial processes and procedures?',
              type: QuestionType.SINGLE_CHOICE,
              required: true,
              order: 6,
              options: [
                {
                  optionId: 'comprehensive',
                  text: 'Yes, comprehensive SOPs',
                  value: 'comprehensive',
                  discMapping: { D: 15, I: 0, S: 5, C: 20 },
                  phaseMapping: { stabilize: 15, organize: 20, build: 20, grow: 15, systemic: 15 },
                },
                {
                  optionId: 'some',
                  text: 'Some documented processes',
                  value: 'some',
                  discMapping: { D: 10, I: 10, S: 10, C: 10 },
                  phaseMapping: { stabilize: 10, organize: 15, build: 15, grow: 10, systemic: 10 },
                },
                {
                  optionId: 'no',
                  text: 'No documentation',
                  value: 'no',
                  discMapping: { D: 0, I: 20, S: 20, C: 0 },
                  phaseMapping: { stabilize: 5, organize: 5, build: 0, grow: 0, systemic: 0 },
                },
              ],
            },
          ],
        },
        {
          sectionId: 'grow-section',
          title: 'Grow Phase',
          description: 'Strategic financial planning and forecasting',
          phase: FinancialPhase.GROW,
          order: 4,
          questions: [
            {
              questionId: 'FIN-007',
              text: 'Do you create financial projections for your business?',
              type: QuestionType.SINGLE_CHOICE,
              required: true,
              order: 7,
              options: [
                {
                  optionId: 'regular',
                  text: 'Yes, regular multi-year projections',
                  value: 'regular',
                  discMapping: { D: 20, I: 0, S: 0, C: 20 },
                  phaseMapping: { stabilize: 10, organize: 15, build: 20, grow: 20, systemic: 15 },
                },
                {
                  optionId: 'occasional',
                  text: 'Occasionally',
                  value: 'occasional',
                  discMapping: { D: 10, I: 10, S: 10, C: 10 },
                  phaseMapping: { stabilize: 5, organize: 10, build: 15, grow: 15, systemic: 10 },
                },
                {
                  optionId: 'no',
                  text: 'No',
                  value: 'no',
                  discMapping: { D: 0, I: 20, S: 20, C: 0 },
                  phaseMapping: { stabilize: 0, organize: 0, build: 5, grow: 0, systemic: 0 },
                },
              ],
            },
          ],
        },
        {
          sectionId: 'systemic-section',
          title: 'Systemic (Financial Literacy)',
          description: 'Understanding and acting on financial reports',
          phase: FinancialPhase.SYSTEMIC,
          order: 5,
          questions: [
            {
              questionId: 'FIN-008',
              text: 'How comfortable are you reading financial reports?',
              type: QuestionType.RATING,
              required: true,
              order: 8,
              options: [
                {
                  optionId: '1',
                  text: 'Not comfortable',
                  value: 1,
                  discMapping: { D: 0, I: 20, S: 20, C: 0 },
                  phaseMapping: { stabilize: 0, organize: 0, build: 0, grow: 0, systemic: 0 },
                },
                {
                  optionId: '2',
                  text: 'Slightly comfortable',
                  value: 2,
                  discMapping: { D: 5, I: 15, S: 15, C: 5 },
                  phaseMapping: { stabilize: 5, organize: 5, build: 5, grow: 0, systemic: 5 },
                },
                {
                  optionId: '3',
                  text: 'Moderately comfortable',
                  value: 3,
                  discMapping: { D: 10, I: 10, S: 10, C: 10 },
                  phaseMapping: { stabilize: 10, organize: 10, build: 10, grow: 5, systemic: 10 },
                },
                {
                  optionId: '4',
                  text: 'Very comfortable',
                  value: 4,
                  discMapping: { D: 15, I: 5, S: 5, C: 15 },
                  phaseMapping: { stabilize: 15, organize: 15, build: 15, grow: 10, systemic: 15 },
                },
                {
                  optionId: '5',
                  text: 'Extremely comfortable',
                  value: 5,
                  discMapping: { D: 20, I: 0, S: 0, C: 20 },
                  phaseMapping: { stabilize: 20, organize: 20, build: 20, grow: 15, systemic: 20 },
                },
              ],
            },
            {
              questionId: 'FIN-009',
              text: 'What additional financial challenges are you facing?',
              type: QuestionType.TEXT,
              required: false,
              order: 9,
            },
          ],
        },
      ],
    };
  }

  private seedMockAssessments() {
    // Mock assessment 1: In Progress
    const assessment1: AssessmentDetail = {
      assessmentId: 'a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d',
      clientName: 'John Smith',
      businessName: 'Acme Corp',
      clientEmail: 'john@acmecorp.com',
      status: AssessmentStatus.IN_PROGRESS,
      progress: 44.44, // 4 out of 9 questions answered
      createdAt: '2025-12-20T08:00:00Z',
      updatedAt: '2025-12-26T14:30:00Z',
      startedAt: '2025-12-20T09:15:00Z',
      completedAt: null,
      responses: [
        {
          questionId: 'FIN-001',
          answer: 'monthly',
          notApplicable: false,
          consultantNotes: 'Client uses QuickBooks',
          answeredAt: '2025-12-20T09:30:00Z',
        },
        {
          questionId: 'FIN-002',
          answer: 'yes_default',
          notApplicable: false,
          answeredAt: '2025-12-20T09:35:00Z',
        },
        {
          questionId: 'FIN-003',
          answer: 3,
          notApplicable: false,
          consultantNotes: 'Working with a CPA',
          answeredAt: '2025-12-20T09:40:00Z',
        },
        {
          questionId: 'FIN-004',
          answer: 'basic',
          notApplicable: false,
          answeredAt: '2025-12-26T14:30:00Z',
        },
      ],
    };

    // Mock assessment 2: Draft
    const assessment2: AssessmentDetail = {
      assessmentId: 'b2c3d4e5-f6a7-5b6c-9d0e-1f2a3b4c5d6e',
      clientName: 'Jane Doe',
      businessName: 'Tech Startup LLC',
      clientEmail: 'jane@techstartup.com',
      status: AssessmentStatus.DRAFT,
      progress: 0,
      createdAt: '2025-12-27T10:00:00Z',
      updatedAt: '2025-12-27T10:00:00Z',
      startedAt: null,
      completedAt: null,
      responses: [],
    };

    this.assessments.set(assessment1.assessmentId, assessment1);
    this.assessments.set(assessment2.assessmentId, assessment2);
  }

  getQuestionnaire(): Questionnaire {
    return this.questionnaireData;
  }

  getAssessment(assessmentId: string): AssessmentDetail | undefined {
    return this.assessments.get(assessmentId);
  }

  getAllAssessments(): AssessmentDetail[] {
    return Array.from(this.assessments.values());
  }

  createAssessment(data: CreateAssessmentRequest): AssessmentDetail {
    const assessmentId = `mock-${this.nextAssessmentId++}-${Date.now()}`;
    const now = new Date().toISOString();

    const newAssessment: AssessmentDetail = {
      assessmentId,
      clientName: data.clientName,
      businessName: data.businessName,
      clientEmail: data.clientEmail,
      status: AssessmentStatus.DRAFT,
      progress: 0,
      createdAt: now,
      updatedAt: now,
      startedAt: null,
      completedAt: null,
      responses: [],
    };

    this.assessments.set(assessmentId, newAssessment);
    return newAssessment;
  }

  updateAssessment(
    assessmentId: string,
    data: UpdateAssessmentRequest
  ): AssessmentDetail | undefined {
    const assessment = this.assessments.get(assessmentId);
    if (!assessment) return undefined;

    const now = new Date().toISOString();

    // Update status
    if (data.status) {
      assessment.status = data.status;
      if (data.status === AssessmentStatus.IN_PROGRESS && !assessment.startedAt) {
        assessment.startedAt = now;
      }
      if (data.status === AssessmentStatus.COMPLETED) {
        assessment.completedAt = now;
        assessment.progress = 100;
      }
    }

    // Update responses
    if (data.responses) {
      data.responses.forEach((newResponse) => {
        const existingIndex = assessment.responses.findIndex(
          (r) => r.questionId === newResponse.questionId
        );

        const responseWithTimestamp = {
          ...newResponse,
          answeredAt: now,
        };

        if (existingIndex >= 0) {
          assessment.responses[existingIndex] = responseWithTimestamp;
        } else {
          assessment.responses.push(responseWithTimestamp);
        }
      });

      // Recalculate progress
      const totalQuestions = this.questionnaireData.sections.reduce(
        (sum, section) => sum + section.questions.length,
        0
      );
      const answeredQuestions = assessment.responses.filter(
        (r) => !r.notApplicable || r.answer !== null
      ).length;
      assessment.progress = (answeredQuestions / totalQuestions) * 100;
    }

    assessment.updatedAt = now;
    this.assessments.set(assessmentId, assessment);
    return assessment;
  }

  deleteAssessment(assessmentId: string): boolean {
    return this.assessments.delete(assessmentId);
  }
}

// Singleton instance
const mockStore = new MockDataStore();

/**
 * Mock API implementation matching API-CONTRACT.md
 */
export const mockApi = {
  /**
   * Create Assessment
   * POST /assessments
   */
  async createAssessment(data: CreateAssessmentRequest): Promise<Assessment> {
    await delay(300);
    const assessment = mockStore.createAssessment(data);
    return assessment;
  },

  /**
   * List Assessments
   * GET /assessments
   */
  async listAssessments(params?: {
    status?: string;
    limit?: number;
    offset?: number;
    sortBy?: string;
    sortOrder?: string;
  }): Promise<{ assessments: Assessment[]; total: number; limit: number; offset: number }> {
    await delay(200);

    let assessments = mockStore.getAllAssessments();

    // Filter by status
    if (params?.status) {
      assessments = assessments.filter((a) => a.status === params.status);
    }

    // Sort
    const sortBy = params?.sortBy || 'updatedAt';
    const sortOrder = params?.sortOrder || 'desc';
    assessments.sort((a, b) => {
      const aVal = a[sortBy as keyof Assessment];
      const bVal = b[sortBy as keyof Assessment];
      if (aVal < bVal) return sortOrder === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortOrder === 'asc' ? 1 : -1;
      return 0;
    });

    // Paginate
    const limit = params?.limit || 10;
    const offset = params?.offset || 0;
    const paginatedAssessments = assessments.slice(offset, offset + limit);

    return {
      assessments: paginatedAssessments,
      total: assessments.length,
      limit,
      offset,
    };
  },

  /**
   * Get Assessment
   * GET /assessments/:id
   */
  async getAssessment(assessmentId: string): Promise<AssessmentDetail> {
    await delay(200);
    const assessment = mockStore.getAssessment(assessmentId);
    if (!assessment) {
      throw new Error('Assessment not found');
    }
    return assessment;
  },

  /**
   * Update Assessment
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
    await delay(300);
    const assessment = mockStore.updateAssessment(assessmentId, data);
    if (!assessment) {
      throw new Error('Assessment not found');
    }
    return {
      assessmentId: assessment.assessmentId,
      status: assessment.status,
      progress: assessment.progress,
      updatedAt: assessment.updatedAt,
      savedResponses: assessment.responses.length,
    };
  },

  /**
   * Delete Assessment
   * DELETE /assessments/:id
   */
  async deleteAssessment(assessmentId: string): Promise<void> {
    await delay(200);
    const deleted = mockStore.deleteAssessment(assessmentId);
    if (!deleted) {
      throw new Error('Assessment not found');
    }
  },

  /**
   * Get Questionnaire
   * GET /questionnaire
   */
  async getQuestionnaire(): Promise<Questionnaire> {
    await delay(200);
    return mockStore.getQuestionnaire();
  },

  /**
   * Generate Both Reports
   * POST /assessments/:id/reports
   */
  async generateBothReports(assessmentId: string): Promise<GenerateReportsResponse> {
    await delay(1500); // Simulate PDF generation time
    const now = new Date().toISOString();
    return {
      success: true,
      data: {
        consultantReport: {
          reportId: `mock-consultant-${Date.now()}`,
          reportType: ReportType.CONSULTANT,
          assessmentId,
          pdfUrl: `https://mock-storage.example.com/reports/consultant-${assessmentId}.pdf`,
          generatedAt: now,
        },
        clientReport: {
          reportId: `mock-client-${Date.now()}`,
          reportType: ReportType.CLIENT,
          assessmentId,
          pdfUrl: `https://mock-storage.example.com/reports/client-${assessmentId}.pdf`,
          generatedAt: now,
        },
      },
    };
  },

  /**
   * Generate Consultant Report
   * POST /assessments/:id/reports/consultant
   */
  async generateConsultantReport(
    assessmentId: string
  ): Promise<GenerateSingleReportResponse> {
    await delay(1500);
    const now = new Date().toISOString();
    return {
      success: true,
      data: {
        reportId: `mock-consultant-${Date.now()}`,
        reportType: ReportType.CONSULTANT,
        assessmentId,
        pdfUrl: `https://mock-storage.example.com/reports/consultant-${assessmentId}.pdf`,
        generatedAt: now,
      },
    };
  },

  /**
   * Generate Client Report
   * POST /assessments/:id/reports/client
   */
  async generateClientReport(assessmentId: string): Promise<GenerateSingleReportResponse> {
    await delay(1500);
    const now = new Date().toISOString();
    return {
      success: true,
      data: {
        reportId: `mock-client-${Date.now()}`,
        reportType: ReportType.CLIENT,
        assessmentId,
        pdfUrl: `https://mock-storage.example.com/reports/client-${assessmentId}.pdf`,
        generatedAt: now,
      },
    };
  },

  /**
   * Download Report
   * GET /reports/:id/download
   */
  async downloadReport(reportId: string): Promise<{ pdfUrl: string }> {
    await delay(100);
    return {
      pdfUrl: `https://mock-storage.example.com/reports/${reportId}.pdf`,
    };
  },
};

export default mockApi;
