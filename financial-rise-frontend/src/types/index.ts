// Assessment types
export enum AssessmentStatus {
  DRAFT = 'draft',
  IN_PROGRESS = 'in_progress',
  COMPLETED = 'completed',
}

export interface Assessment {
  assessmentId: string;
  clientName: string;
  businessName: string;
  clientEmail?: string;
  status: AssessmentStatus;
  progress: number;
  createdAt: string;
  updatedAt: string;
  startedAt?: string | null;
  completedAt?: string | null;
}

export interface AssessmentDetail extends Assessment {
  responses: AssessmentResponse[];
}

export interface AssessmentResponse {
  questionId: string;
  answer: any;
  notApplicable?: boolean;
  consultantNotes?: string;
  answeredAt?: string | null;
}

// Questionnaire types
export enum QuestionType {
  SINGLE_CHOICE = 'single_choice',
  MULTIPLE_CHOICE = 'multiple_choice',
  RATING = 'rating',
  TEXT = 'text',
  CONDITIONAL = 'conditional',
}

export enum FinancialPhase {
  STABILIZE = 'stabilize',
  ORGANIZE = 'organize',
  BUILD = 'build',
  GROW = 'grow',
  SYSTEMIC = 'systemic',
}

export interface QuestionOption {
  optionId: string;
  text: string;
  value: any;
  discMapping?: Record<string, number>;
  phaseMapping?: Record<string, number>;
}

export interface Question {
  questionId: string;
  text: string;
  type: QuestionType;
  required: boolean;
  order: number;
  options?: QuestionOption[];
  conditionalLogic?: {
    dependsOn: string | null;
    showWhen?: {
      optionId: string;
      value: any;
    };
  };
}

export interface QuestionnaireSection {
  sectionId: string;
  title: string;
  description: string;
  phase: FinancialPhase;
  order: number;
  questions: Question[];
}

export interface Questionnaire {
  version: string;
  sections: QuestionnaireSection[];
}

// API types
export interface ApiError {
  error: {
    code: string;
    message: string;
    details?: any;
  };
}

export interface CreateAssessmentRequest {
  clientName: string;
  businessName: string;
  clientEmail: string;
  notes?: string;
}

export interface UpdateAssessmentRequest {
  responses?: Array<{
    questionId: string;
    answer: any;
    notApplicable?: boolean;
    consultantNotes?: string;
  }>;
  status?: AssessmentStatus;
}

// UI State types
export interface AssessmentFormData {
  clientName: string;
  businessName: string;
  clientEmail: string;
  notes?: string;
}

export interface QuestionnaireState {
  currentQuestionIndex: number;
  responses: Map<string, AssessmentResponse>;
  isDirty: boolean;
  lastSavedAt: Date | null;
}
