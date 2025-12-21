import { Request } from 'express';

export interface AuthenticatedRequest extends Request {
  consultantId?: string;
  userId?: string;
}

export enum AssessmentStatus {
  DRAFT = 'draft',
  IN_PROGRESS = 'in_progress',
  COMPLETED = 'completed',
}

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
  discMapping?: {
    D?: number;
    I?: number;
    S?: number;
    C?: number;
  };
  phaseMapping?: {
    [key in FinancialPhase]?: number;
  };
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

export interface AssessmentResponse {
  questionId: string;
  answer: any;
  notApplicable?: boolean;
  consultantNotes?: string;
}

export interface ValidationError {
  field: string;
  message: string;
}

export interface ValidationResult {
  valid: boolean;
  errors?: ValidationError[];
}

export interface CompletionValidationResult extends ValidationResult {
  missingQuestions?: string[];
}

export interface ProgressCalculationResult {
  progress: number;
  totalQuestions: number;
  answeredQuestions: number;
}
