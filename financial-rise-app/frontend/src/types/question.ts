/**
 * Question and Response Type Definitions
 * Matches backend API response structures
 */

export type QuestionType = 'single_choice' | 'multiple_choice' | 'rating' | 'text';

export type QuestionSection =
  | 'stabilize'
  | 'organize'
  | 'build'
  | 'grow'
  | 'systemic'
  | 'disc'
  | 'metadata';

export interface QuestionOption {
  value: string;
  label: string;
  weight?: number;
}

export interface Question {
  id: string;
  question_key: string;
  question_text: string;
  question_type: QuestionType;
  options: QuestionOption[] | Record<string, any> | null;
  required: boolean;
  display_order: number;
  section?: QuestionSection;
  created_at?: string;
  updated_at?: string;
}

export interface QuestionResponse {
  id?: string;
  assessmentId: string;
  questionId: string; // question_key
  answer: Record<string, any>;
  notApplicable?: boolean;
  consultantNotes?: string;
  created_at?: string;
  updated_at?: string;
}

export interface QuestionsMeta {
  totalQuestions: number;
  requiredQuestions: number;
  optionalQuestions: number;
}

export interface QuestionsResponse {
  questions: Question[];
  meta: QuestionsMeta;
}
