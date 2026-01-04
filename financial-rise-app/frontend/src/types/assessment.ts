/**
 * Assessment Type Definitions
 * Matches backend API response structures
 */

export type AssessmentStatus = 'draft' | 'in_progress' | 'completed';

export type FinancialPhase = 'stabilize' | 'organize' | 'build' | 'grow' | 'systemic';

export type DISCProfile = 'D' | 'I' | 'S' | 'C';

export interface Assessment {
  id: string;
  consultant_id: string;
  client_name: string;
  client_email: string;
  status: AssessmentStatus;
  created_at: string;
  updated_at: string;
  completed_at?: string;

  // Assessment results (available after completion)
  primary_phase?: FinancialPhase;
  secondary_phases?: FinancialPhase[];
  disc_profile?: DISCProfile;
  overall_score?: number;

  // Confidence scores
  before_confidence?: number;
  after_confidence?: number;

  // Report URLs (if generated)
  consultant_report_url?: string;
  client_report_url?: string;
}

export interface AssessmentListItem {
  id: string;
  client_name: string;
  client_email: string;
  status: AssessmentStatus;
  primary_phase?: FinancialPhase;
  created_at: string;
  updated_at: string;
  completed_at?: string;
}

export interface AssessmentFilters {
  status?: AssessmentStatus;
  phase?: FinancialPhase;
  search?: string;
  sortBy?: 'created_at' | 'updated_at' | 'client_name' | 'status';
  sortOrder?: 'asc' | 'desc';
  page?: number;
  limit?: number;
}

export interface AssessmentListResponse {
  assessments: AssessmentListItem[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}

export interface CreateAssessmentRequest {
  client_name: string;
  client_email: string;
}

export interface CreateAssessmentResponse {
  assessment: Assessment;
}
