/**
 * Results Type Definitions
 * Matches backend API response structures for DISC and Phase results
 */

export type DISCType = 'D' | 'I' | 'S' | 'C';
export type ConfidenceLevel = 'low' | 'medium' | 'high';
export type FinancialPhase = 'stabilize' | 'organize' | 'build' | 'grow' | 'systemic';

export interface DISCProfile {
  assessment_id: string;
  d_score: number;
  i_score: number;
  s_score: number;
  c_score: number;
  primary_type: DISCType;
  secondary_type: DISCType | null;
  confidence_level: ConfidenceLevel;
  calculated_at: string;
}

export interface PersonalitySummary {
  primary_traits: string[];
  communication_style: string;
  report_preferences: {
    focus: string;
    visual_style: string;
  };
}

export interface DISCProfileWithSummary extends DISCProfile {
  personality_summary: PersonalitySummary;
}

export interface PhaseDetails {
  name: string;
  objective: string;
  key_focus_areas: string[];
}

export interface PhaseResults {
  assessment_id: string;
  stabilize_score: number;
  organize_score: number;
  build_score: number;
  grow_score: number;
  systemic_score: number;
  primary_phase: FinancialPhase;
  secondary_phases: string[];
  transition_state: boolean;
  calculated_at: string;
}

export interface PhaseResultsWithDetails extends PhaseResults {
  phase_details: Record<string, PhaseDetails>;
}

export interface CalculationResult {
  assessment_id: string;
  disc_profile: DISCProfile;
  phase_results: PhaseResults;
  calculated_at: string;
}
