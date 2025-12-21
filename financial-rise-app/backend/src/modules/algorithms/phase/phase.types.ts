import { FinancialPhase } from '../entities/phase-result.entity';

/**
 * Raw phase scores aggregated from question responses
 */
export interface RawPhaseScores {
  stabilize: number;
  organize: number;
  build: number;
  grow: number;
  systemic: number;
}

/**
 * Normalized phase scores (0-100 scale)
 */
export interface NormalizedPhaseScores {
  stabilize: number;
  organize: number;
  build: number;
  grow: number;
  systemic: number;
}

/**
 * Phase weights from a question response option
 */
export interface PhaseWeights {
  stabilize_score: number;
  organize_score: number;
  build_score: number;
  grow_score: number;
  systemic_score: number;
}

/**
 * Question response with phase weights
 */
export interface PhaseQuestionResponse {
  question_id: string;
  selected_value: string;
  weights: PhaseWeights;
}

/**
 * Complete phase determination result
 */
export interface PhaseResultData {
  assessment_id: string;
  stabilize_score: number;
  organize_score: number;
  build_score: number;
  grow_score: number;
  systemic_score: number;
  primary_phase: FinancialPhase;
  secondary_phases: string[];
  transition_state: boolean;
  calculated_at: Date;
}

/**
 * Phase ranking for determining primary/secondary
 */
export interface PhaseRanking {
  phase: FinancialPhase;
  score: number;
}

/**
 * Phase details for enrichment
 */
export interface PhaseDetails {
  name: string;
  objective: string;
  key_focus_areas: string[];
}
