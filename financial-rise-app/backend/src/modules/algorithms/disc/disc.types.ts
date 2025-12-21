import { DISCType, ConfidenceLevel } from '../entities/disc-profile.entity';

/**
 * Raw DISC scores aggregated from question responses
 */
export interface RawDISCScores {
  D: number;
  I: number;
  S: number;
  C: number;
}

/**
 * Normalized DISC scores (0-100 scale)
 */
export interface NormalizedDISCScores {
  D: number;
  I: number;
  S: number;
  C: number;
}

/**
 * DISC weights from a question response option
 */
export interface DISCWeights {
  disc_d_score: number;
  disc_i_score: number;
  disc_s_score: number;
  disc_c_score: number;
}

/**
 * Question response with DISC weights
 */
export interface DISCQuestionResponse {
  question_id: string;
  selected_value: string;
  weights: DISCWeights;
}

/**
 * Complete DISC profile result
 */
export interface DISCProfileResult {
  assessment_id: string;
  d_score: number;
  i_score: number;
  s_score: number;
  c_score: number;
  primary_type: DISCType;
  secondary_type: DISCType | null;
  confidence_level: ConfidenceLevel;
  calculated_at: Date;
}

/**
 * DISC personality traits and communication preferences
 */
export interface DISCPersonalitySummary {
  primary_traits: string[];
  communication_style: string;
  report_preferences: {
    focus: string;
    visual_style: string;
  };
}
