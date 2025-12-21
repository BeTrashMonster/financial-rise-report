import { DISCType, ConfidenceLevel } from '../entities/disc-profile.entity';
import { FinancialPhase } from '../entities/phase-result.entity';

/**
 * DISC Profile response DTO
 */
export class DISCProfileDto {
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
 * DISC Profile with personality summary DTO
 */
export class DISCProfileWithSummaryDto extends DISCProfileDto {
  personality_summary: {
    primary_traits: string[];
    communication_style: string;
    report_preferences: {
      focus: string;
      visual_style: string;
    };
  };
}

/**
 * Phase Results response DTO
 */
export class PhaseResultsDto {
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
 * Phase Results with details DTO
 */
export class PhaseResultsWithDetailsDto extends PhaseResultsDto {
  phase_details: Record<
    string,
    {
      name: string;
      objective: string;
      key_focus_areas: string[];
    }
  >;
}

/**
 * Combined calculation result DTO
 */
export class CalculationResultDto {
  assessment_id: string;
  disc_profile: DISCProfileDto;
  phase_results: PhaseResultsDto;
  calculated_at: Date;
}
