import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { PhaseResult, FinancialPhase } from '../entities/phase-result.entity';
import {
  PhaseQuestionResponse,
  RawPhaseScores,
  NormalizedPhaseScores,
  PhaseResultData,
  PhaseRanking,
} from './phase.types';

/**
 * Service for determining financial readiness phases from assessment responses
 *
 * Implements the Phase Determination algorithm as specified in:
 * plans/work-stream-7-implementation-spec.md Section 3
 */
@Injectable()
export class PhaseCalculatorService {
  private readonly logger = new Logger(PhaseCalculatorService.name);
  private readonly SECONDARY_PHASE_THRESHOLD = 15; // percentage points
  private readonly CRITICAL_STABILIZE_THRESHOLD = 30; // Minimum stabilize % before forcing stabilize phase

  constructor(
    @InjectRepository(PhaseResult)
    private phaseResultRepository: Repository<PhaseResult>,
  ) {}

  /**
   * Calculate phase determination for an assessment
   *
   * @param assessmentId - UUID of the assessment
   * @param responses - Array of question responses with phase weights
   * @returns Complete phase result data
   */
  async calculate(
    assessmentId: string,
    responses: PhaseQuestionResponse[],
  ): Promise<PhaseResultData> {
    this.logger.log(`Calculating phase results for assessment ${assessmentId}`);

    // Step 1: Validate inputs
    this.validateInputs(responses);

    // Step 2: Aggregate raw scores
    const rawScores = this.aggregateScores(responses);

    // Step 3: Normalize scores to 0-100 scale
    const normalizedScores = this.normalizeScores(rawScores);

    // Step 4: Rank phases by score
    const rankings = this.rankPhases(normalizedScores);

    // Step 5: Apply phase sequencing logic
    const { primaryPhase, secondaryPhases, transitionState } = this.applySequencingLogic(
      normalizedScores,
      rankings,
    );

    // Step 6: Create and save result
    const result = this.phaseResultRepository.create({
      assessment_id: assessmentId,
      stabilize_score: normalizedScores.stabilize,
      organize_score: normalizedScores.organize,
      build_score: normalizedScores.build,
      grow_score: normalizedScores.grow,
      systemic_score: normalizedScores.systemic,
      primary_phase: primaryPhase,
      secondary_phases: secondaryPhases,
      transition_state: transitionState,
    });

    const savedResult = await this.phaseResultRepository.save(result);

    this.logger.log(
      `Phase results calculated: Primary=${primaryPhase}, Secondary=[${secondaryPhases.join(', ')}], Transition=${transitionState}`,
    );

    return {
      assessment_id: savedResult.assessment_id,
      stabilize_score: savedResult.stabilize_score,
      organize_score: savedResult.organize_score,
      build_score: savedResult.build_score,
      grow_score: savedResult.grow_score,
      systemic_score: savedResult.systemic_score,
      primary_phase: savedResult.primary_phase,
      secondary_phases: savedResult.secondary_phases,
      transition_state: savedResult.transition_state,
      calculated_at: savedResult.calculated_at,
    };
  }

  /**
   * Validate that we have phase question responses
   *
   * @param responses - Question responses to validate
   * @throws Error if no responses provided
   */
  validateInputs(responses: PhaseQuestionResponse[]): void {
    if (responses.length === 0) {
      throw new Error('No phase question responses provided');
    }
  }

  /**
   * Aggregate raw phase scores from all responses
   *
   * Note: The question bank uses "readiness scores" where higher = better
   *
   * @param responses - Question responses with phase weights
   * @returns Raw aggregated scores
   */
  aggregateScores(responses: PhaseQuestionResponse[]): RawPhaseScores {
    const scores: RawPhaseScores = {
      stabilize: 0,
      organize: 0,
      build: 0,
      grow: 0,
      systemic: 0,
    };

    for (const response of responses) {
      scores.stabilize += response.weights.stabilize_score || 0;
      scores.organize += response.weights.organize_score || 0;
      scores.build += response.weights.build_score || 0;
      scores.grow += response.weights.grow_score || 0;
      scores.systemic += response.weights.systemic_score || 0;
    }
    this.logger.debug(`Raw phase scores: ${JSON.stringify(scores)}`);
    return scores;
  }

  /**
   * Normalize raw scores to 0-100 scale
   *
   * @param rawScores - Raw aggregated scores
   * @returns Normalized scores (0-100)
   */
  normalizeScores(rawScores: RawPhaseScores): NormalizedPhaseScores {
    const totalPoints =
      rawScores.stabilize +
      rawScores.organize +
      rawScores.build +
      rawScores.grow +
      rawScores.systemic;

    if (totalPoints === 0) {
      // All scores are zero - return even distribution
      return {
        stabilize: 20,
        organize: 20,
        build: 20,
        grow: 20,
        systemic: 20,
      };
    }

    const normalized: NormalizedPhaseScores = {
      stabilize: (rawScores.stabilize / totalPoints) * 100,
      organize: (rawScores.organize / totalPoints) * 100,
      build: (rawScores.build / totalPoints) * 100,
      grow: (rawScores.grow / totalPoints) * 100,
      systemic: (rawScores.systemic / totalPoints) * 100,
    };

    this.logger.debug(`Normalized phase scores: ${JSON.stringify(normalized)}`);
    return normalized;
  }

  /**
   * Rank phases by their scores
   *
   * @param scores - Normalized phase scores
   * @returns Array of phases ranked by score (descending)
   */
  rankPhases(scores: NormalizedPhaseScores): PhaseRanking[] {
    const rankings: PhaseRanking[] = [
      { phase: 'stabilize', score: scores.stabilize },
      { phase: 'organize', score: scores.organize },
      { phase: 'build', score: scores.build },
      { phase: 'grow', score: scores.grow },
      { phase: 'systemic', score: scores.systemic },
    ];

    // Sort by score descending
    rankings.sort((a, b) => b.score - a.score);

    return rankings;
  }

  /**
   * Apply phase sequencing logic and identify primary/secondary phases
   *
   * Phases are sequential: Stabilize → Organize → Build → Grow
   * Systemic (financial literacy) is cross-cutting
   *
   * Critical stabilization issues (low stabilize score) override other phases
   *
   * @param scores - Normalized phase scores
   * @param rankings - Phases ranked by score
   * @returns Primary phase, secondary phases, and transition state
   */
  applySequencingLogic(
    scores: NormalizedPhaseScores,
    rankings: PhaseRanking[],
  ): {
    primaryPhase: FinancialPhase;
    secondaryPhases: string[];
    transitionState: boolean;
  } {
    const highestRanking = rankings[0];

    // Check for perfectly even scores first (before critical stabilization check)
    // This handles the edge case where all scores are evenly distributed
    if (rankings.every((r) => Math.abs(r.score - rankings[0].score) < 1)) {
      this.logger.warn('Perfectly even phase scores detected, defaulting to stabilize');
      return {
        primaryPhase: 'stabilize',
        secondaryPhases: ['organize', 'build', 'grow', 'systemic'],
        transitionState: true,
      };
    }

    // Critical stabilization check
    // If stabilize score is very low, client needs stabilization first
    if (scores.stabilize < this.CRITICAL_STABILIZE_THRESHOLD) {
      this.logger.log(
        `Critical stabilization needed (score: ${scores.stabilize.toFixed(1)})`,
      );
      return {
        primaryPhase: 'stabilize',
        secondaryPhases: [],
        transitionState: false,
      };
    }

    // Check for sequential override
    // If a foundational phase has a significantly lower score than a later phase,
    // the foundational phase should be addressed first
    if (scores.organize < 50 && scores.build > scores.organize + 20) {
      this.logger.log('Sequential override: Organization needed before building');
      return {
        primaryPhase: 'organize',
        secondaryPhases: ['build'],
        transitionState: true,
      };
    }

    if (scores.stabilize < 50 && scores.organize > scores.stabilize + 20) {
      this.logger.log('Sequential override: Stabilization needed before organizing');
      return {
        primaryPhase: 'stabilize',
        secondaryPhases: ['organize'],
        transitionState: true,
      };
    }

    // Identify primary and secondary phases based on scores
    const primaryPhase = highestRanking.phase;
    const secondaryPhases: string[] = [];
    let transitionState = false;

    // Find secondary phases within threshold
    for (let i = 1; i < rankings.length; i++) {
      const ranking = rankings[i];
      const scoreDifference = highestRanking.score - ranking.score;

      if (scoreDifference <= this.SECONDARY_PHASE_THRESHOLD) {
        secondaryPhases.push(ranking.phase);
        transitionState = true;
      }
    }

    return {
      primaryPhase,
      secondaryPhases,
      transitionState,
    };
  }

  /**
   * Retrieve existing phase result for an assessment
   *
   * @param assessmentId - UUID of the assessment
   * @returns Phase result or null if not found
   */
  async getResult(assessmentId: string): Promise<PhaseResult | null> {
    return this.phaseResultRepository.findOne({
      where: { assessment_id: assessmentId },
    });
  }

  /**
   * Check if a phase result exists for an assessment
   *
   * @param assessmentId - UUID of the assessment
   * @returns True if result exists
   */
  async resultExists(assessmentId: string): Promise<boolean> {
    const count = await this.phaseResultRepository.count({
      where: { assessment_id: assessmentId },
    });
    return count > 0;
  }
}
