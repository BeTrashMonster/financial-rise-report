import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { DISCProfile, DISCType, ConfidenceLevel } from '../entities/disc-profile.entity';
import {
  DISCQuestionResponse,
  RawDISCScores,
  NormalizedDISCScores,
  DISCProfileResult,
} from './disc.types';
import { LogSanitizer } from '../../../common/utils/log-sanitizer';

/**
 * Service for calculating DISC personality profiles from assessment responses
 *
 * Implements the DISC calculation algorithm as specified in:
 * plans/work-stream-7-implementation-spec.md Section 2
 */
@Injectable()
export class DISCCalculatorService {
  private readonly logger = new Logger(DISCCalculatorService.name);
  private readonly MINIMUM_QUESTIONS = 12;
  private readonly SECONDARY_TRAIT_THRESHOLD = 10; // percentage points

  constructor(
    @InjectRepository(DISCProfile)
    private discProfileRepository: Repository<DISCProfile>,
  ) {}

  /**
   * Calculate DISC profile for an assessment
   *
   * @param assessmentId - UUID of the assessment
   * @param responses - Array of question responses with DISC weights
   * @returns Complete DISC profile result
   */
  async calculate(
    assessmentId: string,
    responses: DISCQuestionResponse[],
  ): Promise<DISCProfileResult> {
    this.logger.log(`Calculating DISC profile for assessment ${assessmentId}`);

    // Step 1: Validate inputs
    this.validateInputs(responses);

    // Step 2: Aggregate raw scores
    const rawScores = this.aggregateScores(responses);

    // Step 3: Normalize scores to 0-100 scale
    const normalizedScores = this.normalizeScores(rawScores);

    // Step 4: Determine primary type
    const primaryType = this.determinePrimaryType(normalizedScores);

    // Step 5: Identify secondary traits
    const secondaryType = this.identifySecondaryTraits(normalizedScores, primaryType);

    // Step 6: Calculate confidence level
    // If insufficient data (<12 questions), force low confidence
    let confidenceLevel = this.calculateConfidenceLevel(normalizedScores);
    if (responses.length < this.MINIMUM_QUESTIONS) {
      confidenceLevel = 'low';
      this.logger.debug(
        `Forcing low confidence due to insufficient data (${responses.length} < ${this.MINIMUM_QUESTIONS})`,
      );
    }

    // Step 7: Create and save profile
    const profile = this.discProfileRepository.create({
      assessment_id: assessmentId,
      d_score: normalizedScores.D,
      i_score: normalizedScores.I,
      s_score: normalizedScores.S,
      c_score: normalizedScores.C,
      primary_type: primaryType,
      secondary_type: secondaryType,
      confidence_level: confidenceLevel,
    });

    const savedProfile = await this.discProfileRepository.save(profile);

    this.logger.log(
      `DISC profile calculated: Primary=${primaryType}, Secondary=${secondaryType}, Confidence=${confidenceLevel}`,
    );

    return {
      assessment_id: savedProfile.assessment_id,
      d_score: savedProfile.d_score,
      i_score: savedProfile.i_score,
      s_score: savedProfile.s_score,
      c_score: savedProfile.c_score,
      primary_type: savedProfile.primary_type,
      secondary_type: savedProfile.secondary_type,
      confidence_level: savedProfile.confidence_level,
      calculated_at: savedProfile.calculated_at,
    };
  }

  /**
   * Validate that we have sufficient DISC question responses
   *
   * @param responses - Question responses to validate
   * @throws Error if insufficient responses
   */
  validateInputs(responses: DISCQuestionResponse[]): void {
    if (responses.length < this.MINIMUM_QUESTIONS) {
      this.logger.warn(
        `Insufficient DISC questions: ${responses.length} (minimum: ${this.MINIMUM_QUESTIONS})`,
      );
      // We allow calculation to proceed but will flag as low confidence
    }

    if (responses.length === 0) {
      throw new Error('No DISC question responses provided');
    }
  }

  /**
   * Aggregate raw DISC scores from all responses
   *
   * @param responses - Question responses with DISC weights
   * @returns Raw aggregated scores
   */
  aggregateScores(responses: DISCQuestionResponse[]): RawDISCScores {
    const scores: RawDISCScores = { D: 0, I: 0, S: 0, C: 0 };

    for (const response of responses) {
      scores.D += response.weights.disc_d_score || 0;
      scores.I += response.weights.disc_i_score || 0;
      scores.S += response.weights.disc_s_score || 0;
      scores.C += response.weights.disc_c_score || 0;
    }

    // SECURITY: Sanitize PII in logs (HIGH-008 remediation)
    this.logger.debug(`DISC calculation completed`, {
      scoreHash: LogSanitizer.sanitizeDISCScores(scores),
      responseCount: responses.length,
    });
    return scores;
  }

  /**
   * Normalize raw scores to 0-100 scale
   *
   * @param rawScores - Raw aggregated scores
   * @returns Normalized scores (0-100)
   */
  normalizeScores(rawScores: RawDISCScores): NormalizedDISCScores {
    const totalPoints = rawScores.D + rawScores.I + rawScores.S + rawScores.C;

    if (totalPoints === 0) {
      // All scores are zero - return even distribution
      return { D: 25, I: 25, S: 25, C: 25 };
    }

    const normalized: NormalizedDISCScores = {
      D: (rawScores.D / totalPoints) * 100,
      I: (rawScores.I / totalPoints) * 100,
      S: (rawScores.S / totalPoints) * 100,
      C: (rawScores.C / totalPoints) * 100,
    };

    this.logger.debug(`Normalized DISC scores: ${JSON.stringify(normalized)}`);
    return normalized;
  }

  /**
   * Determine the primary DISC type (highest score)
   *
   * @param scores - Normalized DISC scores
   * @returns Primary DISC type
   */
  determinePrimaryType(scores: NormalizedDISCScores): DISCType {
    const entries: [DISCType, number][] = [
      ['D', scores.D],
      ['I', scores.I],
      ['S', scores.S],
      ['C', scores.C],
    ];

    // Sort by score descending
    entries.sort((a, b) => b[1] - a[1]);

    // Handle tie - if multiple types have the same highest score
    const highestScore = entries[0][1];
    const tiedTypes = entries.filter(([_, score]) => score === highestScore);

    if (tiedTypes.length > 1) {
      // Perfectly even distribution - default to 'C' (analytical approach)
      this.logger.warn('Perfectly even DISC scores detected, defaulting to C type');
      return 'C';
    }

    return entries[0][0];
  }

  /**
   * Identify secondary DISC traits when scores are close
   *
   * @param scores - Normalized DISC scores
   * @param primaryType - The primary DISC type
   * @returns Secondary DISC type or null
   */
  identifySecondaryTraits(
    scores: NormalizedDISCScores,
    primaryType: DISCType,
  ): DISCType | null {
    const primaryScore = scores[primaryType];

    // Find the second highest score
    const otherTypes = (['D', 'I', 'S', 'C'] as DISCType[]).filter(
      (type) => type !== primaryType,
    );

    let secondaryType: DISCType | null = null;
    let secondHighestScore = 0;

    for (const type of otherTypes) {
      if (scores[type] > secondHighestScore) {
        secondHighestScore = scores[type];
        secondaryType = type;
      }
    }

    // Check if secondary score is within threshold
    if (secondaryType && primaryScore - secondHighestScore <= this.SECONDARY_TRAIT_THRESHOLD) {
      this.logger.debug(
        `Secondary trait identified: ${secondaryType} (score difference: ${(primaryScore - secondHighestScore).toFixed(1)})`,
      );
      return secondaryType;
    }

    return null;
  }

  /**
   * Calculate confidence level based on score distribution
   *
   * High: Primary score >40% AND difference from second >15 points
   * Moderate: Primary score >30% AND difference from second >10 points
   * Low: Otherwise
   *
   * @param scores - Normalized DISC scores
   * @returns Confidence level
   */
  calculateConfidenceLevel(scores: NormalizedDISCScores): ConfidenceLevel {
    const sortedScores = [scores.D, scores.I, scores.S, scores.C].sort((a, b) => b - a);
    const primaryScore = sortedScores[0];
    const secondScore = sortedScores[1];
    const scoreDifference = primaryScore - secondScore;

    if (primaryScore > 40 && scoreDifference > 15) {
      return 'high';
    }

    if (primaryScore > 30 && scoreDifference > 10) {
      return 'moderate';
    }

    return 'low';
  }

  /**
   * Retrieve existing DISC profile for an assessment
   *
   * @param assessmentId - UUID of the assessment
   * @returns DISC profile or null if not found
   */
  async getProfile(assessmentId: string): Promise<DISCProfile | null> {
    return this.discProfileRepository.findOne({
      where: { assessment_id: assessmentId },
    });
  }

  /**
   * Check if a DISC profile exists for an assessment
   *
   * @param assessmentId - UUID of the assessment
   * @returns True if profile exists
   */
  async profileExists(assessmentId: string): Promise<boolean> {
    const count = await this.discProfileRepository.count({
      where: { assessment_id: assessmentId },
    });
    return count > 0;
  }
}
