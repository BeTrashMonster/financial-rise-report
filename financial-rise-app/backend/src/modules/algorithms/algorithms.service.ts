import { Injectable, Logger, ConflictException, NotFoundException } from '@nestjs/common';
import { DISCCalculatorService } from './disc/disc-calculator.service';
import { PhaseCalculatorService } from './phase/phase-calculator.service';
import { DISCQuestionResponse, DISCProfileResult } from './disc/disc.types';
import { PhaseQuestionResponse, PhaseResultData } from './phase/phase.types';
import * as fs from 'fs/promises';
import * as path from 'path';

/**
 * Response structure from question bank JSON files
 */
interface QuestionOption {
  value: string;
  label: string;
  disc_d_score?: number;
  disc_i_score?: number;
  disc_s_score?: number;
  disc_c_score?: number;
  stabilize_score?: number;
  organize_score?: number;
  build_score?: number;
  grow_score?: number;
  systemic_score?: number;
}

interface Question {
  id: string;
  question_text: string;
  options: QuestionOption[];
}

interface QuestionBank {
  questions: Question[];
}

/**
 * Assessment response from database
 */
interface AssessmentResponse {
  question_id: string;
  response_value: string;
}

/**
 * Combined calculation result
 */
export interface CalculationResult {
  disc_profile: DISCProfileResult;
  phase_results: PhaseResultData;
  calculated_at: Date;
}

/**
 * Orchestrator service that coordinates DISC and Phase calculations
 *
 * This service:
 * 1. Fetches assessment responses
 * 2. Loads question weights from JSON files
 * 3. Coordinates DISC and Phase calculation services
 * 4. Returns combined results
 */
@Injectable()
export class AlgorithmsService {
  private readonly logger = new Logger(AlgorithmsService.name);
  private questionsCache: Map<string, Question> = new Map();
  private cacheLoaded = false;

  constructor(
    private readonly discCalculator: DISCCalculatorService,
    private readonly phaseCalculator: PhaseCalculatorService,
  ) {}

  /**
   * Calculate both DISC profile and phase results for an assessment
   *
   * @param assessmentId - UUID of the assessment
   * @param responses - Assessment responses from database
   * @returns Combined DISC and phase calculation results
   * @throws ConflictException if results already exist
   */
  async calculateAll(
    assessmentId: string,
    responses: AssessmentResponse[],
  ): Promise<CalculationResult> {
    this.logger.log(`Starting calculation for assessment ${assessmentId}`);

    // Check if results already exist
    const [discExists, phaseExists] = await Promise.all([
      this.discCalculator.profileExists(assessmentId),
      this.phaseCalculator.resultExists(assessmentId),
    ]);

    if (discExists || phaseExists) {
      throw new ConflictException(
        'Results already calculated for this assessment. Use recalculate endpoint to update.',
      );
    }

    // Load question weights from JSON files
    await this.loadQuestionWeights();

    // Separate DISC and Phase responses
    const discResponses = this.extractDISCResponses(responses);
    const phaseResponses = this.extractPhaseResponses(responses);

    // Calculate in parallel
    const [discProfile, phaseResults] = await Promise.all([
      this.discCalculator.calculate(assessmentId, discResponses),
      this.phaseCalculator.calculate(assessmentId, phaseResponses),
    ]);

    return {
      disc_profile: discProfile,
      phase_results: phaseResults,
      calculated_at: new Date(),
    };
  }

  /**
   * Get DISC profile for an assessment
   *
   * @param assessmentId - UUID of the assessment
   * @returns DISC profile result
   * @throws NotFoundException if profile not found
   */
  async getDISCProfile(assessmentId: string): Promise<DISCProfileResult> {
    const profile = await this.discCalculator.getProfile(assessmentId);

    if (!profile) {
      throw new NotFoundException(
        `DISC profile not found for assessment ${assessmentId}. Run calculation first.`,
      );
    }

    return {
      assessment_id: profile.assessment_id,
      d_score: profile.d_score,
      i_score: profile.i_score,
      s_score: profile.s_score,
      c_score: profile.c_score,
      primary_type: profile.primary_type,
      secondary_type: profile.secondary_type,
      confidence_level: profile.confidence_level,
      calculated_at: profile.calculated_at,
    };
  }

  /**
   * Get phase results for an assessment
   *
   * @param assessmentId - UUID of the assessment
   * @returns Phase result data
   * @throws NotFoundException if result not found
   */
  async getPhaseResults(assessmentId: string): Promise<PhaseResultData> {
    const result = await this.phaseCalculator.getResult(assessmentId);

    if (!result) {
      throw new NotFoundException(
        `Phase results not found for assessment ${assessmentId}. Run calculation first.`,
      );
    }

    return {
      assessment_id: result.assessment_id,
      stabilize_score: result.stabilize_score,
      organize_score: result.organize_score,
      build_score: result.build_score,
      grow_score: result.grow_score,
      systemic_score: result.systemic_score,
      primary_phase: result.primary_phase,
      secondary_phases: result.secondary_phases,
      transition_state: result.transition_state,
      calculated_at: result.calculated_at,
    };
  }

  /**
   * Reset cache (for testing only)
   * @internal
   */
  resetCache(): void {
    this.cacheLoaded = false;
    this.questionsCache.clear();
  }

  /**
   * Load question weights from unified JSON file into cache
   */
  private async loadQuestionWeights(): Promise<void> {
    if (this.cacheLoaded) {
      return;
    }

    try {
      // Path resolution for both test and production environments
      // In tests (Jest rootDir='src'): __dirname is src/modules/algorithms, go up 3 to backend/ then into content/
      // In production: __dirname is dist/modules/algorithms, go up 3 to backend/ then into content/
      const contentPath = path.join(__dirname, '../../..', 'content');

      // Load unified assessment questions (includes both phase and embedded DISC)
      const questionsPath = path.join(contentPath, 'assessment-questions.json');
      const questionsData = await fs.readFile(questionsPath, 'utf-8');
      const questionsBank: QuestionBank = JSON.parse(questionsData);

      let discQuestionCount = 0;
      for (const question of questionsBank.questions) {
        this.questionsCache.set(question.id, question);

        // Count questions with DISC scores (embedded DISC questions)
        // Only check questions that have options (rating questions don't have options)
        if (question.options && Array.isArray(question.options)) {
          const hasDiscScores = question.options.some(
            (opt) =>
              opt.disc_d_score !== undefined ||
              opt.disc_i_score !== undefined ||
              opt.disc_s_score !== undefined ||
              opt.disc_c_score !== undefined,
          );
          if (hasDiscScores) {
            discQuestionCount++;
          }
        }
      }

      this.cacheLoaded = true;
      this.logger.log(
        `Loaded ${this.questionsCache.size} total questions (${discQuestionCount} with DISC scoring)`,
      );
    } catch (error) {
      this.logger.error('Failed to load question weights', error);
      throw new Error('Failed to load question bank data');
    }
  }

  /**
   * Extract DISC responses with weights from assessment responses
   *
   * Checks all questions for DISC scoring (handles embedded DISC questions)
   *
   * @param responses - All assessment responses
   * @returns DISC responses with weights
   */
  private extractDISCResponses(
    responses: AssessmentResponse[],
  ): DISCQuestionResponse[] {
    const discResponses: DISCQuestionResponse[] = [];

    for (const response of responses) {
      const question = this.questionsCache.get(response.question_id);

      if (!question) {
        // Question not found in cache, skip
        continue;
      }

      // Skip questions without options (e.g., rating questions)
      if (!question.options || !Array.isArray(question.options)) {
        continue;
      }

      const selectedOption = question.options.find(
        (opt) => opt.value === response.response_value,
      );

      if (!selectedOption) {
        this.logger.warn(
          `Invalid response value for question ${response.question_id}`,
        );
        continue;
      }

      // Check if this option has DISC scores (embedded DISC question)
      const hasDiscScores =
        selectedOption.disc_d_score !== undefined ||
        selectedOption.disc_i_score !== undefined ||
        selectedOption.disc_s_score !== undefined ||
        selectedOption.disc_c_score !== undefined;

      if (!hasDiscScores) {
        // Not a DISC question, skip
        continue;
      }

      discResponses.push({
        question_id: response.question_id,
        selected_value: response.response_value,
        weights: {
          disc_d_score: selectedOption.disc_d_score || 0,
          disc_i_score: selectedOption.disc_i_score || 0,
          disc_s_score: selectedOption.disc_s_score || 0,
          disc_c_score: selectedOption.disc_c_score || 0,
        },
      });
    }

    return discResponses;
  }

  /**
   * Extract phase responses with weights from assessment responses
   *
   * @param responses - All assessment responses
   * @returns Phase responses with weights
   */
  private extractPhaseResponses(
    responses: AssessmentResponse[],
  ): PhaseQuestionResponse[] {
    const phaseResponses: PhaseQuestionResponse[] = [];

    for (const response of responses) {
      const question = this.questionsCache.get(response.question_id);

      if (!question) {
        // Not a phase question, skip
        continue;
      }

      // Skip questions without options (e.g., rating questions)
      if (!question.options || !Array.isArray(question.options)) {
        continue;
      }

      const selectedOption = question.options.find(
        (opt) => opt.value === response.response_value,
      );

      if (!selectedOption) {
        this.logger.warn(
          `Invalid response value for phase question ${response.question_id}`,
        );
        continue;
      }

      phaseResponses.push({
        question_id: response.question_id,
        selected_value: response.response_value,
        weights: {
          stabilize_score: selectedOption.stabilize_score || 0,
          organize_score: selectedOption.organize_score || 0,
          build_score: selectedOption.build_score || 0,
          grow_score: selectedOption.grow_score || 0,
          systemic_score: selectedOption.systemic_score || 0,
        },
      });
    }

    return phaseResponses;
  }
}
