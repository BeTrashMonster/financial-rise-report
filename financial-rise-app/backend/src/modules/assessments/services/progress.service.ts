import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AssessmentResponse } from '../entities/assessment-response.entity';
import { Question } from '../../questions/entities/question.entity';

export interface ProgressCalculationResult {
  progress: number;
  totalQuestions: number;
  answeredQuestions: number;
}

/**
 * Progress Service - Calculate assessment progress
 * REQ-ASSESS-006: Display progress as percentage
 *
 * Ported from Express backend: src/services/progressService.ts
 * Key changes:
 * - Converted to NestJS injectable service
 * - Uses TypeORM instead of Sequelize
 * - Removed dependency on questionnaireService (uses Question repository directly)
 */
@Injectable()
export class ProgressService {
  constructor(
    @InjectRepository(AssessmentResponse)
    private responseRepository: Repository<AssessmentResponse>,
    @InjectRepository(Question)
    private questionRepository: Repository<Question>,
  ) {}

  /**
   * Calculate assessment progress based on answered questions
   * Formula: (answered questions / total required questions) * 100
   *
   * @param assessmentId - UUID of the assessment
   * @returns Progress calculation result with percentage and counts
   */
  async calculateProgress(assessmentId: string): Promise<ProgressCalculationResult> {
    // Get total number of required questions
    const requiredQuestions = await this.questionRepository.find({
      where: { required: true },
    });
    const totalQuestions = requiredQuestions.length;

    // Edge case: No required questions in system
    if (totalQuestions === 0) {
      return {
        progress: 0,
        totalQuestions: 0,
        answeredQuestions: 0,
      };
    }

    // Get all responses for this assessment
    const responses = await this.responseRepository.find({
      where: { assessment_id: assessmentId },
    });

    // Count answered questions
    // A question is "answered" if:
    // - answer is not null/undefined OR
    // - notApplicable is true (explicitly marked as N/A)
    const answeredQuestions = responses.filter(
      (r) => r.answer !== null || r.not_applicable === true,
    ).length;

    // Calculate percentage (rounded to 2 decimal places)
    const progress =
      totalQuestions > 0
        ? Math.round((answeredQuestions / totalQuestions) * 100 * 100) / 100
        : 0;

    return {
      progress,
      totalQuestions,
      answeredQuestions,
    };
  }

  /**
   * Calculate progress for only required questions
   * This ensures optional questions don't affect completion percentage
   *
   * @param assessmentId - UUID of the assessment
   * @returns Progress calculation result for required questions only
   */
  async calculateRequiredProgress(assessmentId: string): Promise<ProgressCalculationResult> {
    // Get all required question IDs
    const requiredQuestions = await this.questionRepository.find({
      where: { required: true },
      select: ['question_key'],
    });

    const requiredQuestionKeys = requiredQuestions.map((q) => q.question_key);
    const totalQuestions = requiredQuestionKeys.length;

    // Edge case: No required questions
    if (totalQuestions === 0) {
      return {
        progress: 0,
        totalQuestions: 0,
        answeredQuestions: 0,
      };
    }

    // Get responses for required questions only
    const responses = await this.responseRepository
      .createQueryBuilder('response')
      .where('response.assessment_id = :assessmentId', { assessmentId })
      .andWhere('response.question_id IN (:...requiredQuestionKeys)', {
        requiredQuestionKeys,
      })
      .getMany();

    // Count answered required questions
    const answeredQuestions = responses.filter(
      (r) => r.answer !== null || r.not_applicable === true,
    ).length;

    // Calculate percentage
    const progress =
      Math.round((answeredQuestions / totalQuestions) * 100 * 100) / 100;

    return {
      progress,
      totalQuestions,
      answeredQuestions,
    };
  }

  /**
   * Check if assessment is complete (all required questions answered)
   *
   * @param assessmentId - UUID of the assessment
   * @returns True if all required questions are answered
   */
  async isAssessmentComplete(assessmentId: string): Promise<boolean> {
    const result = await this.calculateRequiredProgress(assessmentId);
    return result.progress === 100;
  }

  /**
   * Get missing required questions for an assessment
   * Useful for completion validation
   *
   * @param assessmentId - UUID of the assessment
   * @returns Array of question keys that are required but not answered
   */
  async getMissingRequiredQuestions(assessmentId: string): Promise<string[]> {
    // Get all required questions
    const requiredQuestions = await this.questionRepository.find({
      where: { required: true },
      select: ['question_key'],
    });

    const requiredQuestionKeys = requiredQuestions.map((q) => q.question_key);

    // Get all answered questions
    const responses = await this.responseRepository.find({
      where: { assessment_id: assessmentId },
      select: ['question_id', 'answer', 'not_applicable'],
    });

    const answeredQuestionKeys = responses
      .filter((r) => r.answer !== null || r.not_applicable === true)
      .map((r) => r.question_id);

    // Find missing required questions
    return requiredQuestionKeys.filter(
      (key) => !answeredQuestionKeys.includes(key),
    );
  }
}
