import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Question, QuestionType } from '../../questions/entities/question.entity';
import { AssessmentResponse } from '../entities/assessment-response.entity';

export interface ValidationError {
  field: string;
  message: string;
}

export interface ValidationResult {
  valid: boolean;
  errors?: ValidationError[];
}

export interface CompletionValidationResult extends ValidationResult {
  missingQuestions?: string[];
}

/**
 * Validation Service - Validate assessment responses
 * REQ-ASSESS-009: Validate required questions before completion
 * REQ-QUEST-004: Support multiple question types with validation
 *
 * Ported from Express backend: src/services/validationService.ts
 * Key changes:
 * - Converted to NestJS injectable service
 * - Uses TypeORM instead of Sequelize
 * - Fetches questions from database instead of questionnaireService
 * - Added BadRequestException for invalid data
 */
@Injectable()
export class ValidationService {
  constructor(
    @InjectRepository(Question)
    private questionRepository: Repository<Question>,
    @InjectRepository(AssessmentResponse)
    private responseRepository: Repository<AssessmentResponse>,
  ) {}

  /**
   * Validate a single response based on question type
   *
   * @param questionId - Question key/ID (e.g., "FIN-001")
   * @param answer - The answer value (varies by question type)
   * @param notApplicable - Whether the question was marked N/A
   * @returns Validation result with errors if invalid
   */
  async validateResponse(
    questionId: string,
    answer: any,
    notApplicable: boolean,
  ): Promise<ValidationResult> {
    // Find the question
    const question = await this.questionRepository.findOne({
      where: { question_key: questionId },
    });

    if (!question) {
      return {
        valid: false,
        errors: [{ field: 'questionId', message: 'Question not found' }],
      };
    }

    // If marked as not applicable, no further validation needed
    if (notApplicable) {
      return { valid: true };
    }

    // If answer is null/undefined and question is required
    if ((answer === null || answer === undefined) && question.required) {
      return {
        valid: false,
        errors: [
          { field: 'answer', message: 'Answer is required for this question' },
        ],
      };
    }

    // Allow null/undefined for optional questions
    if ((answer === null || answer === undefined) && !question.required) {
      return { valid: true };
    }

    // Type-specific validation
    switch (question.question_type) {
      case QuestionType.SINGLE_CHOICE:
        return this.validateSingleChoice(question, answer);

      case QuestionType.MULTIPLE_CHOICE:
        return this.validateMultipleChoice(question, answer);

      case QuestionType.RATING:
        return this.validateRating(answer);

      case QuestionType.TEXT:
        return this.validateText(answer);

      default:
        return { valid: true };
    }
  }

  /**
   * Validate single choice answer
   * Answer must be one of the valid option IDs
   */
  private validateSingleChoice(
    question: Question,
    answer: any,
  ): ValidationResult {
    if (!question.options || !Array.isArray(question.options)) {
      return {
        valid: false,
        errors: [{ field: 'answer', message: 'Question has no options' }],
      };
    }

    // Extract valid option IDs from the options array
    const validOptionIds = question.options.map((opt: any) => opt.optionId || opt.value);

    // Answer comes as {value: "x"} from frontend, extract the value
    const answerValue = typeof answer === 'object' && answer.value ? answer.value : answer;

    if (!validOptionIds.includes(answerValue)) {
      return {
        valid: false,
        errors: [{ field: 'answer', message: 'Invalid option selected' }],
      };
    }

    return { valid: true };
  }

  /**
   * Validate multiple choice answer
   * Answer must be an array of valid option IDs
   */
  private validateMultipleChoice(
    question: Question,
    answer: any,
  ): ValidationResult {
    // Answer may come as {value: ["x", "y"]} from frontend, extract the value
    const answerArray = typeof answer === 'object' && answer.value && Array.isArray(answer.value)
      ? answer.value
      : answer;

    if (!Array.isArray(answerArray)) {
      return {
        valid: false,
        errors: [{ field: 'answer', message: 'Answer must be an array' }],
      };
    }

    if (answerArray.length === 0 && question.required) {
      return {
        valid: false,
        errors: [
          {
            field: 'answer',
            message: 'At least one option must be selected',
          },
        ],
      };
    }

    if (!question.options || !Array.isArray(question.options)) {
      return {
        valid: false,
        errors: [{ field: 'answer', message: 'Question has no options' }],
      };
    }

    const validOptionIds = question.options.map((opt: any) => opt.optionId || opt.value);
    const invalidOptions = answerArray.filter(
      (optId: string) => !validOptionIds.includes(optId),
    );

    if (invalidOptions.length > 0) {
      return {
        valid: false,
        errors: [{ field: 'answer', message: 'Invalid options selected' }],
      };
    }

    return { valid: true };
  }

  /**
   * Validate rating answer (1-5 scale)
   * Must be an integer between 1 and 5
   */
  private validateRating(answer: any): ValidationResult {
    // Answer may come as {value: 3} from frontend, extract the value
    const ratingValue = typeof answer === 'object' && answer.value !== undefined
      ? answer.value
      : answer;

    if (typeof ratingValue !== 'number') {
      return {
        valid: false,
        errors: [{ field: 'answer', message: 'Rating must be a number' }],
      };
    }

    if (!Number.isInteger(ratingValue) || ratingValue < 1 || ratingValue > 5) {
      return {
        valid: false,
        errors: [
          {
            field: 'answer',
            message: 'Rating must be an integer between 1 and 5',
          },
        ],
      };
    }

    return { valid: true };
  }

  /**
   * Validate text answer
   * Must be a string with max length of 1000 characters
   */
  private validateText(answer: any): ValidationResult {
    if (typeof answer !== 'string') {
      return {
        valid: false,
        errors: [{ field: 'answer', message: 'Answer must be a string' }],
      };
    }

    if (answer.length > 1000) {
      return {
        valid: false,
        errors: [
          {
            field: 'answer',
            message: 'Text answer must not exceed 1000 characters',
          },
        ],
      };
    }

    return { valid: true };
  }

  /**
   * Validate assessment completion
   * Checks if all required questions have been answered
   *
   * @param assessmentId - UUID of the assessment
   * @returns Validation result with missing questions if incomplete
   */
  async validateCompletion(
    assessmentId: string,
  ): Promise<CompletionValidationResult> {
    // Get all required questions
    const requiredQuestions = await this.questionRepository.find({
      where: { required: true },
      select: ['question_key'],
    });

    // Get all responses for this assessment
    const responses = await this.responseRepository.find({
      where: { assessment_id: assessmentId },
      select: ['question_id', 'answer', 'not_applicable'],
    });

    // Get question IDs that have been answered
    const answeredQuestionIds = responses
      .filter((r) => r.answer !== null || r.not_applicable === true)
      .map((r) => r.question_id);

    // Find missing required questions
    const missingQuestions = requiredQuestions
      .filter((q) => !answeredQuestionIds.includes(q.question_key))
      .map((q) => q.question_key);

    if (missingQuestions.length > 0) {
      return {
        valid: false,
        missingQuestions,
        errors: [
          {
            field: 'responses',
            message: `${missingQuestions.length} required question(s) not answered`,
          },
        ],
      };
    }

    return { valid: true };
  }

  /**
   * Validate and throw exception if invalid
   * Convenience method for use in controllers/services
   *
   * @param questionId - Question key/ID
   * @param answer - Answer value
   * @param notApplicable - N/A flag
   * @throws BadRequestException if validation fails
   */
  async validateResponseOrThrow(
    questionId: string,
    answer: any,
    notApplicable: boolean,
  ): Promise<void> {
    const result = await this.validateResponse(questionId, answer, notApplicable);

    if (!result.valid) {
      const errorMessages = result.errors?.map((e) => e.message).join(', ');
      throw new BadRequestException(errorMessages || 'Validation failed');
    }
  }

  /**
   * Validate completion and throw exception if incomplete
   * Convenience method for use in controllers/services
   *
   * @param assessmentId - UUID of the assessment
   * @throws BadRequestException if assessment is incomplete
   */
  async validateCompletionOrThrow(assessmentId: string): Promise<void> {
    const result = await this.validateCompletion(assessmentId);

    if (!result.valid) {
      throw new BadRequestException(
        `Assessment incomplete: ${result.missingQuestions?.length} required questions not answered. Missing: ${result.missingQuestions?.join(', ')}`,
      );
    }
  }

  /**
   * Batch validate multiple responses
   * Useful for validating entire questionnaire submissions
   *
   * @param responses - Array of {questionId, answer, notApplicable}
   * @returns Array of validation results matching input order
   */
  async validateMultipleResponses(
    responses: Array<{
      questionId: string;
      answer: any;
      notApplicable: boolean;
    }>,
  ): Promise<ValidationResult[]> {
    return Promise.all(
      responses.map((r) =>
        this.validateResponse(r.questionId, r.answer, r.notApplicable),
      ),
    );
  }
}
