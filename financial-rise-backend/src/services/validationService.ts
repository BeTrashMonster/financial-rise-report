import { ValidationResult, CompletionValidationResult, QuestionType } from '../types';
import { AssessmentResponse } from '../models';
import questionnaireService from './questionnaireService';

/**
 * Validation service for assessment responses
 * REQ-ASSESS-009: Validate required questions before completion
 * REQ-QUEST-004: Support multiple question types with validation
 */
class ValidationService {
  /**
   * Validate a single response based on question type
   */
  async validateResponse(questionId: string, answer: any, notApplicable: boolean): Promise<ValidationResult> {
    const questionnaire = await questionnaireService.getQuestionnaire();
    const question = questionnaire.sections
      .flatMap((s) => s.questions)
      .find((q) => q.questionId === questionId);

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
        errors: [{ field: 'answer', message: 'Answer is required for this question' }],
      };
    }

    // Type-specific validation
    switch (question.type) {
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
   */
  private validateSingleChoice(question: any, answer: any): ValidationResult {
    if (!question.options) {
      return { valid: false, errors: [{ field: 'answer', message: 'Question has no options' }] };
    }

    const validOptionIds = question.options.map((opt: any) => opt.optionId);
    if (!validOptionIds.includes(answer)) {
      return {
        valid: false,
        errors: [{ field: 'answer', message: 'Invalid option selected' }],
      };
    }

    return { valid: true };
  }

  /**
   * Validate multiple choice answer
   */
  private validateMultipleChoice(question: any, answer: any): ValidationResult {
    if (!Array.isArray(answer)) {
      return {
        valid: false,
        errors: [{ field: 'answer', message: 'Answer must be an array' }],
      };
    }

    if (answer.length === 0 && question.required) {
      return {
        valid: false,
        errors: [{ field: 'answer', message: 'At least one option must be selected' }],
      };
    }

    const validOptionIds = question.options?.map((opt: any) => opt.optionId) || [];
    const invalidOptions = answer.filter((optId: string) => !validOptionIds.includes(optId));

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
   */
  private validateRating(answer: any): ValidationResult {
    if (typeof answer !== 'number') {
      return {
        valid: false,
        errors: [{ field: 'answer', message: 'Rating must be a number' }],
      };
    }

    if (!Number.isInteger(answer) || answer < 1 || answer > 5) {
      return {
        valid: false,
        errors: [{ field: 'answer', message: 'Rating must be an integer between 1 and 5' }],
      };
    }

    return { valid: true };
  }

  /**
   * Validate text answer
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
        errors: [{ field: 'answer', message: 'Text answer must not exceed 1000 characters' }],
      };
    }

    return { valid: true };
  }

  /**
   * Validate assessment completion
   * Checks if all required questions have been answered
   */
  async validateCompletion(assessmentId: string): Promise<CompletionValidationResult> {
    const questionnaire = await questionnaireService.getQuestionnaire();
    const requiredQuestions = questionnaire.sections
      .flatMap((s) => s.questions)
      .filter((q) => q.required);

    const responses = await AssessmentResponse.findAll({
      where: { assessmentId },
    });

    const answeredQuestionIds = responses
      .filter((r) => r.answer !== null || r.notApplicable === true)
      .map((r) => r.questionId);

    const missingQuestions = requiredQuestions
      .filter((q) => !answeredQuestionIds.includes(q.questionId))
      .map((q) => q.questionId);

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
}

export default new ValidationService();
