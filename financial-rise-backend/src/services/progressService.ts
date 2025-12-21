import { AssessmentResponse } from '../models';
import { ProgressCalculationResult } from '../types';
import questionnaireService from './questionnaireService';

/**
 * Calculate assessment progress based on answered questions
 * REQ-ASSESS-006: Display progress as percentage
 */
class ProgressService {
  async calculateProgress(assessmentId: string): Promise<ProgressCalculationResult> {
    // Get total number of required questions
    const questionnaire = await questionnaireService.getQuestionnaire();
    const allQuestions = questionnaire.sections.flatMap((section) => section.questions);
    const requiredQuestions = allQuestions.filter((q) => q.required);
    const totalQuestions = requiredQuestions.length;

    // Get all responses for this assessment
    const responses = await AssessmentResponse.findAll({
      where: { assessmentId },
    });

    // Count answered questions (answer is not null OR notApplicable is true)
    const answeredQuestions = responses.filter(
      (r) => r.answer !== null || r.notApplicable === true
    ).length;

    // Calculate percentage
    const progress = totalQuestions > 0 ? Math.round((answeredQuestions / totalQuestions) * 100 * 100) / 100 : 0;

    return {
      progress,
      totalQuestions,
      answeredQuestions,
    };
  }
}

export default new ProgressService();
