import { QuestionnaireSection, QuestionType, FinancialPhase } from '../types';

/**
 * Questionnaire service
 * NOTE: This is mock data for Work Stream 6 testing
 * Real questionnaire data will come from Work Stream 5 (Content Development)
 * and should be stored in database tables (questionnaire_versions, sections, questions, etc.)
 */
class QuestionnaireService {
  /**
   * Get the current questionnaire structure
   * REQ-QUEST-001 through REQ-QUEST-010
   */
  async getQuestionnaire(): Promise<{ version: string; sections: QuestionnaireSection[] }> {
    // Mock questionnaire data for testing
    // In production, this would fetch from database
    return {
      version: '1.0',
      sections: [
        {
          sectionId: '550e8400-e29b-41d4-a716-446655440001',
          title: 'Financial Stability Assessment',
          description: 'Evaluate current accounting health and compliance',
          phase: FinancialPhase.STABILIZE,
          order: 1,
          questions: [
            {
              questionId: '550e8400-e29b-41d4-a716-446655440101',
              text: 'How confident do you feel about your business finances right now?',
              type: QuestionType.RATING,
              required: true,
              order: 1,
            },
            {
              questionId: '550e8400-e29b-41d4-a716-446655440102',
              text: 'Do you have a current bookkeeping system in place?',
              type: QuestionType.SINGLE_CHOICE,
              required: true,
              order: 2,
              options: [
                {
                  optionId: '550e8400-e29b-41d4-a716-446655440201',
                  text: 'Yes, and it is up to date',
                  value: 'yes_current',
                  phaseMapping: { stabilize: 1.0, organize: 0.5 },
                },
                {
                  optionId: '550e8400-e29b-41d4-a716-446655440202',
                  text: 'Yes, but it is behind',
                  value: 'yes_behind',
                  phaseMapping: { stabilize: 0.5, organize: 0.3 },
                },
                {
                  optionId: '550e8400-e29b-41d4-a716-446655440203',
                  text: 'No',
                  value: 'no',
                  phaseMapping: { stabilize: 0.0 },
                },
              ],
            },
            {
              questionId: '550e8400-e29b-41d4-a716-446655440103',
              text: 'What is your business entity type?',
              type: QuestionType.SINGLE_CHOICE,
              required: true,
              order: 3,
              options: [
                {
                  optionId: '550e8400-e29b-41d4-a716-446655440211',
                  text: 'Sole Proprietor',
                  value: 'sole_proprietor',
                },
                {
                  optionId: '550e8400-e29b-41d4-a716-446655440212',
                  text: 'LLC',
                  value: 'llc',
                },
                {
                  optionId: '550e8400-e29b-41d4-a716-446655440213',
                  text: 'S-Corp',
                  value: 's_corp',
                },
                {
                  optionId: '550e8400-e29b-41d4-a716-446655440214',
                  text: 'C-Corp',
                  value: 'c_corp',
                },
              ],
            },
          ],
        },
        {
          sectionId: '550e8400-e29b-41d4-a716-446655440002',
          title: 'Financial Organization',
          description: 'Assess foundational systems and processes',
          phase: FinancialPhase.ORGANIZE,
          order: 2,
          questions: [
            {
              questionId: '550e8400-e29b-41d4-a716-446655440104',
              text: 'Do you have a Chart of Accounts (COA) set up?',
              type: QuestionType.SINGLE_CHOICE,
              required: true,
              order: 1,
              options: [
                {
                  optionId: '550e8400-e29b-41d4-a716-446655440221',
                  text: 'Yes, customized for my business',
                  value: 'yes_customized',
                },
                {
                  optionId: '550e8400-e29b-41d4-a716-446655440222',
                  text: 'Yes, using default template',
                  value: 'yes_default',
                },
                {
                  optionId: '550e8400-e29b-41d4-a716-446655440223',
                  text: 'No',
                  value: 'no',
                },
              ],
            },
          ],
        },
      ],
    };
  }

  /**
   * Get a specific question by ID
   */
  async getQuestion(questionId: string) {
    const questionnaire = await this.getQuestionnaire();
    return questionnaire.sections
      .flatMap((s) => s.questions)
      .find((q) => q.questionId === questionId);
  }
}

export default new QuestionnaireService();
