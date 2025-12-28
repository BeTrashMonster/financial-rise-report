import validationService from '../validationService';
import { QuestionType } from '../../types';
import questionnaireService from '../questionnaireService';
import { AssessmentResponse } from '../../models';

jest.mock('../questionnaireService');
jest.mock('../../models');

describe('ValidationService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('validateResponse', () => {
    it('should return error for non-existent question', async () => {
      (questionnaireService.getQuestionnaire as jest.Mock).mockResolvedValue({
        sections: [{ questions: [] }],
      });

      const result = await validationService.validateResponse('invalid-id', 'answer', false);

      expect(result.valid).toBe(false);
      expect(result.errors).toHaveLength(1);
      expect(result.errors![0].message).toContain('Question not found');
    });

    it('should validate notApplicable responses', async () => {
      (questionnaireService.getQuestionnaire as jest.Mock).mockResolvedValue({
        sections: [
          {
            questions: [
              {
                questionId: 'q1',
                type: QuestionType.SINGLE_CHOICE,
                required: true,
              },
            ],
          },
        ],
      });

      const result = await validationService.validateResponse('q1', null, true);

      expect(result.valid).toBe(true);
    });

    it('should reject null answer for required question', async () => {
      (questionnaireService.getQuestionnaire as jest.Mock).mockResolvedValue({
        sections: [
          {
            questions: [
              {
                questionId: 'q1',
                type: QuestionType.TEXT,
                required: true,
              },
            ],
          },
        ],
      });

      const result = await validationService.validateResponse('q1', null, false);

      expect(result.valid).toBe(false);
      expect(result.errors![0].message).toContain('required');
    });

    describe('Single Choice validation', () => {
      it('should validate correct single choice answer', async () => {
        (questionnaireService.getQuestionnaire as jest.Mock).mockResolvedValue({
          sections: [
            {
              questions: [
                {
                  questionId: 'q1',
                  type: QuestionType.SINGLE_CHOICE,
                  required: true,
                  options: [
                    { optionId: 'opt1', text: 'Option 1' },
                    { optionId: 'opt2', text: 'Option 2' },
                  ],
                },
              ],
            },
          ],
        });

        const result = await validationService.validateResponse('q1', 'opt1', false);

        expect(result.valid).toBe(true);
      });

      it('should reject invalid single choice option', async () => {
        (questionnaireService.getQuestionnaire as jest.Mock).mockResolvedValue({
          sections: [
            {
              questions: [
                {
                  questionId: 'q1',
                  type: QuestionType.SINGLE_CHOICE,
                  required: true,
                  options: [{ optionId: 'opt1', text: 'Option 1' }],
                },
              ],
            },
          ],
        });

        const result = await validationService.validateResponse('q1', 'invalid-option', false);

        expect(result.valid).toBe(false);
        expect(result.errors![0].message).toContain('Invalid option');
      });
    });

    describe('Multiple Choice validation', () => {
      it('should validate correct multiple choice answer', async () => {
        (questionnaireService.getQuestionnaire as jest.Mock).mockResolvedValue({
          sections: [
            {
              questions: [
                {
                  questionId: 'q1',
                  type: QuestionType.MULTIPLE_CHOICE,
                  required: true,
                  options: [
                    { optionId: 'opt1' },
                    { optionId: 'opt2' },
                    { optionId: 'opt3' },
                  ],
                },
              ],
            },
          ],
        });

        const result = await validationService.validateResponse('q1', ['opt1', 'opt2'], false);

        expect(result.valid).toBe(true);
      });

      it('should reject non-array multiple choice answer', async () => {
        (questionnaireService.getQuestionnaire as jest.Mock).mockResolvedValue({
          sections: [
            {
              questions: [
                {
                  questionId: 'q1',
                  type: QuestionType.MULTIPLE_CHOICE,
                  required: true,
                  options: [{ optionId: 'opt1' }],
                },
              ],
            },
          ],
        });

        const result = await validationService.validateResponse('q1', 'not-an-array', false);

        expect(result.valid).toBe(false);
        expect(result.errors![0].message).toContain('array');
      });

      it('should reject empty array for required multiple choice', async () => {
        (questionnaireService.getQuestionnaire as jest.Mock).mockResolvedValue({
          sections: [
            {
              questions: [
                {
                  questionId: 'q1',
                  type: QuestionType.MULTIPLE_CHOICE,
                  required: true,
                  options: [{ optionId: 'opt1' }],
                },
              ],
            },
          ],
        });

        const result = await validationService.validateResponse('q1', [], false);

        expect(result.valid).toBe(false);
        expect(result.errors![0].message).toContain('At least one option');
      });
    });

    describe('Rating validation', () => {
      it('should validate correct rating', async () => {
        (questionnaireService.getQuestionnaire as jest.Mock).mockResolvedValue({
          sections: [
            {
              questions: [
                {
                  questionId: 'q1',
                  type: QuestionType.RATING,
                  required: true,
                },
              ],
            },
          ],
        });

        for (let rating = 1; rating <= 5; rating++) {
          const result = await validationService.validateResponse('q1', rating, false);
          expect(result.valid).toBe(true);
        }
      });

      it('should reject out-of-range ratings', async () => {
        (questionnaireService.getQuestionnaire as jest.Mock).mockResolvedValue({
          sections: [
            {
              questions: [
                {
                  questionId: 'q1',
                  type: QuestionType.RATING,
                  required: true,
                },
              ],
            },
          ],
        });

        const result1 = await validationService.validateResponse('q1', 0, false);
        expect(result1.valid).toBe(false);

        const result2 = await validationService.validateResponse('q1', 6, false);
        expect(result2.valid).toBe(false);
      });

      it('should reject non-integer ratings', async () => {
        (questionnaireService.getQuestionnaire as jest.Mock).mockResolvedValue({
          sections: [
            {
              questions: [
                {
                  questionId: 'q1',
                  type: QuestionType.RATING,
                  required: true,
                },
              ],
            },
          ],
        });

        const result = await validationService.validateResponse('q1', 3.5, false);

        expect(result.valid).toBe(false);
      });
    });

    describe('Text validation', () => {
      it('should validate text answer', async () => {
        (questionnaireService.getQuestionnaire as jest.Mock).mockResolvedValue({
          sections: [
            {
              questions: [
                {
                  questionId: 'q1',
                  type: QuestionType.TEXT,
                  required: true,
                },
              ],
            },
          ],
        });

        const result = await validationService.validateResponse('q1', 'This is a valid text answer', false);

        expect(result.valid).toBe(true);
      });

      it('should reject text exceeding 1000 characters', async () => {
        (questionnaireService.getQuestionnaire as jest.Mock).mockResolvedValue({
          sections: [
            {
              questions: [
                {
                  questionId: 'q1',
                  type: QuestionType.TEXT,
                  required: true,
                },
              ],
            },
          ],
        });

        const longText = 'a'.repeat(1001);
        const result = await validationService.validateResponse('q1', longText, false);

        expect(result.valid).toBe(false);
        expect(result.errors![0].message).toContain('1000 characters');
      });
    });
  });

  describe('validateCompletion', () => {
    it('should validate complete assessment', async () => {
      (questionnaireService.getQuestionnaire as jest.Mock).mockResolvedValue({
        sections: [
          {
            questions: [
              { questionId: 'q1', required: true },
              { questionId: 'q2', required: true },
            ],
          },
        ],
      });

      (AssessmentResponse.findAll as jest.Mock).mockResolvedValue([
        { questionId: 'q1', answer: 'yes', notApplicable: false },
        { questionId: 'q2', answer: null, notApplicable: true },
      ]);

      const result = await validationService.validateCompletion('test-id');

      expect(result.valid).toBe(true);
      expect(result.missingQuestions).toBeUndefined();
    });

    it('should identify missing required questions', async () => {
      (questionnaireService.getQuestionnaire as jest.Mock).mockResolvedValue({
        sections: [
          {
            questions: [
              { questionId: 'q1', required: true },
              { questionId: 'q2', required: true },
              { questionId: 'q3', required: true },
            ],
          },
        ],
      });

      (AssessmentResponse.findAll as jest.Mock).mockResolvedValue([
        { questionId: 'q1', answer: 'yes', notApplicable: false },
      ]);

      const result = await validationService.validateCompletion('test-id');

      expect(result.valid).toBe(false);
      expect(result.missingQuestions).toHaveLength(2);
      expect(result.missingQuestions).toContain('q2');
      expect(result.missingQuestions).toContain('q3');
    });
  });
});
