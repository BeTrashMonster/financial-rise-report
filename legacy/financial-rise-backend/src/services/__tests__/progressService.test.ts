import progressService from '../progressService';
import { AssessmentResponse } from '../../models';
import questionnaireService from '../questionnaireService';

// Mock dependencies
jest.mock('../../models');
jest.mock('../questionnaireService');

describe('ProgressService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('calculateProgress', () => {
    it('should calculate 0% progress when no questions answered', async () => {
      // Mock questionnaire with 5 required questions
      (questionnaireService.getQuestionnaire as jest.Mock).mockResolvedValue({
        version: '1.0',
        sections: [
          {
            questions: [
              { questionId: '1', required: true },
              { questionId: '2', required: true },
              { questionId: '3', required: true },
              { questionId: '4', required: true },
              { questionId: '5', required: true },
            ],
          },
        ],
      });

      // No responses
      (AssessmentResponse.findAll as jest.Mock).mockResolvedValue([]);

      const result = await progressService.calculateProgress('test-assessment-id');

      expect(result.progress).toBe(0);
      expect(result.totalQuestions).toBe(5);
      expect(result.answeredQuestions).toBe(0);
    });

    it('should calculate 50% progress when half questions answered', async () => {
      (questionnaireService.getQuestionnaire as jest.Mock).mockResolvedValue({
        version: '1.0',
        sections: [
          {
            questions: [
              { questionId: '1', required: true },
              { questionId: '2', required: true },
              { questionId: '3', required: true },
              { questionId: '4', required: true },
            ],
          },
        ],
      });

      // 2 answered questions
      (AssessmentResponse.findAll as jest.Mock).mockResolvedValue([
        { questionId: '1', answer: 'yes', notApplicable: false },
        { questionId: '2', answer: null, notApplicable: true },
      ]);

      const result = await progressService.calculateProgress('test-assessment-id');

      expect(result.progress).toBe(50);
      expect(result.totalQuestions).toBe(4);
      expect(result.answeredQuestions).toBe(2);
    });

    it('should calculate 100% progress when all questions answered', async () => {
      (questionnaireService.getQuestionnaire as jest.Mock).mockResolvedValue({
        version: '1.0',
        sections: [
          {
            questions: [
              { questionId: '1', required: true },
              { questionId: '2', required: true },
              { questionId: '3', required: true },
            ],
          },
        ],
      });

      (AssessmentResponse.findAll as jest.Mock).mockResolvedValue([
        { questionId: '1', answer: 'yes', notApplicable: false },
        { questionId: '2', answer: 5, notApplicable: false },
        { questionId: '3', answer: null, notApplicable: true },
      ]);

      const result = await progressService.calculateProgress('test-assessment-id');

      expect(result.progress).toBe(100);
      expect(result.totalQuestions).toBe(3);
      expect(result.answeredQuestions).toBe(3);
    });

    it('should handle questionnaire with no required questions', async () => {
      (questionnaireService.getQuestionnaire as jest.Mock).mockResolvedValue({
        version: '1.0',
        sections: [
          {
            questions: [{ questionId: '1', required: false }],
          },
        ],
      });

      (AssessmentResponse.findAll as jest.Mock).mockResolvedValue([]);

      const result = await progressService.calculateProgress('test-assessment-id');

      expect(result.progress).toBe(0);
      expect(result.totalQuestions).toBe(0);
    });
  });
});
