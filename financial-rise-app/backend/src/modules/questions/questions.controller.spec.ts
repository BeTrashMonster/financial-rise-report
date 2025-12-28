import { Test, TestingModule } from '@nestjs/testing';
import { QuestionsController } from './questions.controller';
import { QuestionsService } from './questions.service';
import { QuestionType } from './entities/question.entity';

describe('QuestionsController', () => {
  let controller: QuestionsController;
  let service: QuestionsService;

  const mockQuestionsService = {
    findAll: jest.fn(),
  };

  const mockQuestion = {
    id: 'question-123',
    question_key: 'Q1',
    question_text: 'Do you have a bookkeeping system in place?',
    question_type: QuestionType.SINGLE_CHOICE,
    display_order: 1,
    required: true,
    options: [
      { value: 'yes', text: 'Yes' },
      { value: 'no', text: 'No' },
    ],
    created_at: new Date(),
    updated_at: new Date(),
  };

  const mockOptionalQuestion = {
    ...mockQuestion,
    id: 'question-456',
    question_key: 'Q2',
    required: false,
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [QuestionsController],
      providers: [
        {
          provide: QuestionsService,
          useValue: mockQuestionsService,
        },
      ],
    }).compile();

    controller = module.get<QuestionsController>(QuestionsController);
    service = module.get<QuestionsService>(QuestionsService);

    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('getQuestions', () => {
    it('should return questions with metadata', async () => {
      const questions = [mockQuestion, mockOptionalQuestion];
      mockQuestionsService.findAll.mockResolvedValue(questions);

      const result = await controller.getQuestions();

      expect(service.findAll).toHaveBeenCalled();
      expect(result).toEqual({
        questions,
        meta: {
          totalQuestions: 2,
          requiredQuestions: 1,
          optionalQuestions: 1,
        },
      });
    });

    it('should handle empty question list', async () => {
      mockQuestionsService.findAll.mockResolvedValue([]);

      const result = await controller.getQuestions();

      expect(result).toEqual({
        questions: [],
        meta: {
          totalQuestions: 0,
          requiredQuestions: 0,
          optionalQuestions: 0,
        },
      });
    });

    it('should count all required questions correctly', async () => {
      const allRequiredQuestions = [
        mockQuestion,
        { ...mockQuestion, id: 'q2', question_key: 'Q2' },
        { ...mockQuestion, id: 'q3', question_key: 'Q3' },
      ];
      mockQuestionsService.findAll.mockResolvedValue(allRequiredQuestions);

      const result = await controller.getQuestions();

      expect(result.meta.totalQuestions).toBe(3);
      expect(result.meta.requiredQuestions).toBe(3);
      expect(result.meta.optionalQuestions).toBe(0);
    });
  });
});
