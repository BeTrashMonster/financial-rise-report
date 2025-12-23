import { Test, TestingModule } from '@nestjs/testing';
import { QuestionsController } from './questions.controller';
import { QuestionsService } from './questions.service';
import { QuestionType, QuestionSection } from '../../../../../database/entities/Question'

describe('QuestionsController', () => {
  let controller: QuestionsController;
  let service: QuestionsService;

  const mockQuestionsService = {
    getQuestionnaire: jest.fn(),
    findBySection: jest.fn(),
    findConditionalQuestions: jest.fn(),
  };

  const mockQuestion = {
    id: 'question-123',
    questionText: 'Do you have a bookkeeping system in place?',
    questionType: QuestionType.SINGLE_CHOICE,
    section: QuestionSection.STABILIZE,
    orderIndex: 1,
    isRequired: true,
    isConditional: false,
    conditionalParentId: null,
    conditionalTriggerValue: null,
    answerOptions: [
      { value: 'yes', label: 'Yes' },
      { value: 'no', label: 'No' },
    ],
    helpText: 'This helps us understand your current setup',
    createdAt: new Date(),
    updatedAt: new Date(),
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

  describe('getQuestionnaire', () => {
    it('should return complete questionnaire including DISC questions (default)', async () => {
      const questionnaireResponse = {
        questions: [mockQuestion],
        total: 1,
      };

      mockQuestionsService.getQuestionnaire.mockResolvedValue(questionnaireResponse);

      const result = await controller.getQuestionnaire();

      expect(service.getQuestionnaire).toHaveBeenCalledWith(true);
      expect(result).toEqual(questionnaireResponse);
    });

    it('should return questionnaire without DISC when includeDisc=false', async () => {
      const questionnaireResponse = {
        questions: [mockQuestion],
        total: 1,
      };

      mockQuestionsService.getQuestionnaire.mockResolvedValue(questionnaireResponse);

      const result = await controller.getQuestionnaire(false);

      expect(service.getQuestionnaire).toHaveBeenCalledWith(false);
      expect(result).toEqual(questionnaireResponse);
    });
  });

  describe('getQuestionsBySection', () => {
    it('should return questions filtered by section', async () => {
      const stabilizeQuestions = [mockQuestion];
      mockQuestionsService.findBySection.mockResolvedValue(stabilizeQuestions);

      const result = await controller.getQuestionsBySection(QuestionSection.STABILIZE);

      expect(service.findBySection).toHaveBeenCalledWith(QuestionSection.STABILIZE);
      expect(result).toEqual(stabilizeQuestions);
    });
  });

  describe('getConditionalQuestions', () => {
    it('should return conditional questions for a parent', async () => {
      const conditionalQuestion = {
        ...mockQuestion,
        isConditional: true,
        conditionalParentId: 'parent-123',
        conditionalTriggerValue: 'S-Corp',
      };

      mockQuestionsService.findConditionalQuestions.mockResolvedValue([conditionalQuestion]);

      const result = await controller.getConditionalQuestions('parent-123');

      expect(service.findConditionalQuestions).toHaveBeenCalledWith('parent-123');
      expect(result).toEqual([conditionalQuestion]);
    });
  });
});
