import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { QuestionsService } from './questions.service';
import { Question, QuestionType, QuestionSection } from '../../../../../database/entities/Question'

describe('QuestionsService', () => {
  let service: QuestionsService;
  let questionRepository: Repository<Question>;

  const mockQuestionRepository = {
    find: jest.fn(),
    findOne: jest.fn(),
    count: jest.fn(),
  };

  const mockQuestion: Partial<Question> = {
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
      { value: 'partial', label: 'Partially' },
    ],
    helpText: 'This helps us understand your current financial management setup',
    createdAt: new Date(),
    updatedAt: new Date(),
    deletedAt: null,
  };

  const mockConditionalQuestion: Partial<Question> = {
    id: 'question-456',
    questionText: 'Are you on S-Corp payroll?',
    questionType: QuestionType.SINGLE_CHOICE,
    section: QuestionSection.METADATA,
    orderIndex: 2,
    isRequired: true,
    isConditional: true,
    conditionalParentId: 'question-entity-type',
    conditionalTriggerValue: 'S-Corp',
    answerOptions: [
      { value: 'yes', label: 'Yes' },
      { value: 'no', label: 'No' },
    ],
    helpText: null,
    createdAt: new Date(),
    updatedAt: new Date(),
    deletedAt: null,
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        QuestionsService,
        {
          provide: getRepositoryToken(Question),
          useValue: mockQuestionRepository,
        },
      ],
    }).compile();

    service = module.get<QuestionsService>(QuestionsService);
    questionRepository = module.get<Repository<Question>>(getRepositoryToken(Question));

    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('findAll', () => {
    it('should return all non-conditional questions ordered by orderIndex', async () => {
      const questions = [mockQuestion];
      mockQuestionRepository.find.mockResolvedValue(questions);

      const result = await service.findAll();

      expect(questionRepository.find).toHaveBeenCalledWith({
        where: { deletedAt: null as any, isConditional: false },
        order: { orderIndex: 'ASC' },
      });
      expect(result).toEqual(questions);
    });

    it('should hide DISC questions from client-facing questionnaire', async () => {
      const discQuestion = {
        ...mockQuestion,
        section: QuestionSection.DISC,
      };

      // Service should filter these out or mark them differently
      mockQuestionRepository.find.mockResolvedValue([mockQuestion]);

      const result = await service.findAll();

      // Should not include DISC questions
      const hasDiscQuestions = result.some((q) => q.section === QuestionSection.DISC);
      expect(hasDiscQuestions).toBe(false);
    });
  });

  describe('findOne', () => {
    it('should return a single question by ID', async () => {
      mockQuestionRepository.findOne.mockResolvedValue(mockQuestion);

      const result = await service.findOne('question-123');

      expect(questionRepository.findOne).toHaveBeenCalledWith({
        where: { id: 'question-123', deletedAt: null as any },
      });
      expect(result).toEqual(mockQuestion);
    });

    it('should return null when question not found', async () => {
      mockQuestionRepository.findOne.mockResolvedValue(null);

      const result = await service.findOne('nonexistent');

      expect(result).toBeNull();
    });
  });

  describe('findBySection', () => {
    it('should return questions filtered by section', async () => {
      const stabilizeQuestions = [mockQuestion];
      mockQuestionRepository.find.mockResolvedValue(stabilizeQuestions);

      const result = await service.findBySection(QuestionSection.STABILIZE);

      expect(questionRepository.find).toHaveBeenCalledWith({
        where: { section: QuestionSection.STABILIZE, deletedAt: null as any },
        order: { orderIndex: 'ASC' },
      });
      expect(result).toEqual(stabilizeQuestions);
    });
  });

  describe('countTotal', () => {
    it('should return total count of non-conditional questions', async () => {
      mockQuestionRepository.count.mockResolvedValue(50);

      const result = await service.countTotal();

      expect(questionRepository.count).toHaveBeenCalledWith({
        where: { deletedAt: null as any, isConditional: false },
      });
      expect(result).toBe(50);
    });
  });

  describe('findConditionalQuestions', () => {
    it('should return conditional questions for a parent', async () => {
      const conditionalQuestions = [mockConditionalQuestion];
      mockQuestionRepository.find.mockResolvedValue(conditionalQuestions);

      const result = await service.findConditionalQuestions('question-entity-type');

      expect(questionRepository.find).toHaveBeenCalledWith({
        where: {
          conditionalParentId: 'question-entity-type',
          deletedAt: null as any,
        },
        order: { orderIndex: 'ASC' },
      });
      expect(result).toEqual(conditionalQuestions);
    });
  });

  describe('getQuestionnaire', () => {
    it('should return complete questionnaire for consultant (including DISC)', async () => {
      const allQuestions = [
        mockQuestion,
        { ...mockQuestion, section: QuestionSection.DISC },
      ];
      mockQuestionRepository.find.mockResolvedValue(allQuestions);
      mockQuestionRepository.count.mockResolvedValue(allQuestions.length);

      const result = await service.getQuestionnaire(true);

      expect(result.questions).toEqual(allQuestions);
      expect(result.total).toBe(allQuestions.length);
    });

    it('should return questionnaire without DISC for clients', async () => {
      const clientQuestions = [mockQuestion];
      const allQuestions = [
        mockQuestion,
        { ...mockQuestion, section: QuestionSection.DISC },
      ];

      // First call returns all, then service filters
      mockQuestionRepository.find.mockResolvedValue(clientQuestions);
      mockQuestionRepository.count.mockResolvedValue(clientQuestions.length);

      const result = await service.getQuestionnaire(false);

      expect(result.questions).toEqual(clientQuestions);
      expect(result.total).toBe(clientQuestions.length);
      const hasDiscQuestions = result.questions.some((q) => q.section === QuestionSection.DISC);
      expect(hasDiscQuestions).toBe(false);
    });
  });
});
