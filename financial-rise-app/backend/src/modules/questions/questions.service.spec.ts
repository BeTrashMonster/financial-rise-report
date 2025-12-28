import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { QuestionsService } from './questions.service';
import { Question, QuestionType } from './entities/question.entity';

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
    question_key: 'Q1',
    question_text: 'Do you have a bookkeeping system in place?',
    question_type: QuestionType.SINGLE_CHOICE,
    display_order: 1,
    required: true,
    options: [
      { value: 'yes', text: 'Yes' },
      { value: 'no', text: 'No' },
      { value: 'partial', text: 'Partially' },
    ],
    created_at: new Date(),
    updated_at: new Date(),
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
    it('should return all questions ordered by display_order', async () => {
      const questions = [mockQuestion];
      mockQuestionRepository.find.mockResolvedValue(questions);

      const result = await service.findAll();

      expect(questionRepository.find).toHaveBeenCalledWith({
        order: { display_order: 'ASC' },
      });
      expect(result).toEqual(questions);
    });

    it('should return empty array when no questions exist', async () => {
      mockQuestionRepository.find.mockResolvedValue([]);

      const result = await service.findAll();

      expect(result).toEqual([]);
    });
  });

  describe('findOne', () => {
    it('should return a single question by ID', async () => {
      mockQuestionRepository.findOne.mockResolvedValue(mockQuestion);

      const result = await service.findOne('question-123');

      expect(questionRepository.findOne).toHaveBeenCalledWith({
        where: { id: 'question-123' },
      });
      expect(result).toEqual(mockQuestion);
    });

    it('should return null when question not found', async () => {
      mockQuestionRepository.findOne.mockResolvedValue(null);

      const result = await service.findOne('nonexistent');

      expect(result).toBeNull();
    });
  });

  describe('countTotal', () => {
    it('should return total count of questions', async () => {
      mockQuestionRepository.count.mockResolvedValue(50);

      const result = await service.countTotal();

      expect(questionRepository.count).toHaveBeenCalled();
      expect(result).toBe(50);
    });

    it('should return 0 when no questions exist', async () => {
      mockQuestionRepository.count.mockResolvedValue(0);

      const result = await service.countTotal();

      expect(result).toBe(0);
    });
  });
});
