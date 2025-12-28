import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ProgressService } from './progress.service';
import { AssessmentResponse } from '../entities/assessment-response.entity';
import { Question } from '../../questions/entities/question.entity';

describe('ProgressService', () => {
  let service: ProgressService;
  let responseRepository: jest.Mocked<Repository<AssessmentResponse>>;
  let questionRepository: jest.Mocked<Repository<Question>>;

  const mockAssessmentId = '550e8400-e29b-41d4-a716-446655440000';

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ProgressService,
        {
          provide: getRepositoryToken(AssessmentResponse),
          useValue: {
            find: jest.fn(),
            createQueryBuilder: jest.fn(),
          },
        },
        {
          provide: getRepositoryToken(Question),
          useValue: {
            find: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<ProgressService>(ProgressService);
    responseRepository = module.get(getRepositoryToken(AssessmentResponse));
    questionRepository = module.get(getRepositoryToken(Question));
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('calculateProgress', () => {
    it('should calculate 0% progress when no questions are answered', async () => {
      const mockRequiredQuestions = [
        { question_key: 'Q1', required: true },
        { question_key: 'Q2', required: true },
        { question_key: 'Q3', required: true },
      ] as Question[];

      questionRepository.find.mockResolvedValue(mockRequiredQuestions);
      responseRepository.find.mockResolvedValue([]);

      const result = await service.calculateProgress(mockAssessmentId);

      expect(result).toEqual({
        progress: 0,
        totalQuestions: 3,
        answeredQuestions: 0,
      });
    });

    it('should calculate 100% progress when all questions are answered', async () => {
      const mockRequiredQuestions = [
        { question_key: 'Q1', required: true },
        { question_key: 'Q2', required: true },
        { question_key: 'Q3', required: true },
      ] as Question[];

      const mockResponses: Partial<AssessmentResponse>[] = [
        {
          id: 'r1',
          assessment_id: mockAssessmentId,
          question_id: 'Q1',
          answer: { value: 'answer1' },
          not_applicable: false,
          consultant_notes: null,
          answered_at: new Date(),
        },
        {
          id: 'r2',
          assessment_id: mockAssessmentId,
          question_id: 'Q2',
          answer: { value: 'answer2' },
          not_applicable: false,
          consultant_notes: null,
          answered_at: new Date(),
        },
        {
          id: 'r3',
          assessment_id: mockAssessmentId,
          question_id: 'Q3',
          answer: { value: 'answer3' },
          not_applicable: false,
          consultant_notes: null,
          answered_at: new Date(),
        },
      ];

      questionRepository.find.mockResolvedValue(mockRequiredQuestions);
      responseRepository.find.mockResolvedValue(mockResponses as AssessmentResponse[]);

      const result = await service.calculateProgress(mockAssessmentId);

      expect(result).toEqual({
        progress: 100,
        totalQuestions: 3,
        answeredQuestions: 3,
      });
    });

    it('should calculate 50% progress when half of questions are answered', async () => {
      const mockRequiredQuestions = [
        { question_key: 'Q1', required: true },
        { question_key: 'Q2', required: true },
        { question_key: 'Q3', required: true },
        { question_key: 'Q4', required: true },
      ] as Question[];

      const mockResponses: Partial<AssessmentResponse>[] = [
        {
          id: 'r1',
          assessment_id: mockAssessmentId,
          question_id: 'Q1',
          answer: { value: 'answer1' },
          not_applicable: false,
          consultant_notes: null,
          answered_at: new Date(),
        },
        {
          id: 'r2',
          assessment_id: mockAssessmentId,
          question_id: 'Q2',
          answer: { value: 'answer2' },
          not_applicable: false,
          consultant_notes: null,
          answered_at: new Date(),
        },
      ];

      questionRepository.find.mockResolvedValue(mockRequiredQuestions);
      responseRepository.find.mockResolvedValue(mockResponses as AssessmentResponse[]);

      const result = await service.calculateProgress(mockAssessmentId);

      expect(result).toEqual({
        progress: 50,
        totalQuestions: 4,
        answeredQuestions: 2,
      });
    });

    it('should count not_applicable responses as answered', async () => {
      const mockRequiredQuestions = [
        { question_key: 'Q1', required: true },
        { question_key: 'Q2', required: true },
        { question_key: 'Q3', required: true },
      ] as Question[];

      const mockResponses: Partial<AssessmentResponse>[] = [
        {
          id: 'r1',
          assessment_id: mockAssessmentId,
          question_id: 'Q1',
          answer: { value: 'answer1' },
          not_applicable: false,
          consultant_notes: null,
          answered_at: new Date(),
        },
        {
          id: 'r2',
          assessment_id: mockAssessmentId,
          question_id: 'Q2',
          // answer omitted - N/A response
          not_applicable: true,
          consultant_notes: null,
          answered_at: new Date(),
        },
        {
          id: 'r3',
          assessment_id: mockAssessmentId,
          question_id: 'Q3',
          answer: { value: 'answer3' },
          not_applicable: false,
          consultant_notes: null,
          answered_at: new Date(),
        },
      ];

      questionRepository.find.mockResolvedValue(mockRequiredQuestions);
      responseRepository.find.mockResolvedValue(mockResponses as AssessmentResponse[]);

      const result = await service.calculateProgress(mockAssessmentId);

      expect(result).toEqual({
        progress: 100,
        totalQuestions: 3,
        answeredQuestions: 3,
      });
    });

    it('should return 0% when no questions exist in system', async () => {
      questionRepository.find.mockResolvedValue([]);
      responseRepository.find.mockResolvedValue([]);

      const result = await service.calculateProgress(mockAssessmentId);

      expect(result).toEqual({
        progress: 0,
        totalQuestions: 0,
        answeredQuestions: 0,
      });
    });

    it('should round progress to 2 decimal places', async () => {
      const mockRequiredQuestions = [
        { question_key: 'Q1', required: true },
        { question_key: 'Q2', required: true },
        { question_key: 'Q3', required: true },
      ] as Question[];

      const mockResponses: Partial<AssessmentResponse>[] = [
        {
          id: 'r1',
          assessment_id: mockAssessmentId,
          question_id: 'Q1',
          answer: { value: 'answer1' },
          not_applicable: false,
          consultant_notes: null,
          answered_at: new Date(),
        },
      ];

      questionRepository.find.mockResolvedValue(mockRequiredQuestions);
      responseRepository.find.mockResolvedValue(mockResponses as AssessmentResponse[]);

      const result = await service.calculateProgress(mockAssessmentId);

      // 1/3 = 33.333... should round to 33.33
      expect(result.progress).toBe(33.33);
    });

    it('should ignore responses with null answer and not_applicable=false', async () => {
      const mockRequiredQuestions = [
        { question_key: 'Q1', required: true },
        { question_key: 'Q2', required: true },
      ] as Question[];

      const mockResponses: Partial<AssessmentResponse>[] = [
        {
          id: 'r1',
          assessment_id: mockAssessmentId,
          question_id: 'Q1',
          answer: { value: 'answer1' },
          not_applicable: false,
          consultant_notes: null,
          answered_at: new Date(),
        },
        {
          id: 'r2',
          assessment_id: mockAssessmentId,
          question_id: 'Q2',
          answer: null as any, // Unanswered question
          not_applicable: false,
          consultant_notes: null,
          answered_at: new Date(),
        },
      ];

      questionRepository.find.mockResolvedValue(mockRequiredQuestions);
      responseRepository.find.mockResolvedValue(mockResponses as AssessmentResponse[]);

      const result = await service.calculateProgress(mockAssessmentId);

      expect(result).toEqual({
        progress: 50,
        totalQuestions: 2,
        answeredQuestions: 1,
      });
    });
  });

  describe('calculateRequiredProgress', () => {
    it('should calculate progress for only required questions', async () => {
      const mockRequiredQuestions = [
        { question_key: 'Q1', required: true },
        { question_key: 'Q2', required: true },
      ] as Question[];

      const mockQueryBuilder = {
        where: jest.fn().mockReturnThis(),
        andWhere: jest.fn().mockReturnThis(),
        getMany: jest.fn().mockResolvedValue([
          { question_id: 'Q1', answer: 'answer1', not_applicable: false },
        ]),
      };

      questionRepository.find.mockResolvedValue(mockRequiredQuestions);
      (responseRepository.createQueryBuilder as jest.Mock).mockReturnValue(
        mockQueryBuilder,
      );

      const result = await service.calculateRequiredProgress(mockAssessmentId);

      expect(result).toEqual({
        progress: 50,
        totalQuestions: 2,
        answeredQuestions: 1,
      });
    });

    it('should return 0% when no required questions exist', async () => {
      questionRepository.find.mockResolvedValue([]);

      const result = await service.calculateRequiredProgress(mockAssessmentId);

      expect(result).toEqual({
        progress: 0,
        totalQuestions: 0,
        answeredQuestions: 0,
      });
    });
  });

  describe('isAssessmentComplete', () => {
    it('should return true when all required questions are answered', async () => {
      const mockRequiredQuestions = [
        { question_key: 'Q1', required: true },
        { question_key: 'Q2', required: true },
      ] as Question[];

      const mockQueryBuilder = {
        where: jest.fn().mockReturnThis(),
        andWhere: jest.fn().mockReturnThis(),
        getMany: jest.fn().mockResolvedValue([
          { question_id: 'Q1', answer: 'answer1', not_applicable: false },
          { question_id: 'Q2', answer: 'answer2', not_applicable: false },
        ]),
      };

      questionRepository.find.mockResolvedValue(mockRequiredQuestions);
      (responseRepository.createQueryBuilder as jest.Mock).mockReturnValue(
        mockQueryBuilder,
      );

      const result = await service.isAssessmentComplete(mockAssessmentId);

      expect(result).toBe(true);
    });

    it('should return false when some required questions are missing', async () => {
      const mockRequiredQuestions = [
        { question_key: 'Q1', required: true },
        { question_key: 'Q2', required: true },
      ] as Question[];

      const mockQueryBuilder = {
        where: jest.fn().mockReturnThis(),
        andWhere: jest.fn().mockReturnThis(),
        getMany: jest.fn().mockResolvedValue([
          { question_id: 'Q1', answer: 'answer1', not_applicable: false },
        ]),
      };

      questionRepository.find.mockResolvedValue(mockRequiredQuestions);
      (responseRepository.createQueryBuilder as jest.Mock).mockReturnValue(
        mockQueryBuilder,
      );

      const result = await service.isAssessmentComplete(mockAssessmentId);

      expect(result).toBe(false);
    });
  });

  describe('getMissingRequiredQuestions', () => {
    it('should return array of missing required question keys', async () => {
      const mockRequiredQuestions = [
        { question_key: 'Q1', required: true },
        { question_key: 'Q2', required: true },
        { question_key: 'Q3', required: true },
      ] as Question[];

      const mockResponses: Partial<AssessmentResponse>[] = [
        {
          id: 'r1',
          assessment_id: mockAssessmentId,
          question_id: 'Q1',
          answer: { value: 'answer1' },
          not_applicable: false,
          consultant_notes: null,
          answered_at: new Date(),
        },
      ];

      questionRepository.find.mockResolvedValue(mockRequiredQuestions);
      responseRepository.find.mockResolvedValue(mockResponses as AssessmentResponse[]);

      const result =
        await service.getMissingRequiredQuestions(mockAssessmentId);

      expect(result).toEqual(['Q2', 'Q3']);
    });

    it('should return empty array when all required questions are answered', async () => {
      const mockRequiredQuestions = [
        { question_key: 'Q1', required: true },
        { question_key: 'Q2', required: true },
      ] as Question[];

      const mockResponses: Partial<AssessmentResponse>[] = [
        {
          id: 'r1',
          assessment_id: mockAssessmentId,
          question_id: 'Q1',
          answer: { value: 'answer1' },
          not_applicable: false,
          consultant_notes: null,
          answered_at: new Date(),
        },
        {
          id: 'r2',
          assessment_id: mockAssessmentId,
          question_id: 'Q2',
          answer: { value: 'answer2' },
          not_applicable: false,
          consultant_notes: null,
          answered_at: new Date(),
        },
      ];

      questionRepository.find.mockResolvedValue(mockRequiredQuestions);
      responseRepository.find.mockResolvedValue(mockResponses as AssessmentResponse[]);

      const result =
        await service.getMissingRequiredQuestions(mockAssessmentId);

      expect(result).toEqual([]);
    });

    it('should count not_applicable as answered', async () => {
      const mockRequiredQuestions = [
        { question_key: 'Q1', required: true },
        { question_key: 'Q2', required: true },
      ] as Question[];

      const mockResponses: Partial<AssessmentResponse>[] = [
        {
          id: 'r1',
          assessment_id: mockAssessmentId,
          question_id: 'Q1',
          answer: { value: 'answer1' },
          not_applicable: false,
          consultant_notes: null,
          answered_at: new Date(),
        },
        {
          id: 'r2',
          assessment_id: mockAssessmentId,
          question_id: 'Q2',
          // answer omitted - N/A response
          not_applicable: true,
          consultant_notes: null,
          answered_at: new Date(),
        },
      ];

      questionRepository.find.mockResolvedValue(mockRequiredQuestions);
      responseRepository.find.mockResolvedValue(mockResponses as AssessmentResponse[]);

      const result =
        await service.getMissingRequiredQuestions(mockAssessmentId);

      expect(result).toEqual([]);
    });

    it('should return all required questions when none are answered', async () => {
      const mockRequiredQuestions = [
        { question_key: 'Q1', required: true },
        { question_key: 'Q2', required: true },
        { question_key: 'Q3', required: true },
      ] as Question[];

      questionRepository.find.mockResolvedValue(mockRequiredQuestions);
      responseRepository.find.mockResolvedValue([]);

      const result =
        await service.getMissingRequiredQuestions(mockAssessmentId);

      expect(result).toEqual(['Q1', 'Q2', 'Q3']);
    });
  });
});
