import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { BadRequestException } from '@nestjs/common';
import { ValidationService } from './validation.service';
import { Question, QuestionType } from '../../questions/entities/question.entity';
import { AssessmentResponse } from '../entities/assessment-response.entity';

describe('ValidationService', () => {
  let service: ValidationService;
  let questionRepository: jest.Mocked<Repository<Question>>;
  let responseRepository: jest.Mocked<Repository<AssessmentResponse>>;

  const mockAssessmentId = '550e8400-e29b-41d4-a716-446655440000';

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ValidationService,
        {
          provide: getRepositoryToken(Question),
          useValue: {
            findOne: jest.fn(),
            find: jest.fn(),
          },
        },
        {
          provide: getRepositoryToken(AssessmentResponse),
          useValue: {
            find: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<ValidationService>(ValidationService);
    questionRepository = module.get(getRepositoryToken(Question));
    responseRepository = module.get(getRepositoryToken(AssessmentResponse));
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('validateResponse', () => {
    it('should return error when question not found', async () => {
      questionRepository.findOne.mockResolvedValue(null);

      const result = await service.validateResponse('INVALID', 'answer', false);

      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual({
        field: 'questionId',
        message: 'Question not found',
      });
    });

    it('should accept notApplicable=true without further validation', async () => {
      const mockQuestion: Partial<Question> = {
        question_key: 'Q1',
        question_type: QuestionType.SINGLE_CHOICE,
        required: true,
      };

      questionRepository.findOne.mockResolvedValue(mockQuestion as Question);

      const result = await service.validateResponse('Q1', null, true);

      expect(result.valid).toBe(true);
    });

    it('should reject null answer for required question', async () => {
      const mockQuestion: Partial<Question> = {
        question_key: 'Q1',
        question_type: QuestionType.TEXT,
        required: true,
      };

      questionRepository.findOne.mockResolvedValue(mockQuestion as Question);

      const result = await service.validateResponse('Q1', null, false);

      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual({
        field: 'answer',
        message: 'Answer is required for this question',
      });
    });

    it('should accept null answer for optional question', async () => {
      const mockQuestion: Partial<Question> = {
        question_key: 'Q1',
        question_type: QuestionType.TEXT,
        required: false,
      };

      questionRepository.findOne.mockResolvedValue(mockQuestion as Question);

      const result = await service.validateResponse('Q1', null, false);

      expect(result.valid).toBe(true);
    });
  });

  describe('Single Choice Validation', () => {
    it('should accept valid single choice answer', async () => {
      const mockQuestion: Partial<Question> = {
        question_key: 'Q1',
        question_type: QuestionType.SINGLE_CHOICE,
        required: true,
        options: [
          { optionId: 'opt1', text: 'Option 1' },
          { optionId: 'opt2', text: 'Option 2' },
        ],
      };

      questionRepository.findOne.mockResolvedValue(mockQuestion as Question);

      const result = await service.validateResponse('Q1', 'opt1', false);

      expect(result.valid).toBe(true);
    });

    it('should reject invalid single choice answer', async () => {
      const mockQuestion: Partial<Question> = {
        question_key: 'Q1',
        question_type: QuestionType.SINGLE_CHOICE,
        required: true,
        options: [
          { optionId: 'opt1', text: 'Option 1' },
          { optionId: 'opt2', text: 'Option 2' },
        ],
      };

      questionRepository.findOne.mockResolvedValue(mockQuestion as Question);

      const result = await service.validateResponse('Q1', 'invalid', false);

      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual({
        field: 'answer',
        message: 'Invalid option selected',
      });
    });

    it('should reject when question has no options', async () => {
      const mockQuestion: Partial<Question> = {
        question_key: 'Q1',
        question_type: QuestionType.SINGLE_CHOICE,
        required: true,
        options: null,
      };

      questionRepository.findOne.mockResolvedValue(mockQuestion as Question);

      const result = await service.validateResponse('Q1', 'opt1', false);

      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual({
        field: 'answer',
        message: 'Question has no options',
      });
    });
  });

  describe('Multiple Choice Validation', () => {
    const mockMultipleChoiceQuestion: Partial<Question> = {
      question_key: 'Q1',
      question_type: QuestionType.MULTIPLE_CHOICE,
      required: true,
      options: [
        { optionId: 'opt1', text: 'Option 1' },
        { optionId: 'opt2', text: 'Option 2' },
        { optionId: 'opt3', text: 'Option 3' },
      ],
    };

    it('should accept valid multiple choice answer', async () => {
      questionRepository.findOne.mockResolvedValue(mockMultipleChoiceQuestion as Question);

      const result = await service.validateResponse(
        'Q1',
        ['opt1', 'opt2'],
        false,
      );

      expect(result.valid).toBe(true);
    });

    it('should reject non-array answer', async () => {
      questionRepository.findOne.mockResolvedValue(mockMultipleChoiceQuestion as Question);

      const result = await service.validateResponse('Q1', 'opt1', false);

      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual({
        field: 'answer',
        message: 'Answer must be an array',
      });
    });

    it('should reject empty array for required question', async () => {
      questionRepository.findOne.mockResolvedValue(mockMultipleChoiceQuestion as Question);

      const result = await service.validateResponse('Q1', [], false);

      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual({
        field: 'answer',
        message: 'At least one option must be selected',
      });
    });

    it('should reject array with invalid option IDs', async () => {
      questionRepository.findOne.mockResolvedValue(mockMultipleChoiceQuestion as Question);

      const result = await service.validateResponse(
        'Q1',
        ['opt1', 'invalid'],
        false,
      );

      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual({
        field: 'answer',
        message: 'Invalid options selected',
      });
    });

    it('should accept empty array for optional question', async () => {
      const optionalQuestion = {
        ...mockMultipleChoiceQuestion,
        required: false,
      };
      questionRepository.findOne.mockResolvedValue(optionalQuestion as Question);

      const result = await service.validateResponse('Q1', [], false);

      expect(result.valid).toBe(true);
    });
  });

  describe('Rating Validation', () => {
    const mockRatingQuestion: Partial<Question> = {
      question_key: 'Q1',
      question_type: QuestionType.RATING,
      required: true,
    };

    it('should accept valid rating (1-5)', async () => {
      questionRepository.findOne.mockResolvedValue(mockRatingQuestion as Question);

      for (let rating = 1; rating <= 5; rating++) {
        const result = await service.validateResponse('Q1', rating, false);
        expect(result.valid).toBe(true);
      }
    });

    it('should reject non-number rating', async () => {
      questionRepository.findOne.mockResolvedValue(mockRatingQuestion as Question);

      const result = await service.validateResponse('Q1', 'three', false);

      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual({
        field: 'answer',
        message: 'Rating must be a number',
      });
    });

    it('should reject rating below 1', async () => {
      questionRepository.findOne.mockResolvedValue(mockRatingQuestion as Question);

      const result = await service.validateResponse('Q1', 0, false);

      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual({
        field: 'answer',
        message: 'Rating must be an integer between 1 and 5',
      });
    });

    it('should reject rating above 5', async () => {
      questionRepository.findOne.mockResolvedValue(mockRatingQuestion as Question);

      const result = await service.validateResponse('Q1', 6, false);

      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual({
        field: 'answer',
        message: 'Rating must be an integer between 1 and 5',
      });
    });

    it('should reject non-integer rating', async () => {
      questionRepository.findOne.mockResolvedValue(mockRatingQuestion as Question);

      const result = await service.validateResponse('Q1', 3.5, false);

      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual({
        field: 'answer',
        message: 'Rating must be an integer between 1 and 5',
      });
    });
  });

  describe('Text Validation', () => {
    const mockTextQuestion: Partial<Question> = {
      question_key: 'Q1',
      question_type: QuestionType.TEXT,
      required: true,
    };

    it('should accept valid text answer', async () => {
      questionRepository.findOne.mockResolvedValue(mockTextQuestion as Question);

      const result = await service.validateResponse(
        'Q1',
        'This is a valid text answer',
        false,
      );

      expect(result.valid).toBe(true);
    });

    it('should reject non-string answer', async () => {
      questionRepository.findOne.mockResolvedValue(mockTextQuestion as Question);

      const result = await service.validateResponse('Q1', 123, false);

      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual({
        field: 'answer',
        message: 'Answer must be a string',
      });
    });

    it('should reject text exceeding 1000 characters', async () => {
      questionRepository.findOne.mockResolvedValue(mockTextQuestion as Question);

      const longText = 'a'.repeat(1001);
      const result = await service.validateResponse('Q1', longText, false);

      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual({
        field: 'answer',
        message: 'Text answer must not exceed 1000 characters',
      });
    });

    it('should accept text at exactly 1000 characters', async () => {
      questionRepository.findOne.mockResolvedValue(mockTextQuestion as Question);

      const maxText = 'a'.repeat(1000);
      const result = await service.validateResponse('Q1', maxText, false);

      expect(result.valid).toBe(true);
    });
  });

  describe('validateCompletion', () => {
    it('should validate complete assessment', async () => {
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

      const result = await service.validateCompletion(mockAssessmentId);

      expect(result.valid).toBe(true);
      expect(result.missingQuestions).toBeUndefined();
    });

    it('should identify missing required questions', async () => {
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

      const result = await service.validateCompletion(mockAssessmentId);

      expect(result.valid).toBe(false);
      expect(result.missingQuestions).toEqual(['Q2', 'Q3']);
      expect(result.errors).toContainEqual({
        field: 'responses',
        message: '2 required question(s) not answered',
      });
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
          answer: null as any,
          not_applicable: true,
          consultant_notes: null,
          answered_at: new Date(),
        },
      ];

      questionRepository.find.mockResolvedValue(mockRequiredQuestions);
      responseRepository.find.mockResolvedValue(mockResponses as AssessmentResponse[]);

      const result = await service.validateCompletion(mockAssessmentId);

      expect(result.valid).toBe(true);
    });
  });

  describe('validateResponseOrThrow', () => {
    it('should not throw for valid response', async () => {
      const mockQuestion: Partial<Question> = {
        question_key: 'Q1',
        question_type: QuestionType.TEXT,
        required: true,
      };

      questionRepository.findOne.mockResolvedValue(mockQuestion as Question);

      await expect(
        service.validateResponseOrThrow('Q1', 'Valid answer', false),
      ).resolves.not.toThrow();
    });

    it('should throw BadRequestException for invalid response', async () => {
      const mockQuestion: Partial<Question> = {
        question_key: 'Q1',
        question_type: QuestionType.RATING,
        required: true,
      };

      questionRepository.findOne.mockResolvedValue(mockQuestion as Question);

      await expect(
        service.validateResponseOrThrow('Q1', 10, false),
      ).rejects.toThrow(BadRequestException);

      await expect(
        service.validateResponseOrThrow('Q1', 10, false),
      ).rejects.toThrow('Rating must be an integer between 1 and 5');
    });
  });

  describe('validateCompletionOrThrow', () => {
    it('should not throw for complete assessment', async () => {
      const mockRequiredQuestions = [
        { question_key: 'Q1', required: true },
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

      await expect(
        service.validateCompletionOrThrow(mockAssessmentId),
      ).resolves.not.toThrow();
    });

    it('should throw BadRequestException for incomplete assessment', async () => {
      const mockRequiredQuestions = [
        { question_key: 'Q1', required: true },
        { question_key: 'Q2', required: true },
      ] as Question[];

      const mockResponses = [] as AssessmentResponse[];

      questionRepository.find.mockResolvedValue(mockRequiredQuestions);
      responseRepository.find.mockResolvedValue(mockResponses as AssessmentResponse[]);

      await expect(
        service.validateCompletionOrThrow(mockAssessmentId),
      ).rejects.toThrow(BadRequestException);

      await expect(
        service.validateCompletionOrThrow(mockAssessmentId),
      ).rejects.toThrow('Assessment incomplete: 2 required questions not answered');
    });
  });

  describe('validateMultipleResponses', () => {
    it('should validate multiple responses in batch', async () => {
      const mockQuestion1: Partial<Question> = {
        question_key: 'Q1',
        question_type: QuestionType.RATING,
        required: true,
      };

      const mockQuestion2: Partial<Question> = {
        question_key: 'Q2',
        question_type: QuestionType.TEXT,
        required: true,
      };

      questionRepository.findOne
        .mockResolvedValueOnce(mockQuestion1 as Question)
        .mockResolvedValueOnce(mockQuestion2 as Question);

      const responses = [
        { questionId: 'Q1', answer: 3, notApplicable: false },
        { questionId: 'Q2', answer: 'Valid text', notApplicable: false },
      ];

      const results = await service.validateMultipleResponses(responses);

      expect(results).toHaveLength(2);
      expect(results[0].valid).toBe(true);
      expect(results[1].valid).toBe(true);
    });

    it('should return validation errors for invalid responses', async () => {
      const mockQuestion: Partial<Question> = {
        question_key: 'Q1',
        question_type: QuestionType.RATING,
        required: true,
      };

      questionRepository.findOne.mockResolvedValue(mockQuestion as Question);

      const responses = [
        { questionId: 'Q1', answer: 3, notApplicable: false },
        { questionId: 'Q1', answer: 10, notApplicable: false },
      ];

      const results = await service.validateMultipleResponses(responses);

      expect(results).toHaveLength(2);
      expect(results[0].valid).toBe(true);
      expect(results[1].valid).toBe(false);
      expect(results[1].errors).toBeDefined();
    });
  });
});
