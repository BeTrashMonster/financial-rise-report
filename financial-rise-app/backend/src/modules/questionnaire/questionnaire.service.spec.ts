import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { NotFoundException, BadRequestException } from '@nestjs/common';
import { QuestionnaireService } from './questionnaire.service';
import { AssessmentResponse } from '../assessments/entities/assessment-response.entity';
import { Assessment } from '../assessments/entities/assessment.entity';
import { Question } from '../questions/entities/question.entity';
import { AssessmentsService } from '../assessments/assessments.service';
import { ValidationService } from '../assessments/services/validation.service';
import { ProgressService } from '../assessments/services/progress.service';
import { SubmitResponseDto } from './dto/submit-response.dto';

describe('QuestionnaireService', () => {
  let service: QuestionnaireService;
  let responseRepository: Repository<AssessmentResponse>;
  let assessmentRepository: Repository<Assessment>;
  let questionRepository: Repository<Question>;
  let assessmentsService: AssessmentsService;
  let validationService: ValidationService;
  let progressService: ProgressService;

  const mockResponseRepository = {
    findOne: jest.fn(),
    create: jest.fn(),
    save: jest.fn(),
  };

  const mockAssessmentRepository = {
    update: jest.fn(),
  };

  const mockQuestionRepository = {
    findOne: jest.fn(),
  };

  const mockAssessmentsService = {
    findOne: jest.fn(),
  };

  const mockValidationService = {
    validateResponseOrThrow: jest.fn(),
  };

  const mockProgressService = {
    calculateProgress: jest.fn(),
  };

  const mockAssessment = {
    id: 'assessment-123',
    consultant_id: 'consultant-123',
    client_name: 'Test Client',
    status: 'in_progress',
    progress: 0,
  };

  const mockQuestion = {
    id: 'q-uuid-123',
    question_key: 'Q001',
    question_text: 'Test question?',
    category: 'stabilize',
    phase: 'stabilize',
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        QuestionnaireService,
        {
          provide: getRepositoryToken(AssessmentResponse),
          useValue: mockResponseRepository,
        },
        {
          provide: getRepositoryToken(Assessment),
          useValue: mockAssessmentRepository,
        },
        {
          provide: getRepositoryToken(Question),
          useValue: mockQuestionRepository,
        },
        {
          provide: AssessmentsService,
          useValue: mockAssessmentsService,
        },
        {
          provide: ValidationService,
          useValue: mockValidationService,
        },
        {
          provide: ProgressService,
          useValue: mockProgressService,
        },
      ],
    }).compile();

    service = module.get<QuestionnaireService>(QuestionnaireService);
    responseRepository = module.get<Repository<AssessmentResponse>>(
      getRepositoryToken(AssessmentResponse),
    );
    assessmentRepository = module.get<Repository<Assessment>>(getRepositoryToken(Assessment));
    questionRepository = module.get<Repository<Question>>(getRepositoryToken(Question));
    assessmentsService = module.get<AssessmentsService>(AssessmentsService);
    validationService = module.get<ValidationService>(ValidationService);
    progressService = module.get<ProgressService>(ProgressService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('submitResponse', () => {
    const submitDto: SubmitResponseDto = {
      assessmentId: 'assessment-123',
      questionId: 'Q001',
      answer: { value: 7, text: 'Seven' },
      notApplicable: false,
      consultantNotes: 'Test notes',
    };

    const consultantId = 'consultant-123';

    beforeEach(() => {
      mockAssessmentsService.findOne.mockResolvedValue(mockAssessment);
      mockQuestionRepository.findOne.mockResolvedValue(mockQuestion);
      mockValidationService.validateResponseOrThrow.mockResolvedValue(undefined);
      mockProgressService.calculateProgress.mockResolvedValue({
        progress: 25,
        totalQuestions: 20,
        answeredQuestions: 5,
      });
    });

    it('should submit a new response successfully', async () => {
      mockResponseRepository.findOne.mockResolvedValue(null); // No existing response

      const newResponse = {
        id: 'response-123',
        assessment_id: submitDto.assessmentId,
        question_id: submitDto.questionId,
        answer: submitDto.answer,
        not_applicable: false,
        consultant_notes: submitDto.consultantNotes,
        answered_at: new Date(),
      };

      mockResponseRepository.create.mockReturnValue(newResponse);
      mockResponseRepository.save.mockResolvedValue(newResponse);

      const result = await service.submitResponse(submitDto, consultantId);

      expect(assessmentsService.findOne).toHaveBeenCalledWith(submitDto.assessmentId, consultantId);
      expect(questionRepository.findOne).toHaveBeenCalledWith({
        where: { question_key: submitDto.questionId },
      });
      expect(validationService.validateResponseOrThrow).toHaveBeenCalledWith(
        submitDto.questionId,
        submitDto.answer,
        false,
      );
      expect(responseRepository.create).toHaveBeenCalled();
      expect(responseRepository.save).toHaveBeenCalled();
      expect(result.progress).toBe(25);
    });

    it('should update existing response', async () => {
      const existingResponse = {
        id: 'response-123',
        assessment_id: submitDto.assessmentId,
        question_id: submitDto.questionId,
        answer: { value: 5, text: 'Five' },
        not_applicable: false,
        consultant_notes: 'Old notes',
        answered_at: new Date('2024-01-01'),
      };

      mockResponseRepository.findOne.mockResolvedValue(existingResponse);
      mockResponseRepository.save.mockResolvedValue({
        ...existingResponse,
        answer: submitDto.answer,
        consultant_notes: submitDto.consultantNotes,
      });

      const result = await service.submitResponse(submitDto, consultantId);

      expect(responseRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          answer: { value: 7, text: 'Seven' },
          consultant_notes: 'Test notes',
        }),
      );
      expect(result.answer).toEqual({ value: 7, text: 'Seven' });
    });

    it('should throw NotFoundException if assessment not found', async () => {
      mockAssessmentsService.findOne.mockRejectedValue(
        new NotFoundException('Assessment not found'),
      );

      await expect(service.submitResponse(submitDto, consultantId)).rejects.toThrow(
        NotFoundException,
      );
    });

    it('should throw NotFoundException if question not found', async () => {
      mockQuestionRepository.findOne.mockResolvedValue(null);

      await expect(service.submitResponse(submitDto, consultantId)).rejects.toThrow(
        NotFoundException,
      );
      await expect(service.submitResponse(submitDto, consultantId)).rejects.toThrow(
        `Question with ID ${submitDto.questionId} not found`,
      );
    });

    it('should validate response before saving', async () => {
      mockResponseRepository.findOne.mockResolvedValue(null);
      mockResponseRepository.create.mockReturnValue({});
      mockResponseRepository.save.mockResolvedValue({});

      await service.submitResponse(submitDto, consultantId);

      expect(validationService.validateResponseOrThrow).toHaveBeenCalledWith(
        submitDto.questionId,
        submitDto.answer,
        false,
      );
    });

    it('should throw if validation fails', async () => {
      mockValidationService.validateResponseOrThrow.mockRejectedValue(
        new BadRequestException('Invalid answer value'),
      );

      await expect(service.submitResponse(submitDto, consultantId)).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should handle N/A responses', async () => {
      const naDto: SubmitResponseDto = {
        assessmentId: submitDto.assessmentId,
        questionId: submitDto.questionId,
        answer: {} as any, // Empty object for N/A
        notApplicable: true,
      };

      mockResponseRepository.findOne.mockResolvedValue(null);
      mockResponseRepository.create.mockReturnValue({});
      mockResponseRepository.save.mockResolvedValue({
        answer: {} as any,
        not_applicable: true,
      });

      await service.submitResponse(naDto, consultantId);

      expect(validationService.validateResponseOrThrow).toHaveBeenCalledWith(
        naDto.questionId,
        {} as any,
        true,
      );
    });

    it('should calculate and update progress', async () => {
      mockResponseRepository.findOne.mockResolvedValue(null);
      mockResponseRepository.create.mockReturnValue({});
      mockResponseRepository.save.mockResolvedValue({});

      await service.submitResponse(submitDto, consultantId);

      expect(progressService.calculateProgress).toHaveBeenCalledWith(submitDto.assessmentId);
      expect(assessmentRepository.update).toHaveBeenCalledWith(submitDto.assessmentId, {
        progress: 25,
      });
    });

    it('should return progress information', async () => {
      mockResponseRepository.findOne.mockResolvedValue(null);
      mockResponseRepository.create.mockReturnValue({});
      mockResponseRepository.save.mockResolvedValue({ id: 'response-123' });

      const result = await service.submitResponse(submitDto, consultantId);

      expect(result.progress).toBe(25);
      expect(result.totalQuestions).toBe(20);
      expect(result.answeredQuestions).toBe(5);
    });

    it('should update answered_at timestamp', async () => {
      const oldTimestamp = new Date('2024-01-01');
      const existingResponse = {
        id: 'response-123',
        assessment_id: submitDto.assessmentId,
        question_id: submitDto.questionId,
        answer: 5,
        answered_at: oldTimestamp,
      };

      mockResponseRepository.findOne.mockResolvedValue(existingResponse);
      mockResponseRepository.save.mockImplementation((response) => Promise.resolve(response));

      const beforeSubmit = Date.now();
      await service.submitResponse(submitDto, consultantId);
      const afterSubmit = Date.now();

      const savedResponse = mockResponseRepository.save.mock.calls[0][0];
      const answeredAtTime = savedResponse.answered_at.getTime();

      expect(answeredAtTime).toBeGreaterThanOrEqual(beforeSubmit);
      expect(answeredAtTime).toBeLessThanOrEqual(afterSubmit);
    });

    it('should handle optional consultant notes', async () => {
      const dtoWithoutNotes = { ...submitDto, consultantNotes: undefined };

      mockResponseRepository.findOne.mockResolvedValue(null);
      mockResponseRepository.create.mockReturnValue({});
      mockResponseRepository.save.mockResolvedValue({});

      await service.submitResponse(dtoWithoutNotes, consultantId);

      const createCall = mockResponseRepository.create.mock.calls[0][0];
      expect(createCall.consultant_notes).toBeNull();
    });

    it('should verify assessment belongs to consultant', async () => {
      await service.submitResponse(submitDto, consultantId);

      expect(assessmentsService.findOne).toHaveBeenCalledWith(
        submitDto.assessmentId,
        consultantId,
      );
    });
  });

  describe('updateResponse', () => {
    const responseId = 'response-123';
    const consultantId = 'consultant-123';
    const updateDto: Partial<SubmitResponseDto> = {
      answer: { value: 8, text: 'Eight' },
      consultantNotes: 'Updated notes',
    };

    const existingResponse = {
      id: responseId,
      assessment_id: 'assessment-123',
      question_id: 'Q001',
      answer: { value: 5, text: 'Five' },
      not_applicable: false,
      consultant_notes: 'Old notes',
      answered_at: new Date('2024-01-01'),
    };

    beforeEach(() => {
      mockAssessmentsService.findOne.mockResolvedValue(mockAssessment);
    });

    it('should update an existing response', async () => {
      mockResponseRepository.findOne.mockResolvedValue(existingResponse);
      mockResponseRepository.save.mockResolvedValue({
        ...existingResponse,
        answer: updateDto.answer,
        consultant_notes: updateDto.consultantNotes,
        answered_at: new Date(),
      });

      const result = await service.updateResponse(responseId, updateDto, consultantId);

      expect(responseRepository.findOne).toHaveBeenCalledWith({
        where: { id: responseId },
        relations: ['assessment'],
      });
      expect(result.answer).toEqual({ value: 8, text: 'Eight' });
      expect(result.consultant_notes).toBe('Updated notes');
    });

    it('should throw NotFoundException if response not found', async () => {
      mockResponseRepository.findOne.mockResolvedValue(null);

      await expect(service.updateResponse(responseId, updateDto, consultantId)).rejects.toThrow(
        NotFoundException,
      );
      await expect(service.updateResponse(responseId, updateDto, consultantId)).rejects.toThrow(
        `Response with ID ${responseId} not found`,
      );
    });

    it('should verify assessment belongs to consultant', async () => {
      mockResponseRepository.findOne.mockResolvedValue(existingResponse);
      mockResponseRepository.save.mockResolvedValue(existingResponse);

      await service.updateResponse(responseId, updateDto, consultantId);

      expect(assessmentsService.findOne).toHaveBeenCalledWith(
        existingResponse.assessment_id,
        consultantId,
      );
    });

    it('should allow partial updates', async () => {
      const partialUpdate = { consultantNotes: 'Only notes updated' };

      // Create a fresh copy to avoid mutation from previous tests
      const freshResponse = {
        id: responseId,
        assessment_id: 'assessment-123',
        question_id: 'Q001',
        answer: { value: 5, text: 'Five' },
        not_applicable: false,
        consultant_notes: 'Old notes',
        answered_at: new Date('2024-01-01'),
      };

      mockResponseRepository.findOne.mockResolvedValue(freshResponse);
      mockResponseRepository.save.mockImplementation((response) => Promise.resolve(response));

      await service.updateResponse(responseId, partialUpdate, consultantId);

      const savedResponse = mockResponseRepository.save.mock.calls[0][0];
      expect(savedResponse.consultant_notes).toBe('Only notes updated');
      expect(savedResponse.answer).toEqual({ value: 5, text: 'Five' }); // Original value preserved
    });

    it('should update answered_at timestamp', async () => {
      mockResponseRepository.findOne.mockResolvedValue(existingResponse);
      mockResponseRepository.save.mockImplementation((response) => Promise.resolve(response));

      const beforeUpdate = Date.now();
      await service.updateResponse(responseId, updateDto, consultantId);
      const afterUpdate = Date.now();

      const savedResponse = mockResponseRepository.save.mock.calls[0][0];
      const answeredAtTime = savedResponse.answered_at.getTime();

      expect(answeredAtTime).toBeGreaterThanOrEqual(beforeUpdate);
      expect(answeredAtTime).toBeLessThanOrEqual(afterUpdate);
    });

    it('should update answer when provided', async () => {
      mockResponseRepository.findOne.mockResolvedValue(existingResponse);
      mockResponseRepository.save.mockImplementation((response) => Promise.resolve(response));

      await service.updateResponse(responseId, { answer: { value: 10, text: 'Ten' } }, consultantId);

      const savedResponse = mockResponseRepository.save.mock.calls[0][0];
      expect(savedResponse.answer).toEqual({ value: 10, text: 'Ten' });
    });

    it('should update notApplicable flag when provided', async () => {
      mockResponseRepository.findOne.mockResolvedValue(existingResponse);
      mockResponseRepository.save.mockImplementation((response) => Promise.resolve(response));

      await service.updateResponse(responseId, { notApplicable: true }, consultantId);

      const savedResponse = mockResponseRepository.save.mock.calls[0][0];
      expect(savedResponse.not_applicable).toBe(true);
    });

    it('should not update fields when undefined in dto', async () => {
      mockResponseRepository.findOne.mockResolvedValue(existingResponse);
      mockResponseRepository.save.mockImplementation((response) => Promise.resolve(response));

      await service.updateResponse(responseId, {}, consultantId);

      const savedResponse = mockResponseRepository.save.mock.calls[0][0];
      expect(savedResponse.answer).toBe(existingResponse.answer);
      expect(savedResponse.consultant_notes).toBe(existingResponse.consultant_notes);
      expect(savedResponse.not_applicable).toBe(existingResponse.not_applicable);
    });

    it('should handle consultant notes being set to undefined', async () => {
      mockResponseRepository.findOne.mockResolvedValue(existingResponse);
      mockResponseRepository.save.mockImplementation((response) => Promise.resolve(response));

      await service.updateResponse(responseId, { consultantNotes: undefined }, consultantId);

      const savedResponse = mockResponseRepository.save.mock.calls[0][0];
      expect(savedResponse.consultant_notes).toBe(existingResponse.consultant_notes);
    });
  });
});
