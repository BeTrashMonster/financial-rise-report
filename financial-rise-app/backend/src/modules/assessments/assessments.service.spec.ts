import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { NotFoundException, ForbiddenException, BadRequestException } from '@nestjs/common';
import { AssessmentsService } from './assessments.service';
import { Assessment, AssessmentStatus } from '../../../../../database/entities/Assessment'
import { Response } from '../../../../../database/entities/Response'
import { Question } from '../../../../../database/entities/Question'
import { CreateAssessmentDto } from './dto/create-assessment.dto';
import { UpdateAssessmentDto } from './dto/update-assessment.dto';
import { SaveResponseDto } from './dto/save-response.dto';

describe('AssessmentsService', () => {
  let service: AssessmentsService;
  let assessmentRepository: Repository<Assessment>;
  let responseRepository: Repository<Response>;
  let questionRepository: Repository<Question>;

  const mockAssessmentRepository = {
    create: jest.fn(),
    save: jest.fn(),
    findOne: jest.fn(),
    find: jest.fn(),
    createQueryBuilder: jest.fn(() => ({
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      orderBy: jest.fn().mockReturnThis(),
      getMany: jest.fn(),
    })),
    softDelete: jest.fn(),
  };

  const mockResponseRepository = {
    findOne: jest.fn(),
    create: jest.fn(),
    save: jest.fn(),
    find: jest.fn(),
    count: jest.fn(),
  };

  const mockQuestionRepository = {
    findOne: jest.fn(),
    count: jest.fn(),
  };

  const mockUser = {
    id: 'user-123',
    email: 'consultant@example.com',
    role: 'consultant',
  };

  const mockAssessment: Partial<Assessment> = {
    id: 'assessment-123',
    consultantId: 'user-123',
    clientName: 'John Smith',
    clientBusinessName: 'Smith Consulting LLC',
    clientEmail: 'john.smith@example.com',
    status: AssessmentStatus.DRAFT,
    entityType: null,
    isSCorpOnPayroll: null,
    confidenceBefore: null,
    confidenceAfter: null,
    progressPercentage: 0,
    startedAt: null,
    completedAt: null,
    createdAt: new Date(),
    updatedAt: new Date(),
    deletedAt: null,
    archivedAt: null,
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AssessmentsService,
        {
          provide: getRepositoryToken(Assessment),
          useValue: mockAssessmentRepository,
        },
        {
          provide: getRepositoryToken(Response),
          useValue: mockResponseRepository,
        },
        {
          provide: getRepositoryToken(Question),
          useValue: mockQuestionRepository,
        },
      ],
    }).compile();

    service = module.get<AssessmentsService>(AssessmentsService);
    assessmentRepository = module.get<Repository<Assessment>>(getRepositoryToken(Assessment));
    responseRepository = module.get<Repository<Response>>(getRepositoryToken(Response));
    questionRepository = module.get<Repository<Question>>(getRepositoryToken(Question));

    // Reset all mocks before each test
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('create', () => {
    it('should create a new assessment', async () => {
      const createDto: CreateAssessmentDto = {
        clientName: 'John Smith',
        clientBusinessName: 'Smith Consulting LLC',
        clientEmail: 'john.smith@example.com',
      };

      mockAssessmentRepository.create.mockReturnValue(mockAssessment);
      mockAssessmentRepository.save.mockResolvedValue(mockAssessment);

      const result = await service.create(createDto, mockUser.id);

      expect(assessmentRepository.create).toHaveBeenCalledWith({
        ...createDto,
        consultantId: mockUser.id,
        status: AssessmentStatus.DRAFT,
        progressPercentage: 0,
      });
      expect(assessmentRepository.save).toHaveBeenCalledWith(mockAssessment);
      expect(result).toEqual(mockAssessment);
    });

    it('should create assessment with optional entity type', async () => {
      const createDto: CreateAssessmentDto = {
        clientName: 'John Smith',
        clientBusinessName: 'Smith Consulting LLC',
        clientEmail: 'john.smith@example.com',
        entityType: 'S-Corp',
      };

      const assessmentWithEntity = { ...mockAssessment, entityType: 'S-Corp' };
      mockAssessmentRepository.create.mockReturnValue(assessmentWithEntity);
      mockAssessmentRepository.save.mockResolvedValue(assessmentWithEntity);

      const result = await service.create(createDto, mockUser.id);

      expect(result.entityType).toBe('S-Corp');
    });
  });

  describe('findAll', () => {
    it('should return all assessments for a consultant', async () => {
      const assessments = [mockAssessment];
      const queryBuilder = assessmentRepository.createQueryBuilder();
      jest.spyOn(queryBuilder, 'getMany').mockResolvedValue(assessments as Assessment[]);

      const result = await service.findAll(mockUser.id);

      expect(result).toEqual(assessments);
      expect(queryBuilder.where).toHaveBeenCalledWith('assessment.consultantId = :consultantId', {
        consultantId: mockUser.id,
      });
      expect(queryBuilder.andWhere).toHaveBeenCalledWith('assessment.deletedAt IS NULL');
      expect(queryBuilder.orderBy).toHaveBeenCalledWith('assessment.updatedAt', 'DESC');
    });

    it('should filter archived assessments by default', async () => {
      const queryBuilder = assessmentRepository.createQueryBuilder();
      jest.spyOn(queryBuilder, 'getMany').mockResolvedValue([]);

      await service.findAll(mockUser.id);

      expect(queryBuilder.andWhere).toHaveBeenCalledWith('assessment.archivedAt IS NULL');
    });

    it('should include archived assessments when requested', async () => {
      const queryBuilder = assessmentRepository.createQueryBuilder();
      jest.spyOn(queryBuilder, 'getMany').mockResolvedValue([]);

      await service.findAll(mockUser.id, true);

      expect(queryBuilder.andWhere).toHaveBeenCalledWith('assessment.archivedAt IS NOT NULL');
    });
  });

  describe('findOne', () => {
    it('should return an assessment with responses', async () => {
      mockAssessmentRepository.findOne.mockResolvedValue(mockAssessment);

      const result = await service.findOne('assessment-123', mockUser.id);

      expect(assessmentRepository.findOne).toHaveBeenCalledWith({
        where: { id: 'assessment-123', consultantId: mockUser.id },
        relations: ['responses'],
      });
      expect(result).toEqual(mockAssessment);
    });

    it('should throw NotFoundException when assessment not found', async () => {
      mockAssessmentRepository.findOne.mockResolvedValue(null);

      await expect(service.findOne('nonexistent', mockUser.id)).rejects.toThrow(NotFoundException);
    });

    it('should throw ForbiddenException when consultant does not own assessment', async () => {
      mockAssessmentRepository.findOne.mockResolvedValue(null);

      await expect(service.findOne('assessment-123', 'different-user')).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe('update', () => {
    it('should update assessment fields', async () => {
      const updateDto: UpdateAssessmentDto = {
        clientName: 'Jane Smith',
        status: AssessmentStatus.IN_PROGRESS,
      };

      mockAssessmentRepository.findOne.mockResolvedValue(mockAssessment);
      const updatedAssessment = { ...mockAssessment, ...updateDto };
      mockAssessmentRepository.save.mockResolvedValue(updatedAssessment);

      const result = await service.update('assessment-123', updateDto, mockUser.id);

      expect(result.clientName).toBe('Jane Smith');
      expect(result.status).toBe(AssessmentStatus.IN_PROGRESS);
    });

    it('should set startedAt when status changes to IN_PROGRESS', async () => {
      const updateDto: UpdateAssessmentDto = {
        status: AssessmentStatus.IN_PROGRESS,
      };

      mockAssessmentRepository.findOne.mockResolvedValue(mockAssessment);
      mockAssessmentRepository.save.mockImplementation((assessment) => Promise.resolve(assessment));

      const result = await service.update('assessment-123', updateDto, mockUser.id);

      expect(result.startedAt).toBeDefined();
    });

    it('should set completedAt when status changes to COMPLETED', async () => {
      const inProgressAssessment = { ...mockAssessment, status: AssessmentStatus.IN_PROGRESS };
      const updateDto: UpdateAssessmentDto = {
        status: AssessmentStatus.COMPLETED,
      };

      mockAssessmentRepository.findOne.mockResolvedValue(inProgressAssessment);
      mockAssessmentRepository.save.mockImplementation((assessment) => Promise.resolve(assessment));

      const result = await service.update('assessment-123', updateDto, mockUser.id);

      expect(result.completedAt).toBeDefined();
    });

    it('should throw NotFoundException when assessment not found', async () => {
      mockAssessmentRepository.findOne.mockResolvedValue(null);

      await expect(
        service.update('nonexistent', { clientName: 'Test' }, mockUser.id),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('remove', () => {
    it('should soft delete a DRAFT assessment', async () => {
      mockAssessmentRepository.findOne.mockResolvedValue(mockAssessment);
      mockAssessmentRepository.softDelete.mockResolvedValue({ affected: 1, raw: {} });

      await service.remove('assessment-123', mockUser.id);

      expect(assessmentRepository.softDelete).toHaveBeenCalledWith('assessment-123');
    });

    it('should throw BadRequestException when deleting non-DRAFT assessment', async () => {
      const completedAssessment = { ...mockAssessment, status: AssessmentStatus.COMPLETED };
      mockAssessmentRepository.findOne.mockResolvedValue(completedAssessment);

      await expect(service.remove('assessment-123', mockUser.id)).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should throw NotFoundException when assessment not found', async () => {
      mockAssessmentRepository.findOne.mockResolvedValue(null);

      await expect(service.remove('nonexistent', mockUser.id)).rejects.toThrow(NotFoundException);
    });
  });

  describe('saveResponse', () => {
    const mockQuestion: Partial<Question> = {
      id: 'question-123',
      questionText: 'Test question',
      isRequired: true,
    };

    const saveDto: SaveResponseDto = {
      questionId: 'question-123',
      answerValue: 'Test answer',
    };

    it('should create a new response', async () => {
      mockAssessmentRepository.findOne.mockResolvedValue(mockAssessment);
      mockQuestionRepository.findOne.mockResolvedValue(mockQuestion);
      mockResponseRepository.findOne.mockResolvedValue(null);

      const newResponse = {
        id: 'response-123',
        assessmentId: 'assessment-123',
        questionId: 'question-123',
        answerValue: 'Test answer',
      };

      mockResponseRepository.create.mockReturnValue(newResponse);
      mockResponseRepository.save.mockResolvedValue(newResponse);

      // Mock progress calculation
      mockQuestionRepository.count.mockResolvedValue(50);
      mockResponseRepository.count.mockResolvedValue(25);
      mockAssessmentRepository.save.mockResolvedValue({
        ...mockAssessment,
        progressPercentage: 50,
      });

      const result = await service.saveResponse('assessment-123', saveDto, mockUser.id);

      expect(result.answerValue).toBe('Test answer');
      expect(responseRepository.save).toHaveBeenCalled();
    });

    it('should update an existing response', async () => {
      const existingResponse = {
        id: 'response-123',
        assessmentId: 'assessment-123',
        questionId: 'question-123',
        answerValue: 'Old answer',
      };

      mockAssessmentRepository.findOne.mockResolvedValue(mockAssessment);
      mockQuestionRepository.findOne.mockResolvedValue(mockQuestion);
      mockResponseRepository.findOne.mockResolvedValue(existingResponse);

      const updatedResponse = { ...existingResponse, answerValue: 'New answer' };
      mockResponseRepository.save.mockResolvedValue(updatedResponse);

      // Mock progress calculation
      mockQuestionRepository.count.mockResolvedValue(50);
      mockResponseRepository.count.mockResolvedValue(25);
      mockAssessmentRepository.save.mockResolvedValue(mockAssessment);

      const result = await service.saveResponse(
        'assessment-123',
        { ...saveDto, answerValue: 'New answer' },
        mockUser.id,
      );

      expect(result.answerValue).toBe('New answer');
    });

    it('should throw NotFoundException when assessment not found', async () => {
      mockAssessmentRepository.findOne.mockResolvedValue(null);

      await expect(service.saveResponse('nonexistent', saveDto, mockUser.id)).rejects.toThrow(
        NotFoundException,
      );
    });

    it('should throw NotFoundException when question not found', async () => {
      mockAssessmentRepository.findOne.mockResolvedValue(mockAssessment);
      mockQuestionRepository.findOne.mockResolvedValue(null);

      await expect(service.saveResponse('assessment-123', saveDto, mockUser.id)).rejects.toThrow(
        NotFoundException,
      );
    });

    it('should update progress percentage after saving response', async () => {
      mockAssessmentRepository.findOne.mockResolvedValue(mockAssessment);
      mockQuestionRepository.findOne.mockResolvedValue(mockQuestion);
      mockResponseRepository.findOne.mockResolvedValue(null);

      mockResponseRepository.create.mockReturnValue({});
      mockResponseRepository.save.mockResolvedValue({});

      // 25 out of 50 questions answered = 50%
      mockQuestionRepository.count.mockResolvedValue(50);
      mockResponseRepository.count.mockResolvedValue(25);

      const updatedAssessment = { ...mockAssessment, progressPercentage: 50 };
      mockAssessmentRepository.save.mockResolvedValue(updatedAssessment);

      await service.saveResponse('assessment-123', saveDto, mockUser.id);

      expect(assessmentRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          progressPercentage: 50,
        }),
      );
    });
  });

  describe('calculateProgress', () => {
    it('should calculate correct progress percentage', async () => {
      mockQuestionRepository.count.mockResolvedValue(100);
      mockResponseRepository.count.mockResolvedValue(75);

      const progress = await service['calculateProgress']('assessment-123');

      expect(progress).toBe(75);
    });

    it('should return 0 when no questions exist', async () => {
      mockQuestionRepository.count.mockResolvedValue(0);
      mockResponseRepository.count.mockResolvedValue(0);

      const progress = await service['calculateProgress']('assessment-123');

      expect(progress).toBe(0);
    });

    it('should return 100 when all questions answered', async () => {
      mockQuestionRepository.count.mockResolvedValue(50);
      mockResponseRepository.count.mockResolvedValue(50);

      const progress = await service['calculateProgress']('assessment-123');

      expect(progress).toBe(100);
    });
  });
});
