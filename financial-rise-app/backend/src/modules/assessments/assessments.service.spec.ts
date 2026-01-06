import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { NotFoundException, ForbiddenException, BadRequestException } from '@nestjs/common';
import { AssessmentsService } from './assessments.service';
import { Assessment, AssessmentStatus } from './entities/assessment.entity';
import { AssessmentResponse } from './entities/assessment-response.entity';
import { Question } from '../questions/entities/question.entity';
import { CreateAssessmentDto } from './dto/create-assessment.dto';
import { UpdateAssessmentDto } from './dto/update-assessment.dto';
import { AlgorithmsService } from '../algorithms/algorithms.service';

describe('AssessmentsService', () => {
  let service: AssessmentsService;
  let assessmentRepository: Repository<Assessment>;
  let responseRepository: Repository<AssessmentResponse>;
  let questionRepository: Repository<Question>;

  const mockQueryBuilder = {
    where: jest.fn().mockReturnThis(),
    andWhere: jest.fn().mockReturnThis(),
    orderBy: jest.fn().mockReturnThis(),
    skip: jest.fn().mockReturnThis(),
    take: jest.fn().mockReturnThis(),
    getMany: jest.fn().mockResolvedValue([]),
    getCount: jest.fn().mockResolvedValue(0),
  };

  const mockAssessmentRepository = {
    create: jest.fn(),
    save: jest.fn(),
    findOne: jest.fn(),
    find: jest.fn(),
    createQueryBuilder: jest.fn(() => mockQueryBuilder),
    softDelete: jest.fn(),
    update: jest.fn(),
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

  const mockAlgorithmsService = {
    calculateAll: jest.fn(),
    getDISCProfile: jest.fn(),
    getPhaseResults: jest.fn(),
  };

  const mockUser = {
    id: 'user-123',
    email: 'consultant@example.com',
    role: 'consultant',
  };

  const mockAssessment: Partial<Assessment> = {
    id: 'assessment-123',
    consultant_id: 'user-123',
    client_name: 'John Smith',
    business_name: 'Smith Consulting LLC',
    client_email: 'john.smith@example.com',
    status: AssessmentStatus.DRAFT,
    notes: null,
    progress: 0,
    started_at: null,
    completed_at: null,
    created_at: new Date(),
    updated_at: new Date(),
    deleted_at: null,
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
          provide: getRepositoryToken(AssessmentResponse),
          useValue: mockResponseRepository,
        },
        {
          provide: getRepositoryToken(Question),
          useValue: mockQuestionRepository,
        },
        {
          provide: AlgorithmsService,
          useValue: mockAlgorithmsService,
        },
      ],
    }).compile();

    service = module.get<AssessmentsService>(AssessmentsService);
    assessmentRepository = module.get<Repository<Assessment>>(getRepositoryToken(Assessment));
    responseRepository = module.get<Repository<AssessmentResponse>>(getRepositoryToken(AssessmentResponse));
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
        businessName: 'Smith Consulting LLC',
        clientEmail: 'john.smith@example.com',
      };

      mockAssessmentRepository.create.mockReturnValue(mockAssessment);
      mockAssessmentRepository.save.mockResolvedValue(mockAssessment);

      const result = await service.create(createDto, mockUser.id);

      expect(assessmentRepository.create).toHaveBeenCalledWith({
        client_name: 'John Smith',
        business_name: 'Smith Consulting LLC',
        client_email: 'john.smith@example.com',
        notes: null,
        consultant_id: mockUser.id,
        status: AssessmentStatus.DRAFT,
        progress: 0,
      });
      expect(assessmentRepository.save).toHaveBeenCalledWith(mockAssessment);
      expect(result).toEqual(mockAssessment);
    });

    it('should create assessment with notes', async () => {
      const createDto: CreateAssessmentDto = {
        clientName: 'John Smith',
        businessName: 'Smith Consulting LLC',
        clientEmail: 'john.smith@example.com',
        notes: 'Initial consultation notes',
      };

      const assessmentWithNotes = { ...mockAssessment, notes: 'Initial consultation notes' };
      mockAssessmentRepository.create.mockReturnValue(assessmentWithNotes);
      mockAssessmentRepository.save.mockResolvedValue(assessmentWithNotes);

      const result = await service.create(createDto, mockUser.id);

      expect(result.notes).toBe('Initial consultation notes');
    });
  });

  describe('findAll', () => {
    it('should return all assessments for a consultant with pagination', async () => {
      const assessments = [mockAssessment];
      mockQueryBuilder.getMany.mockResolvedValue(assessments as Assessment[]);
      mockQueryBuilder.getCount.mockResolvedValue(1);

      const result = await service.findAll(mockUser.id);

      expect(result).toEqual({
        data: assessments,
        meta: {
          page: 1,
          limit: 10,
          total: 1,
          totalPages: 1,
        },
      });
      expect(mockQueryBuilder.where).toHaveBeenCalledWith('assessment.consultant_id = :consultantId', {
        consultantId: mockUser.id,
      });
      expect(mockQueryBuilder.andWhere).toHaveBeenCalledWith('assessment.deleted_at IS NULL');
      expect(mockQueryBuilder.orderBy).toHaveBeenCalledWith('assessment.updated_at', 'DESC');
    });

    it('should filter deleted assessments by default', async () => {
      mockQueryBuilder.getMany.mockResolvedValue([]);
      mockQueryBuilder.getCount.mockResolvedValue(0);

      const result = await service.findAll(mockUser.id);

      expect(result.data).toEqual([]);
      expect(mockQueryBuilder.andWhere).toHaveBeenCalled();
    });

    it('should filter by status when provided', async () => {
      mockQueryBuilder.getMany.mockResolvedValue([]);
      mockQueryBuilder.getCount.mockResolvedValue(0);

      const result = await service.findAll(mockUser.id, { status: AssessmentStatus.COMPLETED });

      expect(result.data).toEqual([]);
      expect(mockQueryBuilder.andWhere).toHaveBeenCalled();
    });
  });

  describe('findOne', () => {
    it('should return an assessment with responses', async () => {
      mockAssessmentRepository.findOne.mockResolvedValue(mockAssessment);

      const result = await service.findOne('assessment-123', mockUser.id);

      expect(assessmentRepository.findOne).toHaveBeenCalledWith({
        where: { id: 'assessment-123', consultant_id: mockUser.id },
        relations: ['responses', 'disc_profiles', 'phase_results'],
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
      const updatedAssessment = {
        ...mockAssessment,
        client_name: 'Jane Smith',
        status: AssessmentStatus.IN_PROGRESS,
      };
      mockAssessmentRepository.save.mockResolvedValue(updatedAssessment);

      const result = await service.update('assessment-123', updateDto, mockUser.id);

      expect(result.client_name).toBe('Jane Smith');
      expect(result.status).toBe(AssessmentStatus.IN_PROGRESS);
    });

    it('should set startedAt when status changes to IN_PROGRESS', async () => {
      const updateDto: UpdateAssessmentDto = {
        status: AssessmentStatus.IN_PROGRESS,
      };

      mockAssessmentRepository.findOne.mockResolvedValue(mockAssessment);
      mockAssessmentRepository.save.mockImplementation((assessment) => Promise.resolve(assessment));

      const result = await service.update('assessment-123', updateDto, mockUser.id);

      expect(result.started_at).toBeDefined();
    });

    it('should set completedAt when status changes to COMPLETED', async () => {
      const inProgressAssessment = { ...mockAssessment, status: AssessmentStatus.IN_PROGRESS };
      const updateDto: UpdateAssessmentDto = {
        status: AssessmentStatus.COMPLETED,
      };

      mockAssessmentRepository.findOne.mockResolvedValue(inProgressAssessment);
      mockAssessmentRepository.save.mockImplementation((assessment) => Promise.resolve(assessment));

      const result = await service.update('assessment-123', updateDto, mockUser.id);

      expect(result.completed_at).toBeDefined();
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


    it('should throw NotFoundException when assessment not found', async () => {
      mockAssessmentRepository.findOne.mockResolvedValue(null);

      await expect(service.remove('nonexistent', mockUser.id)).rejects.toThrow(NotFoundException);
    });
  });

  describe('updateProgress', () => {
    it('should calculate and update correct progress percentage', async () => {
      mockQuestionRepository.count.mockResolvedValue(100);
      mockResponseRepository.count.mockResolvedValue(75);
      mockAssessmentRepository.update.mockResolvedValue({ affected: 1, raw: {}, generatedMaps: [] });

      const progress = await service.updateProgress('assessment-123');

      expect(progress).toBe(75);
      expect(mockAssessmentRepository.update).toHaveBeenCalledWith('assessment-123', { progress: 75 });
    });

    it('should return 0 when no questions exist', async () => {
      mockQuestionRepository.count.mockResolvedValue(0);
      mockResponseRepository.count.mockResolvedValue(0);
      mockAssessmentRepository.update.mockResolvedValue({ affected: 1, raw: {}, generatedMaps: [] });

      const progress = await service.updateProgress('assessment-123');

      expect(progress).toBe(0);
    });

    it('should return 100 when all questions answered', async () => {
      mockQuestionRepository.count.mockResolvedValue(50);
      mockResponseRepository.count.mockResolvedValue(50);
      mockAssessmentRepository.update.mockResolvedValue({ affected: 1, raw: {}, generatedMaps: [] });

      const progress = await service.updateProgress('assessment-123');

      expect(progress).toBe(100);
      expect(mockAssessmentRepository.update).toHaveBeenCalledWith('assessment-123', { progress: 100 });
    });
  });
});
