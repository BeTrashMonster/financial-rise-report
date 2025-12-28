import { Test, TestingModule } from '@nestjs/testing';
import { AssessmentsController } from './assessments.controller';
import { AssessmentsService } from './assessments.service';
import { CreateAssessmentDto } from './dto/create-assessment.dto';
import { UpdateAssessmentDto } from './dto/update-assessment.dto';
import { AssessmentStatus } from './entities/assessment.entity';

describe('AssessmentsController', () => {
  let controller: AssessmentsController;
  let service: AssessmentsService;

  const mockUser = {
    id: 'user-123',
    email: 'consultant@example.com',
  };

  const mockAssessment = {
    id: 'assessment-123',
    consultant_id: 'user-123',
    client_name: 'John Smith',
    business_name: 'Smith Consulting LLC',
    client_email: 'john.smith@example.com',
    status: AssessmentStatus.DRAFT,
    progress: 0,
    notes: null,
    started_at: null,
    completed_at: null,
    created_at: new Date(),
    updated_at: new Date(),
    deleted_at: null,
  };

  const mockAssessmentsService = {
    create: jest.fn(),
    findAll: jest.fn(),
    findOne: jest.fn(),
    update: jest.fn(),
    remove: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AssessmentsController],
      providers: [
        {
          provide: AssessmentsService,
          useValue: mockAssessmentsService,
        },
      ],
    }).compile();

    controller = module.get<AssessmentsController>(AssessmentsController);
    service = module.get<AssessmentsService>(AssessmentsService);

    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('create', () => {
    it('should create a new assessment', async () => {
      const createDto: CreateAssessmentDto = {
        clientName: 'John Smith',
        businessName: 'Smith Consulting LLC',
        clientEmail: 'john.smith@example.com',
      };

      mockAssessmentsService.create.mockResolvedValue(mockAssessment);

      const result = await controller.create(createDto, mockUser);

      expect(service.create).toHaveBeenCalledWith(createDto, mockUser.id);
      expect(result).toEqual(mockAssessment);
    });
  });

  describe('findAll', () => {
    it('should return paginated assessments', async () => {
      const paginatedResponse = {
        data: [mockAssessment],
        meta: {
          page: 1,
          limit: 10,
          total: 1,
          totalPages: 1,
        },
      };

      mockAssessmentsService.findAll.mockResolvedValue(paginatedResponse);

      const result = await controller.findAll(mockUser);

      expect(service.findAll).toHaveBeenCalledWith(mockUser.id, {
        page: undefined,
        limit: undefined,
        status: undefined,
        search: undefined,
        sortBy: undefined,
        sortOrder: undefined,
      });
      expect(result).toEqual(paginatedResponse);
    });

    it('should apply filters when provided', async () => {
      const paginatedResponse = {
        data: [],
        meta: { page: 1, limit: 10, total: 0, totalPages: 0 },
      };

      mockAssessmentsService.findAll.mockResolvedValue(paginatedResponse);

      await controller.findAll(
        mockUser,
        1,
        10,
        AssessmentStatus.COMPLETED,
        'Smith',
        'updated_at',
        'DESC',
      );

      expect(service.findAll).toHaveBeenCalledWith(mockUser.id, {
        page: 1,
        limit: 10,
        status: AssessmentStatus.COMPLETED,
        search: 'Smith',
        sortBy: 'updated_at',
        sortOrder: 'DESC',
      });
    });
  });

  describe('findOne', () => {
    it('should return a single assessment', async () => {
      mockAssessmentsService.findOne.mockResolvedValue(mockAssessment);

      const result = await controller.findOne('assessment-123', mockUser);

      expect(service.findOne).toHaveBeenCalledWith('assessment-123', mockUser.id);
      expect(result).toEqual(mockAssessment);
    });
  });

  describe('update', () => {
    it('should update an assessment', async () => {
      const updateDto: UpdateAssessmentDto = {
        clientName: 'Jane Smith',
        status: AssessmentStatus.IN_PROGRESS,
      };

      const updatedAssessment = {
        ...mockAssessment,
        client_name: 'Jane Smith',
        status: AssessmentStatus.IN_PROGRESS,
      };

      mockAssessmentsService.update.mockResolvedValue(updatedAssessment);

      const result = await controller.update('assessment-123', updateDto, mockUser);

      expect(service.update).toHaveBeenCalledWith('assessment-123', updateDto, mockUser.id);
      expect(result.client_name).toBe('Jane Smith');
      expect(result.status).toBe(AssessmentStatus.IN_PROGRESS);
    });
  });

  describe('remove', () => {
    it('should soft delete an assessment', async () => {
      mockAssessmentsService.remove.mockResolvedValue(undefined);

      const result = await controller.remove('assessment-123', mockUser);

      expect(service.remove).toHaveBeenCalledWith('assessment-123', mockUser.id);
      expect(result).toBeUndefined();
    });
  });
});
