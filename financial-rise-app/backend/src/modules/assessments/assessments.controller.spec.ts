import { Test, TestingModule } from '@nestjs/testing';
import { AssessmentsController } from './assessments.controller';
import { AssessmentsService } from './assessments.service';
import { CreateAssessmentDto } from './dto/create-assessment.dto';
import { UpdateAssessmentDto } from './dto/update-assessment.dto';
import { SaveResponseDto } from './dto/save-response.dto';
import { AssessmentStatus } from '../../../../../database/entities/Assessment'

describe('AssessmentsController', () => {
  let controller: AssessmentsController;
  let service: AssessmentsService;

  const mockAssessmentsService = {
    create: jest.fn(),
    findAll: jest.fn(),
    findOne: jest.fn(),
    update: jest.fn(),
    remove: jest.fn(),
    archive: jest.fn(),
    restore: jest.fn(),
    saveResponse: jest.fn(),
    getResponses: jest.fn(),
  };

  const mockUser = {
    id: 'user-123',
    email: 'consultant@example.com',
    role: 'consultant',
  };

  const mockAssessment = {
    id: 'assessment-123',
    consultantId: 'user-123',
    clientName: 'John Smith',
    clientBusinessName: 'Smith Consulting LLC',
    clientEmail: 'john.smith@example.com',
    status: AssessmentStatus.DRAFT,
    progressPercentage: 0,
    createdAt: new Date(),
    updatedAt: new Date(),
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
        clientBusinessName: 'Smith Consulting LLC',
        clientEmail: 'john.smith@example.com',
      };

      mockAssessmentsService.create.mockResolvedValue(mockAssessment);

      const result = await controller.create(createDto, mockUser);

      expect(service.create).toHaveBeenCalledWith(createDto, mockUser.id);
      expect(result).toEqual(mockAssessment);
    });
  });

  describe('findAll', () => {
    it('should return all assessments for consultant', async () => {
      const assessments = [mockAssessment];
      mockAssessmentsService.findAll.mockResolvedValue(assessments);

      const result = await controller.findAll(mockUser, false);

      expect(service.findAll).toHaveBeenCalledWith(mockUser.id, false);
      expect(result).toEqual(assessments);
    });

    it('should return archived assessments when archived=true', async () => {
      mockAssessmentsService.findAll.mockResolvedValue([]);

      await controller.findAll(mockUser, true);

      expect(service.findAll).toHaveBeenCalledWith(mockUser.id, true);
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
      };

      const updatedAssessment = { ...mockAssessment, clientName: 'Jane Smith' };
      mockAssessmentsService.update.mockResolvedValue(updatedAssessment);

      const result = await controller.update('assessment-123', updateDto, mockUser);

      expect(service.update).toHaveBeenCalledWith('assessment-123', updateDto, mockUser.id);
      expect(result.clientName).toBe('Jane Smith');
    });
  });

  describe('remove', () => {
    it('should delete a draft assessment', async () => {
      mockAssessmentsService.remove.mockResolvedValue(undefined);

      await controller.remove('assessment-123', mockUser);

      expect(service.remove).toHaveBeenCalledWith('assessment-123', mockUser.id);
    });
  });

  describe('archive', () => {
    it('should archive an assessment', async () => {
      const archivedAssessment = { ...mockAssessment, archivedAt: new Date() };
      mockAssessmentsService.archive.mockResolvedValue(archivedAssessment);

      const result = await controller.archive('assessment-123', mockUser);

      expect(service.archive).toHaveBeenCalledWith('assessment-123', mockUser.id);
      expect(result.archivedAt).toBeDefined();
    });
  });

  describe('restore', () => {
    it('should restore an archived assessment', async () => {
      mockAssessmentsService.restore.mockResolvedValue(mockAssessment);

      const result = await controller.restore('assessment-123', mockUser);

      expect(service.restore).toHaveBeenCalledWith('assessment-123', mockUser.id);
      expect(result).toEqual(mockAssessment);
    });
  });

  describe('saveResponse', () => {
    it('should save a response', async () => {
      const saveDto: SaveResponseDto = {
        questionId: 'question-123',
        answerValue: 'Test answer',
      };

      const mockResponse = {
        id: 'response-123',
        assessmentId: 'assessment-123',
        questionId: 'question-123',
        answerValue: 'Test answer',
      };

      mockAssessmentsService.saveResponse.mockResolvedValue(mockResponse);

      const result = await controller.saveResponse('assessment-123', saveDto, mockUser);

      expect(service.saveResponse).toHaveBeenCalledWith('assessment-123', saveDto, mockUser.id);
      expect(result).toEqual(mockResponse);
    });
  });

  describe('getResponses', () => {
    it('should return all responses for an assessment', async () => {
      const mockResponses = [
        {
          id: 'response-1',
          questionId: 'question-1',
          answerValue: 'Answer 1',
        },
        {
          id: 'response-2',
          questionId: 'question-2',
          answerValue: 'Answer 2',
        },
      ];

      mockAssessmentsService.getResponses.mockResolvedValue(mockResponses);

      const result = await controller.getResponses('assessment-123', mockUser);

      expect(service.getResponses).toHaveBeenCalledWith('assessment-123', mockUser.id);
      expect(result).toEqual(mockResponses);
    });
  });
});
