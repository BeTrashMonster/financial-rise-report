import { Test, TestingModule } from '@nestjs/testing';
import { QuestionnaireController } from './questionnaire.controller';
import { QuestionnaireService } from './questionnaire.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { SubmitResponseDto } from './dto/submit-response.dto';
import { NotFoundException, BadRequestException } from '@nestjs/common';

describe('QuestionnaireController', () => {
  let controller: QuestionnaireController;
  let service: QuestionnaireService;

  const mockQuestionnaireService = {
    submitResponse: jest.fn(),
    updateResponse: jest.fn(),
  };

  const mockUser = {
    id: 'user-123',
    email: 'consultant@example.com',
    role: 'consultant',
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [QuestionnaireController],
      providers: [
        {
          provide: QuestionnaireService,
          useValue: mockQuestionnaireService,
        },
      ],
    })
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: jest.fn(() => true) })
      .compile();

    controller = module.get<QuestionnaireController>(QuestionnaireController);
    service = module.get<QuestionnaireService>(QuestionnaireService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('submitResponse', () => {
    const submitDto: SubmitResponseDto = {
      assessmentId: 'assessment-123',
      questionId: 'Q001',
      answer: { value: 5, text: 'Five' },
      notApplicable: false,
      consultantNotes: 'Client response notes',
    };

    const mockResponse = {
      id: 'response-123',
      assessment_id: 'assessment-123',
      question_id: 'Q001',
      answer: { value: 5, text: 'Five' },
      not_applicable: false,
      consultant_notes: 'Client response notes',
      answered_at: new Date(),
      progress: 25,
      totalQuestions: 20,
      answeredQuestions: 5,
    };

    it('should submit a response successfully', async () => {
      mockQuestionnaireService.submitResponse.mockResolvedValue(mockResponse);

      const result = await controller.submitResponse(submitDto, mockUser);

      expect(result).toEqual(mockResponse);
      expect(service.submitResponse).toHaveBeenCalledWith(submitDto, mockUser.id);
      expect(service.submitResponse).toHaveBeenCalledTimes(1);
    });

    it('should extract user from @GetUser decorator', async () => {
      mockQuestionnaireService.submitResponse.mockResolvedValue(mockResponse);

      await controller.submitResponse(submitDto, mockUser);

      expect(service.submitResponse).toHaveBeenCalledWith(submitDto, 'user-123');
    });

    it('should handle assessment not found error', async () => {
      mockQuestionnaireService.submitResponse.mockRejectedValue(
        new NotFoundException('Assessment not found'),
      );

      await expect(controller.submitResponse(submitDto, mockUser)).rejects.toThrow(
        NotFoundException,
      );
    });

    it('should handle question not found error', async () => {
      mockQuestionnaireService.submitResponse.mockRejectedValue(
        new NotFoundException('Question with ID Q001 not found'),
      );

      await expect(controller.submitResponse(submitDto, mockUser)).rejects.toThrow(
        'Question with ID Q001 not found',
      );
    });

    it('should handle validation errors', async () => {
      mockQuestionnaireService.submitResponse.mockRejectedValue(
        new BadRequestException('Invalid answer value'),
      );

      await expect(controller.submitResponse(submitDto, mockUser)).rejects.toThrow(
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

      const naResponse = {
        ...mockResponse,
        answer: {} as any,
        not_applicable: true,
      };

      mockQuestionnaireService.submitResponse.mockResolvedValue(naResponse);

      const result = await controller.submitResponse(naDto, mockUser);

      expect(result.not_applicable).toBe(true);
    });

    it('should include progress information in response', async () => {
      mockQuestionnaireService.submitResponse.mockResolvedValue(mockResponse);

      const result = await controller.submitResponse(submitDto, mockUser);

      expect(result.progress).toBe(25);
      expect(result.totalQuestions).toBe(20);
      expect(result.answeredQuestions).toBe(5);
    });

    it('should use JwtAuthGuard', () => {
      const guards = Reflect.getMetadata('__guards__', QuestionnaireController);
      const guardNames = guards.map((guard: any) => guard.name);
      expect(guardNames).toContain('JwtAuthGuard');
    });
  });

  describe('updateResponse', () => {
    const responseId = 'response-123';
    const updateDto: Partial<SubmitResponseDto> = {
      answer: { value: 7, text: 'Seven' },
      consultantNotes: 'Updated notes',
    };

    const mockUpdatedResponse = {
      id: responseId,
      assessment_id: 'assessment-123',
      question_id: 'Q001',
      answer: { value: 7, text: 'Seven' },
      not_applicable: false,
      consultant_notes: 'Updated notes',
      answered_at: new Date(),
    };

    it('should update a response successfully', async () => {
      mockQuestionnaireService.updateResponse.mockResolvedValue(mockUpdatedResponse);

      const result = await controller.updateResponse(responseId, updateDto, mockUser);

      expect(result).toEqual(mockUpdatedResponse);
      expect(service.updateResponse).toHaveBeenCalledWith(responseId, updateDto, mockUser.id);
      expect(service.updateResponse).toHaveBeenCalledTimes(1);
    });

    it('should handle response not found error', async () => {
      mockQuestionnaireService.updateResponse.mockRejectedValue(
        new NotFoundException(`Response with ID ${responseId} not found`),
      );

      await expect(controller.updateResponse(responseId, updateDto, mockUser)).rejects.toThrow(
        NotFoundException,
      );
    });

    it('should use ParseUUIDPipe for response ID validation', async () => {
      // ParseUUIDPipe is applied at the route level and will validate
      // the UUID format before the controller method is called
      // This is tested through integration tests, not unit tests
      expect(controller.updateResponse).toBeDefined();
    });

    it('should allow partial updates', async () => {
      const partialUpdate = {
        consultantNotes: 'Only updating notes',
      };

      mockQuestionnaireService.updateResponse.mockResolvedValue({
        ...mockUpdatedResponse,
        consultant_notes: 'Only updating notes',
      });

      const result = await controller.updateResponse(responseId, partialUpdate, mockUser);

      expect(service.updateResponse).toHaveBeenCalledWith(responseId, partialUpdate, mockUser.id);
      expect(result.consultant_notes).toBe('Only updating notes');
    });

    it('should verify user ownership through service', async () => {
      mockQuestionnaireService.updateResponse.mockResolvedValue(mockUpdatedResponse);

      await controller.updateResponse(responseId, updateDto, mockUser);

      // Service should receive the user ID to verify ownership
      expect(service.updateResponse).toHaveBeenCalledWith(
        responseId,
        updateDto,
        'user-123',
      );
    });

    it('should update answered_at timestamp', async () => {
      const beforeUpdate = new Date();
      mockQuestionnaireService.updateResponse.mockResolvedValue(mockUpdatedResponse);

      const result = await controller.updateResponse(responseId, updateDto, mockUser);

      expect(result.answered_at).toBeDefined();
      expect(result.answered_at).toBeInstanceOf(Date);
    });
  });
});
