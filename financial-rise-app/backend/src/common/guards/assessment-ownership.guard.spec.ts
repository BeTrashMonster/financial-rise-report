import { Test, TestingModule } from '@nestjs/testing';
import { ExecutionContext, ForbiddenException, NotFoundException } from '@nestjs/common';
import { AssessmentOwnershipGuard } from './assessment-ownership.guard';
import { AssessmentsService } from '../../modules/assessments/assessments.service';

describe('AssessmentOwnershipGuard', () => {
  let guard: AssessmentOwnershipGuard;
  let assessmentsService: jest.Mocked<AssessmentsService>;

  const mockAssessmentsService = {
    findOne: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AssessmentOwnershipGuard,
        {
          provide: AssessmentsService,
          useValue: mockAssessmentsService,
        },
      ],
    }).compile();

    guard = module.get<AssessmentOwnershipGuard>(AssessmentOwnershipGuard);
    assessmentsService = module.get(AssessmentsService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('canActivate', () => {
    const mockExecutionContext = (params: any, user: any): ExecutionContext => {
      return {
        switchToHttp: () => ({
          getRequest: () => ({
            user,
            params,
          }),
        }),
        getHandler: jest.fn(),
        getClass: jest.fn(),
      } as unknown as ExecutionContext;
    };

    describe('successful authorization', () => {
      it('should allow access when user owns the assessment', async () => {
        const userId = 'user-123';
        const assessmentId = 'assessment-456';
        const mockAssessment = {
          id: assessmentId,
          consultant_id: userId,
          client_name: 'Test Client',
        };

        assessmentsService.findOne.mockResolvedValue(mockAssessment as any);

        const context = mockExecutionContext(
          { id: assessmentId },
          { id: userId, role: 'consultant' },
        );

        const result = await guard.canActivate(context);

        expect(result).toBe(true);
        expect(assessmentsService.findOne).toHaveBeenCalledWith(assessmentId, userId);
      });

      it('should allow access for admin users even if they do not own the assessment', async () => {
        const adminId = 'admin-123';
        const assessmentId = 'assessment-456';
        const ownerId = 'owner-789';
        const mockAssessment = {
          id: assessmentId,
          consultant_id: ownerId,
          client_name: 'Test Client',
        };

        // Admin should be able to access any assessment
        assessmentsService.findOne.mockResolvedValue(mockAssessment as any);

        const context = mockExecutionContext(
          { id: assessmentId },
          { id: adminId, role: 'admin' },
        );

        const result = await guard.canActivate(context);

        expect(result).toBe(true);
      });
    });

    describe('IDOR attack prevention', () => {
      it('should throw ForbiddenException when user tries to access another user assessment', async () => {
        const userId = 'user-123';
        const assessmentId = 'assessment-456';

        // Assessment belongs to different user
        assessmentsService.findOne.mockRejectedValue(
          new NotFoundException('Assessment with ID assessment-456 not found'),
        );

        const context = mockExecutionContext(
          { id: assessmentId },
          { id: userId, role: 'consultant' },
        );

        await expect(guard.canActivate(context)).rejects.toThrow(NotFoundException);
        expect(assessmentsService.findOne).toHaveBeenCalledWith(assessmentId, userId);
      });

      it('should throw NotFoundException when assessment does not exist', async () => {
        const userId = 'user-123';
        const assessmentId = 'nonexistent-assessment';

        assessmentsService.findOne.mockRejectedValue(
          new NotFoundException(`Assessment with ID ${assessmentId} not found`),
        );

        const context = mockExecutionContext(
          { id: assessmentId },
          { id: userId, role: 'consultant' },
        );

        await expect(guard.canActivate(context)).rejects.toThrow(NotFoundException);
      });

      it('should prevent access when assessmentId is manipulated in URL', async () => {
        const userId = 'user-123';
        const maliciousId = 'someone-elses-assessment';

        assessmentsService.findOne.mockRejectedValue(
          new NotFoundException(`Assessment with ID ${maliciousId} not found`),
        );

        const context = mockExecutionContext(
          { id: maliciousId },
          { id: userId, role: 'consultant' },
        );

        await expect(guard.canActivate(context)).rejects.toThrow(NotFoundException);
      });
    });

    describe('edge cases', () => {
      it('should handle missing user object gracefully', async () => {
        const assessmentId = 'assessment-456';

        const context = mockExecutionContext({ id: assessmentId }, null);

        await expect(guard.canActivate(context)).rejects.toThrow();
      });

      it('should handle missing assessment ID in params', async () => {
        const userId = 'user-123';

        const context = mockExecutionContext({}, { id: userId, role: 'consultant' });

        await expect(guard.canActivate(context)).rejects.toThrow();
      });

      it('should handle malformed UUID in assessment ID', async () => {
        const userId = 'user-123';
        const malformedId = 'not-a-uuid';

        assessmentsService.findOne.mockRejectedValue(
          new NotFoundException(`Assessment with ID ${malformedId} not found`),
        );

        const context = mockExecutionContext(
          { id: malformedId },
          { id: userId, role: 'consultant' },
        );

        await expect(guard.canActivate(context)).rejects.toThrow(NotFoundException);
      });
    });

    describe('multiple assessment IDs access pattern', () => {
      it('should validate each assessment access independently', async () => {
        const userId = 'user-123';
        const assessmentId1 = 'assessment-1';
        const assessmentId2 = 'assessment-2';

        const mockAssessment1 = {
          id: assessmentId1,
          consultant_id: userId,
        };

        // First assessment - owned by user
        assessmentsService.findOne.mockResolvedValueOnce(mockAssessment1 as any);

        const context1 = mockExecutionContext(
          { id: assessmentId1 },
          { id: userId, role: 'consultant' },
        );

        await expect(guard.canActivate(context1)).resolves.toBe(true);

        // Second assessment - not owned by user
        assessmentsService.findOne.mockRejectedValueOnce(
          new NotFoundException(`Assessment with ID ${assessmentId2} not found`),
        );

        const context2 = mockExecutionContext(
          { id: assessmentId2 },
          { id: userId, role: 'consultant' },
        );

        await expect(guard.canActivate(context2)).rejects.toThrow(NotFoundException);
      });
    });

    describe('service integration', () => {
      it('should rely on service layer for ownership validation', async () => {
        const userId = 'user-123';
        const assessmentId = 'assessment-456';
        const mockAssessment = {
          id: assessmentId,
          consultant_id: userId,
        };

        assessmentsService.findOne.mockResolvedValue(mockAssessment as any);

        const context = mockExecutionContext(
          { id: assessmentId },
          { id: userId, role: 'consultant' },
        );

        await guard.canActivate(context);

        // Verify service is called with correct parameters
        expect(assessmentsService.findOne).toHaveBeenCalledWith(assessmentId, userId);
        expect(assessmentsService.findOne).toHaveBeenCalledTimes(1);
      });

      it('should propagate service exceptions correctly', async () => {
        const userId = 'user-123';
        const assessmentId = 'assessment-456';
        const serviceError = new Error('Database connection failed');

        assessmentsService.findOne.mockRejectedValue(serviceError);

        const context = mockExecutionContext(
          { id: assessmentId },
          { id: userId, role: 'consultant' },
        );

        await expect(guard.canActivate(context)).rejects.toThrow('Database connection failed');
      });
    });
  });
});
