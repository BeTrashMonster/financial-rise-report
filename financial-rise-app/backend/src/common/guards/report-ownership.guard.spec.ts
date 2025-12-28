import { Test, TestingModule } from '@nestjs/testing';
import { ExecutionContext, ForbiddenException, NotFoundException } from '@nestjs/common';
import { ReportOwnershipGuard } from './report-ownership.guard';
import { ReportGenerationService } from '../../reports/services/report-generation.service';

describe('ReportOwnershipGuard', () => {
  let guard: ReportOwnershipGuard;
  let reportService: jest.Mocked<ReportGenerationService>;

  const mockReportService = {
    getReportStatus: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ReportOwnershipGuard,
        {
          provide: ReportGenerationService,
          useValue: mockReportService,
        },
      ],
    }).compile();

    guard = module.get<ReportOwnershipGuard>(ReportOwnershipGuard);
    reportService = module.get(ReportGenerationService);
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
      it('should allow access when user owns the report assessment', async () => {
        const userId = 'user-123';
        const reportId = 'report-456';
        const assessmentId = 'assessment-789';

        const mockReport = {
          id: reportId,
          assessmentId: assessmentId,
          consultantId: userId,
          status: 'completed',
        };

        reportService.getReportStatus.mockResolvedValue(mockReport as any);

        const context = mockExecutionContext(
          { id: reportId },
          { id: userId, role: 'consultant' },
        );

        const result = await guard.canActivate(context);

        expect(result).toBe(true);
        expect(reportService.getReportStatus).toHaveBeenCalledWith(reportId);
      });

      it('should allow access for admin users even if they do not own the report', async () => {
        const adminId = 'admin-123';
        const reportId = 'report-456';
        const ownerId = 'owner-789';

        const mockReport = {
          id: reportId,
          assessmentId: 'assessment-789',
          consultantId: ownerId,
          status: 'completed',
        };

        reportService.getReportStatus.mockResolvedValue(mockReport as any);

        const context = mockExecutionContext(
          { id: reportId },
          { id: adminId, role: 'admin' },
        );

        const result = await guard.canActivate(context);

        expect(result).toBe(true);
      });
    });

    describe('IDOR attack prevention', () => {
      it('should throw ForbiddenException when user tries to access another user report', async () => {
        const userId = 'user-123';
        const reportId = 'report-456';
        const differentUserId = 'user-999';

        const mockReport = {
          id: reportId,
          assessmentId: 'assessment-789',
          consultantId: differentUserId,
          status: 'completed',
        };

        reportService.getReportStatus.mockResolvedValue(mockReport as any);

        const context = mockExecutionContext(
          { id: reportId },
          { id: userId, role: 'consultant' },
        );

        await expect(guard.canActivate(context)).rejects.toThrow(ForbiddenException);
        await expect(guard.canActivate(context)).rejects.toThrow(
          'You do not have permission to access this report',
        );
      });

      it('should throw NotFoundException when report does not exist', async () => {
        const userId = 'user-123';
        const reportId = 'nonexistent-report';

        reportService.getReportStatus.mockResolvedValue(null);

        const context = mockExecutionContext(
          { id: reportId },
          { id: userId, role: 'consultant' },
        );

        await expect(guard.canActivate(context)).rejects.toThrow(NotFoundException);
        await expect(guard.canActivate(context)).rejects.toThrow(
          `Report with ID ${reportId} not found`,
        );
      });

      it('should prevent access when reportId is manipulated in URL', async () => {
        const userId = 'user-123';
        const maliciousId = 'someone-elses-report';

        reportService.getReportStatus.mockResolvedValue(null);

        const context = mockExecutionContext(
          { id: maliciousId },
          { id: userId, role: 'consultant' },
        );

        await expect(guard.canActivate(context)).rejects.toThrow(NotFoundException);
      });
    });

    describe('edge cases', () => {
      it('should handle missing user object gracefully', async () => {
        const reportId = 'report-456';

        const context = mockExecutionContext({ id: reportId }, null);

        await expect(guard.canActivate(context)).rejects.toThrow();
      });

      it('should handle missing report ID in params', async () => {
        const userId = 'user-123';

        const context = mockExecutionContext({}, { id: userId, role: 'consultant' });

        await expect(guard.canActivate(context)).rejects.toThrow();
      });

      it('should handle malformed UUID in report ID', async () => {
        const userId = 'user-123';
        const malformedId = 'not-a-uuid';

        reportService.getReportStatus.mockResolvedValue(null);

        const context = mockExecutionContext(
          { id: malformedId },
          { id: userId, role: 'consultant' },
        );

        await expect(guard.canActivate(context)).rejects.toThrow(NotFoundException);
      });
    });

    describe('multiple report IDs access pattern', () => {
      it('should validate each report access independently', async () => {
        const userId = 'user-123';
        const reportId1 = 'report-1';
        const reportId2 = 'report-2';
        const differentUserId = 'user-999';

        // First report - owned by user
        const mockReport1 = {
          id: reportId1,
          assessmentId: 'assessment-1',
          consultantId: userId,
        };
        reportService.getReportStatus.mockResolvedValueOnce(mockReport1 as any);

        const context1 = mockExecutionContext(
          { id: reportId1 },
          { id: userId, role: 'consultant' },
        );

        await expect(guard.canActivate(context1)).resolves.toBe(true);

        // Second report - not owned by user
        const mockReport2 = {
          id: reportId2,
          assessmentId: 'assessment-2',
          consultantId: differentUserId,
        };
        reportService.getReportStatus.mockResolvedValueOnce(mockReport2 as any);

        const context2 = mockExecutionContext(
          { id: reportId2 },
          { id: userId, role: 'consultant' },
        );

        await expect(guard.canActivate(context2)).rejects.toThrow(ForbiddenException);
      });
    });

    describe('service integration', () => {
      it('should rely on service layer for report retrieval', async () => {
        const userId = 'user-123';
        const reportId = 'report-456';

        const mockReport = {
          id: reportId,
          assessmentId: 'assessment-789',
          consultantId: userId,
        };

        reportService.getReportStatus.mockResolvedValue(mockReport as any);

        const context = mockExecutionContext(
          { id: reportId },
          { id: userId, role: 'consultant' },
        );

        await guard.canActivate(context);

        expect(reportService.getReportStatus).toHaveBeenCalledWith(reportId);
        expect(reportService.getReportStatus).toHaveBeenCalledTimes(1);
      });

      it('should propagate service exceptions correctly', async () => {
        const userId = 'user-123';
        const reportId = 'report-456';
        const serviceError = new Error('Database connection failed');

        reportService.getReportStatus.mockRejectedValue(serviceError);

        const context = mockExecutionContext(
          { id: reportId },
          { id: userId, role: 'consultant' },
        );

        await expect(guard.canActivate(context)).rejects.toThrow('Database connection failed');
      });
    });

    describe('report status scenarios', () => {
      it('should allow access to reports in generating status if owned by user', async () => {
        const userId = 'user-123';
        const reportId = 'report-456';

        const mockReport = {
          id: reportId,
          assessmentId: 'assessment-789',
          consultantId: userId,
          status: 'generating',
        };

        reportService.getReportStatus.mockResolvedValue(mockReport as any);

        const context = mockExecutionContext(
          { id: reportId },
          { id: userId, role: 'consultant' },
        );

        await expect(guard.canActivate(context)).resolves.toBe(true);
      });

      it('should allow access to reports in failed status if owned by user', async () => {
        const userId = 'user-123';
        const reportId = 'report-456';

        const mockReport = {
          id: reportId,
          assessmentId: 'assessment-789',
          consultantId: userId,
          status: 'failed',
          error: 'PDF generation error',
        };

        reportService.getReportStatus.mockResolvedValue(mockReport as any);

        const context = mockExecutionContext(
          { id: reportId },
          { id: userId, role: 'consultant' },
        );

        await expect(guard.canActivate(context)).resolves.toBe(true);
      });
    });
  });
});
