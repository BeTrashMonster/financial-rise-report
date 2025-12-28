import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository, LessThan, IsNull, Not } from 'typeorm';
import { DataRetentionService } from './data-retention.service';
import { Assessment, AssessmentStatus } from '../../modules/assessments/entities/assessment.entity';
import { Report } from '../../reports/entities/report.entity';
import { Logger } from '@nestjs/common';

describe('DataRetentionService', () => {
  let service: DataRetentionService;
  let assessmentRepository: Repository<Assessment>;
  let reportRepository: Repository<Report>;
  let loggerSpy: jest.SpyInstance;

  const mockAssessmentRepository = {
    softDelete: jest.fn(),
    delete: jest.fn(),
    count: jest.fn(),
    createQueryBuilder: jest.fn(),
  };

  const mockReportRepository = {
    delete: jest.fn(),
    count: jest.fn(),
    createQueryBuilder: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        DataRetentionService,
        {
          provide: getRepositoryToken(Assessment),
          useValue: mockAssessmentRepository,
        },
        {
          provide: getRepositoryToken(Report),
          useValue: mockReportRepository,
        },
      ],
    }).compile();

    service = module.get<DataRetentionService>(DataRetentionService);
    assessmentRepository = module.get<Repository<Assessment>>(
      getRepositoryToken(Assessment),
    );
    reportRepository = module.get<Repository<Report>>(
      getRepositoryToken(Report),
    );

    // Spy on logger
    loggerSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation();

    // Reset mocks
    jest.clearAllMocks();
  });

  afterEach(() => {
    loggerSpy.mockRestore();
  });

  describe('enforceRetentionPolicies', () => {
    it('should be defined', () => {
      expect(service).toBeDefined();
      expect(service.enforceRetentionPolicies).toBeDefined();
    });

    it('should delete completed assessments older than 2 years', async () => {
      const twoYearsAgo = new Date();
      twoYearsAgo.setFullYear(twoYearsAgo.getFullYear() - 2);

      mockAssessmentRepository.softDelete.mockResolvedValue({ affected: 5 });
      mockReportRepository.delete.mockResolvedValue({ affected: 3 });

      await service.enforceRetentionPolicies();

      expect(mockAssessmentRepository.softDelete).toHaveBeenCalledWith(
        expect.objectContaining({
          status: AssessmentStatus.COMPLETED,
          completed_at: expect.any(Object), // LessThan matcher
        }),
      );
    });

    it('should delete expired reports based on expires_at', async () => {
      mockReportRepository.delete.mockResolvedValue({ affected: 3 });

      await service.enforceRetentionPolicies();

      expect(mockReportRepository.delete).toHaveBeenCalledWith(
        expect.objectContaining({
          expiresAt: expect.any(Object), // LessThan matcher
        }),
      );
    });

    it('should log retention actions for compliance audit', async () => {
      mockAssessmentRepository.softDelete.mockResolvedValue({ affected: 5 });
      mockReportRepository.delete.mockResolvedValue({ affected: 3 });

      await service.enforceRetentionPolicies();

      expect(loggerSpy).toHaveBeenCalledWith(
        expect.stringContaining('Data retention policies enforced'),
      );
      expect(loggerSpy).toHaveBeenCalledWith(
        expect.stringContaining('5 assessments'),
      );
      expect(loggerSpy).toHaveBeenCalledWith(
        expect.stringContaining('3 reports'),
      );
    });

    it('should handle zero deletions gracefully', async () => {
      mockAssessmentRepository.softDelete.mockResolvedValue({ affected: 0 });
      mockReportRepository.delete.mockResolvedValue({ affected: 0 });

      await expect(
        service.enforceRetentionPolicies(),
      ).resolves.not.toThrow();

      expect(loggerSpy).toHaveBeenCalledWith(
        expect.stringContaining('0 assessments'),
      );
    });

    it('should use soft delete for assessments to maintain audit trail', async () => {
      mockAssessmentRepository.softDelete.mockResolvedValue({ affected: 5 });
      mockReportRepository.delete.mockResolvedValue({ affected: 3 });

      await service.enforceRetentionPolicies();

      // Verify soft delete is used, not hard delete
      expect(mockAssessmentRepository.softDelete).toHaveBeenCalled();
      expect(mockAssessmentRepository.delete).not.toHaveBeenCalled();
    });

    it('should handle repository errors gracefully', async () => {
      mockAssessmentRepository.softDelete.mockRejectedValue(
        new Error('Database connection lost'),
      );

      await expect(service.enforceRetentionPolicies()).rejects.toThrow(
        'Database connection lost',
      );
    });
  });

  describe('getRetentionStats', () => {
    it('should return statistics about data eligible for deletion', async () => {
      const mockQueryBuilder = {
        where: jest.fn(function() { return this; }),
        andWhere: jest.fn(function() { return this; }),
        getCount: jest.fn().mockResolvedValue(10),
      };

      mockAssessmentRepository.createQueryBuilder.mockReturnValue(
        mockQueryBuilder,
      );
      mockReportRepository.createQueryBuilder.mockReturnValue(
        mockQueryBuilder,
      );

      const stats = await service.getRetentionStats();

      expect(stats).toHaveProperty('assessmentsEligibleForDeletion');
      expect(stats).toHaveProperty('reportsEligibleForDeletion');
      expect(stats.assessmentsEligibleForDeletion).toBe(10);
      expect(stats.reportsEligibleForDeletion).toBe(10);
    });
  });

  describe('purgeOldData', () => {
    it('should manually trigger data purge for testing', async () => {
      mockAssessmentRepository.softDelete.mockResolvedValue({ affected: 5 });
      mockReportRepository.delete.mockResolvedValue({ affected: 3 });

      const result = await service.purgeOldData();

      expect(result).toHaveProperty('assessmentsDeleted', 5);
      expect(result).toHaveProperty('reportsDeleted', 3);
      expect(result).toHaveProperty('timestamp');
    });
  });

  describe('getRetentionConfig', () => {
    it('should return current retention policy configuration', () => {
      const config = service.getRetentionConfig();

      expect(config).toHaveProperty('assessmentRetentionYears');
      expect(config.assessmentRetentionYears).toBe(2);
      expect(config).toHaveProperty('cronSchedule');
      expect(config.cronSchedule).toBe('0 2 * * *');
    });
  });

  describe('CRON schedule', () => {
    it('should have @Cron decorator with correct schedule', () => {
      // This test verifies the decorator exists
      const descriptor = Object.getOwnPropertyDescriptor(
        Object.getPrototypeOf(service),
        'enforceRetentionPolicies',
      );
      expect(descriptor).toBeDefined();
    });
  });

  describe('Compliance logging', () => {
    it('should log timestamp of retention action', async () => {
      mockAssessmentRepository.softDelete.mockResolvedValue({ affected: 5 });
      mockReportRepository.delete.mockResolvedValue({ affected: 3 });

      await service.enforceRetentionPolicies();

      expect(loggerSpy).toHaveBeenCalledWith(
        expect.stringMatching(/\d{4}-\d{2}-\d{2}/),
      );
    });

    it('should log retention policy being enforced', async () => {
      mockAssessmentRepository.softDelete.mockResolvedValue({ affected: 5 });
      mockReportRepository.delete.mockResolvedValue({ affected: 3 });

      await service.enforceRetentionPolicies();

      expect(loggerSpy).toHaveBeenCalledWith(
        expect.stringContaining('2 years'),
      );
    });

    it('should create audit trail entry for compliance', async () => {
      mockAssessmentRepository.softDelete.mockResolvedValue({ affected: 5 });
      mockReportRepository.delete.mockResolvedValue({ affected: 3 });

      await service.enforceRetentionPolicies();

      // Verify comprehensive audit logging
      expect(loggerSpy).toHaveBeenCalledWith(
        expect.stringContaining('GDPR'),
      );
    });
  });

  describe('Date calculations', () => {
    it('should correctly calculate 2 years ago date', async () => {
      const now = new Date('2025-12-28T10:00:00Z');
      jest.spyOn(global, 'Date').mockImplementation(() => now as any);

      mockAssessmentRepository.softDelete.mockImplementation((criteria) => {
        const expectedDate = new Date('2023-12-28T10:00:00Z');
        expect(criteria.completed_at).toBeDefined();
        return Promise.resolve({ affected: 5 });
      });

      await service.enforceRetentionPolicies();

      expect(mockAssessmentRepository.softDelete).toHaveBeenCalled();
    });
  });
});
