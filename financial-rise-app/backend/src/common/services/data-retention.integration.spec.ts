import { Test, TestingModule } from '@nestjs/testing';
import { TypeOrmModule } from '@nestjs/typeorm';
import { DataRetentionService } from './data-retention.service';
import { Assessment, AssessmentStatus } from '../../modules/assessments/entities/assessment.entity';
import { Report } from '../../reports/entities/report.entity';
import { Repository } from 'typeorm';
import { getRepositoryToken } from '@nestjs/typeorm';

/**
 * Integration Tests for Data Retention Service
 *
 * These tests verify the actual database operations for GDPR compliance
 * using an in-memory SQLite database for isolation.
 *
 * Security Finding: HIGH-007 - Missing Data Retention Policy
 * Compliance: GDPR Article 5(1)(e) - Storage Limitation
 */
describe('DataRetentionService (Integration)', () => {
  let service: DataRetentionService;
  let assessmentRepository: Repository<Assessment>;
  let reportRepository: Repository<Report>;
  let module: TestingModule;

  beforeAll(async () => {
    module = await Test.createTestingModule({
      imports: [
        TypeOrmModule.forRoot({
          type: 'sqlite',
          database: ':memory:',
          entities: [Assessment, Report],
          synchronize: true,
          dropSchema: true,
        }),
        TypeOrmModule.forFeature([Assessment, Report]),
      ],
      providers: [DataRetentionService],
    }).compile();

    service = module.get<DataRetentionService>(DataRetentionService);
    assessmentRepository = module.get<Repository<Assessment>>(
      getRepositoryToken(Assessment),
    );
    reportRepository = module.get<Repository<Report>>(
      getRepositoryToken(Report),
    );
  });

  afterAll(async () => {
    await module.close();
  });

  beforeEach(async () => {
    // Clear all data before each test
    await assessmentRepository.query('DELETE FROM assessments');
    await reportRepository.query('DELETE FROM reports');
  });

  describe('enforceRetentionPolicies - Assessment Deletion', () => {
    it('should soft delete completed assessments older than 2 years', async () => {
      // Create old completed assessment (3 years ago)
      const threeYearsAgo = new Date();
      threeYearsAgo.setFullYear(threeYearsAgo.getFullYear() - 3);

      const oldAssessment = assessmentRepository.create({
        consultant_id: '123e4567-e89b-12d3-a456-426614174000',
        client_name: 'Old Client',
        business_name: 'Old Business',
        client_email: 'old@example.com',
        status: AssessmentStatus.COMPLETED,
        completed_at: threeYearsAgo,
      });
      await assessmentRepository.save(oldAssessment);

      // Create recent completed assessment (1 year ago)
      const oneYearAgo = new Date();
      oneYearAgo.setFullYear(oneYearAgo.getFullYear() - 1);

      const recentAssessment = assessmentRepository.create({
        consultant_id: '123e4567-e89b-12d3-a456-426614174000',
        client_name: 'Recent Client',
        business_name: 'Recent Business',
        client_email: 'recent@example.com',
        status: AssessmentStatus.COMPLETED,
        completed_at: oneYearAgo,
      });
      await assessmentRepository.save(recentAssessment);

      // Run retention policy
      await service.enforceRetentionPolicies();

      // Verify old assessment is soft-deleted
      const foundOld = await assessmentRepository.findOne({
        where: { id: oldAssessment.id },
        withDeleted: true,
      });
      expect(foundOld).toBeDefined();
      expect(foundOld!.deleted_at).toBeDefined();
      expect(foundOld!.deleted_at).not.toBeNull();

      // Verify recent assessment is NOT deleted
      const foundRecent = await assessmentRepository.findOne({
        where: { id: recentAssessment.id },
      });
      expect(foundRecent).toBeDefined();
      expect(foundRecent!.deleted_at).toBeNull();
    });

    it('should NOT delete non-completed assessments regardless of age', async () => {
      const threeYearsAgo = new Date();
      threeYearsAgo.setFullYear(threeYearsAgo.getFullYear() - 3);

      const oldDraftAssessment = assessmentRepository.create({
        consultant_id: '123e4567-e89b-12d3-a456-426614174000',
        client_name: 'Old Draft Client',
        business_name: 'Old Draft Business',
        client_email: 'olddraft@example.com',
        status: AssessmentStatus.DRAFT,
        created_at: threeYearsAgo,
      });
      await assessmentRepository.save(oldDraftAssessment);

      await service.enforceRetentionPolicies();

      const found = await assessmentRepository.findOne({
        where: { id: oldDraftAssessment.id },
        withDeleted: true,
      });
      expect(found).toBeDefined();
      expect(found!.deleted_at).toBeNull();
    });

    it('should maintain audit trail with soft delete', async () => {
      const threeYearsAgo = new Date();
      threeYearsAgo.setFullYear(threeYearsAgo.getFullYear() - 3);

      const oldAssessment = assessmentRepository.create({
        consultant_id: '123e4567-e89b-12d3-a456-426614174000',
        client_name: 'Audit Trail Client',
        business_name: 'Audit Trail Business',
        client_email: 'audit@example.com',
        status: AssessmentStatus.COMPLETED,
        completed_at: threeYearsAgo,
      });
      await assessmentRepository.save(oldAssessment);

      await service.enforceRetentionPolicies();

      // Verify data still exists with withDeleted: true
      const foundWithDeleted = await assessmentRepository.findOne({
        where: { id: oldAssessment.id },
        withDeleted: true,
      });
      expect(foundWithDeleted).toBeDefined();
      expect(foundWithDeleted!.client_name).toBe('Audit Trail Client');

      // Verify data is NOT returned in normal queries
      const foundNormal = await assessmentRepository.findOne({
        where: { id: oldAssessment.id },
      });
      expect(foundNormal).toBeNull();
    });
  });

  describe('enforceRetentionPolicies - Report Deletion', () => {
    it('should hard delete expired reports', async () => {
      // Create expired report
      const yesterday = new Date();
      yesterday.setDate(yesterday.getDate() - 1);

      const expiredReport = reportRepository.create({
        assessmentId: '123e4567-e89b-12d3-a456-426614174000',
        reportType: 'client',
        status: 'completed',
        expiresAt: yesterday,
      });
      await reportRepository.save(expiredReport);

      // Create non-expired report
      const tomorrow = new Date();
      tomorrow.setDate(tomorrow.getDate() + 1);

      const activeReport = reportRepository.create({
        assessmentId: '123e4567-e89b-12d3-a456-426614174001',
        reportType: 'consultant',
        status: 'completed',
        expiresAt: tomorrow,
      });
      await reportRepository.save(activeReport);

      await service.enforceRetentionPolicies();

      // Verify expired report is hard-deleted (completely removed)
      const foundExpired = await reportRepository.findOne({
        where: { id: expiredReport.id },
      });
      expect(foundExpired).toBeNull();

      // Verify active report still exists
      const foundActive = await reportRepository.findOne({
        where: { id: activeReport.id },
      });
      expect(foundActive).toBeDefined();
    });

    it('should NOT delete reports without expiration date', async () => {
      const reportWithoutExpiry = reportRepository.create({
        assessmentId: '123e4567-e89b-12d3-a456-426614174000',
        reportType: 'client',
        status: 'completed',
        expiresAt: null,
      });
      await reportRepository.save(reportWithoutExpiry);

      await service.enforceRetentionPolicies();

      const found = await reportRepository.findOne({
        where: { id: reportWithoutExpiry.id },
      });
      expect(found).toBeDefined();
    });
  });

  describe('getRetentionStats', () => {
    it('should return accurate statistics about data eligible for deletion', async () => {
      // Create 3 old completed assessments
      const threeYearsAgo = new Date();
      threeYearsAgo.setFullYear(threeYearsAgo.getFullYear() - 3);

      for (let i = 0; i < 3; i++) {
        const oldAssessment = assessmentRepository.create({
          consultant_id: '123e4567-e89b-12d3-a456-426614174000',
          client_name: `Old Client ${i}`,
          business_name: `Old Business ${i}`,
          client_email: `old${i}@example.com`,
          status: AssessmentStatus.COMPLETED,
          completed_at: threeYearsAgo,
        });
        await assessmentRepository.save(oldAssessment);
      }

      // Create 2 expired reports
      const yesterday = new Date();
      yesterday.setDate(yesterday.getDate() - 1);

      for (let i = 0; i < 2; i++) {
        const expiredReport = reportRepository.create({
          assessmentId: `123e4567-e89b-12d3-a456-42661417400${i}`,
          reportType: 'client',
          status: 'completed',
          expiresAt: yesterday,
        });
        await reportRepository.save(expiredReport);
      }

      const stats = await service.getRetentionStats();

      expect(stats.assessmentsEligibleForDeletion).toBe(3);
      expect(stats.reportsEligibleForDeletion).toBe(2);
      expect(stats.timestamp).toBeInstanceOf(Date);
    });
  });

  describe('purgeOldData - Manual Purge', () => {
    it('should manually purge old data and return counts', async () => {
      const threeYearsAgo = new Date();
      threeYearsAgo.setFullYear(threeYearsAgo.getFullYear() - 3);

      const oldAssessment = assessmentRepository.create({
        consultant_id: '123e4567-e89b-12d3-a456-426614174000',
        client_name: 'Manual Purge Client',
        business_name: 'Manual Purge Business',
        client_email: 'purge@example.com',
        status: AssessmentStatus.COMPLETED,
        completed_at: threeYearsAgo,
      });
      await assessmentRepository.save(oldAssessment);

      const yesterday = new Date();
      yesterday.setDate(yesterday.getDate() - 1);

      const expiredReport = reportRepository.create({
        assessmentId: '123e4567-e89b-12d3-a456-426614174000',
        reportType: 'client',
        status: 'completed',
        expiresAt: yesterday,
      });
      await reportRepository.save(expiredReport);

      const result = await service.purgeOldData();

      expect(result.assessmentsDeleted).toBe(1);
      expect(result.reportsDeleted).toBe(1);
      expect(result.timestamp).toBeInstanceOf(Date);
    });
  });

  describe('GDPR Compliance Verification', () => {
    it('should comply with 2-year retention policy', async () => {
      const config = service.getRetentionConfig();
      expect(config.assessmentRetentionYears).toBe(2);
    });

    it('should run scheduled task daily at 2 AM', () => {
      const config = service.getRetentionConfig();
      expect(config.cronSchedule).toBe('0 2 * * *');
    });

    it('should have auto-cleanup enabled', () => {
      const config = service.getRetentionConfig();
      expect(config.enabledAutoCleanup).toBe(true);
    });
  });
});
