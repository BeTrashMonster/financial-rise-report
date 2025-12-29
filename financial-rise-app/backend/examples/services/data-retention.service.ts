import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, LessThan } from 'typeorm';
import { Cron, CronExpression } from '@nestjs/schedule';
import { Assessment, AssessmentStatus } from '../../modules/assessments/entities/assessment.entity';
import { Report } from '../../reports/entities/report.entity';

export interface RetentionStats {
  assessmentsEligibleForDeletion: number;
  reportsEligibleForDeletion: number;
  timestamp: Date;
}

export interface PurgeResult {
  assessmentsDeleted: number;
  reportsDeleted: number;
  timestamp: Date;
}

export interface RetentionConfig {
  assessmentRetentionYears: number;
  cronSchedule: string;
  enabledAutoCleanup: boolean;
}

/**
 * DataRetentionService - Implements GDPR-compliant data retention policies
 *
 * This service automatically deletes old data to comply with:
 * - GDPR Article 5(1)(e) - Storage Limitation
 * - CCPA data minimization requirements
 *
 * Key Features:
 * - Scheduled automatic cleanup (daily at 2 AM)
 * - Soft delete for assessments (maintains audit trail)
 * - Hard delete for expired reports
 * - Comprehensive compliance logging
 * - Manual purge capability for testing
 *
 * Security Finding: HIGH-007 - Missing Data Retention Policy
 * Reference: SECURITY-AUDIT-REPORT.md Lines 1024-1077
 */
@Injectable()
export class DataRetentionService {
  private readonly logger = new Logger(DataRetentionService.name);
  private readonly RETENTION_YEARS = 2;
  private readonly CRON_SCHEDULE = '0 2 * * *'; // Daily at 2 AM

  constructor(
    @InjectRepository(Assessment)
    private readonly assessmentRepository: Repository<Assessment>,
    @InjectRepository(Report)
    private readonly reportRepository: Repository<Report>,
  ) {}

  /**
   * Scheduled job that runs daily at 2 AM to enforce retention policies
   *
   * GDPR Compliance: Automatically deletes data beyond retention period
   */
  @Cron('0 2 * * *')
  async enforceRetentionPolicies(): Promise<void> {
    const startTime = new Date();
    this.logger.log(
      `[GDPR COMPLIANCE] Starting data retention enforcement at ${startTime.toISOString()}`,
    );

    try {
      // Calculate retention date (2 years ago)
      const retentionDate = new Date();
      retentionDate.setFullYear(retentionDate.getFullYear() - this.RETENTION_YEARS);

      // Soft delete completed assessments older than 2 years
      // Uses soft delete to maintain audit trail
      const assessmentResult = await this.assessmentRepository.softDelete({
        status: AssessmentStatus.COMPLETED,
        completed_at: LessThan(retentionDate),
      });

      const assessmentsDeleted = assessmentResult.affected || 0;

      // Hard delete expired reports
      const reportResult = await this.reportRepository.delete({
        expiresAt: LessThan(new Date()),
      });

      const reportsDeleted = reportResult.affected || 0;

      // Compliance audit logging
      this.logger.log(
        `[GDPR COMPLIANCE] Data retention policies enforced successfully`,
      );
      this.logger.log(
        `[AUDIT TRAIL] Retention policy: ${this.RETENTION_YEARS} years for completed assessments`,
      );
      this.logger.log(
        `[AUDIT TRAIL] ${assessmentsDeleted} assessments soft-deleted (older than ${retentionDate.toISOString()})`,
      );
      this.logger.log(
        `[AUDIT TRAIL] ${reportsDeleted} reports hard-deleted (expired)`,
      );
      this.logger.log(
        `[AUDIT TRAIL] Retention enforcement completed at ${new Date().toISOString()}`,
      );
    } catch (error) {
      this.logger.error(
        `[GDPR COMPLIANCE ERROR] Data retention enforcement failed: ${error.message}`,
        error.stack,
      );
      throw error;
    }
  }

  /**
   * Get statistics about data eligible for deletion
   *
   * Useful for compliance reporting and monitoring
   */
  async getRetentionStats(): Promise<RetentionStats> {
    const retentionDate = new Date();
    retentionDate.setFullYear(retentionDate.getFullYear() - this.RETENTION_YEARS);

    const assessmentsEligible = await this.assessmentRepository
      .createQueryBuilder('assessment')
      .where('assessment.status = :status', { status: AssessmentStatus.COMPLETED })
      .andWhere('assessment.completed_at < :date', { date: retentionDate })
      .getCount();

    const reportsEligible = await this.reportRepository
      .createQueryBuilder('report')
      .where('report.expiresAt < :now', { now: new Date() })
      .getCount();

    return {
      assessmentsEligibleForDeletion: assessmentsEligible,
      reportsEligibleForDeletion: reportsEligible,
      timestamp: new Date(),
    };
  }

  /**
   * Manual data purge for testing purposes
   *
   * This method can be exposed via an admin endpoint for manual cleanup
   */
  async purgeOldData(): Promise<PurgeResult> {
    const retentionDate = new Date();
    retentionDate.setFullYear(retentionDate.getFullYear() - this.RETENTION_YEARS);

    const assessmentResult = await this.assessmentRepository.softDelete({
      status: AssessmentStatus.COMPLETED,
      completed_at: LessThan(retentionDate),
    });

    const reportResult = await this.reportRepository.delete({
      expiresAt: LessThan(new Date()),
    });

    this.logger.log(
      `[MANUAL PURGE] ${assessmentResult.affected || 0} assessments soft-deleted`,
    );
    this.logger.log(
      `[MANUAL PURGE] ${reportResult.affected || 0} reports hard-deleted`,
    );

    return {
      assessmentsDeleted: assessmentResult.affected || 0,
      reportsDeleted: reportResult.affected || 0,
      timestamp: new Date(),
    };
  }

  /**
   * Get current retention policy configuration
   *
   * Returns the active retention settings for compliance documentation
   */
  getRetentionConfig(): RetentionConfig {
    return {
      assessmentRetentionYears: this.RETENTION_YEARS,
      cronSchedule: this.CRON_SCHEDULE,
      enabledAutoCleanup: true,
    };
  }
}
