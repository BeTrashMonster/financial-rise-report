# Data Retention Policy - GDPR Compliance

**Version:** 1.0
**Last Updated:** 2025-12-28
**Security Finding:** HIGH-007 - Missing Data Retention Policy
**Compliance:** GDPR Article 5(1)(e), CCPA Data Minimization

---

## Table of Contents
1. [Overview](#overview)
2. [Retention Policies](#retention-policies)
3. [Implementation](#implementation)
4. [Scheduled Cleanup](#scheduled-cleanup)
5. [Manual Purge](#manual-purge)
6. [Compliance Logging](#compliance-logging)
7. [Configuration](#configuration)
8. [Testing](#testing)
9. [Troubleshooting](#troubleshooting)

---

## Overview

The Financial RISE application implements automated data retention policies to comply with:
- **GDPR Article 5(1)(e)**: Storage Limitation Principle
- **CCPA Section 1798.100**: Data Minimization Requirements
- **OWASP A04:2021**: Insecure Design (addressing CWE-404)

The `DataRetentionService` automatically deletes old data according to defined retention periods, reducing:
- Privacy compliance risks
- Data breach surface area
- Storage costs
- Legal liability

---

## Retention Policies

### Assessments
- **Retention Period:** 2 years from completion date
- **Scope:** Completed assessments only (`status = 'completed'`)
- **Deletion Type:** Soft delete (maintains audit trail)
- **Calculation:** From `completed_at` timestamp

**Rationale:**
- Allows consultants to review historical assessments for up to 2 years
- Maintains compliance with tax record retention requirements (typically 7 years, but financial assessment data itself is not tax records)
- Soft delete preserves audit trails for compliance investigations

### Reports
- **Retention Period:** Based on `expires_at` field
- **Scope:** All reports with a defined expiration date
- **Deletion Type:** Hard delete (complete removal)
- **Calculation:** When `expires_at < current_date`

**Rationale:**
- Reports are generated documents that can be regenerated if needed
- Expiration date is set when report is generated
- Hard delete reduces storage costs for PDF files

### Data NOT Subject to Automatic Deletion
- Draft assessments (not yet completed)
- In-progress assessments
- User accounts
- Questions/questionnaire templates
- DISC profiles (linked to assessments)
- Phase results (linked to assessments)

---

## Implementation

### Service Architecture

```typescript
src/common/services/
├── data-retention.service.ts         # Main service implementation
├── data-retention.service.spec.ts    # Unit tests (15 tests)
└── data-retention.integration.spec.ts # Integration tests
```

### Key Components

#### DataRetentionService
```typescript
@Injectable()
export class DataRetentionService {
  @Cron('0 2 * * *') // Daily at 2 AM
  async enforceRetentionPolicies(): Promise<void>

  async getRetentionStats(): Promise<RetentionStats>
  async purgeOldData(): Promise<PurgeResult>
  getRetentionConfig(): RetentionConfig
}
```

### Database Operations

**Soft Delete (Assessments):**
```typescript
await assessmentRepository.softDelete({
  status: AssessmentStatus.COMPLETED,
  completed_at: LessThan(retentionDate),
});
```

- Sets `deleted_at` timestamp
- Data remains in database for audit purposes
- Excluded from normal queries
- Can be retrieved with `withDeleted: true`

**Hard Delete (Reports):**
```typescript
await reportRepository.delete({
  expiresAt: LessThan(new Date()),
});
```

- Permanently removes data from database
- Cannot be recovered
- Reduces storage costs

---

## Scheduled Cleanup

### CRON Schedule

**Frequency:** Daily
**Time:** 2:00 AM UTC
**CRON Expression:** `0 2 * * *`

### Automatic Execution

The service uses NestJS `@Cron` decorator to automatically run retention policies:

```typescript
@Cron('0 2 * * *')
async enforceRetentionPolicies(): Promise<void> {
  // Calculates retention date (2 years ago)
  // Soft deletes old completed assessments
  // Hard deletes expired reports
  // Logs all actions for compliance audit
}
```

### Logs Generated

Every scheduled run generates compliance audit logs:

```
[GDPR COMPLIANCE] Starting data retention enforcement at 2025-12-28T02:00:00.000Z
[AUDIT TRAIL] Retention policy: 2 years for completed assessments
[AUDIT TRAIL] 15 assessments soft-deleted (older than 2023-12-28T02:00:00.000Z)
[AUDIT TRAIL] 8 reports hard-deleted (expired)
[AUDIT TRAIL] Retention enforcement completed at 2025-12-28T02:00:15.234Z
```

---

## Manual Purge

### Admin Endpoint (Recommended)

Create an admin-only endpoint for manual data purge:

```typescript
@Controller('admin/data-retention')
@UseGuards(AuthGuard, AdminGuard)
export class DataRetentionController {
  @Post('purge')
  async manualPurge(): Promise<PurgeResult> {
    return this.dataRetentionService.purgeOldData();
  }

  @Get('stats')
  async getStats(): Promise<RetentionStats> {
    return this.dataRetentionService.getRetentionStats();
  }
}
```

### Manual Service Call

For testing or emergency purges:

```typescript
const result = await dataRetentionService.purgeOldData();
console.log(`Deleted ${result.assessmentsDeleted} assessments`);
console.log(`Deleted ${result.reportsDeleted} reports`);
```

### Response Format

```json
{
  "assessmentsDeleted": 15,
  "reportsDeleted": 8,
  "timestamp": "2025-12-28T14:30:00.000Z"
}
```

---

## Compliance Logging

### Log Levels

**INFO:** Normal retention operations
```
[GDPR COMPLIANCE] Starting data retention enforcement
[AUDIT TRAIL] 15 assessments soft-deleted
```

**ERROR:** Failures during retention enforcement
```
[GDPR COMPLIANCE ERROR] Data retention enforcement failed: Database connection lost
```

### Audit Trail Requirements

All retention actions are logged with:
- Timestamp (ISO 8601 format)
- Number of records deleted
- Retention policy applied (e.g., "2 years")
- Type of deletion (soft/hard)
- Retention date threshold

### Log Retention

Retention logs themselves should be preserved for:
- **Minimum:** 3 years (longer than data retention period)
- **Recommended:** 7 years (standard compliance record retention)

Configure log archival with your logging provider (CloudWatch, Datadog, etc.)

---

## Configuration

### Current Settings

```typescript
{
  assessmentRetentionYears: 2,
  cronSchedule: '0 2 * * *',
  enabledAutoCleanup: true
}
```

### Customization

To modify retention period, update `DataRetentionService`:

```typescript
private readonly RETENTION_YEARS = 2; // Change to desired years
```

To change CRON schedule:

```typescript
@Cron('0 2 * * *') // Modify cron expression
```

### Environment Variables (Optional)

Consider externalizing configuration:

```typescript
constructor(
  private configService: ConfigService
) {
  this.RETENTION_YEARS = this.configService.get('DATA_RETENTION_YEARS', 2);
}
```

`.env.local`:
```
DATA_RETENTION_YEARS=2
DATA_RETENTION_CRON=0 2 * * *
DATA_RETENTION_ENABLED=true
```

---

## Testing

### Unit Tests

**Location:** `src/common/services/data-retention.service.spec.ts`
**Coverage:** 15 tests covering:
- Retention policy enforcement
- Soft delete vs hard delete
- Compliance logging
- Error handling
- Statistics generation
- Manual purge
- CRON schedule validation
- Date calculations

**Run Tests:**
```bash
npm test -- data-retention.service.spec.ts
```

**Expected Output:**
```
Test Suites: 1 passed
Tests:       15 passed
```

### Integration Tests

**Location:** `src/common/services/data-retention.integration.spec.ts`
**Purpose:** Verify actual database operations with SQLite in-memory DB

**Run Tests:**
```bash
npm test -- data-retention.integration.spec.ts
```

### Manual Testing

1. **Create old test data:**
```sql
UPDATE assessments
SET status = 'completed', completed_at = '2022-01-01'
WHERE id = 'test-assessment-id';
```

2. **Run manual purge:**
```typescript
const stats = await service.getRetentionStats();
console.log(`Eligible: ${stats.assessmentsEligibleForDeletion}`);

const result = await service.purgeOldData();
console.log(`Deleted: ${result.assessmentsDeleted}`);
```

3. **Verify soft delete:**
```typescript
const deleted = await assessmentRepository.findOne({
  where: { id: 'test-assessment-id' },
  withDeleted: true
});
console.log('Deleted at:', deleted.deleted_at);
```

---

## Troubleshooting

### Issue: Scheduled task not running

**Symptoms:** No retention logs in application logs at 2 AM

**Causes:**
- ScheduleModule not imported in AppModule
- Application not running at 2 AM
- CRON expression syntax error

**Solutions:**
1. Verify ScheduleModule is imported:
```typescript
imports: [ScheduleModule.forRoot()]
```

2. Check CRON syntax:
```bash
# Use https://crontab.guru/ to validate
0 2 * * *  # Daily at 2 AM
```

3. Manually trigger to test:
```typescript
await dataRetentionService.enforceRetentionPolicies();
```

### Issue: Soft delete not working

**Symptoms:** Old assessments still appear in queries

**Causes:**
- DeleteDateColumn not defined on entity
- Query not excluding soft-deleted records

**Solutions:**
1. Verify entity has `@DeleteDateColumn()`:
```typescript
@Entity('assessments')
export class Assessment {
  @DeleteDateColumn()
  deleted_at: Date | null;
}
```

2. TypeORM automatically excludes soft-deleted records. To include them:
```typescript
findOne({ where: { id }, withDeleted: true })
```

### Issue: Too much data deleted

**Symptoms:** Recent assessments were deleted

**Causes:**
- Incorrect retention period calculation
- Bug in date comparison

**Solutions:**
1. Check retention period:
```typescript
this.RETENTION_YEARS = 2; // Should be 2
```

2. Verify date calculation:
```typescript
const retentionDate = new Date();
retentionDate.setFullYear(retentionDate.getFullYear() - 2);
console.log('Retention date:', retentionDate);
```

3. Review logs:
```
[AUDIT TRAIL] 15 assessments soft-deleted (older than 2023-12-28T02:00:00.000Z)
```

### Issue: Database performance degradation

**Symptoms:** Retention job takes >5 minutes

**Causes:**
- Large number of records to delete
- Missing indexes on `completed_at` and `status`

**Solutions:**
1. Add database indexes:
```sql
CREATE INDEX idx_assessments_completed_at ON assessments(completed_at);
CREATE INDEX idx_assessments_status ON assessments(status);
CREATE INDEX idx_reports_expires_at ON reports(expires_at);
```

2. Monitor deletion counts:
```typescript
const stats = await service.getRetentionStats();
console.log(`Will delete: ${stats.assessmentsEligibleForDeletion}`);
```

3. Consider batch deletion for large datasets:
```typescript
// Delete in chunks of 1000
const batchSize = 1000;
let deleted = 0;
while (true) {
  const result = await assessmentRepository
    .softDelete({...criteria, take: batchSize});
  deleted += result.affected || 0;
  if ((result.affected || 0) < batchSize) break;
}
```

---

## GDPR Data Subject Rights

While this service handles automated data retention, remember:

**Right to Erasure (Article 17):** Users can request immediate deletion of their data, regardless of retention period. Implement:
```typescript
async deleteUserData(userId: string): Promise<void> {
  // Hard delete all user's assessments (override retention policy)
  await assessmentRepository.delete({ consultant_id: userId });
}
```

**Right to Access (Article 15):** Users can request copies of their data, including soft-deleted assessments:
```typescript
async getUserData(userId: string): Promise<Assessment[]> {
  return assessmentRepository.find({
    where: { consultant_id: userId },
    withDeleted: true  // Include soft-deleted records
  });
}
```

---

## Security Considerations

1. **Access Control:** Only administrators should manually trigger retention enforcement
2. **Audit Logging:** All retention actions must be logged for compliance audits
3. **Backup Strategy:** Ensure backups exclude soft-deleted records after backup retention period
4. **Data Recovery:** Document process for recovering accidentally deleted data (if using soft delete)
5. **Monitoring:** Alert on retention job failures or unusually high deletion counts

---

## References

- **GDPR:** [Article 5(1)(e) - Storage Limitation](https://gdpr-info.eu/art-5-gdpr/)
- **CCPA:** [Section 1798.100 - Data Minimization](https://oag.ca.gov/privacy/ccpa)
- **OWASP:** [A04:2021 - Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
- **CWE:** [CWE-404 - Improper Resource Shutdown](https://cwe.mitre.org/data/definitions/404.html)
- **Security Audit:** `SECURITY-AUDIT-REPORT.md` Lines 1024-1077

---

## Change Log

| Version | Date       | Changes                      | Author           |
|---------|------------|------------------------------|------------------|
| 1.0     | 2025-12-28 | Initial data retention policy| tdd-executor-retention |

---

**Document Owner:** Security & Compliance Team
**Review Frequency:** Quarterly
**Next Review:** 2026-03-28
