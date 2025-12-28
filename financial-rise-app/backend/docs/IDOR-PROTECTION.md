# IDOR Protection & Ownership Guards

## Overview

This document describes the Insecure Direct Object Reference (IDOR) protection mechanisms implemented in the Financial RISE Report application to prevent unauthorized access to user resources.

**Security Classification:** MEDIUM Priority
**OWASP Category:** A01:2021 - Broken Access Control
**CWE:** CWE-639 - Authorization Bypass Through User-Controlled Key
**Work Stream:** 62 - IDOR Protection & Ownership Guards

## What is IDOR?

Insecure Direct Object Reference (IDOR) is a vulnerability that occurs when an application provides direct access to objects based on user-supplied input. Attackers can manipulate references to access unauthorized data.

### IDOR Attack Example

```typescript
// VULNERABLE CODE (DO NOT USE)
@Get(':id')
async getAssessment(@Param('id') id: string) {
  // Anyone with a valid ID can access any assessment
  return this.assessmentService.findOne(id);
}

// Attack scenario:
// User A tries to access User B's assessment by changing the URL:
// GET /assessments/user-b-assessment-id
// Result: User A can see User B's private data!
```

### Our Protection

```typescript
// SECURE CODE (IMPLEMENTED)
@Get(':id')
@UseGuards(JwtAuthGuard, AssessmentOwnershipGuard)
async getAssessment(@Param('id') id: string, @GetUser() user: any) {
  // Ownership guard validates user owns this assessment
  return this.assessmentService.findOne(id, user.id);
}

// Attack scenario:
// User A tries to access User B's assessment:
// GET /assessments/user-b-assessment-id
// Result: 404 Not Found (assessment ownership validation fails)
```

## Architecture

### Defense Layers

We implement **defense in depth** with multiple validation layers:

```
┌─────────────────────────────────────────────────────┐
│ 1. Authentication (JwtAuthGuard)                    │
│    - Validates JWT token                            │
│    - Extracts user ID and role                      │
└────────────────┬────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────┐
│ 2. Authorization (Ownership Guards)                 │
│    - AssessmentOwnershipGuard                       │
│    - ReportOwnershipGuard                           │
│    - Validates resource ownership                   │
└────────────────┬────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────┐
│ 3. Service Layer (Double Validation)                │
│    - findOne(id, consultantId)                      │
│    - WHERE id = :id AND consultant_id = :userId     │
│    - Database-enforced ownership                    │
└─────────────────────────────────────────────────────┘
```

### Ownership Guards

We have implemented two ownership guards:

#### 1. AssessmentOwnershipGuard

Protects assessment resources from unauthorized access.

**Location:** `src/common/guards/assessment-ownership.guard.ts`

**Usage:**
```typescript
@Get(':id')
@UseGuards(JwtAuthGuard, AssessmentOwnershipGuard)
async findOne(@Param('id') id: string, @GetUser() user: any) {
  return this.assessmentsService.findOne(id, user.id);
}
```

**How it works:**
1. Extracts assessment ID from route parameters
2. Extracts user ID from JWT (via JwtAuthGuard)
3. Calls `AssessmentsService.findOne(assessmentId, userId)`
4. Service validates `consultant_id = userId` in database query
5. Throws `NotFoundException` if assessment doesn't exist or user doesn't own it
6. Admin users bypass ownership check (role-based exception)

#### 2. ReportOwnershipGuard

Protects report resources from unauthorized access.

**Location:** `src/common/guards/report-ownership.guard.ts`

**Usage:**
```typescript
@Get('status/:id')
@UseGuards(JwtAuthGuard, ReportOwnershipGuard)
async getReportStatus(@Param('id') reportId: string) {
  return this.reportService.getReportStatus(reportId);
}
```

**How it works:**
1. Extracts report ID from route parameters
2. Extracts user ID from JWT (via JwtAuthGuard)
3. Retrieves report from database
4. Validates `report.consultantId === user.id`
5. Throws `NotFoundException` if report doesn't exist
6. Throws `ForbiddenException` if user doesn't own the report
7. Admin users bypass ownership check (role-based exception)

## Protected Endpoints

### Assessment Endpoints

All assessment endpoints with `:id` parameter are protected:

| Method | Endpoint | Guard | Access Control |
|--------|----------|-------|----------------|
| GET | `/api/v1/assessments/:id` | AssessmentOwnershipGuard | Owner or Admin |
| PATCH | `/api/v1/assessments/:id` | AssessmentOwnershipGuard | Owner or Admin |
| DELETE | `/api/v1/assessments/:id` | AssessmentOwnershipGuard | Owner or Admin |
| GET | `/api/v1/assessments` | None (filtered by user) | Own assessments only |
| POST | `/api/v1/assessments` | None (user auto-assigned) | Creates for current user |

### Report Endpoints

All report endpoints with `:id` parameter are protected:

| Method | Endpoint | Guard | Access Control |
|--------|----------|-------|----------------|
| GET | `/reports/status/:id` | ReportOwnershipGuard | Owner or Admin |
| GET | `/reports/download/:id` | ReportOwnershipGuard | Owner or Admin |
| POST | `/reports/generate/consultant` | None (user auto-assigned) | Creates for current user |
| POST | `/reports/generate/client` | None (user auto-assigned) | Creates for current user |

## Service Layer Validation

All guards rely on service-layer ownership validation for defense in depth.

### AssessmentsService.findOne()

```typescript
async findOne(id: string, consultantId: string): Promise<Assessment> {
  const assessment = await this.assessmentRepository.findOne({
    where: { id, consultant_id: consultantId }, // 👈 Ownership validation
    relations: ['responses', 'disc_profiles', 'phase_results'],
  });

  if (!assessment) {
    throw new NotFoundException(`Assessment with ID ${id} not found`);
  }

  return assessment;
}
```

**Key features:**
- Uses `WHERE` clause with both `id` AND `consultant_id`
- Returns 404 for both non-existent and unauthorized assessments
- Prevents information disclosure (doesn't reveal assessment exists)

### ReportGenerationService.getReportStatus()

```typescript
async getReportStatus(reportId: string): Promise<Report | null> {
  return this.reportRepository.findOne({ where: { id: reportId } });
}
```

**Note:** Report ownership validation is handled in the guard layer, but the service still returns `null` for non-existent reports.

## Admin Access

Admin users bypass ownership checks and can access all resources:

```typescript
// In ownership guards
if (user.role === 'admin') {
  return true; // Bypass ownership check
}
```

This enables administrative functions like:
- User support and troubleshooting
- Data export for compliance
- System monitoring and auditing

## Error Handling

### Information Disclosure Prevention

We carefully design error messages to prevent information disclosure:

**Scenario 1: Assessment doesn't exist**
```
GET /assessments/nonexistent-id
Response: 404 Not Found
Message: "Assessment with ID nonexistent-id not found"
```

**Scenario 2: Assessment exists but belongs to another user**
```
GET /assessments/other-user-assessment-id
Response: 404 Not Found
Message: "Assessment with ID other-user-assessment-id not found"
```

**Why?** Same error message prevents attackers from enumerating valid assessment IDs.

**Scenario 3: Report exists but belongs to another user**
```
GET /reports/status/other-user-report-id
Response: 403 Forbidden
Message: "You do not have permission to access this report"
```

**Why?** Reports use explicit 403 because the report generation API is different and doesn't support the same query-based approach.

## Testing

### Unit Tests

**AssessmentOwnershipGuard:** `src/common/guards/assessment-ownership.guard.spec.ts`
- 11 test cases covering ownership validation, IDOR prevention, edge cases
- Tests admin bypass, service integration, error propagation

**ReportOwnershipGuard:** `src/common/guards/report-ownership.guard.spec.ts`
- 13 test cases covering ownership validation, IDOR prevention, edge cases
- Tests admin bypass, different report statuses, service integration

### Integration Tests

**IDOR Attack Tests:** `src/common/guards/idor-attack.integration.spec.ts`
- 20+ comprehensive attack scenarios
- Tests actual HTTP requests with real database
- Validates defense in depth across all layers
- Tests ID enumeration, parameter manipulation, SQL injection attempts

#### Test Coverage

```
Attack Vectors Tested:
✅ Cross-user assessment access (GET, PATCH, DELETE)
✅ Cross-user report access (status, download)
✅ ID enumeration attacks
✅ Parameter manipulation (malformed UUIDs, SQL injection)
✅ Missing/invalid/expired JWT tokens
✅ Admin bypass validation
✅ Defense consistency across all endpoints
```

### Running Tests

```bash
# Unit tests
npm test -- assessment-ownership.guard.spec.ts
npm test -- report-ownership.guard.spec.ts

# Integration tests
npm test -- idor-attack.integration.spec.ts

# All ownership tests
npm test -- ownership
```

## Security Best Practices

### 1. Always Use Guards on ID-Based Endpoints

```typescript
// ✅ CORRECT
@Get(':id')
@UseGuards(JwtAuthGuard, AssessmentOwnershipGuard)
async findOne(@Param('id') id: string) { ... }

// ❌ WRONG
@Get(':id')
@UseGuards(JwtAuthGuard) // Missing ownership guard!
async findOne(@Param('id') id: string) { ... }
```

### 2. Always Validate Ownership in Service Layer

```typescript
// ✅ CORRECT
async findOne(id: string, consultantId: string) {
  return await this.repo.findOne({
    where: { id, consultant_id: consultantId }
  });
}

// ❌ WRONG
async findOne(id: string) {
  return await this.repo.findOne({ where: { id } });
}
```

### 3. Use Consistent Error Messages

```typescript
// ✅ CORRECT
if (!assessment) {
  throw new NotFoundException(`Assessment with ID ${id} not found`);
}

// ❌ WRONG
if (!assessment) {
  throw new ForbiddenException('You do not own this assessment');
  // Reveals assessment exists!
}
```

### 4. Test IDOR Scenarios

Always write integration tests for new ID-based endpoints:

```typescript
it('should prevent User A from accessing User B resource', async () => {
  await request(app)
    .get(`/resource/${userBResourceId}`)
    .set('Authorization', `Bearer ${userAToken}`)
    .expect(404);
});
```

## Database Schema Support

### Reports Table Migration

The `consultant_id` column was added to the `reports` table to enable ownership validation:

**Migration:** `1735390000000-AddConsultantIdToReports.ts`

```sql
ALTER TABLE reports ADD COLUMN consultant_id UUID NOT NULL;
ALTER TABLE reports ADD CONSTRAINT FK_reports_consultant
  FOREIGN KEY (consultant_id) REFERENCES users(id) ON DELETE CASCADE;
CREATE INDEX IDX_reports_consultant_id ON reports(consultant_id);
```

This enables:
- Direct ownership queries
- Referential integrity enforcement
- Performance optimization via index
- Cascade deletion when users are deleted

## Code Review Checklist

When reviewing code for IDOR vulnerabilities:

- [ ] All ID-based GET endpoints use ownership guards
- [ ] All ID-based PATCH/PUT/DELETE endpoints use ownership guards
- [ ] Service methods accept `consultantId` parameter
- [ ] Service queries include `consultant_id` in WHERE clause
- [ ] Error messages don't reveal resource existence
- [ ] Admin users can access all resources (when appropriate)
- [ ] Unit tests cover ownership validation
- [ ] Integration tests cover IDOR attack scenarios
- [ ] Documentation updated with new endpoints

## References

- **OWASP A01:2021** - Broken Access Control
  https://owasp.org/Top10/A01_2021-Broken_Access_Control/

- **CWE-639** - Authorization Bypass Through User-Controlled Key
  https://cwe.mitre.org/data/definitions/639.html

- **Security Audit Report:** `SECURITY-AUDIT-REPORT.md` Lines 449-523

- **Work Stream 62:** IDOR Protection & Ownership Guards implementation

## Support

For questions or security concerns, contact:
- Security Team: security@financial-rise.com
- Lead Developer: dev@financial-rise.com

**Last Updated:** 2025-12-28
**Version:** 1.0
**Author:** TDD Executor WS62
