# Code Review Checklist: IDOR Protection

## Purpose

This checklist ensures that all code changes properly implement IDOR (Insecure Direct Object Reference) protection and ownership validation.

**Use this checklist when reviewing:**
- New API endpoints
- Changes to existing endpoints
- New service methods
- Database queries involving user data

## Critical IDOR Protection Checklist

### 1. Controller-Level Protection

#### ✅ Guards Applied

- [ ] **All ID-based GET endpoints** use `AssessmentOwnershipGuard` or `ReportOwnershipGuard`
  ```typescript
  @Get(':id')
  @UseGuards(JwtAuthGuard, AssessmentOwnershipGuard) // ✅ Both guards present
  async findOne(@Param('id') id: string) { ... }
  ```

- [ ] **All ID-based PATCH/PUT endpoints** use ownership guards
  ```typescript
  @Patch(':id')
  @UseGuards(JwtAuthGuard, AssessmentOwnershipGuard) // ✅ Both guards present
  async update(@Param('id') id: string) { ... }
  ```

- [ ] **All ID-based DELETE endpoints** use ownership guards
  ```typescript
  @Delete(':id')
  @UseGuards(JwtAuthGuard, AssessmentOwnershipGuard) // ✅ Both guards present
  async remove(@Param('id') id: string) { ... }
  ```

- [ ] **JwtAuthGuard is ALWAYS applied before ownership guards**
  ```typescript
  @Controller('api/v1/assessments')
  @UseGuards(JwtAuthGuard) // ✅ Applied at controller level
  export class AssessmentsController { ... }
  ```

#### ✅ User Context Extraction

- [ ] Endpoints pass `@GetUser()` to extract authenticated user
  ```typescript
  async findOne(@Param('id') id: string, @GetUser() user: any) {
    return this.service.findOne(id, user.id); // ✅ Passes user.id
  }
  ```

- [ ] User ID is passed to service layer methods
  ```typescript
  // ✅ CORRECT
  this.service.findOne(id, user.id)

  // ❌ WRONG
  this.service.findOne(id)
  ```

### 2. Service-Level Validation (Defense in Depth)

#### ✅ Method Signatures

- [ ] Service methods accept `consultantId` or `userId` parameter
  ```typescript
  // ✅ CORRECT
  async findOne(id: string, consultantId: string): Promise<Assessment>

  // ❌ WRONG
  async findOne(id: string): Promise<Assessment>
  ```

- [ ] Service methods validate ownership in database queries
  ```typescript
  // ✅ CORRECT
  const assessment = await this.repo.findOne({
    where: { id, consultant_id: consultantId }
  });

  // ❌ WRONG
  const assessment = await this.repo.findOne({
    where: { id }
  });
  ```

#### ✅ Query Construction

- [ ] **WHERE clause includes ownership condition**
  ```typescript
  // ✅ CORRECT
  where: { id, consultant_id: consultantId }

  // ❌ WRONG
  where: { id }
  ```

- [ ] **QueryBuilder includes ownership filter**
  ```typescript
  // ✅ CORRECT
  .where('assessment.id = :id', { id })
  .andWhere('assessment.consultant_id = :consultantId', { consultantId })

  // ❌ WRONG
  .where('assessment.id = :id', { id })
  ```

- [ ] **Parameterized queries (NO string interpolation)**
  ```typescript
  // ✅ CORRECT
  .where('assessment.consultant_id = :consultantId', { consultantId })

  // ❌ WRONG - SQL INJECTION RISK
  .where(`assessment.consultant_id = '${consultantId}'`)
  ```

### 3. Error Handling (Information Disclosure Prevention)

#### ✅ Error Messages

- [ ] **404 errors don't reveal resource existence**
  ```typescript
  // ✅ CORRECT - Same message for non-existent and unauthorized
  if (!assessment) {
    throw new NotFoundException(`Assessment with ID ${id} not found`);
  }

  // ❌ WRONG - Reveals existence
  if (!assessment) {
    throw new ForbiddenException('You do not own this assessment');
  }
  ```

- [ ] **Error messages are consistent**
  ```typescript
  // Both should return same message:
  // - Assessment doesn't exist
  // - Assessment exists but belongs to another user
  ```

- [ ] **403 Forbidden used only when appropriate** (for reports, explicit permission denial)

#### ✅ Admin Access

- [ ] Admin users can access all resources (if business logic requires)
  ```typescript
  // ✅ In guard
  if (user.role === 'admin') {
    return true; // Bypass ownership check
  }
  ```

- [ ] Admin bypass is documented and intentional

### 4. Database Schema

#### ✅ Foreign Keys

- [ ] Resource tables have `consultant_id` or `user_id` column
  ```sql
  ALTER TABLE assessments ADD COLUMN consultant_id UUID NOT NULL;
  ALTER TABLE reports ADD COLUMN consultant_id UUID NOT NULL;
  ```

- [ ] Foreign key constraints exist
  ```sql
  ALTER TABLE reports ADD CONSTRAINT FK_reports_consultant
    FOREIGN KEY (consultant_id) REFERENCES users(id) ON DELETE CASCADE;
  ```

- [ ] Indexes exist for performance
  ```sql
  CREATE INDEX IDX_reports_consultant_id ON reports(consultant_id);
  ```

#### ✅ Entity Definitions

- [ ] Entity includes `consultantId` property
  ```typescript
  @Column({ type: 'uuid', name: 'consultant_id' })
  consultantId: string;
  ```

### 5. Testing Requirements

#### ✅ Unit Tests

- [ ] **Ownership guard unit tests exist**
  - Tests successful authorization (user owns resource)
  - Tests IDOR prevention (user doesn't own resource)
  - Tests admin bypass
  - Tests edge cases (missing user, missing ID)

- [ ] **Service unit tests include ownership validation**
  ```typescript
  it('should only return assessment if user owns it', async () => {
    // Test ownership validation
  });
  ```

#### ✅ Integration Tests

- [ ] **IDOR attack scenarios tested**
  ```typescript
  it('should prevent User A from accessing User B assessment', async () => {
    await request(app)
      .get(`/assessments/${userBAssessmentId}`)
      .set('Authorization', `Bearer ${userAToken}`)
      .expect(404);
  });
  ```

- [ ] **All CRUD operations tested** for ownership validation
  - GET (read)
  - PATCH/PUT (update)
  - DELETE (delete)

- [ ] **Attack vectors tested:**
  - [ ] Cross-user access attempts
  - [ ] ID enumeration
  - [ ] Parameter manipulation (malformed UUIDs, SQL injection)
  - [ ] Missing/invalid tokens

#### ✅ Test Coverage

- [ ] Ownership validation code has >80% coverage (per REQ-MAINT-002)
- [ ] Integration tests cover realistic attack scenarios
- [ ] Tests verify both technical protection and business logic

### 6. API Documentation

#### ✅ Swagger/OpenAPI

- [ ] Endpoint descriptions mention IDOR protection
  ```typescript
  @ApiOperation({
    summary: 'Get assessment by ID',
    description: 'IDOR protected - users can only access their own assessments.'
  })
  ```

- [ ] 403 Forbidden response documented
  ```typescript
  @ApiResponse({
    status: 403,
    description: 'Forbidden - assessment belongs to another user'
  })
  ```

#### ✅ Internal Documentation

- [ ] Ownership guards usage documented
- [ ] Service methods include ownership validation comments
- [ ] Security considerations noted in code comments

### 7. Common Vulnerabilities to Check

#### ❌ Missing Ownership Validation

```typescript
// ❌ VULNERABLE
@Get(':id')
async findOne(@Param('id') id: string) {
  return this.service.findById(id); // No user context!
}
```

#### ❌ Client-Side Trust

```typescript
// ❌ VULNERABLE
@Get(':id')
async findOne(@Param('id') id: string, @Body() body: { userId: string }) {
  // Never trust client-provided user ID!
  return this.service.findOne(id, body.userId);
}
```

#### ❌ Conditional Ownership Checks

```typescript
// ❌ VULNERABLE
async findOne(id: string, consultantId?: string) {
  const query: any = { id };
  if (consultantId) { // Optional check is dangerous!
    query.consultant_id = consultantId;
  }
  return this.repo.findOne({ where: query });
}
```

#### ❌ Information Disclosure

```typescript
// ❌ VULNERABLE
if (assessment.consultant_id !== user.id) {
  throw new ForbiddenException(
    `Assessment belongs to user ${assessment.consultant_id}, not you!`
  );
  // Reveals ownership information!
}
```

## Sign-Off

### Reviewer Checklist

I have verified that this code change:

- [ ] ✅ Implements all required ownership guards
- [ ] ✅ Includes service-layer ownership validation
- [ ] ✅ Has appropriate error handling
- [ ] ✅ Includes comprehensive tests (unit + integration)
- [ ] ✅ Documents IDOR protection
- [ ] ✅ Passes all security tests
- [ ] ✅ Follows defense-in-depth principles

**Reviewer Name:** ____________________
**Date:** ____________________
**Approval:** [ ] Approved  [ ] Changes Required

### Common Review Feedback

**If changes required, check applicable items:**

- [ ] Add ownership guard to endpoints
- [ ] Update service methods to accept `consultantId`
- [ ] Fix database queries to include ownership validation
- [ ] Improve error messages (prevent information disclosure)
- [ ] Add unit tests for ownership validation
- [ ] Add integration tests for IDOR scenarios
- [ ] Document ownership guards usage
- [ ] Add admin bypass logic (if needed)

## References

- **IDOR Protection Documentation:** `docs/IDOR-PROTECTION.md`
- **Security Audit Report:** `SECURITY-AUDIT-REPORT.md` Lines 449-523
- **OWASP A01:2021:** Broken Access Control
- **CWE-639:** Authorization Bypass Through User-Controlled Key

---

**Last Updated:** 2025-12-28
**Version:** 1.0
**Maintained by:** Security Team
