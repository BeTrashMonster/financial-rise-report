# Code Review Checklist - Financial RISE Backend

**Purpose:** Ensure code quality, security, and maintainability standards are met before merging

---

## 🔒 Security Checklist

### SQL Injection Prevention (CRIT-003)

- [ ] **All database queries use TypeORM Query Builder or Repository methods**
  - No raw `.query()` calls with user input
  - Example: `.createQueryBuilder('user').where('user.id = :id', { id })`

- [ ] **No string interpolation in SQL queries**
  - ❌ Forbidden: `` `SELECT * FROM users WHERE email = '${email}'` ``
  - ✅ Required: `.where('email = :email', { email })`

- [ ] **Named parameters used for all user inputs**
  - Syntax: `:paramName` for single values
  - Syntax: `:...arrayParam` for arrays

- [ ] **ORDER BY/GROUP BY use whitelisted values only**
  ```typescript
  const allowedSortFields = ['created_at', 'client_name'];
  const sortBy = allowedSortFields.includes(req.query.sort)
    ? req.query.sort
    : 'created_at';
  ```

- [ ] **JSONB queries (if any) use parameterized operators**
  - ✅ Safe: `.where("answer->>'field' = :value", { value })`
  - ❌ Unsafe: `.where("answer->>'field' = '${value}'")`

- [ ] **SQL injection tests added for new endpoints**
  - Add test cases to `src/security/sql-injection.spec.ts`

---

### Encryption & Data Protection (CRIT-004, CRIT-005)

- [ ] **Sensitive data encrypted at rest**
  - DISC scores use `EncryptedColumnTransformer`
  - Financial data (assessment responses) encrypted
  - No plaintext PII in database

- [ ] **Secrets not hardcoded in source code**
  - All secrets loaded from environment variables
  - No `.env` or `.env.local` files committed
  - GCP Secret Manager used for production secrets

- [ ] **Encryption keys validated on startup**
  - `DB_ENCRYPTION_KEY` is 64 hex characters (256-bit)
  - `JWT_SECRET` is cryptographically secure (64+ characters)

---

### PII & Logging (CRIT-002)

- [ ] **No PII in console.log or logger calls**
  - Use `LogSanitizer.sanitizeEmail()` for email logging
  - Never log passwords, tokens, DISC scores, or financial data
  - Example: `logger.log(LogSanitizer.sanitizeEmail(user.email))`

- [ ] **Password reset tokens never logged**
  - Even in development mode

- [ ] **Error messages don't expose sensitive data**
  - No database schema details in errors
  - Generic messages for authentication failures

---

### Authentication & Authorization

- [ ] **JWT tokens properly validated**
  - `@UseGuards(JwtAuthGuard)` on protected endpoints
  - Token expiration checked

- [ ] **User ownership verified**
  - Consultants can only access their own assessments
  - Use `req.user.id` for ownership checks

- [ ] **Role-based access control enforced**
  - Admin-only endpoints check `user.role === 'admin'`
  - Use `@Roles()` decorator where applicable

---

## ✅ Code Quality Checklist

### TypeScript & Type Safety

- [ ] **No `any` types (use specific types or `unknown`)**
  - Exception: External library types that lack definitions

- [ ] **DTOs use class-validator decorators**
  ```typescript
  @IsEmail()
  email: string;

  @IsUUID()
  @IsOptional()
  assessmentId?: string;
  ```

- [ ] **Return types explicitly defined for public methods**
  ```typescript
  async findOne(id: string): Promise<Assessment | null> { }
  ```

- [ ] **Enums used for fixed value sets**
  ```typescript
  enum AssessmentStatus { DRAFT = 'draft', COMPLETED = 'completed' }
  ```

---

### Testing

- [ ] **Unit tests for new business logic**
  - Minimum 80% code coverage (REQ-MAINT-002)
  - Test happy path, edge cases, and error conditions

- [ ] **Integration tests for new endpoints**
  - Test authentication, authorization, input validation
  - Test database interactions

- [ ] **Test names follow Given-When-Then pattern**
  ```typescript
  it('should return 404 when assessment not found', async () => { })
  ```

- [ ] **Mocks used appropriately**
  - Mock external services (email, GCP Secret Manager)
  - Use real database for integration tests (in-memory SQLite)

---

### Error Handling

- [ ] **Try-catch blocks for async operations**
  ```typescript
  try {
    const result = await service.operation();
    return result;
  } catch (error) {
    this.logger.error('Operation failed', error.stack);
    throw new InternalServerErrorException('Operation failed');
  }
  ```

- [ ] **Appropriate HTTP status codes**
  - 400: Bad Request (validation errors)
  - 401: Unauthorized (not authenticated)
  - 403: Forbidden (not authorized)
  - 404: Not Found
  - 500: Internal Server Error

- [ ] **Error messages are user-friendly**
  - No stack traces or technical details in production
  - Use NestJS exception filters for consistent formatting

---

### Database & Performance

- [ ] **No N+1 query problems**
  - Use `.leftJoinAndSelect()` or `.relations` to eager load
  - Monitor query count in test logs

- [ ] **Database indexes exist for queried columns**
  - Indexed: foreign keys, UUIDs, email (unique)
  - Check migration files for `@Index()` decorators

- [ ] **Pagination implemented for list endpoints**
  ```typescript
  .skip((page - 1) * limit)
  .take(Math.min(limit, 100))
  ```

- [ ] **Soft delete used instead of hard delete**
  - `deleted_at` timestamp instead of `DELETE FROM`
  - Preserves audit trail

---

### Code Style & Readability

- [ ] **ESLint and Prettier passing**
  ```bash
  npm run lint
  npm run format
  ```

- [ ] **Descriptive variable names**
  - ❌ `const d = new Date()`
  - ✅ `const createdAt = new Date()`

- [ ] **Functions are single-purpose and small**
  - Max 50 lines per function
  - Extract complex logic into private methods

- [ ] **Comments explain "why", not "what"**
  ```typescript
  // Good: Explain business logic
  // We cache DISC profiles for 24 hours to reduce database load
  // during report generation (REQ-PERF-002)

  // Bad: Restate code
  // Set cache to 24 hours
  this.cacheManager.set(key, profile, 86400);
  ```

---

## 📋 Documentation Checklist

- [ ] **API endpoints documented with Swagger decorators**
  ```typescript
  @ApiOperation({ summary: 'Create new assessment' })
  @ApiResponse({ status: 201, description: 'Assessment created' })
  @ApiResponse({ status: 400, description: 'Validation error' })
  ```

- [ ] **Complex business logic documented**
  - DISC profiling algorithm
  - Phase determination scoring
  - Encryption/decryption flows

- [ ] **README updated for new features**
  - Installation steps
  - Environment variables
  - Running tests

- [ ] **Database migrations include comments**
  ```sql
  -- Migration: Encrypt DISC scores (CRIT-004)
  -- Converts decimal columns to text for encrypted storage
  ```

---

## 🧪 Pre-Merge Verification

### Automated Checks

- [ ] **All tests passing**
  ```bash
  npm test
  ```

- [ ] **Code coverage threshold met (80%)**
  ```bash
  npm run test:cov
  ```

- [ ] **Build succeeds**
  ```bash
  npm run build
  ```

- [ ] **Linter passing**
  ```bash
  npm run lint
  ```

---

### Manual Checks

- [ ] **Code compiles without TypeScript errors**
  ```bash
  npx tsc --noEmit
  ```

- [ ] **No console.log statements in production code**
  - Use `Logger` service instead
  - Search: `grep -r "console.log" src/`

- [ ] **Environment variables documented in `.env.example`**

- [ ] **Database migrations tested**
  - Run migration up: `npm run migration:run`
  - Run migration down (revert): `npm run migration:revert`
  - Verify schema changes

---

## 🚀 Deployment Checklist

### Pre-Deployment

- [ ] **Secrets configured in GCP Secret Manager**
  - `JWT_SECRET`
  - `JWT_REFRESH_SECRET`
  - `DB_ENCRYPTION_KEY`

- [ ] **Database backup created**

- [ ] **Migration plan documented**
  - Will this change require downtime?
  - Rollback plan if migration fails

---

### Post-Deployment

- [ ] **Health check endpoint returning 200**
  ```bash
  curl https://api.financialrise.com/health
  ```

- [ ] **Monitor logs for errors**
  - Check CloudWatch/GCP Logs for 15 minutes post-deploy

- [ ] **Smoke tests on production**
  - Login works
  - Create assessment works
  - Report generation works

---

## 📊 Code Review Severity Levels

### 🔴 CRITICAL - Must Fix Before Merge

- SQL injection vulnerability
- Hardcoded secrets
- PII exposed in logs
- Authentication bypass
- Data encryption missing

### 🟠 HIGH - Should Fix Before Merge

- Missing input validation
- N+1 query problem
- Missing error handling
- Poor test coverage (<80%)
- Security headers missing

### 🟡 MEDIUM - Fix or Create Follow-up Issue

- Code duplication
- Missing Swagger docs
- Inconsistent naming
- Missing comments for complex logic
- Performance optimization opportunity

### 🟢 LOW - Optional/Nit

- Code style preference
- Minor refactoring suggestion
- Additional test case idea

---

## ✍️ Review Approval

**Reviewer Name:** ________________
**Review Date:** ________________
**Approval:** [ ] Approved [ ] Request Changes [ ] Comment Only

**Notes:**
```
[Add review comments here]
```

---

**Checklist Version:** 1.0
**Last Updated:** 2025-12-28
**Owner:** TDD Executor Team
