# Code Review Checklist - Security & Best Practices

**Version:** 1.0
**Date:** 2025-12-28
**Purpose:** Comprehensive code review checklist for pull requests

## SQL Injection Prevention (CRIT-003)

### Database Queries

- [ ] **No raw SQL with string interpolation**
  - ❌ BAD: `` `SELECT * FROM users WHERE id = ${userId}` ``
  - ✅ GOOD: `.where('users.id = :userId', { userId })`

- [ ] **All repository methods use safe parameters**
  - ✅ `repository.find({ where: { userId } })`
  - ✅ `repository.update({ id }, { name })`
  - ✅ `repository.delete({ userId })`

- [ ] **QueryBuilder uses parameterized where clauses**
  - ✅ `.where('user.email = :email', { email })`
  - ✅ `.andWhere('user.role IN (:...roles)', { roles })`
  - ❌ `.where(\`user.email = '${email}'\`)`

- [ ] **Dynamic column names use whitelists**
  - ✅ Validate sortBy against allowed columns
  - ❌ Direct string interpolation: `` `ORDER BY ${sortBy}` ``

- [ ] **JSONB queries use parameterized operators**
  - ✅ `.where("options->>'key' = :value", { value })`
  - ❌ `.where(\`options->>'key' = '${value}'\`)`

- [ ] **No .query() calls with user input**
  - ✅ Only use .query() for static DDL in migrations
  - ❌ Never `.query(\`INSERT INTO table VALUES ('${userInput}')\`)`

### Error Handling

- [ ] **Database errors don't expose schema information**
  - No table names in error messages
  - No column names in error messages
  - Generic error messages only

- [ ] **SQL errors caught and sanitized**
  - Wrap queries in try-catch
  - Log full error, return sanitized message to client

## PII & Sensitive Data Protection (CRIT-002)

### Logging

- [ ] **No PII in log statements**
  - ❌ `console.log('User:', user)`
  - ❌ `logger.log('Password reset token:', token)`
  - ❌ `logger.debug('DISC scores:', scores)`

- [ ] **Use LogSanitizer for all logs**
  - ✅ `logger.log(\`User logged in: ${LogSanitizer.sanitizeEmail(email)}\`)`
  - ✅ `logger.debug('Reset initiated', { user: LogSanitizer.sanitizeUser(user) })`

- [ ] **Sensitive fields excluded from logs**
  - Never log: passwords, tokens, DISC scores, financial data
  - Safe to log: user IDs (UUIDs), timestamps, status codes

### API Responses

- [ ] **Tokens never returned in API responses**
  - ❌ `{ resetToken: 'abc123' }`
  - ✅ `{ message: 'Reset email sent' }`

- [ ] **DISC scores only returned to authorized consultants**
  - Never expose to clients (REQ-QUEST-003)
  - Verify consultant ownership before returning

## Encryption (CRIT-004, CRIT-005)

### Data at Rest

- [ ] **DISC scores encrypted**
  - `@Column({ transformer: EncryptedColumnTransformer })`
  - All d_score, i_score, s_score, c_score columns

- [ ] **Financial PII encrypted**
  - `assessment_responses.answer` field encrypted
  - All sensitive financial data protected

- [ ] **Encryption key from Secret Manager**
  - Never hardcoded
  - DB_ENCRYPTION_KEY from environment

### Key Management

- [ ] **No hardcoded encryption keys**
  - All keys from GCP Secret Manager or environment variables
  - Keys never committed to git

- [ ] **Key rotation documented**
  - Rotation procedures in SECRETS-MANAGEMENT.md
  - 90-day rotation policy

## Authentication & Authorization

### JWT Tokens

- [ ] **JWT secrets from Secret Manager**
  - Never hardcoded in .env files committed to git
  - Minimum 64-character hex strings

- [ ] **Token expiration configured**
  - Access tokens: 15 minutes
  - Refresh tokens: 7 days

- [ ] **Refresh tokens hashed before storage**
  - `bcrypt.hash(token, 10)`
  - Never store plaintext tokens

### Authorization Checks

- [ ] **Consultant ownership verified**
  - Verify assessment belongs to consultant
  - Prevent IDOR vulnerabilities

- [ ] **Role-based access control applied**
  - Admin routes protected with RolesGuard
  - Client access restricted appropriately

## Input Validation

### DTOs

- [ ] **All inputs have class-validator decorators**
  - `@IsEmail()`, `@IsString()`, `@IsUUID()`
  - `@Length()`, `@Min()`, `@Max()`

- [ ] **Sanitization applied where needed**
  - Trim whitespace
  - Remove HTML tags if not allowed

- [ ] **Type validation enforced**
  - `@Type(() => Number)` for numeric inputs
  - Proper enum validation

### Query Parameters

- [ ] **Pagination limits enforced**
  - Maximum page size (100 items)
  - Default values provided

- [ ] **Sort/filter inputs validated**
  - Whitelist allowed columns
  - Validate enum values

## Testing

### Security Tests

- [ ] **SQL injection tests added for new endpoints**
  - Test with injection payloads
  - Verify parameterization

- [ ] **PII masking tests for new logs**
  - Ensure LogSanitizer used
  - No sensitive data exposed

- [ ] **Encryption tests for new sensitive fields**
  - Verify encryption applied
  - Test decryption works

### Code Coverage

- [ ] **Minimum 80% coverage for business logic**
  - New services have comprehensive tests
  - Edge cases covered

- [ ] **E2E tests for critical flows**
  - Authentication flow
  - Assessment creation/completion
  - Report generation

## Performance

### Query Optimization

- [ ] **No N+1 queries**
  - Use eager loading where appropriate
  - Batch queries when possible

- [ ] **Pagination applied to list endpoints**
  - Never return unbounded result sets
  - Default and maximum limits enforced

- [ ] **Indexes exist for frequently queried columns**
  - Foreign keys indexed
  - Search columns indexed

## Documentation

- [ ] **API endpoints documented with Swagger**
  - `@ApiTags()`, `@ApiOperation()`
  - Request/response examples

- [ ] **Security considerations documented**
  - Sensitive endpoints noted
  - Authentication requirements clear

- [ ] **Complex logic has inline comments**
  - Explain "why" not "what"
  - Document business rules

## Git Hygiene

- [ ] **No secrets in commit history**
  - No .env files
  - No API keys or tokens

- [ ] **No commented-out code**
  - Remove dead code
  - Use git history instead

- [ ] **Descriptive commit messages**
  - Follow conventional commits format
  - Explain rationale for changes

## Dependency Management

- [ ] **No new high/critical vulnerabilities**
  - Run `npm audit`
  - Update vulnerable dependencies

- [ ] **Dependencies justify their addition**
  - Avoid unnecessary dependencies
  - Prefer well-maintained packages

## TypeScript

- [ ] **No `any` types without justification**
  - Use proper typing
  - Document why `any` is necessary

- [ ] **Strict null checks respected**
  - Handle null/undefined cases
  - Use optional chaining where appropriate

- [ ] **Interfaces/types documented**
  - Complex types explained
  - Examples provided

## Error Handling

- [ ] **All async functions have error handling**
  - Try-catch blocks
  - HTTP exception filters

- [ ] **Errors logged appropriately**
  - Full error for debugging
  - Sanitized message for client

- [ ] **Proper HTTP status codes used**
  - 400 for validation errors
  - 401 for authentication failures
  - 403 for authorization failures
  - 404 for not found
  - 500 for server errors

## DISC Confidentiality (REQ-QUEST-003)

- [ ] **DISC data never exposed to clients**
  - Only consultants can access
  - Reports adapt based on DISC but don't reveal it

- [ ] **DISC questions separated from other questions**
  - Clients don't see which questions are for profiling
  - Questions integrated naturally

## Accessibility

- [ ] **API responses are screen-reader friendly**
  - Proper error messages
  - Descriptive field names

## GDPR/CCPA Compliance

- [ ] **Data minimization applied**
  - Only collect necessary data
  - Don't store unnecessary PII

- [ ] **Deletion cascades correctly**
  - User deletion removes all associated data
  - `onDelete: 'CASCADE'` configured

---

## Review Sign-Off

- [ ] Code reviewed by at least one other developer
- [ ] All automated tests pass
- [ ] Security checklist items verified
- [ ] No new security warnings from static analysis

**Reviewer:** _______________
**Date:** _______________
**Approved:** [ ] Yes [ ] No

---

**Document Version:** 1.0
**Last Updated:** 2025-12-28
**Work Stream:** 55 (CRIT-003)
