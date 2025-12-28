# Code Review Security Checklist

**Version:** 1.0
**Date:** 2025-12-28
**Purpose:** Security-focused code review checklist for all pull requests

---

## SQL Injection Prevention

### Critical Checks

- [ ] **No string interpolation in database queries**
  - No template literals with `${userInput}` in SQL
  - No string concatenation with `+` operator in queries
  - No `query()` calls with dynamic SQL strings

- [ ] **All queries use parameterized statements**
  - WHERE clauses use `:paramName` syntax with TypeORM
  - Parameters passed as objects: `{ paramName: value }`
  - IN clauses use `whereInIds()` or `:...arrayParam` syntax
  - No raw parameter substitution

- [ ] **Dynamic query elements are validated**
  - Sort columns validated against whitelist
  - Table/column names are static or explicitly validated
  - Limit/offset values are numbers (not string concatenation)

### Examples

**❌ REJECT - SQL Injection Vulnerability:**
```typescript
// DANGEROUS: String interpolation
const users = await this.dataSource.query(`
  SELECT * FROM users WHERE email = '${email}'
`);

// DANGEROUS: String concatenation
const query = "SELECT * FROM users WHERE name = '" + userName + "'";

// DANGEROUS: Dynamic column without validation
queryBuilder.orderBy(`assessment.${sortByColumn}`, order);
```

**✅ APPROVE - Parameterized Queries:**
```typescript
// SAFE: Parameterized query
const users = await this.userRepository
  .createQueryBuilder('user')
  .where('user.email = :email', { email })
  .getMany();

// SAFE: Validated dynamic column
const allowedColumns = ['created_at', 'updated_at', 'status'];
if (!allowedColumns.includes(sortBy)) {
  throw new BadRequestException('Invalid sort column');
}
queryBuilder.orderBy(`assessment.${sortBy}`, order);
```

---

## Input Validation

- [ ] **All DTOs use class-validator decorators**
  - `@IsEmail()` for email fields
  - `@IsString()`, `@IsNumber()`, etc. for type validation
  - `@MinLength()`, `@MaxLength()` for string lengths
  - `@IsEnum()` for enumerated values

- [ ] **UUIDs validated with ParseUUIDPipe**
  - All ID parameters use `@Param('id', ParseUUIDPipe)`
  - Prevents SQL injection in ID-based queries

- [ ] **Global validation pipe configured**
  - `whitelist: true` to strip unknown properties
  - `forbidNonWhitelisted: true` to reject extra properties
  - Prevents mass assignment vulnerabilities

### Example

```typescript
// ✅ Proper validation
@Controller('assessments')
export class AssessmentsController {
  @Get(':id')
  async findOne(
    @Param('id', ParseUUIDPipe) id: string,  // UUID validation
    @GetUser() user: any
  ) {
    return this.assessmentsService.findOne(id, user.id);
  }

  @Post()
  async create(
    @Body() createDto: CreateAssessmentDto,  // DTO validation
    @GetUser() user: any
  ) {
    return this.assessmentsService.create(createDto, user.id);
  }
}
```

---

## Authentication & Authorization

- [ ] **Endpoints use proper guards**
  - `@UseGuards(JwtAuthGuard)` for authenticated endpoints
  - `@UseGuards(RolesGuard)` for role-based access
  - No endpoints missing authentication

- [ ] **Ownership validation in services**
  - Methods check `user.id` matches resource owner
  - Throw `ForbiddenException` for unauthorized access
  - No IDOR (Insecure Direct Object Reference) vulnerabilities

### Example

```typescript
// ✅ Proper authorization check
async findOne(id: string, consultantId: string) {
  const assessment = await this.repository.findOne({ where: { id } });

  if (!assessment) {
    throw new NotFoundException('Assessment not found');
  }

  // CRITICAL: Verify ownership
  if (assessment.consultant_id !== consultantId) {
    throw new ForbiddenException('Access denied');
  }

  return assessment;
}
```

---

## Sensitive Data Handling

- [ ] **No secrets in code**
  - No hardcoded API keys, passwords, or tokens
  - All secrets loaded from environment variables
  - No secrets in log messages

- [ ] **No PII in logs**
  - Email addresses sanitized (show domain only)
  - No password reset tokens in logs
  - No DISC scores in production logs
  - No client financial data in logs

- [ ] **Sensitive fields excluded from API responses**
  - `@Exclude()` decorator on password hashes
  - DTOs don't expose internal fields
  - DISC calculation metadata hidden from client reports

### Example

```typescript
// ✅ Password hash excluded
@Entity('users')
export class User {
  @Column()
  email: string;

  @Column()
  @Exclude()  // Never serialize in API responses
  password_hash: string;
}

// ✅ Sanitized logging
this.logger.log(`Password reset requested`, {
  email: this.sanitizeEmail(email),  // Show domain only
  timestamp: new Date().toISOString(),
});
```

---

## Error Handling

- [ ] **Errors don't leak schema information**
  - No SQL error messages in API responses
  - Generic error messages for production
  - Detailed errors logged server-side only

- [ ] **Status codes appropriate**
  - `400` for validation errors
  - `401` for authentication failures
  - `403` for authorization failures
  - `404` for not found
  - `500` for server errors (generic message)

### Example

```typescript
// ❌ REJECT - Information disclosure
catch (error) {
  throw new InternalServerErrorException(error.message);
  // Might expose SQL errors, file paths, etc.
}

// ✅ APPROVE - Sanitized errors
catch (error) {
  this.logger.error('Database error', error.stack);
  throw new InternalServerErrorException(
    'An error occurred processing your request'
  );
}
```

---

## JSONB Query Safety

- [ ] **JSONB queries use parameterization**
  - No string interpolation in `->` or `->>` operators
  - Field names validated if dynamic
  - Values always parameterized

### Example

```typescript
// ❌ REJECT - JSONB injection
const result = await this.dataSource.query(`
  SELECT * FROM responses WHERE answer->>'${fieldName}' = '${value}'
`);

// ✅ APPROVE - Parameterized JSONB
const result = await this.dataSource.query(`
  SELECT * FROM responses WHERE answer->>'field' = $1
`, [value]);
```

---

## Rate Limiting

- [ ] **Auth endpoints have rate limits**
  - Login: 5 attempts/minute
  - Password reset: 3 attempts/5 minutes
  - Registration: 3 attempts/hour

- [ ] **Rate limit headers present**
  - `X-RateLimit-Limit`
  - `X-RateLimit-Remaining`
  - `X-RateLimit-Reset`

---

## Security Headers

- [ ] **Helmet configured with enhanced settings**
  - Content Security Policy (CSP)
  - HSTS with preload
  - X-Frame-Options: DENY
  - X-Content-Type-Options: nosniff

- [ ] **CORS properly configured**
  - Origin whitelist (no wildcards)
  - Credentials allowed only for trusted origins
  - Allowed methods explicitly defined

---

## Testing

- [ ] **Security tests included**
  - SQL injection attack tests
  - IDOR tests (accessing other users' data)
  - Authentication bypass tests
  - Authorization tests

- [ ] **Coverage requirements met**
  - Business logic: >80% coverage
  - Security-critical code: 100% coverage
  - All new endpoints tested

---

## Code Quality

- [ ] **No commented-out code**
  - Remove debug statements
  - Remove console.log() calls
  - Clean up TODO comments

- [ ] **Type safety**
  - No `any` types (use specific types)
  - All parameters typed
  - Return types defined

- [ ] **Error handling complete**
  - All async operations have try/catch
  - All promises have .catch()
  - Database operations handle failures

---

## Deployment Safety

- [ ] **Environment variables documented**
  - `.env.example` updated
  - No production secrets in `.env.example`
  - Required vs. optional variables noted

- [ ] **Database migrations tested**
  - Migrations run successfully
  - Rollback tested
  - No data loss

- [ ] **Breaking changes documented**
  - API changes noted
  - Migration guide provided
  - Version number updated

---

## Automated Checks

Before approving any PR, run:

```bash
# 1. SQL injection scan
node scripts/scan-sql-injection.js

# 2. Run all tests
npm test

# 3. Check coverage
npm run test:cov

# 4. Lint code
npm run lint

# 5. Security audit
npm audit

# 6. TypeScript check
npm run build
```

All must pass before merge.

---

## Review Comments Templates

### SQL Injection Issue

```
🔒 SECURITY: Potential SQL injection vulnerability

This query uses string interpolation which could allow SQL injection attacks.

**Issue:**
```typescript
query(`SELECT * FROM users WHERE email = '${email}'`)
```

**Fix:**
Use parameterized queries:
```typescript
.where('user.email = :email', { email })
```

**Reference:** docs/SQL_INJECTION_PREVENTION.md
```

### Missing Authorization

```
🔒 SECURITY: Missing ownership validation

This endpoint doesn't verify that the user owns the requested resource, allowing potential IDOR attacks.

**Fix:**
```typescript
if (assessment.consultant_id !== user.id) {
  throw new ForbiddenException('Access denied');
}
```
```

### PII in Logs

```
🔒 SECURITY: Sensitive data in logs

This log statement exposes PII which violates GDPR.

**Fix:**
Remove or sanitize sensitive data before logging:
```typescript
this.logger.log(`Action performed`, {
  email: this.sanitizeEmail(email),
  userId: user.id,
});
```
```

---

## Escalation

If you identify a critical security issue:

1. **Do not approve the PR**
2. **Mark as "Changes Requested"**
3. **Tag security team:** @security
4. **Create security issue:** Label as "security" and "critical"
5. **Notify lead developer**

Critical issues include:
- SQL injection vulnerabilities
- Authentication bypass
- Authorization bypass (IDOR)
- Hardcoded secrets
- PII exposure

---

**Checklist Version:** 1.0
**Last Updated:** 2025-12-28
**Maintained By:** Security Team

