# Senior Developer Review Checklist

**Build this over time. Every correction becomes a checklist item.**

## Universal Checks
- [ ] No single-letter variable names (except loop counters)
- [ ] No functions over 50 lines
- [ ] No files over 300 lines
- [ ] No hardcoded secrets or credentials
- [ ] All public functions have docstrings
- [ ] Error messages are specific and actionable

## Testing Checks
- [ ] Every new function has at least one test
- [ ] Edge cases are explicitly tested
- [ ] Mocking doesn't hide bugs
- [ ] Test mocks match production implementations (e.g., ExecutionContext with getHandler/getClass for Reflector)

## Security Checks
- [ ] No SQL string concatenation
- [ ] User input is validated
- [ ] Secrets from environment, not code
- [ ] CSRF protection properly configured for all routes
- [ ] Public routes explicitly marked with @Public() decorator

## TypeScript/Type Safety Checks
- [ ] Frontend types match backend response structures
- [ ] No `any` types without justification
- [ ] Interfaces properly exported and imported
- [ ] Type definitions verified before using properties

## Build & CI/CD Checks
- [ ] Frontend build runs successfully (`npm run build`)
- [ ] Backend tests pass (`npm run test:cov`)
- [ ] No TypeScript compilation errors
- [ ] All tests passing before commit/push

## Code Review & Coordination Checks
- [ ] Changes documented in AGENT-COORDINATION.md when working in multi-agent environment
- [ ] Breaking changes communicated to team
- [ ] No commits to main without explicit approval (if required by project)
- [ ] Regression fixes documented with root cause analysis

## Project-Specific Checks
[Add as you discover them]

### NestJS & TypeORM Patterns
- [ ] NestJS guards using Reflector must have corresponding test mock methods (getHandler, getClass)
- [ ] TypeORM indexes: Use property-level `@Index()` for single columns, NOT class-level `@Index(['columnName'])`
- [ ] TypeORM class-level index arrays use database column names, not TypeScript property names
- [ ] Node.js crypto polyfill required in main.ts for @nestjs/schedule in production builds
- [ ] Environment variable names must match exactly between backend validation and docker-compose (TOKEN_SECRET vs JWT_SECRET)

### Frontend/Backend Contract
- [ ] Frontend User interface fields match backend User entity and AuthResponse
- [ ] Register/login DTOs match between frontend and backend
- [ ] All authentication routes tested in E2E tests
- [ ] Frontend types match backend response structures exactly

### Docker & Deployment
- [ ] Docker Compose: Never merge base + override files in production (use standalone prod file only)
- [ ] Docker Compose v3.8 MERGES arrays (volumes, networks) - it does NOT replace them
- [ ] Health check endpoints must exist in the service being checked (frontend != backend)
- [ ] Frontend nginx health checks should test `/` not `/health`
- [ ] Production images only contain compiled JS - no TypeScript files in /app/dist
- [ ] Migration scripts must use compiled JS paths, not TypeScript source paths
- [ ] Disk space monitoring: Alert at 70%, cleanup at 85%, critical at 95%
- [ ] Docker cleanup commands in deployment workflows: `docker image prune -a -f && docker volume prune -f`

### GCP & Infrastructure
- [ ] Secret Manager: Always verify latest version after updates with `gcloud secrets versions access latest`
- [ ] DB_ENCRYPTION_KEY must be exactly 64 hexadecimal characters (32 bytes)
- [ ] Cloud SQL: Public IP + authorized networks acceptable for staging, NOT for production
- [ ] Cloud SQL production: Use Private IP or Cloud SQL Auth Proxy
- [ ] Preemptible VMs acceptable for staging, standard VMs required for production
- [ ] VM IP must be in Cloud SQL authorized networks list for public IP connections

### Security & Secrets
- [ ] Secrets validation must match environment variable naming conventions
- [ ] Backend SecretsValidationService expectations documented and matched in configs
- [ ] No .git directory access in production nginx configs
- [ ] Rate limiting configured for public endpoints
- [ ] Bot scanning paths blocked: /cgi-bin, /wp-admin, /phpMyAdmin, /.git, /.env
