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
- [ ] NestJS guards using Reflector must have corresponding test mock methods (getHandler, getClass)
- [ ] Frontend User interface fields match backend User entity and AuthResponse
- [ ] Register/login DTOs match between frontend and backend
- [ ] All authentication routes tested in E2E tests
