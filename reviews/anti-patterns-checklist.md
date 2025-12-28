# Architecture & Code Anti-Patterns Checklist

**Version:** 1.1
**Last Updated:** 2025-12-27 17:40
**Purpose:** Living document of anti-patterns discovered during autonomous reviews

This checklist is automatically maintained by the autonomous reviewer agent. Each review run adds newly discovered anti-patterns, creating a comprehensive quality knowledge base over time.

---

## How This Checklist Works

- **Automatic Growth:** The reviewer agent adds new anti-patterns as they're discovered
- **Priority Levels:** Critical (🔴), High (🟠), Medium (🟡), Low (🟢)
- **Context-Aware:** Each pattern includes when it applies and why it's problematic
- **Action-Oriented:** Links to roadmap items created to address issues

---

## Current Anti-Patterns

### Security

#### SEC-001: Hardcoded Credentials 🔴 CRITICAL
- **Description:** Credentials, API keys, or secrets hardcoded in source files
- **Impact:** Security breach, credential leakage
- **Check For:**
  - Strings containing "password", "secret", "api_key", "token"
  - Database connection strings with credentials
  - AWS/GCP/Azure keys in code
- **Correct Approach:** Use environment variables, secret management systems
- **Discovered:** Initial checklist (2025-12-27)

#### SEC-002: SQL Injection Vulnerabilities 🔴 CRITICAL
- **Description:** Unsanitized user input in SQL queries
- **Impact:** Database breach, data loss
- **Check For:**
  - String concatenation in SQL queries
  - Raw queries without parameterization
  - ORM misuse that builds raw SQL
- **Correct Approach:** Use parameterized queries, ORMs properly, input validation
- **Discovered:** Initial checklist (2025-12-27)

#### SEC-003: Missing Authentication/Authorization 🟠 HIGH
- **Description:** Endpoints or functions accessible without proper auth
- **Impact:** Unauthorized access, data exposure
- **Check For:**
  - API endpoints without auth middleware
  - Admin functions without role checks
  - Missing JWT validation
- **Correct Approach:** Implement auth middleware, role-based access control
- **Discovered:** Initial checklist (2025-12-27)

---

### Architecture

#### ARCH-001: God Objects/Classes 🟠 HIGH
- **Description:** Single class/module with excessive responsibilities
- **Impact:** Unmaintainable code, tight coupling, difficult testing
- **Check For:**
  - Classes > 500 lines
  - Classes with > 10 methods
  - Classes handling multiple concerns (DB + business logic + presentation)
- **Correct Approach:** Single Responsibility Principle, extract services
- **Discovered:** Initial checklist (2025-12-27)

#### ARCH-002: Circular Dependencies 🟠 HIGH
- **Description:** Module A imports B, B imports A
- **Impact:** Build issues, tight coupling, hard to reason about
- **Check For:**
  - Import cycles in modules
  - Bidirectional service dependencies
- **Correct Approach:** Extract shared interface/types, dependency injection
- **Discovered:** Initial checklist (2025-12-27)

#### ARCH-003: Missing Abstraction Layers 🟡 MEDIUM
- **Description:** Business logic directly coupled to framework/database
- **Impact:** Hard to test, hard to change infrastructure
- **Check For:**
  - Database queries in controllers/routes
  - Business logic in HTTP handlers
  - Framework-specific code in domain models
- **Correct Approach:** Repository pattern, service layer, clean architecture
- **Discovered:** Initial checklist (2025-12-27)

---

### Code Quality

#### CODE-001: Copy-Paste Code 🟡 MEDIUM
- **Description:** Identical or near-identical code blocks duplicated
- **Impact:** Maintenance burden, inconsistent bug fixes
- **Check For:**
  - Similar function implementations across files
  - Repeated logic patterns
  - Functions > 80% similar
- **Correct Approach:** Extract shared functions, use composition
- **Discovered:** Initial checklist (2025-12-27)

#### CODE-002: Magic Numbers/Strings 🟡 MEDIUM
- **Description:** Unexplained numeric or string literals in code
- **Impact:** Unclear intent, hard to maintain
- **Check For:**
  - Numeric literals without context (except 0, 1)
  - String literals used multiple times
  - Unexplained constants
- **Correct Approach:** Named constants with descriptive names
- **Discovered:** Initial checklist (2025-12-27)

#### CODE-003: Overly Complex Functions 🟡 MEDIUM
- **Description:** Functions with high cyclomatic complexity
- **Impact:** Hard to test, understand, maintain
- **Check For:**
  - Functions > 50 lines
  - Nested conditionals > 3 levels
  - Multiple return points without clear pattern
- **Correct Approach:** Extract methods, simplify logic, early returns
- **Discovered:** Initial checklist (2025-12-27)

---

### Testing

#### TEST-001: Missing Test Coverage 🟠 HIGH
- **Description:** Business logic without unit tests
- **Impact:** Regression risk, fear of refactoring
- **Check For:**
  - Services/models without test files
  - Coverage < 80% for business logic
  - Critical paths untested
- **Correct Approach:** TDD, aim for 80%+ coverage, test critical paths
- **Discovered:** Initial checklist (2025-12-27)

#### TEST-002: Testing Implementation Instead of Behavior 🟡 MEDIUM
- **Description:** Tests coupled to internal implementation details
- **Impact:** Brittle tests, false failures on refactoring
- **Check For:**
  - Tests accessing private methods/properties
  - Tests verifying internal state instead of outputs
  - Mocking everything including internal functions
- **Correct Approach:** Test public API, behavior-driven tests, integration tests
- **Discovered:** Initial checklist (2025-12-27)

---

### Performance

#### PERF-001: N+1 Query Problem 🟠 HIGH
- **Description:** Loading related data in loops instead of batch
- **Impact:** Severe performance degradation, database overload
- **Check For:**
  - Database queries inside loops
  - Lazy loading in iterations
  - Missing joins/includes in ORM
- **Correct Approach:** Eager loading, batch queries, proper joins
- **Discovered:** Initial checklist (2025-12-27)

#### PERF-002: Missing Indexes 🟡 MEDIUM
- **Description:** Database queries on unindexed columns
- **Impact:** Slow queries, poor scalability
- **Check For:**
  - WHERE/JOIN on columns without indexes
  - Foreign keys without indexes
  - Missing composite indexes for common queries
- **Correct Approach:** Index frequently queried columns, analyze query plans
- **Discovered:** Initial checklist (2025-12-27)

---

### Error Handling

#### ERR-001: Silent Failures 🔴 CRITICAL
- **Description:** Errors caught but not logged or handled
- **Impact:** Hidden bugs, impossible to debug production issues
- **Check For:**
  - Empty catch blocks
  - Errors caught without logging
  - Missing error monitoring
- **Correct Approach:** Log all errors, use error tracking (Sentry), fail fast
- **Discovered:** Initial checklist (2025-12-27)

#### ERR-002: Generic Error Messages 🟡 MEDIUM
- **Description:** Error messages without context or actionable info
- **Impact:** Poor user experience, hard to debug
- **Check For:**
  - Errors with message "Error" or "Something went wrong"
  - Missing error codes
  - No context in error messages
- **Correct Approach:** Specific messages, error codes, include context
- **Discovered:** Initial checklist (2025-12-27)

---

### API Design

#### API-001: Inconsistent Endpoints 🟡 MEDIUM
- **Description:** Inconsistent naming, response formats, or patterns
- **Impact:** Confusing API, integration difficulties
- **Check For:**
  - Mixed naming conventions (camelCase vs snake_case)
  - Inconsistent response structures
  - Different error formats across endpoints
- **Correct Approach:** API style guide, consistent patterns, OpenAPI spec
- **Discovered:** Initial checklist (2025-12-27)

#### API-002: Missing Pagination 🟠 HIGH
- **Description:** Endpoints returning unbounded result sets
- **Impact:** Performance issues, memory problems, timeouts
- **Check For:**
  - List endpoints without limit parameter
  - Queries without pagination
  - Missing "next" cursors for large datasets
- **Correct Approach:** Always paginate collections, use cursor-based for large sets
- **Discovered:** Initial checklist (2025-12-27)

---

### Dependencies

#### DEP-001: Outdated Dependencies 🟠 HIGH
- **Description:** Using old versions with known security vulnerabilities
- **Impact:** Security risks, missing bug fixes
- **Check For:**
  - npm/pip/composer audit warnings
  - Dependencies > 2 major versions behind
  - Deprecated packages still in use
- **Correct Approach:** Regular updates, automated dependency scanning
- **Discovered:** Initial checklist (2025-12-27)

#### DEP-002: Unused Dependencies 🟢 LOW
- **Description:** Dependencies installed but never imported/used
- **Impact:** Bloated bundle size, security surface area
- **Check For:**
  - Packages in package.json not imported anywhere
  - Tree-shaking not removing unused code
- **Correct Approach:** Remove unused deps, audit regularly
- **Discovered:** Initial checklist (2025-12-27)

#### DEP-003: Dependency Version Mismatch 🟠 HIGH
- **Description:** Backend and frontend using different major versions of the same library, or specifying non-existent package versions
- **Impact:** Type incompatibilities, runtime errors, developer confusion, build failures
- **Check For:**
  - Same dependency with different major versions in frontend/backend package.json
  - Package versions that don't exist in npm registry (e.g., zod@4.2.1 when only 3.x exists)
  - Type definition mismatches between projects
  - Shared validation/utility libraries with version drift
- **Correct Approach:** Use workspace/monorepo tools to enforce consistent versions, maintain shared package.json for common dependencies, verify package versions exist before committing, use exact versions (no ^ or ~) for critical shared dependencies
- **Discovered:** Review 2025-12-27 (found zod 4.2.1 in backend, 3.22.4 in frontend)

---

### Testing (Additional)

#### TEST-003: Empty Test File Stubs 🟠 HIGH
- **Description:** Test files that exist in project structure but contain only skeleton code with TODO comments, giving false impression of test coverage
- **Impact:** False confidence in test coverage, regression risk, delays finding bugs, misleading metrics
- **Check For:**
  - Test files with only `describe()` and `it()` shells
  - Test bodies containing only `// TODO: Implement actual tests`
  - High ratio of test files to actual implemented tests
  - Test coverage reports showing files but no assertions
- **Correct Approach:** Don't commit empty test stubs unless actively working on them, use test coverage tools to identify untested code, follow TDD (write tests before implementation), mark incomplete test suites clearly in documentation
- **Discovered:** Review 2025-12-27 (found 24/37 test files were empty stubs)

---

### Code Quality (Additional)

#### CODE-004: Production TODOs in Controllers 🟡 MEDIUM
- **Description:** Controllers using hardcoded mock data with TODO comments indicating incomplete integration with actual services
- **Impact:** Production code doesn't deliver full functionality, reports show fake data, users get inconsistent results
- **Check For:**
  - `// TODO:` comments in controller methods
  - Hardcoded mock objects (discProfile, phaseResults, test data, etc.)
  - Comments mentioning "will be replaced", "for now", "mock data"
  - Controllers returning static data instead of dynamic results
- **Correct Approach:** Complete service integration before deploying, use feature flags for incomplete features, fail fast with clear errors rather than serving mock data, create placeholder services that throw NotImplementedError
- **Discovered:** Review 2025-12-27 (found 12 TODOs in reportController.ts with mock DISC/phase data)

#### CODE-005: Console Logging in Production Code 🟡 MEDIUM
- **Description:** Using console.log/error/warn instead of structured logging library for production code
- **Impact:** Unstructured logs, hard to parse, no log levels, no metadata, poor production debugging, can't aggregate logs
- **Check For:**
  - `console.log`, `console.error`, `console.warn`, `console.debug` in src/ directories
  - Exclude test files and development scripts
  - Check if logging library (Winston, Pino, etc.) is installed but unused
  - Startup/config scripts using console instead of logger
- **Correct Approach:** Use structured logging library (Winston, Pino, Bunyan), include context/metadata in logs, use appropriate log levels (info, warn, error, debug), configure different transports for dev/production
- **Discovered:** Review 2025-12-27 (found 7 files using console.* with Winston already installed)

---

### Security (Additional)

#### SEC-004: CSP Unsafe-Inline in Production 🟡 MEDIUM
- **Description:** Content Security Policy allows inline scripts/styles, weakening XSS protection
- **Impact:** Reduced XSS protection, easier for attackers to inject malicious scripts
- **Check For:**
  - `'unsafe-inline'` in CSP directives
  - TODO comments about "will fix in production"
  - Missing nonce-based CSP implementation
  - Inline event handlers (onclick, etc.)
- **Correct Approach:** Implement nonce-based CSP with crypto.randomBytes, pass nonce to templates, add nonce attribute to all inline scripts/styles, remove 'unsafe-inline' directive
- **Discovered:** Review 2025-12-27 (found in middleware/security.ts:19)

---

## Review History

### 2025-12-27 17:40 - Review #1 Completed
- **New Patterns Added:** 5
  - DEP-003: Dependency Version Mismatch 🟠 HIGH
  - TEST-003: Empty Test File Stubs 🟠 HIGH
  - CODE-004: Production TODOs in Controllers 🟡 MEDIUM
  - CODE-005: Console Logging in Production Code 🟡 MEDIUM
  - SEC-004: CSP Unsafe-Inline in Production 🟡 MEDIUM
- **Findings:** 9 issues total (0 Critical, 4 High, 4 Medium, 1 Low)
- **Key Issues:** Puppeteer vulnerabilities, Zod version mismatch, 24 empty test stubs, unbounded queries
- **Review Report:** reviews/review-20251227-174038.md

### 2025-12-27 - Initial Checklist
- Created baseline checklist with common anti-patterns
- Organized into categories: Security, Architecture, Code Quality, Testing, Performance, Error Handling, API Design, Dependencies
- Established priority system (🔴🟠🟡🟢)

---

## Instructions for Autonomous Reviewer

When you run a review:

1. **Scan codebase** using the patterns defined above
2. **Check each anti-pattern** against actual code
3. **Document new findings** in review report (reviews/review-YYYYMMDD-HHMMSS.md)
4. **Add new patterns** to this checklist when you discover them
5. **Create roadmap items** for critical/high priority issues via project manager
6. **Update this checklist** with new patterns you discover

**Checklist Growth Rules:**
- Only add patterns that are objective and verifiable
- Include specific "Check For" criteria
- Explain why it's problematic
- Provide correct approach
- Tag with discovery date
- Assign appropriate priority

**Review Process:**
- Run through ALL patterns in this checklist each review
- Generate findings report with specific file:line references
- Prioritize findings by severity
- For Critical/High issues: create roadmap items via project manager
- Update this checklist with new patterns discovered
