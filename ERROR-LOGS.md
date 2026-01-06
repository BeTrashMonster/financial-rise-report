# Financial RISE Report - Error Logs & Lessons Learned

**Last Updated:** 2026-01-06
**Project:** Financial RISE Report - Production Deployment
**Status:** Production Live ✅

---

## Production Environment

**Live Site:** https://getoffthemoneyshametrain.com
**Production VM:** `financial-rise-prod-vm` (34.72.61.170)
**Cloud SQL:** PostgreSQL 14 with Private IP (ZONAL)
**HTTPS:** Caddy automatic SSL with Let's Encrypt
**Monthly Cost:** $103 (budget optimized)

---

## Key Lessons Learned

### 1. Deployment & CI/CD

**Lesson:** Always use GitHub Actions for production deployment, not manual builds.
- Commit and push to `main` branch triggers automatic build and deployment via `.github/workflows/deploy-gcp.yml`
- Manual deployments are error-prone and bypass the tested CI/CD pipeline
- Check GitHub Actions status before attempting manual fixes

**Lesson:** Docker multi-stage builds only copy explicitly specified files to production.
- Source files (`scripts/`, `content/`) must be explicitly copied in Dockerfile
- Production images need `tsconfig.json` if running TypeScript files
- Dev dependencies (like `ts-node`) must be installed separately if needed in production

**Lesson:** Container name conflicts occur when deployment scripts don't clean up properly.
- Always remove old containers before creating new ones with same name
- Use `docker-compose down` before `docker-compose up` in deployment scripts

### 2. TypeScript & Type Safety

**Lesson:** Check interface definitions before accessing nested properties.
- `QuestionResponse` has nested `answer` object - access via `response.answer.value`, not `response.value`
- TypeScript errors are compiler hints - read them carefully before making changes

**Lesson:** Maintain single source of truth for shared types.
- Duplicate type definitions (enum vs type alias) cause import conflicts
- Use type aliases for union types instead of enums to avoid module boundary issues
- Import shared types from a single canonical location

**Lesson:** TypeScript's strict type checking prevents runtime bugs.
- Enum and type alias are incompatible even with identical values
- Type errors during build catch issues that would fail silently at runtime

### 3. Database Operations

**Lesson:** Production database credentials should never be in git.
- `.env` files are correctly gitignored for security
- Use environment variables or Secret Manager for production credentials
- Docker containers receive credentials via docker-compose environment variables

**Lesson:** Running seed scripts in production requires careful planning.
- Seed scripts need access to source files, not just compiled code
- TypeScript execution in production needs ts-node, tsconfig.json, and source files
- Destructive operations (like DELETE FROM) should have interactive confirmation prompts

**Lesson:** Environment variable naming conventions must be consistent.
- Docker-compose sets `DATABASE_*` variables (DATABASE_HOST, DATABASE_PASSWORD, etc.)
- Local .env files may use `DB_*` variables (DB_HOST, DB_PASSWORD, etc.)
- Scripts must check both naming patterns: `process.env.DATABASE_HOST || process.env.DB_HOST`
- Document which naming convention is canonical for the project

### 4. SSH & Remote Access

**Lesson:** Large pastes into SSH sessions often fail or corrupt.
- SSH doesn't handle large clipboard pastes reliably
- Use alternative methods: scp, git clone, base64 encoding, or Python generation
- Break large content into smaller chunks if pasting is unavoidable

**Lesson:** PowerShell execution policies block scripts on Windows.
- Use `powershell -ExecutionPolicy Bypass -File script.ps1` for one-time execution
- Or set permanently: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`
- SSH is more reliable than PowerShell for production operations

### 5. Testing & Validation

**Lesson:** Frontend validation must handle all edge cases.
- Network failures: implement retry logic with exponential backoff
- Malformed data: validate question structure before rendering
- Offline detection: use `navigator.onLine` and listen for online events
- Empty responses: handle gracefully without crashing

**Lesson:** Test mocks must accurately simulate production environment.
- Mock data should match production data structures exactly
- Security properties (headers, CORS) need realistic mocks
- Test environment should mirror production behavior

### 6. Code Organization

**Lesson:** Avoid over-engineering - implement only what's requested.
- Don't add features, refactoring, or "improvements" beyond requirements
- Don't add error handling for scenarios that can't happen
- Three similar lines of code is better than premature abstraction

**Lesson:** Delete unused code completely, don't leave breadcrumbs.
- No backwards-compatibility hacks like `_unused` variables or `// removed` comments
- Clean deletions are better than commented-out code
- Git history preserves everything - no need to keep dead code

### 7. Debugging Process

**Lesson:** Always check existing documentation before trying new solutions.
- ERROR-LOGS.md documents past solutions - read it first
- GitHub Actions workflows show automated deployment process
- Don't reinvent solutions that already exist and work

**Lesson:** Incremental problem-solving wastes time.
- Identify ALL requirements before making first commit
- One deployment is better than three sequential fixes
- Check dependencies, configurations, and file inclusions upfront

**Lesson:** Read error messages completely.
- Stack traces show exact file and line numbers
- Error messages explain what's missing or incompatible
- Following the error path saves hours of guessing

### 8. Project Management

**Lesson:** Document errors and resolutions immediately.
- Future problems often have similar root causes
- Error logs prevent repeating the same mistakes
- Keep logs clean and focused on lessons, not raw error output

**Lesson:** Time estimates in roadmaps lead to scope creep.
- Focus on what needs to be done, not when
- Break work into dependency levels, not time blocks
- Let users decide scheduling based on priority

---

## Common Error Patterns

### Pattern: Missing Dependencies in Production
**Symptom:** Module not found errors in production container
**Root Cause:** Dev dependency not installed in production
**Solution:** Add to production dependencies or install separately in Dockerfile

### Pattern: TypeScript Compilation Failures
**Symptom:** Property doesn't exist on type, type not assignable
**Root Cause:** Incorrect type usage or duplicate type definitions
**Solution:** Import correct types, check interface definitions, use single source of truth

### Pattern: Docker File Not Found
**Symptom:** `ls: /app/directory: No such file or directory`
**Root Cause:** Files not copied in Dockerfile
**Solution:** Add `COPY --from=builder /app/directory ./directory` to Dockerfile

### Pattern: SSH Connection Issues
**Symptom:** Connection timeouts, paste corruption, session drops
**Root Cause:** Network issues, large data transfers, VPN routing
**Solution:** Use scp, git, or generate files on server instead of pasting

### Pattern: Container Name Conflicts
**Symptom:** `The container name is already in use`
**Root Cause:** Deployment script doesn't remove old containers
**Solution:** Add `docker-compose down` before `docker-compose up` in deployment

---

## Resolution Times

**Total Issues Documented:** 18
**Average Resolution Time:** 1-2 hours
**Longest Issue:** 5 hours (47-question seed deployment - circular problem solving)
**Quickest Issue:** 10 minutes (simple TypeScript type fixes)

---

## Current Status

✅ All builds passing
✅ GitHub Actions deployment working
✅ Backend container includes seed scripts and content
✅ 47-question structure seeded to production database
✅ Ready for end-to-end testing

**Next:** Test new assessment workflow with BUILD-007 (multiple_choice) and SYS-009 (rating) questions
