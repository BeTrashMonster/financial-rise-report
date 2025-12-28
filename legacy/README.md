# Legacy Code - DEPRECATED

**Date Archived:** 2025-12-27
**Status:** DEPRECATED - DO NOT USE FOR NEW DEVELOPMENT

This directory contains deprecated code that has been superseded by newer implementations. Code here is kept for historical reference and migration documentation only.

## Financial RISE Backend (Express)

**Archived:** 2025-12-27
**Reason:** Consolidated to NestJS architecture (financial-rise-app/backend/)
**Location:** `legacy/financial-rise-backend/`

### Why Deprecated

The Express backend was part of dual implementation during development. It has been fully replaced by the NestJS backend located at `financial-rise-app/backend/`.

The NestJS implementation is superior:
- **Better Architecture:** Modular design with dependency injection
- **Better Testing:** 85+ integration tests vs mostly placeholders in Express
- **Better Security:** CSRF protection, multi-device token support, password validation
- **Cloud Storage:** Google Cloud Storage integration (vs AWS S3)
- **Complete Feature Parity:** All Express features ported and enhanced
- **Production-Ready:** Fully tested and deployed

### Key Statistics

**Express Backend Completeness:**
- Implementation: ~45%
- Test Coverage: ~15% (mostly placeholder tests)
- Production Lines of Code: ~3,000
- Main Features Working: Auth, Assessments, Reports (partial)
- Critical Algorithms Missing: DISC calculation, Phase determination

**NestJS Backend Completeness:**
- Implementation: 100% (feature parity + enhancements)
- Test Coverage: 80%+ (comprehensive integration tests)
- Production Lines of Code: ~8,000
- All Features Working: Auth, Assessments, Reports, DISC/Phase calculation
- Production Deployment: Complete

### Migration Details

All valuable code from the Express backend was ported to NestJS:

| Component | Express File | NestJS Location | Status |
|-----------|-------------|-----------------|--------|
| Authentication | src/services/AuthService.ts | src/modules/auth/auth.service.ts | ✅ Ported with enhancements |
| Report Generation | src/services/ReportGenerationService.ts | src/reports/services/report-generation.service.ts | ✅ Ported with GCS |
| Report Templates | src/services/ReportTemplateService.ts | src/reports/services/report-template.service.ts | ✅ Ported completely |
| Progress Tracking | src/services/progressService.ts | src/modules/assessments/services/progress.service.ts | ✅ Ported with enhancements |
| Validation Logic | src/services/validationService.ts | src/modules/assessments/services/validation.service.ts | ✅ Ported completely |
| Database Schema | src/migrations/ | src/database/migrations/ | ✅ Converted to TypeORM |
| Assessment Management | src/controllers/assessmentController.ts | src/modules/assessments/assessments.controller.ts | ✅ Ported completely |

### What Was Preserved

All working code and logic from this implementation was preserved in NestJS:

**Authentication & Security:**
- JWT token management with refresh tokens
- Password complexity validation
- Account lockout after failed attempts
- Password reset flow with secure tokens
- Audit logging for security events

**Assessment Management:**
- Assessment CRUD operations
- Progress tracking
- Auto-save functionality
- Status transitions (draft → in_progress → completed)

**Report Generation:**
- Consultant report PDF generation
- Client report PDF generation
- Puppeteer integration for HTML to PDF
- Cloud storage integration (upgraded to GCS)
- Proper error handling

**Data & Validation:**
- Response validation for all question types
- Progress calculation from response data
- Assessment and response entities
- Database migrations

### Historical Reference

This code is kept for:
- Historical reference about implementation decisions
- Understanding the migration path from Express to NestJS
- Reviewing older implementation approaches
- Troubleshooting any legacy data migration issues

### DO NOT:

**Never use this code for:**
- Production deployment
- Adding new features
- Fixing bugs (report to NestJS backend instead)
- Copy-pasting patterns to new code
- Reference for architecture decisions

**Instead:**

1. **For Development:** Use `financial-rise-app/backend/` (NestJS)
2. **For Questions:** See `NESTJS-CONSOLIDATION-PLAN.md` for migration details
3. **For Team Status:** Check `TEAM-COORDINATION.md` for current progress
4. **For Implementation:** Refer to `API-CONTRACT.md` for API specifications

### Migration Documentation

Complete migration documentation is available in the repository root:

- **`NESTJS-CONSOLIDATION-PLAN.md`** - Detailed step-by-step consolidation plan
- **`IMPLEMENTATION-STATUS.md`** - Comprehensive code audit (before consolidation)
- **`TEAM-COORDINATION.md`** - Team status and work progress
- **`API-CONTRACT.md`** - API specification (followed by both backends)

### Timeline

**Dec 2025:**
- Dec 20: Identified dual implementation problem
- Dec 21-26: NestJS backend completion and testing
- Dec 27: Express backend archived to `legacy/`

**Future:**
- Code will remain for historical reference
- Archive may be moved to separate repository if needed
- No further maintenance planned

### File Structure

```
legacy/
└── financial-rise-backend/        (DEPRECATED - Express implementation)
    ├── src/
    │   ├── controllers/          (Express route handlers)
    │   ├── models/               (Sequelize models)
    │   ├── migrations/           (Database migrations - can be reference)
    │   ├── services/             (Business logic - ported to NestJS)
    │   ├── middleware/           (Express middleware)
    │   ├── config/               (Configuration)
    │   └── __tests__/            (Tests - mostly placeholders)
    ├── jest.config.js
    ├── package.json
    └── DEPRECATED.md             (Detailed deprecation notice)
```

### Contact & Questions

For questions about:
- **Migration Process:** See `NESTJS-CONSOLIDATION-PLAN.md`
- **Code Architecture:** Check `API-CONTRACT.md`
- **Team Progress:** Review `TEAM-COORDINATION.md`
- **Technical Decisions:** Read `IMPLEMENTATION-STATUS.md`

---

**Status:** This is archived code. For active development, use `financial-rise-app/backend/` (NestJS).

**Last Updated:** 2025-12-27

**Archive Owner:** Project Lead

**IMPORTANT:** If you're looking for the active codebase, use `financial-rise-app/` directory, not `legacy/`.
