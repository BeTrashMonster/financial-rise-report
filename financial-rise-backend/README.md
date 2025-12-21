# Financial RISE Report - Backend API

## Overview

Backend API for the Financial RISE Report (Readiness Insights for Sustainable Entrepreneurship) - a web-based assessment tool for financial consultants to evaluate client business financial health and provide personalized action plans.

**Work Stream:** 6 - Assessment API & Business Logic
**Status:** Complete
**Version:** 1.0.0

## Features

### Implemented (Work Stream 6)

✅ **Assessment Management API**
- Create, read, update, delete assessments
- Auto-save functionality (< 2 second requirement)
- Progress tracking
- Status management (draft, in_progress, completed)

✅ **Questionnaire API**
- Retrieve complete questionnaire structure
- DISC personality profiling integration
- Financial phase categorization

✅ **Response Validation**
- Multiple question types (single choice, multiple choice, rating, text)
- Required field validation
- Completion validation

✅ **Authentication & Authorization**
- JWT-based authentication
- Consultant-only access control
- Rate limiting

✅ **Testing**
- 80%+ code coverage (unit tests)
- Integration tests
- Performance tests

## Technology Stack

- **Runtime:** Node.js 18 LTS+
- **Framework:** Express.js
- **Language:** TypeScript
- **Database:** PostgreSQL 14+
- **ORM:** Sequelize
- **Authentication:** JWT
- **Testing:** Jest
- **API Documentation:** Swagger/OpenAPI 3.0

## Project Structure

```
financial-rise-backend/
├── src/
│   ├── config/             # Configuration files
│   │   └── database.ts     # Database connection
│   ├── models/             # Sequelize models
│   │   ├── Assessment.ts
│   │   ├── AssessmentResponse.ts
│   │   └── index.ts
│   ├── migrations/         # Database migrations
│   │   ├── 20251220000001-create-assessments.ts
│   │   └── 20251220000002-create-assessment-responses.ts
│   ├── middleware/         # Express middleware
│   │   ├── auth.ts         # JWT authentication
│   │   ├── validation.ts   # Request validation
│   │   └── errorHandler.ts # Error handling
│   ├── routes/             # API routes
│   │   ├── assessmentRoutes.ts
│   │   ├── questionnaireRoutes.ts
│   │   └── index.ts
│   ├── controllers/        # Route controllers
│   │   ├── assessmentController.ts
│   │   └── questionnaireController.ts
│   ├── services/           # Business logic
│   │   ├── progressService.ts
│   │   ├── validationService.ts
│   │   └── questionnaireService.ts
│   ├── types/              # TypeScript types
│   │   └── index.ts
│   ├── utils/              # Utility functions
│   ├── __tests__/          # Test files
│   ├── app.ts              # Express app configuration
│   └── index.ts            # Entry point
├── package.json
├── tsconfig.json
├── jest.config.js
├── .env.example
└── README.md
```

## Setup Instructions

### Prerequisites

- Node.js 18 LTS or higher
- PostgreSQL 14 or higher
- npm 9 or higher

### Installation

1. **Clone or navigate to the repository:**
   ```bash
   cd financial-rise-backend
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Set up environment variables:**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Create PostgreSQL database:**
   ```bash
   createdb financial_rise_dev
   ```

5. **Run database migrations:**
   ```bash
   npm run migrate
   ```

### Development

```bash
# Start development server with hot reload
npm run dev

# Build TypeScript
npm run build

# Run production server
npm start
```

### Testing

```bash
# Run all tests with coverage
npm test

# Run tests in watch mode
npm run test:watch

# Run integration tests only
npm run test:integration
```

### Database Management

```bash
# Run migrations
npm run migrate

# Rollback last migration
npm run migrate:undo

# Create new migration
npm run migrate:create -- migration-name

# Run seeds
npm run seed
```

## API Endpoints

### Base URL
```
http://localhost:3000/api/v1
```

### Authentication

All endpoints require JWT authentication via `Authorization: Bearer <token>` header.

### Endpoints

#### Assessments

**Create Assessment**
```
POST /api/v1/assessments
Content-Type: application/json
Authorization: Bearer <token>

{
  "clientName": "John Doe",
  "businessName": "Acme Corp",
  "clientEmail": "john@acme.com",
  "notes": "Optional notes"
}

Response: 201 Created
```

**List Assessments**
```
GET /api/v1/assessments?status=draft&limit=50&offset=0
Authorization: Bearer <token>

Response: 200 OK
```

**Get Assessment**
```
GET /api/v1/assessments/:id
Authorization: Bearer <token>

Response: 200 OK
```

**Update Assessment (Auto-save)**
```
PATCH /api/v1/assessments/:id
Authorization: Bearer <token>

{
  "responses": [
    {
      "questionId": "uuid",
      "answer": "value",
      "notApplicable": false,
      "consultantNotes": "Notes"
    }
  ],
  "status": "in_progress"
}

Response: 200 OK
```

**Delete Assessment**
```
DELETE /api/v1/assessments/:id
Authorization: Bearer <token>

Response: 204 No Content
```

#### Questionnaire

**Get Questionnaire**
```
GET /api/v1/questionnaire
Authorization: Bearer <token>

Response: 200 OK
```

### Health Check

```
GET /health

Response: 200 OK
{
  "status": "ok",
  "timestamp": "2025-12-20T...",
  "service": "financial-rise-backend",
  "version": "v1"
}
```

## Error Handling

All errors follow consistent JSON format:

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": {}
  }
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| INVALID_REQUEST | 400 | Malformed request |
| VALIDATION_ERROR | 400 | Validation failed |
| UNAUTHORIZED | 401 | Missing/invalid auth |
| TOKEN_EXPIRED | 401 | JWT expired |
| FORBIDDEN | 403 | Insufficient permissions |
| NOT_FOUND | 404 | Resource not found |
| CONFLICT | 409 | Resource conflict |
| RATE_LIMIT_EXCEEDED | 429 | Too many requests |
| INTERNAL_ERROR | 500 | Server error |

## Performance Requirements

✅ Auto-save operations complete within 2 seconds (REQ-PERF-004)
✅ API endpoints respond within 1 second
✅ Database queries use indexes for optimization
✅ Connection pooling enabled

## Security Features

✅ JWT authentication with token expiration
✅ Helmet.js security headers
✅ CORS configuration
✅ Rate limiting (100 requests/minute)
✅ Input validation and sanitization
✅ SQL injection protection (Sequelize ORM)
✅ XSS protection

## Testing Coverage

**Target:** 80%+ code coverage
**Current:** 80%+

Test suites include:
- Unit tests for services (progress, validation)
- Unit tests for middleware (auth, validation)
- Unit tests for controllers
- Integration tests for API endpoints
- Performance tests for auto-save

## Requirements Traceability

### Functional Requirements
- ✅ REQ-ASSESS-001: Create assessments
- ✅ REQ-ASSESS-002: Generate unique IDs
- ✅ REQ-ASSESS-003: Draft status persistence
- ✅ REQ-ASSESS-004: Resume assessments
- ✅ REQ-ASSESS-005: Auto-save every 30 seconds
- ✅ REQ-ASSESS-006: Progress percentage
- ✅ REQ-ASSESS-007: Mark questions as N/A
- ✅ REQ-ASSESS-009: Validate required questions
- ✅ REQ-ASSESS-010: Record timestamps
- ✅ REQ-QUEST-001 through REQ-QUEST-010: Questionnaire

### Technical Requirements
- ✅ REQ-TECH-007: RESTful API
- ✅ REQ-TECH-008: JSON payloads
- ✅ REQ-TECH-009: API versioning (/api/v1/)
- ✅ REQ-TECH-010: HTTP status codes
- ✅ REQ-TECH-011: JWT authentication
- ✅ REQ-TECH-013: PostgreSQL database
- ✅ REQ-TECH-014: Database migrations
- ✅ REQ-TECH-015: Database indexing

### Performance Requirements
- ✅ REQ-PERF-004: Auto-save < 2 seconds

## Next Steps

### Work Stream 7 (Parallel)
- DISC calculation algorithm
- Phase determination algorithm

### Work Stream 8 (Blocked by WS6)
- Frontend assessment workflow
- Integration with assessment API

### Work Stream 11 (Blocked by WS6)
- Report generation backend
- Use assessment data for reports

## Contributing

This is part of the Financial RISE Report project. See main repository for contribution guidelines.

## License

MIT License - See LICENSE file for details

## Contact

For questions or issues, please refer to the main project repository.

---

**Implementation Status:** ✅ Complete
**Work Stream 6 Completion Date:** 2025-12-20
**Code Coverage:** 80%+
**All Tests:** Passing
**Performance Targets:** Met
