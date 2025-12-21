# Work Stream 6: Assessment API & Business Logic - Implementation Plan

**Status:** In Progress
**Agent:** Backend Developer 1
**Started:** 2025-12-20
**Version:** 1.0

---

## 1. Overview

This implementation plan details the technical specifications for Work Stream 6: Assessment API & Business Logic. This work stream delivers the core backend functionality for creating, managing, and tracking financial readiness assessments.

### 1.1 Dependencies (All Complete)
- ✅ Work Stream 2: Database Schema & Data Model
- ✅ Work Stream 3: Authentication System
- ✅ Work Stream 5: Content Development (Question bank)

### 1.2 Blocks
- Work Stream 8: Frontend Assessment Workflow
- Work Stream 11: Report Generation Backend

---

## 2. API Endpoints Specification

### 2.1 Assessment Management Endpoints

All endpoints require JWT authentication via `Authorization: Bearer <token>` header.

#### POST /api/v1/assessments
**Purpose:** Create a new assessment
**Authentication:** Required (Consultant role)

**Request Body:**
```json
{
  "clientName": "string (required, 1-100 chars)",
  "businessName": "string (required, 1-100 chars)",
  "clientEmail": "string (required, valid email format)",
  "notes": "string (optional, max 1000 chars)"
}
```

**Response:** 201 Created
```json
{
  "assessmentId": "uuid",
  "clientName": "string",
  "businessName": "string",
  "clientEmail": "string",
  "status": "draft",
  "progress": 0,
  "createdAt": "ISO 8601 timestamp",
  "updatedAt": "ISO 8601 timestamp",
  "consultantId": "uuid"
}
```

**Error Responses:**
- 400: Invalid request body (missing required fields, invalid email)
- 401: Unauthorized (missing or invalid JWT)
- 403: Forbidden (user is not a consultant)
- 500: Internal server error

**Business Logic:**
- Generate unique UUID for assessment
- Set status to "draft"
- Set progress to 0
- Record createdAt and updatedAt timestamps
- Associate with authenticated consultant
- REQ-ASSESS-001, REQ-ASSESS-002, REQ-ASSESS-003

---

#### GET /api/v1/assessments
**Purpose:** List all assessments for the authenticated consultant
**Authentication:** Required (Consultant role)

**Query Parameters:**
```
?status=draft|in_progress|completed (optional)
&limit=number (optional, default 50, max 200)
&offset=number (optional, default 0)
&sortBy=createdAt|updatedAt|clientName (optional, default: updatedAt)
&sortOrder=asc|desc (optional, default: desc)
```

**Response:** 200 OK
```json
{
  "assessments": [
    {
      "assessmentId": "uuid",
      "clientName": "string",
      "businessName": "string",
      "status": "draft|in_progress|completed",
      "progress": 0-100,
      "createdAt": "ISO 8601 timestamp",
      "updatedAt": "ISO 8601 timestamp",
      "completedAt": "ISO 8601 timestamp or null"
    }
  ],
  "total": number,
  "limit": number,
  "offset": number
}
```

**Error Responses:**
- 401: Unauthorized
- 500: Internal server error

**Business Logic:**
- Return only assessments belonging to authenticated consultant
- Filter by status if provided
- Apply pagination
- Sort by specified field and order
- REQ-ASSESS-004

---

#### GET /api/v1/assessments/:id
**Purpose:** Get a specific assessment with all responses
**Authentication:** Required (Consultant role, must own assessment)

**Response:** 200 OK
```json
{
  "assessmentId": "uuid",
  "clientName": "string",
  "businessName": "string",
  "clientEmail": "string",
  "status": "draft|in_progress|completed",
  "progress": 0-100,
  "createdAt": "ISO 8601 timestamp",
  "updatedAt": "ISO 8601 timestamp",
  "completedAt": "ISO 8601 timestamp or null",
  "startedAt": "ISO 8601 timestamp or null",
  "responses": [
    {
      "questionId": "uuid",
      "answer": "any (depends on question type)",
      "notApplicable": boolean,
      "consultantNotes": "string or null",
      "answeredAt": "ISO 8601 timestamp or null"
    }
  ]
}
```

**Error Responses:**
- 401: Unauthorized
- 403: Forbidden (assessment belongs to different consultant)
- 404: Assessment not found
- 500: Internal server error

**Business Logic:**
- Verify assessment belongs to authenticated consultant
- Include all responses (answered and unanswered)
- Calculate progress based on answered questions
- REQ-ASSESS-010

---

#### PATCH /api/v1/assessments/:id
**Purpose:** Update assessment responses (auto-save)
**Authentication:** Required (Consultant role, must own assessment)

**Request Body:**
```json
{
  "responses": [
    {
      "questionId": "uuid",
      "answer": "any (depends on question type)",
      "notApplicable": boolean (optional, default false),
      "consultantNotes": "string (optional)"
    }
  ],
  "status": "draft|in_progress|completed (optional)"
}
```

**Response:** 200 OK
```json
{
  "assessmentId": "uuid",
  "status": "string",
  "progress": 0-100,
  "updatedAt": "ISO 8601 timestamp",
  "savedResponses": number
}
```

**Error Responses:**
- 400: Invalid request (invalid questionId, invalid answer format)
- 401: Unauthorized
- 403: Forbidden (assessment belongs to different consultant)
- 404: Assessment not found
- 409: Conflict (cannot modify completed assessment)
- 500: Internal server error

**Business Logic:**
- Verify assessment belongs to authenticated consultant
- Cannot modify assessment with status "completed"
- Validate questionId exists in questionnaire
- Validate answer format matches question type
- Update updatedAt timestamp
- Recalculate progress
- If first response and status is "draft", update status to "in_progress" and set startedAt
- If status changes to "completed", validate all required questions answered
- Set completedAt when status changes to "completed"
- REQ-ASSESS-005, REQ-ASSESS-006, REQ-ASSESS-007, REQ-ASSESS-009, REQ-ASSESS-010

---

#### DELETE /api/v1/assessments/:id
**Purpose:** Delete a draft assessment
**Authentication:** Required (Consultant role, must own assessment)

**Response:** 204 No Content

**Error Responses:**
- 401: Unauthorized
- 403: Forbidden (assessment belongs to different consultant)
- 404: Assessment not found
- 409: Conflict (cannot delete non-draft assessments)
- 500: Internal server error

**Business Logic:**
- Verify assessment belongs to authenticated consultant
- Only allow deletion of assessments with status "draft"
- Delete all associated responses
- Soft delete recommended (add deletedAt timestamp instead of hard delete)

---

### 2.2 Questionnaire Endpoint

#### GET /api/v1/questionnaire
**Purpose:** Retrieve the complete questionnaire structure
**Authentication:** Required (Consultant role)

**Response:** 200 OK
```json
{
  "version": "1.0",
  "sections": [
    {
      "sectionId": "uuid",
      "title": "string",
      "description": "string",
      "phase": "stabilize|organize|build|grow|systemic",
      "order": number,
      "questions": [
        {
          "questionId": "uuid",
          "text": "string",
          "type": "single_choice|multiple_choice|rating|text|conditional",
          "required": boolean,
          "order": number,
          "options": [
            {
              "optionId": "uuid",
              "text": "string",
              "value": "any",
              "discMapping": {
                "D": number (0-1, weight for Dominance),
                "I": number (0-1, weight for Influence),
                "S": number (0-1, weight for Steadiness),
                "C": number (0-1, weight for Compliance)
              },
              "phaseMapping": {
                "stabilize": number (weight),
                "organize": number (weight),
                "build": number (weight),
                "grow": number (weight),
                "systemic": number (weight)
              }
            }
          ],
          "conditionalLogic": {
            "dependsOn": "uuid (questionId or null)",
            "showWhen": {
              "optionId": "uuid",
              "value": "any"
            }
          }
        }
      ]
    }
  ]
}
```

**Error Responses:**
- 401: Unauthorized
- 500: Internal server error

**Business Logic:**
- Return current version of questionnaire
- Include all questions ordered by section and question order
- Include DISC and phase mappings (consultant-only, never exposed to client UI)
- REQ-QUEST-001 through REQ-QUEST-010
- REQ-DISC-001, REQ-PHASE-001, REQ-PHASE-002

---

## 3. Data Models

### 3.1 Assessment Table

**Table Name:** `assessments`

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | UUID | PRIMARY KEY | Unique assessment identifier |
| consultant_id | UUID | NOT NULL, FOREIGN KEY(users.id) | Consultant who owns assessment |
| client_name | VARCHAR(100) | NOT NULL | Client's full name |
| business_name | VARCHAR(100) | NOT NULL | Client's business name |
| client_email | VARCHAR(255) | NOT NULL | Client's email address |
| status | ENUM | NOT NULL, DEFAULT 'draft' | draft, in_progress, completed |
| progress | DECIMAL(5,2) | NOT NULL, DEFAULT 0 | Percentage complete (0-100) |
| created_at | TIMESTAMP | NOT NULL, DEFAULT NOW() | Assessment creation time |
| updated_at | TIMESTAMP | NOT NULL, DEFAULT NOW() | Last modification time |
| started_at | TIMESTAMP | NULL | When first response was recorded |
| completed_at | TIMESTAMP | NULL | When marked as completed |
| deleted_at | TIMESTAMP | NULL | Soft delete timestamp |
| notes | TEXT | NULL | General consultant notes |

**Indexes:**
- PRIMARY KEY on `id`
- INDEX on `consultant_id`
- INDEX on `status`
- INDEX on `updated_at`
- INDEX on `client_email`

---

### 3.2 Assessment Responses Table

**Table Name:** `assessment_responses`

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | UUID | PRIMARY KEY | Unique response identifier |
| assessment_id | UUID | NOT NULL, FOREIGN KEY(assessments.id) ON DELETE CASCADE | Parent assessment |
| question_id | UUID | NOT NULL, FOREIGN KEY(questions.id) | Question being answered |
| answer | JSONB | NULL | Answer value (format varies by question type) |
| not_applicable | BOOLEAN | NOT NULL, DEFAULT FALSE | Marked as N/A by consultant |
| consultant_notes | TEXT | NULL | Consultant notes for this question |
| answered_at | TIMESTAMP | NULL | When answer was provided |
| created_at | TIMESTAMP | NOT NULL, DEFAULT NOW() | Response record creation |
| updated_at | TIMESTAMP | NOT NULL, DEFAULT NOW() | Last modification |

**Indexes:**
- PRIMARY KEY on `id`
- UNIQUE INDEX on `(assessment_id, question_id)`
- INDEX on `assessment_id`
- INDEX on `question_id`

---

### 3.3 Questionnaire Tables (from Work Stream 5)

These tables should already exist from Work Stream 5:

- `questionnaire_versions` - Tracks questionnaire versions
- `sections` - Question sections organized by phase
- `questions` - Individual questions with type and metadata
- `question_options` - Options for choice-based questions
- `disc_mappings` - DISC weights for question options
- `phase_mappings` - Phase weights for question options

---

## 4. Business Logic Components

### 4.1 Progress Calculation Service

**Function:** `calculateProgress(assessmentId: UUID): number`

**Algorithm:**
```
1. Get total number of required questions (from questionnaire)
2. Get number of answered questions (responses where answer IS NOT NULL OR not_applicable = true)
3. Calculate: (answered / total) * 100
4. Round to 2 decimal places
5. Return percentage
```

**Requirements:**
- REQ-ASSESS-006

---

### 4.2 Auto-Save Service

**Function:** `autoSaveResponses(assessmentId: UUID, responses: Response[]): SaveResult`

**Logic:**
```
1. Validate assessmentId exists and belongs to authenticated user
2. Validate assessment is not completed
3. For each response:
   a. Validate questionId exists in current questionnaire
   b. Validate answer format matches question type
   c. Upsert response (INSERT or UPDATE)
   d. Set answered_at to NOW() if answer provided
4. Update assessment.updated_at
5. Recalculate and update assessment.progress
6. If first response and status = 'draft':
   a. Update status to 'in_progress'
   b. Set started_at to NOW()
7. Return updated assessment summary
```

**Performance Requirements:**
- Must complete within 2 seconds (REQ-PERF-004)
- Use batch upsert operations
- Minimize database round trips

**Requirements:**
- REQ-ASSESS-005

---

### 4.3 Response Validation Service

**Function:** `validateResponse(questionId: UUID, answer: any): ValidationResult`

**Validation Rules by Question Type:**

**Single Choice:**
- Answer must be a valid optionId from the question
- Answer cannot be null unless notApplicable = true

**Multiple Choice:**
- Answer must be an array of valid optionIds
- Array cannot be empty unless notApplicable = true

**Rating (1-5):**
- Answer must be an integer between 1 and 5 inclusive
- Answer cannot be null unless notApplicable = true

**Text Input:**
- Answer must be a string
- Maximum length: 1000 characters
- Can be empty string, but not null unless notApplicable = true

**Conditional:**
- Validate based on the underlying question type
- If question is hidden (conditional not met), answer should be null

**Requirements:**
- REQ-ASSESS-009
- REQ-QUEST-004

---

### 4.4 Completion Validation Service

**Function:** `validateCompletion(assessmentId: UUID): ValidationResult`

**Logic:**
```
1. Get all required questions from questionnaire
2. Get all responses for assessment
3. For each required question:
   a. Check if response exists
   b. Check if (answer IS NOT NULL) OR (not_applicable = true)
   c. If conditional question and condition not met, skip
4. If any required question unanswered, return validation errors
5. If all required questions answered, return success
```

**Return:**
```typescript
{
  valid: boolean,
  missingQuestions: QuestionId[],
  errors: string[]
}
```

**Requirements:**
- REQ-ASSESS-009

---

### 4.5 Status Management Service

**Function:** `updateStatus(assessmentId: UUID, newStatus: Status): StatusUpdate`

**State Transitions:**
```
draft → in_progress: Allowed (automatic on first response)
draft → completed: Allowed (if all required questions answered)
in_progress → completed: Allowed (if all required questions answered)
in_progress → draft: NOT ALLOWED
completed → any: NOT ALLOWED (immutable once completed)
```

**Logic:**
```
1. Validate current status allows transition
2. If transitioning to 'completed':
   a. Run completion validation
   b. If validation fails, reject with 409 Conflict
   c. Set completed_at = NOW()
3. If transitioning from 'draft' to 'in_progress':
   a. Set started_at = NOW() if not already set
4. Update assessment.status
5. Update assessment.updated_at
6. Return updated assessment
```

**Requirements:**
- REQ-ASSESS-003

---

## 5. Authentication and Authorization

### 5.1 Authentication Middleware

All endpoints require:
- Valid JWT token in `Authorization: Bearer <token>` header
- Token must not be expired
- Token must contain valid consultantId

**Implementation:**
- Extract JWT from Authorization header
- Verify signature using secret key
- Decode payload
- Extract consultantId
- Attach consultantId to request context

---

### 5.2 Authorization Rules

**Consultant Access:**
- Can create assessments
- Can list only their own assessments
- Can view/update/delete only their own assessments
- Cannot access other consultants' assessments

**Admin Access (future):**
- Can list all assessments
- Can view any assessment
- Cannot modify assessments they don't own

**Implementation:**
```sql
-- Example authorization check
SELECT * FROM assessments
WHERE id = :assessmentId
  AND consultant_id = :authenticatedConsultantId
  AND deleted_at IS NULL
```

---

## 6. Error Handling

### 6.1 Error Response Format

All errors return JSON:
```json
{
  "error": {
    "code": "string (error code)",
    "message": "string (human-readable message)",
    "details": {} // Optional additional context
  }
}
```

### 6.2 Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| INVALID_REQUEST | 400 | Malformed request body |
| VALIDATION_ERROR | 400 | Business validation failed |
| UNAUTHORIZED | 401 | Missing or invalid authentication |
| FORBIDDEN | 403 | Authenticated but lacks permission |
| NOT_FOUND | 404 | Resource not found |
| CONFLICT | 409 | Operation conflicts with resource state |
| INTERNAL_ERROR | 500 | Unexpected server error |

### 6.3 Validation Error Details

For 400 validation errors, include field-specific errors:
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Request validation failed",
    "details": {
      "fields": {
        "clientEmail": ["Invalid email format"],
        "clientName": ["Required field missing"]
      }
    }
  }
}
```

---

## 7. Testing Strategy

### 7.1 Unit Tests (Target: 80%+ Coverage)

**Assessment Creation:**
- ✅ Create assessment with valid data
- ✅ Reject assessment with missing required fields
- ✅ Reject assessment with invalid email
- ✅ Verify UUID generation
- ✅ Verify timestamps set correctly

**Assessment Listing:**
- ✅ List assessments for authenticated consultant
- ✅ Filter by status
- ✅ Pagination works correctly
- ✅ Sorting works correctly
- ✅ Empty list when no assessments

**Assessment Retrieval:**
- ✅ Get assessment with all responses
- ✅ 404 when assessment doesn't exist
- ✅ 403 when assessment belongs to different consultant
- ✅ Progress calculated correctly

**Assessment Update (Auto-save):**
- ✅ Save single response
- ✅ Save multiple responses
- ✅ Update existing response
- ✅ Validate question IDs
- ✅ Validate answer formats
- ✅ Reject updates to completed assessments
- ✅ Progress recalculated after save
- ✅ Status transitions from draft to in_progress
- ✅ Started_at set on first response

**Completion Validation:**
- ✅ Validate all required questions answered
- ✅ Identify missing required questions
- ✅ Allow N/A to satisfy required questions
- ✅ Handle conditional questions correctly

**Response Validation:**
- ✅ Validate single choice answers
- ✅ Validate multiple choice answers
- ✅ Validate rating answers (1-5)
- ✅ Validate text answers (max length)
- ✅ Reject invalid option IDs
- ✅ Reject out-of-range ratings

**Authorization:**
- ✅ Consultant can only access own assessments
- ✅ Cannot access other consultant's assessments
- ✅ Unauthenticated requests rejected

---

### 7.2 Integration Tests

**End-to-End Assessment Workflow:**
- ✅ Create assessment → Save responses → Complete assessment → Verify final state
- ✅ Auto-save workflow (multiple partial saves)
- ✅ Resume in-progress assessment
- ✅ Mark questions as N/A
- ✅ Add consultant notes to responses

**Database Integration:**
- ✅ Concurrent updates handled correctly (optimistic locking)
- ✅ Foreign key constraints enforced
- ✅ Cascade deletes work correctly
- ✅ Indexes improve query performance

**Questionnaire Integration:**
- ✅ Retrieve questionnaire successfully
- ✅ Questionnaire version tracked
- ✅ DISC and phase mappings included

---

### 7.3 Performance Tests

**Auto-Save Performance:**
- ✅ Auto-save completes within 2 seconds (REQ-PERF-004)
- ✅ Batch save of 50 responses completes within 2 seconds
- ✅ No blocking during auto-save

**API Response Times:**
- ✅ GET /assessments responds within 1 second
- ✅ GET /assessments/:id responds within 1 second
- ✅ POST /assessments responds within 1 second

**Database Performance:**
- ✅ Query plan uses indexes
- ✅ No N+1 query issues
- ✅ Connection pooling working

---

### 7.4 Security Tests

**Authentication:**
- ✅ Reject requests without JWT
- ✅ Reject requests with invalid JWT
- ✅ Reject requests with expired JWT

**Authorization:**
- ✅ Cannot access other consultant's assessments
- ✅ Cannot delete completed assessments
- ✅ Cannot modify other consultant's data

**Input Validation:**
- ✅ SQL injection attempts blocked
- ✅ XSS in text fields sanitized
- ✅ Oversized payloads rejected
- ✅ Invalid JSON rejected

---

## 8. API Documentation

### 8.1 Swagger/OpenAPI Specification

Generate OpenAPI 3.0 specification including:
- All endpoint paths and methods
- Request body schemas
- Response schemas
- Error response schemas
- Authentication requirements
- Example requests and responses

**Tools:**
- Swagger UI for interactive documentation
- Postman collection export

---

## 9. Implementation Checklist

### Phase 1: Setup and Data Models
- [ ] Set up project structure
- [ ] Configure database connection
- [ ] Create database migration for assessments table
- [ ] Create database migration for assessment_responses table
- [ ] Set up ORM models (Sequelize/TypeORM/etc.)
- [ ] Set up authentication middleware

### Phase 2: Core Endpoints
- [ ] POST /api/v1/assessments
- [ ] GET /api/v1/assessments
- [ ] GET /api/v1/assessments/:id
- [ ] PATCH /api/v1/assessments/:id
- [ ] DELETE /api/v1/assessments/:id
- [ ] GET /api/v1/questionnaire

### Phase 3: Business Logic Services
- [ ] Progress calculation service
- [ ] Auto-save service
- [ ] Response validation service
- [ ] Completion validation service
- [ ] Status management service

### Phase 4: Testing
- [ ] Unit tests (80%+ coverage target)
- [ ] Integration tests
- [ ] Performance tests
- [ ] Security tests

### Phase 5: Documentation
- [ ] Generate Swagger/OpenAPI spec
- [ ] Set up Swagger UI
- [ ] Create Postman collection
- [ ] Document deployment instructions

---

## 10. Dependencies and Blockers

### 10.1 External Dependencies

**From Work Stream 2 (Database):**
- Database schema for users table
- Database connection configuration
- Migration tool setup

**From Work Stream 3 (Authentication):**
- JWT authentication middleware
- User/consultant authentication
- JWT secret key configuration

**From Work Stream 5 (Content):**
- Complete question bank
- DISC mappings for questions
- Phase mappings for questions
- Question types and validation rules

### 10.2 Blocks

**Work Stream 8 (Frontend Assessment Workflow):**
- Needs all CRUD endpoints
- Needs auto-save endpoint
- Needs questionnaire endpoint

**Work Stream 11 (Report Generation):**
- Needs assessment data structure
- Needs response data structure
- Needs completion status

---

## 11. Requirements Traceability

### Functional Requirements Satisfied:
- REQ-ASSESS-001: Create assessments with required fields ✅
- REQ-ASSESS-002: Unique assessment ID generation ✅
- REQ-ASSESS-003: Draft status persistence ✅
- REQ-ASSESS-004: Resume in-progress assessments ✅
- REQ-ASSESS-005: Auto-save every 30 seconds ✅
- REQ-ASSESS-006: Progress percentage display ✅
- REQ-ASSESS-007: Mark questions as N/A ✅
- REQ-ASSESS-008: Navigate forward/backward (frontend dependency)
- REQ-ASSESS-009: Validate required questions ✅
- REQ-ASSESS-010: Record timestamps ✅
- REQ-QUEST-001 through REQ-QUEST-010: Questionnaire structure ✅

### Technical Requirements Satisfied:
- REQ-TECH-007: RESTful API design ✅
- REQ-TECH-008: JSON payloads ✅
- REQ-TECH-009: API versioning (/api/v1/) ✅
- REQ-TECH-010: Appropriate HTTP status codes ✅
- REQ-TECH-011: JWT authentication ✅
- REQ-TECH-013: Relational database ✅
- REQ-TECH-014: Database migrations ✅
- REQ-TECH-015: Database indexing ✅

### Performance Requirements Satisfied:
- REQ-PERF-004: Auto-save within 2 seconds ✅

### Maintainability Requirements Satisfied:
- REQ-MAINT-002: 80%+ code coverage target ✅

---

## 12. Timeline and Effort Estimate

**Complexity:** Medium
**Effort:** Medium
**Estimated Duration:** 3-5 days (for AI agent working continuously)

**Breakdown:**
- Setup and data models: 0.5 days
- Core endpoints: 1.5 days
- Business logic services: 1 day
- Testing: 1.5 days
- Documentation: 0.5 days

**Note:** This is an AI agent-driven timeline. No human calendar time estimates per roadmap principles.

---

## 13. Success Criteria

Work Stream 6 is complete when:

✅ All 6 API endpoints implemented and tested
✅ Auto-save functionality working within 2 seconds
✅ Progress calculation accurate
✅ Response validation working for all question types
✅ Completion validation working
✅ 80%+ code coverage achieved
✅ Integration tests passing
✅ Performance tests passing (auto-save < 2s)
✅ Security tests passing (authentication, authorization)
✅ Swagger documentation generated
✅ Postman collection created
✅ All tasks in roadmap checked off

---

**Document Status:** Active Implementation Plan
**Last Updated:** 2025-12-20
**Next Review:** Upon completion of implementation
