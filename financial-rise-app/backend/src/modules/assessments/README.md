# Assessments Module

## Overview

The Assessments Module provides comprehensive API endpoints and business logic for managing financial readiness assessments in the Financial RISE Report application. This module follows Test-Driven Development (TDD) principles and implements RESTful API design patterns.

## Features

- **CRUD Operations**: Create, Read, Update, and Delete assessments
- **Auto-save Support**: Automatic progress tracking and response persistence
- **Progress Calculation**: Real-time progress tracking based on answered questions
- **Status Management**: Draft → In Progress → Completed workflow
- **Archive Functionality**: Archive completed assessments to keep dashboard clean
- **Response Management**: Save and retrieve assessment responses
- **Role-Based Access Control**: Consultants can only access their own assessments
- **Soft Delete**: Draft assessments can be deleted (soft delete)

## API Endpoints

### Assessment Management

```
POST   /api/v1/assessments              - Create new assessment
GET    /api/v1/assessments              - List all assessments (with optional archived filter)
GET    /api/v1/assessments/:id          - Get specific assessment with responses
PATCH  /api/v1/assessments/:id          - Update assessment (supports auto-save)
DELETE /api/v1/assessments/:id          - Delete draft assessment (soft delete)
PATCH  /api/v1/assessments/:id/archive  - Archive completed assessment
PATCH  /api/v1/assessments/:id/restore  - Restore archived assessment
```

### Response Management

```
POST   /api/v1/assessments/:id/responses     - Save/update response to question
GET    /api/v1/assessments/:id/responses     - Get all responses for assessment
```

## Data Transfer Objects (DTOs)

### CreateAssessmentDto
- `clientName` (required): Client full name (2-100 chars)
- `clientBusinessName` (required): Business name (2-200 chars)
- `clientEmail` (required): Valid email address
- `entityType` (optional): Business entity type (LLC, S-Corp, etc.)

### UpdateAssessmentDto
All fields are optional:
- `clientName`: Update client name
- `clientBusinessName`: Update business name
- `clientEmail`: Update email
- `status`: Update status (draft, in_progress, completed)
- `entityType`: Update entity type
- `isSCorpOnPayroll`: Conditional S-Corp payroll flag
- `confidenceBefore`: Confidence level before assessment (1-10)
- `confidenceAfter`: Confidence level after assessment (1-10)

### SaveResponseDto
- `questionId` (required): UUID of the question
- `answerValue` (optional): Text answer
- `answerNumeric` (optional): Numeric answer for ratings
- `isNotApplicable` (optional): Mark question as N/A
- `consultantNotes` (optional): Private consultant notes

### AssessmentResponseDto
Complete assessment data including:
- All assessment fields
- Progress percentage (0-100)
- Status timestamps (started, completed, archived)
- Embedded responses (optional)

## Business Logic

### Progress Calculation
```typescript
progressPercentage = (answeredQuestions / totalQuestions) * 100
```

Progress is automatically updated whenever a response is saved.

### Status Transitions
1. **DRAFT → IN_PROGRESS**: Auto-sets `startedAt` timestamp
2. **IN_PROGRESS → COMPLETED**: Auto-sets `completedAt` timestamp

### Deletion Rules
- Only **DRAFT** assessments can be deleted
- Completed assessments should be archived instead
- Deletion is a soft delete (sets `deletedAt` timestamp)

### Archive Functionality
- Archive completed assessments to clean up the dashboard
- Archived assessments are hidden by default
- Can be restored at any time
- Use query parameter `?archived=true` to view archived items

## Authorization

All endpoints require:
- Valid JWT token (Bearer authentication)
- User role: CONSULTANT or ADMIN
- Consultants can only access their own assessments

## Testing

### Unit Tests
- **AssessmentsService**: 100% coverage of business logic
  - CRUD operations
  - Progress calculation
  - Status management
  - Authorization checks
  - Edge cases (empty data, invalid states)

### Integration Tests
- **AssessmentsController**: HTTP endpoint testing
  - Request/response validation
  - Auth guard integration
  - DTO validation
  - Error handling

### Running Tests
```bash
npm test -- assessments
npm test -- assessments --coverage
```

### Coverage Requirements
- Minimum 80% code coverage (REQ-MAINT-002)
- All business logic paths tested
- Error scenarios covered

## Usage Examples

### Create Assessment
```typescript
POST /api/v1/assessments
Content-Type: application/json
Authorization: Bearer <token>

{
  "clientName": "John Smith",
  "clientBusinessName": "Smith Consulting LLC",
  "clientEmail": "john@example.com",
  "entityType": "S-Corp"
}
```

### Save Response (Auto-save)
```typescript
POST /api/v1/assessments/123e4567-e89b-12d3-a456-426614174000/responses
Content-Type: application/json
Authorization: Bearer <token>

{
  "questionId": "456e7890-e89b-12d3-a456-426614174000",
  "answerValue": "Yes",
  "consultantNotes": "Client has good processes in place"
}
```

### Update Assessment Status
```typescript
PATCH /api/v1/assessments/123e4567-e89b-12d3-a456-426614174000
Content-Type: application/json
Authorization: Bearer <token>

{
  "status": "completed",
  "confidenceAfter": 8
}
```

## Dependencies

- `@nestjs/common`: Core NestJS functionality
- `@nestjs/typeorm`: TypeORM integration
- `@nestjs/swagger`: API documentation
- `class-validator`: DTO validation
- `class-transformer`: Data transformation

## Related Modules

- **QuestionsModule**: Provides questionnaire data
- **AuthModule**: Authentication and authorization
- **UsersModule**: User management
- **ReportsModule**: Report generation (depends on Assessments)
- **AlgorithmsModule**: DISC & Phase determination (depends on Assessments)

## Error Handling

Common error responses:
- `400 Bad Request`: Invalid input data, trying to delete non-draft assessment
- `401 Unauthorized`: Missing or invalid JWT token
- `403 Forbidden`: Trying to access another consultant's assessment
- `404 Not Found`: Assessment not found

## Performance Considerations

- Lazy loading: Responses are only loaded when requested (`findOne` with relations)
- Indexed queries: consultantId, status, createdAt are indexed
- Bulk operations: Not yet implemented (Phase 2 feature)

## Future Enhancements (Phase 2+)

- Bulk response saving
- Assessment templates
- Duplicate assessment functionality
- Assessment sharing between consultants
- Advanced filtering (by client name, date range, etc.)
- Search functionality

## Compliance

- **RBAC**: Consultants can only access their own data (REQ-SEC-002)
- **Data Privacy**: Soft deletes preserve data audit trail (REQ-SEC-005)
- **Input Validation**: All DTOs use class-validator (REQ-SEC-003)

## Support

For questions or issues, please refer to:
- Main project README: `../../README.md`
- Requirements specification: `../../../../../plans/requirements.md`
- API documentation: Available via Swagger UI at `/api/docs` (when server is running)
