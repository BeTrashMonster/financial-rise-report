# Questions Module

## Overview

The Questions Module provides API endpoints for retrieving the Financial RISE assessment questionnaire. This module manages the complete set of questions used to evaluate client financial readiness across 5 phases (Stabilize, Organize, Build, Grow, Systemic) plus DISC personality profiling.

## Features

- **Complete Questionnaire**: Retrieve all assessment questions in order
- **DISC Privacy**: Hide DISC questions from client view (REQ-QUEST-003)
- **Section Filtering**: Get questions by financial phase
- **Conditional Logic Support**: Retrieve conditional questions (Phase 3 feature)
- **Non-conditional Focus**: Only non-conditional questions shown by default
- **Ordered Results**: Questions returned in correct order (by `orderIndex`)

## API Endpoints

```
GET /api/v1/questionnaire                      - Get complete questionnaire
GET /api/v1/questionnaire/sections/:section    - Get questions by section/phase
GET /api/v1/questionnaire/conditional/:parentId - Get conditional questions (Phase 3)
```

## Query Parameters

### GET /api/v1/questionnaire
- `includeDisc` (boolean, optional, default: `true`)
  - `true`: Include DISC questions (consultant view)
  - `false`: Exclude DISC questions (client view - REQ-QUEST-003)

## Question Sections

Questions are organized into the following sections:

1. **stabilize**: Basic financial health and compliance
2. **organize**: Foundational systems setup
3. **build**: Operational processes and SOPs
4. **grow**: Strategic planning and forecasting
5. **systemic**: Financial literacy and report interpretation
6. **disc**: Personality profiling (hidden from clients)
7. **metadata**: Basic client information

## Data Structure

### QuestionResponseDto

```typescript
{
  id: string;                    // UUID
  questionText: string;          // The question
  questionType: QuestionType;    // single_choice, multiple_choice, rating, text
  section: QuestionSection;      // stabilize, organize, build, grow, systemic, disc, metadata
  orderIndex: number;            // Display order
  isRequired: boolean;           // Whether question is mandatory
  isConditional: boolean;        // Whether question is conditional
  conditionalParentId?: string;  // Parent question ID (if conditional)
  conditionalTriggerValue?: string; // Value that triggers this question
  answerOptions?: AnswerOption[]; // Options for choice questions
  helpText?: string;             // Additional help text
  createdAt: Date;
  updatedAt: Date;
}
```

### AnswerOption

```typescript
{
  value: string;  // Internal value
  label: string;  // Display label
}
```

### QuestionnaireResponseDto

```typescript
{
  questions: QuestionResponseDto[];  // Array of questions
  total: number;                     // Total count
}
```

## Question Types

- **single_choice**: Radio buttons (one selection)
- **multiple_choice**: Checkboxes (multiple selections)
- **rating**: Numeric scale (e.g., 1-10)
- **text**: Free-form text input

## Requirements Compliance

### REQ-QUEST-002: Minimum Question Count
The questionnaire must contain at least 12 DISC questions for statistical reliability.

### REQ-QUEST-003: DISC Privacy
DISC questions **MUST** be hidden from clients during assessment. Only consultants can see these questions for profiling purposes.

### REQ-QUEST-010: Conditional Questions
Entity type question triggers conditional follow-up:
- If entity type = "S-Corp" → Show "Are you on S-Corp payroll?" question
- Implemented via `conditionalParentId` and `conditionalTriggerValue`

## Business Logic

### DISC Question Filtering

```typescript
// Consultant view - includes all questions
GET /api/v1/questionnaire?includeDisc=true

// Client view - excludes DISC questions
GET /api/v1/questionnaire?includeDisc=false
```

This ensures clients never see DISC questions during assessment, maintaining the integrity of personality profiling (REQ-QUEST-003).

### Conditional Questions (Phase 3)

Conditional questions are:
1. Hidden by default (`isConditional: true`)
2. Only shown when parent question has specific answer value
3. Retrieved via dedicated endpoint for dynamic display

Example:
```typescript
// Get conditional questions for entity type question
GET /api/v1/questionnaire/conditional/entity-type-question-id

// Returns S-Corp payroll question if parent answer is "S-Corp"
```

## Authorization

All endpoints require:
- Valid JWT token (Bearer authentication)
- User role: CONSULTANT or ADMIN

## Testing

### Unit Tests
- **QuestionsService**: 100% coverage
  - Questionnaire retrieval
  - DISC filtering logic
  - Section filtering
  - Conditional question logic
  - Edge cases

### Integration Tests
- **QuestionsController**: HTTP endpoint testing
  - Query parameter handling
  - Auth guard integration
  - Response format validation

### Running Tests
```bash
npm test -- questions
npm test -- questions --coverage
```

## Usage Examples

### Get Complete Questionnaire (Consultant View)
```typescript
GET /api/v1/questionnaire?includeDisc=true
Authorization: Bearer <token>

Response: {
  "questions": [
    {
      "id": "123e4567-...",
      "questionText": "Do you have a bookkeeping system?",
      "questionType": "single_choice",
      "section": "stabilize",
      "orderIndex": 1,
      "isRequired": true,
      "isConditional": false,
      "answerOptions": [
        { "value": "yes", "label": "Yes" },
        { "value": "no", "label": "No" },
        { "value": "partial", "label": "Partially" }
      ],
      "helpText": "This helps us understand your current setup"
    },
    // ... more questions including DISC
  ],
  "total": 50
}
```

### Get Questions by Section
```typescript
GET /api/v1/questionnaire/sections/stabilize
Authorization: Bearer <token>

Response: [
  {
    "id": "...",
    "questionText": "Do you have a bookkeeping system?",
    "section": "stabilize",
    // ...
  },
  // ... all stabilize questions
]
```

### Get Client-Safe Questionnaire
```typescript
GET /api/v1/questionnaire?includeDisc=false
Authorization: Bearer <token>

// Returns questionnaire WITHOUT DISC questions
// Complies with REQ-QUEST-003
```

## Question Management

Questions are managed through:
1. **Database seeding**: Initial questionnaire loaded via seed scripts
2. **Admin interface** (Phase 2): Future feature for question management
3. **Migration scripts**: Questions updated via database migrations

## Performance Considerations

- Questions are relatively static data
- Consider implementing caching in Phase 2
- Indexed by: section, orderIndex, conditionalParentId
- Soft delete support (questions never truly deleted)

## Integration with Other Modules

### AssessmentsModule
- Questions feed the assessment workflow
- Question IDs used in Response entities
- Total question count used for progress calculation

### AlgorithmsModule
- DISC questions power personality profiling
- Phase-related questions determine financial readiness phase
- Question metadata includes `discTraitMapping` and `phaseWeightMapping`

### ReportsModule
- Question text included in consultant reports
- Question responses displayed in assessment summaries

## Future Enhancements (Phase 2+)

- Admin UI for question management
- Question versioning (track question changes over time)
- Question templates for different industries
- Multi-language support
- Question analytics (which questions cause confusion, etc.)

## Conditional Logic (Phase 3)

The module is designed to support conditional question logic:

```typescript
// Example: S-Corp payroll question
{
  id: "scorp-payroll-question",
  questionText: "Are you on S-Corp payroll?",
  isConditional: true,
  conditionalParentId: "entity-type-question",
  conditionalTriggerValue: "S-Corp"
}
```

Frontend implementation:
1. Show parent question (entity type)
2. When user selects "S-Corp"
3. Fetch conditional questions: `GET /api/v1/questionnaire/conditional/entity-type-question`
4. Display S-Corp payroll question

## Error Handling

Common error responses:
- `401 Unauthorized`: Missing or invalid JWT token
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Section or parent question not found

## Compliance

- **DISC Privacy (REQ-QUEST-003)**: DISC questions hidden from clients by default
- **Minimum DISC Questions (REQ-QUEST-002)**: At least 12 DISC questions for reliability
- **Conditional Logic (REQ-QUEST-010)**: S-Corp payroll conditional question support

## Support

For questions or issues, please refer to:
- Main project README: `../../README.md`
- Requirements specification: `../../../../../plans/requirements.md`
- Content guidelines: `../../../../../content/` (when available)
- API documentation: Available via Swagger UI at `/api/docs` (when server is running)
