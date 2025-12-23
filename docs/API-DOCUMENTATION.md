# Financial RISE API Documentation

**Version:** 1.0
**Base URL:** `https://api.financialrise.com/v1`
**Authentication:** JWT Bearer Token

## Table of Contents

1. [Authentication](#authentication)
2. [Users & Consultants](#users--consultants)
3. [Assessments](#assessments)
4. [Questions & Responses](#questions--responses)
5. [Reports](#reports)
6. [Admin](#admin)
7. [Error Codes](#error-codes)

---

## Authentication

### POST /auth/register

Register a new consultant account.

**Request Body:**
```json
{
  "email": "consultant@example.com",
  "password": "SecurePass123!",
  "firstName": "Jane",
  "lastName": "Consultant",
  "company": "Financial Advisors LLC",
  "phone": "+1-555-0100"
}
```

**Response:** `201 Created`
```json
{
  "user": {
    "id": "usr_abc123",
    "email": "consultant@example.com",
    "firstName": "Jane",
    "lastName": "Consultant",
    "role": "consultant",
    "createdAt": "2025-12-22T10:00:00Z"
  },
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Validation:**
- Email: Valid format, unique
- Password: Min 8 chars, 1 uppercase, 1 lowercase, 1 number, 1 special char
- Phone: E.164 format (optional)

### POST /auth/login

Authenticate and receive tokens.

**Request Body:**
```json
{
  "email": "consultant@example.com",
  "password": "SecurePass123!"
}
```

**Response:** `200 OK`
```json
{
  "user": {
    "id": "usr_abc123",
    "email": "consultant@example.com",
    "firstName": "Jane",
    "lastName": "Consultant",
    "role": "consultant"
  },
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Rate Limit:** 5 requests per 15 minutes per IP

### POST /auth/refresh

Refresh access token using refresh token.

**Request Body:**
```json
{
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response:** `200 OK`
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### POST /auth/logout

Invalidate current session and refresh token.

**Headers:** `Authorization: Bearer <accessToken>`

**Response:** `204 No Content`

---

## Users & Consultants

### GET /users/me

Get current authenticated user profile.

**Headers:** `Authorization: Bearer <accessToken>`

**Response:** `200 OK`
```json
{
  "id": "usr_abc123",
  "email": "consultant@example.com",
  "firstName": "Jane",
  "lastName": "Consultant",
  "company": "Financial Advisors LLC",
  "phone": "+1-555-0100",
  "role": "consultant",
  "settings": {
    "emailNotifications": true,
    "theme": "light"
  },
  "createdAt": "2025-12-22T10:00:00Z",
  "updatedAt": "2025-12-22T10:00:00Z"
}
```

### PATCH /users/me

Update current user profile.

**Headers:** `Authorization: Bearer <accessToken>`

**Request Body:**
```json
{
  "firstName": "Jane",
  "lastName": "Smith",
  "company": "New Company LLC",
  "phone": "+1-555-0200",
  "settings": {
    "emailNotifications": false
  }
}
```

**Response:** `200 OK` (returns updated user object)

### PUT /users/me/password

Change password for current user.

**Headers:** `Authorization: Bearer <accessToken>`

**Request Body:**
```json
{
  "currentPassword": "OldPass123!",
  "newPassword": "NewSecurePass456!"
}
```

**Response:** `204 No Content`

**Rate Limit:** 3 requests per hour

---

## Assessments

### POST /assessments

Create a new assessment.

**Headers:** `Authorization: Bearer <accessToken>`

**Request Body:**
```json
{
  "clientName": "John Business Owner",
  "clientEmail": "john@business.com",
  "businessName": "ABC Manufacturing",
  "industry": "Manufacturing",
  "assessmentType": "self-administered",
  "notes": "Initial consultation assessment"
}
```

**Response:** `201 Created`
```json
{
  "id": "asm_xyz789",
  "userId": "usr_abc123",
  "clientName": "John Business Owner",
  "clientEmail": "john@business.com",
  "businessName": "ABC Manufacturing",
  "industry": "Manufacturing",
  "assessmentType": "self-administered",
  "status": "pending",
  "uniqueLink": "https://app.financialrise.com/assess/asm_xyz789_abc123def456",
  "createdAt": "2025-12-22T11:00:00Z",
  "expiresAt": "2025-12-29T11:00:00Z"
}
```

**Assessment Types:**
- `self-administered` - Client completes independently
- `collaborative` - Consultant and client complete together

**Status Values:**
- `pending` - Created, not started
- `in_progress` - Client has started
- `completed` - All questions answered
- `expired` - Past expiration date

### GET /assessments

List assessments for current consultant.

**Headers:** `Authorization: Bearer <accessToken>`

**Query Parameters:**
- `status` (optional): Filter by status (`pending`, `in_progress`, `completed`, `expired`)
- `page` (optional): Page number (default: 1)
- `limit` (optional): Results per page (default: 20, max: 100)
- `sort` (optional): Sort field (`createdAt`, `updatedAt`, `clientName`)
- `order` (optional): Sort order (`asc`, `desc`, default: `desc`)

**Response:** `200 OK`
```json
{
  "assessments": [
    {
      "id": "asm_xyz789",
      "clientName": "John Business Owner",
      "businessName": "ABC Manufacturing",
      "status": "in_progress",
      "progress": 45,
      "createdAt": "2025-12-22T11:00:00Z",
      "updatedAt": "2025-12-22T12:30:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 42,
    "totalPages": 3
  }
}
```

### GET /assessments/:id

Get detailed assessment information.

**Headers:** `Authorization: Bearer <accessToken>`

**Response:** `200 OK`
```json
{
  "id": "asm_xyz789",
  "userId": "usr_abc123",
  "clientName": "John Business Owner",
  "clientEmail": "john@business.com",
  "businessName": "ABC Manufacturing",
  "industry": "Manufacturing",
  "assessmentType": "self-administered",
  "status": "completed",
  "progress": 100,
  "uniqueLink": "https://app.financialrise.com/assess/asm_xyz789_abc123def456",
  "discProfile": {
    "primary": "D",
    "scores": {
      "D": 75,
      "I": 45,
      "S": 30,
      "C": 50
    }
  },
  "phaseResults": {
    "primary": "Build",
    "scores": {
      "Stabilize": 80,
      "Organize": 85,
      "Build": 55,
      "Grow": 30,
      "Systemic": 40
    }
  },
  "createdAt": "2025-12-22T11:00:00Z",
  "completedAt": "2025-12-22T12:45:00Z",
  "notes": "Initial consultation assessment"
}
```

### PATCH /assessments/:id

Update assessment details.

**Headers:** `Authorization: Bearer <accessToken>`

**Request Body:**
```json
{
  "notes": "Updated notes after follow-up",
  "status": "completed"
}
```

**Response:** `200 OK` (returns updated assessment object)

### DELETE /assessments/:id

Delete an assessment (soft delete).

**Headers:** `Authorization: Bearer <accessToken>`

**Response:** `204 No Content`

---

## Questions & Responses

### GET /questions

Get all assessment questions.

**Headers:** `Authorization: Bearer <accessToken>`

**Query Parameters:**
- `category` (optional): Filter by category
- `includeDisc` (optional): Include DISC questions (default: `false`, only for consultants)

**Response:** `200 OK`
```json
{
  "questions": [
    {
      "id": "q_001",
      "category": "Financial Health",
      "phase": "Stabilize",
      "text": "How would you describe your current bookkeeping practices?",
      "type": "multiple_choice",
      "options": [
        {
          "id": "opt_001_a",
          "text": "No formal system, manual tracking",
          "score": 1
        },
        {
          "id": "opt_001_b",
          "text": "Basic software (QuickBooks, Xero)",
          "score": 3
        },
        {
          "id": "opt_001_c",
          "text": "Fully integrated cloud system",
          "score": 5
        }
      ],
      "isRequired": true,
      "orderIndex": 1
    }
  ]
}
```

### POST /assessments/:id/responses

Submit responses for an assessment.

**Headers:** `Authorization: Bearer <accessToken>` (optional for client-side)

**Request Body:**
```json
{
  "responses": [
    {
      "questionId": "q_001",
      "selectedOption": "opt_001_b"
    },
    {
      "questionId": "q_002",
      "selectedOption": "opt_002_c"
    }
  ],
  "isPartial": false
}
```

**Parameters:**
- `isPartial`: Set to `true` for auto-save, `false` for final submission

**Response:** `200 OK`
```json
{
  "assessmentId": "asm_xyz789",
  "responsesCount": 25,
  "progress": 100,
  "status": "completed"
}
```

### GET /assessments/:id/responses

Get all responses for an assessment.

**Headers:** `Authorization: Bearer <accessToken>`

**Response:** `200 OK`
```json
{
  "assessmentId": "asm_xyz789",
  "responses": [
    {
      "questionId": "q_001",
      "selectedOption": "opt_001_b",
      "answeredAt": "2025-12-22T12:00:00Z"
    }
  ],
  "progress": 100
}
```

---

## Reports

### POST /reports/:assessmentId/generate

Generate reports for a completed assessment.

**Headers:** `Authorization: Bearer <accessToken>`

**Request Body:**
```json
{
  "reportType": "consultant"
}
```

**Parameters:**
- `reportType`: `consultant` or `client`

**Response:** `200 OK`
```json
{
  "reportId": "rpt_abc123",
  "assessmentId": "asm_xyz789",
  "reportType": "consultant",
  "status": "processing",
  "estimatedTime": 5
}
```

**Report Status Values:**
- `processing` - Being generated
- `ready` - Available for download
- `failed` - Generation failed

### GET /reports/:reportId

Get report details.

**Headers:** `Authorization: Bearer <accessToken>`

**Response:** `200 OK`
```json
{
  "reportId": "rpt_abc123",
  "assessmentId": "asm_xyz789",
  "reportType": "consultant",
  "status": "ready",
  "downloadUrl": "https://s3.amazonaws.com/reports/rpt_abc123.pdf",
  "expiresAt": "2025-12-23T12:00:00Z",
  "generatedAt": "2025-12-22T13:00:00Z"
}
```

### GET /reports/:reportId/download

Download report PDF.

**Headers:** `Authorization: Bearer <accessToken>`

**Response:** `200 OK` (PDF file)

**Content-Type:** `application/pdf`

---

## Admin

### GET /admin/users

List all users (admin only).

**Headers:** `Authorization: Bearer <accessToken>`

**Query Parameters:**
- `role` (optional): Filter by role (`admin`, `consultant`)
- `page` (optional): Page number
- `limit` (optional): Results per page

**Response:** `200 OK`
```json
{
  "users": [
    {
      "id": "usr_abc123",
      "email": "consultant@example.com",
      "firstName": "Jane",
      "lastName": "Consultant",
      "role": "consultant",
      "status": "active",
      "createdAt": "2025-12-22T10:00:00Z",
      "lastLogin": "2025-12-22T14:00:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 150,
    "totalPages": 8
  }
}
```

### PATCH /admin/users/:id

Update user (admin only).

**Headers:** `Authorization: Bearer <accessToken>`

**Request Body:**
```json
{
  "status": "suspended",
  "role": "consultant"
}
```

**Status Values:**
- `active` - Normal access
- `suspended` - Login disabled
- `deleted` - Soft deleted

**Response:** `200 OK` (returns updated user object)

### GET /admin/analytics

Get system analytics (admin only).

**Headers:** `Authorization: Bearer <accessToken>`

**Query Parameters:**
- `startDate` (optional): Start date (ISO 8601)
- `endDate` (optional): End date (ISO 8601)

**Response:** `200 OK`
```json
{
  "period": {
    "startDate": "2025-12-01T00:00:00Z",
    "endDate": "2025-12-22T23:59:59Z"
  },
  "metrics": {
    "totalUsers": 150,
    "activeUsers": 120,
    "totalAssessments": 450,
    "completedAssessments": 380,
    "reportsGenerated": 760,
    "averageCompletionTime": 35
  },
  "discDistribution": {
    "D": 28,
    "I": 35,
    "S": 22,
    "C": 15
  },
  "phaseDistribution": {
    "Stabilize": 30,
    "Organize": 25,
    "Build": 20,
    "Grow": 15,
    "Systemic": 10
  }
}
```

---

## Error Codes

All errors follow this format:

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": {
      "field": "Additional context"
    }
  }
}
```

### HTTP Status Codes

| Status | Code | Description |
|--------|------|-------------|
| 400 | `INVALID_REQUEST` | Malformed request body |
| 400 | `VALIDATION_ERROR` | Request validation failed |
| 401 | `UNAUTHORIZED` | Missing or invalid token |
| 401 | `TOKEN_EXPIRED` | Access token expired |
| 403 | `FORBIDDEN` | Insufficient permissions |
| 404 | `NOT_FOUND` | Resource not found |
| 409 | `CONFLICT` | Resource already exists |
| 429 | `RATE_LIMIT_EXCEEDED` | Too many requests |
| 500 | `INTERNAL_ERROR` | Server error |
| 503 | `SERVICE_UNAVAILABLE` | Temporary service issue |

### Common Error Responses

**400 Validation Error:**
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Request validation failed",
    "details": {
      "email": "Invalid email format",
      "password": "Password must be at least 8 characters"
    }
  }
}
```

**401 Unauthorized:**
```json
{
  "error": {
    "code": "UNAUTHORIZED",
    "message": "Invalid or expired access token"
  }
}
```

**429 Rate Limit:**
```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Too many requests. Please try again later.",
    "details": {
      "retryAfter": 900
    }
  }
}
```

---

## Rate Limits

| Endpoint | Limit | Window |
|----------|-------|--------|
| `/auth/login` | 5 requests | 15 minutes |
| `/auth/register` | 3 requests | 1 hour |
| `/users/me/password` | 3 requests | 1 hour |
| `/reports/:id/generate` | 10 requests | 1 minute |
| All other endpoints | 100 requests | 15 minutes |

**Headers:**
- `X-RateLimit-Limit` - Maximum requests allowed
- `X-RateLimit-Remaining` - Requests remaining
- `X-RateLimit-Reset` - Unix timestamp when limit resets

---

## Pagination

All list endpoints support pagination with these parameters:

| Parameter | Type | Default | Max | Description |
|-----------|------|---------|-----|-------------|
| `page` | integer | 1 | - | Page number |
| `limit` | integer | 20 | 100 | Results per page |

**Response Format:**
```json
{
  "data": [...],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 150,
    "totalPages": 8,
    "hasNext": true,
    "hasPrev": false
  }
}
```

---

## Webhooks (Future)

Webhooks will be supported for:
- Assessment completed
- Report generated
- User registered

**Webhook Payload:**
```json
{
  "event": "assessment.completed",
  "timestamp": "2025-12-22T13:00:00Z",
  "data": {
    "assessmentId": "asm_xyz789",
    "userId": "usr_abc123"
  }
}
```

---

**API Version:** 1.0
**Last Updated:** 2025-12-22
**Support:** api-support@financialrise.com
