# Financial RISE API Contract Agreement

**Version:** 1.0
**Date:** 2025-12-27
**Backend:** NestJS (`financial-rise-app/backend/`)
**Frontend:** React (`financial-rise-frontend/`)
**Status:** Draft for Team Agreement

---

## Purpose

This document defines the API contract between frontend and backend teams to enable **parallel development**. Once agreed upon, both teams can work independently using this specification.

**Frontend teams** can use mock data matching these contracts.
**Backend teams** must implement endpoints exactly as specified.

---

## Table of Contents

1. [Base Configuration](#1-base-configuration)
2. [Authentication Endpoints](#2-authentication-endpoints)
3. [Assessment Endpoints](#3-assessment-endpoints)
4. [Questionnaire Endpoints](#4-questionnaire-endpoints)
5. [Report Endpoints](#5-report-endpoints)
6. [User Management Endpoints](#6-user-management-endpoints)
7. [Common Response Formats](#7-common-response-formats)
8. [Error Handling](#8-error-handling)
9. [Data Models](#9-data-models)

---

## 1. Base Configuration

### Base URL
```
Development: http://localhost:3000/api/v1
Staging: https://staging-api.financial-rise.com/api/v1
Production: https://api.financial-rise.com/api/v1
```

### Headers

**All Requests:**
```http
Content-Type: application/json
Accept: application/json
```

**Authenticated Requests:**
```http
Authorization: Bearer {access_token}
```

### HTTP Methods
- `GET` - Retrieve resources (no request body)
- `POST` - Create resources
- `PUT` - Update entire resources
- `PATCH` - Partial update
- `DELETE` - Delete resources

### Status Codes
- `200 OK` - Successful GET, PUT, PATCH
- `201 Created` - Successful POST
- `204 No Content` - Successful DELETE
- `400 Bad Request` - Validation error
- `401 Unauthorized` - Missing or invalid token
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `409 Conflict` - Resource conflict (e.g., duplicate email)
- `429 Too Many Requests` - Rate limit exceeded
- `500 Internal Server Error` - Server error

---

## 2. Authentication Endpoints

### 2.1 Register

**Endpoint:** `POST /auth/register`

**Request Body:**
```json
{
  "email": "consultant@example.com",
  "password": "SecurePass123!",
  "firstName": "Jane",
  "lastName": "Consultant"
}
```

**Validation Rules:**
- `email`: Valid email format, max 255 chars, unique
- `password`: Min 8 chars, must contain uppercase, lowercase, number, special char
- `firstName`: Min 1 char, max 100 chars
- `lastName`: Min 1 char, max 100 chars

**Success Response (201):**
```json
{
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "consultant@example.com",
    "firstName": "Jane",
    "lastName": "Consultant",
    "role": "consultant",
    "status": "active",
    "createdAt": "2025-12-27T10:30:00Z"
  },
  "tokens": {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expiresIn": 900
  }
}
```

**Error Response (409 Conflict):**
```json
{
  "statusCode": 409,
  "message": "Email already registered",
  "error": "Conflict"
}
```

---

### 2.2 Login

**Endpoint:** `POST /auth/login`

**Request Body:**
```json
{
  "email": "consultant@example.com",
  "password": "SecurePass123!"
}
```

**Success Response (200):**
```json
{
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "consultant@example.com",
    "firstName": "Jane",
    "lastName": "Consultant",
    "role": "consultant",
    "status": "active",
    "lastLoginAt": "2025-12-27T10:30:00Z"
  },
  "tokens": {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expiresIn": 900
  }
}
```

**Error Response (401 Unauthorized):**
```json
{
  "statusCode": 401,
  "message": "Invalid email or password",
  "error": "Unauthorized"
}
```

**Error Response (423 Locked):**
```json
{
  "statusCode": 423,
  "message": "Account locked due to too many failed login attempts. Please try again in 15 minutes.",
  "error": "Locked",
  "lockedUntil": "2025-12-27T10:45:00Z"
}
```

---

### 2.3 Refresh Token

**Endpoint:** `POST /auth/refresh`

**Request Body:**
```json
{
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Success Response (200):**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresIn": 900
}
```

---

### 2.4 Logout

**Endpoint:** `POST /auth/logout`

**Headers:** `Authorization: Bearer {access_token}`

**Request Body:**
```json
{
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Success Response (204):** No content

---

### 2.5 Request Password Reset

**Endpoint:** `POST /auth/forgot-password`

**Request Body:**
```json
{
  "email": "consultant@example.com"
}
```

**Success Response (200):**
```json
{
  "message": "If an account with that email exists, a password reset link has been sent."
}
```

**Note:** Always return 200 to prevent email enumeration attacks.

---

### 2.6 Reset Password

**Endpoint:** `POST /auth/reset-password`

**Request Body:**
```json
{
  "token": "abc123xyz789resettoken",
  "newPassword": "NewSecurePass456!"
}
```

**Success Response (200):**
```json
{
  "message": "Password successfully reset. You can now log in with your new password."
}
```

**Error Response (400 Bad Request):**
```json
{
  "statusCode": 400,
  "message": "Invalid or expired reset token",
  "error": "Bad Request"
}
```

---

## 3. Assessment Endpoints

### 3.1 List Assessments

**Endpoint:** `GET /assessments`

**Headers:** `Authorization: Bearer {access_token}`

**Query Parameters:**
- `page` (optional, default: 1) - Page number
- `limit` (optional, default: 10, max: 100) - Items per page
- `status` (optional) - Filter by status: `draft`, `in_progress`, `completed`
- `search` (optional) - Search by client name, business name, or email
- `sortBy` (optional, default: `updatedAt`) - Sort field
- `sortOrder` (optional, default: `desc`) - `asc` or `desc`

**Example:**
```
GET /assessments?page=1&limit=20&status=in_progress&search=acme&sortBy=updatedAt&sortOrder=desc
```

**Success Response (200):**
```json
{
  "data": [
    {
      "id": "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d",
      "consultantId": "550e8400-e29b-41d4-a716-446655440000",
      "clientName": "John Smith",
      "businessName": "Acme Corp",
      "clientEmail": "john@acmecorp.com",
      "status": "in_progress",
      "progress": 45.5,
      "createdAt": "2025-12-20T08:00:00Z",
      "updatedAt": "2025-12-26T14:30:00Z",
      "startedAt": "2025-12-20T09:15:00Z",
      "completedAt": null,
      "notes": "Follow up on payroll questions"
    }
  ],
  "meta": {
    "page": 1,
    "limit": 20,
    "total": 45,
    "totalPages": 3
  }
}
```

---

### 3.2 Get Assessment

**Endpoint:** `GET /assessments/:id`

**Headers:** `Authorization: Bearer {access_token}`

**Success Response (200):**
```json
{
  "id": "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d",
  "consultantId": "550e8400-e29b-41d4-a716-446655440000",
  "clientName": "John Smith",
  "businessName": "Acme Corp",
  "clientEmail": "john@acmecorp.com",
  "status": "in_progress",
  "progress": 45.5,
  "createdAt": "2025-12-20T08:00:00Z",
  "updatedAt": "2025-12-26T14:30:00Z",
  "startedAt": "2025-12-20T09:15:00Z",
  "completedAt": null,
  "notes": "Follow up on payroll questions",
  "responses": [
    {
      "id": "r1r2r3r4-r5r6-4a5b-8c9d-0e1f2a3b4c5d",
      "questionId": "FIN-001",
      "answer": {
        "value": "monthly",
        "text": "Monthly"
      },
      "notApplicable": false,
      "consultantNotes": "Client uses QuickBooks",
      "answeredAt": "2025-12-20T09:30:00Z"
    }
  ],
  "discProfile": {
    "id": "d1d2d3d4-d5d6-4a5b-8c9d-0e1f2a3b4c5d",
    "dScore": 75,
    "iScore": 60,
    "sScore": 45,
    "cScore": 85,
    "primaryType": "C",
    "secondaryType": "D",
    "confidenceLevel": "high",
    "calculatedAt": "2025-12-26T14:30:00Z"
  },
  "phaseResult": {
    "id": "p1p2p3p4-p5p6-4a5b-8c9d-0e1f2a3b4c5d",
    "stabilizeScore": 65,
    "organizeScore": 45,
    "buildScore": 30,
    "growScore": 20,
    "systemicScore": 40,
    "primaryPhase": "organize",
    "secondaryPhases": ["stabilize"],
    "transitionState": true,
    "calculatedAt": "2025-12-26T14:30:00Z"
  }
}
```

**Error Response (404):**
```json
{
  "statusCode": 404,
  "message": "Assessment not found",
  "error": "Not Found"
}
```

---

### 3.3 Create Assessment

**Endpoint:** `POST /assessments`

**Headers:** `Authorization: Bearer {access_token}`

**Request Body:**
```json
{
  "clientName": "John Smith",
  "businessName": "Acme Corp",
  "clientEmail": "john@acmecorp.com",
  "notes": "Initial consultation scheduled for next week"
}
```

**Validation Rules:**
- `clientName`: Required, min 1 char, max 100 chars
- `businessName`: Required, min 1 char, max 100 chars
- `clientEmail`: Required, valid email, max 255 chars
- `notes`: Optional, max 5000 chars

**Success Response (201):**
```json
{
  "id": "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d",
  "consultantId": "550e8400-e29b-41d4-a716-446655440000",
  "clientName": "John Smith",
  "businessName": "Acme Corp",
  "clientEmail": "john@acmecorp.com",
  "status": "draft",
  "progress": 0,
  "createdAt": "2025-12-27T10:30:00Z",
  "updatedAt": "2025-12-27T10:30:00Z",
  "startedAt": null,
  "completedAt": null,
  "notes": "Initial consultation scheduled for next week"
}
```

---

### 3.4 Update Assessment

**Endpoint:** `PATCH /assessments/:id`

**Headers:** `Authorization: Bearer {access_token}`

**Request Body (all fields optional):**
```json
{
  "clientName": "John M. Smith",
  "businessName": "Acme Corporation",
  "clientEmail": "john.smith@acmecorp.com",
  "notes": "Updated notes",
  "status": "in_progress"
}
```

**Validation Rules:**
- `status`: Must be valid transition (draft→in_progress, in_progress→completed)
- Cannot update `status` to `draft` if already `completed`

**Success Response (200):**
```json
{
  "id": "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d",
  "consultantId": "550e8400-e29b-41d4-a716-446655440000",
  "clientName": "John M. Smith",
  "businessName": "Acme Corporation",
  "clientEmail": "john.smith@acmecorp.com",
  "status": "in_progress",
  "progress": 45.5,
  "createdAt": "2025-12-20T08:00:00Z",
  "updatedAt": "2025-12-27T10:35:00Z",
  "startedAt": "2025-12-27T10:35:00Z",
  "completedAt": null,
  "notes": "Updated notes"
}
```

---

### 3.5 Delete Assessment

**Endpoint:** `DELETE /assessments/:id`

**Headers:** `Authorization: Bearer {access_token}`

**Success Response (204):** No content

**Note:** This is a soft delete (sets `deletedAt` timestamp). Assessment can be recovered by admins.

---

## 4. Questionnaire Endpoints

### 4.1 Get Questions

**Endpoint:** `GET /questionnaire/questions`

**Headers:** `Authorization: Bearer {access_token}`

**Query Parameters:**
- `assessmentId` (optional) - If provided, returns questions with user's responses

**Success Response (200):**
```json
{
  "questions": [
    {
      "id": "FIN-001",
      "questionKey": "FIN-001",
      "questionText": "How frequently do you review your financial statements?",
      "questionType": "single_choice",
      "options": [
        {
          "value": "weekly",
          "text": "Weekly",
          "discScores": { "D": 15, "I": 5, "S": 0, "C": 20 },
          "phaseScores": { "stabilize": 20, "organize": 15, "build": 10, "grow": 5, "systemic": 15 }
        },
        {
          "value": "monthly",
          "text": "Monthly",
          "discScores": { "D": 10, "I": 10, "S": 10, "C": 15 },
          "phaseScores": { "stabilize": 15, "organize": 10, "build": 5, "grow": 0, "systemic": 10 }
        },
        {
          "value": "quarterly",
          "text": "Quarterly",
          "discScores": { "D": 5, "I": 15, "S": 15, "C": 5 },
          "phaseScores": { "stabilize": 10, "organize": 5, "build": 0, "grow": 0, "systemic": 5 }
        },
        {
          "value": "annually",
          "text": "Annually or less",
          "discScores": { "D": 0, "I": 20, "S": 20, "C": 0 },
          "phaseScores": { "stabilize": 5, "organize": 0, "build": 0, "grow": 0, "systemic": 0 }
        }
      ],
      "required": true,
      "displayOrder": 1,
      "userResponse": null
    },
    {
      "id": "FIN-002",
      "questionKey": "FIN-002",
      "questionText": "Do you have a documented chart of accounts?",
      "questionType": "single_choice",
      "options": [
        {
          "value": "yes_custom",
          "text": "Yes, customized for my business",
          "discScores": { "D": 15, "I": 5, "S": 10, "C": 20 },
          "phaseScores": { "stabilize": 10, "organize": 20, "build": 15, "grow": 10, "systemic": 10 }
        },
        {
          "value": "yes_default",
          "text": "Yes, using the default from my accounting software",
          "discScores": { "D": 5, "I": 10, "S": 15, "C": 10 },
          "phaseScores": { "stabilize": 5, "organize": 10, "build": 5, "grow": 0, "systemic": 5 }
        },
        {
          "value": "no",
          "text": "No",
          "discScores": { "D": 0, "I": 20, "S": 20, "C": 0 },
          "phaseScores": { "stabilize": 0, "organize": 0, "build": 0, "grow": 0, "systemic": 0 }
        }
      ],
      "required": true,
      "displayOrder": 2,
      "userResponse": null
    }
  ],
  "meta": {
    "totalQuestions": 42,
    "requiredQuestions": 40,
    "optionalQuestions": 2
  }
}
```

**Note:** DISC scores are intentionally included in the response to the consultant but MUST NOT be exposed to the client interface.

---

### 4.2 Submit Response

**Endpoint:** `POST /questionnaire/responses`

**Headers:** `Authorization: Bearer {access_token}`

**Request Body:**
```json
{
  "assessmentId": "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d",
  "questionId": "FIN-001",
  "answer": {
    "value": "monthly",
    "text": "Monthly"
  },
  "notApplicable": false,
  "consultantNotes": "Client uses QuickBooks Online"
}
```

**Validation Rules:**
- `assessmentId`: Required, must exist and belong to consultant
- `questionId`: Required, must exist
- `answer`: Required if `notApplicable` is false
- `notApplicable`: Boolean, default false
- `consultantNotes`: Optional, max 2000 chars

**Success Response (201):**
```json
{
  "id": "r1r2r3r4-r5r6-4a5b-8c9d-0e1f2a3b4c5d",
  "assessmentId": "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d",
  "questionId": "FIN-001",
  "answer": {
    "value": "monthly",
    "text": "Monthly"
  },
  "notApplicable": false,
  "consultantNotes": "Client uses QuickBooks Online",
  "answeredAt": "2025-12-27T10:40:00Z",
  "progress": 2.4
}
```

**Note:** Response includes updated progress percentage.

---

### 4.3 Update Response

**Endpoint:** `PATCH /questionnaire/responses/:id`

**Headers:** `Authorization: Bearer {access_token}`

**Request Body (all fields optional):**
```json
{
  "answer": {
    "value": "weekly",
    "text": "Weekly"
  },
  "consultantNotes": "Updated: Client switched to weekly reviews"
}
```

**Success Response (200):**
```json
{
  "id": "r1r2r3r4-r5r6-4a5b-8c9d-0e1f2a3b4c5d",
  "assessmentId": "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d",
  "questionId": "FIN-001",
  "answer": {
    "value": "weekly",
    "text": "Weekly"
  },
  "notApplicable": false,
  "consultantNotes": "Updated: Client switched to weekly reviews",
  "answeredAt": "2025-12-27T10:45:00Z"
}
```

---

## 5. Report Endpoints

### 5.1 Calculate DISC Profile

**Endpoint:** `POST /reports/disc-profile`

**Headers:** `Authorization: Bearer {access_token}`

**Request Body:**
```json
{
  "assessmentId": "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d"
}
```

**Success Response (200):**
```json
{
  "id": "d1d2d3d4-d5d6-4a5b-8c9d-0e1f2a3b4c5d",
  "assessmentId": "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d",
  "dScore": 75,
  "iScore": 60,
  "sScore": 45,
  "cScore": 85,
  "primaryType": "C",
  "secondaryType": "D",
  "confidenceLevel": "high",
  "calculatedAt": "2025-12-27T10:50:00Z",
  "traits": {
    "C": {
      "name": "Compliance",
      "description": "Analytical, detail-oriented, systematic",
      "score": 85,
      "isPrimary": true
    },
    "D": {
      "name": "Dominance",
      "description": "Results-oriented, direct, decisive",
      "score": 75,
      "isSecondary": true
    },
    "I": {
      "name": "Influence",
      "description": "Enthusiastic, collaborative, persuasive",
      "score": 60,
      "isSecondary": false
    },
    "S": {
      "name": "Steadiness",
      "description": "Patient, consistent, supportive",
      "score": 45,
      "isSecondary": false
    }
  }
}
```

**Error Response (400):**
```json
{
  "statusCode": 400,
  "message": "Insufficient responses for reliable DISC calculation. Minimum 12 questions required, found 8.",
  "error": "Bad Request"
}
```

---

### 5.2 Calculate Phase Result

**Endpoint:** `POST /reports/phase-result`

**Headers:** `Authorization: Bearer {access_token}`

**Request Body:**
```json
{
  "assessmentId": "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d"
}
```

**Success Response (200):**
```json
{
  "id": "p1p2p3p4-p5p6-4a5b-8c9d-0e1f2a3b4c5d",
  "assessmentId": "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d",
  "stabilizeScore": 65,
  "organizeScore": 45,
  "buildScore": 30,
  "growScore": 20,
  "systemicScore": 40,
  "primaryPhase": "organize",
  "secondaryPhases": ["stabilize"],
  "transitionState": true,
  "calculatedAt": "2025-12-27T10:50:00Z",
  "phases": {
    "stabilize": {
      "name": "Stabilize",
      "description": "Establishing basic financial order and compliance",
      "score": 65,
      "isPrimary": false,
      "isSecondary": true,
      "status": "in_progress"
    },
    "organize": {
      "name": "Organize",
      "description": "Building foundational systems and processes",
      "score": 45,
      "isPrimary": true,
      "isSecondary": false,
      "status": "current_focus"
    },
    "build": {
      "name": "Build",
      "description": "Creating robust operational systems",
      "score": 30,
      "isPrimary": false,
      "isSecondary": false,
      "status": "future"
    },
    "grow": {
      "name": "Grow",
      "description": "Strategic financial planning and forecasting",
      "score": 20,
      "isPrimary": false,
      "isSecondary": false,
      "status": "future"
    },
    "systemic": {
      "name": "Systemic (Financial Literacy)",
      "description": "Understanding and acting on financial reports",
      "score": 40,
      "isPrimary": false,
      "isSecondary": false,
      "status": "cross_cutting"
    }
  }
}
```

---

### 5.3 Generate Consultant Report

**Endpoint:** `POST /reports/generate/consultant`

**Headers:** `Authorization: Bearer {access_token}`

**Request Body:**
```json
{
  "assessmentId": "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d"
}
```

**Success Response (202 Accepted):**
```json
{
  "reportId": "rep1rep2-rep3-rep4-rep5-rep6rep7rep8",
  "status": "generating",
  "message": "Report generation started. Poll /reports/status/{reportId} for updates.",
  "estimatedCompletionTime": 5
}
```

**Note:** Report generation is asynchronous due to PDF processing time.

---

### 5.4 Generate Client Report

**Endpoint:** `POST /reports/generate/client`

**Headers:** `Authorization: Bearer {access_token}`

**Request Body:**
```json
{
  "assessmentId": "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d"
}
```

**Success Response (202 Accepted):**
```json
{
  "reportId": "rep1rep2-rep3-rep4-rep5-rep6rep7rep8",
  "status": "generating",
  "message": "Report generation started. Poll /reports/status/{reportId} for updates.",
  "estimatedCompletionTime": 5
}
```

---

### 5.5 Get Report Status

**Endpoint:** `GET /reports/status/:reportId`

**Headers:** `Authorization: Bearer {access_token}`

**Success Response (200) - Generating:**
```json
{
  "reportId": "rep1rep2-rep3-rep4-rep5-rep6rep7rep8",
  "status": "generating",
  "progress": 60,
  "message": "Generating PDF...",
  "estimatedTimeRemaining": 2
}
```

**Success Response (200) - Complete:**
```json
{
  "reportId": "rep1rep2-rep3-rep4-rep5-rep6rep7rep8",
  "assessmentId": "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d",
  "reportType": "consultant",
  "status": "completed",
  "fileUrl": "https://storage.googleapis.com/financial-rise-reports/rep1rep2-rep3-rep4-rep5-rep6rep7rep8.pdf?signature=...",
  "fileSizeBytes": 245678,
  "generatedAt": "2025-12-27T10:52:00Z",
  "expiresAt": "2025-12-27T18:52:00Z"
}
```

**Success Response (200) - Failed:**
```json
{
  "reportId": "rep1rep2-rep3-rep4-rep5-rep6rep7rep8",
  "status": "failed",
  "error": "Insufficient data to generate report",
  "message": "Assessment must be completed before generating reports."
}
```

---

### 5.6 Download Report

**Endpoint:** `GET /reports/download/:reportId`

**Headers:** `Authorization: Bearer {access_token}`

**Success Response (200):**
- Content-Type: `application/pdf`
- Content-Disposition: `attachment; filename="Financial-RISE-Report-John-Smith-2025-12-27.pdf"`
- Body: PDF binary data

**Error Response (404):**
```json
{
  "statusCode": 404,
  "message": "Report not found or expired",
  "error": "Not Found"
}
```

---

## 6. User Management Endpoints

### 6.1 Get Current User

**Endpoint:** `GET /users/me`

**Headers:** `Authorization: Bearer {access_token}`

**Success Response (200):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "consultant@example.com",
  "firstName": "Jane",
  "lastName": "Consultant",
  "role": "consultant",
  "status": "active",
  "createdAt": "2025-01-15T08:00:00Z",
  "lastLoginAt": "2025-12-27T10:30:00Z"
}
```

---

### 6.2 Update Current User

**Endpoint:** `PATCH /users/me`

**Headers:** `Authorization: Bearer {access_token}`

**Request Body (all fields optional):**
```json
{
  "firstName": "Jane Marie",
  "lastName": "Consultant-Smith",
  "email": "jane.consultant@newdomain.com"
}
```

**Success Response (200):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "jane.consultant@newdomain.com",
  "firstName": "Jane Marie",
  "lastName": "Consultant-Smith",
  "role": "consultant",
  "status": "active",
  "createdAt": "2025-01-15T08:00:00Z",
  "lastLoginAt": "2025-12-27T10:30:00Z",
  "updatedAt": "2025-12-27T11:00:00Z"
}
```

---

### 6.3 Change Password

**Endpoint:** `POST /users/me/change-password`

**Headers:** `Authorization: Bearer {access_token}`

**Request Body:**
```json
{
  "currentPassword": "OldSecurePass123!",
  "newPassword": "NewSecurePass456!"
}
```

**Validation Rules:**
- `currentPassword`: Required, must match current password
- `newPassword`: Required, must meet complexity requirements, must differ from current

**Success Response (200):**
```json
{
  "message": "Password successfully changed. All refresh tokens have been revoked."
}
```

**Error Response (401):**
```json
{
  "statusCode": 401,
  "message": "Current password is incorrect",
  "error": "Unauthorized"
}
```

---

## 7. Common Response Formats

### Success Response Wrapper (List)
```json
{
  "data": [...],
  "meta": {
    "page": 1,
    "limit": 10,
    "total": 45,
    "totalPages": 5
  }
}
```

### Success Response Wrapper (Single)
```json
{
  "id": "...",
  "field1": "value1",
  ...
}
```

---

## 8. Error Handling

### Error Response Format

**All error responses follow this structure:**
```json
{
  "statusCode": 400,
  "message": "Validation failed",
  "error": "Bad Request",
  "details": [
    {
      "field": "email",
      "message": "Email must be a valid email address"
    },
    {
      "field": "password",
      "message": "Password must contain at least one uppercase letter"
    }
  ]
}
```

**Fields:**
- `statusCode` (number): HTTP status code
- `message` (string): Human-readable error message
- `error` (string): Error type (e.g., "Bad Request", "Unauthorized")
- `details` (array, optional): Field-specific validation errors

---

### Common Error Codes

| Status Code | Error Type | Usage |
|-------------|------------|-------|
| 400 | Bad Request | Validation errors, malformed requests |
| 401 | Unauthorized | Missing/invalid token, incorrect credentials |
| 403 | Forbidden | User lacks permission for resource |
| 404 | Not Found | Resource doesn't exist |
| 409 | Conflict | Duplicate resource (e.g., email already exists) |
| 422 | Unprocessable Entity | Business logic validation failed |
| 423 | Locked | Account locked due to failed login attempts |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Unexpected server error |
| 503 | Service Unavailable | Temporary outage or maintenance |

---

### Validation Error Examples

**Email Validation:**
```json
{
  "statusCode": 400,
  "message": "Validation failed",
  "error": "Bad Request",
  "details": [
    {
      "field": "email",
      "message": "Email must be a valid email address",
      "value": "not-an-email"
    }
  ]
}
```

**Password Complexity:**
```json
{
  "statusCode": 400,
  "message": "Validation failed",
  "error": "Bad Request",
  "details": [
    {
      "field": "password",
      "message": "Password must be at least 8 characters long",
      "constraint": "minLength"
    },
    {
      "field": "password",
      "message": "Password must contain at least one uppercase letter",
      "constraint": "uppercase"
    },
    {
      "field": "password",
      "message": "Password must contain at least one special character",
      "constraint": "specialChar"
    }
  ]
}
```

**Required Field:**
```json
{
  "statusCode": 400,
  "message": "Validation failed",
  "error": "Bad Request",
  "details": [
    {
      "field": "clientName",
      "message": "clientName should not be empty",
      "constraint": "isNotEmpty"
    }
  ]
}
```

---

## 9. Data Models

### User
```typescript
interface User {
  id: string;                    // UUID
  email: string;                 // Unique, max 255 chars
  firstName: string;             // Max 100 chars
  lastName: string;              // Max 100 chars
  role: 'consultant' | 'admin';
  status: 'active' | 'inactive' | 'locked';
  createdAt: string;             // ISO 8601 timestamp
  lastLoginAt: string | null;    // ISO 8601 timestamp
  updatedAt: string;             // ISO 8601 timestamp
}
```

### Assessment
```typescript
interface Assessment {
  id: string;                    // UUID
  consultantId: string;          // UUID, FK to User
  clientName: string;            // Max 100 chars
  businessName: string;          // Max 100 chars
  clientEmail: string;           // Max 255 chars
  status: 'draft' | 'in_progress' | 'completed';
  progress: number;              // 0-100, decimal(5,2)
  createdAt: string;             // ISO 8601 timestamp
  updatedAt: string;             // ISO 8601 timestamp
  startedAt: string | null;      // ISO 8601 timestamp
  completedAt: string | null;    // ISO 8601 timestamp
  notes: string | null;          // Max 5000 chars
  responses?: AssessmentResponse[];
  discProfile?: DISCProfile;
  phaseResult?: PhaseResult;
}
```

### AssessmentResponse
```typescript
interface AssessmentResponse {
  id: string;                    // UUID
  assessmentId: string;          // UUID, FK to Assessment
  questionId: string;            // FK to Question
  answer: {                      // JSONB
    value: string | number | string[];
    text?: string;
  };
  notApplicable: boolean;
  consultantNotes: string | null; // Max 2000 chars
  answeredAt: string;            // ISO 8601 timestamp
}
```

### Question
```typescript
interface Question {
  id: string;                    // UUID
  questionKey: string;           // Unique, max 50 chars (e.g., "FIN-001")
  questionText: string;          // Question text
  questionType: 'single_choice' | 'multiple_choice' | 'rating' | 'text';
  options: QuestionOption[] | null; // JSONB, null for text questions
  required: boolean;
  displayOrder: number;
  createdAt: string;             // ISO 8601 timestamp
  updatedAt: string;             // ISO 8601 timestamp
}

interface QuestionOption {
  value: string;
  text: string;
  discScores: {
    D: number;
    I: number;
    S: number;
    C: number;
  };
  phaseScores: {
    stabilize: number;
    organize: number;
    build: number;
    grow: number;
    systemic: number;
  };
}
```

### DISCProfile
```typescript
interface DISCProfile {
  id: string;                    // UUID
  assessmentId: string;          // UUID, FK to Assessment
  dScore: number;                // 0-100
  iScore: number;                // 0-100
  sScore: number;                // 0-100
  cScore: number;                // 0-100
  primaryType: 'D' | 'I' | 'S' | 'C';
  secondaryType: 'D' | 'I' | 'S' | 'C' | null;
  confidenceLevel: 'high' | 'moderate' | 'low';
  calculatedAt: string;          // ISO 8601 timestamp
}
```

### PhaseResult
```typescript
interface PhaseResult {
  id: string;                    // UUID
  assessmentId: string;          // UUID, FK to Assessment
  stabilizeScore: number;        // 0-100
  organizeScore: number;         // 0-100
  buildScore: number;            // 0-100
  growScore: number;             // 0-100
  systemicScore: number;         // 0-100
  primaryPhase: 'stabilize' | 'organize' | 'build' | 'grow' | 'systemic';
  secondaryPhases: Array<'stabilize' | 'organize' | 'build' | 'grow' | 'systemic'>;
  transitionState: boolean;
  calculatedAt: string;          // ISO 8601 timestamp
}
```

### Report
```typescript
interface Report {
  id: string;                    // UUID
  assessmentId: string;          // UUID, FK to Assessment
  reportType: 'consultant' | 'client';
  status: 'generating' | 'completed' | 'failed';
  fileUrl: string | null;        // Signed GCS URL
  fileSizeBytes: number | null;
  generatedAt: string | null;    // ISO 8601 timestamp
  expiresAt: string | null;      // ISO 8601 timestamp (for signed URL)
  error: string | null;          // Error message if failed
}
```

---

## 10. Frontend Mock Data Guidelines

For **parallel development**, frontend teams should create mock data generators that match these contracts exactly.

### Example Mock Service (TypeScript)
```typescript
// mockApi.ts
import { Assessment, User, Question } from './types';

export const mockApi = {
  auth: {
    login: async (email: string, password: string) => {
      await delay(500);
      return {
        user: mockUser,
        tokens: {
          accessToken: 'mock-access-token',
          refreshToken: 'mock-refresh-token',
          expiresIn: 900
        }
      };
    }
  },

  assessments: {
    list: async (page = 1, limit = 10) => {
      await delay(300);
      return {
        data: mockAssessments.slice((page - 1) * limit, page * limit),
        meta: {
          page,
          limit,
          total: mockAssessments.length,
          totalPages: Math.ceil(mockAssessments.length / limit)
        }
      };
    }
  }
};

const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
```

### Switching from Mock to Real API
```typescript
// api.ts
const USE_MOCK = process.env.REACT_APP_USE_MOCK === 'true';

export const api = USE_MOCK ? mockApi : realApi;
```

---

## 11. Rate Limiting

### Global Limits
- **100 requests per minute** per IP address
- **1000 requests per hour** per IP address

### Endpoint-Specific Limits

| Endpoint | Limit | Window |
|----------|-------|--------|
| `POST /auth/login` | 5 attempts | 15 minutes |
| `POST /auth/register` | 3 attempts | 1 hour |
| `POST /auth/forgot-password` | 3 attempts | 1 hour |
| `POST /auth/reset-password` | 5 attempts | 1 hour |
| `POST /reports/generate/*` | 10 requests | 1 hour |

### Rate Limit Headers
```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640625600
```

### Rate Limit Exceeded Response (429)
```json
{
  "statusCode": 429,
  "message": "Too many requests. Please try again in 12 minutes.",
  "error": "Too Many Requests",
  "retryAfter": 720
}
```

---

## 12. Authentication Flow

### Token Lifecycle

1. **Login** → Receive `accessToken` (15 min) + `refreshToken` (7 days)
2. **API Requests** → Include `Authorization: Bearer {accessToken}`
3. **Token Expiry** → Receive 401 response
4. **Refresh** → Call `/auth/refresh` with `refreshToken`
5. **New Tokens** → Receive new `accessToken` + `refreshToken` (token rotation)
6. **Logout** → Call `/auth/logout` to revoke refresh token

### Frontend Token Storage

**Recommended:**
- `accessToken`: Memory only (React state, not localStorage)
- `refreshToken`: httpOnly cookie (backend-managed) OR secure localStorage

**Security Note:** Never store tokens in regular localStorage if XSS risk exists. Prefer httpOnly cookies for refresh tokens.

---

## 13. CORS Configuration

### Allowed Origins
```
Development: http://localhost:5173, http://localhost:3000
Staging: https://staging.financial-rise.com
Production: https://financial-rise.com, https://www.financial-rise.com
```

### Allowed Methods
```
GET, POST, PUT, PATCH, DELETE, OPTIONS
```

### Allowed Headers
```
Content-Type, Authorization, X-Requested-With
```

### Exposed Headers
```
X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset
```

---

## 14. Versioning Strategy

### URL Versioning
All endpoints use `/api/v1/` prefix.

### Version Deprecation Policy
- New version announced **90 days** before old version deprecation
- Old version continues working for **6 months** after new version release
- Deprecation warnings sent via `X-API-Deprecated` header:
  ```http
  X-API-Deprecated: true
  X-API-Sunset: 2026-06-01T00:00:00Z
  X-API-Upgrade-To: /api/v2/
  ```

---

## 15. Testing Recommendations

### Backend Testing
- Unit tests for all controllers, services, guards
- Integration tests for full API workflows
- E2E tests for critical paths (login → create assessment → generate report)
- Mock external dependencies (GCS, email)

### Frontend Testing
- Component tests with React Testing Library
- Mock API responses using this contract
- E2E tests with Playwright matching real API behavior

### Contract Validation
- Use tools like **Postman Collections** or **OpenAPI validators**
- Run contract tests on CI/CD pipeline
- Ensure frontend and backend teams validate against this contract weekly

---

## 16. Next Steps

### For Backend Team
1. ✅ Review and approve this contract
2. ⬜ Generate OpenAPI/Swagger spec from this document
3. ⬜ Implement endpoints matching these exact signatures
4. ⬜ Write integration tests validating all request/response formats
5. ⬜ Deploy to staging for frontend team integration testing

### For Frontend Team
1. ✅ Review and approve this contract
2. ⬜ Create TypeScript interfaces from Data Models section
3. ⬜ Build mock API service matching all endpoints
4. ⬜ Develop UI components using mock data
5. ⬜ Switch to real API once backend staging is ready

### For Both Teams
1. ⬜ Weekly sync to discuss any contract changes
2. ⬜ Document breaking changes in CHANGELOG
3. ⬜ Maintain backward compatibility during transition

---

## Approval Signatures

**Backend Team Lead:**
- Name: _________________
- Date: _________________
- Signature: _________________

**Frontend Team Lead:**
- Name: _________________
- Date: _________________
- Signature: _________________

**Project Manager:**
- Name: _________________
- Date: _________________
- Signature: _________________

---

**Document Version:** 1.0
**Last Updated:** 2025-12-27
**Next Review:** After first sprint integration testing
