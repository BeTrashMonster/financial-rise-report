# Authentication System Design Document
## Work Stream 3: Authentication System

**Version:** 1.0
**Date:** 2025-12-19
**Status:** In Progress
**Agent:** Backend Developer 2

---

## 1. Overview

This document defines the architecture and implementation plan for the Financial RISE Report authentication system (Work Stream 3). The system provides secure user authentication, role-based access control, and session management for consultants and administrators.

## 2. Requirements Summary

### Functional Requirements
- **REQ-AUTH-001:** Secure user authentication for consultants and administrators
- **REQ-AUTH-002:** Role-based access control (RBAC) - Consultant and Administrator roles
- **REQ-AUTH-003:** Password complexity: min 12 chars, uppercase, lowercase, number, special char
- **REQ-AUTH-004:** Account lockout after 5 failed login attempts within 15 minutes
- **REQ-AUTH-005:** Password reset mechanism via email verification
- **REQ-AUTH-006:** Session timeout after 30 minutes of inactivity

### Security Requirements
- **REQ-SEC-001:** TLS 1.2+ for data in transit
- **REQ-SEC-002:** Encrypt sensitive data at rest
- **REQ-SEC-003:** bcrypt password hashing (work factor ≥ 12)
- **REQ-SEC-004:** Protection against SQL injection, XSS, CSRF
- **REQ-SEC-005:** Rate limiting on auth endpoints (max 5 attempts per 15 min per IP)
- **REQ-SEC-007:** Authorization checks - consultants can only access own data
- **REQ-SEC-008:** Audit logs for all data access and modifications
- **REQ-SEC-010:** Password reset tokens expire after 24 hours or first use

### Technical Requirements
- **REQ-TECH-011:** JWT (JSON Web Tokens) for API authentication
- **REQ-TECH-007:** RESTful API endpoints
- **REQ-TECH-008:** JSON request/response payloads
- **REQ-TECH-010:** Appropriate HTTP status codes

---

## 3. Technology Stack

### Backend Framework
**Choice:** Node.js 18 LTS with Express.js

**Rationale:**
- Aligns with REQ-TECH-005 recommendations
- Excellent JWT library ecosystem (jsonwebtoken, passport-jwt)
- Large community and extensive middleware availability
- TypeScript support for type safety
- Fast development velocity

### Key Libraries
- **express** - Web framework
- **typescript** - Type safety
- **jsonwebtoken** - JWT creation and validation
- **bcrypt** - Password hashing
- **express-rate-limit** - Rate limiting middleware
- **express-validator** - Input validation and sanitization
- **nodemailer** - Email sending (password reset)
- **dotenv** - Environment variable management
- **pg** / **typeorm** - PostgreSQL database access
- **winston** - Logging
- **jest** - Unit testing
- **supertest** - API endpoint testing

---

## 4. Architecture

### 4.1 System Components

```
┌─────────────────────────────────────────────────────────────┐
│                       Client Application                     │
│                    (React/Vue Frontend)                      │
└────────────────────┬────────────────────────────────────────┘
                     │ HTTPS (TLS 1.2+)
                     │ JWT in Authorization Header
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                     API Gateway / Router                     │
│                      (Express.js)                            │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────┐   │
│  │         Authentication Middleware                    │   │
│  │  - JWT validation                                    │   │
│  │  - Token expiration check                            │   │
│  │  - User extraction from token                        │   │
│  └──────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │         Authorization Middleware                     │   │
│  │  - Role-based access control (RBAC)                  │   │
│  │  - Resource ownership validation                     │   │
│  └──────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │         Rate Limiting Middleware                     │   │
│  │  - IP-based rate limiting                            │   │
│  │  - Account lockout tracking                          │   │
│  └──────────────────────────────────────────────────────┘   │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                Authentication Service Layer                  │
├─────────────────────────────────────────────────────────────┤
│  - register()           - verifyPassword()                   │
│  - login()              - createAccessToken()                │
│  - logout()             - createRefreshToken()               │
│  - refreshToken()       - validateToken()                    │
│  - forgotPassword()     - checkAccountLockout()              │
│  - resetPassword()      - recordFailedAttempt()              │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                    Data Access Layer                         │
│                      (TypeORM)                               │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                  PostgreSQL Database                         │
├─────────────────────────────────────────────────────────────┤
│  Tables:                                                     │
│  - users                                                     │
│  - refresh_tokens                                            │
│  - password_reset_tokens                                     │
│  - failed_login_attempts                                     │
│  - audit_logs                                                │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 Token Strategy

**Access Token (JWT):**
- Short-lived (15 minutes)
- Stateless
- Contains: userId, email, role, issuedAt, expiresAt
- Signed with HS256 algorithm (HMAC with SHA-256)
- Sent in Authorization header: `Bearer <token>`

**Refresh Token:**
- Long-lived (7 days)
- Stored in database (allows revocation)
- Used to obtain new access tokens
- Rotated on each use (sliding window)
- HttpOnly, Secure cookie (optional alternative to response body)

### 4.3 Database Schema

```sql
-- Users Table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL CHECK (role IN ('consultant', 'admin')),
    is_active BOOLEAN DEFAULT true,
    email_verified BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login_at TIMESTAMP
);

-- Refresh Tokens Table
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP
);

-- Password Reset Tokens Table
CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    used_at TIMESTAMP
);

-- Failed Login Attempts Table
CREATE TABLE failed_login_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_email_time (email, attempted_at),
    INDEX idx_ip_time (ip_address, attempted_at)
);

-- Audit Logs Table
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id UUID,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    details JSONB
);

-- Indexes for performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_token ON refresh_tokens(token);
CREATE INDEX idx_password_reset_tokens_token ON password_reset_tokens(token);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
```

---

## 5. API Endpoints

### 5.1 POST /api/v1/auth/register

**Purpose:** Register a new consultant account

**Request:**
```json
{
  "email": "consultant@example.com",
  "password": "SecurePass123!",
  "role": "consultant"
}
```

**Response (201 Created):**
```json
{
  "message": "Account created successfully",
  "userId": "uuid-here"
}
```

**Validation:**
- Email: valid format, unique, max 255 chars
- Password: min 12 chars, uppercase, lowercase, number, special char
- Role: only "consultant" allowed via public endpoint (admin created by existing admin)

**Security:**
- Rate limit: 5 requests per hour per IP
- Password hashed with bcrypt (work factor 12)
- Input sanitization

---

### 5.2 POST /api/v1/auth/login

**Purpose:** Authenticate user and issue tokens

**Request:**
```json
{
  "email": "consultant@example.com",
  "password": "SecurePass123!"
}
```

**Response (200 OK):**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIs...",
  "refreshToken": "uuid-refresh-token",
  "expiresIn": 900,
  "user": {
    "id": "uuid",
    "email": "consultant@example.com",
    "role": "consultant"
  }
}
```

**Error Responses:**
- **401 Unauthorized:** Invalid credentials
- **403 Forbidden:** Account locked due to failed attempts
- **429 Too Many Requests:** Rate limit exceeded

**Security:**
- Rate limit: 5 attempts per 15 minutes per IP
- Account lockout after 5 failed attempts within 15 minutes
- Audit log all login attempts
- Update last_login_at on success

---

### 5.3 POST /api/v1/auth/logout

**Purpose:** Invalidate refresh token

**Headers:**
```
Authorization: Bearer <access-token>
```

**Request:**
```json
{
  "refreshToken": "uuid-refresh-token"
}
```

**Response (200 OK):**
```json
{
  "message": "Logged out successfully"
}
```

**Security:**
- Require valid access token
- Mark refresh token as revoked in database
- Audit log logout event

---

### 5.4 POST /api/v1/auth/refresh

**Purpose:** Obtain new access token using refresh token

**Request:**
```json
{
  "refreshToken": "uuid-refresh-token"
}
```

**Response (200 OK):**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIs...",
  "refreshToken": "new-uuid-refresh-token",
  "expiresIn": 900
}
```

**Error Responses:**
- **401 Unauthorized:** Invalid or expired refresh token

**Security:**
- Validate refresh token exists in database and not revoked
- Check expiration
- Rotate refresh token (delete old, create new)
- Rate limit: 10 requests per minute per user

---

### 5.5 POST /api/v1/auth/forgot-password

**Purpose:** Initiate password reset process

**Request:**
```json
{
  "email": "consultant@example.com"
}
```

**Response (200 OK):**
```json
{
  "message": "If an account exists with this email, a password reset link has been sent."
}
```

**Security:**
- Always return 200 OK (don't reveal if email exists)
- Generate secure random token (32 bytes, base64url)
- Token expires in 24 hours
- Rate limit: 3 requests per hour per IP
- Send email with reset link: `https://app.example.com/reset-password?token=<token>`
- Audit log password reset requests

---

### 5.6 POST /api/v1/auth/reset-password

**Purpose:** Complete password reset with token

**Request:**
```json
{
  "token": "reset-token-here",
  "newPassword": "NewSecurePass456!"
}
```

**Response (200 OK):**
```json
{
  "message": "Password reset successfully"
}
```

**Error Responses:**
- **400 Bad Request:** Invalid or expired token
- **422 Unprocessable Entity:** Password doesn't meet complexity requirements

**Security:**
- Validate token exists, not used, not expired
- Validate new password complexity
- Hash new password with bcrypt
- Mark token as used
- Revoke all existing refresh tokens for user
- Audit log password reset completion
- Send confirmation email

---

## 6. Security Implementation Details

### 6.1 Password Hashing
```typescript
import bcrypt from 'bcrypt';

const SALT_ROUNDS = 12; // REQ-SEC-003

async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, SALT_ROUNDS);
}

async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}
```

### 6.2 JWT Creation
```typescript
import jwt from 'jsonwebtoken';

interface AccessTokenPayload {
  userId: string;
  email: string;
  role: 'consultant' | 'admin';
}

function createAccessToken(payload: AccessTokenPayload): string {
  return jwt.sign(payload, process.env.JWT_SECRET!, {
    expiresIn: '15m',
    algorithm: 'HS256'
  });
}

function verifyAccessToken(token: string): AccessTokenPayload {
  return jwt.verify(token, process.env.JWT_SECRET!) as AccessTokenPayload;
}
```

### 6.3 Account Lockout Logic
```typescript
async function checkAccountLockout(email: string): Promise<boolean> {
  const fifteenMinutesAgo = new Date(Date.now() - 15 * 60 * 1000);

  const failedAttempts = await failedLoginAttemptsRepository.count({
    where: {
      email,
      attempted_at: MoreThan(fifteenMinutesAgo)
    }
  });

  return failedAttempts >= 5; // REQ-AUTH-004
}
```

### 6.4 Rate Limiting
```typescript
import rateLimit from 'express-rate-limit';

// Auth endpoints rate limiter (REQ-SEC-005)
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many authentication attempts, please try again later.'
});

// Registration rate limiter
export const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5,
  message: 'Too many account creation attempts, please try again later.'
});
```

### 6.5 Input Validation
```typescript
import { body, validationResult } from 'express-validator';

export const registerValidation = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .isLength({ max: 255 })
    .withMessage('Valid email required'),

  body('password')
    .isLength({ min: 12 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must be at least 12 characters with uppercase, lowercase, number, and special character'),

  body('role')
    .isIn(['consultant'])
    .withMessage('Invalid role')
];
```

---

## 7. Testing Strategy

### 7.1 Unit Tests (Target: 80%+ coverage)

**Authentication Service Tests:**
- ✅ Password hashing and verification
- ✅ JWT token creation and validation
- ✅ Token expiration handling
- ✅ Refresh token rotation
- ✅ Account lockout logic
- ✅ Password reset token generation

**Middleware Tests:**
- ✅ JWT authentication middleware
- ✅ Role-based authorization middleware
- ✅ Input validation
- ✅ Error handling

### 7.2 Integration Tests

**API Endpoint Tests:**
- ✅ POST /api/v1/auth/register - successful registration
- ✅ POST /api/v1/auth/register - duplicate email rejection
- ✅ POST /api/v1/auth/register - password validation
- ✅ POST /api/v1/auth/login - successful login
- ✅ POST /api/v1/auth/login - invalid credentials
- ✅ POST /api/v1/auth/login - account lockout after 5 failures
- ✅ POST /api/v1/auth/logout - successful logout
- ✅ POST /api/v1/auth/refresh - token refresh
- ✅ POST /api/v1/auth/refresh - expired token rejection
- ✅ POST /api/v1/auth/forgot-password - email sent
- ✅ POST /api/v1/auth/reset-password - successful reset

### 7.3 Security Tests (REQ-SECTEST-001, REQ-SECTEST-002)

- ✅ SQL injection attempts blocked
- ✅ XSS payload sanitization
- ✅ CSRF protection
- ✅ Rate limiting enforcement
- ✅ Authorization bypass attempts
- ✅ Token tampering detection
- ✅ Expired token rejection

---

## 8. Implementation Checklist

### Phase 1: Project Setup
- [ ] Initialize Node.js + TypeScript project
- [ ] Install dependencies
- [ ] Configure TypeORM with PostgreSQL
- [ ] Set up environment variables (.env)
- [ ] Create database migration scripts
- [ ] Configure Jest for testing

### Phase 2: Core Authentication
- [ ] Create User entity and repository
- [ ] Implement password hashing utilities
- [ ] Implement JWT utilities (create, verify)
- [ ] Create authentication service
- [ ] Implement register endpoint
- [ ] Implement login endpoint
- [ ] Write unit tests for auth service

### Phase 3: Token Management
- [ ] Create RefreshToken entity and repository
- [ ] Implement refresh token creation and validation
- [ ] Implement logout endpoint
- [ ] Implement refresh endpoint
- [ ] Write unit tests for token management

### Phase 4: Middleware
- [ ] Create JWT authentication middleware
- [ ] Create RBAC authorization middleware
- [ ] Create rate limiting middleware
- [ ] Create input validation middleware
- [ ] Write unit tests for middleware

### Phase 5: Password Reset
- [ ] Create PasswordResetToken entity
- [ ] Implement forgot-password endpoint
- [ ] Implement reset-password endpoint
- [ ] Configure email service (Nodemailer)
- [ ] Create password reset email template
- [ ] Write integration tests

### Phase 6: Security Hardening
- [ ] Implement account lockout logic
- [ ] Create FailedLoginAttempts entity
- [ ] Implement audit logging
- [ ] Create AuditLog entity
- [ ] Add input sanitization
- [ ] Configure CORS
- [ ] Configure helmet.js security headers

### Phase 7: Testing & Documentation
- [ ] Write comprehensive unit tests
- [ ] Write integration tests for all endpoints
- [ ] Perform security testing
- [ ] Generate API documentation (Swagger/OpenAPI)
- [ ] Write deployment guide
- [ ] Achieve 80%+ code coverage

---

## 9. Environment Variables

```env
# Server
NODE_ENV=development
PORT=3000

# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=financial_rise_dev
DB_USER=postgres
DB_PASSWORD=your-secure-password

# JWT
JWT_SECRET=your-secure-secret-key-min-32-chars
JWT_REFRESH_SECRET=your-refresh-secret-key-min-32-chars

# Email (SendGrid or AWS SES)
EMAIL_SERVICE=sendgrid
EMAIL_API_KEY=your-sendgrid-api-key
EMAIL_FROM=noreply@financialrise.com

# Application
APP_URL=http://localhost:3000
FRONTEND_URL=http://localhost:5173

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=5
```

---

## 10. Deliverables

- [ ] Complete authentication system with all endpoints
- [ ] Database schema and migrations
- [ ] Unit tests (80%+ coverage)
- [ ] Integration tests for all endpoints
- [ ] API documentation (Swagger/OpenAPI)
- [ ] Security audit report
- [ ] Deployment guide

---

## 11. Dependencies

**Blocks:**
- All protected API endpoints (assessments, reports, etc.)
- Admin interface (Work Stream 9)
- User management features

**Depends On:**
- Database schema (Work Stream 2) - can mock initially for development

---

## 12. Success Criteria

- ✅ All authentication endpoints functional and tested
- ✅ 80%+ code coverage achieved
- ✅ All security requirements met (REQ-SEC-001 through REQ-SEC-010)
- ✅ Rate limiting enforced
- ✅ Account lockout working after 5 failed attempts
- ✅ Password reset flow complete with email delivery
- ✅ JWT authentication and refresh token rotation working
- ✅ RBAC implemented (consultant vs admin roles)
- ✅ API documentation generated and accurate
- ✅ Security testing completed with no critical vulnerabilities

---

**Document Status:** Active Development
**Next Review:** Upon Phase 7 completion
