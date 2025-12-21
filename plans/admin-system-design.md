# Admin Interface System Design Document
## Work Stream 9: Admin Interface

**Version:** 1.0
**Date:** 2025-12-19
**Status:** In Progress
**Agent:** Backend Developer 1

---

## 1. Overview

This document defines the architecture and implementation plan for the Financial RISE Report admin interface (Work Stream 9). The system provides administrators with the ability to manage consultant accounts, view activity logs, and monitor system metrics.

## 2. Requirements Summary

### Functional Requirements
- **REQ-ADMIN-001:** Admin interface for managing consultant user accounts
- **REQ-ADMIN-002:** Create new consultant accounts with email and initial password
- **REQ-ADMIN-003:** Deactivate consultant accounts
- **REQ-ADMIN-004:** Reset consultant passwords
- **REQ-ADMIN-005:** View user activity logs (login history, assessment activity)
- **REQ-ADMIN-006:** Log all authentication events (already implemented in Work Stream 3)
- **REQ-ADMIN-007:** Log assessment events (will be implemented in Work Stream 6)
- **REQ-ADMIN-008:** Performance monitoring dashboard (SHOULD - low priority, deferred)

### Security Requirements
- Admin-only access using RBAC (from Work Stream 3)
- All admin actions must be audit logged
- Sensitive operations require authentication

---

## 3. Architecture

### 3.1 System Components

```
┌─────────────────────────────────────────────────────────────┐
│                   Admin Client (Frontend)                    │
│            Future: React Admin Dashboard (WS 9)             │
└────────────────────┬────────────────────────────────────────┘
                     │ HTTPS + JWT (Admin Role Required)
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                     Admin API Router                         │
│                  /api/v1/admin/*                            │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────┐   │
│  │    Authentication Middleware (from WS 3)             │   │
│  │    - Verify JWT token                                │   │
│  └──────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │    Authorization Middleware (from WS 3)              │   │
│  │    - Require ADMIN role                              │   │
│  └──────────────────────────────────────────────────────┘   │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                  Admin Service Layer                         │
├─────────────────────────────────────────────────────────────┤
│  - listUsers()                                               │
│  - createUser()                                              │
│  - updateUser()                                              │
│  - deactivateUser()                                          │
│  - resetUserPassword()                                       │
│  - getActivityLogs()                                         │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              Existing Database Entities                      │
│                  (from Work Stream 3)                        │
├─────────────────────────────────────────────────────────────┤
│  - User (consultants and admins)                            │
│  - AuditLog (activity tracking)                             │
│  - RefreshToken (for password reset side effects)           │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 Dependencies

**Leveraging Work Stream 3 (Authentication System):**
- ✅ User entity with role field (consultant, admin)
- ✅ AuditLog entity for activity tracking
- ✅ `authenticate` middleware for JWT validation
- ✅ `authorize(UserRole.ADMIN)` middleware for admin-only access
- ✅ Password hashing utilities
- ✅ Audit logging service

**No new database entities required!**

---

## 4. API Endpoints

### 4.1 GET /api/v1/admin/users

**Purpose:** List all users (consultants and admins) with pagination

**Authorization:** Admin only

**Query Parameters:**
```typescript
{
  page?: number;        // Default: 1
  limit?: number;       // Default: 20, max: 100
  role?: 'consultant' | 'admin';  // Filter by role
  isActive?: boolean;   // Filter by active status
  search?: string;      // Search by email
}
```

**Response (200 OK):**
```json
{
  "users": [
    {
      "id": "uuid",
      "email": "consultant@example.com",
      "role": "consultant",
      "isActive": true,
      "emailVerified": false,
      "createdAt": "2025-12-19T10:00:00.000Z",
      "updatedAt": "2025-12-19T10:00:00.000Z",
      "lastLoginAt": "2025-12-19T11:30:00.000Z"
    }
  ],
  "pagination": {
    "total": 45,
    "page": 1,
    "limit": 20,
    "totalPages": 3
  }
}
```

---

### 4.2 POST /api/v1/admin/users

**Purpose:** Create a new user account (consultant or admin)

**Authorization:** Admin only

**Request:**
```json
{
  "email": "newconsultant@example.com",
  "password": "TemporaryPass123!",
  "role": "consultant"
}
```

**Response (201 Created):**
```json
{
  "message": "User created successfully",
  "user": {
    "id": "uuid",
    "email": "newconsultant@example.com",
    "role": "consultant",
    "isActive": true,
    "createdAt": "2025-12-19T10:00:00.000Z"
  }
}
```

**Validation:**
- Email: valid format, unique, max 255 chars
- Password: complexity requirements (REQ-AUTH-003)
- Role: 'consultant' or 'admin'

**Security:**
- Rate limit: 10 users per hour per admin (prevent abuse)
- Audit log creation with admin user ID
- Password hashed with bcrypt

---

### 4.3 PATCH /api/v1/admin/users/:id

**Purpose:** Update user account details

**Authorization:** Admin only

**Request:**
```json
{
  "email": "updatedemail@example.com",  // Optional
  "role": "admin",                       // Optional
  "isActive": false                      // Optional
}
```

**Response (200 OK):**
```json
{
  "message": "User updated successfully",
  "user": {
    "id": "uuid",
    "email": "updatedemail@example.com",
    "role": "admin",
    "isActive": false,
    "updatedAt": "2025-12-19T12:00:00.000Z"
  }
}
```

**Validation:**
- Cannot deactivate last admin
- Cannot change own role (prevent lockout)
- Email must be unique if changed

**Security:**
- Audit log update action
- Revoke all refresh tokens if role changed

---

### 4.4 DELETE /api/v1/admin/users/:id

**Purpose:** Delete a user account (hard delete)

**Authorization:** Admin only

**Response (200 OK):**
```json
{
  "message": "User deleted successfully"
}
```

**Validation:**
- Cannot delete last admin
- Cannot delete own account

**Security:**
- Audit log deletion action
- Cascade delete: all refresh tokens, password reset tokens
- Consider soft delete instead (set isActive=false)

---

### 4.5 POST /api/v1/admin/users/:id/reset-password

**Purpose:** Admin-initiated password reset for a user

**Authorization:** Admin only

**Request:**
```json
{
  "newPassword": "NewTemporaryPass456!"
}
```

**Response (200 OK):**
```json
{
  "message": "Password reset successfully"
}
```

**Validation:**
- Password complexity requirements (REQ-AUTH-003)

**Security:**
- Revoke all refresh tokens for user (force re-login)
- Audit log password reset action
- Send email notification to user

---

### 4.6 GET /api/v1/admin/activity-logs

**Purpose:** View system activity logs

**Authorization:** Admin only

**Query Parameters:**
```typescript
{
  page?: number;           // Default: 1
  limit?: number;          // Default: 50, max: 200
  userId?: string;         // Filter by user
  action?: string;         // Filter by action type
  startDate?: string;      // ISO 8601 date
  endDate?: string;        // ISO 8601 date
  resourceType?: string;   // Filter by resource type
}
```

**Response (200 OK):**
```json
{
  "logs": [
    {
      "id": "uuid",
      "userId": "uuid",
      "action": "user.login",
      "resourceType": "user",
      "resourceId": "uuid",
      "ipAddress": "192.168.1.1",
      "userAgent": "Mozilla/5.0...",
      "createdAt": "2025-12-19T10:00:00.000Z",
      "details": {
        "success": true
      },
      "user": {
        "email": "consultant@example.com"
      }
    }
  ],
  "pagination": {
    "total": 1234,
    "page": 1,
    "limit": 50,
    "totalPages": 25
  }
}
```

**Performance:**
- Indexes on userId, createdAt, action (already in AuditLog entity)
- Default date range: last 30 days if not specified
- Export to CSV option (future enhancement)

---

## 5. Implementation Details

### 5.1 Admin Service

**Location:** `src/services/AdminService.ts`

```typescript
import { Repository, FindOptionsWhere, Like, Between } from 'typeorm';
import { User, UserRole } from '../database/entities/User';
import { AuditLog } from '../database/entities/AuditLog';
import { RefreshToken } from '../database/entities/RefreshToken';
import { hashPassword, validatePasswordComplexity } from '../utils/password';

export interface ListUsersInput {
  page?: number;
  limit?: number;
  role?: UserRole;
  isActive?: boolean;
  search?: string;
}

export interface CreateUserInput {
  email: string;
  password: string;
  role: UserRole;
}

export interface UpdateUserInput {
  email?: string;
  role?: UserRole;
  isActive?: boolean;
}

export interface ListActivityLogsInput {
  page?: number;
  limit?: number;
  userId?: string;
  action?: string;
  startDate?: Date;
  endDate?: Date;
  resourceType?: string;
}

export class AdminService {
  constructor(
    private userRepository: Repository<User>,
    private auditLogRepository: Repository<AuditLog>,
    private refreshTokenRepository: Repository<RefreshToken>
  ) {}

  /**
   * List all users with pagination and filtering
   * REQ-ADMIN-001
   */
  async listUsers(input: ListUsersInput, adminId: string) {
    // Implementation
  }

  /**
   * Create a new user account
   * REQ-ADMIN-002
   */
  async createUser(input: CreateUserInput, adminId: string) {
    // Implementation
  }

  /**
   * Update user account
   * REQ-ADMIN-003
   */
  async updateUser(userId: string, input: UpdateUserInput, adminId: string) {
    // Implementation
  }

  /**
   * Delete user account
   */
  async deleteUser(userId: string, adminId: string) {
    // Implementation
  }

  /**
   * Reset user password (admin-initiated)
   * REQ-ADMIN-004
   */
  async resetUserPassword(userId: string, newPassword: string, adminId: string) {
    // Implementation
  }

  /**
   * Get activity logs with pagination and filtering
   * REQ-ADMIN-005
   */
  async getActivityLogs(input: ListActivityLogsInput, adminId: string) {
    // Implementation
  }
}
```

### 5.2 Admin Controller

**Location:** `src/controllers/AdminController.ts`

```typescript
import { Request, Response } from 'express';
import { AdminService } from '../services/AdminService';

export class AdminController {
  constructor(private adminService: AdminService) {}

  async listUsers(req: Request, res: Response): Promise<void> {
    // Extract query params, call service, return response
  }

  async createUser(req: Request, res: Response): Promise<void> {
    // Extract body, call service, return response
  }

  async updateUser(req: Request, res: Response): Promise<void> {
    // Extract params and body, call service, return response
  }

  async deleteUser(req: Request, res: Response): Promise<void> {
    // Extract params, call service, return response
  }

  async resetUserPassword(req: Request, res: Response): Promise<void> {
    // Extract params and body, call service, return response
  }

  async getActivityLogs(req: Request, res: Response): Promise<void> {
    // Extract query params, call service, return response
  }
}
```

### 5.3 Admin Routes

**Location:** `src/routes/admin.routes.ts`

```typescript
import { Router } from 'express';
import { AdminController } from '../controllers/AdminController';
import { authenticate, authorize } from '../middleware/auth';
import { UserRole } from '../database/entities/User';

export function createAdminRoutes(adminController: AdminController): Router {
  const router = Router();

  // All admin routes require authentication AND admin role
  router.use(authenticate, authorize(UserRole.ADMIN));

  router.get('/users', (req, res) => adminController.listUsers(req, res));
  router.post('/users', (req, res) => adminController.createUser(req, res));
  router.patch('/users/:id', (req, res) => adminController.updateUser(req, res));
  router.delete('/users/:id', (req, res) => adminController.deleteUser(req, res));
  router.post('/users/:id/reset-password', (req, res) => adminController.resetUserPassword(req, res));
  router.get('/activity-logs', (req, res) => adminController.getActivityLogs(req, res));

  return router;
}
```

### 5.4 Validation Middleware

**Location:** `src/middleware/validator.ts` (extend existing)

```typescript
export const createUserValidation = [
  body('email').isEmail().normalizeEmail().isLength({ max: 255 }),
  body('password').isLength({ min: 12 }).matches(/[a-z]/).matches(/[A-Z]/).matches(/\d/).matches(/[@$!%*?&]/),
  body('role').isIn(['consultant', 'admin']),
  handleValidationErrors
];

export const updateUserValidation = [
  body('email').optional().isEmail().normalizeEmail(),
  body('role').optional().isIn(['consultant', 'admin']),
  body('isActive').optional().isBoolean(),
  handleValidationErrors
];

export const resetPasswordValidation = [
  body('newPassword').isLength({ min: 12 }).matches(/[a-z]/).matches(/[A-Z]/).matches(/\d/).matches(/[@$!%*?&]/),
  handleValidationErrors
];
```

---

## 6. Security Considerations

### 6.1 Authorization

**All admin endpoints require:**
1. Valid JWT access token (`authenticate` middleware)
2. Admin role (`authorize(UserRole.ADMIN)` middleware)

**Prevents:**
- Consultant users from accessing admin functions
- Unauthenticated access to user management
- Privilege escalation attacks

### 6.2 Self-Protection

**Safeguards:**
- Cannot delete last admin (prevent lockout)
- Cannot change own role (prevent accidental demotion)
- Cannot delete own account (prevent accidental lockout)
- All admin actions audit logged with admin user ID

### 6.3 Audit Logging

**All admin actions logged:**
- `admin.user.created` - User creation with email and role
- `admin.user.updated` - User updates with changed fields
- `admin.user.deleted` - User deletion with email
- `admin.user.password_reset` - Password reset with target user ID
- `admin.activity_logs.viewed` - Activity log access with filters

**Log includes:**
- Admin user ID (who performed action)
- Target user ID (who was affected)
- IP address and user agent
- Timestamp
- Action details (what changed)

### 6.4 Rate Limiting

**Admin-specific limits:**
- User creation: 10 per hour per admin (prevent bulk account creation)
- General admin endpoints: 100 requests per minute per admin
- Activity log queries: 50 per minute per admin (prevent data scraping)

---

## 7. Testing Strategy

### 7.1 Unit Tests

**AdminService Tests:**
- ✅ List users with pagination
- ✅ List users with filters (role, active status, search)
- ✅ Create user with valid data
- ✅ Create user with duplicate email (should fail)
- ✅ Update user details
- ✅ Update user email to existing email (should fail)
- ✅ Deactivate user
- ✅ Delete user
- ✅ Cannot delete last admin
- ✅ Cannot delete own account
- ✅ Reset user password
- ✅ List activity logs with pagination
- ✅ List activity logs with filters

### 7.2 Integration Tests

**API Endpoint Tests:**
- ✅ GET /admin/users - list all users
- ✅ GET /admin/users?role=consultant - filter by role
- ✅ GET /admin/users?search=john - search by email
- ✅ POST /admin/users - create consultant
- ✅ POST /admin/users - create admin
- ✅ POST /admin/users with invalid password (should fail)
- ✅ PATCH /admin/users/:id - update email
- ✅ PATCH /admin/users/:id - deactivate user
- ✅ PATCH /admin/users/:id - cannot change own role (should fail)
- ✅ DELETE /admin/users/:id - delete user
- ✅ DELETE /admin/users/:id - cannot delete last admin (should fail)
- ✅ POST /admin/users/:id/reset-password - reset password
- ✅ GET /admin/activity-logs - list all logs
- ✅ GET /admin/activity-logs?userId=xxx - filter by user
- ✅ Consultant cannot access admin endpoints (401/403)

### 7.3 Security Tests

- ✅ Admin middleware blocks non-admin users
- ✅ Admin middleware blocks unauthenticated requests
- ✅ Cannot escalate privileges by modifying own role
- ✅ All admin actions create audit log entries
- ✅ Rate limiting enforced on admin endpoints
- ✅ Input validation prevents injection attacks

---

## 8. Implementation Checklist

### Phase 1: Service Layer
- [ ] Create AdminService class
- [ ] Implement listUsers with pagination
- [ ] Implement createUser with validation
- [ ] Implement updateUser with safeguards
- [ ] Implement deleteUser with safeguards
- [ ] Implement resetUserPassword
- [ ] Implement getActivityLogs with filters
- [ ] Write unit tests for AdminService

### Phase 2: Controller & Routes
- [ ] Create AdminController class
- [ ] Implement controller methods
- [ ] Create admin route definitions
- [ ] Add validation middleware for admin endpoints
- [ ] Integrate with Express app

### Phase 3: Testing & Documentation
- [ ] Write integration tests for all endpoints
- [ ] Test authorization (admin-only access)
- [ ] Test safeguards (cannot delete last admin, etc.)
- [ ] Update README with admin API documentation
- [ ] Create admin API reference

---

## 9. Future Enhancements (Post-MVP)

### Phase 2 Enhancements (Work Stream 45)
- Admin performance monitoring dashboard (REQ-ADMIN-008)
- System metrics: active users, assessments completed
- Resource usage monitoring

### Phase 3 Enhancements (Work Stream 46)
- Enhanced activity logging with search
- Advanced log filtering and export
- CSV/JSON export of activity logs
- Real-time activity monitoring

### Additional Features
- Bulk user operations (import, export, bulk deactivate)
- User impersonation (for support purposes)
- Configurable email templates for admin-created users
- Two-factor authentication enforcement for admins
- IP whitelisting for admin access

---

## 10. Deliverables

- [ ] AdminService with all user management methods
- [ ] AdminController with HTTP request handlers
- [ ] Admin route definitions with RBAC
- [ ] Validation middleware for admin endpoints
- [ ] Unit tests (80%+ coverage)
- [ ] Integration tests for all endpoints
- [ ] API documentation
- [ ] Security audit compliance

---

## 11. Success Criteria

- ✅ All admin endpoints functional and tested
- ✅ RBAC enforced (admin-only access)
- ✅ Cannot delete last admin or own account
- ✅ All admin actions audit logged
- ✅ 80%+ code coverage achieved
- ✅ All requirements met (REQ-ADMIN-001 through REQ-ADMIN-005)
- ✅ Integration with existing auth system (Work Stream 3)
- ✅ API documentation complete
- ✅ Security testing passed

---

**Document Status:** Active Development
**Dependencies:** Work Stream 3 (Auth) ✅ Complete
**Next Review:** Upon completion
