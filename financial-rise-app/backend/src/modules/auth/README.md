# Authentication System Documentation

## Overview

This authentication system provides secure user authentication and authorization for the Financial RISE Report application using JWT (JSON Web Tokens) with refresh token rotation, bcrypt password hashing, and role-based access control (RBAC).

## Features

- **User Registration** with strong password validation
- **JWT-based Authentication** with access and refresh tokens
- **Account Lockout Protection** (5 failed login attempts = 30-minute lock)
- **Password Reset Flow** with secure token generation
- **Role-Based Access Control** (Consultant, Admin)
- **Refresh Token Rotation** for enhanced security
- **TypeORM Integration** with PostgreSQL
- **Input Validation** using class-validator

## Architecture

### Module Structure

```
src/modules/
├── auth/
│   ├── decorators/
│   │   └── roles.decorator.ts        # @Roles() decorator for RBAC
│   ├── dto/
│   │   ├── forgot-password.dto.ts    # Email validation for password reset
│   │   ├── login.dto.ts              # Login credentials validation
│   │   ├── refresh-token.dto.ts      # Refresh token validation
│   │   ├── register.dto.ts           # User registration validation
│   │   └── reset-password.dto.ts     # Password reset validation
│   ├── guards/
│   │   ├── jwt-auth.guard.ts         # JWT authentication guard
│   │   ├── local-auth.guard.ts       # Local authentication guard
│   │   └── roles.guard.ts            # Role-based authorization guard
│   ├── strategies/
│   │   ├── jwt.strategy.ts           # JWT Passport strategy
│   │   └── local.strategy.ts         # Local Passport strategy
│   ├── auth.controller.ts            # Authentication endpoints
│   ├── auth.module.ts                # Auth module configuration
│   ├── auth.service.ts               # Authentication business logic
│   └── README.md                     # This file
└── users/
    ├── entities/
    │   └── user.entity.ts            # User TypeORM entity
    ├── users.controller.ts           # User management endpoints
    ├── users.module.ts               # Users module configuration
    └── users.service.ts              # User CRUD operations
```

## User Entity

### Schema (`user.entity.ts`)

| Column                    | Type      | Description                                    |
|---------------------------|-----------|------------------------------------------------|
| `id`                      | UUID      | Primary key                                    |
| `email`                   | VARCHAR   | Unique email address (indexed)                 |
| `password_hash`           | VARCHAR   | Bcrypt hashed password (12 rounds)             |
| `first_name`              | VARCHAR   | User's first name                              |
| `last_name`               | VARCHAR   | User's last name                               |
| `role`                    | ENUM      | consultant \| admin                            |
| `status`                  | ENUM      | active \| inactive \| locked                   |
| `failed_login_attempts`   | INT       | Counter for failed login attempts              |
| `locked_until`            | TIMESTAMP | Account unlock time (null if not locked)       |
| `reset_password_token`    | VARCHAR   | Hashed password reset token                    |
| `reset_password_expires`  | TIMESTAMP | Token expiration time                          |
| `refresh_token`           | VARCHAR   | Hashed refresh token                           |
| `created_at`              | TIMESTAMP | Account creation timestamp                     |
| `updated_at`              | TIMESTAMP | Last update timestamp                          |
| `last_login_at`           | TIMESTAMP | Last successful login                          |

### Enums

```typescript
enum UserRole {
  CONSULTANT = 'consultant',
  ADMIN = 'admin',
}

enum UserStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  LOCKED = 'locked',
}
```

## API Endpoints

### POST `/auth/register`

Register a new user account.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecureP@ss123",
  "first_name": "John",
  "last_name": "Doe",
  "role": "consultant"
}
```

**Password Requirements:**
- Minimum 8 characters
- Maximum 128 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character (@$!%*?&#)

**Response (201 Created):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "role": "consultant"
  }
}
```

---

### POST `/auth/login`

Authenticate user and receive JWT tokens.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecureP@ss123"
}
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "role": "consultant"
  }
}
```

**Error Response (401 Unauthorized):**
```json
{
  "statusCode": 401,
  "message": "Invalid email or password"
}
```

**Account Lockout Response (401 Unauthorized):**
```json
{
  "statusCode": 401,
  "message": "Account is locked due to multiple failed login attempts. Please try again in 28 minutes."
}
```

---

### POST `/auth/logout`

Invalidate refresh token (requires authentication).

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (200 OK):**
```json
{
  "message": "Logged out successfully"
}
```

---

### POST `/auth/refresh`

Obtain a new access token using refresh token.

**Request Body:**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

---

### POST `/auth/forgot-password`

Request password reset email.

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

**Response (200 OK):**
```json
{
  "message": "If an account with that email exists, a password reset link has been sent."
}
```

**Development Mode Only:**
```json
{
  "message": "If an account with that email exists, a password reset link has been sent.",
  "resetToken": "a1b2c3d4e5f6..."
}
```

---

### POST `/auth/reset-password`

Reset password using reset token.

**Request Body:**
```json
{
  "token": "a1b2c3d4e5f6...",
  "new_password": "NewSecureP@ss456"
}
```

**Response (200 OK):**
```json
{
  "message": "Password has been reset successfully"
}
```

**Error Response (400 Bad Request):**
```json
{
  "statusCode": 400,
  "message": "Invalid or expired reset token"
}
```

---

### GET `/users/profile`

Get authenticated user profile (requires authentication).

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (200 OK):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "role": "consultant",
  "status": "active",
  "created_at": "2025-12-19T10:30:00Z",
  "updated_at": "2025-12-19T10:30:00Z",
  "last_login_at": "2025-12-19T12:45:00Z"
}
```

## Security Features

### Password Hashing

- **Algorithm:** bcrypt
- **Salt Rounds:** 12
- **Storage:** Only password hashes are stored, never plaintext passwords

### Account Lockout

- **Trigger:** 5 consecutive failed login attempts
- **Duration:** 30 minutes
- **Auto-unlock:** Account automatically unlocks after 30 minutes
- **Counter Reset:** Failed attempts reset to 0 on successful login

### JWT Configuration

**Access Token:**
- **Expiration:** 1 hour (configurable via `JWT_EXPIRATION`)
- **Secret:** Stored in `JWT_SECRET` environment variable
- **Algorithm:** HS256

**Refresh Token:**
- **Expiration:** 7 days (configurable via `JWT_REFRESH_EXPIRATION`)
- **Secret:** Stored in `JWT_REFRESH_SECRET` environment variable
- **Storage:** Hashed and stored in database
- **Rotation:** New refresh token generated on each login

### Password Reset

- **Token Generation:** 32-byte cryptographically secure random token
- **Expiration:** 1 hour
- **Storage:** Hashed token stored in database
- **Security:** Tokens are single-use and invalidated after password reset

## Guards and Decorators

### JWT Auth Guard

Protect routes requiring authentication:

```typescript
@UseGuards(JwtAuthGuard)
@Get('protected')
async getProtectedResource(@Request() req) {
  // req.user contains { userId, email, role }
  return { data: 'Protected data' };
}
```

### Roles Guard

Restrict access by user role:

```typescript
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(UserRole.ADMIN)
@Get('admin-only')
async adminOnlyEndpoint() {
  return { data: 'Admin only data' };
}
```

### Combined Usage

```typescript
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(UserRole.ADMIN, UserRole.CONSULTANT)
@Get('multi-role')
async multiRoleEndpoint(@Request() req) {
  return { userId: req.user.userId };
}
```

## Environment Variables

Required environment variables in `.env`:

```bash
# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_REFRESH_SECRET=your-super-secret-refresh-key-change-this-in-production
JWT_EXPIRATION=1h
JWT_REFRESH_EXPIRATION=7d
JWT_EXPIRATION_SECONDS=3600

# Database Configuration
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_USER=financial_rise_user
DATABASE_PASSWORD=secure_password
DATABASE_NAME=financial_rise_db

# Node Environment
NODE_ENV=development
```

## Usage Examples

### Registering a New User

```typescript
import { AuthService } from './auth/auth.service';
import { RegisterDto } from './auth/dto/register.dto';

// In a controller or service
const registerDto: RegisterDto = {
  email: 'consultant@example.com',
  password: 'SecureP@ss123',
  first_name: 'Jane',
  last_name: 'Smith',
  role: UserRole.CONSULTANT,
};

const result = await authService.register(registerDto);
// Returns { access_token, refresh_token, user }
```

### Validating User Credentials

```typescript
const user = await authService.validateUser(
  'consultant@example.com',
  'SecureP@ss123'
);

if (!user) {
  throw new UnauthorizedException('Invalid credentials');
}
```

### Refreshing Access Token

```typescript
const newTokens = await authService.refreshToken(oldRefreshToken);
// Returns { access_token, token_type, expires_in }
```

### Password Reset Flow

```typescript
// Step 1: Request reset
await authService.forgotPassword('user@example.com');
// Sends email with reset token

// Step 2: Reset password
await authService.resetPassword(resetToken, 'NewSecureP@ss456');
// Updates password and invalidates token
```

## Database Migration

To create the users table, run the TypeORM migration:

```bash
npm run migration:generate -- -n CreateUsersTable
npm run migration:run
```

Or use the provided SQL schema in `database/migrations/`.

## Testing

### Unit Tests

Test files should be created for:
- `auth.service.spec.ts`
- `auth.controller.spec.ts`
- `users.service.spec.ts`
- `jwt.strategy.spec.ts`
- `local.strategy.spec.ts`

### Integration Tests

E2E tests for authentication flow:
- User registration
- Login with valid/invalid credentials
- Account lockout after 5 failed attempts
- Token refresh flow
- Password reset flow
- Protected route access

## Best Practices

1. **Never log sensitive data** (passwords, tokens)
2. **Use HTTPS in production** for all API requests
3. **Rotate JWT secrets regularly** in production
4. **Implement rate limiting** on authentication endpoints
5. **Use secure password storage** (bcrypt with 12+ rounds)
6. **Validate all inputs** using DTOs and class-validator
7. **Implement refresh token rotation** to prevent token theft
8. **Use short-lived access tokens** (1 hour recommended)
9. **Store refresh tokens securely** (hashed in database)
10. **Implement CORS properly** to prevent unauthorized access

## Security Considerations

### Password Policy

The system enforces strong passwords with:
- Minimum length: 8 characters
- Complexity requirements: uppercase, lowercase, numbers, special characters
- Maximum length: 128 characters (prevents DoS via bcrypt)

### Token Security

- Access tokens are short-lived (1 hour)
- Refresh tokens are hashed before storage
- Tokens are invalidated on logout
- Password reset tokens expire after 1 hour
- All tokens use cryptographically secure random generation

### Account Protection

- Failed login attempts are tracked
- Accounts lock after 5 failed attempts
- Locked accounts auto-unlock after 30 minutes
- Inactive accounts cannot authenticate
- Last login timestamp is tracked

## Future Enhancements

- [ ] Email verification on registration
- [ ] Two-factor authentication (2FA)
- [ ] OAuth2 integration (Google, Microsoft)
- [ ] Session management (list active sessions)
- [ ] Device fingerprinting
- [ ] Password history (prevent reuse)
- [ ] Audit logging for security events
- [ ] Rate limiting per IP/user
- [ ] CAPTCHA on repeated failed logins
- [ ] Email notifications for security events

## Troubleshooting

### Common Issues

**Issue:** "Invalid or expired token"
- **Cause:** Access token has expired
- **Solution:** Use refresh token to obtain new access token

**Issue:** "Account is locked"
- **Cause:** 5 failed login attempts
- **Solution:** Wait 30 minutes or contact admin to unlock

**Issue:** "User with this email already exists"
- **Cause:** Duplicate email during registration
- **Solution:** Use different email or login with existing account

**Issue:** JWT secret not found
- **Cause:** Missing environment variables
- **Solution:** Ensure `.env` file has `JWT_SECRET` and `JWT_REFRESH_SECRET`

## Support

For questions or issues with the authentication system, contact the backend development team or refer to the project documentation.

## License

Copyright 2025 Financial RISE Report. All rights reserved.
