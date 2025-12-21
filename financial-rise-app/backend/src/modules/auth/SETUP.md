# Authentication System Setup Guide

## Prerequisites

- Node.js 18 LTS or higher
- PostgreSQL 14+ running
- npm or yarn package manager

## Installation Steps

### 1. Install Required Dependencies

```bash
cd backend
npm install --save @nestjs/jwt @nestjs/passport passport passport-jwt passport-local bcrypt
npm install --save-dev @types/passport-jwt @types/passport-local @types/bcrypt
```

### 2. Configure Environment Variables

Copy the example environment file and update with your values:

```bash
cp .env.auth.example .env
```

Edit `.env` and set secure values for:
- `JWT_SECRET` - Use a strong random secret (minimum 32 characters)
- `JWT_REFRESH_SECRET` - Use a different strong random secret
- `DATABASE_*` - Your PostgreSQL connection details

**Generate Secure Secrets:**

```bash
# Generate JWT_SECRET
node -e "console.log('JWT_SECRET=' + require('crypto').randomBytes(64).toString('hex'))"

# Generate JWT_REFRESH_SECRET
node -e "console.log('JWT_REFRESH_SECRET=' + require('crypto').randomBytes(64).toString('hex'))"
```

### 3. Update App Module

Update `src/app.module.ts` to include the Auth and Users modules:

```typescript
import { Module } from '@nestjs/module';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthModule } from './modules/auth/auth.module';
import { UsersModule } from './modules/users/users.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
    }),
    TypeOrmModule.forRoot({
      type: 'postgres',
      host: process.env.DATABASE_HOST,
      port: parseInt(process.env.DATABASE_PORT, 10),
      username: process.env.DATABASE_USER,
      password: process.env.DATABASE_PASSWORD,
      database: process.env.DATABASE_NAME,
      entities: [__dirname + '/**/*.entity{.ts,.js}'],
      synchronize: process.env.NODE_ENV === 'development', // Only for development!
      logging: process.env.NODE_ENV === 'development',
    }),
    AuthModule,
    UsersModule,
  ],
})
export class AppModule {}
```

### 4. Create Database Migration

Generate and run the migration to create the users table:

```bash
# Generate migration
npm run migration:generate -- -n CreateUsersTable

# Run migration
npm run migration:run
```

Or manually create the table using this SQL:

```sql
CREATE TYPE user_role AS ENUM ('consultant', 'admin');
CREATE TYPE user_status AS ENUM ('active', 'inactive', 'locked');

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    role user_role DEFAULT 'consultant' NOT NULL,
    status user_status DEFAULT 'active' NOT NULL,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP,
    reset_password_token VARCHAR(255),
    reset_password_expires TIMESTAMP,
    refresh_token VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login_at TIMESTAMP,
    CONSTRAINT email_format CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_status ON users(status);
CREATE INDEX idx_users_reset_token ON users(reset_password_token) WHERE reset_password_token IS NOT NULL;
```

### 5. Update Main Application

Ensure `src/main.ts` has proper configuration:

```typescript
import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Enable validation pipes globally
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  // Enable CORS
  app.enableCors({
    origin: process.env.CORS_ORIGIN || 'http://localhost:3001',
    credentials: true,
  });

  // Set global prefix
  app.setGlobalPrefix('api');

  const port = process.env.PORT || 3000;
  await app.listen(port);
  console.log(`Application is running on: http://localhost:${port}`);
}
bootstrap();
```

### 6. Start the Application

```bash
# Development mode with hot reload
npm run start:dev

# Production mode
npm run build
npm run start:prod
```

## Verification

### Test Authentication Endpoints

1. **Register a new user:**

```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecureP@ss123",
    "first_name": "Test",
    "last_name": "User",
    "role": "consultant"
  }'
```

2. **Login:**

```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecureP@ss123"
  }'
```

3. **Access protected route:**

```bash
# Replace <ACCESS_TOKEN> with the token from login response
curl -X GET http://localhost:3000/api/users/profile \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```

4. **Refresh token:**

```bash
# Replace <REFRESH_TOKEN> with the refresh token from login response
curl -X POST http://localhost:3000/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "<REFRESH_TOKEN>"
  }'
```

## Testing

### Create Test User

Create a test admin user directly in the database:

```sql
INSERT INTO users (
    email,
    password_hash,
    first_name,
    last_name,
    role,
    status
) VALUES (
    'admin@financialrise.com',
    -- Password: Admin@123456 (hashed with bcrypt, 12 rounds)
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYIJpL2nu4S',
    'Admin',
    'User',
    'admin',
    'active'
);
```

### Run Unit Tests

```bash
npm run test
```

### Run E2E Tests

```bash
npm run test:e2e
```

## Common Issues

### Issue: "Cannot find module '@nestjs/jwt'"

**Solution:**
```bash
npm install @nestjs/jwt @nestjs/passport passport passport-jwt
```

### Issue: "Connection refused" to PostgreSQL

**Solution:**
1. Ensure PostgreSQL is running: `sudo service postgresql status`
2. Check database credentials in `.env`
3. Verify database exists: `psql -U postgres -l`

### Issue: "JWT_SECRET is not defined"

**Solution:**
Ensure `.env` file exists in the backend root directory with proper JWT secrets.

### Issue: TypeORM synchronize not creating tables

**Solution:**
Run migrations manually or use the SQL schema provided in step 4.

## Next Steps

1. **Implement Email Service** for password reset functionality
2. **Add Rate Limiting** to prevent brute force attacks
3. **Set up Logging** for security events
4. **Configure Email Templates** for password reset emails
5. **Add API Documentation** using Swagger/OpenAPI
6. **Implement 2FA** for enhanced security
7. **Add Session Management** for active session tracking

## Security Recommendations

### Development

- Use `.env` file (never commit to Git)
- Enable CORS only for trusted origins
- Use `synchronize: true` for easy development

### Production

- Use environment variables or secrets manager (AWS Secrets Manager, Azure Key Vault)
- Set `synchronize: false` and use migrations
- Enable HTTPS/TLS
- Implement rate limiting
- Enable audit logging
- Set up monitoring and alerts
- Use strong JWT secrets (64+ characters)
- Configure proper CORS origins
- Implement IP-based rate limiting
- Enable helmet middleware for security headers
- Set up database connection pooling

## Support

For issues or questions:
1. Check the [README.md](./README.md) for detailed API documentation
2. Review NestJS authentication documentation
3. Contact the backend development team

## Resources

- [NestJS Authentication](https://docs.nestjs.com/security/authentication)
- [Passport.js Documentation](http://www.passportjs.org/)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
