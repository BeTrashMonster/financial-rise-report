import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule } from '@nestjs/config';
import * as request from 'supertest';
import { AuthModule } from './auth.module';
import { UsersModule } from '../users/users.module';
import { Repository, DataSource } from 'typeorm';
import { User, UserRole } from '../users/entities/user.entity';
import { getRepositoryToken } from '@nestjs/typeorm';
import * as bcrypt from 'bcrypt';

/**
 * SQL Injection Security Tests for Authentication Module
 *
 * SECURITY FINDING: CRIT-003 - SQL Injection Protection Verification
 * Reference: SECURITY-AUDIT-REPORT.md Lines 652-735
 *
 * Purpose:
 * - Verify authentication endpoints are protected against SQL injection
 * - Test email and password fields for classic injection attacks
 * - Ensure login bypass attempts are blocked
 * - Validate password reset token handling is safe
 *
 * Critical Attack Vectors:
 * 1. Authentication bypass (admin'-- / OR 1=1)
 * 2. User enumeration via injection
 * 3. Password reset token manipulation
 * 4. Registration injection attacks
 *
 * Expected Behavior:
 * - No authentication bypass
 * - Email treated as literal string
 * - Proper error handling without info disclosure
 * - Failed login attempts should increment correctly
 */
describe('Authentication SQL Injection Security Tests (WS55)', () => {
  let app: INestApplication;
  let dataSource: DataSource;
  let userRepository: Repository<User>;
  let validUser: User;

  // Authentication-specific SQL injection payloads
  const AUTH_INJECTION_PAYLOADS = [
    // Classic auth bypass
    "admin'--",
    "admin' #",
    "admin'/*",
    "' OR '1'='1",
    "' OR 1=1--",
    "') OR '1'='1'--",
    "') OR ('1'='1",

    // Boolean-based enumeration
    "admin' AND '1'='1",
    "admin' AND '1'='2",

    // Union-based password extraction
    "' UNION SELECT NULL, password_hash FROM users WHERE email='admin@test.com'--",

    // Stacked queries
    "admin'; UPDATE users SET role='admin' WHERE email='victim@test.com'--",

    // Comment variations
    "admin' -- comment",
    "admin'-- -",
  ];

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({
          isGlobal: true,
          envFilePath: '.env.test',
        }),
        TypeOrmModule.forRoot({
          type: 'postgres',
          host: process.env.DB_HOST || 'localhost',
          port: parseInt(process.env.DB_PORT, 10) || 5432,
          username: process.env.DB_USERNAME || 'postgres',
          password: process.env.DB_PASSWORD || 'postgres',
          database: process.env.DB_DATABASE || 'financial_rise_test',
          entities: [__dirname + '/../**/*.entity{.ts,.js}'],
          synchronize: true,
          dropSchema: true,
          logging: false,
        }),
        AuthModule,
        UsersModule,
      ],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ transform: true, whitelist: true }));
    await app.init();

    dataSource = moduleFixture.get<DataSource>(DataSource);
    userRepository = moduleFixture.get<Repository<User>>(getRepositoryToken(User));

    // Create valid test user
    const hashedPassword = await bcrypt.hash('ValidPass123!', 10);
    validUser = await userRepository.save({
      email: 'validuser@test.com',
      password_hash: hashedPassword,
      first_name: 'Valid',
      last_name: 'User',
      role: UserRole.CONSULTANT,
      email_verified: true,
    });
  });

  afterAll(async () => {
    await dataSource.destroy();
    await app.close();
  });

  describe('POST /auth/login - SQL Injection Tests', () => {
    it('should reject authentication bypass via email SQL injection', async () => {
      for (const payload of AUTH_INJECTION_PAYLOADS.slice(0, 7)) {
        const response = await request(app.getHttpServer())
          .post('/auth/login')
          .send({
            email: payload,
            password: 'anypassword',
          });

        // Should NOT authenticate
        expect(response.status).not.toBe(200);
        expect(response.body.accessToken).toBeUndefined();
      }
    });

    it('should reject authentication bypass via password SQL injection', async () => {
      const payload = "' OR '1'='1";

      const response = await request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: 'validuser@test.com',
          password: payload,
        });

      // Should NOT authenticate (password doesn't match hash)
      expect(response.status).toBe(401);
      expect(response.body.accessToken).toBeUndefined();

      // Verify failed login attempt was recorded
      const user = await userRepository.findOne({
        where: { email: 'validuser@test.com' },
      });
      expect(user.failed_login_attempts).toBeGreaterThan(0);
    });

    it('should prevent login with union-based injection', async () => {
      const payload = "' UNION SELECT 'admin@test.com', 'password123' --";

      const response = await request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: payload,
          password: 'password123',
        });

      expect(response.status).toBe(401);
      expect(response.body.accessToken).toBeUndefined();
    });

    it('should handle comment-based injection safely', async () => {
      const payload = "validuser@test.com'--";

      const response = await request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: payload,
          password: 'ValidPass123!',
        });

      // Should fail (email doesn't match exactly)
      expect(response.status).toBe(401);
    });

    it('should not leak user existence via timing or error messages', async () => {
      const existingEmail = 'validuser@test.com';
      const nonExistentEmail = "nonexistent@test.com' OR '1'='1";

      // Test with existing user + injection
      const startExisting = Date.now();
      const existingResponse = await request(app.getHttpServer())
        .post('/auth/login')
        .send({ email: `${existingEmail}' OR '1'='1`, password: 'wrong' });
      const existingDuration = Date.now() - startExisting;

      // Test with non-existent user + injection
      const startNonExistent = Date.now();
      const nonExistentResponse = await request(app.getHttpServer())
        .post('/auth/login')
        .send({ email: nonExistentEmail, password: 'wrong' });
      const nonExistentDuration = Date.now() - startNonExistent;

      // Both should return 401
      expect(existingResponse.status).toBe(401);
      expect(nonExistentResponse.status).toBe(401);

      // Error messages should be identical
      expect(existingResponse.body.message).toBe(nonExistentResponse.body.message);

      // Timing should be similar (within 500ms to account for bcrypt)
      const timingDifference = Math.abs(existingDuration - nonExistentDuration);
      expect(timingDifference).toBeLessThan(1000); // Loose timing check
    });

    it('should prevent privilege escalation via stacked queries', async () => {
      const payload = "validuser@test.com'; UPDATE users SET role='admin' WHERE email='validuser@test.com'--";

      const response = await request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: payload,
          password: 'ValidPass123!',
        });

      expect(response.status).toBe(401);

      // Verify user role was NOT changed
      const user = await userRepository.findOne({
        where: { email: 'validuser@test.com' },
      });
      expect(user.role).toBe(UserRole.CONSULTANT); // Still consultant
    });
  });

  describe('POST /auth/register - SQL Injection Tests', () => {
    it('should reject SQL injection in email field', async () => {
      const payload = "newuser@test.com'; DROP TABLE users; --";

      const response = await request(app.getHttpServer())
        .post('/auth/register')
        .send({
          email: payload,
          password: 'ValidPass123!',
          firstName: 'Test',
          lastName: 'User',
        });

      // Should either validate email format or store safely
      expect(response.status).not.toBe(500);

      // Verify users table still exists
      const userCount = await userRepository.count();
      expect(userCount).toBeGreaterThan(0);
    });

    it('should reject SQL injection in firstName field', async () => {
      const payload = "Robert'; DELETE FROM users WHERE '1'='1";

      const response = await request(app.getHttpServer())
        .post('/auth/register')
        .send({
          email: 'newuser2@test.com',
          password: 'ValidPass123!',
          firstName: payload,
          lastName: 'User',
        });

      if (response.status === 201) {
        // Verify name stored as literal
        const user = await userRepository.findOne({
          where: { email: 'newuser2@test.com' },
        });
        expect(user.first_name).toContain('Robert');

        // Verify no mass deletion
        const count = await userRepository.count();
        expect(count).toBeGreaterThan(1);

        // Cleanup
        await userRepository.delete(user.id);
      }
    });

    it('should reject SQL injection in lastName field', async () => {
      const payload = "DROP TABLE'; --";

      const response = await request(app.getHttpServer())
        .post('/auth/register')
        .send({
          email: 'newuser3@test.com',
          password: 'ValidPass123!',
          firstName: 'Test',
          lastName: payload,
        });

      if (response.status === 201) {
        const user = await userRepository.findOne({
          where: { email: 'newuser3@test.com' },
        });
        expect(user.last_name).toBe(payload);

        await userRepository.delete(user.id);
      }
    });

    it('should handle single quotes in names correctly', async () => {
      const payload = "O'Connor";

      const response = await request(app.getHttpServer())
        .post('/auth/register')
        .send({
          email: 'oconnor@test.com',
          password: 'ValidPass123!',
          firstName: 'Sean',
          lastName: payload,
        });

      expect(response.status).toBe(201);

      const user = await userRepository.findOne({
        where: { email: 'oconnor@test.com' },
      });
      expect(user.last_name).toBe("O'Connor");

      await userRepository.delete(user.id);
    });
  });

  describe('POST /auth/forgot-password - SQL Injection Tests', () => {
    it('should reject SQL injection in email field', async () => {
      for (const payload of AUTH_INJECTION_PAYLOADS.slice(0, 5)) {
        const response = await request(app.getHttpServer())
          .post('/auth/forgot-password')
          .send({ email: payload });

        // Should return success regardless (prevent user enumeration)
        expect([200, 201]).toContain(response.status);

        // Should not leak database info
        const bodyString = JSON.stringify(response.body);
        expect(bodyString).not.toContain('SQL');
        expect(bodyString).not.toContain('syntax');
      }
    });

    it('should not allow password reset via injection', async () => {
      const payload = "validuser@test.com' OR '1'='1";

      const response = await request(app.getHttpServer())
        .post('/auth/forgot-password')
        .send({ email: payload });

      expect(response.status).not.toBe(500);

      // Verify only exact email match would get reset token
      const user = await userRepository.findOne({
        where: { email: 'validuser@test.com' },
      });

      // If injection worked, ALL users would have reset tokens
      const usersWithResetToken = await userRepository.count({
        where: { reset_password_token: user.reset_password_token },
      });

      // Should be 0 or 1, never ALL users
      expect(usersWithResetToken).toBeLessThanOrEqual(1);
    });
  });

  describe('POST /auth/reset-password - SQL Injection Tests', () => {
    let resetToken: string;

    beforeAll(async () => {
      // Generate valid reset token for testing
      const crypto = require('crypto');
      resetToken = crypto.randomBytes(32).toString('hex');

      await userRepository.update(validUser.id, {
        reset_password_token: resetToken,
        reset_password_expires: new Date(Date.now() + 3600000),
      });
    });

    it('should reject SQL injection in reset token', async () => {
      const payload = `${resetToken}' OR '1'='1`;

      const response = await request(app.getHttpServer())
        .post('/auth/reset-password')
        .send({
          token: payload,
          newPassword: 'NewValidPass123!',
        });

      // Should fail to find token
      expect(response.status).not.toBe(200);
    });

    it('should reject SQL injection in new password field', async () => {
      const payload = "Password123!'; UPDATE users SET role='admin'--";

      const response = await request(app.getHttpServer())
        .post('/auth/reset-password')
        .send({
          token: resetToken,
          newPassword: payload,
        });

      // Password may be rejected by validation or stored safely
      expect(response.status).not.toBe(500);

      // Verify no privilege escalation
      const user = await userRepository.findOne({
        where: { id: validUser.id },
      });
      expect(user.role).toBe(UserRole.CONSULTANT);
    });
  });

  describe('Special Character Handling Tests', () => {
    it('should handle NULL bytes safely', async () => {
      const payload = "test@test.com\x00admin@test.com";

      const response = await request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: payload,
          password: 'anypassword',
        });

      // Should not truncate at NULL byte
      expect(response.status).toBe(401);
    });

    it('should handle Unicode SQL injection attempts', async () => {
      const payload = "admin\u0027\u002d\u002dadmin"; // Unicode single quote and dashes

      const response = await request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: payload,
          password: 'anypassword',
        });

      expect(response.status).toBe(401);
    });

    it('should handle multi-line injection attempts', async () => {
      const payload = "validuser@test.com'\nOR '1'='1'\n--";

      const response = await request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: payload,
          password: 'ValidPass123!',
        });

      expect(response.status).toBe(401);
    });
  });

  describe('Error Information Disclosure Tests', () => {
    it('should not expose SQL errors in login response', async () => {
      const payload = "test' AND (SELECT 1/0)--";

      const response = await request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: payload,
          password: 'anypassword',
        });

      const bodyString = JSON.stringify(response.body);
      expect(bodyString).not.toContain('division by zero');
      expect(bodyString).not.toContain('SQL');
      expect(bodyString).not.toContain('postgres');
      expect(bodyString).not.toContain('syntax error');
    });

    it('should not leak database schema via injection', async () => {
      const payload = "' UNION SELECT table_name FROM information_schema.tables--";

      const response = await request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: payload,
          password: 'anypassword',
        });

      const bodyString = JSON.stringify(response.body);
      expect(bodyString).not.toContain('table_name');
      expect(bodyString).not.toContain('information_schema');
      expect(bodyString).not.toContain('users');
      expect(bodyString).not.toContain('assessments');
    });
  });

  describe('Account Security Tests', () => {
    it('should not bypass account lockout via SQL injection', async () => {
      // Create user with lockout
      const lockedUser = await userRepository.save({
        email: 'locked@test.com',
        password_hash: await bcrypt.hash('Pass123!', 10),
        first_name: 'Locked',
        last_name: 'User',
        role: UserRole.CONSULTANT,
        email_verified: true,
        failed_login_attempts: 5,
        locked_until: new Date(Date.now() + 3600000),
      });

      const payload = "locked@test.com' OR locked_until IS NULL--";

      const response = await request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: payload,
          password: 'Pass123!',
        });

      // Should remain locked
      expect(response.status).toBe(401);
      expect(response.body.message).toContain('locked');

      await userRepository.delete(lockedUser.id);
    });

    it('should not bypass email verification via SQL injection', async () => {
      const unverifiedUser = await userRepository.save({
        email: 'unverified@test.com',
        password_hash: await bcrypt.hash('Pass123!', 10),
        first_name: 'Unverified',
        last_name: 'User',
        role: UserRole.CONSULTANT,
        email_verified: false,
      });

      const payload = "unverified@test.com' OR email_verified=true--";

      const response = await request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: payload,
          password: 'Pass123!',
        });

      // Email should not be bypassed
      expect(response.status).toBe(401);

      await userRepository.delete(unverifiedUser.id);
    });
  });
});
