import request from 'supertest';
import { Application } from 'express';
import { createApp } from '../../src/app';
import { AppDataSource } from '../../src/config/database';
import { User, UserRole } from '../../src/database/entities/User';

/**
 * Integration tests for authentication endpoints
 * These tests verify the full request/response cycle
 */
describe('Auth API Integration Tests', () => {
  let app: Application;
  let accessToken: string;
  let refreshToken: string;
  let testUser: User;

  beforeAll(async () => {
    // Initialize database connection
    if (!AppDataSource.isInitialized) {
      await AppDataSource.initialize();
    }

    // Create Express app
    app = createApp();

    // Clean up test data
    await AppDataSource.getRepository(User).delete({});
  });

  afterAll(async () => {
    // Clean up and close database connection
    if (AppDataSource.isInitialized) {
      await AppDataSource.getRepository(User).delete({});
      await AppDataSource.destroy();
    }
  });

  describe('POST /api/v1/auth/register', () => {
    it('should register a new user successfully', async () => {
      const response = await request(app)
        .post('/api/v1/auth/register')
        .send({
          email: 'testuser@example.com',
          password: 'SecurePass123!'
        })
        .expect(201);

      expect(response.body).toHaveProperty('message', 'Account created successfully');
      expect(response.body).toHaveProperty('userId');
      expect(response.body.userId).toBeTruthy();
    });

    it('should return 409 if email already exists', async () => {
      const response = await request(app)
        .post('/api/v1/auth/register')
        .send({
          email: 'testuser@example.com',
          password: 'AnotherPass456!'
        })
        .expect(409);

      expect(response.body).toHaveProperty('error', 'Conflict');
      expect(response.body.message).toContain('already registered');
    });

    it('should return 422 for weak password', async () => {
      const response = await request(app)
        .post('/api/v1/auth/register')
        .send({
          email: 'newuser@example.com',
          password: 'weak'
        })
        .expect(422);

      expect(response.body).toHaveProperty('error', 'Validation Error');
      expect(response.body.message).toContain('Password must');
    });

    it('should return 400 for invalid email format', async () => {
      const response = await request(app)
        .post('/api/v1/auth/register')
        .send({
          email: 'invalid-email',
          password: 'SecurePass123!'
        })
        .expect(400);

      expect(response.body).toHaveProperty('error');
    });
  });

  describe('POST /api/v1/auth/login', () => {
    it('should login successfully with valid credentials', async () => {
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'testuser@example.com',
          password: 'SecurePass123!'
        })
        .expect(200);

      expect(response.body).toHaveProperty('accessToken');
      expect(response.body).toHaveProperty('refreshToken');
      expect(response.body).toHaveProperty('expiresIn', 900);
      expect(response.body).toHaveProperty('user');
      expect(response.body.user).toHaveProperty('email', 'testuser@example.com');
      expect(response.body.user).toHaveProperty('role', UserRole.CONSULTANT);

      // Save tokens for subsequent tests
      accessToken = response.body.accessToken;
      refreshToken = response.body.refreshToken;
    });

    it('should return 401 for invalid credentials', async () => {
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'testuser@example.com',
          password: 'WrongPassword123!'
        })
        .expect(401);

      expect(response.body).toHaveProperty('error', 'Unauthorized');
      expect(response.body.message).toContain('Invalid credentials');
    });

    it('should return 401 for non-existent user', async () => {
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'nonexistent@example.com',
          password: 'SecurePass123!'
        })
        .expect(401);

      expect(response.body).toHaveProperty('error', 'Unauthorized');
      expect(response.body.message).toContain('Invalid credentials');
    });

    it('should return 403 after 5 failed login attempts', async () => {
      const testEmail = 'locktest@example.com';

      // Register user first
      await request(app)
        .post('/api/v1/auth/register')
        .send({
          email: testEmail,
          password: 'SecurePass123!'
        });

      // Make 5 failed login attempts
      for (let i = 0; i < 5; i++) {
        await request(app)
          .post('/api/v1/auth/login')
          .send({
            email: testEmail,
            password: 'WrongPassword!'
          })
          .expect(401);
      }

      // 6th attempt should be locked
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: testEmail,
          password: 'SecurePass123!'
        })
        .expect(403);

      expect(response.body.message).toContain('locked');
    });
  });

  describe('POST /api/v1/auth/refresh', () => {
    it('should refresh access token successfully', async () => {
      const response = await request(app)
        .post('/api/v1/auth/refresh')
        .send({
          refreshToken
        })
        .expect(200);

      expect(response.body).toHaveProperty('accessToken');
      expect(response.body).toHaveProperty('refreshToken');
      expect(response.body).toHaveProperty('expiresIn', 900);

      // Update tokens
      accessToken = response.body.accessToken;
      refreshToken = response.body.refreshToken;
    });

    it('should return 401 for invalid refresh token', async () => {
      const response = await request(app)
        .post('/api/v1/auth/refresh')
        .send({
          refreshToken: 'invalid-token'
        })
        .expect(401);

      expect(response.body).toHaveProperty('error', 'Unauthorized');
    });

    it('should return 401 for missing refresh token', async () => {
      const response = await request(app)
        .post('/api/v1/auth/refresh')
        .send({})
        .expect(401);

      expect(response.body).toHaveProperty('error', 'Unauthorized');
    });
  });

  describe('POST /api/v1/auth/logout', () => {
    it('should logout successfully', async () => {
      const response = await request(app)
        .post('/api/v1/auth/logout')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          refreshToken
        })
        .expect(200);

      expect(response.body).toHaveProperty('message', 'Logged out successfully');
    });

    it('should return 401 without authentication', async () => {
      const response = await request(app)
        .post('/api/v1/auth/logout')
        .send({
          refreshToken: 'some-token'
        })
        .expect(401);

      expect(response.body).toHaveProperty('error', 'Unauthorized');
    });
  });

  describe('POST /api/v1/auth/forgot-password', () => {
    it('should initiate password reset for existing user', async () => {
      const response = await request(app)
        .post('/api/v1/auth/forgot-password')
        .send({
          email: 'testuser@example.com'
        })
        .expect(200);

      expect(response.body).toHaveProperty('message');
      expect(response.body.message).toContain('password reset link');

      // In development mode, token should be returned
      if (process.env.NODE_ENV === 'development') {
        expect(response.body).toHaveProperty('token');
      }
    });

    it('should return success even for non-existent email (prevent enumeration)', async () => {
      const response = await request(app)
        .post('/api/v1/auth/forgot-password')
        .send({
          email: 'nonexistent@example.com'
        })
        .expect(200);

      expect(response.body).toHaveProperty('message');
      expect(response.body.message).toContain('password reset link');
    });
  });

  describe('POST /api/v1/auth/reset-password', () => {
    let resetToken: string;

    beforeAll(async () => {
      // Get a reset token first
      const response = await request(app)
        .post('/api/v1/auth/forgot-password')
        .send({
          email: 'testuser@example.com'
        });

      resetToken = response.body.token;
    });

    it('should reset password successfully with valid token', async () => {
      const response = await request(app)
        .post('/api/v1/auth/reset-password')
        .send({
          token: resetToken,
          newPassword: 'NewSecurePass456!'
        })
        .expect(200);

      expect(response.body).toHaveProperty('message', 'Password reset successfully');

      // Verify can login with new password
      const loginResponse = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'testuser@example.com',
          password: 'NewSecurePass456!'
        })
        .expect(200);

      expect(loginResponse.body).toHaveProperty('accessToken');
    });

    it('should return 400 for invalid reset token', async () => {
      const response = await request(app)
        .post('/api/v1/auth/reset-password')
        .send({
          token: 'invalid-token',
          newPassword: 'NewSecurePass456!'
        })
        .expect(400);

      expect(response.body).toHaveProperty('error', 'Bad Request');
    });

    it('should return 422 for weak new password', async () => {
      // Get a fresh reset token
      const forgotResponse = await request(app)
        .post('/api/v1/auth/forgot-password')
        .send({
          email: 'testuser@example.com'
        });

      const freshToken = forgotResponse.body.token;

      const response = await request(app)
        .post('/api/v1/auth/reset-password')
        .send({
          token: freshToken,
          newPassword: 'weak'
        })
        .expect(422);

      expect(response.body).toHaveProperty('error', 'Validation Error');
      expect(response.body.message).toContain('Password must');
    });
  });

  describe('GET /health', () => {
    it('should return health check status', async () => {
      const response = await request(app)
        .get('/health')
        .expect(200);

      expect(response.body).toHaveProperty('status', 'healthy');
      expect(response.body).toHaveProperty('timestamp');
      expect(response.body).toHaveProperty('service', 'financial-rise-backend');
    });
  });
});
