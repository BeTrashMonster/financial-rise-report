import request from 'supertest';
import { Application } from 'express';
import { createApp } from '../../src/app';
import { AppDataSource } from '../../src/config/database';
import { User, UserRole } from '../../src/database/entities/User';

/**
 * Integration tests for admin endpoints
 * These tests verify the full request/response cycle for admin operations
 */
describe('Admin API Integration Tests', () => {
  let app: Application;
  let adminToken: string;
  let consultantToken: string;
  let testConsultantId: string;

  beforeAll(async () => {
    // Initialize database connection
    if (!AppDataSource.isInitialized) {
      await AppDataSource.initialize();
    }

    // Create Express app
    app = createApp();

    // Clean up test data
    await AppDataSource.getRepository(User).delete({});

    // Create admin user
    const adminResponse = await request(app)
      .post('/api/v1/auth/register')
      .send({
        email: 'admin@example.com',
        password: 'AdminPass123!',
        role: UserRole.ADMIN
      });

    // Login as admin
    const adminLoginResponse = await request(app)
      .post('/api/v1/auth/login')
      .send({
        email: 'admin@example.com',
        password: 'AdminPass123!'
      });

    adminToken = adminLoginResponse.body.accessToken;

    // Create consultant user
    const consultantResponse = await request(app)
      .post('/api/v1/auth/register')
      .send({
        email: 'consultant@example.com',
        password: 'ConsultantPass123!',
        role: UserRole.CONSULTANT
      });

    testConsultantId = consultantResponse.body.userId;

    // Login as consultant
    const consultantLoginResponse = await request(app)
      .post('/api/v1/auth/login')
      .send({
        email: 'consultant@example.com',
        password: 'ConsultantPass123!'
      });

    consultantToken = consultantLoginResponse.body.accessToken;
  });

  afterAll(async () => {
    // Clean up and close database connection
    if (AppDataSource.isInitialized) {
      await AppDataSource.getRepository(User).delete({});
      await AppDataSource.destroy();
    }
  });

  describe('GET /api/v1/admin/users', () => {
    it('should list all users as admin', async () => {
      const response = await request(app)
        .get('/api/v1/admin/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(response.body).toHaveProperty('users');
      expect(response.body).toHaveProperty('pagination');
      expect(Array.isArray(response.body.users)).toBe(true);
      expect(response.body.users.length).toBeGreaterThan(0);
      expect(response.body.pagination).toHaveProperty('total');
      expect(response.body.pagination).toHaveProperty('page');
      expect(response.body.pagination).toHaveProperty('limit');
    });

    it('should filter users by role', async () => {
      const response = await request(app)
        .get('/api/v1/admin/users?role=consultant')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(response.body.users).toBeDefined();
      response.body.users.forEach((user: User) => {
        expect(user.role).toBe(UserRole.CONSULTANT);
      });
    });

    it('should paginate users correctly', async () => {
      const response = await request(app)
        .get('/api/v1/admin/users?page=1&limit=1')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(response.body.pagination.page).toBe(1);
      expect(response.body.pagination.limit).toBe(1);
      expect(response.body.users.length).toBeLessThanOrEqual(1);
    });

    it('should return 401 without authentication', async () => {
      const response = await request(app)
        .get('/api/v1/admin/users')
        .expect(401);

      expect(response.body).toHaveProperty('error', 'Unauthorized');
    });

    it('should return 403 for consultant user', async () => {
      const response = await request(app)
        .get('/api/v1/admin/users')
        .set('Authorization', `Bearer ${consultantToken}`)
        .expect(403);

      expect(response.body).toHaveProperty('error', 'Forbidden');
      expect(response.body.message).toContain('Insufficient permissions');
    });
  });

  describe('POST /api/v1/admin/users', () => {
    it('should create a new user as admin', async () => {
      const response = await request(app)
        .post('/api/v1/admin/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          email: 'newconsultant@example.com',
          password: 'NewConsultantPass123!',
          role: UserRole.CONSULTANT
        })
        .expect(201);

      expect(response.body).toHaveProperty('message', 'User created successfully');
      expect(response.body).toHaveProperty('user');
      expect(response.body.user).toHaveProperty('email', 'newconsultant@example.com');
      expect(response.body.user).toHaveProperty('role', UserRole.CONSULTANT);
    });

    it('should return 409 for duplicate email', async () => {
      const response = await request(app)
        .post('/api/v1/admin/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          email: 'admin@example.com',
          password: 'AnotherPass123!',
          role: UserRole.CONSULTANT
        })
        .expect(409);

      expect(response.body).toHaveProperty('error', 'Conflict');
      expect(response.body.message).toContain('already registered');
    });

    it('should return 422 for weak password', async () => {
      const response = await request(app)
        .post('/api/v1/admin/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          email: 'weakpass@example.com',
          password: 'weak',
          role: UserRole.CONSULTANT
        })
        .expect(422);

      expect(response.body).toHaveProperty('error', 'Validation Error');
      expect(response.body.message).toContain('Password must');
    });

    it('should return 403 for consultant user', async () => {
      const response = await request(app)
        .post('/api/v1/admin/users')
        .set('Authorization', `Bearer ${consultantToken}`)
        .send({
          email: 'another@example.com',
          password: 'SecurePass123!',
          role: UserRole.CONSULTANT
        })
        .expect(403);

      expect(response.body).toHaveProperty('error', 'Forbidden');
    });
  });

  describe('PATCH /api/v1/admin/users/:id', () => {
    it('should update user successfully as admin', async () => {
      const response = await request(app)
        .patch(`/api/v1/admin/users/${testConsultantId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          email: 'updatedconsultant@example.com'
        })
        .expect(200);

      expect(response.body).toHaveProperty('message', 'User updated successfully');
      expect(response.body.user).toHaveProperty('email', 'updatedconsultant@example.com');
    });

    it('should return 404 for non-existent user', async () => {
      const response = await request(app)
        .patch('/api/v1/admin/users/00000000-0000-0000-0000-000000000000')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          email: 'newemail@example.com'
        })
        .expect(404);

      expect(response.body).toHaveProperty('error', 'Not Found');
    });

    it('should return 403 for consultant user', async () => {
      const response = await request(app)
        .patch(`/api/v1/admin/users/${testConsultantId}`)
        .set('Authorization', `Bearer ${consultantToken}`)
        .send({
          email: 'newemail@example.com'
        })
        .expect(403);

      expect(response.body).toHaveProperty('error', 'Forbidden');
    });
  });

  describe('DELETE /api/v1/admin/users/:id', () => {
    let userToDeleteId: string;

    beforeAll(async () => {
      // Create a user to delete
      const response = await request(app)
        .post('/api/v1/admin/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          email: 'deleteme@example.com',
          password: 'DeleteMe123!',
          role: UserRole.CONSULTANT
        });

      userToDeleteId = response.body.user.id;
    });

    it('should delete user successfully as admin', async () => {
      const response = await request(app)
        .delete(`/api/v1/admin/users/${userToDeleteId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(response.body).toHaveProperty('message', 'User deleted successfully');

      // Verify user is deleted
      const listResponse = await request(app)
        .get('/api/v1/admin/users')
        .set('Authorization', `Bearer ${adminToken}`);

      const deletedUser = listResponse.body.users.find((u: User) => u.id === userToDeleteId);
      expect(deletedUser).toBeUndefined();
    });

    it('should return 404 for non-existent user', async () => {
      const response = await request(app)
        .delete('/api/v1/admin/users/00000000-0000-0000-0000-000000000000')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(404);

      expect(response.body).toHaveProperty('error', 'Not Found');
    });

    it('should return 403 for consultant user', async () => {
      const response = await request(app)
        .delete(`/api/v1/admin/users/${testConsultantId}`)
        .set('Authorization', `Bearer ${consultantToken}`)
        .expect(403);

      expect(response.body).toHaveProperty('error', 'Forbidden');
    });
  });

  describe('POST /api/v1/admin/users/:id/reset-password', () => {
    it('should reset user password successfully as admin', async () => {
      const response = await request(app)
        .post(`/api/v1/admin/users/${testConsultantId}/reset-password`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          newPassword: 'NewResetPass456!'
        })
        .expect(200);

      expect(response.body).toHaveProperty('message', 'Password reset successfully');

      // Verify can login with new password
      const loginResponse = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'updatedconsultant@example.com',
          password: 'NewResetPass456!'
        })
        .expect(200);

      expect(loginResponse.body).toHaveProperty('accessToken');
    });

    it('should return 422 for weak password', async () => {
      const response = await request(app)
        .post(`/api/v1/admin/users/${testConsultantId}/reset-password`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          newPassword: 'weak'
        })
        .expect(422);

      expect(response.body).toHaveProperty('error', 'Validation Error');
      expect(response.body.message).toContain('Password must');
    });

    it('should return 404 for non-existent user', async () => {
      const response = await request(app)
        .post('/api/v1/admin/users/00000000-0000-0000-0000-000000000000/reset-password')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          newPassword: 'NewSecurePass456!'
        })
        .expect(404);

      expect(response.body).toHaveProperty('error', 'Not Found');
    });

    it('should return 403 for consultant user', async () => {
      const response = await request(app)
        .post(`/api/v1/admin/users/${testConsultantId}/reset-password`)
        .set('Authorization', `Bearer ${consultantToken}`)
        .send({
          newPassword: 'NewSecurePass456!'
        })
        .expect(403);

      expect(response.body).toHaveProperty('error', 'Forbidden');
    });
  });

  describe('GET /api/v1/admin/activity-logs', () => {
    it('should retrieve activity logs as admin', async () => {
      const response = await request(app)
        .get('/api/v1/admin/activity-logs')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(response.body).toHaveProperty('logs');
      expect(response.body).toHaveProperty('pagination');
      expect(Array.isArray(response.body.logs)).toBe(true);
      expect(response.body.logs.length).toBeGreaterThan(0);
    });

    it('should filter logs by action', async () => {
      const response = await request(app)
        .get('/api/v1/admin/activity-logs?action=login')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(response.body.logs).toBeDefined();
      // Logs with 'login' in action should be returned
    });

    it('should paginate logs correctly', async () => {
      const response = await request(app)
        .get('/api/v1/admin/activity-logs?page=1&limit=5')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(response.body.pagination.page).toBe(1);
      expect(response.body.pagination.limit).toBe(5);
      expect(response.body.logs.length).toBeLessThanOrEqual(5);
    });

    it('should return 401 without authentication', async () => {
      const response = await request(app)
        .get('/api/v1/admin/activity-logs')
        .expect(401);

      expect(response.body).toHaveProperty('error', 'Unauthorized');
    });

    it('should return 403 for consultant user', async () => {
      const response = await request(app)
        .get('/api/v1/admin/activity-logs')
        .set('Authorization', `Bearer ${consultantToken}`)
        .expect(403);

      expect(response.body).toHaveProperty('error', 'Forbidden');
    });
  });
});
