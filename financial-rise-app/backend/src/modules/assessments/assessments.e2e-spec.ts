import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AssessmentsModule } from './assessments.module';
import { AuthModule } from '../auth/auth.module';
import { UsersModule } from '../users/users.module';
import { Assessment, AssessmentStatus } from './entities/assessment.entity';
import { AssessmentResponse as AssessmentResponseEntity } from './entities/assessment-response.entity';
import { User } from '../users/entities/user.entity';
import { RefreshToken } from '../auth/entities/refresh-token.entity';
import { Question } from '../questions/entities/question.entity';
import { DISCProfile } from '../algorithms/entities/disc-profile.entity';
import { PhaseResult } from '../algorithms/entities/phase-result.entity';

describe('Assessments E2E Tests', () => {
  let app: INestApplication;
  let authToken: string;
  let userId: string;
  let assessmentId: string;
  const testEmail = `assessments-${Date.now()}@example.com`;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [
        TypeOrmModule.forRoot({
          type: 'sqlite',
          database: ':memory:',
          entities: [
            User,
            RefreshToken,
            Assessment,
            AssessmentResponseEntity,
            Question,
            DISCProfile,
            PhaseResult,
          ],
          synchronize: true,
          dropSchema: true,
          logging: false,
        }),
        AuthModule,
        UsersModule,
        AssessmentsModule,
      ],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ transform: true, whitelist: true }));
    await app.init();

    // Register and login to get auth token
    const registerResponse = await request(app.getHttpServer())
      .post('/auth/register')
      .send({
        email: testEmail,
        password: 'TestPass123!',
        first_name: 'Test',
        last_name: 'User',
      });

    authToken = registerResponse.body.tokens.accessToken;
    userId = registerResponse.body.user.id;
  });

  afterAll(async () => {
    await app.close();
  });

  describe('POST /assessments', () => {
    it('should create a new assessment', async () => {
      const response = await request(app.getHttpServer())
        .post('/assessments')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          client_name: 'John Smith',
          business_name: 'Acme Corp',
          client_email: 'john@acmecorp.com',
          notes: 'Initial consultation scheduled',
        })
        .expect(201);

      expect(response.body).toHaveProperty('id');
      expect(response.body.client_name).toBe('John Smith');
      expect(response.body.business_name).toBe('Acme Corp');
      expect(response.body.client_email).toBe('john@acmecorp.com');
      expect(response.body.status).toBe('draft');
      expect(response.body.progress).toBe(0);
      expect(response.body.consultant_id).toBe(userId);

      // Save for later tests
      assessmentId = response.body.id;
    });

    it('should reject assessment without authentication', async () => {
      await request(app.getHttpServer())
        .post('/assessments')
        .send({
          client_name: 'Test Client',
          business_name: 'Test Business',
          client_email: 'test@example.com',
        })
        .expect(401);
    });

    it('should reject assessment with missing required fields', async () => {
      const response = await request(app.getHttpServer())
        .post('/assessments')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          client_name: 'Test Client',
          // Missing business_name and client_email
        })
        .expect(400);

      expect(response.body.message).toBeDefined();
    });

    it('should reject assessment with invalid email', async () => {
      const response = await request(app.getHttpServer())
        .post('/assessments')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          client_name: 'Test Client',
          business_name: 'Test Business',
          client_email: 'not-an-email',
        })
        .expect(400);

      expect(response.body.message).toContain('email');
    });
  });

  describe('GET /assessments', () => {
    beforeAll(async () => {
      // Create additional assessments for list testing
      const statuses = ['draft', 'in_progress', 'completed'];
      for (let i = 0; i < 5; i++) {
        await request(app.getHttpServer())
          .post('/assessments')
          .set('Authorization', `Bearer ${authToken}`)
          .send({
            client_name: `Client ${i}`,
            business_name: `Business ${i}`,
            client_email: `client${i}@example.com`,
            status: statuses[i % 3],
          });
      }
    });

    it('should list all assessments for authenticated user', async () => {
      const response = await request(app.getHttpServer())
        .get('/assessments')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body).toHaveProperty('data');
      expect(response.body).toHaveProperty('meta');
      expect(Array.isArray(response.body.data)).toBe(true);
      expect(response.body.data.length).toBeGreaterThan(0);
      expect(response.body.meta).toHaveProperty('total');
      expect(response.body.meta).toHaveProperty('page');
      expect(response.body.meta).toHaveProperty('limit');
    });

    it('should support pagination', async () => {
      const response = await request(app.getHttpServer())
        .get('/assessments?page=1&limit=2')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.data.length).toBeLessThanOrEqual(2);
      expect(response.body.meta.page).toBe(1);
      expect(response.body.meta.limit).toBe(2);
    });

    it('should filter by status', async () => {
      const response = await request(app.getHttpServer())
        .get('/assessments?status=draft')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.data.every((a: any) => a.status === 'draft')).toBe(true);
    });

    it('should support search by client name', async () => {
      const response = await request(app.getHttpServer())
        .get('/assessments?search=John')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(
        response.body.data.some((a: any) => a.client_name.includes('John'))
      ).toBe(true);
    });

    it('should support search by business name', async () => {
      const response = await request(app.getHttpServer())
        .get('/assessments?search=Acme')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(
        response.body.data.some((a: any) => a.business_name.includes('Acme'))
      ).toBe(true);
    });

    it('should support sorting', async () => {
      const ascResponse = await request(app.getHttpServer())
        .get('/assessments?sortBy=client_name&sortOrder=asc')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      const descResponse = await request(app.getHttpServer())
        .get('/assessments?sortBy=client_name&sortOrder=desc')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(ascResponse.body.data).toBeDefined();
      expect(descResponse.body.data).toBeDefined();
    });

    it('should reject unauthenticated requests', async () => {
      await request(app.getHttpServer())
        .get('/assessments')
        .expect(401);
    });
  });

  describe('GET /assessments/:id', () => {
    it('should get single assessment with all relationships', async () => {
      const response = await request(app.getHttpServer())
        .get(`/assessments/${assessmentId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.id).toBe(assessmentId);
      expect(response.body).toHaveProperty('client_name');
      expect(response.body).toHaveProperty('business_name');
      expect(response.body).toHaveProperty('client_email');
      expect(response.body).toHaveProperty('status');
      expect(response.body).toHaveProperty('progress');
      expect(response.body).toHaveProperty('created_at');
      expect(response.body).toHaveProperty('updated_at');
    });

    it('should return 404 for non-existent assessment', async () => {
      const fakeId = '00000000-0000-0000-0000-000000000000';
      await request(app.getHttpServer())
        .get(`/assessments/${fakeId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(404);
    });

    it('should reject invalid UUID format', async () => {
      await request(app.getHttpServer())
        .get('/assessments/invalid-id')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(400);
    });
  });

  describe('PATCH /assessments/:id', () => {
    it('should update assessment details', async () => {
      const response = await request(app.getHttpServer())
        .patch(`/assessments/${assessmentId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          client_name: 'John M. Smith',
          business_name: 'Acme Corporation',
          notes: 'Updated notes',
        })
        .expect(200);

      expect(response.body.client_name).toBe('John M. Smith');
      expect(response.body.business_name).toBe('Acme Corporation');
      expect(response.body.notes).toBe('Updated notes');
    });

    it('should update status from draft to in_progress', async () => {
      const response = await request(app.getHttpServer())
        .patch(`/assessments/${assessmentId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          status: 'in_progress',
        })
        .expect(200);

      expect(response.body.status).toBe('in_progress');
      expect(response.body.started_at).toBeDefined();
    });

    it('should update status from in_progress to completed', async () => {
      const response = await request(app.getHttpServer())
        .patch(`/assessments/${assessmentId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          status: 'completed',
        })
        .expect(200);

      expect(response.body.status).toBe('completed');
      expect(response.body.completed_at).toBeDefined();
    });

    it('should reject invalid status transitions', async () => {
      // Can't go from completed back to draft
      const response = await request(app.getHttpServer())
        .patch(`/assessments/${assessmentId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          status: 'draft',
        })
        .expect(400);

      expect(response.body.message).toContain('transition');
    });

    it('should allow partial updates', async () => {
      const response = await request(app.getHttpServer())
        .patch(`/assessments/${assessmentId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          notes: 'Only updating notes',
        })
        .expect(200);

      expect(response.body.notes).toBe('Only updating notes');
    });
  });

  describe('DELETE /assessments/:id', () => {
    let deleteTestId: string;

    beforeAll(async () => {
      // Create an assessment to delete
      const createResponse = await request(app.getHttpServer())
        .post('/assessments')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          client_name: 'Delete Test',
          business_name: 'Delete Corp',
          client_email: 'delete@test.com',
        });

      deleteTestId = createResponse.body.id;
    });

    it('should soft delete assessment', async () => {
      await request(app.getHttpServer())
        .delete(`/assessments/${deleteTestId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(204);

      // Verify it's not in regular list
      const listResponse = await request(app.getHttpServer())
        .get('/assessments')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(
        listResponse.body.data.find((a: any) => a.id === deleteTestId)
      ).toBeUndefined();
    });

    it('should return 404 when deleting non-existent assessment', async () => {
      const fakeId = '00000000-0000-0000-0000-000000000000';
      await request(app.getHttpServer())
        .delete(`/assessments/${fakeId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(404);
    });
  });

  describe('Authorization', () => {
    let otherUserToken: string;
    let otherUserAssessmentId: string;

    beforeAll(async () => {
      // Create another user
      const registerResponse = await request(app.getHttpServer())
        .post('/auth/register')
        .send({
          email: `other-${Date.now()}@example.com`,
          password: 'OtherPass123!',
          first_name: 'Other',
          last_name: 'User',
        });

      otherUserToken = registerResponse.body.tokens.accessToken;

      // Create an assessment for the other user
      const assessmentResponse = await request(app.getHttpServer())
        .post('/assessments')
        .set('Authorization', `Bearer ${otherUserToken}`)
        .send({
          client_name: 'Other Client',
          business_name: 'Other Business',
          client_email: 'other@example.com',
        });

      otherUserAssessmentId = assessmentResponse.body.id;
    });

    it('should not allow user to access another user\'s assessment', async () => {
      await request(app.getHttpServer())
        .get(`/assessments/${otherUserAssessmentId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(403);
    });

    it('should not allow user to update another user\'s assessment', async () => {
      await request(app.getHttpServer())
        .patch(`/assessments/${otherUserAssessmentId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          notes: 'Attempting unauthorized update',
        })
        .expect(403);
    });

    it('should not allow user to delete another user\'s assessment', async () => {
      await request(app.getHttpServer())
        .delete(`/assessments/${otherUserAssessmentId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(403);
    });

    it('should only list user\'s own assessments', async () => {
      const response = await request(app.getHttpServer())
        .get('/assessments')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(
        response.body.data.every((a: any) => a.consultant_id === userId)
      ).toBe(true);
    });
  });

  describe('Assessment Workflow', () => {
    it('should complete full assessment workflow: create → update → complete → delete', async () => {
      // 1. Create
      const createResponse = await request(app.getHttpServer())
        .post('/assessments')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          client_name: 'Workflow Test',
          business_name: 'Workflow Corp',
          client_email: 'workflow@test.com',
        })
        .expect(201);

      const workflowId = createResponse.body.id;
      expect(createResponse.body.status).toBe('draft');

      // 2. Update to in_progress
      const updateResponse = await request(app.getHttpServer())
        .patch(`/assessments/${workflowId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          status: 'in_progress',
          notes: 'Started assessment',
        })
        .expect(200);

      expect(updateResponse.body.status).toBe('in_progress');
      expect(updateResponse.body.started_at).toBeDefined();

      // 3. Update progress
      const progressResponse = await request(app.getHttpServer())
        .patch(`/assessments/${workflowId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          progress: 50.5,
        })
        .expect(200);

      expect(Number(progressResponse.body.progress)).toBe(50.5);

      // 4. Complete
      const completeResponse = await request(app.getHttpServer())
        .patch(`/assessments/${workflowId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          status: 'completed',
          progress: 100,
        })
        .expect(200);

      expect(completeResponse.body.status).toBe('completed');
      expect(completeResponse.body.completed_at).toBeDefined();

      // 5. Delete
      await request(app.getHttpServer())
        .delete(`/assessments/${workflowId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(204);
    });
  });
});
