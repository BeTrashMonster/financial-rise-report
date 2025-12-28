import request from 'supertest';
import express, { Application } from 'express';
import assessmentRoutes from '../../routes/assessmentRoutes';
import questionnaireRoutes from '../../routes/questionnaireRoutes';
import { FinancialPhase } from '../../types';

describe('Assessment Integration Tests', () => {
  let app: Application;
  let authToken: string;
  let assessmentId: string;

  beforeAll(async () => {
    // Set up Express app with routes
    app = express();
    app.use(express.json());
    app.use('/api/v1/assessments', assessmentRoutes);
    app.use('/api/v1/questionnaire', questionnaireRoutes);

    // Mock authentication for tests
    authToken = 'mock-auth-token';
  });

  describe('POST /api/v1/assessments', () => {
    it('should create a new assessment', async () => {
      const response = await request(app)
        .post('/api/v1/assessments')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          clientName: 'John Doe',
          businessName: 'Doe Enterprises',
          clientEmail: 'john@doeenterprises.com',
        });

      expect(response.status).toBe(201);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('id');
      expect(response.body.data.clientName).toBe('John Doe');
      expect(response.body.data.status).toBe('draft');

      assessmentId = response.body.data.id;
    });

    it('should validate required fields', async () => {
      const response = await request(app)
        .post('/api/v1/assessments')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          clientName: 'John Doe',
          // Missing required fields
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBeDefined();
    });
  });

  describe('GET /api/v1/assessments', () => {
    it('should list all assessments for consultant', async () => {
      const response = await request(app)
        .get('/api/v1/assessments')
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(Array.isArray(response.body.data)).toBe(true);
    });

    it('should filter assessments by status', async () => {
      const response = await request(app)
        .get('/api/v1/assessments?status=draft')
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
    });
  });

  describe('GET /api/v1/assessments/:id', () => {
    it('should get a specific assessment', async () => {
      const response = await request(app)
        .get(`/api/v1/assessments/${assessmentId}`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data.id).toBe(assessmentId);
    });

    it('should return 404 for non-existent assessment', async () => {
      const response = await request(app)
        .get('/api/v1/assessments/non-existent-id')
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(404);
    });
  });

  describe('PATCH /api/v1/assessments/:id', () => {
    it('should update assessment responses', async () => {
      const response = await request(app)
        .patch(`/api/v1/assessments/${assessmentId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          responses: [
            {
              questionId: 'Q1',
              answer: 'Yes',
            },
          ],
        });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
    });

    it('should mark assessment as completed', async () => {
      const response = await request(app)
        .patch(`/api/v1/assessments/${assessmentId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          status: 'completed',
        });

      expect(response.status).toBe(200);
      expect(response.body.data.status).toBe('completed');
    });
  });

  describe('GET /api/v1/questionnaire', () => {
    it('should return questionnaire structure', async () => {
      const response = await request(app)
        .get('/api/v1/questionnaire')
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(Array.isArray(response.body.data.sections)).toBe(true);
    });

    it('should include questions for all phases', async () => {
      const response = await request(app)
        .get('/api/v1/questionnaire')
        .set('Authorization', `Bearer ${authToken}`);

      const sections = response.body.data.sections;
      const phases = sections.map((s: any) => s.phase);

      expect(phases).toContain(FinancialPhase.STABILIZE);
      expect(phases).toContain(FinancialPhase.ORGANIZE);
      expect(phases).toContain(FinancialPhase.BUILD);
    });
  });

  describe('Authentication Middleware', () => {
    it('should reject requests without auth token', async () => {
      const response = await request(app)
        .get('/api/v1/assessments');

      expect(response.status).toBe(401);
    });

    it('should reject requests with invalid token', async () => {
      const response = await request(app)
        .get('/api/v1/assessments')
        .set('Authorization', 'Bearer invalid-token');

      expect(response.status).toBe(401);
    });
  });
});
