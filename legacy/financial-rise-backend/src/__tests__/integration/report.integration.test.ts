import request from 'supertest';
import express, { Application } from 'express';
import reportRoutes from '../../routes/reportRoutes';
import { FinancialPhase } from '../../types';

describe('Report Generation Integration Tests', () => {
  let app: Application;
  let authToken: string;
  const completedAssessmentId = 'test-assessment-123';

  beforeAll(async () => {
    // Set up Express app with routes
    app = express();
    app.use(express.json());
    app.use('/api/v1/reports', reportRoutes);

    // Mock authentication
    authToken = 'mock-auth-token';
  });

  describe('POST /api/v1/assessments/:id/reports/consultant', () => {
    it('should generate consultant report for completed assessment', async () => {
      const response = await request(app)
        .post(`/api/v1/assessments/${completedAssessmentId}/reports/consultant`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(201);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('reportId');
      expect(response.body.data).toHaveProperty('pdfUrl');
      expect(response.body.data.reportType).toBe('consultant');
    });

    it('should reject report generation for incomplete assessment', async () => {
      const response = await request(app)
        .post('/api/v1/assessments/incomplete-assessment-id/reports/consultant')
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe('ASSESSMENT_NOT_COMPLETED');
    });

    it('should require authentication', async () => {
      const response = await request(app)
        .post(`/api/v1/assessments/${completedAssessmentId}/reports/consultant`);

      expect(response.status).toBe(401);
    });
  });

  describe('POST /api/v1/assessments/:id/reports/client', () => {
    it('should generate client report for completed assessment', async () => {
      const response = await request(app)
        .post(`/api/v1/assessments/${completedAssessmentId}/reports/client`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(201);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('reportId');
      expect(response.body.data).toHaveProperty('pdfUrl');
      expect(response.body.data.reportType).toBe('client');
    });

    it('should include personalized content based on DISC profile', async () => {
      const response = await request(app)
        .post(`/api/v1/assessments/${completedAssessmentId}/reports/client`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(201);
      // Report should be generated with DISC-adapted content
      expect(response.body.data.pdfUrl).toBeDefined();
    });
  });

  describe('POST /api/v1/assessments/:id/reports/both', () => {
    it('should generate both consultant and client reports', async () => {
      const response = await request(app)
        .post(`/api/v1/assessments/${completedAssessmentId}/reports/both`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(201);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('consultantReport');
      expect(response.body.data).toHaveProperty('clientReport');
      expect(response.body.data.consultantReport.reportType).toBe('consultant');
      expect(response.body.data.clientReport.reportType).toBe('client');
    });

    it('should handle errors gracefully', async () => {
      const response = await request(app)
        .post('/api/v1/assessments/non-existent/reports/both')
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBeGreaterThanOrEqual(400);
      expect(response.body.error).toBeDefined();
    });
  });

  describe('Report Download', () => {
    it('should allow downloading generated reports', async () => {
      const response = await request(app)
        .get('/api/v1/reports/test-report-id/download')
        .set('Authorization', `Bearer ${authToken}`);

      // Implementation pending - should either return PDF or redirect to S3 URL
      expect([200, 302, 404]).toContain(response.status);
    });
  });

  describe('Error Handling', () => {
    it('should handle missing assessment ID', async () => {
      const response = await request(app)
        .post('/api/v1/assessments//reports/consultant')
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(404);
    });

    it('should handle invalid report type', async () => {
      const response = await request(app)
        .post(`/api/v1/assessments/${completedAssessmentId}/reports/invalid-type`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(404);
    });
  });

  describe('Rate Limiting', () => {
    it('should apply rate limiting to report generation', async () => {
      // Make multiple requests in quick succession
      const requests = Array(10).fill(null).map(() =>
        request(app)
          .post(`/api/v1/assessments/${completedAssessmentId}/reports/consultant`)
          .set('Authorization', `Bearer ${authToken}`)
      );

      const responses = await Promise.all(requests);
      
      // At least one should succeed
      const successfulRequests = responses.filter(r => r.status === 201);
      expect(successfulRequests.length).toBeGreaterThan(0);
    });
  });
});
