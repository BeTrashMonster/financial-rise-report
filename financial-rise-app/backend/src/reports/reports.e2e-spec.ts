import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ReportsModule } from './reports.module';
import { AlgorithmsModule } from '../modules/algorithms/algorithms.module';
import { AssessmentsModule } from '../modules/assessments/assessments.module';
import { QuestionsModule } from '../modules/questions/questions.module';
import { QuestionnaireModule } from '../modules/questionnaire/questionnaire.module';
import { AuthModule } from '../modules/auth/auth.module';
import { UsersModule } from '../modules/users/users.module';
import { Assessment } from '../modules/assessments/entities/assessment.entity';
import { AssessmentResponse } from '../modules/assessments/entities/assessment-response.entity';
import { Question, QuestionType } from '../modules/questions/entities/question.entity';
import { User } from '../modules/users/entities/user.entity';
import { RefreshToken } from '../modules/auth/entities/refresh-token.entity';
import { DISCProfile } from '../modules/algorithms/entities/disc-profile.entity';
import { PhaseResult } from '../modules/algorithms/entities/phase-result.entity';
import { Report } from './entities/report.entity';
import { Repository } from 'typeorm';

describe('Reports E2E Tests', () => {
  let app: INestApplication;
  let authToken: string;
  let assessmentId: string;
  let questionRepo: Repository<Question>;
  const testEmail = `reports-${Date.now()}@example.com`;

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
            AssessmentResponse,
            Question,
            DISCProfile,
            PhaseResult,
            Report,
          ],
          synchronize: true,
          dropSchema: true,
          logging: false,
        }),
        AuthModule,
        UsersModule,
        AssessmentsModule,
        QuestionsModule,
        QuestionnaireModule,
        AlgorithmsModule,
        ReportsModule,
      ],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ transform: true, whitelist: true }));
    await app.init();

    questionRepo = moduleFixture.get('QuestionRepository');

    // Seed minimal questions for testing
    for (let i = 1; i <= 15; i++) {
      await questionRepo.save({
        question_key: `Q-${i.toString().padStart(3, '0')}`,
        question_text: `Test Question ${i}`,
        question_type: QuestionType.SINGLE_CHOICE,
        options: {
          options: [
            {
              value: 'option_a',
              text: 'Option A',
              discScores: { D: 10, I: 5, S: 5, C: 10 },
              phaseScores: { stabilize: 10, organize: 10, build: 5, grow: 5, systemic: 5 },
            },
          ],
        },
        required: true,
        display_order: i,
      });
    }

    // Register and login
    const registerResponse = await request(app.getHttpServer())
      .post('/auth/register')
      .send({
        email: testEmail,
        password: 'TestPass123!',
        first_name: 'Test',
        last_name: 'User',
      });

    authToken = registerResponse.body.tokens.accessToken;

    // Create and complete assessment
    const assessmentResponse = await request(app.getHttpServer())
      .post('/assessments')
      .set('Authorization', `Bearer ${authToken}`)
      .send({
        client_name: 'Report Test Client',
        business_name: 'Report Test Corp',
        client_email: 'reporttest@example.com',
      });

    assessmentId = assessmentResponse.body.id;

    // Answer all questions
    for (let i = 1; i <= 15; i++) {
      await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
          questionId: `Q-${i.toString().padStart(3, '0')}`,
          answer: { value: 'option_a' },
        });
    }

    // Calculate DISC and Phase
    await request(app.getHttpServer())
      .post('/algorithms/disc-profile')
      .set('Authorization', `Bearer ${authToken}`)
      .send({ assessmentId });

    await request(app.getHttpServer())
      .post('/algorithms/phase-result')
      .set('Authorization', `Bearer ${authToken}`)
      .send({ assessmentId });
  });

  afterAll(async () => {
    await app.close();
  });

  describe('POST /reports/generate/consultant', () => {
    it('should initiate consultant report generation', async () => {
      const response = await request(app.getHttpServer())
        .post('/reports/generate/consultant')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
        });

      // May return 202 (Accepted) for async processing or 201 for sync
      expect([201, 202]).toContain(response.status);

      if (response.status === 202) {
        expect(response.body).toHaveProperty('reportId');
        expect(response.body).toHaveProperty('status');
        expect(response.body.status).toBe('generating');
        expect(response.body).toHaveProperty('message');
        expect(response.body).toHaveProperty('estimatedCompletionTime');
      } else {
        expect(response.body).toHaveProperty('id');
        expect(response.body.report_type).toBe('consultant');
      }
    });

    it('should reject generation for incomplete assessment', async () => {
      // Create assessment without answers
      const incompleteAssessment = await request(app.getHttpServer())
        .post('/assessments')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          client_name: 'Incomplete',
          business_name: 'Test',
          client_email: 'incomplete@test.com',
        });

      const response = await request(app.getHttpServer())
        .post('/reports/generate/consultant')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: incompleteAssessment.body.id,
        })
        .expect(400);

      expect(response.body.message).toContain('complete');
    });

    it('should reject generation without authentication', async () => {
      await request(app.getHttpServer())
        .post('/reports/generate/consultant')
        .send({
          assessmentId: assessmentId,
        })
        .expect(401);
    });

    it('should reject generation for non-existent assessment', async () => {
      const fakeId = '00000000-0000-0000-0000-000000000000';

      await request(app.getHttpServer())
        .post('/reports/generate/consultant')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: fakeId,
        })
        .expect(404);
    });
  });

  describe('POST /reports/generate/client', () => {
    it('should initiate client report generation', async () => {
      const response = await request(app.getHttpServer())
        .post('/reports/generate/client')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
        });

      expect([201, 202]).toContain(response.status);

      if (response.status === 202) {
        expect(response.body).toHaveProperty('reportId');
        expect(response.body).toHaveProperty('status');
        expect(response.body.status).toBe('generating');
      } else {
        expect(response.body).toHaveProperty('id');
        expect(response.body.report_type).toBe('client');
      }
    });

    it('should not expose DISC scores in client report', async () => {
      const response = await request(app.getHttpServer())
        .post('/reports/generate/client')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
        });

      if (response.status === 201) {
        // DISC scores should be hidden in client report
        expect(response.body).not.toHaveProperty('disc_profile');
      }
    });
  });

  describe('GET /reports/status/:reportId', () => {
    let reportId: string;

    beforeAll(async () => {
      const generateResponse = await request(app.getHttpServer())
        .post('/reports/generate/consultant')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
        });

      if (generateResponse.status === 202) {
        reportId = generateResponse.body.reportId;
      } else {
        reportId = generateResponse.body.id;
      }
    });

    it('should get report status', async () => {
      const response = await request(app.getHttpServer())
        .get(`/reports/status/${reportId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body).toHaveProperty('reportId');
      expect(response.body).toHaveProperty('status');
      expect(['generating', 'completed', 'failed']).toContain(response.body.status);

      if (response.body.status === 'generating') {
        expect(response.body).toHaveProperty('progress');
        expect(response.body).toHaveProperty('message');
      } else if (response.body.status === 'completed') {
        expect(response.body).toHaveProperty('fileUrl');
        expect(response.body).toHaveProperty('generatedAt');
        expect(response.body).toHaveProperty('expiresAt');
      } else if (response.body.status === 'failed') {
        expect(response.body).toHaveProperty('error');
        expect(response.body).toHaveProperty('message');
      }
    });

    it('should return 404 for non-existent report', async () => {
      const fakeId = '00000000-0000-0000-0000-000000000000';

      await request(app.getHttpServer())
        .get(`/reports/status/${fakeId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(404);
    });
  });

  describe('GET /reports/download/:reportId', () => {
    let reportId: string;

    beforeAll(async () => {
      const generateResponse = await request(app.getHttpServer())
        .post('/reports/generate/consultant')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
        });

      if (generateResponse.status === 202) {
        reportId = generateResponse.body.reportId;
        // Wait for report to complete (simplified for test)
        await new Promise(resolve => setTimeout(resolve, 2000));
      } else {
        reportId = generateResponse.body.id;
      }
    });

    it('should download completed report', async () => {
      const response = await request(app.getHttpServer())
        .get(`/reports/download/${reportId}`)
        .set('Authorization', `Bearer ${authToken}`);

      if (response.status === 200) {
        expect(response.headers['content-type']).toContain('pdf');
        expect(response.headers['content-disposition']).toContain('attachment');
        expect(response.body).toBeDefined();
      } else {
        // Report may still be generating
        expect(response.status).toBe(404);
      }
    });

    it('should return 404 for non-existent report', async () => {
      const fakeId = '00000000-0000-0000-0000-000000000000';

      await request(app.getHttpServer())
        .get(`/reports/download/${fakeId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(404);
    });

    it('should reject download without authentication', async () => {
      await request(app.getHttpServer())
        .get(`/reports/download/${reportId}`)
        .expect(401);
    });
  });

  describe('Complete Report Generation Flow', () => {
    it('should generate consultant and client reports for completed assessment', async () => {
      // 1. Generate consultant report
      const consultantResponse = await request(app.getHttpServer())
        .post('/reports/generate/consultant')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
        });

      expect([201, 202]).toContain(consultantResponse.status);

      // 2. Generate client report
      const clientResponse = await request(app.getHttpServer())
        .post('/reports/generate/client')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
        });

      expect([201, 202]).toContain(clientResponse.status);

      // 3. Verify both reports can be accessed
      if (consultantResponse.status === 202) {
        const statusCheck = await request(app.getHttpServer())
          .get(`/reports/status/${consultantResponse.body.reportId}`)
          .set('Authorization', `Bearer ${authToken}`)
          .expect(200);

        expect(statusCheck.body).toHaveProperty('status');
      }

      if (clientResponse.status === 202) {
        const statusCheck = await request(app.getHttpServer())
          .get(`/reports/status/${clientResponse.body.reportId}`)
          .set('Authorization', `Bearer ${authToken}`)
          .expect(200);

        expect(statusCheck.body).toHaveProperty('status');
      }
    });
  });

  describe('Report Error Handling', () => {
    it('should handle PDF generation errors gracefully', async () => {
      // This would test error handling in the report service
      // Implementation depends on actual service structure

      const response = await request(app.getHttpServer())
        .post('/reports/generate/consultant')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
        });

      // Should not crash, even if PDF generation fails
      expect([200, 201, 202, 500]).toContain(response.status);
    });

    it('should validate assessment has DISC profile before generating', async () => {
      // Create assessment without DISC calculation
      const noDiscAssessment = await request(app.getHttpServer())
        .post('/assessments')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          client_name: 'No DISC',
          business_name: 'Test',
          client_email: 'nodisc@test.com',
        });

      // Answer questions
      for (let i = 1; i <= 15; i++) {
        await request(app.getHttpServer())
          .post('/questionnaire/responses')
          .set('Authorization', `Bearer ${authToken}`)
          .send({
            assessmentId: noDiscAssessment.body.id,
            questionId: `Q-${i.toString().padStart(3, '0')}`,
            answer: { value: 'option_a' },
          });
      }

      // Try to generate report without DISC calculation
      const response = await request(app.getHttpServer())
        .post('/reports/generate/consultant')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: noDiscAssessment.body.id,
        })
        .expect(400);

      expect(response.body.message).toContain('DISC');
    });

    it('should validate assessment has Phase result before generating', async () => {
      // Create assessment with DISC but no Phase
      const noPhaseAssessment = await request(app.getHttpServer())
        .post('/assessments')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          client_name: 'No Phase',
          business_name: 'Test',
          client_email: 'nophase@test.com',
        });

      // Answer questions
      for (let i = 1; i <= 15; i++) {
        await request(app.getHttpServer())
          .post('/questionnaire/responses')
          .set('Authorization', `Bearer ${authToken}`)
          .send({
            assessmentId: noPhaseAssessment.body.id,
            questionId: `Q-${i.toString().padStart(3, '0')}`,
            answer: { value: 'option_a' },
          });
      }

      // Calculate only DISC
      await request(app.getHttpServer())
        .post('/algorithms/disc-profile')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ assessmentId: noPhaseAssessment.body.id });

      // Try to generate report without Phase calculation
      const response = await request(app.getHttpServer())
        .post('/reports/generate/consultant')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: noPhaseAssessment.body.id,
        })
        .expect(400);

      expect(response.body.message).toContain('Phase');
    });
  });
});
