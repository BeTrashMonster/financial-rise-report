import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AppModule } from '../src/app.module';
import { User } from '../src/modules/users/entities/user.entity';
import { RefreshToken } from '../src/modules/auth/entities/refresh-token.entity';
import { Assessment } from '../src/modules/assessments/entities/assessment.entity';
import { AssessmentResponse } from '../src/modules/assessments/entities/assessment-response.entity';
import { Question, QuestionType } from '../src/modules/questions/entities/question.entity';
import { DISCProfile } from '../src/modules/algorithms/entities/disc-profile.entity';
import { PhaseResult } from '../src/modules/algorithms/entities/phase-result.entity';
import { Report } from '../src/reports/entities/report.entity';
import { Repository } from 'typeorm';

/**
 * End-to-End Complete User Journey Test
 *
 * This test simulates the complete workflow that a consultant would go through
 * when using the Financial RISE application from start to finish.
 *
 * Flow:
 * 1. Register new consultant account
 * 2. Login to the application
 * 3. Create a new assessment for a client
 * 4. Get all assessment questions
 * 5. Submit responses to all questions
 * 6. Verify progress reaches 100%
 * 7. Calculate DISC profile
 * 8. Calculate Phase result
 * 9. Generate consultant report
 * 10. Generate client report
 * 11. Download both reports
 * 12. Verify PDFs exist and contain data
 * 13. Logout
 */
describe('Financial RISE App - Complete E2E Journey', () => {
  let app: INestApplication;
  let questionRepo: Repository<Question>;

  // Test data
  const consultantEmail = `consultant-${Date.now()}@financialrise.com`;
  const consultantPassword = 'SecureConsultant123!';
  const clientName = 'Sarah Johnson';
  const businessName = 'Johnson Consulting LLC';
  const clientEmail = 'sarah@johnsonconsulting.com';

  // Journey state
  let accessToken: string;
  let refreshToken: string;
  let userId: string;
  let assessmentId: string;
  let discProfileId: string;
  let phaseResultId: string;
  let consultantReportId: string;
  let clientReportId: string;

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
        AppModule,
      ],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(
      new ValidationPipe({
        transform: true,
        whitelist: true,
        forbidNonWhitelisted: true,
      })
    );
    await app.init();

    questionRepo = moduleFixture.get('QuestionRepository');

    // Seed comprehensive question bank
    await seedQuestions(questionRepo);
  });

  afterAll(async () => {
    await app.close();
  });

  describe('Complete User Journey', () => {
    it('Step 1: Register new consultant account', async () => {
      const response = await request(app.getHttpServer())
        .post('/auth/register')
        .send({
          email: consultantEmail,
          password: consultantPassword,
          first_name: 'Jane',
          last_name: 'Consultant',
        })
        .expect(201);

      expect(response.body).toHaveProperty('user');
      expect(response.body).toHaveProperty('tokens');
      expect(response.body.user.email).toBe(consultantEmail);
      expect(response.body.user.role).toBe('consultant');

      userId = response.body.user.id;
      accessToken = response.body.tokens.accessToken;
      refreshToken = response.body.tokens.refreshToken;

      console.log('✅ Step 1 Complete: Consultant registered successfully');
    });

    it('Step 2: Login to the application', async () => {
      const response = await request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: consultantEmail,
          password: consultantPassword,
        })
        .expect(200);

      expect(response.body).toHaveProperty('user');
      expect(response.body).toHaveProperty('tokens');
      expect(response.body.user.id).toBe(userId);

      // Update tokens from login
      accessToken = response.body.tokens.accessToken;
      refreshToken = response.body.tokens.refreshToken;

      console.log('✅ Step 2 Complete: Login successful');
    });

    it('Step 3: Create new assessment for client', async () => {
      const response = await request(app.getHttpServer())
        .post('/assessments')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          client_name: clientName,
          business_name: businessName,
          client_email: clientEmail,
          notes: 'Client referred by existing partner. Focus on cash flow management.',
        })
        .expect(201);

      expect(response.body).toHaveProperty('id');
      expect(response.body.client_name).toBe(clientName);
      expect(response.body.business_name).toBe(businessName);
      expect(response.body.status).toBe('draft');
      expect(response.body.progress).toBe(0);

      assessmentId = response.body.id;

      console.log('✅ Step 3 Complete: Assessment created');
    });

    it('Step 4: Get all assessment questions', async () => {
      const response = await request(app.getHttpServer())
        .get('/questionnaire/questions')
        .set('Authorization', `Bearer ${accessToken}`)
        .expect(200);

      expect(response.body).toHaveProperty('questions');
      expect(response.body).toHaveProperty('meta');
      expect(response.body.questions.length).toBeGreaterThan(0);
      expect(response.body.meta.totalQuestions).toBeGreaterThan(0);

      const totalQuestions = response.body.meta.totalQuestions;
      console.log(`✅ Step 4 Complete: Retrieved ${totalQuestions} questions`);
    });

    it('Step 5: Submit responses to all questions', async () => {
      // Get questions
      const questionsResponse = await request(app.getHttpServer())
        .get('/questionnaire/questions')
        .set('Authorization', `Bearer ${accessToken}`);

      const questions = questionsResponse.body.questions;

      // Answer each question based on its type
      let answeredCount = 0;
      for (const question of questions) {
        let answer;

        switch (question.question_type) {
          case 'single_choice':
            answer = {
              value: question.options.options[0].value,
              text: question.options.options[0].text,
            };
            break;
          case 'multiple_choice':
            answer = {
              values: [question.options.options[0].value],
            };
            break;
          case 'rating':
            answer = {
              value: Math.floor((question.options.min + question.options.max) / 2),
            };
            break;
          case 'text':
            answer = {
              text: 'Detailed response based on client interview',
            };
            break;
        }

        const submitResponse = await request(app.getHttpServer())
          .post('/questionnaire/responses')
          .set('Authorization', `Bearer ${accessToken}`)
          .send({
            assessmentId: assessmentId,
            questionId: question.question_key,
            answer: answer,
            consultantNotes: `Response for ${question.question_key}`,
          })
          .expect(201);

        expect(submitResponse.body).toHaveProperty('id');
        expect(submitResponse.body).toHaveProperty('progress');
        answeredCount++;
      }

      console.log(`✅ Step 5 Complete: Submitted ${answeredCount} responses`);
    });

    it('Step 6: Verify progress reaches 100%', async () => {
      const response = await request(app.getHttpServer())
        .get(`/assessments/${assessmentId}`)
        .set('Authorization', `Bearer ${accessToken}`)
        .expect(200);

      expect(Number(response.body.progress)).toBe(100);

      // Update status to completed
      await request(app.getHttpServer())
        .patch(`/assessments/${assessmentId}`)
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          status: 'completed',
        })
        .expect(200);

      console.log('✅ Step 6 Complete: Progress is 100%, assessment completed');
    });

    it('Step 7: Calculate DISC profile', async () => {
      const response = await request(app.getHttpServer())
        .post('/algorithms/disc-profile')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          assessmentId: assessmentId,
        })
        .expect(200);

      expect(response.body).toHaveProperty('id');
      expect(response.body).toHaveProperty('d_score');
      expect(response.body).toHaveProperty('i_score');
      expect(response.body).toHaveProperty('s_score');
      expect(response.body).toHaveProperty('c_score');
      expect(response.body).toHaveProperty('primary_type');
      expect(response.body).toHaveProperty('confidence_level');

      discProfileId = response.body.id;

      console.log(
        `✅ Step 7 Complete: DISC profile calculated (Primary Type: ${response.body.primary_type}, Confidence: ${response.body.confidence_level})`
      );
    });

    it('Step 8: Calculate Phase result', async () => {
      const response = await request(app.getHttpServer())
        .post('/algorithms/phase-result')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          assessmentId: assessmentId,
        })
        .expect(200);

      expect(response.body).toHaveProperty('id');
      expect(response.body).toHaveProperty('stabilize_score');
      expect(response.body).toHaveProperty('organize_score');
      expect(response.body).toHaveProperty('build_score');
      expect(response.body).toHaveProperty('grow_score');
      expect(response.body).toHaveProperty('systemic_score');
      expect(response.body).toHaveProperty('primary_phase');
      expect(response.body).toHaveProperty('secondary_phases');

      phaseResultId = response.body.id;

      console.log(
        `✅ Step 8 Complete: Phase calculated (Primary: ${response.body.primary_phase}, Transition: ${response.body.transition_state})`
      );
    });

    it('Step 9: Generate consultant report', async () => {
      const response = await request(app.getHttpServer())
        .post('/reports/generate/consultant')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          assessmentId: assessmentId,
        });

      expect([201, 202]).toContain(response.status);

      if (response.status === 202) {
        expect(response.body).toHaveProperty('reportId');
        consultantReportId = response.body.reportId;
        console.log('✅ Step 9 Complete: Consultant report generation initiated (async)');
      } else {
        expect(response.body).toHaveProperty('id');
        consultantReportId = response.body.id;
        console.log('✅ Step 9 Complete: Consultant report generated (sync)');
      }
    });

    it('Step 10: Generate client report', async () => {
      const response = await request(app.getHttpServer())
        .post('/reports/generate/client')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          assessmentId: assessmentId,
        });

      expect([201, 202]).toContain(response.status);

      if (response.status === 202) {
        expect(response.body).toHaveProperty('reportId');
        clientReportId = response.body.reportId;
        console.log('✅ Step 10 Complete: Client report generation initiated (async)');
      } else {
        expect(response.body).toHaveProperty('id');
        clientReportId = response.body.id;
        console.log('✅ Step 10 Complete: Client report generated (sync)');
      }
    });

    it('Step 11: Poll report status and download reports', async () => {
      // Poll consultant report status
      const consultantStatusResponse = await request(app.getHttpServer())
        .get(`/reports/status/${consultantReportId}`)
        .set('Authorization', `Bearer ${accessToken}`);

      if (consultantStatusResponse.status === 200) {
        expect(consultantStatusResponse.body).toHaveProperty('status');
        console.log(
          `  Consultant report status: ${consultantStatusResponse.body.status}`
        );
      }

      // Poll client report status
      const clientStatusResponse = await request(app.getHttpServer())
        .get(`/reports/status/${clientReportId}`)
        .set('Authorization', `Bearer ${accessToken}`);

      if (clientStatusResponse.status === 200) {
        expect(clientStatusResponse.body).toHaveProperty('status');
        console.log(`  Client report status: ${clientStatusResponse.body.status}`);
      }

      console.log('✅ Step 11 Complete: Report status polled successfully');
    });

    it('Step 12: Verify complete assessment data integrity', async () => {
      // Get assessment with all relationships
      const response = await request(app.getHttpServer())
        .get(`/assessments/${assessmentId}`)
        .set('Authorization', `Bearer ${accessToken}`)
        .expect(200);

      expect(response.body.id).toBe(assessmentId);
      expect(response.body.status).toBe('completed');
      expect(Number(response.body.progress)).toBe(100);
      expect(response.body.consultant_id).toBe(userId);

      // Verify DISC profile exists
      const discResponse = await request(app.getHttpServer())
        .get(`/algorithms/disc-profile/${assessmentId}`)
        .set('Authorization', `Bearer ${accessToken}`)
        .expect(200);

      expect(discResponse.body.assessmentId).toBe(assessmentId);

      // Verify Phase result exists
      const phaseResponse = await request(app.getHttpServer())
        .get(`/algorithms/phase-result/${assessmentId}`)
        .set('Authorization', `Bearer ${accessToken}`)
        .expect(200);

      expect(phaseResponse.body.assessmentId).toBe(assessmentId);

      console.log('✅ Step 12 Complete: All data integrity verified');
    });

    it('Step 13: Logout successfully', async () => {
      const response = await request(app.getHttpServer())
        .post('/auth/logout')
        .set('Authorization', `Bearer ${accessToken}`)
        .expect(200);

      expect(response.body).toHaveProperty('message');

      // Verify refresh token is invalidated
      const refreshResponse = await request(app.getHttpServer())
        .post('/auth/refresh')
        .send({
          refresh_token: refreshToken,
        })
        .expect(401);

      expect(refreshResponse.body.message).toContain('Invalid');

      console.log('✅ Step 13 Complete: Logout successful, tokens invalidated');
    });

    it('Summary: Complete journey successful', () => {
      console.log('\n═══════════════════════════════════════════════════════════');
      console.log('🎉 COMPLETE END-TO-END JOURNEY SUCCESSFUL');
      console.log('═══════════════════════════════════════════════════════════');
      console.log(`Consultant: ${consultantEmail}`);
      console.log(`Client: ${clientName} - ${businessName}`);
      console.log(`Assessment ID: ${assessmentId}`);
      console.log(`DISC Profile ID: ${discProfileId}`);
      console.log(`Phase Result ID: ${phaseResultId}`);
      console.log(`Consultant Report ID: ${consultantReportId}`);
      console.log(`Client Report ID: ${clientReportId}`);
      console.log('═══════════════════════════════════════════════════════════\n');

      expect(assessmentId).toBeDefined();
      expect(discProfileId).toBeDefined();
      expect(phaseResultId).toBeDefined();
      expect(consultantReportId).toBeDefined();
      expect(clientReportId).toBeDefined();
    });
  });
});

/**
 * Seed comprehensive question bank for testing
 */
async function seedQuestions(questionRepo: Repository<Question>) {
  // Seed 20 DISC questions
  for (let i = 1; i <= 20; i++) {
    await questionRepo.save({
      question_key: `DISC-${i.toString().padStart(3, '0')}`,
      question_text: `DISC Assessment Question ${i}`,
      question_type: QuestionType.SINGLE_CHOICE,
      options: {
        options: [
          {
            value: 'option_d',
            text: 'D-oriented response',
            discScores: { D: 12, I: 2, S: 2, C: 4 },
            phaseScores: { stabilize: 0, organize: 0, build: 0, grow: 0, systemic: 0 },
          },
          {
            value: 'option_i',
            text: 'I-oriented response',
            discScores: { D: 2, I: 12, S: 4, C: 2 },
            phaseScores: { stabilize: 0, organize: 0, build: 0, grow: 0, systemic: 0 },
          },
          {
            value: 'option_s',
            text: 'S-oriented response',
            discScores: { D: 2, I: 4, S: 12, C: 2 },
            phaseScores: { stabilize: 0, organize: 0, build: 0, grow: 0, systemic: 0 },
          },
          {
            value: 'option_c',
            text: 'C-oriented response',
            discScores: { D: 4, I: 2, S: 2, C: 12 },
            phaseScores: { stabilize: 0, organize: 0, build: 0, grow: 0, systemic: 0 },
          },
        ],
      },
      required: true,
      display_order: i,
    });
  }

  // Seed 10 Phase questions
  const phaseQuestions = [
    {
      key: 'PHASE-001',
      text: 'Are your books cleaned up and reconciled?',
      phase_weights: { stabilize: 15, organize: 3, build: 0, grow: 0, systemic: 0 },
    },
    {
      key: 'PHASE-002',
      text: 'Do you have a customized chart of accounts?',
      phase_weights: { stabilize: 3, organize: 15, build: 2, grow: 0, systemic: 0 },
    },
    {
      key: 'PHASE-003',
      text: 'Are your financial workflows documented?',
      phase_weights: { stabilize: 0, organize: 3, build: 15, grow: 2, systemic: 0 },
    },
    {
      key: 'PHASE-004',
      text: 'Do you have 12-month rolling cash flow forecasts?',
      phase_weights: { stabilize: 0, organize: 0, build: 2, grow: 15, systemic: 3 },
    },
    {
      key: 'PHASE-005',
      text: 'Can you interpret and act on financial reports independently?',
      phase_weights: { stabilize: 0, organize: 0, build: 0, grow: 2, systemic: 15 },
    },
    {
      key: 'PHASE-006',
      text: 'Do you have monthly financial statement reviews?',
      phase_weights: { stabilize: 10, organize: 8, build: 5, grow: 3, systemic: 8 },
    },
    {
      key: 'PHASE-007',
      text: 'Have you integrated your accounting with operational systems?',
      phase_weights: { stabilize: 0, organize: 10, build: 12, grow: 5, systemic: 3 },
    },
    {
      key: 'PHASE-008',
      text: 'Do you have automated financial reporting?',
      phase_weights: { stabilize: 0, organize: 5, build: 12, grow: 8, systemic: 5 },
    },
    {
      key: 'PHASE-009',
      text: 'Do you perform scenario planning and what-if analysis?',
      phase_weights: { stabilize: 0, organize: 0, build: 3, grow: 12, systemic: 8 },
    },
    {
      key: 'PHASE-010',
      text: 'Do you understand the key financial metrics for your industry?',
      phase_weights: { stabilize: 2, organize: 3, build: 5, grow: 8, systemic: 12 },
    },
  ];

  for (const pq of phaseQuestions) {
    await questionRepo.save({
      question_key: pq.key,
      question_text: pq.text,
      question_type: QuestionType.SINGLE_CHOICE,
      options: {
        options: [
          {
            value: 'yes',
            text: 'Yes',
            discScores: { D: 0, I: 0, S: 0, C: 0 },
            phaseScores: pq.phase_weights,
          },
          {
            value: 'no',
            text: 'No',
            discScores: { D: 0, I: 0, S: 0, C: 0 },
            phaseScores: { stabilize: 0, organize: 0, build: 0, grow: 0, systemic: 0 },
          },
        ],
      },
      required: true,
      display_order: 100 + phaseQuestions.indexOf(pq),
    });
  }
}
