# NestJS Consolidation Action Plan

**Date:** 2025-12-27
**Decision:** Consolidate to NestJS architecture
**Canonical Backend:** `financial-rise-app/backend/`
**Canonical Frontend:** `financial-rise-frontend/`

---

## Executive Summary

This plan outlines the specific steps to consolidate the Financial RISE codebase from dual implementations (Express + NestJS) to a single NestJS-based backend, while retaining the more complete Express frontend.

**Key Documents:**
- Code Audit: `IMPLEMENTATION-STATUS.md`
- API Contract: `API-CONTRACT.md`
- Team Coordination: `TEAM-COORDINATION.md`

---

## Phase 1: Foundation (CRITICAL - Do First)

### 1.1 Generate Database Migrations

**Priority:** 🔴 CRITICAL
**Owner:** DevOps Agent

**Current State:**
- NestJS entities exist but no migrations
- Cannot run application without database schema

**Actions:**

#### Step 1: Configure TypeORM CLI
```bash
cd financial-rise-app/backend

# Verify typeorm.config.ts exists
# Should export DataSource for migrations
```

**Expected File:** `financial-rise-app/backend/src/config/typeorm.config.ts`

#### Step 2: Generate Initial Migration
```bash
# Generate migration from current entities
npm run typeorm migration:generate -- -n InitialSchema
```

**Expected Output:**
- File: `src/database/migrations/{timestamp}-InitialSchema.ts`
- Contains: CREATE TABLE statements for all entities

#### Step 3: Review and Modify Migration

**Add Missing Elements:**
1. Foreign key constraints (Assessment → User, etc.)
2. Database indexes for performance
3. Check constraints for enums
4. Proper cascade delete rules

**Critical Tables:**
- `users` (id, email, password_hash, role, status, etc.)
- `assessments` (id, consultant_id, client_name, status, progress, etc.)
- `assessment_responses` (id, assessment_id, question_id, answer, etc.)
- `questions` (id, question_key, question_text, question_type, options, etc.)
- `disc_profiles` (id, assessment_id, d_score, i_score, s_score, c_score, etc.)
- `phase_results` (id, assessment_id, stabilize_score, organize_score, etc.)
- `refresh_tokens` (id, user_id, token, expires_at, etc.)
- `reports` (id, assessment_id, report_type, file_url, etc.)

#### Step 4: Create Seed Data Migration
```bash
npm run typeorm migration:create -- -n SeedQuestions
```

**Seed Data Requirements:**
- Insert ~42 questions with full DISC/Phase scoring
- Use data from Express backend's hardcoded question bank
- Ensure `display_order` is sequential

**Example Seed Structure:**
```sql
INSERT INTO questions (
  question_key,
  question_text,
  question_type,
  options,
  required,
  display_order
) VALUES (
  'FIN-001',
  'How frequently do you review your financial statements?',
  'single_choice',
  '{ "options": [ ... ] }'::jsonb,
  true,
  1
);
```

#### Step 5: Test Migrations Locally
```bash
# Create test database
createdb financial_rise_dev

# Run migrations
npm run typeorm migration:run

# Verify tables created
psql financial_rise_dev -c "\dt"

# Check seed data
psql financial_rise_dev -c "SELECT COUNT(*) FROM questions;"
```

**Success Criteria:**
- [ ] All tables created successfully
- [ ] Foreign keys enforced
- [ ] Indexes exist
- [ ] 42 questions seeded
- [ ] No migration errors

---

### 1.2 Fix Security Vulnerabilities

**Priority:** 🔴 CRITICAL
**Owner:** Backend Agent 1

**Issues Identified in Audit:**
1. No password complexity validation in NestJS
2. Reset token reuse possible
3. Missing CSRF protection
4. Refresh token stored in users table (single device only)

#### Issue 1: Password Complexity Validation

**File:** `financial-rise-app/backend/src/modules/auth/auth.service.ts`

**Current:** No password validation

**Required:** Add validation matching Express backend

**Implementation:**
```typescript
// Add to auth.service.ts
private validatePasswordComplexity(password: string): void {
  const minLength = 8;
  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumber = /\d/.test(password);
  const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);

  if (password.length < minLength) {
    throw new BadRequestException('Password must be at least 8 characters long');
  }
  if (!hasUppercase) {
    throw new BadRequestException('Password must contain at least one uppercase letter');
  }
  if (!hasLowercase) {
    throw new BadRequestException('Password must contain at least one lowercase letter');
  }
  if (!hasNumber) {
    throw new BadRequestException('Password must contain at least one number');
  }
  if (!hasSpecial) {
    throw new BadRequestException('Password must contain at least one special character');
  }
}

// Call in register() method
async register(registerDto: RegisterDto) {
  this.validatePasswordComplexity(registerDto.password);
  // ... rest of registration logic
}
```

**Test:**
```typescript
// auth.service.spec.ts
it('should reject weak passwords', async () => {
  await expect(
    service.register({ email: 'test@test.com', password: 'weak' })
  ).rejects.toThrow('Password must be at least 8 characters');
});
```

---

#### Issue 2: Reset Token Reuse Prevention

**File:** `financial-rise-app/backend/src/modules/users/entities/user.entity.ts`

**Current:**
```typescript
@Column({ type: 'varchar', length: 255, nullable: true })
resetPasswordToken: string;

@Column({ type: 'timestamp', nullable: true })
resetPasswordExpires: Date;
```

**Required:** Add `resetPasswordUsedAt` column

**Migration:**
```bash
npm run typeorm migration:create -- -n AddResetTokenUsedAt
```

**Migration Content:**
```typescript
await queryRunner.query(`
  ALTER TABLE users
  ADD COLUMN reset_password_used_at TIMESTAMP NULL
`);
```

**Service Update:**
```typescript
// auth.service.ts - resetPassword method
async resetPassword(token: string, newPassword: string) {
  const user = await this.usersService.findByResetToken(token);

  if (!user || user.resetPasswordExpires < new Date()) {
    throw new BadRequestException('Invalid or expired reset token');
  }

  // NEW: Check if token already used
  if (user.resetPasswordUsedAt) {
    throw new BadRequestException('Reset token has already been used');
  }

  this.validatePasswordComplexity(newPassword);

  user.password = await bcrypt.hash(newPassword, 10);
  user.resetPasswordToken = null;
  user.resetPasswordExpires = null;
  user.resetPasswordUsedAt = new Date(); // NEW

  await this.usersService.save(user);
}
```

---

#### Issue 3: CSRF Protection

**File:** `financial-rise-app/backend/src/main.ts`

**Install Package:**
```bash
npm install --save csurf
npm install --save-dev @types/csurf
```

**Implementation:**
```typescript
// main.ts
import * as csurf from 'csurf';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // ... existing middleware

  // Add CSRF protection
  app.use(csurf({ cookie: true }));

  await app.listen(3000);
}
```

**Note:** Frontend must include CSRF token in state-changing requests

**Alternative (for API-only):** Use double-submit cookie pattern

---

#### Issue 4: Refresh Token Table

**Current:** Refresh token stored in `users.refresh_token` column

**Problem:** Only one token per user (single device)

**Solution:** Create `refresh_tokens` table

**Migration:**
```bash
npm run typeorm migration:create -- -n CreateRefreshTokensTable
```

**Migration Content:**
```typescript
await queryRunner.query(`
  CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
  );

  CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);
  CREATE INDEX idx_refresh_tokens_token ON refresh_tokens(token);
`);
```

**Entity:**
```typescript
// src/modules/auth/entities/refresh-token.entity.ts
@Entity('refresh_tokens')
export class RefreshToken {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  userId: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: User;

  @Column({ type: 'varchar', length: 255, unique: true })
  token: string;

  @Column({ type: 'timestamp' })
  expiresAt: Date;

  @Column({ type: 'timestamp', nullable: true })
  revokedAt: Date;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;
}
```

**Service Update:**
```typescript
// auth.service.ts
async login(user: User) {
  const accessToken = this.generateAccessToken(user);
  const refreshToken = this.generateRefreshToken();

  // Store refresh token in database
  await this.refreshTokenRepository.save({
    userId: user.id,
    token: refreshToken,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
  });

  return { accessToken, refreshToken };
}

async revokeAllUserTokens(userId: string) {
  await this.refreshTokenRepository.update(
    { userId, revokedAt: null },
    { revokedAt: new Date() }
  );
}
```

---

### 1.3 Re-enable Assessment Module

**Priority:** 🔴 CRITICAL
**Owner:** Backend Agent 1

**Current State:**
- Assessment and Questions modules commented out in `app.module.ts` (line 8)
- Entities don't exist in NestJS backend

#### Step 1: Create Assessment Entities

**File:** `financial-rise-app/backend/src/modules/assessments/entities/assessment.entity.ts`

```typescript
import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, OneToMany, JoinColumn, CreateDateColumn, UpdateDateColumn, DeleteDateColumn } from 'typeorm';
import { User } from '../../users/entities/user.entity';
import { AssessmentResponse } from './assessment-response.entity';
import { DISCProfile } from '../../algorithms/entities/disc-profile.entity';
import { PhaseResult } from '../../algorithms/entities/phase-result.entity';

@Entity('assessments')
export class Assessment {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid', name: 'consultant_id' })
  consultantId: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'consultant_id' })
  consultant: User;

  @Column({ type: 'varchar', length: 100, name: 'client_name' })
  clientName: string;

  @Column({ type: 'varchar', length: 100, name: 'business_name' })
  businessName: string;

  @Column({ type: 'varchar', length: 255, name: 'client_email' })
  clientEmail: string;

  @Column({
    type: 'enum',
    enum: ['draft', 'in_progress', 'completed'],
    default: 'draft',
  })
  status: 'draft' | 'in_progress' | 'completed';

  @Column({ type: 'decimal', precision: 5, scale: 2, default: 0 })
  progress: number;

  @Column({ type: 'text', nullable: true })
  notes: string;

  @OneToMany(() => AssessmentResponse, response => response.assessment)
  responses: AssessmentResponse[];

  @OneToMany(() => DISCProfile, profile => profile.assessment)
  discProfiles: DISCProfile[];

  @OneToMany(() => PhaseResult, result => result.assessment)
  phaseResults: PhaseResult[];

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;

  @Column({ type: 'timestamp', nullable: true, name: 'started_at' })
  startedAt: Date;

  @Column({ type: 'timestamp', nullable: true, name: 'completed_at' })
  completedAt: Date;

  @DeleteDateColumn({ name: 'deleted_at' })
  deletedAt: Date;
}
```

**File:** `financial-rise-app/backend/src/modules/assessments/entities/assessment-response.entity.ts`

```typescript
@Entity('assessment_responses')
export class AssessmentResponse {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid', name: 'assessment_id' })
  assessmentId: string;

  @ManyToOne(() => Assessment, assessment => assessment.responses, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'assessment_id' })
  assessment: Assessment;

  @Column({ type: 'varchar', length: 50, name: 'question_id' })
  questionId: string;

  @ManyToOne(() => Question, { onDelete: 'RESTRICT' })
  @JoinColumn({ name: 'question_id', referencedColumnName: 'questionKey' })
  question: Question;

  @Column({ type: 'jsonb' })
  answer: Record<string, any>;

  @Column({ type: 'boolean', default: false, name: 'not_applicable' })
  notApplicable: boolean;

  @Column({ type: 'text', nullable: true, name: 'consultant_notes' })
  consultantNotes: string;

  @Column({ type: 'timestamp', name: 'answered_at' })
  answeredAt: Date;
}
```

**File:** `financial-rise-app/backend/src/modules/questions/entities/question.entity.ts`

```typescript
@Entity('questions')
export class Question {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'varchar', length: 50, unique: true, name: 'question_key' })
  questionKey: string;

  @Column({ type: 'text', name: 'question_text' })
  questionText: string;

  @Column({
    type: 'enum',
    enum: ['single_choice', 'multiple_choice', 'rating', 'text'],
    name: 'question_type',
  })
  questionType: 'single_choice' | 'multiple_choice' | 'rating' | 'text';

  @Column({ type: 'jsonb', nullable: true })
  options: Record<string, any>;

  @Column({ type: 'boolean', default: true })
  required: boolean;

  @Column({ type: 'int', name: 'display_order' })
  displayOrder: number;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;
}
```

#### Step 2: Update DISC/Phase Entities

**File:** `financial-rise-app/backend/src/modules/algorithms/entities/disc-profile.entity.ts`

**Uncomment and fix:**
```typescript
// BEFORE:
// @ManyToOne(() => Assessment, { onDelete: 'CASCADE' })
// @JoinColumn({ name: 'assessment_id' })
// assessment: Assessment;

// AFTER:
@Column({ type: 'uuid', name: 'assessment_id' })
assessmentId: string;

@ManyToOne(() => Assessment, assessment => assessment.discProfiles, { onDelete: 'CASCADE' })
@JoinColumn({ name: 'assessment_id' })
assessment: Assessment;
```

**Same for:** `phase-result.entity.ts`

#### Step 3: Create Modules

**File:** `financial-rise-app/backend/src/modules/assessments/assessments.module.ts`

```typescript
@Module({
  imports: [
    TypeOrmModule.forFeature([Assessment, AssessmentResponse]),
  ],
  controllers: [AssessmentsController],
  providers: [AssessmentsService],
  exports: [AssessmentsService],
})
export class AssessmentsModule {}
```

**File:** `financial-rise-app/backend/src/modules/questions/questions.module.ts`

```typescript
@Module({
  imports: [TypeOrmModule.forFeature([Question])],
  controllers: [QuestionsController],
  providers: [QuestionsService],
  exports: [QuestionsService],
})
export class QuestionsModule {}
```

#### Step 4: Re-enable in App Module

**File:** `financial-rise-app/backend/src/app.module.ts`

```typescript
@Module({
  imports: [
    // ... existing modules
    AssessmentsModule, // UNCOMMENT
    QuestionsModule,   // UNCOMMENT
    // ... rest
  ],
})
export class AppModule {}
```

#### Step 5: Generate Migration for New Entities

```bash
npm run typeorm migration:generate -- -n AddAssessmentEntities
npm run typeorm migration:run
```

---

## Phase 2: Service Migration (HIGH PRIORITY)

### 2.1 Port Report Generation Service

**Priority:** 🟠 HIGH
**Owner:** Backend Agent 3

**Source Files:**
- `financial-rise-backend/src/services/ReportGenerationService.ts`
- `financial-rise-backend/src/services/ReportTemplateService.ts`

**Target Location:**
- `financial-rise-app/backend/src/modules/reports/`

**Key Changes Required:**
1. Convert to NestJS service (use `@Injectable()`)
2. Update S3 → Google Cloud Storage
3. Integrate with DISC/Phase calculators (already exist in NestJS)
4. Use TypeORM instead of Sequelize

**Steps:**

#### Step 1: Create Reports Module
```bash
cd financial-rise-app/backend
nest generate module reports
nest generate service reports
nest generate controller reports
```

#### Step 2: Port ReportTemplateService

**New File:** `src/modules/reports/services/report-template.service.ts`

**Key Adaptations:**
```typescript
@Injectable()
export class ReportTemplateService {
  constructor(
    @InjectRepository(Assessment)
    private assessmentRepo: Repository<Assessment>,
    private discCalculatorService: DiscCalculatorService,
    private phaseCalculatorService: PhaseCalculatorService,
  ) {}

  async generateConsultantReportHTML(assessmentId: string): Promise<string> {
    const assessment = await this.assessmentRepo.findOne({
      where: { id: assessmentId },
      relations: ['responses', 'discProfiles', 'phaseResults', 'consultant'],
    });

    // ... port template logic from Express
  }
}
```

#### Step 3: Port ReportGenerationService

**New File:** `src/modules/reports/services/report-generation.service.ts`

**Key Changes:**
- Replace S3 client with Google Cloud Storage
- Update bucket names
- Keep Puppeteer logic (works cross-platform)

**GCS Setup:**
```typescript
import { Storage } from '@google-cloud/storage';

@Injectable()
export class ReportGenerationService {
  private storage: Storage;
  private bucketName: string;

  constructor(
    private reportTemplateService: ReportTemplateService,
    private configService: ConfigService,
  ) {
    this.storage = new Storage({
      keyFilename: configService.get('GOOGLE_APPLICATION_CREDENTIALS'),
    });
    this.bucketName = configService.get('GCS_BUCKET_NAME');
  }

  async generatePDF(html: string): Promise<Buffer> {
    // Port Puppeteer logic from Express (unchanged)
  }

  async uploadToGCS(buffer: Buffer, filename: string): Promise<string> {
    const file = this.storage.bucket(this.bucketName).file(filename);

    await file.save(buffer, {
      metadata: {
        contentType: 'application/pdf',
      },
    });

    // Generate signed URL (expires in 8 hours)
    const [url] = await file.getSignedUrl({
      action: 'read',
      expires: Date.now() + 8 * 60 * 60 * 1000,
    });

    return url;
  }
}
```

#### Step 4: Create Reports Controller

**File:** `src/modules/reports/reports.controller.ts`

**Implement endpoints from API-CONTRACT.md:**
- `POST /reports/disc-profile`
- `POST /reports/phase-result`
- `POST /reports/generate/consultant`
- `POST /reports/generate/client`
- `GET /reports/status/:id`
- `GET /reports/download/:id`

---

### 2.2 Port Core Services

**Priority:** 🟠 HIGH
**Owner:** Backend Agent 1, Backend Agent 2

**Services to Port:**

#### questionnaireService.ts
- Move to: `src/modules/questions/questions.service.ts`
- Replace hardcoded questions with database queries
- Use TypeORM

#### progressService.ts
- Move to: `src/modules/assessments/services/progress.service.ts`
- Calculate progress based on answered questions
- Update Assessment entity

#### validationService.ts
- Move to: `src/modules/assessments/services/validation.service.ts`
- Validate responses against question schema
- Use class-validator

**Pattern for All:**
```typescript
@Injectable()
export class QuestionsService {
  constructor(
    @InjectRepository(Question)
    private questionRepo: Repository<Question>,
  ) {}

  async getAllQuestions(): Promise<Question[]> {
    return this.questionRepo.find({
      order: { displayOrder: 'ASC' },
    });
  }
}
```

---

## Phase 3: Testing & Integration

### 3.1 Write Integration Tests

**Priority:** 🟠 HIGH
**Owner:** QA Agent 1

**Test Suites Required:**
1. Auth flow (register → login → refresh → logout)
2. Assessment workflow (create → update → respond → complete)
3. DISC calculation (edge cases, insufficient data)
4. Phase calculation (transitions, thresholds)
5. Report generation (consultant, client, errors)

**Example:**
```typescript
// assessments.e2e-spec.ts
describe('Assessment Workflow (e2e)', () => {
  let app: INestApplication;
  let accessToken: string;

  beforeAll(async () => {
    // Setup test database, create test user
  });

  it('should create assessment', async () => {
    const response = await request(app.getHttpServer())
      .post('/api/v1/assessments')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({
        clientName: 'Test Client',
        businessName: 'Test Business',
        clientEmail: 'test@test.com',
      })
      .expect(201);

    expect(response.body.status).toBe('draft');
  });
});
```

---

### 3.2 Delete Placeholder Tests

**Priority:** 🟡 MEDIUM
**Owner:** QA Agent 1

**Action:** Delete all test files with only `TODO: Implement tests`

**Express Backend:**
```bash
cd financial-rise-backend

# Find placeholder tests
grep -r "TODO: Implement tests" src/__tests__/

# Delete empty placeholders (manual review first)
```

**Impact:** Improves honest test coverage metrics

---

## Phase 4: Deployment & Polish

### 4.1 Update Frontend API Client

**Priority:** 🟠 HIGH
**Owner:** Frontend Agents

**Steps:**

1. Create API client based on `API-CONTRACT.md`
2. Replace mock data with real API calls
3. Add error handling
4. Test all workflows

**File:** `financial-rise-frontend/src/services/api.ts`

```typescript
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:3000/api/v1';

export const api = {
  auth: {
    login: async (email: string, password: string) => {
      const response = await fetch(`${API_BASE_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      if (!response.ok) {
        throw await response.json();
      }

      return response.json();
    },
  },

  assessments: {
    list: async (params?: ListParams) => {
      const query = new URLSearchParams(params).toString();
      const response = await fetch(`${API_BASE_URL}/assessments?${query}`, {
        headers: {
          'Authorization': `Bearer ${getAccessToken()}`,
        },
      });

      return response.json();
    },
  },
};
```

---

### 4.2 Archive Express Backend

**Priority:** 🟢 LOW (only after NestJS feature-complete)
**Owner:** Project Lead

**Steps:**

1. Create `legacy/` folder in repository root
2. Move `financial-rise-backend/` → `legacy/financial-rise-backend/`
3. Add README explaining deprecation
4. Keep migrations for reference
5. Update CI/CD to ignore legacy folder

**README Template:**
```markdown
# Legacy Express Backend (DEPRECATED)

**Status:** Archived 2025-12-27
**Reason:** Consolidated to NestJS architecture

This code is kept for historical reference only. DO NOT use for new development.

See `NESTJS-CONSOLIDATION-PLAN.md` for migration details.
```

---

## Success Criteria

### Phase 1 Complete When:
- [ ] All TypeORM migrations generated and tested
- [ ] Database seeded with questions
- [ ] Security vulnerabilities fixed
- [ ] Assessment module re-enabled and working
- [ ] All NestJS modules uncommented and integrated

### Phase 2 Complete When:
- [ ] Report generation ported to NestJS
- [ ] All core services migrated
- [ ] GCS integration working
- [ ] APIs match contract specification

### Phase 3 Complete When:
- [ ] Integration tests passing
- [ ] 80%+ code coverage
- [ ] Placeholder tests deleted
- [ ] E2E tests covering critical paths

### Phase 4 Complete When:
- [ ] Frontend connected to NestJS backend
- [ ] All workflows tested end-to-end
- [ ] Express backend archived
- [ ] Documentation updated

---

## Risk Mitigation

### Risk: Database Migration Failures
**Mitigation:** Test on local database first, backup staging before migration

### Risk: Breaking API Changes
**Mitigation:** Follow API-CONTRACT.md exactly, version endpoints

### Risk: Report Generation Performance
**Mitigation:** Benchmark early, implement browser pooling if needed

### Risk: Frontend Blocked on Backend
**Mitigation:** Frontend uses mock data, continues development independently

---

## Immediate Next Actions

1. **Assign DevOps Agent** → Start Phase 1.1 (migrations)
2. **Assign Backend Agent 1** → Start Phase 1.2 (security fixes)
3. **Assign Frontend Agents** → Start mock data development (Phase 4.1 prep)
4. **Update Progress** → Agents update `TEAM-COORDINATION.md` after completing exceptional work

---

**Document Owner:** Project Manager
**Status:** Ready for Execution
**Last Updated:** 2025-12-27
