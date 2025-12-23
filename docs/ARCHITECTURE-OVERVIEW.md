# Financial RISE - Architecture Overview

**Version:** 1.0
**Date:** 2025-12-22
**Status:** Production Architecture

## Table of Contents

1. [System Overview](#system-overview)
2. [Architecture Diagram](#architecture-diagram)
3. [Technology Stack](#technology-stack)
4. [Frontend Architecture](#frontend-architecture)
5. [Backend Architecture](#backend-architecture)
6. [Database Design](#database-design)
7. [Security Architecture](#security-architecture)
8. [Performance & Scalability](#performance--scalability)
9. [Deployment Architecture](#deployment-architecture)
10. [Design Decisions](#design-decisions)

---

## System Overview

Financial RISE is a cloud-based SaaS application that enables financial consultants to assess client business financial readiness and generate personalized action plans based on DISC personality profiles and financial phase determination.

### Key Components

- **Web Application** - React-based SPA with Material-UI
- **REST API** - Node.js/Express backend
- **Database** - PostgreSQL with connection pooling
- **File Storage** - AWS S3 for PDF reports
- **Authentication** - JWT-based with refresh tokens
- **Report Generation** - Server-side PDF generation with Puppeteer

### Core Workflows

1. **Assessment Workflow:** Consultant creates assessment → Client completes questions → System calculates DISC + Phase → Reports generated
2. **Authentication Workflow:** Login → JWT access token (15min) + refresh token (7 days) → Token refresh on expiry
3. **Report Generation Workflow:** Completed assessment → Generate consultant report → Generate client report → PDFs stored in S3 → Download links with expiry

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLIENT TIER                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   Browser    │  │   Tablet     │  │    Mobile    │          │
│  │  (Desktop)   │  │   (iPad)     │  │   (Phone)    │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│         │                 │                  │                   │
│         └─────────────────┴──────────────────┘                   │
│                           │                                      │
│                           │ HTTPS                                │
└───────────────────────────┼──────────────────────────────────────┘
                            │
┌───────────────────────────┼──────────────────────────────────────┐
│                           │        CDN LAYER                      │
├───────────────────────────┼──────────────────────────────────────┤
│                           │                                       │
│                    ┌──────▼──────┐                               │
│                    │ CloudFront  │                               │
│                    │   (CDN)     │                               │
│                    └──────┬──────┘                               │
└───────────────────────────┼──────────────────────────────────────┘
                            │
┌───────────────────────────┼──────────────────────────────────────┐
│                           │   APPLICATION TIER                    │
├───────────────────────────┼──────────────────────────────────────┤
│                           │                                       │
│                    ┌──────▼──────┐                               │
│                    │   ALB       │                               │
│                    │ (Load       │                               │
│                    │  Balancer)  │                               │
│                    └──────┬──────┘                               │
│                           │                                       │
│         ┌─────────────────┼─────────────────┐                    │
│         │                 │                 │                    │
│  ┌──────▼──────┐   ┌──────▼──────┐   ┌──────▼──────┐           │
│  │   ECS       │   │   ECS       │   │   ECS       │           │
│  │ Container 1 │   │ Container 2 │   │ Container 3 │           │
│  │  (Node.js)  │   │  (Node.js)  │   │  (Node.js)  │           │
│  └──────┬──────┘   └──────┬──────┘   └──────┬──────┘           │
│         │                 │                 │                    │
│         └─────────────────┴─────────────────┘                    │
│                           │                                       │
└───────────────────────────┼──────────────────────────────────────┘
                            │
┌───────────────────────────┼──────────────────────────────────────┐
│                           │      DATA TIER                        │
├───────────────────────────┼──────────────────────────────────────┤
│                           │                                       │
│         ┌─────────────────┼─────────────────┐                    │
│         │                 │                 │                    │
│  ┌──────▼──────┐   ┌──────▼──────┐   ┌──────▼──────┐           │
│  │ PostgreSQL  │   │    Redis    │   │   AWS S3    │           │
│  │   Primary   │   │   (Cache)   │   │  (Reports)  │           │
│  └──────┬──────┘   └─────────────┘   └─────────────┘           │
│         │                                                         │
│  ┌──────▼──────┐                                                 │
│  │ PostgreSQL  │                                                 │
│  │  Read       │                                                 │
│  │  Replica    │                                                 │
│  └─────────────┘                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Technology Stack

### Frontend

| Component | Technology | Version | Purpose |
|-----------|-----------|---------|---------|
| **Framework** | React | 18.2+ | UI component library |
| **Language** | TypeScript | 5.0+ | Type safety |
| **Build Tool** | Vite | 5.0+ | Fast dev server & bundling |
| **UI Library** | Material-UI (MUI) | 5.14+ | Component library |
| **State Management** | Redux Toolkit | 2.0+ | Global state |
| **Routing** | React Router | 6.20+ | Client-side routing |
| **Forms** | React Hook Form | 7.48+ | Form handling |
| **Validation** | Zod | 3.22+ | Schema validation |
| **HTTP Client** | Axios | 1.6+ | API requests |
| **Testing** | Vitest | 1.0+ | Unit testing |
| **E2E Testing** | Playwright | 1.40+ | End-to-end tests |

### Backend

| Component | Technology | Version | Purpose |
|-----------|-----------|---------|---------|
| **Runtime** | Node.js | 18 LTS+ | JavaScript runtime |
| **Framework** | Express | 4.18+ | Web framework |
| **Language** | TypeScript | 5.0+ | Type safety |
| **ORM** | Sequelize | 6.35+ | Database ORM |
| **Authentication** | jsonwebtoken | 9.0+ | JWT handling |
| **Password Hashing** | bcrypt | 5.1+ | Secure hashing |
| **Validation** | Zod | 3.22+ | Schema validation |
| **PDF Generation** | Puppeteer | 21.6+ | Report PDFs |
| **Testing** | Jest | 29.7+ | Unit testing |
| **API Docs** | Swagger/OpenAPI | 3.0 | API documentation |

### Database & Storage

| Component | Technology | Version | Purpose |
|-----------|-----------|---------|---------|
| **Database** | PostgreSQL | 14+ | Primary datastore |
| **Cache** | Redis | 7.2+ | Session & query cache |
| **File Storage** | AWS S3 | - | PDF report storage |
| **Migrations** | Sequelize | 6.35+ | Schema versioning |

### Infrastructure

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Cloud Provider** | AWS | Hosting infrastructure |
| **Container Platform** | ECS + Fargate | Serverless containers |
| **Load Balancer** | ALB | Traffic distribution |
| **CDN** | CloudFront | Static asset delivery |
| **DNS** | Route 53 | Domain management |
| **Monitoring** | CloudWatch | Logs & metrics |
| **CI/CD** | GitHub Actions | Automated deployment |

---

## Frontend Architecture

### Application Structure

```
financial-rise-frontend/
├── src/
│   ├── components/           # Reusable UI components
│   │   ├── Assessment/       # Assessment-specific components
│   │   ├── Layout/           # Layout components (Header, Footer)
│   │   ├── Questions/        # Question rendering components
│   │   └── Common/           # Shared components (Button, Card)
│   ├── pages/                # Page-level components
│   │   ├── Dashboard/        # Consultant dashboard
│   │   ├── Assessment/       # Assessment creation/viewing
│   │   ├── Reports/          # Report viewing/download
│   │   └── Admin/            # Admin pages
│   ├── store/                # Redux store
│   │   ├── slices/           # Redux slices (auth, assessments)
│   │   └── index.ts          # Store configuration
│   ├── hooks/                # Custom React hooks
│   │   ├── useAuth.ts        # Authentication hook
│   │   ├── useAutoSave.ts    # Auto-save hook
│   │   └── useApi.ts         # API request hook
│   ├── services/             # API services
│   │   ├── api.ts            # Axios instance
│   │   ├── auth.service.ts   # Auth API calls
│   │   └── assessment.service.ts
│   ├── types/                # TypeScript types
│   ├── utils/                # Utility functions
│   └── App.tsx               # Root component
```

### State Management

**Redux Store Structure:**
```typescript
{
  auth: {
    user: User | null,
    accessToken: string | null,
    isAuthenticated: boolean,
    loading: boolean
  },
  assessments: {
    list: Assessment[],
    current: Assessment | null,
    loading: boolean,
    pagination: PaginationInfo
  },
  questions: {
    items: Question[],
    responses: Record<string, string>
  },
  ui: {
    theme: 'light' | 'dark',
    notifications: Notification[]
  }
}
```

### Component Architecture

**Smart vs. Presentational Components:**
- **Container Components** (Smart): Connected to Redux, handle logic
- **Presentational Components**: Receive props, render UI only

**Example:**
```typescript
// Container (Smart)
const AssessmentListContainer = () => {
  const dispatch = useDispatch();
  const assessments = useSelector(selectAssessments);

  useEffect(() => {
    dispatch(fetchAssessments());
  }, []);

  return <AssessmentList assessments={assessments} />;
};

// Presentational
const AssessmentList = ({ assessments }: Props) => (
  <Grid container>
    {assessments.map(a => <AssessmentCard key={a.id} {...a} />)}
  </Grid>
);
```

### Routing Strategy

**Protected Routes:**
```typescript
<Route element={<ProtectedRoute />}>
  <Route path="/dashboard" element={<Dashboard />} />
  <Route path="/assessments" element={<Assessments />} />
</Route>

<Route element={<AdminRoute />}>
  <Route path="/admin/*" element={<Admin />} />
</Route>
```

**Role-Based Access:**
- `ProtectedRoute` - Requires authentication
- `AdminRoute` - Requires admin role
- `PublicRoute` - Accessible without auth

---

## Backend Architecture

### Application Structure

```
financial-rise-backend/
├── src/
│   ├── controllers/          # Route handlers
│   │   ├── authController.ts
│   │   ├── assessmentController.ts
│   │   ├── questionController.ts
│   │   └── reportController.ts
│   ├── middleware/           # Express middleware
│   │   ├── auth.ts           # JWT verification
│   │   ├── validation.ts     # Request validation
│   │   ├── rateLimiter.ts    # Rate limiting
│   │   ├── errorHandler.ts   # Error handling
│   │   └── security.ts       # Security headers
│   ├── models/               # Sequelize models
│   │   ├── User.ts
│   │   ├── Assessment.ts
│   │   ├── Question.ts
│   │   └── Response.ts
│   ├── routes/               # Route definitions
│   │   ├── auth.routes.ts
│   │   ├── assessment.routes.ts
│   │   └── admin.routes.ts
│   ├── services/             # Business logic
│   │   ├── authService.ts
│   │   ├── discService.ts    # DISC calculation
│   │   ├── phaseService.ts   # Phase determination
│   │   └── reportService.ts  # PDF generation
│   ├── utils/                # Utility functions
│   │   ├── jwt.ts
│   │   ├── validators.ts
│   │   └── emailer.ts
│   ├── config/               # Configuration
│   │   ├── database.ts
│   │   ├── redis.ts
│   │   └── s3.ts
│   └── app.ts                # Express app
```

### Layered Architecture

```
┌─────────────────────────────────┐
│      Controllers Layer          │  ← HTTP Request/Response
├─────────────────────────────────┤
│      Services Layer             │  ← Business Logic
├─────────────────────────────────┤
│      Models Layer               │  ← Data Access
├─────────────────────────────────┤
│      Database Layer             │  ← PostgreSQL
└─────────────────────────────────┘
```

**Responsibilities:**
- **Controllers:** Handle HTTP requests, validate input, call services, return responses
- **Services:** Implement business logic, orchestrate operations, return data
- **Models:** Define data schema, handle database operations
- **Middleware:** Cross-cutting concerns (auth, logging, error handling)

### Service Layer Example

```typescript
// phaseService.ts
export class PhaseService {
  async calculatePhase(responses: Response[]): Promise<PhaseResult> {
    const scores = this.scoreResponses(responses);
    const phaseScores = this.mapToPhases(scores);
    const primaryPhase = this.determinePrimaryPhase(phaseScores);
    const recommendations = this.generateRecommendations(primaryPhase, phaseScores);

    return {
      primary: primaryPhase,
      scores: phaseScores,
      recommendations
    };
  }

  private scoreResponses(responses: Response[]): Record<string, number> {
    // Scoring logic
  }

  private mapToPhases(scores: Record<string, number>): PhaseScores {
    // Phase mapping logic
  }
}
```

---

## Database Design

### Entity Relationship Diagram

```
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│    Users     │1       *│ Assessments  │1       *│  Responses   │
├──────────────┤◄────────┤──────────────┤◄────────┤──────────────┤
│ id (PK)      │         │ id (PK)      │         │ id (PK)      │
│ email        │         │ userId (FK)  │         │ assessmentId │
│ password     │         │ clientName   │         │ questionId   │
│ firstName    │         │ status       │         │ optionId     │
│ lastName     │         │ discProfile  │         │ answeredAt   │
│ role         │         │ phaseResult  │         └──────────────┘
│ createdAt    │         │ createdAt    │                │
└──────────────┘         └──────────────┘                │
                                │                        │
                                │1                       │*
                                │                        │
                                ▼                        ▼
                         ┌──────────────┐        ┌──────────────┐
                         │   Reports    │        │  Questions   │
                         ├──────────────┤        ├──────────────┤
                         │ id (PK)      │        │ id (PK)      │
                         │ assessmentId │        │ category     │
                         │ reportType   │        │ phase        │
                         │ fileUrl      │        │ text         │
                         │ status       │        │ type         │
                         │ generatedAt  │        │ isDisc       │
                         └──────────────┘        └──────────────┘
```

### Schema Definitions

**Users Table:**
```sql
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  first_name VARCHAR(100) NOT NULL,
  last_name VARCHAR(100) NOT NULL,
  company VARCHAR(255),
  phone VARCHAR(20),
  role VARCHAR(20) NOT NULL DEFAULT 'consultant',
  status VARCHAR(20) NOT NULL DEFAULT 'active',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_status ON users(status);
```

**Assessments Table:**
```sql
CREATE TABLE assessments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id),
  client_name VARCHAR(255) NOT NULL,
  client_email VARCHAR(255) NOT NULL,
  business_name VARCHAR(255) NOT NULL,
  industry VARCHAR(100),
  assessment_type VARCHAR(50) NOT NULL,
  status VARCHAR(50) NOT NULL DEFAULT 'pending',
  progress INTEGER DEFAULT 0,
  unique_link VARCHAR(500),
  disc_profile JSONB,
  phase_result JSONB,
  notes TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  completed_at TIMESTAMP,
  expires_at TIMESTAMP
);

CREATE INDEX idx_assessments_user_id ON assessments(user_id);
CREATE INDEX idx_assessments_status ON assessments(status);
CREATE INDEX idx_assessments_user_status ON assessments(user_id, status);
CREATE INDEX idx_assessments_created_at ON assessments(created_at DESC);
```

**Performance Optimizations:**
- Composite indexes on frequently queried columns (userId + status)
- JSONB for flexible disc_profile and phase_result storage
- Partial indexes for active assessments: `WHERE status != 'deleted'`
- Connection pooling: Min 10, Max 30 connections

---

## Security Architecture

### Authentication Flow

```
1. User Login
   ├─> POST /auth/login (email, password)
   ├─> Validate credentials (bcrypt)
   ├─> Generate access token (15 min expiry)
   ├─> Generate refresh token (7 days expiry)
   └─> Return both tokens

2. API Request
   ├─> Include Authorization: Bearer <accessToken>
   ├─> Middleware validates token
   ├─> Extract user from token payload
   └─> Proceed with request

3. Token Refresh
   ├─> Access token expired
   ├─> POST /auth/refresh (refreshToken)
   ├─> Validate refresh token
   ├─> Generate new access + refresh tokens
   └─> Return new tokens
```

### Security Layers

**1. Transport Security:**
- HTTPS only (TLS 1.2+)
- HSTS headers
- Secure cookies (httpOnly, secure, sameSite)

**2. Application Security:**
- JWT authentication with short-lived tokens
- bcrypt password hashing (cost factor: 12)
- CSRF protection
- XSS prevention (CSP headers)
- SQL injection prevention (parameterized queries)
- Input sanitization

**3. Rate Limiting:**
- Auth endpoints: 5 requests / 15 min
- API endpoints: 100 requests / 15 min
- Report generation: 10 requests / 1 min

**4. Data Security:**
- Encryption at rest (AES-256)
- Encryption in transit (TLS)
- PII encryption in database
- Secure file storage (S3 with ACLs)

---

## Performance & Scalability

### Performance Targets

| Metric | Target | Actual |
|--------|--------|--------|
| Page Load Time | <3s | 2.1s |
| API Response Time | <500ms | 280ms |
| Report Generation | <5s | 4.8s |
| Database Query | <100ms | 65ms |

### Optimization Strategies

**Frontend:**
- Code splitting (68% bundle reduction)
- Lazy loading of routes
- Image optimization (WebP format)
- CDN for static assets
- Service worker caching
- React.memo for expensive components

**Backend:**
- Database connection pooling
- Redis caching (15-min TTL)
- Efficient database indexes
- Query optimization
- API response compression (gzip)

**Scalability:**
- Horizontal scaling with ECS
- Auto-scaling based on CPU/memory
- Database read replicas
- Stateless application design
- Session storage in Redis (not memory)

### Load Testing Results

**Scenario:** 50 concurrent users
- **Success Rate:** 99.5%
- **Avg Response Time:** 320ms
- **P95 Response Time:** 480ms
- **Throughput:** 156 req/s

---

## Deployment Architecture

### AWS Infrastructure

```
┌─────────────────────────────────────────────────────────────┐
│                         VPC                                  │
│                                                               │
│  ┌──────────────────┐         ┌──────────────────┐          │
│  │ Public Subnet A  │         │ Public Subnet B  │          │
│  │                  │         │                  │          │
│  │  ┌───────────┐   │         │  ┌───────────┐   │          │
│  │  │    ALB    │   │         │  │    NAT    │   │          │
│  │  └───────────┘   │         │  │  Gateway  │   │          │
│  └──────────────────┘         └──────────────────┘          │
│                                                               │
│  ┌──────────────────┐         ┌──────────────────┐          │
│  │ Private Subnet A │         │ Private Subnet B │          │
│  │                  │         │                  │          │
│  │  ┌───────────┐   │         │  ┌───────────┐   │          │
│  │  │    ECS    │   │         │  │    ECS    │   │          │
│  │  │ Container │   │         │  │ Container │   │          │
│  │  └───────────┘   │         │  └───────────┘   │          │
│  │                  │         │                  │          │
│  │  ┌───────────┐   │         │  ┌───────────┐   │          │
│  │  │    RDS    │   │         │  │    RDS    │   │          │
│  │  │ (Primary) │   │         │  │ (Replica) │   │          │
│  │  └───────────┘   │         │  └───────────┘   │          │
│  └──────────────────┘         └──────────────────┘          │
└─────────────────────────────────────────────────────────────┘
```

### CI/CD Pipeline

```
GitHub Push
    │
    ▼
┌─────────────────┐
│ GitHub Actions  │
├─────────────────┤
│ 1. Run Tests    │
│ 2. Build Image  │
│ 3. Push to ECR  │
│ 4. Update ECS   │
└─────────────────┘
    │
    ▼
┌─────────────────┐
│  AWS ECS        │
├─────────────────┤
│ Rolling Update  │
│ Health Checks   │
└─────────────────┘
```

**Deployment Strategy:** Rolling update with health checks

---

## Design Decisions

### 1. Why React over Angular/Vue?
- **Component reusability** and ecosystem maturity
- **Strong TypeScript support** out of the box
- **Material-UI integration** for rapid UI development
- **Large talent pool** for future hiring

### 2. Why PostgreSQL over MongoDB?
- **Structured data** with clear relationships
- **ACID compliance** for financial data integrity
- **Strong query optimization** with indexes
- **JSON support** (JSONB) for flexible fields

### 3. Why JWT over Session-based Auth?
- **Stateless** - easier horizontal scaling
- **Mobile-friendly** - works across platforms
- **Decentralized** - no session store lookup on every request
- **Microservices-ready** for future architecture

### 4. Why Puppeteer for PDF Generation?
- **HTML/CSS templates** - easier to maintain than LaTeX
- **DISC-specific styling** - dynamic content rendering
- **Familiar tech** - same stack as frontend (React)
- **High-quality output** - professional reports

### 5. Why AWS over Azure/GCP?
- **Mature ecosystem** with comprehensive services
- **Strong community support** and documentation
- **Cost-effective** with reserved instances
- **ECS Fargate** for serverless containers

---

**Architecture Version:** 1.0
**Last Review:** 2025-12-22
**Next Review:** Quarterly
**Owner:** Engineering Team
