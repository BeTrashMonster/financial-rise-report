# Financial RISE - CI/CD Architecture Diagram

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          GITHUB REPOSITORY                              │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────┐    │
│  │  Source Code                                                   │    │
│  │  ├─ financial-rise-app/backend/     (NestJS API)             │    │
│  │  ├─ financial-rise-app/frontend/    (React App)              │    │
│  │  ├─ docker-compose.yml                                        │    │
│  │  └─ .github/workflows/deploy-gcp.yml                         │    │
│  └───────────────────────────────────────────────────────────────┘    │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────┐    │
│  │  GitHub Secrets (Encrypted)                                   │    │
│  │  ├─ GCP_PROJECT_ID                                            │    │
│  │  ├─ GCP_WORKLOAD_IDENTITY_PROVIDER                            │    │
│  │  ├─ GCP_SERVICE_ACCOUNT                                       │    │
│  │  ├─ GCP_REGION                                                │    │
│  │  ├─ ARTIFACT_REGISTRY_REPO                                    │    │
│  │  ├─ STAGING_VM_NAME                                           │    │
│  │  ├─ STAGING_VM_ZONE                                           │    │
│  │  ├─ PRODUCTION_VM_NAME                                        │    │
│  │  └─ PRODUCTION_VM_ZONE                                        │    │
│  └───────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ Push to main branch
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│                        GITHUB ACTIONS WORKFLOW                          │
│                                                                         │
│  Step 1: Test Backend                                                  │
│  ┌─────────────────────────────────────────────────────────────┐      │
│  │  • Lint code                                                 │      │
│  │  • Run unit tests with PostgreSQL                           │      │
│  │  • Generate coverage report                                 │      │
│  │  • Upload to Codecov                                        │      │
│  └─────────────────────────────────────────────────────────────┘      │
│                                                                         │
│  Step 2: Test Frontend                                                 │
│  ┌─────────────────────────────────────────────────────────────┐      │
│  │  • Lint code                                                 │      │
│  │  • Type check TypeScript                                    │      │
│  │  • Run tests                                                │      │
│  │  • Build production bundle                                  │      │
│  └─────────────────────────────────────────────────────────────┘      │
│                                                                         │
│                           ↓ (Tests Pass)                               │
│                                                                         │
│  Step 3: Build & Push Docker Images                                    │
│  ┌─────────────────────────────────────────────────────────────┐      │
│  │  1. Request OIDC Token from GitHub                          │      │
│  │         ↓                                                    │      │
│  │  2. Exchange for GCP credentials (Workload Identity)         │      │
│  │         ↓                                                    │      │
│  │  3. Authenticate to Artifact Registry                       │      │
│  │         ↓                                                    │      │
│  │  4. Build backend:commit-sha & backend:latest               │      │
│  │         ↓                                                    │      │
│  │  5. Build frontend:commit-sha & frontend:latest             │      │
│  │         ↓                                                    │      │
│  │  6. Push all images to Artifact Registry                    │      │
│  └─────────────────────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│                      GOOGLE CLOUD PLATFORM                              │
│                         (Project: financial-rise-prod)                  │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────┐      │
│  │  Workload Identity Federation                               │      │
│  │  ┌──────────────────────────────────────────────────┐       │      │
│  │  │  Pool: github-actions-pool                       │       │      │
│  │  │  Provider: github-provider                       │       │      │
│  │  │  ├─ Validates GitHub OIDC tokens                 │       │      │
│  │  │  ├─ Maps to service account                      │       │      │
│  │  │  └─ Issues short-lived credentials (1 hour)      │       │      │
│  │  └──────────────────────────────────────────────────┘       │      │
│  └─────────────────────────────────────────────────────────────┘      │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────┐      │
│  │  Service Account: github-actions@...                         │      │
│  │  Permissions:                                                │      │
│  │  ├─ roles/artifactregistry.writer                           │      │
│  │  ├─ roles/compute.admin                                     │      │
│  │  ├─ roles/storage.admin                                     │      │
│  │  ├─ roles/secretmanager.secretAccessor                      │      │
│  │  └─ roles/cloudsql.client                                   │      │
│  └─────────────────────────────────────────────────────────────┘      │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────┐      │
│  │  Artifact Registry (us-central1)                             │      │
│  │  Repository: financial-rise-docker                           │      │
│  │  ├─ backend:commit-sha (immutable)                          │      │
│  │  ├─ backend:latest (updated on each deploy)                 │      │
│  │  ├─ frontend:commit-sha (immutable)                         │      │
│  │  └─ frontend:latest (updated on each deploy)                │      │
│  └─────────────────────────────────────────────────────────────┘      │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────┐      │
│  │  Secret Manager                                              │      │
│  │  ├─ financial-rise-staging-env                              │      │
│  │  │   └─ All environment variables for staging              │      │
│  │  └─ financial-rise-production-env                           │      │
│  │      └─ All environment variables for production            │      │
│  └─────────────────────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    │                               │
                    ↓                               ↓
┌──────────────────────────────────┐  ┌──────────────────────────────────┐
│   STAGING ENVIRONMENT            │  │   PRODUCTION ENVIRONMENT         │
│   (us-central1-a)                │  │   (us-central1-a)                │
│                                  │  │   (Requires Manual Approval)     │
│  ┌────────────────────────────┐ │  │  ┌────────────────────────────┐  │
│  │  Compute Engine VM         │ │  │  │  Compute Engine VM         │  │
│  │  financial-rise-staging-vm │ │  │  │  financial-rise-production │  │
│  │  Type: e2-medium           │ │  │  │  Type: e2-standard-2       │  │
│  │  Static IP: XXX.XXX.XXX.XX │ │  │  │  Static IP: XXX.XXX.XXX.XX │  │
│  │                            │ │  │  │                            │  │
│  │  ┌──────────────────────┐  │ │  │  │  ┌──────────────────────┐  │  │
│  │  │  Docker Containers   │  │ │  │  │  │  Docker Containers   │  │  │
│  │  │  ├─ Backend (NestJS) │  │ │  │  │  │  ├─ Backend (NestJS) │  │  │
│  │  │  ├─ Frontend (React) │  │ │  │  │  │  ├─ Frontend (React) │  │  │
│  │  │  └─ Redis            │  │ │  │  │  │  └─ Redis            │  │  │
│  │  └──────────────────────┘  │ │  │  │  └──────────────────────┘  │  │
│  └────────────────────────────┘ │  │  └────────────────────────────┘  │
│                                  │  │                                  │
│  ┌────────────────────────────┐ │  │  ┌────────────────────────────┐  │
│  │  Cloud SQL PostgreSQL      │ │  │  │  Cloud SQL PostgreSQL      │  │
│  │  financial-rise-staging    │ │  │  │  financial-rise-production │  │
│  │  Version: 14               │ │  │  │  Version: 14               │  │
│  │  Private IP: 10.x.x.x      │ │  │  │  Private IP: 10.x.x.x      │  │
│  │  Daily Backups Enabled     │ │  │  │  Daily Backups Enabled     │  │
│  └────────────────────────────┘ │  │  └────────────────────────────┘  │
│                                  │  │                                  │
│  ┌────────────────────────────┐ │  │  ┌────────────────────────────┐  │
│  │  Cloud Storage             │ │  │  │  Cloud Storage             │  │
│  │  financial-rise-reports    │ │  │  │  financial-rise-reports    │  │
│  │  (PDF reports storage)     │ │  │  │  (PDF reports storage)     │  │
│  └────────────────────────────┘ │  │  └────────────────────────────┘  │
│                                  │  │                                  │
│  Deployment Process:             │  │  Deployment Process:             │
│  1. Copy docker-compose files   │  │  1. Create database backup       │
│  2. Pull env from Secret Manager│  │  2. Upload backup to GCS         │
│  3. Pull Docker images          │  │  3. Copy docker-compose files    │
│  4. Run database migrations     │  │  4. Pull env from Secret Manager │
│  5. Restart containers          │  │  5. Pull Docker images           │
│  6. Health check                │  │  6. Run database migrations      │
│  7. Auto-rollback on failure    │  │  7. Rolling restart (backend)    │
│                                  │  │  8. Rolling restart (frontend)   │
│                                  │  │  9. Health check                 │
│                                  │  │ 10. Auto-rollback on failure     │
└──────────────────────────────────┘  └──────────────────────────────────┘
```

## Data Flow

### Build & Deploy Flow

```
Developer
    ↓
Git Push to main
    ↓
GitHub Actions Triggered
    ↓
┌─────────────────────┐
│  Run Tests          │
│  (Backend+Frontend) │
└─────────────────────┘
    ↓ (Pass)
┌─────────────────────────────────────────┐
│  Authenticate to GCP                    │
│  (Workload Identity Federation)         │
│  ┌───────────────────────────────────┐  │
│  │ 1. Request OIDC token from GitHub │  │
│  │ 2. Send to GCP WIF Provider       │  │
│  │ 3. Validate token claims          │  │
│  │ 4. Issue GCP credentials          │  │
│  │ 5. Credentials valid for 1 hour   │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
    ↓
┌─────────────────────┐
│  Build Docker Images│
│  ├─ Backend         │
│  └─ Frontend        │
└─────────────────────┘
    ↓
┌─────────────────────┐
│  Push to Artifact   │
│  Registry           │
│  ├─ commit-sha tags │
│  └─ latest tags     │
└─────────────────────┘
    ↓
┌─────────────────────────────────────┐
│  Deploy to Staging                  │
│  ├─ SSH to staging VM               │
│  ├─ Copy docker-compose files       │
│  ├─ Pull env vars from Secret Mgr   │
│  ├─ Pull Docker images               │
│  ├─ Run migrations                  │
│  ├─ Restart containers              │
│  └─ Health check                    │
└─────────────────────────────────────┘
    ↓ (Success)
┌─────────────────────────────────────┐
│  WAIT FOR MANUAL APPROVAL           │
│  (GitHub Environment Protection)    │
└─────────────────────────────────────┘
    ↓ (Approved)
┌─────────────────────────────────────┐
│  Deploy to Production               │
│  ├─ Create DB backup                │
│  ├─ SSH to production VM            │
│  ├─ Copy docker-compose files       │
│  ├─ Pull env vars from Secret Mgr   │
│  ├─ Pull Docker images               │
│  ├─ Run migrations                  │
│  ├─ Rolling restart (zero downtime) │
│  └─ Health check                    │
└─────────────────────────────────────┘
    ↓
✅ Deployment Complete
```

### User Request Flow (Runtime)

```
User Browser
    ↓
HTTPS Request
    ↓
GCP Load Balancer / Static IP
    ↓
Compute Engine VM
    ↓
┌─────────────────────────────────────┐
│  Docker Containers                  │
│                                     │
│  Frontend (React)                   │
│      ↓                              │
│      │ API Request                  │
│      ↓                              │
│  Backend (NestJS)                   │
│      ├─ Authentication (JWT)        │
│      ├─ Business Logic              │
│      ├─ Database Queries            │
│      └─ PDF Generation              │
└─────────────────────────────────────┘
    │                   │
    │                   ↓
    │          Cloud SQL PostgreSQL
    │          (User data, assessments,
    │           results, settings)
    │
    ↓
Cloud Storage (GCS)
(Generated PDF reports)
```

## Network Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  VPC Network: financial-rise-vpc                            │
│  Region: us-central1                                        │
│  Subnet: financial-rise-subnet (10.0.0.0/24)                │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Firewall Rules                                     │   │
│  │  ├─ allow-ssh (port 22)                             │   │
│  │  ├─ allow-http (port 80)                            │   │
│  │  ├─ allow-https (port 443)                          │   │
│  │  ├─ allow-backend-api (port 4000)                   │   │
│  │  └─ allow-frontend (port 3000)                      │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  Resources in VPC:                                          │
│  ├─ financial-rise-staging-vm (10.0.0.2)                   │
│  ├─ financial-rise-production-vm (10.0.0.3)                │
│  ├─ Cloud SQL staging (10.x.x.x - private IP)             │
│  └─ Cloud SQL production (10.x.x.x - private IP)          │
│                                                             │
│  External IPs (Static):                                     │
│  ├─ financial-rise-staging-ip                              │
│  └─ financial-rise-production-ip                           │
└─────────────────────────────────────────────────────────────┘
```

## Security Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Authentication & Authorization                             │
│                                                             │
│  GitHub Actions                                             │
│      ↓                                                      │
│  OIDC Token (No keys, no passwords)                         │
│      ↓                                                      │
│  Workload Identity Federation                               │
│      ├─ Validates repository                                │
│      ├─ Validates branch                                    │
│      └─ Validates workflow                                  │
│      ↓                                                      │
│  Service Account (github-actions@...)                       │
│      └─ Minimal required permissions only                   │
│      ↓                                                      │
│  GCP Resources (time-limited access)                        │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  Secrets Management                                          │
│                                                             │
│  Application Secrets                                         │
│      ↓                                                      │
│  GCP Secret Manager                                          │
│      ├─ financial-rise-staging-env                          │
│      └─ financial-rise-production-env                       │
│      ↓                                                      │
│  Pulled at deployment time only                             │
│      ↓                                                      │
│  Never stored on VM disk                                    │
│      ↓                                                      │
│  Loaded as environment variables in containers              │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  Data Protection                                             │
│                                                             │
│  User Data → PostgreSQL (Cloud SQL)                         │
│              ├─ Encrypted at rest                           │
│              ├─ Encrypted in transit (SSL)                  │
│              ├─ Private IP only (no public access)          │
│              └─ Automated daily backups (7-day retention)   │
│                                                             │
│  PDF Reports → Cloud Storage (GCS)                          │
│               ├─ Encrypted at rest                          │
│               ├─ Secure signed URLs for access              │
│               └─ Lifecycle policies for data retention      │
└─────────────────────────────────────────────────────────────┘
```

## Deployment Timeline

```
0:00 - Developer pushes to main
       │
0:01 - GitHub Actions triggered
       │
0:02 - Backend tests start (parallel)
0:02 - Frontend tests start (parallel)
       │
0:05 - Tests complete (pass)
       │
0:06 - Workload Identity auth
0:07 - Backend Docker build
0:08 - Frontend Docker build
       │
0:10 - Push images to Artifact Registry
       │
0:11 - Deploy to staging starts
       ├─ Copy files
       ├─ Pull images
       ├─ Run migrations
       └─ Restart containers
       │
0:13 - Staging health check
       │
0:14 - ⏸️  WAIT FOR MANUAL APPROVAL
       │
       │ (Reviewer approves)
       │
0:XX - Production deployment starts
       ├─ Database backup
       ├─ Copy files
       ├─ Pull images
       ├─ Run migrations
       └─ Rolling restart
       │
0:XX - Production health check
       │
0:XX - ✅ Deployment complete
```

## Monitoring & Observability

```
┌─────────────────────────────────────────────────────────────┐
│  GCP Cloud Monitoring                                        │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  VM Metrics                                         │   │
│  │  ├─ CPU utilization                                 │   │
│  │  ├─ Memory usage                                    │   │
│  │  ├─ Disk I/O                                        │   │
│  │  └─ Network traffic                                 │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Application Metrics                                │   │
│  │  ├─ HTTP request rates                              │   │
│  │  ├─ Response times                                  │   │
│  │  ├─ Error rates                                     │   │
│  │  └─ Database query performance                      │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Cloud SQL Metrics                                  │   │
│  │  ├─ Connection count                                │   │
│  │  ├─ Query execution time                            │   │
│  │  ├─ Database size                                   │   │
│  │  └─ Replication lag                                 │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Uptime Checks                                      │   │
│  │  ├─ Staging health endpoint (every 1 min)           │   │
│  │  └─ Production health endpoint (every 1 min)        │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Alerting Policies                                  │   │
│  │  ├─ High error rate → Email + Slack                 │   │
│  │  ├─ Service down → PagerDuty                        │   │
│  │  ├─ High CPU → Email                                │   │
│  │  └─ Disk full → Email                               │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  GCP Cloud Logging                                           │
│                                                             │
│  Application Logs                                            │
│  ├─ Backend API logs                                        │
│  ├─ Frontend access logs                                    │
│  └─ Error stack traces                                     │
│                                                             │
│  Infrastructure Logs                                         │
│  ├─ VM system logs                                          │
│  ├─ Cloud SQL logs                                          │
│  ├─ Load balancer logs                                      │
│  └─ Firewall logs                                           │
│                                                             │
│  Audit Logs                                                  │
│  ├─ IAM permission changes                                  │
│  ├─ Resource modifications                                  │
│  └─ Authentication attempts                                 │
└─────────────────────────────────────────────────────────────┘
```

## High Availability Setup (Future Enhancement)

```
┌─────────────────────────────────────────────────────────────┐
│  Multi-Zone Deployment (Optional)                           │
│                                                             │
│  Cloud Load Balancer                                         │
│         │                                                   │
│         ├─────────────┬──────────────┐                      │
│         ↓             ↓              ↓                      │
│    VM Zone A      VM Zone B      VM Zone C                 │
│    (Primary)      (Standby)      (Standby)                 │
│                                                             │
│  Cloud SQL High Availability                                 │
│         ├─ Primary instance (zone A)                        │
│         ├─ Standby instance (zone B)                        │
│         └─ Automatic failover                               │
│                                                             │
│  Read Replicas (Optional)                                   │
│         └─ Distribute read traffic across zones             │
└─────────────────────────────────────────────────────────────┘
```

---

**Legend:**
- `→` Sequential flow
- `├─` Hierarchical relationship
- `↓` Process flow
- `⏸️` Manual intervention required
- `✅` Success state

**Notes:**
- All communication between services uses private IPs within VPC
- External access only through static IPs with firewall rules
- Secrets never committed to git or stored in plain text
- Automatic backups run daily at 2 AM UTC
- Health checks run every 30 seconds during deployment

