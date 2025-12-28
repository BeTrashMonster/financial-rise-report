# Financial RISE - Deployment Guide

**Version:** 2.0.0
**Last Updated:** 2025-12-28

## Overview

This guide covers deploying the Financial RISE Report application to Google Cloud Platform (GCP) using Docker, GCP Secret Manager, and GitHub Actions.

**SECURITY:** All secrets are managed via GCP Secret Manager (Work Stream 51 - CRIT-001). NO secrets should ever be committed to version control.

## Prerequisites

### Local Development
- Node.js 18 LTS or higher
- Docker and Docker Compose
- PostgreSQL 14+ (or use Docker)
- Git

### GCP Deployment
- GCP Account with appropriate permissions
- GCP CLI (gcloud) installed and configured
- Service account with Secret Manager permissions
- Docker and Docker Compose
- GitHub repository with secrets configured

## Local Development Setup

### 1. Clone and Install

```bash
# Clone repository
git clone <repository-url>
cd financial-rise-app

# SECURITY: Never commit .env files to version control!
# Copy environment template
cp backend/.env.example backend/.env.local

# Generate secure secrets (minimum 64 characters for production)
cd backend
node -e "console.log('JWT_SECRET=' + require('crypto').randomBytes(32).toString('hex'))" >> .env.local
node -e "console.log('REFRESH_TOKEN_SECRET=' + require('crypto').randomBytes(32).toString('hex'))" >> .env.local

# Edit .env.local with your local configuration
nano .env.local
```

### 2. Start with Docker Compose

```bash
# Start all services (backend, frontend, database, redis)
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### 3. Manual Setup (without Docker)

**Backend:**
```bash
cd backend
npm install
npm run migration:run
npm run seed
npm run start:dev
```

**Frontend:**
```bash
cd frontend
npm install
npm start
```

**Database:**
```bash
# Install PostgreSQL 14
# Create database
createdb financial_rise_db

# Run migrations
cd backend
npm run migration:run
```

## GCP Secret Manager Setup (Work Stream 51 - CRIT-001)

### CRITICAL SECURITY REQUIREMENT

ALL production secrets MUST be stored in GCP Secret Manager. This section implements Work Stream 51 security requirements.

### 1. Enable Secret Manager API

```bash
# Set your GCP project
export GCP_PROJECT_ID="your-project-id"
gcloud config set project $GCP_PROJECT_ID

# Enable Secret Manager API
gcloud services enable secretmanager.googleapis.com
```

### 2. Generate Cryptographically Secure Secrets

```bash
# Generate JWT_SECRET (64 characters = 32 bytes hex)
JWT_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
echo "JWT_SECRET: $JWT_SECRET"

# Generate REFRESH_TOKEN_SECRET (64 characters)
REFRESH_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
echo "REFRESH_TOKEN_SECRET: $REFRESH_SECRET"

# Generate DB_ENCRYPTION_KEY (64 characters)
DB_ENCRYPTION_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
echo "DB_ENCRYPTION_KEY: $DB_ENCRYPTION_KEY"

# Generate DATABASE_PASSWORD (32 characters minimum)
DB_PASSWORD=$(node -e "console.log(require('crypto').randomBytes(16).toString('hex'))")
echo "DATABASE_PASSWORD: $DB_PASSWORD"
```

### 3. Create Secrets in GCP Secret Manager

```bash
# Create JWT_SECRET
echo -n "$JWT_SECRET" | gcloud secrets create JWT_SECRET \
  --data-file=- \
  --replication-policy="automatic"

# Create REFRESH_TOKEN_SECRET
echo -n "$REFRESH_SECRET" | gcloud secrets create REFRESH_TOKEN_SECRET \
  --data-file=- \
  --replication-policy="automatic"

# Create DB_ENCRYPTION_KEY (for encrypting DISC and financial data)
echo -n "$DB_ENCRYPTION_KEY" | gcloud secrets create DB_ENCRYPTION_KEY \
  --data-file=- \
  --replication-policy="automatic"

# Create DATABASE_PASSWORD
echo -n "$DB_PASSWORD" | gcloud secrets create DATABASE_PASSWORD \
  --data-file=- \
  --replication-policy="automatic"

# Create environment-specific secret bundle
cat > staging-env.txt <<EOF
NODE_ENV=staging
JWT_SECRET=$JWT_SECRET
REFRESH_TOKEN_SECRET=$REFRESH_SECRET
DB_ENCRYPTION_KEY=$DB_ENCRYPTION_KEY
DATABASE_PASSWORD=$DB_PASSWORD
DATABASE_HOST=your-cloud-sql-instance
DATABASE_PORT=5432
DATABASE_NAME=financial_rise_staging
DATABASE_USER=financial_rise
GCP_PROJECT_ID=$GCP_PROJECT_ID
EOF

gcloud secrets create financial-rise-staging-env \
  --data-file=staging-env.txt \
  --replication-policy="automatic"

# Clean up sensitive file
rm staging-env.txt
```

### 4. Grant Service Account Access

```bash
# Create service account for the application
gcloud iam service-accounts create financial-rise-app \
  --display-name="Financial RISE Application"

# Grant Secret Manager access
export SERVICE_ACCOUNT="financial-rise-app@${GCP_PROJECT_ID}.iam.gserviceaccount.com"

gcloud secrets add-iam-policy-binding JWT_SECRET \
  --member="serviceAccount:${SERVICE_ACCOUNT}" \
  --role="roles/secretmanager.secretAccessor"

gcloud secrets add-iam-policy-binding REFRESH_TOKEN_SECRET \
  --member="serviceAccount:${SERVICE_ACCOUNT}" \
  --role="roles/secretmanager.secretAccessor"

gcloud secrets add-iam-policy-binding DB_ENCRYPTION_KEY \
  --member="serviceAccount:${SERVICE_ACCOUNT}" \
  --role="roles/secretmanager.secretAccessor"

gcloud secrets add-iam-policy-binding DATABASE_PASSWORD \
  --member="serviceAccount:${SERVICE_ACCOUNT}" \
  --role="roles/secretmanager.secretAccessor"

gcloud secrets add-iam-policy-binding financial-rise-staging-env \
  --member="serviceAccount:${SERVICE_ACCOUNT}" \
  --role="roles/secretmanager.secretAccessor"
```

### 5. Verify Secret Creation

```bash
# List all secrets
gcloud secrets list

# Verify secret strength (should be 64+ characters)
gcloud secrets versions access latest --secret="JWT_SECRET" | wc -c
gcloud secrets versions access latest --secret="REFRESH_TOKEN_SECRET" | wc -c
```

## GCP Artifact Registry Setup

### 1. Create Artifact Registry Repository

```bash
# Enable Artifact Registry API
gcloud services enable artifactregistry.googleapis.com

# Create repository for Docker images
gcloud artifacts repositories create financial-rise \
  --repository-format=docker \
  --location=us-central1 \
  --description="Financial RISE Docker images"
```

### 2. Build and Push Images

```bash
# Configure Docker for Artifact Registry
gcloud auth configure-docker us-central1-docker.pkg.dev

# Set variables
export GCP_PROJECT_ID="your-project-id"
export REGISTRY="us-central1-docker.pkg.dev/${GCP_PROJECT_ID}/financial-rise"

# Build and push backend
docker build -f infrastructure/docker/backend.Dockerfile -t financial-rise-backend:latest ./backend
docker tag financial-rise-backend:latest ${REGISTRY}/backend:latest
docker push ${REGISTRY}/backend:latest

# Build and push frontend
docker build -f infrastructure/docker/frontend.Dockerfile -t financial-rise-frontend:latest ./frontend
docker tag financial-rise-frontend:latest ${REGISTRY}/frontend:latest
docker push ${REGISTRY}/frontend:latest
```

## GitHub Actions CI/CD

### 1. Configure GitHub Secrets

In your GitHub repository, go to Settings > Secrets and add:

**IMPORTANT:** Use GCP Workload Identity Federation instead of service account keys for production.

- `GCP_PROJECT_ID`: Your GCP project ID
- `GCP_SERVICE_ACCOUNT`: Service account email (financial-rise-app@PROJECT.iam.gserviceaccount.com)
- `GCP_WORKLOAD_IDENTITY_PROVIDER`: Workload identity provider resource name

### 2. Enable GitHub Environments

Create two environments in GitHub:
- `staging`: Auto-deploy from main branch
- `production`: Requires manual approval

### 3. Trigger Deployment

```bash
# Push to main branch triggers staging deployment
git push origin main

# Production deployment requires manual approval in GitHub Actions
```

## Database Migrations

### Run Migrations in Production

```bash
# SSH into ECS task or use ECS Exec
aws ecs execute-command \
  --cluster financial-rise-production \
  --task <task-id> \
  --container backend \
  --command "npm run migration:run" \
  --interactive
```

## Monitoring and Logging

### CloudWatch Logs

```bash
# View backend logs
aws logs tail /ecs/financial-rise-production-backend --follow

# View frontend logs
aws logs tail /ecs/financial-rise-production-frontend --follow
```

### CloudWatch Metrics

Access CloudWatch dashboard at:
https://console.aws.amazon.com/cloudwatch/

### Sentry Error Tracking

Configure Sentry DSN in environment variables:
```
SENTRY_DSN=your-sentry-dsn-here
```

## Scaling

### Manual Scaling

```bash
# Scale backend service
aws ecs update-service \
  --cluster financial-rise-production \
  --service backend \
  --desired-count 3

# Scale frontend service
aws ecs update-service \
  --cluster financial-rise-production \
  --service frontend \
  --desired-count 3
```

### Auto-Scaling

Auto-scaling is configured in Terraform based on CPU/memory metrics.

## Backup and Recovery

### Database Backups

Automated backups are enabled with 7-day retention (configurable in Terraform).

Manual backup:
```bash
aws rds create-db-snapshot \
  --db-instance-identifier financial-rise-production \
  --db-snapshot-identifier manual-backup-$(date +%Y%m%d)
```

### Restore from Backup

```bash
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier financial-rise-restored \
  --db-snapshot-identifier manual-backup-20251219
```

## Security Best Practices (Work Stream 51 - CRIT-001)

### Critical Security Requirements

1. **Secrets Management** (MANDATORY)
   - ALL secrets MUST be stored in GCP Secret Manager
   - NEVER commit secrets to version control
   - Use cryptographically secure random generators (crypto.randomBytes)
   - Minimum 64-character secrets for production (JWT, REFRESH_TOKEN)
   - Application validates secret strength on startup
   - See `backend/docs/SECRETS-MANAGEMENT.md` for complete documentation

2. **Secret Rotation Policy**
   - JWT_SECRET: Rotate every 90 days
   - REFRESH_TOKEN_SECRET: Rotate every 90 days
   - DATABASE_PASSWORD: Rotate every 180 days
   - DB_ENCRYPTION_KEY: Manual rotation with re-encryption strategy

3. **Encryption at Rest**
   - DISC personality data encrypted with AES-256-GCM (Work Stream 52)
   - Financial data encrypted with AES-256-GCM (Work Stream 53)
   - Encryption keys stored in GCP Secret Manager

4. **Access Control**
   - Use GCP Workload Identity Federation (not service account keys)
   - Grant least-privilege IAM roles
   - Service accounts with roles/secretmanager.secretAccessor only

5. **Environment Isolation**
   - Separate secrets for staging and production
   - Use different GCP projects for environments
   - Database in private VPC only

6. **Monitoring & Auditing**
   - Enable Cloud Audit Logs for Secret Manager access
   - Monitor for unauthorized secret access attempts
   - Alert on secret rotation failures

## Troubleshooting

### Service Not Starting

```bash
# Check ECS service events
aws ecs describe-services \
  --cluster financial-rise-production \
  --services backend

# Check task logs
aws logs tail /ecs/financial-rise-production-backend --since 1h
```

### Database Connection Issues

```bash
# Test database connectivity from ECS task
aws ecs execute-command \
  --cluster financial-rise-production \
  --task <task-id> \
  --container backend \
  --command "pg_isready -h <db-endpoint>" \
  --interactive
```

### High CPU/Memory

```bash
# Check CloudWatch metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/ECS \
  --metric-name CPUUtilization \
  --dimensions Name=ServiceName,Value=backend \
  --start-time 2025-12-19T00:00:00Z \
  --end-time 2025-12-19T23:59:59Z \
  --period 3600 \
  --statistics Average
```

## Rollback Procedures

### Rollback ECS Deployment

```bash
# Update to previous task definition
aws ecs update-service \
  --cluster financial-rise-production \
  --service backend \
  --task-definition financial-rise-backend:<previous-revision>
```

### Rollback Database Migration

```bash
# Revert migration
npm run migration:revert
```

## Health Checks

### Application Health

- Backend: `GET /api/v1/health`
- Frontend: `GET /health`

### Database Health

```bash
# Check RDS status
aws rds describe-db-instances \
  --db-instance-identifier financial-rise-production
```

## Support and Escalation

For deployment issues:
1. Check CloudWatch Logs
2. Review GitHub Actions workflow logs
3. Check AWS service health dashboard
4. Contact DevOps team

## References

- [AWS ECS Documentation](https://docs.aws.amazon.com/ecs/)
- [Terraform AWS Provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
