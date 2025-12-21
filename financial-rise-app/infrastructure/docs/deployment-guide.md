# Financial RISE - Deployment Guide

**Version:** 1.0.0
**Last Updated:** 2025-12-19

## Overview

This guide covers deploying the Financial RISE Report application to AWS using Docker, Terraform, and GitHub Actions.

## Prerequisites

### Local Development
- Node.js 18 LTS or higher
- Docker and Docker Compose
- PostgreSQL 14+ (or use Docker)
- Git

### AWS Deployment
- AWS Account with appropriate permissions
- AWS CLI configured
- Terraform 1.0+
- GitHub repository with secrets configured

## Local Development Setup

### 1. Clone and Install

```bash
# Clone repository
git clone <repository-url>
cd financial-rise-app

# Copy environment variables
cp .env.example .env

# Edit .env with your local configuration
nano .env
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

## AWS Infrastructure Setup

### 1. Terraform State Backend

Create S3 bucket and DynamoDB table for Terraform state:

```bash
aws s3 mb s3://financial-rise-terraform-state --region us-east-1

aws dynamodb create-table \
  --table-name terraform-state-lock \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5 \
  --region us-east-1
```

### 2. Create terraform.tfvars

```bash
cd infrastructure/terraform

cat > terraform.tfvars <<EOF
environment     = "staging"
aws_region      = "us-east-1"
db_username     = "admin"
db_password     = "CHANGE_ME_SECURE_PASSWORD"
jwt_secret      = "CHANGE_ME_MIN_32_CHARS"
jwt_refresh_secret = "CHANGE_ME_MIN_32_CHARS"
sendgrid_api_key   = "YOUR_SENDGRID_API_KEY"
alert_email     = "alerts@yourcompany.com"
EOF
```

### 3. Deploy Infrastructure

```bash
# Initialize Terraform
terraform init

# Plan deployment
terraform plan

# Apply infrastructure
terraform apply

# Save outputs
terraform output > outputs.txt
```

## Container Registry Setup

### 1. Create ECR Repositories

```bash
aws ecr create-repository --repository-name financial-rise-backend --region us-east-1
aws ecr create-repository --repository-name financial-rise-frontend --region us-east-1
```

### 2. Build and Push Images

```bash
# Login to ECR
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin <account-id>.dkr.ecr.us-east-1.amazonaws.com

# Build and push backend
docker build -f infrastructure/docker/backend.Dockerfile -t financial-rise-backend:latest ./backend
docker tag financial-rise-backend:latest <account-id>.dkr.ecr.us-east-1.amazonaws.com/financial-rise-backend:latest
docker push <account-id>.dkr.ecr.us-east-1.amazonaws.com/financial-rise-backend:latest

# Build and push frontend
docker build -f infrastructure/docker/frontend.Dockerfile -t financial-rise-frontend:latest ./frontend
docker tag financial-rise-frontend:latest <account-id>.dkr.ecr.us-east-1.amazonaws.com/financial-rise-frontend:latest
docker push <account-id>.dkr.ecr.us-east-1.amazonaws.com/financial-rise-frontend:latest
```

## GitHub Actions CI/CD

### 1. Configure GitHub Secrets

In your GitHub repository, go to Settings > Secrets and add:

- `AWS_ACCESS_KEY_ID`: AWS access key
- `AWS_SECRET_ACCESS_KEY`: AWS secret key
- `AWS_REGION`: us-east-1

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

## Security Best Practices

1. **Secrets Management**: Use AWS Secrets Manager (already configured)
2. **HTTPS Only**: Configure ALB with SSL certificate
3. **Security Groups**: Restrict access (configured in Terraform)
4. **IAM Roles**: Use least-privilege IAM roles for ECS tasks
5. **VPC**: Database in private subnets only
6. **Encryption**: Enable encryption at rest for RDS and S3

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
