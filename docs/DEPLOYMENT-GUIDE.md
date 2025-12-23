# Financial RISE - Deployment Guide

**Version:** 1.0
**Date:** 2025-12-22
**Target Environment:** AWS Production

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Environment Setup](#environment-setup)
3. [Database Setup](#database-setup)
4. [Application Deployment](#application-deployment)
5. [Infrastructure as Code](#infrastructure-as-code)
6. [CI/CD Pipeline](#cicd-pipeline)
7. [Monitoring & Logging](#monitoring--logging)
8. [Backup & Recovery](#backup--recovery)
9. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Accounts & Access

- **AWS Account** with admin access
- **GitHub** repository access
- **Domain registrar** access (for DNS)
- **SendGrid** account (for email)

### Required Tools

| Tool | Version | Purpose |
|------|---------|---------|
| **AWS CLI** | 2.0+ | AWS resource management |
| **Docker** | 24.0+ | Container management |
| **Node.js** | 18 LTS+ | Local development |
| **PostgreSQL Client** | 14+ | Database management |
| **Terraform** | 1.6+ | Infrastructure as Code |

### Installation

**macOS/Linux:**
```bash
# AWS CLI
curl "https://awscli.amazonaws.com/AWSCLIV2.pkg" -o "AWSCLIV2.pkg"
sudo installer -pkg AWSCLIV2.pkg -target /

# Docker
brew install --cask docker

# Node.js (via nvm)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
nvm install 18
nvm use 18

# PostgreSQL Client
brew install postgresql@14

# Terraform
brew tap hashicorp/tap
brew install hashicorp/tap/terraform
```

**Windows:**
```powershell
# Install via Chocolatey
choco install awscli docker-desktop nodejs-lts postgresql terraform
```

### AWS CLI Configuration

```bash
aws configure
# AWS Access Key ID: <your-key>
# AWS Secret Access Key: <your-secret>
# Default region name: us-east-1
# Default output format: json
```

---

## Environment Setup

### Environment Variables

Create `.env` files for each environment:

**Backend (.env.production):**
```bash
# Application
NODE_ENV=production
PORT=3000
API_URL=https://api.financialrise.com

# Database
DB_HOST=financial-rise-db.us-east-1.rds.amazonaws.com
DB_PORT=5432
DB_NAME=financialrise_prod
DB_USER=financialrise_app
DB_PASSWORD=<from-aws-secrets-manager>
DB_SSL=true
DB_POOL_MIN=10
DB_POOL_MAX=30

# Redis
REDIS_HOST=financial-rise-cache.us-east-1.cache.amazonaws.com
REDIS_PORT=6379
REDIS_PASSWORD=<from-aws-secrets-manager>

# JWT
JWT_SECRET=<from-aws-secrets-manager>
JWT_ACCESS_EXPIRY=15m
JWT_REFRESH_EXPIRY=7d

# AWS S3
AWS_REGION=us-east-1
AWS_S3_BUCKET=financial-rise-reports
AWS_ACCESS_KEY_ID=<from-aws-secrets-manager>
AWS_SECRET_ACCESS_KEY=<from-aws-secrets-manager>

# Email (SendGrid)
SENDGRID_API_KEY=<from-aws-secrets-manager>
FROM_EMAIL=noreply@financialrise.com

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# Logging
LOG_LEVEL=info
```

**Frontend (.env.production):**
```bash
VITE_API_URL=https://api.financialrise.com/v1
VITE_APP_URL=https://app.financialrise.com
VITE_ENVIRONMENT=production
```

### AWS Secrets Manager Setup

```bash
# Store database password
aws secretsmanager create-secret \
  --name financial-rise/prod/db-password \
  --secret-string "<secure-password>"

# Store JWT secret
aws secretsmanager create-secret \
  --name financial-rise/prod/jwt-secret \
  --secret-string "$(openssl rand -base64 64)"

# Store SendGrid API key
aws secretsmanager create-secret \
  --name financial-rise/prod/sendgrid-key \
  --secret-string "<sendgrid-api-key>"
```

---

## Database Setup

### RDS PostgreSQL Instance

**Create via AWS Console:**

1. **Navigate to RDS** → Create Database
2. **Engine:** PostgreSQL 14.10
3. **Template:** Production
4. **DB Instance:** db.t3.medium (2 vCPU, 4 GB RAM)
5. **Storage:** 100 GB SSD, enable autoscaling to 500 GB
6. **Availability:** Multi-AZ deployment
7. **VPC:** Select production VPC
8. **Security Group:** Allow PostgreSQL (5432) from ECS security group
9. **Backup:** 7-day retention, preferred window 03:00-04:00 UTC
10. **Monitoring:** Enable Enhanced Monitoring

**Create via Terraform:**
```hcl
resource "aws_db_instance" "postgres" {
  identifier        = "financial-rise-db"
  engine            = "postgres"
  engine_version    = "14.10"
  instance_class    = "db.t3.medium"
  allocated_storage = 100
  storage_type      = "gp3"

  db_name  = "financialrise_prod"
  username = "financialrise_app"
  password = data.aws_secretsmanager_secret_version.db_password.secret_string

  multi_az               = true
  publicly_accessible    = false
  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name

  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "Mon:04:00-Mon:05:00"

  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  tags = {
    Name        = "financial-rise-db"
    Environment = "production"
  }
}
```

### Database Initialization

```bash
# Connect to RDS instance
psql -h financial-rise-db.us-east-1.rds.amazonaws.com \
     -U financialrise_app \
     -d financialrise_prod

# Run migrations
cd financial-rise-backend
npm run migrate:prod

# Seed initial data (questions, options)
npm run seed:prod
```

### Read Replica Setup

```bash
aws rds create-db-instance-read-replica \
  --db-instance-identifier financial-rise-db-replica \
  --source-db-instance-identifier financial-rise-db \
  --db-instance-class db.t3.medium \
  --availability-zone us-east-1b
```

---

## Application Deployment

### Docker Image Build

**Backend Dockerfile:**
```dockerfile
FROM node:18-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

FROM node:18-alpine
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY package*.json ./

EXPOSE 3000
CMD ["node", "dist/app.js"]
```

**Frontend Dockerfile:**
```dockerfile
FROM node:18-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

**Build and Push:**
```bash
# Authenticate Docker to ECR
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin \
  <account-id>.dkr.ecr.us-east-1.amazonaws.com

# Build backend
cd financial-rise-backend
docker build -t financial-rise-backend:latest .
docker tag financial-rise-backend:latest \
  <account-id>.dkr.ecr.us-east-1.amazonaws.com/financial-rise-backend:latest
docker push <account-id>.dkr.ecr.us-east-1.amazonaws.com/financial-rise-backend:latest

# Build frontend
cd ../financial-rise-frontend
docker build -t financial-rise-frontend:latest .
docker tag financial-rise-frontend:latest \
  <account-id>.dkr.ecr.us-east-1.amazonaws.com/financial-rise-frontend:latest
docker push <account-id>.dkr.ecr.us-east-1.amazonaws.com/financial-rise-frontend:latest
```

### ECS Deployment

**Task Definition (backend-task.json):**
```json
{
  "family": "financial-rise-backend",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "containerDefinitions": [
    {
      "name": "backend",
      "image": "<account-id>.dkr.ecr.us-east-1.amazonaws.com/financial-rise-backend:latest",
      "portMappings": [
        {
          "containerPort": 3000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        { "name": "NODE_ENV", "value": "production" },
        { "name": "PORT", "value": "3000" }
      ],
      "secrets": [
        {
          "name": "DB_PASSWORD",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:...:secret:financial-rise/prod/db-password"
        },
        {
          "name": "JWT_SECRET",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:...:secret:financial-rise/prod/jwt-secret"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/financial-rise-backend",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -f http://localhost:3000/health || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 60
      }
    }
  ]
}
```

**Register Task Definition:**
```bash
aws ecs register-task-definition \
  --cli-input-json file://backend-task.json
```

**Create ECS Service:**
```bash
aws ecs create-service \
  --cluster financial-rise-prod \
  --service-name backend-service \
  --task-definition financial-rise-backend \
  --desired-count 2 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-xxx,subnet-yyy],securityGroups=[sg-xxx],assignPublicIp=DISABLED}" \
  --load-balancers "targetGroupArn=arn:aws:elasticloadbalancing:...,containerName=backend,containerPort=3000" \
  --health-check-grace-period-seconds 60
```

### Load Balancer Setup

**Application Load Balancer:**
```bash
# Create ALB
aws elbv2 create-load-balancer \
  --name financial-rise-alb \
  --subnets subnet-xxx subnet-yyy \
  --security-groups sg-xxx \
  --scheme internet-facing \
  --type application

# Create target group
aws elbv2 create-target-group \
  --name financial-rise-backend-tg \
  --protocol HTTP \
  --port 3000 \
  --vpc-id vpc-xxx \
  --target-type ip \
  --health-check-path /health \
  --health-check-interval-seconds 30

# Create listener
aws elbv2 create-listener \
  --load-balancer-arn arn:aws:elasticloadbalancing:... \
  --protocol HTTPS \
  --port 443 \
  --certificates CertificateArn=arn:aws:acm:... \
  --default-actions Type=forward,TargetGroupArn=arn:aws:elasticloadbalancing:...
```

---

## Infrastructure as Code

### Terraform Configuration

**main.tf:**
```hcl
terraform {
  required_version = ">= 1.6"

  backend "s3" {
    bucket = "financial-rise-terraform-state"
    key    = "prod/terraform.tfstate"
    region = "us-east-1"
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# VPC
module "vpc" {
  source = "./modules/vpc"

  name             = "financial-rise-vpc"
  cidr             = "10.0.0.0/16"
  azs              = ["us-east-1a", "us-east-1b"]
  private_subnets  = ["10.0.1.0/24", "10.0.2.0/24"]
  public_subnets   = ["10.0.101.0/24", "10.0.102.0/24"]
  enable_nat       = true
}

# ECS Cluster
module "ecs" {
  source = "./modules/ecs"

  cluster_name = "financial-rise-prod"
  vpc_id       = module.vpc.vpc_id
  subnets      = module.vpc.private_subnets
}

# RDS Database
module "database" {
  source = "./modules/rds"

  identifier     = "financial-rise-db"
  engine_version = "14.10"
  instance_class = "db.t3.medium"
  vpc_id         = module.vpc.vpc_id
  subnets        = module.vpc.private_subnets
}

# S3 Bucket for Reports
module "s3" {
  source = "./modules/s3"

  bucket_name = "financial-rise-reports"
}
```

**Deploy with Terraform:**
```bash
# Initialize
terraform init

# Plan
terraform plan -out=tfplan

# Apply
terraform apply tfplan

# Outputs
terraform output
```

---

## CI/CD Pipeline

### GitHub Actions Workflow

**.github/workflows/deploy.yml:**
```yaml
name: Deploy to Production

on:
  push:
    branches: [main]

env:
  AWS_REGION: us-east-1
  ECR_BACKEND_REPO: financial-rise-backend
  ECR_FRONTEND_REPO: financial-rise-frontend
  ECS_CLUSTER: financial-rise-prod
  ECS_BACKEND_SERVICE: backend-service
  ECS_FRONTEND_SERVICE: frontend-service

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '18'
          cache: 'npm'
          cache-dependency-path: |
            financial-rise-backend/package-lock.json
            financial-rise-frontend/package-lock.json

      - name: Test Backend
        run: |
          cd financial-rise-backend
          npm ci
          npm run test
          npm run test:e2e

      - name: Test Frontend
        run: |
          cd financial-rise-frontend
          npm ci
          npm run test
          npm run test:e2e

  deploy-backend:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: ${{ env.AWS_REGION }}

      - name: Login to ECR
        id: login-ecr
        uses: aws-actions/amazon-ecr-login@v2

      - name: Build and Push Backend
        env:
          ECR_REGISTRY: ${{ steps.login-ecr.outputs.registry }}
          IMAGE_TAG: ${{ github.sha }}
        run: |
          cd financial-rise-backend
          docker build -t $ECR_REGISTRY/$ECR_BACKEND_REPO:$IMAGE_TAG .
          docker push $ECR_REGISTRY/$ECR_BACKEND_REPO:$IMAGE_TAG
          docker tag $ECR_REGISTRY/$ECR_BACKEND_REPO:$IMAGE_TAG \
                     $ECR_REGISTRY/$ECR_BACKEND_REPO:latest
          docker push $ECR_REGISTRY/$ECR_BACKEND_REPO:latest

      - name: Update ECS Service
        run: |
          aws ecs update-service \
            --cluster $ECS_CLUSTER \
            --service $ECS_BACKEND_SERVICE \
            --force-new-deployment

  deploy-frontend:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: ${{ env.AWS_REGION }}

      - name: Login to ECR
        id: login-ecr
        uses: aws-actions/amazon-ecr-login@v2

      - name: Build and Push Frontend
        env:
          ECR_REGISTRY: ${{ steps.login-ecr.outputs.registry }}
          IMAGE_TAG: ${{ github.sha }}
        run: |
          cd financial-rise-frontend
          docker build -t $ECR_REGISTRY/$ECR_FRONTEND_REPO:$IMAGE_TAG .
          docker push $ECR_REGISTRY/$ECR_FRONTEND_REPO:$IMAGE_TAG
          docker tag $ECR_REGISTRY/$ECR_FRONTEND_REPO:$IMAGE_TAG \
                     $ECR_REGISTRY/$ECR_FRONTEND_REPO:latest
          docker push $ECR_REGISTRY/$ECR_FRONTEND_REPO:latest

      - name: Update ECS Service
        run: |
          aws ecs update-service \
            --cluster $ECS_CLUSTER \
            --service $ECS_FRONTEND_SERVICE \
            --force-new-deployment

      - name: Invalidate CloudFront Cache
        run: |
          aws cloudfront create-invalidation \
            --distribution-id ${{ secrets.CLOUDFRONT_DISTRIBUTION_ID }} \
            --paths "/*"
```

---

## Monitoring & Logging

### CloudWatch Setup

**Log Groups:**
```bash
# Create log groups
aws logs create-log-group --log-group-name /ecs/financial-rise-backend
aws logs create-log-group --log-group-name /ecs/financial-rise-frontend
aws logs create-log-group --log-group-name /rds/financial-rise-db

# Set retention
aws logs put-retention-policy \
  --log-group-name /ecs/financial-rise-backend \
  --retention-in-days 30
```

**Alarms:**
```bash
# High CPU alarm
aws cloudwatch put-metric-alarm \
  --alarm-name financial-rise-high-cpu \
  --alarm-description "Alert when CPU exceeds 80%" \
  --metric-name CPUUtilization \
  --namespace AWS/ECS \
  --statistic Average \
  --period 300 \
  --evaluation-periods 2 \
  --threshold 80 \
  --comparison-operator GreaterThanThreshold \
  --dimensions Name=ServiceName,Value=backend-service

# High error rate
aws cloudwatch put-metric-alarm \
  --alarm-name financial-rise-high-errors \
  --alarm-description "Alert when error rate exceeds 5%" \
  --metric-name 5XXError \
  --namespace AWS/ApplicationELB \
  --statistic Sum \
  --period 60 \
  --evaluation-periods 2 \
  --threshold 10 \
  --comparison-operator GreaterThanThreshold
```

### Application Performance Monitoring

**Health Check Endpoint:**
```typescript
// backend/src/routes/health.ts
app.get('/health', async (req, res) => {
  const dbStatus = await checkDatabaseConnection();
  const redisStatus = await checkRedisConnection();

  const health = {
    status: dbStatus && redisStatus ? 'healthy' : 'unhealthy',
    timestamp: new Date().toISOString(),
    services: {
      database: dbStatus ? 'up' : 'down',
      redis: redisStatus ? 'up' : 'down'
    }
  };

  res.status(health.status === 'healthy' ? 200 : 503).json(health);
});
```

---

## Backup & Recovery

### Database Backups

**Automated Backups:**
- **Daily snapshots** at 03:00 UTC
- **7-day retention** for point-in-time recovery
- **Multi-region replication** for disaster recovery

**Manual Backup:**
```bash
# Create snapshot
aws rds create-db-snapshot \
  --db-instance-identifier financial-rise-db \
  --db-snapshot-identifier financial-rise-manual-$(date +%Y%m%d)

# List snapshots
aws rds describe-db-snapshots \
  --db-instance-identifier financial-rise-db
```

**Restore from Snapshot:**
```bash
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier financial-rise-db-restored \
  --db-snapshot-identifier financial-rise-manual-20251222
```

### S3 Backups

**Versioning enabled on reports bucket:**
```bash
aws s3api put-bucket-versioning \
  --bucket financial-rise-reports \
  --versioning-configuration Status=Enabled
```

**Lifecycle policy for old versions:**
```bash
aws s3api put-bucket-lifecycle-configuration \
  --bucket financial-rise-reports \
  --lifecycle-configuration file://lifecycle.json
```

---

## Troubleshooting

### Common Issues

**1. ECS Task Failing to Start**

**Symptoms:** Tasks start then immediately stop

**Diagnosis:**
```bash
# Check task logs
aws logs tail /ecs/financial-rise-backend --follow

# Describe task
aws ecs describe-tasks \
  --cluster financial-rise-prod \
  --tasks <task-id>
```

**Solutions:**
- Verify environment variables are correct
- Check secrets are accessible
- Ensure health check passes
- Verify security group allows traffic

**2. Database Connection Timeout**

**Symptoms:** Backend logs show "ETIMEDOUT" errors

**Diagnosis:**
```bash
# Test connection from ECS task
aws ecs execute-command \
  --cluster financial-rise-prod \
  --task <task-id> \
  --container backend \
  --command "nc -zv financial-rise-db.us-east-1.rds.amazonaws.com 5432" \
  --interactive
```

**Solutions:**
- Verify security group allows PostgreSQL (5432)
- Check VPC routing
- Verify database is in same VPC
- Check connection pool settings

**3. High Latency**

**Symptoms:** API responses >1s

**Diagnosis:**
```bash
# Check database slow queries
psql -h <db-host> -U <user> -d <db> -c "
  SELECT query, mean_exec_time, calls
  FROM pg_stat_statements
  ORDER BY mean_exec_time DESC
  LIMIT 10;"

# Check CloudWatch metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/ECS \
  --metric-name CPUUtilization \
  --dimensions Name=ServiceName,Value=backend-service \
  --start-time 2025-12-22T00:00:00Z \
  --end-time 2025-12-22T23:59:59Z \
  --period 3600 \
  --statistics Average
```

**Solutions:**
- Add database indexes
- Increase ECS task CPU/memory
- Enable caching
- Add read replica

---

**Deployment Guide Version:** 1.0
**Last Updated:** 2025-12-22
**Maintained By:** DevOps Team
**Emergency Contact:** devops@financialrise.com
