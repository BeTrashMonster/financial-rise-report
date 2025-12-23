# Production Deployment Runbook - Financial RISE

**Version:** 1.0
**Date:** 2025-12-22
**Environment:** AWS Production

## Table of Contents

1. [Pre-Deployment Checklist](#pre-deployment-checklist)
2. [Deployment Procedure](#deployment-procedure)
3. [Post-Deployment Verification](#post-deployment-verification)
4. [Rollback Procedures](#rollback-procedures)
5. [Monitoring & Alerts](#monitoring--alerts)
6. [Emergency Contacts](#emergency-contacts)

---

## Pre-Deployment Checklist

### T-7 Days: Preparation

**Infrastructure:**
- [ ] Production AWS account configured
- [ ] VPC and subnets created
- [ ] RDS PostgreSQL instance running (Multi-AZ)
- [ ] Redis ElastiCache cluster running
- [ ] S3 bucket for reports created
- [ ] CloudFront distribution configured
- [ ] Route 53 DNS configured
- [ ] ACM SSL certificate issued and validated
- [ ] ECS cluster created
- [ ] ALB configured with target groups

**Code:**
- [ ] All P0/P1 bugs fixed
- [ ] All tests passing (unit, integration, E2E)
- [ ] Code coverage >80%
- [ ] Security audit passed
- [ ] Performance benchmarks met
- [ ] Final code review complete
- [ ] Main branch tagged with version number (e.g., v1.0.0)

**Database:**
- [ ] Migration scripts tested on staging
- [ ] Database backup taken
- [ ] Rollback scripts prepared
- [ ] Seed data scripts ready (questions, options)

**Documentation:**
- [ ] API documentation complete
- [ ] User documentation complete
- [ ] Admin documentation complete
- [ ] Deployment runbook reviewed
- [ ] Rollback procedures reviewed

**Monitoring:**
- [ ] CloudWatch log groups created
- [ ] CloudWatch alarms configured
- [ ] Status page set up
- [ ] Uptime monitoring configured (e.g., Pingdom, UptimeRobot)

---

### T-48 Hours: Final Checks

**Staging Validation:**
- [ ] Full deployment to staging successful
- [ ] Smoke tests passed on staging
- [ ] Performance tests passed on staging
- [ ] Security scan passed on staging
- [ ] UAT participants tested on staging

**Team Coordination:**
- [ ] Deployment date/time confirmed
- [ ] All team members available
- [ ] Emergency contacts list updated
- [ ] Communication plan reviewed
- [ ] Go/No-Go meeting scheduled

**Production Environment:**
- [ ] Database migration dry-run completed
- [ ] Secrets stored in AWS Secrets Manager
- [ ] Environment variables configured
- [ ] SSL certificate validated
- [ ] DNS propagation verified

---

### T-24 Hours: Go/No-Go Decision

**Go/No-Go Meeting Attendees:**
- Product Owner (final decision maker)
- Engineering Lead
- DevOps Lead
- QA Lead
- Support Lead

**Go Criteria:**
- [ ] All P0/P1 bugs resolved
- [ ] All pre-deployment checklist items complete
- [ ] Staging deployment successful
- [ ] Team ready and available
- [ ] Rollback plan understood
- [ ] Support team briefed

**If NO-GO:**
- Reschedule deployment
- Address blocking issues
- Re-run Go/No-Go meeting

---

## Deployment Procedure

### Deployment Window

**Recommended Time:** Saturday 2:00 AM - 6:00 AM EST
- Low traffic period
- Team available for 24 hours post-deployment
- Weekend allows time to stabilize before Monday

**Team Roles:**
- **Deployment Lead:** DevOps Engineer (runs commands, makes decisions)
- **Engineering Lead:** Technical oversight, code issues
- **QA Lead:** Smoke testing
- **Product Owner:** Business decision maker
- **Support Lead:** User communications

---

### Phase 1: Database Migration (30 minutes)

**Time:** T+0 (2:00 AM)

**Steps:**

1. **Take Database Snapshot**
   ```bash
   aws rds create-db-snapshot \
     --db-instance-identifier financial-rise-db \
     --db-snapshot-identifier pre-deploy-$(date +%Y%m%d-%H%M%S)
   ```

   Wait for completion (5-10 min):
   ```bash
   aws rds describe-db-snapshots \
     --db-snapshot-identifier pre-deploy-20251222-020000 \
     --query 'DBSnapshots[0].Status'
   ```

2. **Run Database Migrations**
   ```bash
   # SSH into bastion host
   ssh -i ~/.ssh/financial-rise-prod.pem ec2-user@bastion.financialrise.com

   # Connect to RDS
   psql -h financial-rise-db.us-east-1.rds.amazonaws.com \
        -U financialrise_app \
        -d financialrise_prod

   # Run migrations
   cd /opt/financial-rise-backend
   npm run migrate:prod
   ```

3. **Verify Migrations**
   ```sql
   -- Check migration status
   SELECT * FROM migrations ORDER BY id DESC LIMIT 5;

   -- Verify table structure
   \d users
   \d assessments
   \d questions
   ```

4. **Seed Production Data**
   ```bash
   npm run seed:prod
   ```

   Verify:
   ```sql
   SELECT COUNT(*) FROM questions;  -- Should be 25
   SELECT COUNT(*) FROM users WHERE role='admin';  -- At least 1
   ```

**Rollback Point #1:** If migration fails, restore from snapshot

---

### Phase 2: Backend Deployment (20 minutes)

**Time:** T+30 (2:30 AM)

**Steps:**

1. **Build & Push Docker Image**
   ```bash
   cd financial-rise-backend

   # Build
   docker build -t financial-rise-backend:v1.0.0 .

   # Tag
   docker tag financial-rise-backend:v1.0.0 \
     123456789012.dkr.ecr.us-east-1.amazonaws.com/financial-rise-backend:v1.0.0

   docker tag financial-rise-backend:v1.0.0 \
     123456789012.dkr.ecr.us-east-1.amazonaws.com/financial-rise-backend:latest

   # Push
   docker push 123456789012.dkr.ecr.us-east-1.amazonaws.com/financial-rise-backend:v1.0.0
   docker push 123456789012.dkr.ecr.us-east-1.amazonaws.com/financial-rise-backend:latest
   ```

2. **Update ECS Task Definition**
   ```bash
   aws ecs register-task-definition \
     --cli-input-json file://task-definition-prod.json
   ```

3. **Update ECS Service**
   ```bash
   aws ecs update-service \
     --cluster financial-rise-prod \
     --service backend-service \
     --task-definition financial-rise-backend:v1.0.0 \
     --force-new-deployment
   ```

4. **Monitor Deployment**
   ```bash
   # Watch service status
   watch -n 5 'aws ecs describe-services \
     --cluster financial-rise-prod \
     --services backend-service \
     --query "services[0].deployments"'
   ```

   Wait for:
   - Running count = desired count
   - Primary deployment at 100%
   - Old tasks drained

5. **Check Application Logs**
   ```bash
   aws logs tail /ecs/financial-rise-backend --follow
   ```

   Look for:
   - "Server started on port 3000"
   - No error messages
   - Database connection successful

**Rollback Point #2:** If deployment fails, revert ECS service to previous task definition

---

### Phase 3: Frontend Deployment (15 minutes)

**Time:** T+50 (2:50 AM)

**Steps:**

1. **Build & Push Docker Image**
   ```bash
   cd financial-rise-frontend

   # Set production environment variables
   export VITE_API_URL=https://api.financialrise.com/v1
   export VITE_APP_URL=https://app.financialrise.com

   # Build
   docker build -t financial-rise-frontend:v1.0.0 .

   # Tag & Push
   docker tag financial-rise-frontend:v1.0.0 \
     123456789012.dkr.ecr.us-east-1.amazonaws.com/financial-rise-frontend:v1.0.0

   docker push 123456789012.dkr.ecr.us-east-1.amazonaws.com/financial-rise-frontend:v1.0.0
   ```

2. **Update ECS Service**
   ```bash
   aws ecs update-service \
     --cluster financial-rise-prod \
     --service frontend-service \
     --task-definition financial-rise-frontend:v1.0.0 \
     --force-new-deployment
   ```

3. **Invalidate CloudFront Cache**
   ```bash
   aws cloudfront create-invalidation \
     --distribution-id E1234567890ABC \
     --paths "/*"
   ```

4. **Monitor Deployment**
   ```bash
   watch -n 5 'aws ecs describe-services \
     --cluster financial-rise-prod \
     --services frontend-service \
     --query "services[0].deployments"'
   ```

**Rollback Point #3:** If deployment fails, revert frontend ECS service

---

## Post-Deployment Verification

### Smoke Tests (15 minutes)

**Time:** T+65 (3:05 AM)

Run these tests in order:

**1. Health Check**
```bash
curl https://api.financialrise.com/health
# Expected: {"status":"healthy","timestamp":"..."}
```

**2. Frontend Loads**
- Navigate to https://app.financialrise.com
- Verify homepage loads
- No console errors
- No 404s in network tab

**3. User Registration**
- Create new test account
- Verify email sent
- Complete registration
- Login successful

**4. Create Assessment**
- Login as test consultant
- Create new assessment
- Verify saved to database
- Check invitation email sent

**5. Complete Assessment**
- Use unique link
- Answer all questions
- Submit assessment
- Verify completion status

**6. Generate Reports**
- Generate consultant report
- Verify PDF downloads
- Generate client report
- Verify PDF downloads

**7. Admin Functions**
- Login as admin
- View users list
- View assessments list
- Check analytics

**Smoke Test Checklist:**
- [ ] API health check returns healthy
- [ ] Frontend loads without errors
- [ ] User can register and login
- [ ] Assessment creation works
- [ ] Assessment completion works
- [ ] Report generation works (<5s)
- [ ] PDF download works
- [ ] Admin panel accessible
- [ ] No errors in CloudWatch logs

---

### Performance Validation (10 minutes)

**Time:** T+80 (3:20 AM)

**1. Page Load Times**
```bash
# Use Lighthouse CI
lighthouse https://app.financialrise.com --output=json
```

Verify:
- Performance score >90
- First Contentful Paint <2s
- Time to Interactive <3s

**2. API Response Times**
```bash
# Test key endpoints
curl -w "@curl-format.txt" -o /dev/null -s https://api.financialrise.com/api/assessments
```

Verify:
- GET /assessments <300ms
- POST /assessments <500ms
- POST /reports/generate <5s

**3. Load Test (Light)**
```bash
# Run k6 with 10 concurrent users for 1 minute
k6 run --vus 10 --duration 1m load-test-prod.js
```

Verify:
- 95th percentile <500ms
- Error rate <1%
- No timeouts

---

### Monitoring Setup Verification (5 minutes)

**Time:** T+90 (3:30 AM)

**1. CloudWatch Alarms**
```bash
aws cloudwatch describe-alarms --state-value ALARM
```

Verify no alarms firing

**2. Log Aggregation**
- Check CloudWatch logs receiving data
- Verify log retention set to 30 days
- Test log search functionality

**3. Uptime Monitoring**
- Verify status page shows "All Systems Operational"
- Check uptime monitor is pinging every 1 minute
- Verify alert notifications configured

**4. Error Tracking**
- Verify Sentry/error tracking receiving events
- Test error notification (trigger test error)
- Confirm alerts sent to Slack/email

---

## Rollback Procedures

### Rollback Decision Criteria

**Immediate Rollback if:**
- Critical functionality broken (can't create/complete assessments)
- Data loss or corruption detected
- Security vulnerability exposed
- Performance degradation >50%
- Error rate >10%

**Consider Rollback if:**
- Non-critical features broken
- Performance degradation 25-50%
- Error rate 5-10%
- User complaints increasing

**Don't Rollback for:**
- Minor UI issues
- Edge case bugs with workarounds
- Performance degradation <25%
- Error rate <5%

---

### Rollback Procedure A: Revert Application Code

**Time Required:** 10-15 minutes

**Use When:** Application code issue, database is fine

**Steps:**

1. **Identify Previous Version**
   ```bash
   aws ecs list-task-definitions \
     --family-prefix financial-rise-backend \
     --sort DESC
   ```

2. **Revert Backend**
   ```bash
   aws ecs update-service \
     --cluster financial-rise-prod \
     --service backend-service \
     --task-definition financial-rise-backend:previous-version
   ```

3. **Revert Frontend**
   ```bash
   aws ecs update-service \
     --cluster financial-rise-prod \
     --service frontend-service \
     --task-definition financial-rise-frontend:previous-version
   ```

4. **Invalidate CloudFront**
   ```bash
   aws cloudfront create-invalidation \
     --distribution-id E1234567890ABC \
     --paths "/*"
   ```

5. **Monitor Rollback**
   ```bash
   watch -n 5 'aws ecs describe-services \
     --cluster financial-rise-prod \
     --services backend-service frontend-service'
   ```

6. **Verify Rollback**
   - Run smoke tests
   - Check error rates
   - Verify functionality restored

---

### Rollback Procedure B: Restore Database

**Time Required:** 20-30 minutes

**Use When:** Database migration issue, data corruption

**WARNING:** This will lose all data created since deployment

**Steps:**

1. **Stop Application**
   ```bash
   aws ecs update-service \
     --cluster financial-rise-prod \
     --service backend-service \
     --desired-count 0
   ```

2. **Identify Snapshot**
   ```bash
   aws rds describe-db-snapshots \
     --db-instance-identifier financial-rise-db \
     --query 'reverse(sort_by(DBSnapshots, &SnapshotCreateTime))[:5]'
   ```

3. **Restore from Snapshot**
   ```bash
   # Rename current database
   aws rds modify-db-instance \
     --db-instance-identifier financial-rise-db \
     --new-db-instance-identifier financial-rise-db-backup \
     --apply-immediately

   # Restore from snapshot
   aws rds restore-db-instance-from-db-snapshot \
     --db-instance-identifier financial-rise-db \
     --db-snapshot-identifier pre-deploy-20251222-020000
   ```

4. **Wait for Restore** (15-20 minutes)
   ```bash
   aws rds wait db-instance-available \
     --db-instance-identifier financial-rise-db
   ```

5. **Restart Application**
   ```bash
   aws ecs update-service \
     --cluster financial-rise-prod \
     --service backend-service \
     --desired-count 2
   ```

6. **Verify Restore**
   ```sql
   psql -h financial-rise-db.us-east-1.rds.amazonaws.com \
        -U financialrise_app \
        -d financialrise_prod

   SELECT COUNT(*) FROM users;
   SELECT COUNT(*) FROM assessments;
   ```

---

### Rollback Procedure C: Full System Rollback

**Time Required:** 30-40 minutes

**Use When:** Complete failure, all systems affected

**Steps:**

1. **Communicate Downtime**
   - Update status page: "System Maintenance"
   - Send email to users (if applicable)
   - Post to social media

2. **Revert Application Code** (see Procedure A)

3. **Restore Database** (see Procedure B)

4. **Clear Caches**
   ```bash
   # Flush Redis
   redis-cli -h financial-rise-cache.us-east-1.cache.amazonaws.com FLUSHALL

   # Invalidate CloudFront
   aws cloudfront create-invalidation \
     --distribution-id E1234567890ABC \
     --paths "/*"
   ```

5. **Run Full Smoke Tests**

6. **Communicate Recovery**
   - Update status page: "All Systems Operational"
   - Send recovery email to users
   - Post update to social media

---

## Monitoring & Alerts

### Critical Alarms

**High Error Rate:**
- Metric: 5XXError >10 in 5 minutes
- Action: Page on-call engineer
- Threshold: 10 errors

**API Response Time:**
- Metric: TargetResponseTime >1000ms for 5 minutes
- Action: Page on-call engineer
- Threshold: 1000ms

**Database CPU:**
- Metric: CPUUtilization >80% for 10 minutes
- Action: Email DevOps team
- Threshold: 80%

**Memory Usage:**
- Metric: MemoryUtilization >85% for 10 minutes
- Action: Email DevOps team
- Threshold: 85%

### Monitoring Dashboard

**CloudWatch Dashboard URL:**
`https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#dashboards:name=FinancialRISE-Production`

**Key Metrics:**
- Request count (per minute)
- Error rate (%)
- Response time (p50, p95, p99)
- Active connections
- Database connections
- Memory usage
- CPU usage

---

## Emergency Contacts

| Role | Name | Phone | Email | Availability |
|------|------|-------|-------|--------------|
| Deployment Lead | [Name] | +1-555-0100 | devops@financialrise.com | 24/7 during deployment |
| Engineering Lead | [Name] | +1-555-0101 | eng-lead@financialrise.com | 24/7 during deployment |
| Product Owner | [Name] | +1-555-0102 | product@financialrise.com | On-call |
| QA Lead | [Name] | +1-555-0103 | qa-lead@financialrise.com | 24/7 during deployment |
| AWS Support | - | - | - | Premium support: 15min response |

**Escalation Path:**
1. Deployment Lead makes technical decisions
2. Escalate to Engineering Lead if uncertain
3. Escalate to Product Owner for go/no-go decisions
4. Contact AWS Support for infrastructure issues

---

## Post-Deployment

### 24-Hour Monitoring

**First 4 Hours (High Alert):**
- Monitor every 15 minutes
- Check error logs
- Watch user activity
- Be ready for immediate rollback

**Hours 4-24 (Moderate Alert):**
- Monitor every hour
- Review metrics trends
- Respond to user feedback
- Address non-critical issues

### Post-Deployment Review (48 hours after)

**Attendees:** Full team

**Agenda:**
1. What went well?
2. What could be improved?
3. Were rollback procedures adequate?
4. Update runbook based on learnings
5. Celebrate success!

---

**Production Deployment Runbook Version:** 1.0
**Owner:** DevOps Lead
**Last Updated:** 2025-12-22
**Next Review:** After first deployment
