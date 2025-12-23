# Financial RISE - Administrator Guide

**Version:** 1.0
**Date:** 2025-12-22
**Audience:** System Administrators

## Table of Contents

1. [Admin Panel Overview](#admin-panel-overview)
2. [User Management](#user-management)
3. [System Monitoring](#system-monitoring)
4. [Data Management](#data-management)
5. [Security Administration](#security-administration)
6. [Troubleshooting](#troubleshooting)
7. [Maintenance Tasks](#maintenance-tasks)

---

## Admin Panel Overview

### Accessing the Admin Panel

**URL:** `https://app.financialrise.com/admin`

**Requirements:**
- User account with `admin` role
- Valid JWT access token
- Two-factor authentication (2FA) enabled

**Login:**
1. Navigate to admin login page
2. Enter admin credentials
3. Complete 2FA verification
4. Access admin dashboard

### Dashboard Overview

The admin dashboard provides:
- **System Health** - Real-time status of all services
- **User Metrics** - Active users, registrations, activity
- **Assessment Stats** - Completions, pending, failed
- **System Alerts** - Critical issues requiring attention
- **Recent Activity** - Audit log of admin actions

---

## User Management

### Viewing Users

**Navigate to:** Admin > Users

**User List displays:**
- User ID, email, name
- Role (consultant, admin)
- Status (active, suspended, deleted)
- Registration date
- Last login
- Assessment count

**Filtering:**
- By role
- By status
- By registration date
- By activity (active/inactive)

**Search:**
- By email
- By name
- By company

### Creating Users

**Manual User Creation:**
1. Click "Create User" button
2. Fill in user details:
   - Email (required, unique)
   - First name (required)
   - Last name (required)
   - Company (optional)
   - Phone (optional)
   - Role (consultant/admin)
   - Send welcome email (checkbox)
3. Click "Create User"
4. System generates temporary password
5. User receives welcome email with login instructions

**Bulk User Import:**
1. Navigate to Admin > Users > Import
2. Download CSV template
3. Fill template with user data:
   ```csv
   email,firstName,lastName,company,phone,role
   jane@example.com,Jane,Consultant,ABC LLC,+1-555-0100,consultant
   john@example.com,John,Smith,XYZ Corp,+1-555-0200,consultant
   ```
4. Upload filled CSV
5. Review import preview
6. Confirm import
7. Users receive welcome emails

### Editing Users

**Update User Details:**
1. Navigate to user profile
2. Click "Edit" button
3. Modify fields:
   - Name
   - Company
   - Phone
   - Role (WARNING: changing to/from admin requires confirmation)
4. Save changes
5. User receives notification of changes

**Password Reset:**
1. Navigate to user profile
2. Click "Reset Password"
3. Choose method:
   - **Send reset email** - User receives password reset link
   - **Generate temporary password** - Admin gets temporary password to share
4. Confirm action
5. Log password reset in audit trail

### Suspending Users

**When to suspend:**
- Suspicious activity
- Terms of service violation
- Payment issues
- User request

**How to suspend:**
1. Navigate to user profile
2. Click "Suspend Account"
3. Enter reason (required)
4. Set suspension duration:
   - Indefinite
   - Until specific date
5. Confirm suspension
6. User cannot log in during suspension
7. User receives suspension notification

**Reactivating:**
1. Navigate to suspended user profile
2. Click "Reactivate Account"
3. Enter reason
4. Confirm reactivation
5. User receives reactivation email

### Deleting Users

**Soft Delete (Recommended):**
- User account disabled
- Data retained for compliance
- Can be restored if needed

**Steps:**
1. Navigate to user profile
2. Click "Delete Account"
3. Confirm understanding of data retention
4. Enter admin password for confirmation
5. User account marked as deleted
6. Data remains in database with `deleted_at` timestamp

**Hard Delete (Compliance Only):**
- **WARNING:** Permanently removes all user data
- Used only for GDPR/CCPA data deletion requests

**Steps:**
1. Verify legal requirement (e.g., GDPR request)
2. Export user data for compliance records
3. Navigate to Admin > Users > Deleted
4. Select user
5. Click "Permanently Delete"
6. Type "PERMANENTLY DELETE" to confirm
7. All user data removed from database
8. Action logged in compliance audit trail

---

## System Monitoring

### Health Check Dashboard

**Navigate to:** Admin > System > Health

**Services Monitored:**
- **Web Application** - Frontend availability
- **API Server** - Backend health
- **Database** - PostgreSQL connection, query performance
- **Cache** - Redis availability
- **Storage** - S3 bucket accessibility
- **Email** - SendGrid API status

**Status Indicators:**
- 🟢 **Healthy** - All systems operational
- 🟡 **Degraded** - Service experiencing issues but functional
- 🔴 **Down** - Service unavailable

**Automated Actions:**
- Unhealthy service triggers alert
- Email/SMS to on-call admin
- Automatic service restart attempted
- Incident ticket created

### Performance Metrics

**Navigate to:** Admin > System > Performance

**Key Metrics:**

| Metric | Target | Alert Threshold |
|--------|--------|-----------------|
| **API Response Time** | <500ms | >1000ms |
| **Page Load Time** | <3s | >5s |
| **Database Query Time** | <100ms | >500ms |
| **Report Generation** | <5s | >10s |
| **CPU Utilization** | <60% | >80% |
| **Memory Usage** | <70% | >85% |
| **Disk Usage** | <80% | >90% |

**Viewing Metrics:**
- Real-time dashboard (auto-refresh every 30s)
- Historical graphs (1h, 24h, 7d, 30d views)
- Export to CSV for analysis

**Performance Alerts:**
1. Metric exceeds threshold
2. Alert sent to admin email/SMS
3. Incident logged with timestamp
4. Remediation suggestions provided

### Error Tracking

**Navigate to:** Admin > System > Errors

**Error Log displays:**
- Timestamp
- Error type (API, Database, Frontend, etc.)
- Error message
- Stack trace
- User affected (if applicable)
- Request details
- Frequency count

**Filtering:**
- By severity (Critical, High, Medium, Low)
- By service (API, DB, Frontend)
- By time range
- By error type

**Error Actions:**
- Mark as resolved
- Assign to developer
- Create bug ticket
- Ignore (for known non-critical errors)

### User Activity Monitoring

**Navigate to:** Admin > System > Activity

**Activity Types Tracked:**
- User logins
- Assessment creations
- Assessment completions
- Report generations
- Report downloads
- Admin actions

**Suspicious Activity Alerts:**
- Multiple failed login attempts (>5 in 15 min)
- Rapid assessment creation (>10 in 1 hour)
- Unusual geographic login
- API rate limit violations

**Actions:**
- Review user account
- Suspend if necessary
- Contact user for verification
- Enable additional security measures

---

## Data Management

### Database Administration

**Navigate to:** Admin > Data > Database

**Database Statistics:**
- Total users
- Total assessments
- Total responses
- Total reports
- Database size
- Growth rate

**Maintenance Tasks:**

**1. Vacuum Database (Weekly):**
```sql
VACUUM ANALYZE;
```
- Reclaims storage
- Updates query planner statistics
- Recommended: Every Sunday at 2 AM

**2. Reindex Tables (Monthly):**
```sql
REINDEX TABLE users;
REINDEX TABLE assessments;
REINDEX TABLE responses;
```
- Rebuilds indexes for performance
- Recommended: First Sunday of month

**3. Update Statistics (Daily):**
```sql
ANALYZE;
```
- Updates query planner statistics
- Recommended: Daily at 1 AM

### Backup Management

**Navigate to:** Admin > Data > Backups

**Automated Backups:**
- **Daily:** Full database snapshot at 3 AM UTC
- **Retention:** 7 days
- **Storage:** AWS S3 with versioning
- **Testing:** Automated restore test weekly

**Manual Backup:**
1. Click "Create Backup"
2. Enter backup name
3. Select backup type:
   - Full database
   - Specific tables
   - Configuration only
4. Confirm backup
5. Download backup file (encrypted)

**Restore from Backup:**
1. Navigate to Admin > Data > Backups
2. Select backup to restore
3. Choose restore type:
   - **Full restore** - WARNING: Overwrites current data
   - **Partial restore** - Restore specific tables
   - **Test restore** - Restore to separate database
4. Confirm restore (requires password)
5. Monitor restore progress
6. Verify data after restore

### Data Export

**Navigate to:** Admin > Data > Export

**Export Options:**

**1. User Data:**
- All users or filtered subset
- Format: CSV, JSON
- Includes: Profile, settings, activity logs

**2. Assessment Data:**
- All assessments or filtered by date/status
- Format: CSV, JSON, Excel
- Includes: Responses, DISC results, phase results

**3. Analytics Data:**
- System usage statistics
- DISC distribution
- Phase distribution
- Completion rates

**Export Process:**
1. Select data type
2. Apply filters (date range, status, etc.)
3. Choose format
4. Click "Export"
5. Receive download link via email
6. Link expires in 24 hours

**Compliance Exports (GDPR/CCPA):**
1. Navigate to user profile
2. Click "Export User Data"
3. Generates complete data package
4. Includes all personal data, activity, assessments
5. Encrypted ZIP file sent to user email
6. Export logged for compliance

### Data Cleanup

**Navigate to:** Admin > Data > Cleanup

**Automated Cleanup Tasks:**

**1. Expired Assessments:**
- Delete assessments >90 days past expiry
- Runs daily at 4 AM
- Soft delete (recoverable for 30 days)

**2. Old Reports:**
- Delete report files >180 days old
- Database records retained
- Can regenerate if needed

**3. Session Data:**
- Clear expired sessions (>7 days)
- Clear expired tokens
- Runs daily at 5 AM

**Manual Cleanup:**
1. Review items for cleanup
2. Select items to delete
3. Confirm deletion
4. Monitor cleanup progress

---

## Security Administration

### Access Control

**Navigate to:** Admin > Security > Access

**Role Management:**

| Role | Permissions |
|------|-------------|
| **Admin** | Full system access, user management, system config |
| **Consultant** | Create assessments, view own data, generate reports |
| **Client** | Complete assigned assessment only |

**Viewing Permissions:**
1. Navigate to Admin > Security > Roles
2. Select role
3. View permission matrix
4. Modify permissions (requires super admin)

### Audit Logs

**Navigate to:** Admin > Security > Audit

**Logged Events:**
- User login/logout
- Password changes
- Role changes
- User creation/deletion
- System configuration changes
- Data exports
- Admin actions

**Audit Log Fields:**
- Timestamp
- User ID
- Action type
- Target (what was changed)
- Old value
- New value
- IP address
- User agent

**Retention:** 90 days (configurable for compliance)

**Searching Audit Logs:**
1. Navigate to Admin > Security > Audit
2. Apply filters:
   - Date range
   - User
   - Action type
   - IP address
3. Export results to CSV

### Security Settings

**Navigate to:** Admin > Security > Settings

**Password Policy:**
- Minimum length: 8 characters (configurable: 8-20)
- Require uppercase: Yes/No
- Require lowercase: Yes/No
- Require numbers: Yes/No
- Require special characters: Yes/No
- Password expiry: Never/30/60/90 days
- Password history: Prevent reuse of last N passwords (0-10)

**Session Settings:**
- Access token lifetime: 15 minutes (configurable: 5-60 min)
- Refresh token lifetime: 7 days (configurable: 1-30 days)
- Concurrent sessions: Allow/Disallow
- Max concurrent sessions: 3 (configurable: 1-10)

**Two-Factor Authentication:**
- Require for admins: Yes/No
- Require for consultants: Yes/No
- Allowed methods: SMS, TOTP app, Email
- Backup codes: Generate on enrollment

**IP Whitelisting (Optional):**
1. Navigate to Admin > Security > IP Whitelist
2. Add allowed IP ranges
3. Save configuration
4. Only whitelisted IPs can access admin panel

---

## Troubleshooting

### Common Issues

**1. User Cannot Login**

**Possible Causes:**
- Incorrect password
- Account suspended
- Account expired
- 2FA issue

**Diagnosis:**
1. Check user status (Admin > Users)
2. Check audit logs for failed login attempts
3. Verify email is correct
4. Check suspension status

**Resolution:**
- Reset password
- Reactivate account if suspended
- Disable 2FA temporarily
- Clear sessions

**2. Reports Not Generating**

**Possible Causes:**
- PDF generation service down
- S3 connection issue
- Incomplete assessment data
- Timeout

**Diagnosis:**
1. Check system health (Admin > System > Health)
2. Check error logs
3. Verify S3 bucket accessibility
4. Check Puppeteer service status

**Resolution:**
- Restart PDF generation service
- Verify AWS credentials
- Check assessment completeness
- Increase timeout limit

**3. Slow Performance**

**Possible Causes:**
- High database load
- Insufficient resources
- Inefficient queries
- Cache miss rate high

**Diagnosis:**
1. Check performance metrics
2. Review slow query log
3. Check CPU/memory usage
4. Review cache hit rate

**Resolution:**
- Add database indexes
- Increase server resources
- Optimize queries
- Clear and warm cache

### Support Escalation

**Level 1 (Admin):**
- User issues
- Basic troubleshooting
- Configuration changes

**Level 2 (DevOps):**
- Infrastructure issues
- Performance problems
- Deployment issues

**Level 3 (Engineering):**
- Code bugs
- Algorithm issues
- Database schema changes

**Escalation Process:**
1. Document issue thoroughly
2. Gather logs and error messages
3. Note troubleshooting steps taken
4. Create support ticket
5. Include relevant metrics/screenshots

---

## Maintenance Tasks

### Daily Tasks

- [ ] Review system health dashboard
- [ ] Check error logs for critical issues
- [ ] Monitor active user count
- [ ] Review failed login attempts
- [ ] Check backup status

### Weekly Tasks

- [ ] Review performance metrics
- [ ] Analyze user activity trends
- [ ] Check database size and growth
- [ ] Review and resolve pending errors
- [ ] Vacuum database (Sunday)

### Monthly Tasks

- [ ] Review security audit logs
- [ ] Update security policies if needed
- [ ] Reindex database tables
- [ ] Review and archive old data
- [ ] Test backup restoration
- [ ] Review user accounts (inactive, suspended)
- [ ] Update system documentation

### Quarterly Tasks

- [ ] Full security audit
- [ ] Review and update access controls
- [ ] Performance optimization review
- [ ] Disaster recovery drill
- [ ] Update admin team training
- [ ] Review compliance (GDPR, CCPA)

---

## Emergency Procedures

### System Outage

**Steps:**
1. Verify outage (check health dashboard)
2. Notify users via status page
3. Check CloudWatch alarms
4. Review error logs
5. Contact DevOps team
6. Document incident
7. Implement fix
8. Monitor recovery
9. Post-mortem analysis

### Data Breach

**Steps:**
1. Isolate affected systems
2. Notify security team immediately
3. Preserve evidence (logs, snapshots)
4. Assess scope of breach
5. Notify affected users (if required)
6. Implement remediation
7. File compliance reports (if required)
8. Conduct security review

### Database Corruption

**Steps:**
1. Stop all write operations
2. Assess corruption extent
3. Restore from latest backup
4. Verify data integrity
5. Resume operations
6. Investigate root cause
7. Implement preventive measures

---

**Admin Guide Version:** 1.0
**Last Updated:** 2025-12-22
**Emergency Contact:** admin-support@financialrise.com
**On-Call:** +1-555-ADMIN-24 (24/7)
