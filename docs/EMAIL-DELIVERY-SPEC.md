# Email Delivery Infrastructure - Technical Specification

**Version:** 1.0
**Date:** 2025-12-22
**Work Stream:** 29 - Email Delivery Infrastructure
**Phase:** 2 - Enhanced Engagement
**Dependency Level:** 0

## Table of Contents

1. [Overview](#overview)
2. [Email Service Selection](#email-service-selection)
3. [Email Authentication Setup](#email-authentication-setup)
4. [Email Template System](#email-template-system)
5. [Database Schema](#database-schema)
6. [API Specification](#api-specification)
7. [Template Library](#template-library)
8. [Implementation Guide](#implementation-guide)
9. [Testing Strategy](#testing-strategy)
10. [Monitoring & Deliverability](#monitoring--deliverability)

---

## Overview

### Purpose

The Email Delivery Infrastructure enables Financial RISE to send transactional and notification emails reliably, including assessment invitations, report delivery, and follow-up communications.

### Key Features

1. **Transactional Email Sending:**
   - Assessment invitations
   - Report delivery (consultant + client reports)
   - Password reset emails
   - Account notifications

2. **Template Management:**
   - Pre-designed email templates
   - Variable substitution (personalization)
   - DISC-adapted email copy
   - Brand customization support

3. **Deliverability:**
   - SPF, DKIM, DMARC configuration
   - Bounce and complaint handling
   - Email reputation monitoring
   - Unsubscribe management

4. **Tracking & Analytics:**
   - Delivery tracking
   - Open rate tracking (optional)
   - Click tracking for links
   - Bounce and complaint tracking

### Requirements

From Work Stream 29:
- Set up email service (SendGrid or AWS SES)
- Configure email templates
- Set up email sending infrastructure
- Configure SPF/DKIM/DMARC for deliverability
- Create email testing environment
- Document email configuration

---

## Email Service Selection

### Comparison: SendGrid vs AWS SES

| Feature | AWS SES | SendGrid |
|---------|---------|----------|
| **Cost** | $0.10 per 1,000 emails | $14.95/mo for 15k emails |
| **Setup Complexity** | Medium | Easy |
| **Template Engine** | Basic | Advanced |
| **Analytics** | Basic (via CloudWatch) | Advanced dashboard |
| **Deliverability Tools** | Good | Excellent |
| **AWS Integration** | Native | API |
| **SMTP Support** | ✅ | ✅ |
| **API** | ✅ | ✅ |
| **Webhooks** | SNS integration | Native webhooks |

### Recommendation: **AWS SES**

**Reasons:**
1. **Cost-Effective:** $10 per 100,000 emails vs SendGrid's tiered pricing
2. **AWS Integration:** Native integration with existing AWS infrastructure (S3, Lambda, SNS)
3. **Scalability:** Proven at scale, same infrastructure as Amazon.com
4. **Sufficient Features:** Template system adequate for our needs
5. **Region Support:** Can send from multiple regions for compliance

**When to Consider SendGrid:**
- Need advanced marketing email features
- Want sophisticated email analytics out-of-the-box
- Prefer simpler setup process
- Need A/B testing capabilities

---

## Email Authentication Setup

### SPF (Sender Policy Framework)

**Purpose:** Verifies that emails come from authorized servers

**DNS Record:**
```
Type: TXT
Name: @
Value: v=spf1 include:amazonses.com ~all
```

**For Custom Domain (financialrise.com):**
```
v=spf1 include:amazonses.com include:_spf.google.com ~all
```

### DKIM (DomainKeys Identified Mail)

**Purpose:** Cryptographically signs emails to prove authenticity

**Setup Steps:**
1. Request DKIM tokens from AWS SES
2. Add CNAME records to DNS

**Example DNS Records:**
```
Type: CNAME
Name: abc123def456._domainkey.financialrise.com
Value: abc123def456.dkim.amazonses.com

Type: CNAME
Name: xyz789ghi012._domainkey.financialrise.com
Value: xyz789ghi012.dkim.amazonses.com

Type: CNAME
Name: mno345pqr678._domainkey.financialrise.com
Value: mno345pqr678.dkim.amazonses.com
```

### DMARC (Domain-based Message Authentication)

**Purpose:** Tells receiving servers how to handle authentication failures

**DNS Record:**
```
Type: TXT
Name: _dmarc.financialrise.com
Value: v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@financialrise.com; ruf=mailto:dmarc-forensics@financialrise.com; pct=100
```

**DMARC Policy Options:**
- `p=none` - Monitor only (start here)
- `p=quarantine` - Send to spam if auth fails (recommended)
- `p=reject` - Reject if auth fails (aggressive)

### Return-Path (Bounce Handling)

**Purpose:** Designates where bounces should be sent

**DNS Record:**
```
Type: MX
Name: bounce.financialrise.com
Priority: 10
Value: feedback-smtp.us-east-1.amazonses.com
```

---

## Email Template System

### Template Engine

Use **Handlebars** for email templates (consistent with report generation).

### Template Structure

```
/email-templates/
├── layouts/
│   └── base.hbs                 # Base HTML layout
├── partials/
│   ├── header.hbs               # Email header with logo
│   ├── footer.hbs               # Email footer with unsubscribe
│   └── button.hbs               # Reusable button component
├── transactional/
│   ├── assessment-invitation.hbs
│   ├── assessment-reminder.hbs
│   ├── report-ready.hbs
│   ├── password-reset.hbs
│   ├── account-created.hbs
│   └── account-verification.hbs
└── notification/
    ├── client-started-assessment.hbs
    ├── client-completed-assessment.hbs
    └── scheduler-booking-confirmed.hbs
```

### Base Layout Template

**File:** `email-templates/layouts/base.hbs`

```handlebars
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{subject}}</title>
  <style>
    /* Email-safe CSS */
    body {
      margin: 0;
      padding: 0;
      font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
      font-size: 16px;
      line-height: 1.6;
      color: #333333;
      background-color: #f4f4f4;
    }
    .container {
      max-width: 600px;
      margin: 0 auto;
      background-color: #ffffff;
    }
    .header {
      background-color: #4B006E;
      padding: 20px;
      text-align: center;
    }
    .header img {
      max-width: 200px;
      height: auto;
    }
    .content {
      padding: 40px 30px;
    }
    .button {
      display: inline-block;
      padding: 14px 28px;
      background-color: #4B006E;
      color: #ffffff !important;
      text-decoration: none;
      border-radius: 4px;
      font-weight: bold;
      margin: 20px 0;
    }
    .button:hover {
      background-color: #3A0055;
    }
    .footer {
      background-color: #f9f9f9;
      padding: 20px;
      text-align: center;
      font-size: 12px;
      color: #666666;
    }
    .footer a {
      color: #4B006E;
      text-decoration: none;
    }
    @media only screen and (max-width: 600px) {
      .content {
        padding: 20px 15px;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    {{> header }}

    <div class="content">
      {{{body}}}
    </div>

    {{> footer }}
  </div>
</body>
</html>
```

### Header Partial

**File:** `email-templates/partials/header.hbs`

```handlebars
<div class="header">
  <img src="{{baseUrl}}/assets/logo-white.png" alt="Financial RISE" />
</div>
```

### Footer Partial

**File:** `email-templates/partials/footer.hbs`

```handlebars
<div class="footer">
  <p>
    <strong>Financial RISE</strong><br>
    Readiness Insights for Sustainable Entrepreneurship
  </p>
  <p>
    <a href="{{baseUrl}}">Visit our website</a> |
    <a href="{{baseUrl}}/privacy">Privacy Policy</a> |
    <a href="{{unsubscribeUrl}}">Unsubscribe</a>
  </p>
  <p style="color: #999999; font-size: 11px;">
    This email was sent to {{recipientEmail}}.<br>
    If you didn't expect this email, please ignore it.
  </p>
</div>
```

---

## Database Schema

### Table: `email_logs`

```sql
CREATE TABLE email_logs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

  -- Recipient info
  to_email VARCHAR(255) NOT NULL,
  to_name VARCHAR(200),
  from_email VARCHAR(255) NOT NULL,
  from_name VARCHAR(200),

  -- Email details
  subject VARCHAR(500) NOT NULL,
  template_name VARCHAR(100),
  template_version INT,
  template_variables JSONB, -- Variables used in template

  -- Tracking
  message_id VARCHAR(200), -- SES Message ID
  status VARCHAR(50) DEFAULT 'pending', -- 'pending', 'sent', 'delivered', 'bounced', 'complained', 'failed'
  sent_at TIMESTAMPTZ,
  delivered_at TIMESTAMPTZ,
  opened_at TIMESTAMPTZ,
  clicked_at TIMESTAMPTZ,
  bounced_at TIMESTAMPTZ,
  complained_at TIMESTAMPTZ,

  -- Error handling
  error_message TEXT,
  retry_count INT DEFAULT 0,
  max_retries INT DEFAULT 3,

  -- Context
  assessment_id UUID REFERENCES assessments(id) ON DELETE SET NULL,
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,

  -- Audit
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),

  CONSTRAINT email_logs_status_check CHECK (
    status IN ('pending', 'sent', 'delivered', 'bounced', 'complained', 'failed', 'opened', 'clicked')
  )
);

-- Indexes
CREATE INDEX idx_email_logs_to_email ON email_logs(to_email);
CREATE INDEX idx_email_logs_message_id ON email_logs(message_id);
CREATE INDEX idx_email_logs_status ON email_logs(status);
CREATE INDEX idx_email_logs_created_at ON email_logs(created_at);
CREATE INDEX idx_email_logs_assessment_id ON email_logs(assessment_id);
```

### Table: `email_templates`

```sql
CREATE TABLE email_templates (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

  -- Template metadata
  name VARCHAR(100) NOT NULL UNIQUE,
  subject VARCHAR(500) NOT NULL,
  description TEXT,
  category VARCHAR(50), -- 'transactional', 'notification', 'marketing'

  -- Template content
  html_template TEXT NOT NULL,
  text_template TEXT, -- Plain text version

  -- Versioning
  version INT DEFAULT 1,
  is_active BOOLEAN DEFAULT TRUE,

  -- Variables documentation
  required_variables TEXT[], -- Array of required variable names
  optional_variables TEXT[], -- Array of optional variable names
  sample_variables JSONB, -- Example variables for testing

  -- Audit
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  created_by UUID REFERENCES users(id),
  updated_by UUID REFERENCES users(id)
);

-- Indexes
CREATE INDEX idx_email_templates_name ON email_templates(name);
CREATE INDEX idx_email_templates_category ON email_templates(category);
CREATE INDEX idx_email_templates_active ON email_templates(is_active);
```

### Table: `email_unsubscribes`

```sql
CREATE TABLE email_unsubscribes (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

  email VARCHAR(255) NOT NULL UNIQUE,
  unsubscribed_at TIMESTAMPTZ DEFAULT NOW(),
  unsubscribe_reason TEXT,

  -- Allow re-subscription
  resubscribed_at TIMESTAMPTZ,

  -- Audit
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Index
CREATE INDEX idx_email_unsubscribes_email ON email_unsubscribes(email);
```

---

## API Specification

### Base URL

```
/api/v1/email
```

### Authentication

All endpoints require JWT authentication. Admin-only endpoints are marked.

---

### POST /email/send

**Description:** Send a transactional email using a template

**Auth:** Required (system/consultant/admin)

**Request:**

```http
POST /api/v1/email/send
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "to": {
    "email": "client@example.com",
    "name": "John Smith"
  },
  "template": "assessment-invitation",
  "variables": {
    "consultant_name": "Jane Doe",
    "client_name": "John Smith",
    "business_name": "ABC Corp",
    "assessment_url": "https://app.financialrise.com/client/assessments/abc123",
    "expiration_date": "2025-12-31"
  },
  "assessment_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
  "context": {
    "source": "manual_send",
    "ip_address": "192.168.1.1"
  }
}
```

**Response:** 200 OK

```json
{
  "success": true,
  "data": {
    "email_log_id": "e1f2g3h4-i5j6-7890-1234-567890abcdef",
    "message_id": "010001234567890a-12345678-1234-1234-1234-123456789abc-000000",
    "status": "sent",
    "sent_at": "2025-12-22T17:00:00Z"
  },
  "message": "Email sent successfully"
}
```

**Validation:**
- `to.email` required, valid email format
- `template` must exist in database
- All required variables for template must be provided
- Email must not be in unsubscribe list

**Error Responses:**
- `400 Bad Request` - Validation error or missing variables
- `403 Forbidden` - Email in unsubscribe list
- `500 Internal Server Error` - SES/SendGrid error

---

### POST /email/send-batch

**Description:** Send email to multiple recipients (max 50)

**Auth:** Required (consultant/admin)

**Request:**

```http
POST /api/v1/email/send-batch
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "template": "assessment-reminder",
  "recipients": [
    {
      "email": "client1@example.com",
      "name": "Client One",
      "variables": {
        "client_name": "Client One",
        "assessment_url": "https://app.financialrise.com/client/assessments/abc123"
      }
    },
    {
      "email": "client2@example.com",
      "name": "Client Two",
      "variables": {
        "client_name": "Client Two",
        "assessment_url": "https://app.financialrise.com/client/assessments/def456"
      }
    }
  ]
}
```

**Response:** 200 OK

```json
{
  "success": true,
  "data": {
    "total_sent": 2,
    "total_failed": 0,
    "sent_emails": [
      {
        "email": "client1@example.com",
        "message_id": "...",
        "status": "sent"
      },
      {
        "email": "client2@example.com",
        "message_id": "...",
        "status": "sent"
      }
    ],
    "failed_emails": []
  }
}
```

---

### GET /email/templates

**Description:** Get all email templates

**Auth:** Required (admin)

**Request:**

```http
GET /api/v1/email/templates
Authorization: Bearer <jwt_token>
```

**Response:** 200 OK

```json
{
  "success": true,
  "data": {
    "templates": [
      {
        "id": "t1a2b3c4-d5e6-7890-1234-567890abcdef",
        "name": "assessment-invitation",
        "subject": "{{consultant_name}} invited you to complete a financial assessment",
        "category": "transactional",
        "version": 2,
        "is_active": true,
        "required_variables": ["consultant_name", "client_name", "assessment_url"],
        "optional_variables": ["business_name", "expiration_date"]
      }
    ]
  }
}
```

---

### POST /email/templates

**Description:** Create or update an email template

**Auth:** Required (admin)

**Request:**

```http
POST /api/v1/email/templates
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "name": "new-template",
  "subject": "Subject line with {{variable}}",
  "category": "transactional",
  "html_template": "<html>...</html>",
  "text_template": "Plain text version...",
  "required_variables": ["variable1", "variable2"],
  "optional_variables": ["variable3"]
}
```

---

### POST /email/test

**Description:** Send a test email with sample variables

**Auth:** Required (admin)

**Request:**

```http
POST /api/v1/email/test
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "template": "assessment-invitation",
  "to_email": "test@financialrise.com"
}
```

**Response:** 200 OK

```json
{
  "success": true,
  "message": "Test email sent to test@financialrise.com",
  "preview_html": "<html>...</html>"
}
```

---

### GET /email/logs

**Description:** Get email sending logs

**Auth:** Required (consultant/admin)

**Request:**

```http
GET /api/v1/email/logs?assessment_id=abc123&status=delivered&limit=50
Authorization: Bearer <jwt_token>
```

**Response:** 200 OK

```json
{
  "success": true,
  "data": {
    "logs": [
      {
        "id": "e1f2g3h4-i5j6-7890-1234-567890abcdef",
        "to_email": "client@example.com",
        "subject": "Jane Doe invited you to complete a financial assessment",
        "template_name": "assessment-invitation",
        "status": "delivered",
        "sent_at": "2025-12-22T17:00:00Z",
        "delivered_at": "2025-12-22T17:00:15Z"
      }
    ],
    "total": 47
  }
}
```

---

## Template Library

### 1. Assessment Invitation

**File:** `email-templates/transactional/assessment-invitation.hbs`

**Subject:** `{{consultant_name}} invited you to complete a financial assessment`

**Template:**

```handlebars
<h2>Hi {{client_name}},</h2>

<p>
  <strong>{{consultant_name}}</strong> has invited you to complete a financial readiness assessment
  {{#if business_name}}for <strong>{{business_name}}</strong>{{/if}}.
</p>

<p>
  This assessment will help identify where your business stands financially and create a personalized action plan for growth.
</p>

<p>
  <strong>What to expect:</strong>
</p>
<ul>
  <li>Takes 30-45 minutes to complete</li>
  <li>Your progress is automatically saved</li>
  <li>All responses are confidential</li>
  <li>You'll receive a detailed action plan when complete</li>
</ul>

<p style="text-align: center;">
  <a href="{{assessment_url}}" class="button">Start Your Assessment</a>
</p>

{{#if expiration_date}}
<p style="font-size: 14px; color: #666666;">
  <em>Note: This invitation expires on {{expiration_date}}.</em>
</p>
{{/if}}

<p>
  Questions? Reply to this email to reach {{consultant_name}} directly.
</p>

<p>
  Best regards,<br>
  <strong>{{consultant_name}}</strong><br>
  via Financial RISE
</p>
```

---

### 2. Report Ready Notification

**File:** `email-templates/transactional/report-ready.hbs`

**Subject:** `Your Financial RISE Assessment Results are Ready`

**Template:**

```handlebars
<h2>Great news, {{client_name}}!</h2>

<p>
  Your financial readiness assessment has been completed and your personalized report is ready.
</p>

<p>
  <strong>{{consultant_name}}</strong> has reviewed your responses and prepared a customized action plan based on your business's current financial phase.
</p>

<p>
  <strong>Your report includes:</strong>
</p>
<ul>
  <li>Your current financial phase and what it means</li>
  <li>Personalized action items tailored to your situation</li>
  <li>Step-by-step guidance adapted to your communication style</li>
  <li>Resources to help you implement recommendations</li>
</ul>

<p style="text-align: center;">
  <a href="{{report_url}}" class="button">View Your Report</a>
</p>

{{#if scheduler_url}}
<p>
  Ready to discuss your results? <a href="{{scheduler_url}}">Schedule a follow-up call</a> with {{consultant_name}}.
</p>
{{/if}}

<p>
  Best regards,<br>
  <strong>{{consultant_name}}</strong>
</p>
```

---

### 3. Assessment Reminder

**File:** `email-templates/notification/assessment-reminder.hbs`

**Subject:** `Reminder: Complete your financial assessment`

**Template:**

```handlebars
<h2>Hi {{client_name}},</h2>

<p>
  Just a friendly reminder that you haven't finished your financial readiness assessment yet.
</p>

<p>
  <strong>Good news:</strong> Your progress has been saved! You can pick up right where you left off.
</p>

<p>
  <strong>Current progress:</strong> {{progress_percentage}}% complete ({{answered_questions}} of {{total_questions}} questions)
</p>

<p style="text-align: center;">
  <a href="{{assessment_url}}" class="button">Continue Assessment</a>
</p>

<p style="font-size: 14px; color: #666666;">
  <em>Reminder: This assessment will help {{consultant_name}} create a personalized action plan for your business.</em>
</p>

<p>
  Have questions? Reply to this email to reach {{consultant_name}}.
</p>
```

---

### 4. Password Reset

**File:** `email-templates/transactional/password-reset.hbs`

**Subject:** `Reset your Financial RISE password`

**Template:**

```handlebars
<h2>Password Reset Request</h2>

<p>
  We received a request to reset the password for your Financial RISE account ({{email}}).
</p>

<p style="text-align: center;">
  <a href="{{reset_url}}" class="button">Reset Your Password</a>
</p>

<p style="font-size: 14px; color: #666666;">
  This link will expire in 1 hour.
</p>

<p>
  <strong>Didn't request this?</strong> You can safely ignore this email. Your password will not change.
</p>

<p style="font-size: 12px; color: #999999;">
  For security reasons, we cannot send your password via email. You must click the link above to create a new password.
</p>
```

---

## Implementation Guide

### Step 1: AWS SES Setup

```bash
# Install AWS SDK
npm install @aws-sdk/client-ses

# Configure AWS credentials
aws configure
# AWS Access Key ID: YOUR_ACCESS_KEY
# AWS Secret Access Key: YOUR_SECRET_KEY
# Default region name: us-east-1
```

**Verify Email Addresses (Development):**

```bash
aws ses verify-email-identity --email-address noreply@financialrise.com
aws ses verify-email-identity --email-address support@financialrise.com
```

**Request Production Access:**

AWS SES starts in "sandbox mode" - limited to verified emails only.

1. Go to AWS Console → SES → Account Dashboard
2. Click "Request production access"
3. Fill out form with use case details
4. Wait for approval (usually 24-48 hours)

---

### Step 2: Configure SPF/DKIM/DMARC

**In AWS SES Console:**
1. Go to "Verified identities"
2. Select your domain (financialrise.com)
3. Click "Generate DKIM records"
4. Copy the 3 CNAME records

**In DNS Provider (Route 53, Cloudflare, etc.):**
1. Add the 3 DKIM CNAME records
2. Add SPF TXT record
3. Add DMARC TXT record
4. Wait for DNS propagation (up to 48 hours)

**Verify Configuration:**

```bash
# Check DKIM
aws ses get-identity-dkim-attributes --identities financialrise.com

# Check SPF
dig TXT financialrise.com +short

# Check DMARC
dig TXT _dmarc.financialrise.com +short
```

---

### Step 3: Create Email Service

**File:** `src/services/emailService.ts`

```typescript
import { SESClient, SendEmailCommand } from '@aws-sdk/client-ses';
import Handlebars from 'handlebars';
import fs from 'fs/promises';
import path from 'path';

const sesClient = new SESClient({ region: process.env.AWS_REGION || 'us-east-1' });

export class EmailService {
  private templatesCache: Map<string, HandlebarsTemplateDelegate> = new Map();
  private baseUrl: string;

  constructor() {
    this.baseUrl = process.env.APP_BASE_URL || 'https://app.financialrise.com';
  }

  async sendEmail(params: {
    to: { email: string; name?: string };
    template: string;
    variables: Record<string, any>;
    assessmentId?: string;
    userId?: string;
  }) {
    // Check unsubscribe list
    const isUnsubscribed = await this.checkUnsubscribe(params.to.email);
    if (isUnsubscribed) {
      throw new Error('Email address has unsubscribed');
    }

    // Load template
    const template = await this.loadTemplate(params.template);

    // Compile template with variables
    const html = await this.compileTemplate(template, params.variables);
    const subject = await this.compileSubject(template, params.variables);

    // Send via SES
    const messageId = await this.sendViaSES({
      to: params.to,
      subject,
      html
    });

    // Log email
    const emailLog = await this.logEmail({
      to_email: params.to.email,
      to_name: params.to.name,
      subject,
      template_name: params.template,
      message_id: messageId,
      assessment_id: params.assessmentId,
      user_id: params.userId,
      template_variables: params.variables
    });

    return {
      email_log_id: emailLog.id,
      message_id: messageId,
      status: 'sent'
    };
  }

  private async loadTemplate(templateName: string) {
    // Check cache
    if (this.templatesCache.has(templateName)) {
      return this.templatesCache.get(templateName)!;
    }

    // Load from database
    const template = await EmailTemplate.findOne({
      where: { name: templateName, is_active: true }
    });

    if (!template) {
      throw new Error(`Template not found: ${templateName}`);
    }

    // Compile with Handlebars
    const compiled = Handlebars.compile(template.html_template);

    // Cache it
    this.templatesCache.set(templateName, compiled);

    return template;
  }

  private async compileTemplate(
    template: any,
    variables: Record<string, any>
  ): Promise<string> {
    // Add global variables
    const allVariables = {
      ...variables,
      baseUrl: this.baseUrl,
      currentYear: new Date().getFullYear(),
      unsubscribeUrl: `${this.baseUrl}/unsubscribe?email=${encodeURIComponent(variables.recipientEmail || '')}`
    };

    // Load layout
    const layoutPath = path.join(__dirname, '../../email-templates/layouts/base.hbs');
    const layoutContent = await fs.readFile(layoutPath, 'utf-8');
    const layoutTemplate = Handlebars.compile(layoutContent);

    // Compile content
    const contentTemplate = Handlebars.compile(template.html_template);
    const content = contentTemplate(allVariables);

    // Render full email
    const html = layoutTemplate({
      ...allVariables,
      body: content,
      subject: template.subject
    });

    return html;
  }

  private async compileSubject(
    template: any,
    variables: Record<string, any>
  ): Promise<string> {
    const subjectTemplate = Handlebars.compile(template.subject);
    return subjectTemplate(variables);
  }

  private async sendViaSES(params: {
    to: { email: string; name?: string };
    subject: string;
    html: string;
  }): Promise<string> {
    const command = new SendEmailCommand({
      Source: `Financial RISE <noreply@financialrise.com>`,
      Destination: {
        ToAddresses: [
          params.to.name
            ? `${params.to.name} <${params.to.email}>`
            : params.to.email
        ]
      },
      Message: {
        Subject: {
          Data: params.subject,
          Charset: 'UTF-8'
        },
        Body: {
          Html: {
            Data: params.html,
            Charset: 'UTF-8'
          }
        }
      },
      Tags: [
        { Name: 'application', Value: 'financial-rise' },
        { Name: 'environment', Value: process.env.NODE_ENV || 'development' }
      ]
    });

    const response = await sesClient.send(command);
    return response.MessageId!;
  }

  private async logEmail(data: any) {
    return await EmailLog.create({
      ...data,
      status: 'sent',
      sent_at: new Date()
    });
  }

  private async checkUnsubscribe(email: string): Promise<boolean> {
    const unsubscribe = await EmailUnsubscribe.findOne({
      where: {
        email: email.toLowerCase(),
        resubscribed_at: null
      }
    });

    return !!unsubscribe;
  }
}
```

---

### Step 4: Set Up SNS for Bounce/Complaint Handling

**Create SNS Topic:**

```bash
aws sns create-topic --name ses-bounces-complaints
```

**Subscribe Lambda to SNS:**

**File:** `lambda/ses-webhook-handler.js`

```javascript
exports.handler = async (event) => {
  for (const record of event.Records) {
    const message = JSON.parse(record.Sns.Message);

    if (message.notificationType === 'Bounce') {
      await handleBounce(message.bounce);
    } else if (message.notificationType === 'Complaint') {
      await handleComplaint(message.complaint);
    }
  }
};

async function handleBounce(bounce) {
  // Update email log
  await fetch(`${process.env.API_URL}/internal/email/webhook/bounce`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(bounce)
  });
}

async function handleComplaint(complaint) {
  // Auto-unsubscribe on complaint
  await fetch(`${process.env.API_URL}/internal/email/webhook/complaint`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(complaint)
  });
}
```

---

## Testing Strategy

### Unit Tests

```typescript
describe('EmailService', () => {
  describe('sendEmail', () => {
    it('should send email via SES', async () => {
      const result = await emailService.sendEmail({
        to: { email: 'test@example.com', name: 'Test User' },
        template: 'assessment-invitation',
        variables: {
          consultant_name: 'Jane Doe',
          client_name: 'Test User',
          assessment_url: 'https://app.financialrise.com/assessments/123'
        }
      });

      expect(result.message_id).toBeTruthy();
      expect(result.status).toBe('sent');
    });

    it('should throw error for unsubscribed email', async () => {
      await EmailUnsubscribe.create({ email: 'unsubscribed@example.com' });

      await expect(
        emailService.sendEmail({
          to: { email: 'unsubscribed@example.com' },
          template: 'test',
          variables: {}
        })
      ).rejects.toThrow('Email address has unsubscribed');
    });
  });
});
```

---

## Monitoring & Deliverability

### Key Metrics

1. **Delivery Rate:** Target >99%
2. **Bounce Rate:** Keep <2%
3. **Complaint Rate:** Keep <0.1%
4. **Inbox Placement:** Target >90%

### CloudWatch Alarms

```bash
# Alarm for high bounce rate
aws cloudwatch put-metric-alarm \
  --alarm-name ses-high-bounce-rate \
  --metric-name Reputation.BounceRate \
  --namespace AWS/SES \
  --statistic Average \
  --period 3600 \
  --threshold 0.05 \
  --comparison-operator GreaterThanThreshold

# Alarm for high complaint rate
aws cloudwatch put-metric-alarm \
  --alarm-name ses-high-complaint-rate \
  --metric-name Reputation.ComplaintRate \
  --namespace AWS/SES \
  --statistic Average \
  --period 3600 \
  --threshold 0.001 \
  --comparison-operator GreaterThanThreshold
```

---

**Document Version:** 1.0
**Author:** DevOps Engineer
**Last Updated:** 2025-12-22
**Status:** Ready for Implementation
