# PII Logging Policy & Best Practices

**Version:** 1.0
**Date:** 2025-12-28
**Status:** PRODUCTION READY
**Work Stream:** 61 - PII Masking in Logs (HIGH-008)

## Table of Contents

1. [Overview](#overview)
2. [PII Categories](#pii-categories)
3. [Masking Requirements](#masking-requirements)
4. [Implementation Guidelines](#implementation-guidelines)
5. [Testing Requirements](#testing-requirements)
6. [Monitoring & Detection](#monitoring--detection)
7. [Compliance](#compliance)
8. [Code Examples](#code-examples)

---

## Overview

### Purpose

This document defines the organization's policy for handling Personally Identifiable Information (PII) in application logs. The policy ensures compliance with GDPR, CCPA, and other privacy regulations while maintaining sufficient logging for debugging and security monitoring.

### Scope

This policy applies to:
- All application logs (error, warning, info, debug, verbose)
- All backend services and APIs
- All environments (development, staging, production)
- All log destinations (console, files, cloud logging services)

### Zero Tolerance Policy

**NO PII MAY BE LOGGED IN PLAIN TEXT IN ANY ENVIRONMENT**

Violations of this policy constitute:
- GDPR Article 32 violation (Security of Processing)
- CCPA Section 1798.100 violation (Consumer Privacy Rights)
- Internal security policy breach

---

## PII Categories

### Category 1: Direct Identifiers (COMPLETE REDACTION REQUIRED)

These fields must NEVER appear in logs:

| PII Type | Examples | Masking Rule |
|----------|----------|--------------|
| **Passwords** | Any password field | `[REDACTED - PASSWORD]` |
| **Tokens** | JWT, API keys, session tokens | `[REDACTED - TOKEN]` |
| **SSN** | Social Security Numbers | `[REDACTED - SSN]` |
| **Tax ID** | EIN, TIN | `[REDACTED - SSN]` |
| **Financial Data** | Revenue, expenses, salaries | `[REDACTED - FINANCIAL]` |
| **DISC Scores** | D/I/S/C personality scores | `[REDACTED - PII]` (production) |
| **Physical Address** | Street addresses | `[REDACTED - ADDRESS]` |

### Category 2: Partial Identifiers (PARTIAL MASKING ALLOWED)

These fields may show limited information for debugging:

| PII Type | Examples | Masking Rule | Example Output |
|----------|----------|--------------|----------------|
| **Email** | user@example.com | Show domain only | `***@example.com` |
| **Phone** | (555) 123-4567 | Show last 4 digits | `***-***-4567` |
| **Credit Card** | 4532-1234-5678-9010 | Show last 4 digits | `****-****-****-9010` |
| **IP Address** | 192.168.1.100 | Show first octet (IPv4) | `192.*.*.*` |
| **Name** | John Doe | Show first letter | `J***` |

### Category 3: Non-PII (NO MASKING REQUIRED)

These fields may be logged without restriction:

- User IDs (UUIDs, database IDs)
- Assessment IDs
- Timestamps
- HTTP status codes
- Request methods (GET, POST, etc.)
- Resource paths (excluding query params)
- Error codes
- Feature flags
- Application version numbers

---

## Masking Requirements

### Automatic Masking

All logging MUST use one of the following approved methods:

#### Method 1: PIISafeLogger (RECOMMENDED)

```typescript
import { PIISafeLogger } from '@/common/utils';

export class MyService {
  private readonly logger = new PIISafeLogger(MyService.name);

  someMethod() {
    // Automatic PII sanitization
    this.logger.log('User logged in', {
      email: 'user@example.com',  // Automatically masked to ***@example.com
      password: 'secret123'         // Automatically masked to [REDACTED - PASSWORD]
    });
  }
}
```

#### Method 2: Manual Sanitization (When PIISafeLogger Cannot Be Used)

```typescript
import { LogSanitizer } from '@/common/utils';
import { Logger } from '@nestjs/common';

export class LegacyService {
  private readonly logger = new Logger(LegacyService.name);

  someMethod(userData: any) {
    // Manual sanitization required
    const sanitized = LogSanitizer.sanitizeObject(userData);
    this.logger.log('Processing user', sanitized);
  }
}
```

### Prohibited Practices

The following logging patterns are **STRICTLY FORBIDDEN**:

```typescript
// ❌ FORBIDDEN - Direct logging of user objects
this.logger.log('User data:', user);

// ❌ FORBIDDEN - Logging passwords/tokens
this.logger.debug(`Reset token: ${resetToken}`);

// ❌ FORBIDDEN - Logging financial data
this.logger.log(`Revenue: $${revenue}`);

// ❌ FORBIDDEN - Logging DISC scores
this.logger.debug(`DISC scores: ${JSON.stringify(scores)}`);

// ❌ FORBIDDEN - Using console.log directly
console.log('User email:', email);
```

---

## Implementation Guidelines

### 1. Logger Initialization

**Always use PIISafeLogger for new code:**

```typescript
import { Injectable } from '@nestjs/common';
import { PIISafeLogger } from '@/common/utils';

@Injectable()
export class UserService {
  // ✅ CORRECT
  private readonly logger = new PIISafeLogger(UserService.name);

  // ❌ INCORRECT
  // private readonly logger = new Logger(UserService.name);
}
```

### 2. Logging User Actions

```typescript
// ✅ CORRECT - Automatic sanitization
this.logger.log('Login attempt', {
  email: loginDto.email,           // Masked: ***@example.com
  ipAddress: req.ip,                // Masked: 192.*.*.*
  timestamp: new Date().toISOString()
});

// ❌ INCORRECT - Missing sanitization
this.logger.log(`User ${user.email} logged in from ${req.ip}`);
```

### 3. Error Logging

```typescript
// ✅ CORRECT - Error objects are automatically sanitized
try {
  await this.processPayment(paymentData);
} catch (error) {
  this.logger.error('Payment processing failed', {
    error: error.message,
    userId: user.id,  // UUID - safe to log
    // cardNumber is automatically masked
  });
}
```

### 4. Debug Logging

```typescript
// ✅ CORRECT - DISC scores masked in production
this.logger.debug('DISC calculation complete', {
  assessmentId: assessment.id,
  scores: discScores,  // Automatically masked to [REDACTED - PII] in production
  calculatedAt: new Date().toISOString()
});
```

### 5. Request/Response Logging

The `LoggingInterceptor` automatically sanitizes all HTTP requests/responses:

```typescript
// Already implemented - no additional work required
// See: src/common/interceptors/logging.interceptor.ts
```

---

## Testing Requirements

### Unit Tests

Every service that logs data MUST include tests verifying PII sanitization:

```typescript
describe('UserService Logging', () => {
  it('should not log passwords in plain text', () => {
    const consoleSpy = jest.spyOn(console, 'log');

    service.registerUser({
      email: 'test@example.com',
      password: 'SecureP@ss123!'
    });

    const logOutput = consoleSpy.mock.calls[0].join(' ');
    expect(logOutput).not.toContain('SecureP@ss123!');
    expect(logOutput).toContain('[REDACTED - PASSWORD]');
  });
});
```

### Integration Tests

Include PII masking tests in E2E test suites:

```typescript
it('should mask email in authentication error logs', async () => {
  const consoleSpy = jest.spyOn(console, 'error');

  await request(app.getHttpServer())
    .post('/auth/login')
    .send({ email: 'user@example.com', password: 'wrong' })
    .expect(401);

  const logOutput = consoleSpy.mock.calls.join(' ');
  expect(logOutput).not.toContain('user@example.com');
});
```

---

## Monitoring & Detection

### Automated PII Detection

Log analysis tools MUST be configured to detect PII leakage:

#### CloudWatch Logs (AWS)

```json
{
  "filterPattern": "[email_pattern = *@*.*, ssn_pattern = *-*-*, card_pattern = ****-****-****-****]",
  "metricName": "PII_Leakage_Detected",
  "metricValue": "1",
  "metricNamespace": "Security/Logging"
}
```

#### Regular Expression Patterns

The following regex patterns detect PII leakage:

```regex
Email:        \b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b
SSN:          \b\d{3}-\d{2}-\d{4}\b
Credit Card:  \b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b
Phone:        \b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b
IPv4:         \b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b
```

### Alert Configuration

Set up alerts for PII detection:

1. **Immediate Alerts** - Email/Slack notification on PII detection
2. **Daily Reports** - Summary of all PII detection events
3. **Weekly Audits** - Manual review of log samples

### Log Sampling

Perform weekly log sampling:

```bash
# Sample 1000 random log lines
gcloud logging read "resource.type=cloud_run_revision" \
  --limit=1000 \
  --format=json | \
  grep -E '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

# Should return 0 results
```

---

## Compliance

### GDPR Compliance

**Article 32 - Security of Processing:**

> "The controller and the processor shall implement appropriate technical and organizational measures to ensure a level of security appropriate to the risk, including inter alia as appropriate... (a) the pseudonymisation and encryption of personal data"

Our PII masking policy satisfies this requirement by:
- Automatic pseudonymisation of all PII in logs
- No personal data stored in log files
- Technical controls preventing PII logging

### CCPA Compliance

**Section 1798.100 - Consumer's Right to Know:**

Consumers have the right to know what personal information is being collected. Our logging policy ensures:
- No personal information is collected in logs beyond what's necessary
- Personal information in logs is anonymized
- Logs cannot be used to re-identify consumers

### Audit Trail

All PII masking must be auditable:

```typescript
// Log sanitization events (metadata only, no PII)
this.logger.log('User data sanitized for logging', {
  userId: user.id,
  fieldsRedacted: ['email', 'phone', 'ssn'],
  timestamp: new Date().toISOString()
});
```

---

## Code Examples

### Example 1: Authentication Service

```typescript
import { Injectable } from '@nestjs/common';
import { PIISafeLogger } from '@/common/utils';

@Injectable()
export class AuthService {
  private readonly logger = new PIISafeLogger(AuthService.name);

  async login(loginDto: LoginDto, ipAddress: string) {
    try {
      // ✅ Automatic PII sanitization
      this.logger.log('Login attempt', {
        email: loginDto.email,           // Masked: ***@example.com
        ipAddress: ipAddress,             // Masked: 192.*.*.*
        timestamp: new Date().toISOString()
      });

      const user = await this.validateUser(loginDto.email, loginDto.password);

      this.logger.log('Login successful', {
        userId: user.id,  // UUID - safe to log
        role: user.role
      });

      return this.generateTokens(user);
    } catch (error) {
      // ✅ Error automatically sanitized
      this.logger.error('Login failed', {
        error: error.message,
        email: loginDto.email  // Masked automatically
      });
      throw error;
    }
  }
}
```

### Example 2: Assessment Service

```typescript
import { Injectable } from '@nestjs/common';
import { PIISafeLogger } from '@/common/utils';

@Injectable()
export class AssessmentService {
  private readonly logger = new PIISafeLogger(AssessmentService.name);

  async calculateDISCProfile(assessmentId: string, responses: any[]) {
    const scores = this.discCalculator.calculate(responses);

    // ✅ DISC scores automatically masked in production
    this.logger.debug('DISC calculation complete', {
      assessmentId: assessmentId,
      scores: scores,  // Masked: [REDACTED - PII] in production
      responseCount: responses.length
    });

    return scores;
  }
}
```

### Example 3: Payment Service

```typescript
import { Injectable } from '@nestjs/common';
import { PIISafeLogger } from '@/common/utils';

@Injectable()
export class PaymentService {
  private readonly logger = new PIISafeLogger(PaymentService.name);

  async processPayment(paymentData: PaymentDto) {
    // ✅ Credit card and financial data automatically masked
    this.logger.log('Processing payment', {
      orderId: paymentData.orderId,
      cardNumber: paymentData.cardNumber,  // Masked: ****-****-****-9010
      amount: paymentData.amount,           // Masked: [REDACTED - FINANCIAL]
      email: paymentData.email              // Masked: ***@example.com
    });

    // ... payment processing logic
  }
}
```

---

## Migration Guide

### Migrating from Logger to PIISafeLogger

**Step 1: Import PIISafeLogger**

```typescript
// OLD
import { Logger } from '@nestjs/common';

// NEW
import { PIISafeLogger } from '@/common/utils';
```

**Step 2: Replace Logger Initialization**

```typescript
// OLD
private readonly logger = new Logger(MyService.name);

// NEW
private readonly logger = new PIISafeLogger(MyService.name);
```

**Step 3: Remove Manual Sanitization**

```typescript
// OLD
this.logger.log('User data', LogSanitizer.sanitizeObject(user));

// NEW (automatic sanitization)
this.logger.log('User data', user);
```

**Step 4: Test**

Run unit tests to verify PII masking works correctly.

---

## Incident Response

### If PII is Discovered in Logs

**Immediate Actions:**

1. **Stop Logging** - Disable the affected logger immediately
2. **Purge Logs** - Delete all log entries containing PII
3. **Notify** - Alert security team and DPO (Data Protection Officer)
4. **Assess** - Determine scope of PII exposure
5. **Remediate** - Fix code to prevent future exposure
6. **Document** - Create incident report

**Notification Requirements:**

- **GDPR:** Report breach to supervisory authority within 72 hours if high risk
- **CCPA:** Notify affected consumers without unreasonable delay

---

## References

- **GDPR Article 32:** Security of Processing
- **CCPA Section 1798.100:** Consumer's Right to Know
- **OWASP A09:2021:** Security Logging and Monitoring Failures
- **CWE-532:** Insertion of Sensitive Information into Log File
- **Work Stream 54:** Remove Sensitive Data from Logs (CRIT-002)
- **Work Stream 61:** PII Masking in Logs (HIGH-008)
- **Security Audit Report:** Lines 1080-1123

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-12-28 | TDD-Executor-WS61 | Initial version - Work Stream 61 |

---

**Questions or Concerns?**

Contact the Security Team at security@company.com or the Data Protection Officer at dpo@company.com
