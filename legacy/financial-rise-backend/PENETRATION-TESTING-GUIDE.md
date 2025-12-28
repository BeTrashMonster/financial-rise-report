# Penetration Testing Guide - Financial RISE Backend

**Version:** 1.0
**Date:** 2025-12-22
**Purpose:** Comprehensive guide for security testing and penetration testing

---

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Automated Security Scanning](#automated-security-scanning)
4. [Manual Penetration Testing](#manual-penetration-testing)
5. [Security Test Cases](#security-test-cases)
6. [Reporting Vulnerabilities](#reporting-vulnerabilities)

---

## Overview

This guide provides comprehensive instructions for conducting security testing on the Financial RISE Backend API. All tests should be performed in a dedicated testing environment, never in production.

### Scope

- Authentication and authorization
- Input validation and sanitization
- Session management
- API security
- Data protection
- Infrastructure security

### Testing Principles

1. **Never test production** - Always use dedicated test environments
2. **Get authorization** - Ensure you have written permission before testing
3. **Document everything** - Record all findings and test procedures
4. **Responsible disclosure** - Report vulnerabilities privately to the security team

---

## Prerequisites

### Required Tools

```bash
# OWASP ZAP (Automated security scanner)
# Download from: https://www.zaproxy.org/download/

# Burp Suite Community (Manual testing)
# Download from: https://portswigger.net/burp/communitydownload

# curl (API testing)
curl --version

# SQLMap (SQL injection testing)
pip install sqlmap

# Node.js security tools
npm install -g retire
npm install -g snyk
```

### Test Environment Setup

```bash
# Clone repository
git clone <repository-url>
cd financial-rise-backend

# Install dependencies
npm install

# Set up test database
cp .env.example .env.test
# Configure test database in .env.test

# Start test server
npm run test:server
```

---

## Automated Security Scanning

### 1. OWASP ZAP Automated Scan

#### Basic Scan

```bash
# Start ZAP in daemon mode
zap.sh -daemon -port 8080 -config api.disablekey=true

# Run automated scan
zap-cli quick-scan http://localhost:3000

# Generate report
zap-cli report -o security-scan-report.html -f html
```

#### Advanced Scan with Authentication

```bash
# Create ZAP context configuration
cat > zap-context.conf <<EOF
{
  "context": {
    "name": "FinancialRISE",
    "includePaths": ["http://localhost:3000/api/.*"],
    "authentication": {
      "type": "json",
      "loginUrl": "http://localhost:3000/api/v1/auth/login",
      "loginRequestData": "{\"email\":\"test@example.com\",\"password\":\"Test123!\"}",
      "usernameParameter": "email",
      "passwordParameter": "password"
    }
  }
}
EOF

# Run authenticated scan
zap-cli --verbose active-scan \
  --scanners all \
  --recursive \
  http://localhost:3000/api/v1
```

### 2. npm audit

```bash
# Check for known vulnerabilities in dependencies
npm audit

# Fix automatically if possible
npm audit fix

# Generate detailed report
npm audit --json > npm-audit-report.json
```

### 3. Snyk Vulnerability Scan

```bash
# Test for vulnerabilities
snyk test

# Monitor project
snyk monitor

# Generate report
snyk test --json > snyk-report.json
```

### 4. Retire.js (JavaScript library vulnerabilities)

```bash
# Scan for vulnerable JavaScript libraries
retire --path ./public

# Generate JSON report
retire --path ./public --outputformat json > retire-report.json
```

---

## Manual Penetration Testing

### 1. SQL Injection Testing

#### Test Cases

**Test 1: Login Bypass**
```bash
# Attempt to bypass authentication with SQL injection
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@test.com'\'' OR 1=1 --",
    "password": "anything"
  }'

# Expected: Should return 400 Bad Request with validation error
```

**Test 2: Data Extraction**
```bash
# Attempt to extract data via UNION SELECT
curl -X GET "http://localhost:3000/api/v1/assessments?id=1 UNION SELECT * FROM users --"

# Expected: Should return 400 Bad Request or sanitized response
```

**Test 3: Blind SQL Injection**
```bash
# Time-based blind SQL injection
curl -X GET "http://localhost:3000/api/v1/users?search=test' AND SLEEP(5) --"

# Expected: Should not delay response, should sanitize input
```

#### Using SQLMap

```bash
# Test login endpoint
sqlmap -u "http://localhost:3000/api/v1/auth/login" \
  --data='{"email":"test@test.com","password":"test"}' \
  --method POST \
  --headers="Content-Type: application/json" \
  --level=5 \
  --risk=3

# Test GET parameters
sqlmap -u "http://localhost:3000/api/v1/assessments?id=1" \
  --cookie="session=<valid-session-cookie>" \
  --level=5 \
  --risk=3
```

### 2. Cross-Site Scripting (XSS) Testing

#### Test Cases

**Test 1: Reflected XSS**
```bash
# Attempt to inject script in query parameter
curl -X GET "http://localhost:3000/api/v1/search?q=<script>alert('XSS')</script>"

# Expected: Should escape < > characters
```

**Test 2: Stored XSS**
```bash
# Attempt to store malicious script in assessment
curl -X POST http://localhost:3000/api/v1/assessments \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "clientName": "<img src=x onerror=alert('XSS')>",
    "businessName": "Test Company"
  }'

# Expected: Should sanitize HTML tags
```

**Test 3: DOM-Based XSS**
```bash
# Attempt XSS via fragment identifier
curl -X GET "http://localhost:3000/api/v1/reports/1#<script>alert('XSS')</script>"

# Expected: Should not execute client-side
```

### 3. Cross-Site Request Forgery (CSRF) Testing

#### Test Case: State-Changing Request

```bash
# Attempt CSRF attack without CSRF token
curl -X DELETE http://localhost:3000/api/v1/assessments/1 \
  -H "Cookie: session=<valid-session-cookie>"

# Expected: Should return 403 Forbidden (CSRF token required)

# Attempt with mismatched CSRF token
curl -X DELETE http://localhost:3000/api/v1/assessments/1 \
  -H "Cookie: session=<valid-session-cookie>" \
  -H "X-CSRF-Token: invalid-token"

# Expected: Should return 403 Forbidden
```

### 4. Authentication Bypass Testing

#### Test Cases

**Test 1: JWT Token Manipulation**
```bash
# Attempt to use modified JWT token
curl -X GET http://localhost:3000/api/v1/users/me \
  -H "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJ1c2VySWQiOiIxMjMifQ."

# Expected: Should return 401 Unauthorized (algorithm: none not accepted)
```

**Test 2: Token Expiration**
```bash
# Use expired token
curl -X GET http://localhost:3000/api/v1/users/me \
  -H "Authorization: Bearer <expired-token>"

# Expected: Should return 401 Unauthorized (token expired)
```

**Test 3: Brute Force Protection**
```bash
# Attempt multiple failed logins
for i in {1..10}; do
  curl -X POST http://localhost:3000/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@test.com","password":"wrong'$i'"}'
  sleep 1
done

# Expected: Should rate limit after 5 attempts
```

### 5. Authorization Testing

#### Test Cases

**Test 1: Vertical Privilege Escalation**
```bash
# Regular user attempts to access admin endpoint
curl -X GET http://localhost:3000/api/v1/admin/users \
  -H "Authorization: Bearer <regular-user-token>"

# Expected: Should return 403 Forbidden
```

**Test 2: Horizontal Privilege Escalation**
```bash
# User A attempts to access User B's data
curl -X GET http://localhost:3000/api/v1/assessments/999 \
  -H "Authorization: Bearer <user-a-token>"

# Expected: Should return 403 Forbidden if assessment belongs to User B
```

**Test 3: Insecure Direct Object Reference (IDOR)**
```bash
# Attempt to access other user's assessment by ID
curl -X GET http://localhost:3000/api/v1/assessments/1 \
  -H "Authorization: Bearer <user-token>"

curl -X GET http://localhost:3000/api/v1/assessments/2 \
  -H "Authorization: Bearer <user-token>"

# Expected: Should only return assessments owned by the authenticated user
```

### 6. Input Validation Testing

#### Test Cases

**Test 1: Oversized Payloads**
```bash
# Send payload exceeding size limit
dd if=/dev/zero bs=1M count=20 | curl -X POST \
  http://localhost:3000/api/v1/assessments \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  --data-binary @-

# Expected: Should return 413 Payload Too Large
```

**Test 2: Invalid Data Types**
```bash
# Send string where number expected
curl -X POST http://localhost:3000/api/v1/assessments \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"clientId": "not-a-number"}'

# Expected: Should return 400 Bad Request with validation error
```

**Test 3: Null Byte Injection**
```bash
# Attempt null byte injection
curl -X POST http://localhost:3000/api/v1/assessments \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"clientName": "Test\u0000Admin"}'

# Expected: Should sanitize or reject null bytes
```

### 7. Rate Limiting Testing

#### Test Case: Verify Rate Limits

```bash
# Test authentication rate limit (5 per 15 min)
for i in {1..10}; do
  echo "Request $i"
  curl -X POST http://localhost:3000/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@test.com","password":"wrong"}'
  echo ""
done

# Expected: Should return 429 Too Many Requests after 5 attempts
```

### 8. Session Management Testing

#### Test Cases

**Test 1: Session Fixation**
```bash
# Attempt session fixation attack
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "Cookie: session=attacker-controlled-session" \
  -d '{"email":"victim@test.com","password":"password"}'

# Expected: Should generate new session ID after login
```

**Test 2: Session Timeout**
```bash
# Login and wait for session timeout
TOKEN=$(curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"Test123!"}' \
  | jq -r '.token')

# Wait 30 minutes
sleep 1800

# Attempt to use expired session
curl -X GET http://localhost:3000/api/v1/users/me \
  -H "Authorization: Bearer $TOKEN"

# Expected: Should return 401 Unauthorized
```

---

## Security Test Cases Checklist

### Authentication & Authorization

- [ ] SQL injection in login form
- [ ] Brute force protection on login
- [ ] Password complexity requirements
- [ ] Session timeout enforcement
- [ ] JWT token validation
- [ ] JWT algorithm confusion
- [ ] Token expiration handling
- [ ] Vertical privilege escalation
- [ ] Horizontal privilege escalation
- [ ] IDOR vulnerabilities
- [ ] Missing authorization checks

### Input Validation

- [ ] SQL injection (all input fields)
- [ ] XSS (reflected, stored, DOM-based)
- [ ] Command injection
- [ ] Path traversal
- [ ] File upload validation
- [ ] XML external entity (XXE)
- [ ] Server-side request forgery (SSRF)
- [ ] Header injection
- [ ] Null byte injection

### Session Management

- [ ] Session fixation
- [ ] Session timeout
- [ ] Secure cookie flags (HttpOnly, Secure, SameSite)
- [ ] CSRF protection
- [ ] Logout functionality

### API Security

- [ ] Rate limiting enforcement
- [ ] CORS policy validation
- [ ] Content-Type validation
- [ ] HTTP method validation
- [ ] API versioning
- [ ] Error message information disclosure

### Data Protection

- [ ] Sensitive data encryption at rest
- [ ] TLS/SSL configuration
- [ ] Password hashing (bcrypt)
- [ ] PII data handling
- [ ] Database encryption

### Infrastructure

- [ ] Security headers (CSP, HSTS, X-Frame-Options)
- [ ] Directory listing disabled
- [ ] Error page information leakage
- [ ] Server version disclosure
- [ ] Default credentials
- [ ] Unnecessary services running

---

## Reporting Vulnerabilities

### Severity Classification

| Severity | Criteria |
|----------|----------|
| **Critical** | Remote code execution, SQL injection with data access, authentication bypass |
| **High** | Privilege escalation, stored XSS, sensitive data exposure |
| **Medium** | CSRF, reflected XSS, information disclosure |
| **Low** | Security misconfiguration, missing security headers |
| **Info** | Best practice violations, informational findings |

### Report Template

```markdown
## Vulnerability Report

**Title:** [Brief description]
**Severity:** [Critical/High/Medium/Low/Info]
**Date Found:** [YYYY-MM-DD]
**Tester:** [Name]

### Description
[Detailed description of the vulnerability]

### Steps to Reproduce
1. [Step 1]
2. [Step 2]
3. [Step 3]

### Proof of Concept
[Include request/response, screenshots, or code]

### Impact
[Describe potential business and technical impact]

### Remediation
[Recommended fix]

### References
[OWASP link, CVE, etc.]
```

---

## Best Practices

1. **Test Responsibly**
   - Only test authorized systems
   - Respect rate limits
   - Clean up test data

2. **Documentation**
   - Record all test procedures
   - Document findings immediately
   - Include reproduction steps

3. **Communication**
   - Report critical issues immediately
   - Use secure channels for reporting
   - Follow responsible disclosure

4. **Continuous Testing**
   - Integrate automated scans in CI/CD
   - Perform manual tests before releases
   - Re-test after remediation

---

## Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/)
- [Burp Suite Documentation](https://portswigger.net/burp/documentation)
- [JWT Security Best Practices](https://tools.ietf.org/html/rfc8725)

---

**Document Version:** 1.0
**Last Updated:** 2025-12-22
**Next Review:** 2026-03-22
