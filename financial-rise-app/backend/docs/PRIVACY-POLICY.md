# Privacy Policy
## Financial RISE Report - Readiness Insights for Sustainable Entrepreneurship

**Effective Date:** [To be determined upon deployment]
**Last Updated:** December 28, 2025

---

## 1. Introduction

This Privacy Policy describes how Financial RISE Report ("we," "our," or "us") collects, uses, discloses, and protects personal information when you use our web-based assessment platform (the "Service"). This policy complies with:

- **GDPR** (General Data Protection Regulation - EU Regulation 2016/679)
- **CCPA** (California Consumer Privacy Act - Cal. Civ. Code § 1798.100 et seq.)
- Applicable state privacy laws in all 50 U.S. states

By using the Service, you consent to the practices described in this Privacy Policy.

---

## 2. Information We Collect

### 2.1 Information You Provide Directly

**Consultant Account Information:**
- Email address (required for account creation)
- First and last name
- Password (stored as bcrypt hash - never in plaintext)
- Professional role (Consultant or Admin)

**Client Assessment Data (collected by consultants on behalf of clients):**
- Client name and business name
- Client email address
- Financial readiness assessment responses
- Business financial data (encrypted at rest with AES-256-GCM)
- DISC personality profile data (encrypted at rest)
- Consultant notes and observations

### 2.2 Automatically Collected Information

**Usage Data:**
- Login timestamps
- Assessment progress and completion dates
- IP addresses (masked in logs per GDPR requirements)
- Session activity logs

**Technical Data:**
- Browser type and version
- Device information
- Operating system

---

## 3. How We Use Your Information

### 3.1 Primary Purposes

We use collected information for the following purposes:

1. **Service Delivery:**
   - Authenticate user access
   - Generate personalized financial readiness reports
   - Calculate DISC personality profiles
   - Determine financial phase assessments

2. **Communication:**
   - Send assessment reports via email
   - Provide account notifications
   - Respond to support requests

3. **Security:**
   - Detect and prevent fraudulent activity
   - Protect against unauthorized access
   - Monitor for SQL injection and other attacks

4. **Compliance:**
   - Maintain audit logs as required by law
   - Respond to legal requests
   - Enforce terms of service

### 3.2 Legal Bases for Processing (GDPR)

We process personal data under the following legal bases:

- **Consent:** When you create an account or submit assessment data
- **Contract Performance:** To provide the Service you've requested
- **Legitimate Interests:** For security, fraud prevention, and service improvement
- **Legal Obligation:** To comply with applicable laws and regulations

---

## 4. Data Sharing and Disclosure

### 4.1 We Do NOT Sell Your Data

We do not sell, rent, or trade personal information to third parties for marketing purposes.

### 4.2 Limited Disclosure Scenarios

We may share data only in the following circumstances:

**Service Providers:**
- Cloud hosting infrastructure (e.g., AWS, Azure, Google Cloud)
- Email delivery services (for report distribution)
- Database hosting services (all data encrypted at rest)

**Legal Requirements:**
- To comply with court orders, subpoenas, or legal processes
- To protect our legal rights or the safety of others
- In response to lawful government requests

**Business Transfers:**
- In the event of a merger, acquisition, or sale of assets (with notice to affected users)

---

## 5. Data Security Measures

We implement industry-standard security practices to protect your data:

### 5.1 Encryption

- **At Rest:** AES-256-GCM encryption for financial data and DISC profiles
- **In Transit:** TLS 1.2+ encryption for all network communications
- **Database:** SSL/TLS connections to PostgreSQL with certificate validation

### 5.2 Access Controls

- Role-based access control (RBAC) - consultants can only access their own data
- JWT authentication with refresh token rotation
- Password requirements: 12+ characters, complexity enforced
- Account lockout after 5 failed login attempts (30-minute lockout)

### 5.3 Security Headers

- Content Security Policy (CSP) to prevent XSS attacks
- HSTS with preload (1-year max-age)
- X-Frame-Options: DENY (clickjacking protection)
- Permissions-Policy to restrict browser features

### 5.4 Monitoring & Auditing

- Comprehensive activity logging (with PII masking)
- SQL injection prevention (parameterized queries only)
- CSRF protection (double-submit cookie pattern)
- Rate limiting to prevent brute-force attacks

---

## 6. Data Retention

### 6.1 Retention Periods

- **Completed Assessments:** Retained for 2 years, then soft-deleted
- **Expired Reports:** Hard-deleted when expires_at date is reached
- **User Accounts:** Retained until user requests deletion
- **Audit Logs:** Retained for 7 years for compliance purposes

### 6.2 Automated Deletion

Our system runs automated data cleanup jobs daily at 2:00 AM UTC to:
- Soft-delete assessments older than 2 years
- Hard-delete expired reports
- Log all deletion actions for GDPR compliance

---

## 7. Your Privacy Rights

### 7.1 GDPR Rights (EU Users)

Under GDPR, you have the following rights:

**Article 15 - Right to Access:**
- Request a copy of all your personal data
- Endpoint: `GET /api/users/{id}/data-export`
- Export format: Machine-readable JSON

**Article 16 - Right to Rectification:**
- Request correction of inaccurate data
- Contact: [Support email to be provided]

**Article 17 - Right to Erasure ("Right to be Forgotten"):**
- Request deletion of your account and all related data
- Endpoint: `DELETE /api/users/{id}`
- Deletion type: Hard delete (permanent, irreversible)
- All cascading data deleted: assessments, responses, DISC profiles, phase results

**Article 18 - Right to Restriction of Processing:**
- Request temporary suspension of data processing
- Contact: [Support email to be provided]

**Article 20 - Right to Data Portability:**
- Receive your data in JSON format
- Transfer data to another service provider

**Article 21 - Right to Object:**
- Object to processing based on legitimate interests
- Contact: [Support email to be provided]

**Article 22 - Automated Decision-Making:**
- Right to human review of automated decisions
- Our DISC profiling includes human consultant oversight

### 7.2 CCPA Rights (California Residents)

Under CCPA, California residents have the following rights:

**Section 1798.100 - Right to Know:**
- Categories of personal information collected
- Purposes for which data is used
- Categories of third parties with whom data is shared

**Section 1798.105 - Right to Delete:**
- Request deletion of personal information
- Same endpoint as GDPR: `DELETE /api/users/{id}`

**Section 1798.115 - Right to Data Portability:**
- Request data in portable format (JSON)

**Section 1798.120 - Right to Opt-Out:**
- Opt out of sale of personal information (we don't sell data)

**Section 1798.125 - Non-Discrimination:**
- We will not discriminate against you for exercising your rights

### 7.3 How to Exercise Your Rights

**Self-Service Options:**
1. Log into your account
2. Navigate to Profile Settings
3. Use "Export My Data" button for data access
4. Use "Delete My Account" button for erasure

**Support Requests:**
- Email: [To be provided]
- Response time: Within 30 days (GDPR requirement)
- Verification required: Identity confirmation before processing requests

---

## 8. Consent Management

### 8.1 Consent Collection

We obtain explicit consent for:
- Account creation and data processing
- Email communications (reports, notifications)
- Storage of financial and DISC profile data

### 8.2 Consent Withdrawal

You may withdraw consent at any time by:
1. Deleting your account
2. Opting out of email communications
3. Contacting our support team

Withdrawal of consent does not affect the lawfulness of processing performed before withdrawal.

---

## 9. Children's Privacy

The Service is not intended for children under 18 years of age. We do not knowingly collect personal information from children. If we discover that we have inadvertently collected data from a child, we will delete it immediately.

---

## 10. International Data Transfers

### 10.1 Data Storage Location

Data is stored in [Region to be specified based on deployment - e.g., "US-West (Oregon)"]

### 10.2 EU-US Data Transfers

For EU users, we ensure adequate protection through:
- Standard Contractual Clauses (SCCs) approved by the European Commission
- Data Processing Agreements (DPAs) with all service providers
- Adherence to Privacy Shield principles (where applicable)

---

## 11. Data Breach Notification

### 11.1 Breach Response Procedures

In the event of a data breach, we will:

**Within 72 Hours (GDPR Requirement):**
1. Notify the appropriate supervisory authority
2. Document the breach (nature, affected data, estimated impact)
3. Begin remediation efforts

**Affected User Notification:**
- Notify affected users without undue delay
- Provide details: nature of breach, data affected, remediation steps
- Offer guidance on protective measures users can take

### 11.2 Breach Response Team

- **Incident Commander:** [To be assigned]
- **Technical Lead:** [To be assigned]
- **Legal Counsel:** [To be assigned]
- **Communications Lead:** [To be assigned]

---

## 12. Third-Party Links

The Service may contain links to third-party websites or services (e.g., external schedulers like Calendly). We are not responsible for the privacy practices of these third parties. We encourage you to review their privacy policies.

---

## 13. Do Not Track Signals

We respect Do Not Track (DNT) browser signals. When DNT is enabled, we:
- Limit analytics tracking
- Do not share data with third-party advertisers
- Reduce non-essential cookies

---

## 14. Cookies and Tracking

### 14.1 Essential Cookies

We use the following cookies necessary for service operation:
- **Session Cookie:** Authentication and session management (JWT)
- **CSRF Token Cookie:** Cross-site request forgery protection
- **Preference Cookie:** User interface preferences

### 14.2 Cookie Lifespan

- Session cookies: Deleted when browser closes
- Authentication tokens: 1-hour expiration (refresh tokens: 7 days)
- Preference cookies: 1 year

### 14.3 Cookie Control

You can control cookies through your browser settings. Note that disabling essential cookies may impair service functionality.

---

## 15. Privacy Policy Updates

### 15.1 Change Notification

We may update this Privacy Policy periodically. Changes will be communicated through:
- Email notification to all registered users
- Prominent notice on the Service homepage
- Updated "Last Updated" date at the top of this policy

### 15.2 Material Changes

For material changes (e.g., new data uses, increased sharing), we will:
- Provide 30 days' advance notice
- Request renewed consent where required by law
- Allow users to object or delete their accounts

---

## 16. Contact Information

### 16.1 Privacy Inquiries

For questions about this Privacy Policy or our data practices:

**Email:** [To be provided]
**Mailing Address:** [To be provided]

### 16.2 Data Protection Officer (DPO)

**Name:** [To be assigned]
**Email:** [To be provided]
**Responsibility:** GDPR compliance oversight

### 16.3 Supervisory Authority (EU Users)

If you are located in the EU and believe we have not adequately addressed your privacy concerns, you have the right to lodge a complaint with your local supervisory authority.

[List of EU Data Protection Authorities](https://edpb.europa.eu/about-edpb/board/members_en)

---

## 17. Jurisdiction-Specific Notices

### 17.1 California Residents (CCPA)

**Shine the Light Law:**
California residents may request information about disclosure of personal information to third parties for their direct marketing purposes (we do not engage in such disclosure).

**CCPA Metrics (Annual Reporting):**
We will publish annual statistics on:
- Number of access requests received and fulfilled
- Number of deletion requests received and fulfilled
- Average response time
- Number of requests denied

### 17.2 Nevada Residents

Nevada residents may opt out of the sale of personal information. As we do not sell personal information, this right is not applicable to our Service.

### 17.3 Oregon Residents

[Additional state-specific requirements to be added based on Oregon Consumer Privacy Act developments]

---

## 18. Accessibility

This Privacy Policy is available in accessible formats. For assistance, please contact: [Accessibility contact to be provided]

---

## 19. Acknowledgment and Consent

By using the Financial RISE Report service, you acknowledge that you have read, understood, and agree to this Privacy Policy.

**For Consultants:**
- I understand that I am responsible for obtaining proper consent from clients before collecting their data
- I will use client data only for the purpose of providing financial consulting services
- I will not share client data with unauthorized third parties

**For Clients:**
- I understand how my data will be collected, used, and protected
- I consent to the processing of my financial and personality assessment data
- I am aware of my rights to access, rectify, and delete my data

---

**Document Version:** 1.0
**Compliance Framework:** GDPR, CCPA, OWASP Privacy Best Practices
**Review Schedule:** Quarterly review, annual update
**Legal Review:** [To be completed before production deployment]

---

## Appendix A: Glossary of Terms

- **Personal Information (PI):** Any information relating to an identified or identifiable individual
- **Processing:** Any operation performed on personal data (collection, storage, use, disclosure, deletion)
- **Controller:** The entity that determines the purposes and means of processing (Financial RISE Report)
- **Processor:** Third-party service providers acting on our behalf
- **Data Subject:** The individual whose personal data is processed
- **Supervisory Authority:** Government body responsible for enforcing data protection laws
- **Consent:** Freely given, specific, informed, and unambiguous indication of agreement

---

## Appendix B: Data Inventory

### Personal Data Categories Collected

| Data Category | Examples | Purpose | Legal Basis | Retention |
|---------------|----------|---------|-------------|-----------|
| Account Data | Email, name, password | Authentication | Contract | Until deletion request |
| Financial Data | Revenue, expenses, debt | Assessment | Consent | 2 years |
| DISC Profile | Personality scores | Report generation | Consent | 2 years |
| Usage Data | Login times, IP addresses | Security | Legitimate interest | 90 days |
| Client Contact | Client name, email, business | Communication | Consent | 2 years |
| Audit Logs | Activity timestamps, actions | Compliance | Legal obligation | 7 years |

---

**END OF PRIVACY POLICY**
