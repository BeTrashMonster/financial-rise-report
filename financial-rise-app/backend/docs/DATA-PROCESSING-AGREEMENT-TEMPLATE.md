# Data Processing Agreement (DPA)
## Financial RISE Report - Third-Party Service Providers

**Template Version:** 1.0
**Last Updated:** December 28, 2025
**GDPR Compliance:** Article 28 (Processor Obligations)

---

## PARTIES

This Data Processing Agreement ("DPA") is entered into by and between:

**DATA CONTROLLER:**
Financial RISE Report
[Address to be provided]
[Email to be provided]
("Controller")

**DATA PROCESSOR:**
[Service Provider Name]
[Service Provider Address]
[Service Provider Email]
("Processor")

**Effective Date:** [Date]

---

## RECITALS

WHEREAS, the Controller provides a web-based financial readiness assessment platform;

WHEREAS, the Processor provides [description of services: e.g., cloud hosting, email delivery, database management];

WHEREAS, in the course of providing services, the Processor will process personal data on behalf of the Controller;

WHEREAS, the parties wish to ensure compliance with the General Data Protection Regulation (GDPR), California Consumer Privacy Act (CCPA), and other applicable data protection laws;

NOW, THEREFORE, the parties agree as follows:

---

## 1. DEFINITIONS

### 1.1 Key Terms

**"Personal Data":** Any information relating to an identified or identifiable natural person as defined by GDPR Article 4(1).

**"Processing":** Any operation or set of operations performed on personal data, including collection, storage, use, disclosure, or deletion.

**"Data Subject":** An identified or identifiable natural person whose personal data is processed (consultants and clients using the Service).

**"Sub-Processor":** Any third party engaged by the Processor to process personal data on behalf of the Controller.

**"Data Breach":** A breach of security leading to accidental or unlawful destruction, loss, alteration, unauthorized disclosure of, or access to personal data.

**"Supervisory Authority":** An independent public authority established by an EU Member State to monitor GDPR compliance.

---

## 2. SCOPE AND PURPOSE

### 2.1 Data Categories

The Processor will process the following categories of personal data:

- **Account Information:** Email addresses, names, encrypted passwords
- **Financial Data:** Business revenue, expenses, debt levels (encrypted at rest)
- **DISC Personality Data:** Personality assessment scores (encrypted at rest)
- **Usage Metadata:** Login timestamps, IP addresses (masked), session data
- **Client Contact Data:** Client names, emails, business names

### 2.2 Data Subject Categories

- Financial consultants (service users)
- Business clients (assessment subjects)

### 2.3 Processing Activities

The Processor is authorized to perform the following processing activities:

- [X] Data storage and hosting
- [X] Data transmission and communication
- [X] Data backup and disaster recovery
- [ ] Data analytics and reporting
- [ ] Marketing communications
- [X] Security monitoring and threat detection

### 2.4 Processing Duration

Processing will continue for the duration of the service agreement and for [X] days thereafter for data retention and backup purposes.

---

## 3. PROCESSOR OBLIGATIONS

### 3.1 Instructions and Compliance

The Processor shall:

1. Process personal data only on documented instructions from the Controller
2. Not process data for any other purpose without prior written authorization
3. Comply with all applicable data protection laws (GDPR, CCPA, state privacy laws)
4. Immediately inform the Controller if instructions violate applicable law

### 3.2 Confidentiality

The Processor shall:

1. Ensure that all personnel authorized to process personal data are bound by confidentiality obligations
2. Implement "need-to-know" access controls
3. Conduct background checks on personnel with access to sensitive data
4. Provide annual data protection training to all relevant personnel

### 3.3 Security Measures (GDPR Article 32)

The Processor shall implement appropriate technical and organizational measures, including:

**Encryption:**
- AES-256-GCM encryption for data at rest
- TLS 1.2+ encryption for data in transit
- Encrypted database connections with certificate validation

**Access Controls:**
- Role-based access control (RBAC)
- Multi-factor authentication (MFA) for administrative access
- Regular access reviews and privilege audits
- Automatic session timeout after 30 minutes of inactivity

**Monitoring:**
- 24/7 intrusion detection and prevention systems
- Real-time security event logging and alerting
- Quarterly vulnerability assessments
- Annual penetration testing

**Business Continuity:**
- Daily automated backups (encrypted)
- Backup retention: 30 days (rolling)
- Disaster recovery plan with 4-hour RTO, 1-hour RPO
- Annual disaster recovery testing

### 3.4 Sub-Processing

The Processor may engage Sub-Processors only with:

1. **Prior Written Authorization:** Controller's approval required for each Sub-Processor
2. **Contractual Obligations:** Sub-Processors must be bound by substantially similar DPA terms
3. **Joint Liability:** Processor remains fully liable for Sub-Processor's processing

**Currently Authorized Sub-Processors:**

| Sub-Processor | Service | Location | Data Processed |
|---------------|---------|----------|----------------|
| [Name] | Cloud hosting | [Region] | All categories |
| [Name] | Email delivery | [Region] | Email addresses, names |
| [Name] | Database hosting | [Region] | All categories |

**Sub-Processor Change Notification:**
- The Processor will provide 30 days' advance notice of new Sub-Processors
- The Controller may object within 15 days
- If Controller objects, parties will negotiate alternative solutions

---

## 4. DATA SUBJECT RIGHTS

### 4.1 Assistance Obligations

The Processor shall assist the Controller in responding to data subject requests:

**GDPR Rights:**
- Article 15: Right to access
- Article 16: Right to rectification
- Article 17: Right to erasure
- Article 18: Right to restriction of processing
- Article 20: Right to data portability
- Article 21: Right to object

**CCPA Rights:**
- Section 1798.100: Right to know
- Section 1798.105: Right to delete
- Section 1798.115: Right to portability
- Section 1798.120: Right to opt-out

**Response Timeline:**
- Processor will provide assistance within 5 business days of Controller's request
- All necessary data provided in machine-readable format (JSON)

---

## 5. DATA BREACH NOTIFICATION

### 5.1 Notification Timeline

The Processor shall notify the Controller of any personal data breach:

**Within 24 Hours:**
1. Initial notification via email and phone
2. Preliminary assessment of breach scope and impact

**Within 72 Hours (GDPR Requirement):**
1. Detailed written report including:
   - Nature of the breach
   - Categories and approximate number of affected data subjects
   - Categories and approximate number of affected personal data records
   - Likely consequences of the breach
   - Measures taken or proposed to address the breach
   - Contact point for further information

### 5.2 Breach Investigation

The Processor shall:

1. Preserve all evidence related to the breach
2. Conduct a root cause analysis
3. Implement remediation measures
4. Provide regular updates to the Controller
5. Cooperate fully with any regulatory investigations

### 5.3 Breach Costs

Costs related to breach notification and remediation will be allocated as follows:
- **Processor fault:** Processor bears all costs
- **Controller fault:** Controller bears all costs
- **Force majeure:** Costs shared proportionally

---

## 6. DATA TRANSFERS

### 6.1 International Transfers

The Processor shall not transfer personal data outside the European Economic Area (EEA) or the United States without:

1. **Prior written consent** from the Controller
2. **Adequate safeguards** such as:
   - Standard Contractual Clauses (SCCs) approved by the European Commission
   - Binding Corporate Rules (BCRs)
   - Certification under an approved framework (e.g., EU-US Data Privacy Framework)

### 6.2 Transfer Documentation

For each international transfer, the Processor shall provide:
- Copy of applicable SCCs or other transfer mechanism
- Assessment of recipient country's data protection laws
- Description of supplementary measures (if required)

---

## 7. AUDITS AND INSPECTIONS

### 7.1 Audit Rights

The Controller (or an independent auditor) has the right to:

1. **Annual Audits:** Conduct one audit per year at no cost to Controller
2. **Ad-Hoc Audits:** Conduct additional audits in case of suspected non-compliance (costs borne by requesting party)
3. **Documentation Access:** Review policies, procedures, and security documentation
4. **Facility Inspections:** Inspect Processor's facilities and systems

### 7.2 Audit Logistics

**Notice Period:** 30 days' advance written notice (except in case of suspected breach: 24 hours)

**Scope:** Audits shall cover:
- Compliance with this DPA
- Security measures and controls
- Personnel training and background checks
- Sub-Processor management
- Incident response procedures

**Confidentiality:** Controller's auditors shall sign confidentiality agreements

**Remediation:** Processor shall address any identified deficiencies within 30 days (or timeline agreed by parties)

---

## 8. DATA RETURN AND DELETION

### 8.1 End of Processing

Upon termination or expiration of the service agreement, the Processor shall:

**Option 1 - Return Data (Controller's choice):**
1. Return all personal data to Controller in JSON format
2. Provide data within 30 days of termination
3. Include all backups and copies

**Option 2 - Delete Data (Controller's choice):**
1. Securely delete all personal data
2. Use methods ensuring data cannot be recovered:
   - Cryptographic erasure (destroy encryption keys)
   - Secure data wiping (DoD 5220.22-M standard)
   - Physical destruction of storage media (if applicable)
3. Provide written certification of deletion within 60 days

### 8.2 Legal Hold Exception

Data may be retained if required by law, subject to:
- Continued protection under this DPA
- Limitation of processing to what is legally required
- Notification to Controller of retention and duration

---

## 9. LIABILITY AND INDEMNIFICATION

### 9.1 Processor Liability

The Processor shall be liable for damages caused by:
- Processing in violation of GDPR Chapter V (data transfers)
- Processing not in accordance with Controller's lawful instructions
- Failure to implement appropriate security measures

### 9.2 Indemnification

The Processor shall indemnify and hold harmless the Controller against:
- Regulatory fines and penalties arising from Processor's non-compliance
- Third-party claims resulting from Processor's breach of this DPA
- Costs of data breach notification and credit monitoring services

**Indemnification Limit:** [To be negotiated - typically capped at service contract value or insurance coverage]

### 9.3 Insurance

The Processor shall maintain:
- Cyber liability insurance: Minimum $[Amount] per occurrence
- Errors and omissions insurance: Minimum $[Amount] per occurrence
- Proof of insurance provided annually to Controller

---

## 10. COMPLIANCE CERTIFICATIONS

### 10.1 Required Certifications

The Processor shall obtain and maintain the following certifications:

- [ ] ISO 27001 (Information Security Management)
- [ ] SOC 2 Type II (Security, Availability, Confidentiality)
- [ ] ISO 27018 (Cloud Privacy)
- [ ] PCI DSS (if processing payment data)
- [ ] HIPAA compliance (if processing health data)

**Certification Evidence:** Copies of current certificates provided annually

### 10.2 Compliance Monitoring

The Processor shall:
- Conduct annual third-party security audits
- Provide audit reports to Controller upon request
- Notify Controller of any certification lapses within 5 business days

---

## 11. TERM AND TERMINATION

### 11.1 Term

This DPA commences on the Effective Date and continues for the duration of the service agreement.

### 11.2 Termination for Cause

Either party may terminate this DPA immediately if:
- The other party materially breaches this DPA and fails to cure within 30 days
- The other party becomes insolvent or enters bankruptcy proceedings
- Continuing performance would violate applicable law

### 11.3 Effect of Termination

Upon termination:
1. Processor shall immediately cease all processing
2. Data return or deletion per Section 8
3. All confidentiality obligations survive termination
4. Sections 9 (Liability) and 11.3 (Effect of Termination) survive

---

## 12. GOVERNING LAW AND JURISDICTION

### 12.1 Governing Law

This DPA shall be governed by the laws of [Jurisdiction - e.g., "State of Oregon, United States"]

### 12.2 Dispute Resolution

**Step 1 - Negotiation:** Parties shall attempt to resolve disputes through good-faith negotiation (30 days)

**Step 2 - Mediation:** If unresolved, non-binding mediation under [Mediation Service] rules (60 days)

**Step 3 - Arbitration/Litigation:** If mediation fails, disputes shall be resolved through:
- [ ] Binding arbitration under [Arbitration Rules]
- [X] Litigation in the courts of [Jurisdiction]

### 12.3 Supervisory Authority Jurisdiction

Nothing in this DPA shall limit the jurisdiction or powers of any supervisory authority under GDPR.

---

## 13. AMENDMENTS

### 13.1 Changes to DPA

This DPA may be amended only by written agreement of both parties, except:

**Automatic Updates:** This DPA shall automatically update to reflect changes in:
- GDPR or other applicable data protection laws
- European Commission-approved Standard Contractual Clauses
- Supervisory authority guidance or decisions

**Notice of Changes:** Processor shall notify Controller of automatic updates within 10 days

---

## 14. ENTIRE AGREEMENT

This DPA constitutes the entire agreement between the parties regarding data processing and supersedes all prior discussions, agreements, or understandings.

**Conflict Resolution:** In case of conflict between this DPA and the service agreement, this DPA shall prevail on data protection matters.

---

## 15. SIGNATURE

**CONTROLLER:**

Signature: _______________________________
Name: [Printed Name]
Title: [Title]
Date: [Date]

**PROCESSOR:**

Signature: _______________________________
Name: [Printed Name]
Title: [Title]
Date: [Date]

---

## APPENDIX A: TECHNICAL AND ORGANIZATIONAL MEASURES

### A.1 Pseudonymization and Encryption
- AES-256-GCM encryption for financial data and DISC profiles
- TLS 1.2+ for data in transit
- Encrypted backups with separate key management

### A.2 Confidentiality
- Role-based access control (RBAC)
- Principle of least privilege
- Annual access reviews
- Confidentiality agreements for all personnel

### A.3 Integrity and Availability
- Daily automated backups
- Redundant infrastructure across multiple availability zones
- Load balancing and auto-scaling
- 99.9% uptime SLA

### A.4 Resilience
- Disaster recovery plan (4-hour RTO, 1-hour RPO)
- Annual DR testing
- Geographically distributed backups
- Incident response plan

### A.5 Testing and Evaluation
- Annual penetration testing
- Quarterly vulnerability scans
- Continuous security monitoring
- Regular security awareness training

---

## APPENDIX B: SUB-PROCESSOR LIST

| Sub-Processor | Service | Data Categories | Location | Date Approved |
|---------------|---------|----------------|----------|---------------|
| [Name] | Cloud Hosting | All | [Region] | [Date] |
| [Name] | Email Delivery | Contact data | [Region] | [Date] |
| [Name] | Database | All | [Region] | [Date] |

**Review Schedule:** Quarterly updates provided to Controller

---

## APPENDIX C: DATA SUBJECT REQUEST PROCEDURES

### C.1 Request Handling

**Receipt of Request:**
1. Controller forwards data subject request to Processor within 2 business days
2. Processor acknowledges receipt within 24 hours

**Data Retrieval:**
1. Processor retrieves all relevant data within 5 business days
2. Data provided in JSON format for portability
3. Decrypted financial and DISC data included

**Deletion Requests:**
1. Processor confirms identity verification with Controller
2. Hard delete executed within 5 business days
3. Written certification of deletion provided

**Timeline:** Total response time not to exceed 20 business days (to allow Controller to meet 30-day GDPR requirement)

---

**END OF DATA PROCESSING AGREEMENT**

**Document Control:**
- Version: 1.0
- Template Status: Ready for customization per service provider
- Legal Review Required: Yes (before execution)
- Next Review Date: [Quarterly]
