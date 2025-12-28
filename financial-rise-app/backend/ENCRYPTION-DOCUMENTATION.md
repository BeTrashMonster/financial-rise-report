# Financial RISE - Data Encryption Documentation

**Version:** 1.0
**Date:** 2025-12-28
**Security Finding:** CRIT-005 - Financial Data Encryption at Rest
**Reference:** SECURITY-AUDIT-REPORT.md Lines 983-1019
**Compliance:** GDPR Article 32, CCPA Section 1798.150

---

## Overview

This document provides comprehensive documentation for the encryption of financial personally identifiable information (PII) in the Financial RISE application. All client financial data is encrypted at rest using AES-256-GCM encryption to meet GDPR/CCPA compliance requirements.

## Encrypted Fields

### Assessment Responses

**Table:** `assessment_responses`
**Column:** `answer`
**Original Type:** JSONB
**Encrypted Type:** TEXT
**Encryption:** AES-256-GCM

**Data Classification:** Financial PII (Highly Sensitive)

**Contains:**
- Annual revenue figures
- Monthly/quarterly revenue breakdowns
- Business expenses (detailed and aggregated)
- Outstanding debt amounts
- Cash on hand/cash reserves
- Bank account balances
- Loan amounts and terms
- Credit card debt
- Employee salary information
- Tax identification numbers (if collected)
- Any other financial metrics submitted during assessment

**Example Encrypted Data:**
```
Original (JSONB):
{
  "annualRevenue": 500000,
  "monthlyExpenses": 40000,
  "outstandingDebt": 100000,
  "cashOnHand": 50000
}

Encrypted (TEXT):
a1b2c3d4e5f6g7h8:i9j0k1l2m3n4o5p6:q7r8s9t0u1v2w3x4y5z6...
Format: [IV:AuthTag:Ciphertext] (all hex-encoded)
```

## Encryption Specification

### Algorithm: AES-256-GCM

**Cipher:** Advanced Encryption Standard (AES)
**Mode:** Galois/Counter Mode (GCM)
**Key Size:** 256 bits (32 bytes)
**IV Size:** 128 bits (16 bytes)
**Authentication Tag:** 128 bits (16 bytes)

**Security Properties:**
- **Confidentiality:** AES-256 provides strong encryption (2^256 key space)
- **Integrity:** GCM mode provides built-in authentication tag
- **Authentication:** Detects any tampering with encrypted data
- **IV Randomness:** Unique IV generated for each encryption operation

### Encrypted Data Format

```
Structure: IV:AuthTag:Ciphertext
Encoding: Hexadecimal

Components:
- IV (32 hex chars)         = 16 bytes random initialization vector
- AuthTag (32 hex chars)    = 16 bytes GCM authentication tag
- Ciphertext (variable)     = Encrypted JSON payload

Example:
a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d:7e8f9a0b...
```

## Key Management

### Encryption Key Requirements

**Environment Variable:** `DB_ENCRYPTION_KEY`
**Format:** 64 hexadecimal characters (32 bytes)
**Minimum Entropy:** 256 bits

**Generation:**
```bash
# Generate cryptographically secure key
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### Key Storage (CRITICAL)

**NEVER:**
- ❌ Commit keys to version control
- ❌ Store keys in `.env` files checked into git
- ❌ Share keys via email or chat
- ❌ Store keys in application code
- ❌ Log keys to console or files

**ALWAYS:**
- ✅ Store in GCP Secret Manager (production)
- ✅ Use separate keys per environment (dev/staging/prod)
- ✅ Restrict access via IAM roles
- ✅ Enable audit logging for key access
- ✅ Rotate keys according to schedule (see Key Rotation)

### GCP Secret Manager Setup

```bash
# Create secret in GCP Secret Manager
gcloud secrets create financial-rise-db-encryption-key \
  --replication-policy="automatic" \
  --labels="app=financial-rise,environment=production"

# Store the key (replace YOUR_KEY with actual generated key)
echo -n "YOUR_64_CHAR_HEX_KEY" | \
  gcloud secrets versions add financial-rise-db-encryption-key --data-file=-

# Grant access to application service account
gcloud secrets add-iam-policy-binding financial-rise-db-encryption-key \
  --member="serviceAccount:financial-rise-prod@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

# Application loads key at startup
# (See backend/src/config/secrets.ts)
```

### Key Rotation

**Schedule:** Every 90 days (quarterly)

**Rotation Process:**

1. **Generate New Key**
   ```bash
   NEW_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
   echo "New key: $NEW_KEY"
   ```

2. **Store New Key in Secret Manager**
   ```bash
   gcloud secrets versions add financial-rise-db-encryption-key --data-file=<(echo -n "$NEW_KEY")
   ```

3. **Dual-Key Migration**
   - Keep both old and new keys active
   - Old key: for decryption only
   - New key: for new encryptions

4. **Run Migration Script**
   ```bash
   npm run migrate:re-encrypt -- --old-key=OLD_KEY --new-key=NEW_KEY
   ```

5. **Verify Migration**
   - Test random sample of records
   - Verify all data decrypts correctly
   - Check application logs for errors

6. **Disable Old Key**
   - Update application to use new key only
   - Archive old key for compliance retention

## Implementation Details

### EncryptedColumnTransformer Class

**Location:** `src/common/transformers/encrypted-column.transformer.ts`

**Methods:**
- `to(value: any): string | null` - Encrypts data before database storage
- `from(value: string | null): any` - Decrypts data when reading from database

**Usage in Entity:**
```typescript
import { EncryptedColumnTransformer } from '../../../common/transformers/encrypted-column.transformer';

@Entity('assessment_responses')
export class AssessmentResponse {
  @Column({
    type: 'text',
    transformer: new EncryptedColumnTransformer(),
  })
  answer: Record<string, any>;
}
```

### Database Migration

**Migration File:** `src/database/migrations/1735387200000-EncryptAssessmentResponsesAnswer.ts`

**Execution:**
```bash
# Run migration (requires DB_ENCRYPTION_KEY)
npm run migration:run

# Rollback migration (decrypts data back to JSONB)
npm run migration:revert
```

**Migration Process:**
1. Validates DB_ENCRYPTION_KEY is set
2. Creates new TEXT column (answer_encrypted)
3. Encrypts all existing JSONB data
4. Verifies all data migrated successfully
5. Drops old JSONB column
6. Renames encrypted column to 'answer'

**Rollback Process:**
1. Creates new JSONB column
2. Decrypts all TEXT data
3. Drops encrypted column
4. Restores original JSONB structure

## Testing

### Unit Tests

**Location:** `src/common/transformers/encrypted-column.transformer.spec.ts`

**Coverage:** 49 test cases covering:
- Encryption/decryption correctness
- Data type preservation
- Authentication tag validation
- IV randomness
- Tampering detection
- Performance benchmarks
- Edge cases

**Run Tests:**
```bash
npm test -- encrypted-column.transformer.spec.ts
```

### Integration Tests

**Location:** `src/modules/assessments/entities/assessment-response.encryption.spec.ts`

**Coverage:**
- End-to-end encryption through TypeORM
- Direct database verification
- JSONB-like query operations
- Data integrity checks
- Performance testing
- GDPR/CCPA compliance validation

**Run Tests:**
```bash
npm test -- assessment-response.encryption.spec.ts
```

### Manual Verification

**Verify Encryption in Database:**
```sql
-- Query encrypted data directly
SELECT id, answer FROM assessment_responses LIMIT 5;

-- Should return encrypted strings like:
-- a1b2c3d4e5f6a7b8:i9j0k1l2m3n4o5p6:q7r8s9t0u1v2w3x4...

-- Verify NO plaintext financial data visible
SELECT answer FROM assessment_responses WHERE answer LIKE '%revenue%';
-- Should return 0 rows

SELECT answer FROM assessment_responses WHERE answer LIKE '%500000%';
-- Should return 0 rows
```

**Verify Decryption Works:**
```typescript
// Through application (ORM decrypts automatically)
const response = await assessmentResponseRepo.findOne({
  where: { id: 'some-uuid' }
});

console.log(response.answer);
// Should log decrypted object:
// { annualRevenue: 500000, monthlyExpenses: 40000, ... }
```

## Performance Impact

### Benchmarks

**Encryption:**
- Single value: <10ms
- Large object (100 fields): <50ms
- Batch (100 records): <2000ms

**Decryption:**
- Single value: <5ms
- Large object (100 fields): <30ms
- Batch (100 records): <1000ms

**Database Impact:**
- Storage: +30% (encrypted TEXT vs JSONB)
- Query performance: Minimal (<5% overhead)
- Index performance: Not indexable (encrypted data)

**Optimization Notes:**
- Encryption is CPU-bound, scales linearly
- Consider caching decrypted data in memory
- Batch operations recommended for bulk updates

## Security Considerations

### Attack Surface

**Protected Against:**
- ✅ Database breach (data encrypted at rest)
- ✅ Backup theft (backups contain encrypted data)
- ✅ SQL injection (data still encrypted)
- ✅ Data tampering (authentication tag validation)
- ✅ Ciphertext reuse (unique IV per encryption)

**NOT Protected Against:**
- ❌ Application-level access (authorized users can decrypt)
- ❌ Memory dumps (decrypted data in RAM)
- ❌ Key compromise (all data decryptable)
- ❌ Side-channel attacks (timing, power analysis)

### Defense in Depth

Encryption is ONE layer of security. Also implement:
- JWT authentication (prevent unauthorized access)
- Row-level security (users can only access their data)
- Audit logging (track all PII access)
- Rate limiting (prevent brute force)
- CSRF protection (prevent unauthorized requests)
- Input validation (prevent injection attacks)

### Compliance Mapping

**GDPR Article 32 - Security of Processing:**
- ✅ Encryption of personal data (financial PII)
- ✅ Ability to ensure confidentiality (AES-256)
- ✅ Ability to ensure integrity (GCM authentication)
- ✅ Regular testing and evaluation (automated tests)

**CCPA Section 1798.150 - Security:**
- ✅ Reasonable security procedures implemented
- ✅ Encryption meets industry standards
- ✅ Regular security assessments conducted

## Troubleshooting

### Common Issues

**Error: "DB_ENCRYPTION_KEY must be 64 hex characters"**
- **Cause:** Missing or invalid encryption key
- **Solution:** Generate new key: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`
- **Set in environment:** `export DB_ENCRYPTION_KEY=<your-64-char-key>`

**Error: "Decryption failed: Data integrity check failed"**
- **Cause:** Data has been tampered with, or wrong encryption key
- **Solution:** Verify DB_ENCRYPTION_KEY matches the key used for encryption
- **Check:** Run `npm run verify:encryption-key`

**Error: "Migration failed at response ID xyz"**
- **Cause:** Corrupted data or insufficient permissions
- **Solution:** Check database logs, verify data integrity
- **Rollback:** `npm run migration:revert` (if safe)

**Performance Degradation**
- **Symptom:** Slow assessment response queries
- **Cause:** Encrypting/decrypting large datasets
- **Solution:** Implement caching, optimize batch operations
- **Monitor:** Check query execution times in logs

### Debugging

**Enable Encryption Debugging:**
```typescript
// src/common/transformers/encrypted-column.transformer.ts
export class EncryptedColumnTransformer {
  private debug = process.env.DEBUG_ENCRYPTION === 'true';

  to(value: any): string | null {
    if (this.debug) {
      console.log('[ENCRYPT] Input:', JSON.stringify(value).substring(0, 100));
    }
    // ... encryption logic
  }
}
```

**Run with debugging:**
```bash
DEBUG_ENCRYPTION=true npm start
```

## Incident Response

### Data Breach Scenario

**If encryption key is compromised:**

1. **Immediate Actions (0-1 hour)**
   - Rotate encryption key immediately
   - Revoke access to compromised key
   - Generate incident report

2. **Short-term (1-24 hours)**
   - Re-encrypt all data with new key
   - Notify security team
   - Review access logs for suspicious activity
   - Identify scope of breach

3. **Medium-term (24-72 hours)**
   - GDPR breach notification (if applicable)
   - User notification (if PII exposed)
   - Forensic analysis
   - Update security procedures

4. **Long-term (72+ hours)**
   - Post-incident review
   - Update key rotation procedures
   - Enhance monitoring
   - Security training for team

### Recovery Procedures

**Lost Encryption Key:**
- ⚠️ **CRITICAL:** If encryption key is lost, data is UNRECOVERABLE
- Always maintain secure backups of encryption keys
- Test recovery procedures quarterly

**Corrupted Encrypted Data:**
- Restore from database backup
- Re-run migration if necessary
- Verify data integrity after restoration

## Monitoring & Alerting

### Key Metrics to Track

```yaml
Encryption Metrics:
  - encryption_operations_total (counter)
  - decryption_operations_total (counter)
  - encryption_duration_seconds (histogram)
  - decryption_duration_seconds (histogram)
  - encryption_errors_total (counter)
  - decryption_errors_total (counter)

Key Management Metrics:
  - key_access_count (counter)
  - key_rotation_date (gauge)
  - key_age_days (gauge)

Database Metrics:
  - encrypted_rows_total (gauge)
  - unencrypted_rows_total (gauge - should be 0)
```

### Alerts

**Critical Alerts:**
- Decryption errors >1% of operations
- Encryption key access from unauthorized IP
- Key age >90 days (rotation overdue)
- Any unencrypted financial PII detected

**Warning Alerts:**
- Encryption performance >100ms (p95)
- Key age >75 days (rotation reminder)
- Unusual spike in encryption operations

## Maintenance

### Regular Tasks

**Weekly:**
- Review encryption error logs
- Monitor performance metrics
- Verify backup encryption key accessible

**Monthly:**
- Test decryption with backup key
- Review key access audit logs
- Update documentation if changes made

**Quarterly:**
- Rotate encryption keys
- Run comprehensive security tests
- Review and update this documentation

## References

- [NIST SP 800-38D - GCM Mode](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [GDPR Article 32 - Security of Processing](https://gdpr-info.eu/art-32-gdpr/)
- [CCPA Section 1798.150](https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.150)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)

---

**Document Owner:** Security Team
**Last Updated:** 2025-12-28
**Next Review:** 2026-03-28
**Classification:** Internal - Security Documentation
