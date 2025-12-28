# Financial RISE API - Encryption Guide

**Version:** 1.0
**Date:** 2025-12-28
**Audience:** API Consumers, Frontend Developers, Third-party Integrators

---

## Overview

The Financial RISE API implements end-to-end encryption for all financial personally identifiable information (PII). This guide explains how encryption affects API consumers and provides best practices for working with encrypted data.

## What's Encrypted?

### Assessment Response Answers

All answers submitted during financial assessments are encrypted at rest in the database.

**Endpoint:** `POST /api/assessments/:id/responses`

**Encrypted Fields:**
- `answer` - Contains financial data (revenue, expenses, debt, etc.)

**Example:**

```http
POST /api/assessments/123e4567-e89b-12d3-a456-426614174000/responses
Authorization: Bearer <jwt-token>
Content-Type: application/json

{
  "questionId": "annual_revenue",
  "answer": {
    "annualRevenue": 500000,
    "monthlyBreakdown": {
      "january": 45000,
      "february": 42000,
      ...
    }
  }
}
```

**What Happens:**
1. API receives plaintext JSON
2. Answer is validated
3. **Answer is encrypted** using AES-256-GCM
4. Encrypted data stored in database
5. Response returned to client

**Response:**
```json
{
  "id": "resp-uuid-123",
  "assessmentId": "123e4567-e89b-12d3-a456-426614174000",
  "questionId": "annual_revenue",
  "answer": {
    "annualRevenue": 500000,
    "monthlyBreakdown": { ... }
  },
  "answeredAt": "2025-12-28T10:30:00Z"
}
```

**Note:** The API response contains **decrypted** data. Encryption is transparent to API consumers.

## Encryption Transparency

### For API Consumers

**You DON'T need to:**
- ❌ Encrypt data before sending to API
- ❌ Decrypt data received from API
- ❌ Manage encryption keys
- ❌ Implement encryption logic

**API handles encryption automatically:**
- ✅ Data encrypted when stored
- ✅ Data decrypted when retrieved
- ✅ Encryption is transparent to clients
- ✅ No changes to API request/response format

### Example: Complete Flow

```typescript
// Frontend code - no encryption logic needed
async function saveAssessmentResponse(assessmentId, response) {
  const result = await fetch(
    `/api/assessments/${assessmentId}/responses`,
    {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        questionId: response.questionId,
        answer: response.answer, // Plaintext - API will encrypt
      }),
    }
  );

  const data = await result.json();
  // data.answer is plaintext - API decrypted it
  console.log(data.answer); // { annualRevenue: 500000, ... }
}
```

## Security Implications

### What's Protected

**Database Breach:**
- ✅ Financial data unreadable in database dumps
- ✅ Backup files contain encrypted data
- ✅ SQL injection won't expose plaintext

**Example - Database View:**
```sql
SELECT answer FROM assessment_responses LIMIT 1;

-- Returns encrypted ciphertext:
-- a1b2c3d4e5f6a7b8:i9j0k1l2m3n4o5p6:q7r8s9t0u1v2w3x4...
-- Not human-readable
```

### What's NOT Protected

**API Access:**
- ⚠️ Authorized users receive decrypted data
- ⚠️ API responses contain plaintext JSON
- ⚠️ Network traffic should use HTTPS

**Best Practices:**
- Always use HTTPS in production
- Protect JWT tokens (don't store in localStorage)
- Implement proper authentication
- Use CORS restrictions
- Enable rate limiting

## API Reference

### Encrypted Endpoints

#### Save Assessment Response

**Endpoint:** `POST /api/assessments/:id/responses`

**Request:**
```json
{
  "questionId": "string",
  "answer": {}, // Any JSON object - will be encrypted
  "notApplicable": false // optional
}
```

**Response:**
```json
{
  "id": "uuid",
  "assessmentId": "uuid",
  "questionId": "string",
  "answer": {}, // Decrypted
  "notApplicable": false,
  "answeredAt": "ISO-8601 timestamp"
}
```

**Encryption:** `answer` field encrypted at rest

---

#### Get Assessment Responses

**Endpoint:** `GET /api/assessments/:id/responses`

**Response:**
```json
[
  {
    "id": "uuid",
    "questionId": "string",
    "answer": {}, // Decrypted
    "answeredAt": "ISO-8601 timestamp"
  }
]
```

**Encryption:** All `answer` fields automatically decrypted

---

#### Update Assessment Response

**Endpoint:** `PATCH /api/assessments/:assessmentId/responses/:responseId`

**Request:**
```json
{
  "answer": {} // Updated answer - will be re-encrypted
}
```

**Response:**
```json
{
  "id": "uuid",
  "answer": {}, // Decrypted updated answer
  "answeredAt": "ISO-8601 timestamp"
}
```

**Encryption:** New answer encrypted, old answer overwritten

---

### Data Retention

**Deletion:** `DELETE /api/assessments/:id`

**Effect on Encrypted Data:**
- All assessment responses CASCADE deleted
- Encrypted data securely removed from database
- No remnants of financial PII remain

**GDPR Compliance:**
- Right to erasure (Article 17) implemented
- Data export available: `GET /api/users/:id/data-export`

## Performance Considerations

### Encryption Overhead

**Typical Performance:**
- Single response save: +5-10ms
- Batch save (10 responses): +50-80ms
- Single response retrieve: +2-5ms
- Assessment retrieve (all responses): +20-50ms

**Recommendations:**
- Use batch endpoints when available
- Cache assessment responses client-side
- Implement pagination for large result sets

### Rate Limits

Encryption adds minimal overhead. Standard rate limits apply:
- Login: 5 requests/minute
- Assessment operations: 100 requests/minute
- Report generation: 10 requests/hour

## Error Handling

### Encryption-Related Errors

#### 500 Internal Server Error - Encryption Failed

```json
{
  "statusCode": 500,
  "message": "Failed to process request",
  "error": "Internal Server Error"
}
```

**Causes:**
- Server encryption key misconfigured
- Disk space exhausted
- Database connection lost

**Client Action:**
- Retry request after 5 seconds
- Contact support if persists

---

#### 500 Internal Server Error - Decryption Failed

```json
{
  "statusCode": 500,
  "message": "Failed to retrieve data",
  "error": "Internal Server Error"
}
```

**Causes:**
- Data corruption
- Server key rotation in progress
- Database integrity issue

**Client Action:**
- Report to support immediately
- Do not retry (may indicate data issue)

## Testing

### Development Environment

**Test Encryption Key:**
- Development uses separate encryption key
- Safe to commit test data
- Production key NEVER in version control

**Local Testing:**
```bash
# Set test encryption key
export DB_ENCRYPTION_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

# Start development server
npm run start:dev
```

### Integration Testing

**Mock Encrypted Responses:**
```typescript
// No need to mock encryption - it's transparent
const mockResponse = {
  id: 'test-uuid',
  assessmentId: 'assessment-uuid',
  questionId: 'annual_revenue',
  answer: { revenue: 500000 }, // Plaintext in mock
  answeredAt: new Date().toISOString(),
};

// Test your component with plaintext data
```

## Migration Guide

### Upgrading from Unencrypted API

**Breaking Changes:** None

**Behavioral Changes:**
- Data stored encrypted (transparent to API)
- Performance: +5-10ms per operation
- No API contract changes

**Steps:**
1. Update to latest API version
2. No code changes required
3. Test existing integration
4. Deploy

## Compliance & Auditing

### GDPR Compliance

**Data Subject Rights:**
- Access: `GET /api/users/:id/data-export` (decrypted JSON)
- Rectification: `PATCH /api/assessments/:id/responses/:id`
- Erasure: `DELETE /api/assessments/:id`
- Portability: `GET /api/users/:id/data-export?format=json`

**Audit Trail:**
- All PII access logged
- Encryption operations monitored
- Available via audit log API (admin only)

### CCPA Compliance

**Consumer Rights:**
- Right to Know: `GET /api/users/:id/data`
- Right to Delete: `DELETE /api/users/:id`
- Right to Opt-Out: `POST /api/users/:id/opt-out`

## Support

### Troubleshooting

**Q: Why is my response save slower than before?**
A: Encryption adds 5-10ms. If significantly slower, check network latency.

**Q: Can I disable encryption for testing?**
A: No. Encryption is mandatory for PII protection.

**Q: How do I verify data is encrypted?**
A: Query database directly (requires admin access):
```sql
SELECT answer FROM assessment_responses LIMIT 1;
-- Should return encrypted string, not JSON
```

**Q: What happens if encryption key is lost?**
A: Data is unrecoverable. Keys are backed up securely by DevOps team.

### Contact

**API Issues:** api-support@financial-rise.com
**Security Questions:** security@financial-rise.com
**Emergency:** security-emergency@financial-rise.com

---

**Document Version:** 1.0
**Last Updated:** 2025-12-28
**Next Review:** 2026-01-28
