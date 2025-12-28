# GDPR Article 21 - Right to Object to Processing

## Overview

GDPR Article 21 gives users the right to object to certain types of data processing. This document explains what the "Right to Object" means, what processing types users can object to, and how to use the API endpoints.

## What is the Right to Object?

The Right to Object (Article 21 GDPR) allows individuals to stop organizations from processing their personal data for specific purposes. This is a fundamental right that must be honored within one month of receiving the objection.

## Processing Types You Can Object To

The Financial RISE application supports objections to three types of processing:

### 1. Marketing (`marketing`)
**What this means:** Direct marketing communications, including promotional emails, newsletters, and product announcements.

**Effect of objection:**
- You will not receive any marketing emails
- Your email address will not be used for promotional purposes
- You will still receive transactional emails (password resets, assessment notifications, etc.)

**Example use case:** You use the Financial RISE tool but don't want to receive newsletters about new features or webinars.

### 2. Analytics (`analytics`)
**What this means:** Use of your data for analytics, statistics, and usage pattern analysis.

**Effect of objection:**
- Your usage data will not be included in aggregate statistics
- Your behavior will not be tracked for product improvement purposes
- Essential logging for security and debugging will continue

**Example use case:** You're concerned about privacy and don't want your data used to improve the product or generate usage statistics.

### 3. Profiling (`profiling`)
**What this means:** Automated decision-making and profiling based on your data.

**Effect of objection:**
- Your data will not be used for automated recommendations
- Profiling for personalized experiences will be disabled
- Core DISC assessment functionality will continue (this is essential service)

**Example use case:** You want to use the tool but don't want automated profiling beyond the core assessment service.

## Processing You CANNOT Object To

Under GDPR, certain processing is necessary and cannot be objected to:

1. **Authentication and Security**
   - Login credentials
   - Security monitoring and fraud detection
   - Audit logs for compliance

2. **Essential Service Functions**
   - Core assessment data storage
   - DISC profile calculations (this is the purpose of the service)
   - Report generation requested by you

3. **Legal Compliance**
   - Data retention required by law
   - Tax and financial record keeping
   - Compliance with court orders

4. **Contractual Obligations**
   - Processing necessary to provide the service you signed up for
   - Billing and payment processing

## API Endpoints

### 1. Create an Objection

**Endpoint:** `POST /api/users/:id/object-to-processing`

**Description:** Create a new objection to a specific processing type.

**Request:**
```json
{
  "objection_type": "marketing",
  "reason": "I do not wish to receive promotional emails or newsletters"
}
```

**Valid objection types:**
- `marketing`
- `analytics`
- `profiling`

**Response (201 Created):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "objection_type": "marketing",
  "reason": "I do not wish to receive promotional emails or newsletters",
  "created_at": "2024-12-28T10:30:00Z",
  "gdpr_article": "Article 21 - Right to Object"
}
```

**cURL Example:**
```bash
curl -X POST https://api.financialrise.com/users/123e4567-e89b-12d3-a456-426614174000/object-to-processing \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "objection_type": "marketing",
    "reason": "I do not wish to receive promotional emails"
  }'
```

**Error Responses:**

```json
// 400 Bad Request - Reason too short
{
  "statusCode": 400,
  "message": ["reason must be at least 10 characters long"],
  "error": "Bad Request"
}

// 400 Bad Request - Duplicate objection
{
  "statusCode": 400,
  "message": "Objection of this type already exists",
  "error": "Bad Request"
}

// 403 Forbidden - Trying to create objection for another user
{
  "statusCode": 403,
  "message": "You can only create objections for your own account",
  "error": "Forbidden"
}
```

### 2. View Your Objections

**Endpoint:** `GET /api/users/:id/objections`

**Description:** Retrieve all objections for a user account.

**Response (200 OK):**
```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "user_id": "123e4567-e89b-12d3-a456-426614174000",
    "objection_type": "marketing",
    "reason": "I do not wish to receive promotional emails",
    "created_at": "2024-12-28T10:30:00Z"
  },
  {
    "id": "660e9511-f39c-52e5-b827-557766551111",
    "user_id": "123e4567-e89b-12d3-a456-426614174000",
    "objection_type": "analytics",
    "reason": "I prefer not to have my usage data tracked",
    "created_at": "2024-12-28T11:00:00Z"
  }
]
```

**cURL Example:**
```bash
curl -X GET https://api.financialrise.com/users/123e4567-e89b-12d3-a456-426614174000/objections \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### 3. Withdraw an Objection

**Endpoint:** `DELETE /api/users/:id/objections/:objectionId`

**Description:** Withdraw (delete) a previously created objection. Once withdrawn, the system may resume the processing you had objected to.

**Response (200 OK):**
```json
{
  "deleted": true,
  "objectionId": "550e8400-e29b-41d4-a716-446655440000",
  "deletedAt": "2024-12-28T12:00:00Z",
  "gdpr_article": "Article 21 - Right to Object (Withdrawal)"
}
```

**cURL Example:**
```bash
curl -X DELETE https://api.financialrise.com/users/123e4567-e89b-12d3-a456-426614174000/objections/550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

**Error Responses:**

```json
// 404 Not Found - Objection doesn't exist
{
  "statusCode": 404,
  "message": "Objection not found",
  "error": "Not Found"
}

// 403 Forbidden - Trying to delete another user's objection
{
  "statusCode": 403,
  "message": "This objection does not belong to you",
  "error": "Forbidden"
}
```

## How Objections Are Enforced

The application automatically honors your objections across all relevant services:

### Marketing Objection
```typescript
// Before sending marketing email
const hasMarketingObjection = await usersService.hasObjection(
  userId,
  ObjectionType.MARKETING
);

if (hasMarketingObjection) {
  // Skip marketing email
  return;
}

// Send marketing email
await emailService.sendMarketingEmail(user);
```

### Analytics Objection
```typescript
// Before tracking analytics event
const hasAnalyticsObjection = await usersService.hasObjection(
  userId,
  ObjectionType.ANALYTICS
);

if (!hasAnalyticsObjection) {
  // Only track if user hasn't objected
  await analyticsService.trackEvent(userId, eventData);
}
```

### Profiling Objection
```typescript
// Before applying profiling
const hasProfilingObjection = await usersService.hasObjection(
  userId,
  ObjectionType.PROFILING
);

if (!hasProfilingObjection) {
  // Only profile if user hasn't objected
  await recommendationService.generateRecommendations(userId);
}
```

## Authentication & Authorization

- **Authentication Required:** All endpoints require a valid JWT token in the `Authorization` header.
- **User Access:** Users can only manage their own objections.
- **Admin Access:** Administrators can manage objections for any user (use with caution).

## Best Practices

1. **Be Specific in Reasons:** Provide clear reasons for your objections (minimum 10 characters).

2. **Review Periodically:** Your objections remain in effect indefinitely. Review them periodically to ensure they still match your preferences.

3. **Understand the Impact:** Some objections may limit functionality or personalization.

4. **Withdrawal is Easy:** You can withdraw any objection at any time if you change your mind.

## GDPR Compliance Notes

- **Processing Time:** Objections are processed immediately (better than the 1-month GDPR requirement).
- **No Cost:** Exercising your right to object is completely free.
- **No Adverse Consequences:** There are no negative consequences for objecting to processing.
- **Audit Trail:** All objections are logged with timestamps for compliance purposes.

## Related Rights

- **Article 15 - Right to Access:** Export all your data (`GET /users/:id/data-export`)
- **Article 17 - Right to Erasure:** Delete your account (`DELETE /users/:id`)
- **Article 18 - Right to Restriction:** Restrict processing temporarily (`POST /users/:id/restrict-processing`)

## Support

If you have questions about your right to object or need assistance:

- **Email:** privacy@financialrise.com
- **Privacy Policy:** https://financialrise.com/privacy
- **Data Protection Officer:** dpo@financialrise.com

## Technical Implementation

For developers implementing objection enforcement:

1. **Check Before Processing:** Always check for objections before performing optional processing.
2. **Use the Service Method:** Use `usersService.hasObjection(userId, type)` for consistent checking.
3. **Document Enforcement:** Document where and how objections are enforced in your code.
4. **Test Coverage:** Ensure tests verify that objections are properly honored.

## Version History

- **v1.0** (2024-12-28): Initial implementation of Article 21 - Right to Object
  - Support for marketing, analytics, and profiling objections
  - Full CRUD operations on objections
  - Automatic enforcement across application
