# GDPR Article 18 - Right to Restriction of Processing

## Overview

GDPR Article 18 grants data subjects (users) the right to obtain from the controller (Financial RISE Report) the restriction of processing under certain circumstances. This document explains the implementation, usage, and legal requirements of this right.

## What is Restriction of Processing?

Restriction of processing means **marking stored personal data with the aim of limiting its processing in the future**. When processing is restricted:

- The data is **retained** (not deleted)
- The data can be **viewed** by the user
- The data can be **exported** by the user (Article 15)
- The data can be **deleted** by the user (Article 17)
- The data **cannot be processed** for other purposes (e.g., creating new assessments, analytics)

## When Can Users Request Restriction?

According to GDPR Article 18(1), users can request restriction when:

1. **Data Accuracy Contest**: The user contests the accuracy of the personal data, for a period enabling the controller to verify the accuracy
2. **Unlawful Processing**: The processing is unlawful and the user opposes the erasure of the data and requests restriction instead
3. **Data No Longer Needed**: The controller no longer needs the data for processing, but the user requires it for legal claims
4. **Objection to Processing**: The user has objected to processing pursuant to Article 21(1), pending verification whether the controller's legitimate grounds override the user's

## Implementation Architecture

### Database Schema

Two new fields added to the `users` table:

```sql
-- Boolean flag indicating if processing is restricted
processing_restricted BOOLEAN DEFAULT FALSE NOT NULL

-- Optional text explaining why the user restricted processing
restriction_reason TEXT NULL
```

### API Endpoints

#### 1. Restrict Processing
```
POST /api/users/:id/restrict-processing
Authorization: Bearer <jwt-token>
Content-Type: application/json

{
  "reason": "I am disputing the accuracy of my assessment data" // optional
}

Response:
{
  "id": "user-123",
  "email": "user@example.com",
  "processing_restricted": true,
  "restriction_reason": "I am disputing the accuracy of my assessment data",
  "updated_at": "2025-12-28T12:00:00Z"
}
```

#### 2. Lift Processing Restriction
```
DELETE /api/users/:id/restrict-processing
Authorization: Bearer <jwt-token>

Response:
{
  "id": "user-123",
  "email": "user@example.com",
  "processing_restricted": false,
  "restriction_reason": null,
  "updated_at": "2025-12-28T13:00:00Z"
}
```

#### 3. Get Processing Status
```
GET /api/users/:id/processing-status
Authorization: Bearer <jwt-token>

Response:
{
  "userId": "user-123",
  "processing_restricted": true,
  "restriction_reason": "I am disputing the accuracy of my assessment data",
  "last_updated": "2025-12-28T12:00:00Z",
  "gdpr_article": "Article 18 - Right to Restriction of Processing"
}
```

### Authorization Rules

- **Users** can only restrict/lift restriction on their **own account**
- **Admins** can restrict/lift restriction on **any account**
- All endpoints require JWT authentication

### Processing Restriction Guard

The `ProcessingRestrictionGuard` automatically blocks restricted users from certain actions.

#### Usage in Controllers:

```typescript
import { ProcessingRestrictionGuard } from '../../common/guards/processing-restriction.guard';
import { AllowWhenRestricted } from '../../common/decorators/allow-when-restricted.decorator';

// This endpoint will block restricted users
@UseGuards(JwtAuthGuard, ProcessingRestrictionGuard)
@Post('assessments')
async createAssessment() { ... }

// This endpoint will allow restricted users
@UseGuards(JwtAuthGuard, ProcessingRestrictionGuard)
@AllowWhenRestricted()
@Get('profile')
async getProfile() { ... }
```

#### What Gets Blocked?

When processing is restricted, users **CANNOT**:
- Create new assessments
- Update existing assessments
- Update client information in assessments
- Perform data analytics operations

#### What Remains Allowed?

When processing is restricted, users **CAN**:
- **View** their profile and data
- **Export** their data (GDPR Article 15)
- **Delete** their account (GDPR Article 17)
- **Update** their profile information (name, email, password)
- **Restrict** or **lift restriction** on their processing
- **Manage** processing objections (GDPR Article 21)

## Code Examples

### Example 1: User Restricts Processing

```typescript
// Frontend request
const response = await fetch('/api/users/user-123/restrict-processing', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    reason: 'I need to verify the accuracy of my assessment data'
  })
});

const data = await response.json();
console.log(data.processing_restricted); // true
```

### Example 2: Check if User is Restricted

```typescript
// In a service or guard
const isRestricted = await this.usersService.isProcessingRestricted('user-123');

if (isRestricted) {
  throw new ForbiddenException(
    'Your processing is restricted. You cannot perform this action.'
  );
}
```

### Example 3: Lift Restriction

```typescript
// Frontend request
const response = await fetch('/api/users/user-123/restrict-processing', {
  method: 'DELETE',
  headers: {
    'Authorization': `Bearer ${token}`
  }
});

const data = await response.json();
console.log(data.processing_restricted); // false
```

## Database Migration

To add restriction of processing support:

```bash
npm run migration:run
```

This runs migration `1735400000000-AddProcessingRestrictionFields.ts` which:
- Adds `processing_restricted` boolean column (default: false)
- Adds `restriction_reason` text column (nullable)
- Creates index on `processing_restricted` for performance

To rollback:

```bash
npm run migration:revert
```

## Testing

Comprehensive tests are available in:
- `src/modules/users/users-processing-restriction.spec.ts` (30+ tests)
- `src/common/guards/processing-restriction.guard.spec.ts` (15+ tests)

Run tests:

```bash
npm test users-processing-restriction
npm test processing-restriction.guard
```

## Compliance Notes

### GDPR Article 18 Requirements

1. **Restriction Duration**: We restrict processing for as long as the user requests
2. **Notification**: We should notify users before lifting restriction (if we initiate it)
3. **Third Parties**: If data was disclosed to third parties, we must inform them of restrictions (not applicable in our system)
4. **Information to User**: We inform users when restriction will be lifted

### Audit Trail

All processing restriction actions are automatically tracked via:
- `updated_at` timestamp on User entity
- Application logs (via logging interceptor)
- Future: Dedicated audit log table for GDPR actions

### User Rights Communication

Users must be informed of their right to restrict processing via:
1. **Privacy Policy** (updated in this implementation)
2. **Account Settings** page (UI should prominently display this option)
3. **Data Subject Rights** documentation

## Integration with Other GDPR Rights

Processing restriction works seamlessly with other GDPR rights:

- **Article 15 (Access)**: Users can export data even when restricted
- **Article 17 (Erasure)**: Users can delete account even when restricted
- **Article 20 (Portability)**: Data portability works during restriction
- **Article 21 (Objection)**: Separate but complementary right

## Error Handling

### Common Errors

1. **User Not Found** (404)
```json
{
  "statusCode": 404,
  "message": "User not found"
}
```

2. **Forbidden** (403) - Trying to restrict another user's account
```json
{
  "statusCode": 403,
  "message": "You can only restrict processing for your own account"
}
```

3. **Forbidden** (403) - Restricted user trying to create assessment
```json
{
  "statusCode": 403,
  "message": "Your account has restricted data processing. You cannot perform this action. You can still view, export, or delete your data. To perform this action, please lift the processing restriction first."
}
```

## Admin Override

Admins can restrict/lift restriction on any user account:

```typescript
// Admin request
POST /api/users/any-user-id/restrict-processing
Authorization: Bearer <admin-jwt-token>

{
  "reason": "Admin intervention: Data accuracy investigation"
}
```

This is useful for:
- Investigating data accuracy issues
- Responding to legal requests
- Compliance investigations

## Performance Considerations

- Index on `processing_restricted` column ensures fast queries
- Guard checks are cached within request lifecycle
- Minimal database overhead (single boolean check)

## Future Enhancements

1. **Email Notifications**: Notify users when restriction is applied/lifted
2. **Temporary Restrictions**: Auto-lift after specified duration
3. **Restriction History**: Track all restriction/lift events
4. **Third-party Notifications**: If we integrate with external systems
5. **Detailed Audit Log**: Dedicated table for GDPR actions

## References

- **GDPR Article 18**: https://gdpr-info.eu/art-18-gdpr/
- **ICO Guidance**: https://ico.org.uk/for-organisations/guide-to-data-protection/guide-to-the-general-data-protection-regulation-gdpr/individual-rights/right-to-restrict-processing/
- **EDPB Guidelines**: https://edpb.europa.eu/our-work-tools/general-guidance/gdpr-guidelines-recommendations-best-practices_en

## Support

For questions about restriction of processing:
- **Technical**: Contact development team
- **Legal**: Contact legal/compliance team
- **User Support**: support@financialrise.com

---

**Last Updated**: 2025-12-28
**Version**: 1.0
**Status**: Implementation Complete
