# Consent Management Guide

## Overview

The Consent Management system provides granular privacy controls for users to manage how their data is processed. This implementation follows GDPR requirements for consent management, including:

- **Transparent consent requests** with clear explanations
- **Granular controls** for different types of data processing
- **Audit trail** with timestamps, IP addresses, and user agents
- **Easy withdrawal** of consent at any time
- **Immutable history** of all consent changes

## Consent Types

The system supports three types of consent:

### 1. Essential Consent
- **Type:** `essential`
- **Required:** Yes (cannot be disabled)
- **Purpose:** Necessary for the application to function
- **Includes:**
  - User authentication and session management
  - Core assessment functionality
  - Report generation
  - Account management

### 2. Analytics Consent
- **Type:** `analytics`
- **Required:** No (optional)
- **Purpose:** Improve application performance and user experience
- **Includes:**
  - Anonymous usage statistics
  - Performance monitoring
  - Error tracking and reporting
  - Feature usage analytics

### 3. Marketing Consent
- **Type:** `marketing`
- **Required:** No (optional)
- **Purpose:** Send promotional and educational communications
- **Includes:**
  - Product updates and feature announcements
  - Educational content and best practices
  - Promotional offers and discounts
  - Newsletter subscriptions

## Architecture

### Database Schema

**Table:** `user_consents`

```sql
CREATE TABLE user_consents (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  consent_type ENUM('essential', 'analytics', 'marketing') NOT NULL,
  granted BOOLEAN NOT NULL DEFAULT false,
  ip_address VARCHAR(45) NULL,  -- Supports IPv6
  user_agent TEXT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

  INDEX idx_user_consent_type (user_id, consent_type),
  INDEX idx_consents_created_at (created_at)
);
```

### Entity: UserConsent

**Location:** `src/modules/consents/entities/user-consent.entity.ts`

```typescript
export enum ConsentType {
  ESSENTIAL = 'essential',
  ANALYTICS = 'analytics',
  MARKETING = 'marketing',
}

@Entity('user_consents')
export class UserConsent {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  user_id: string;

  @Column({ type: 'enum', enum: ConsentType })
  consent_type: ConsentType;

  @Column({ type: 'boolean', default: false })
  granted: boolean;

  @Column({ type: 'varchar', length: 45, nullable: true })
  ip_address: string | null;

  @Column({ type: 'text', nullable: true })
  user_agent: string | null;

  @CreateDateColumn()
  created_at: Date;

  @UpdateDateColumn()
  updated_at: Date;
}
```

## API Endpoints

### 1. Get All Consents

**Endpoint:** `GET /api/users/:id/consents`

**Description:** Retrieve all consent records for a user (all types, full history)

**Authentication:** Required (JWT)

**Authorization:** Users can only access their own consents unless they are admin

**Response:**
```json
[
  {
    "id": "uuid",
    "user_id": "uuid",
    "consent_type": "analytics",
    "granted": true,
    "ip_address": "192.168.1.1",
    "user_agent": "Mozilla/5.0...",
    "created_at": "2024-01-15T10:30:00Z",
    "updated_at": "2024-01-15T10:30:00Z"
  }
]
```

### 2. Update Consent

**Endpoint:** `PATCH /api/users/:id/consents/:type`

**Description:** Update consent for a specific type (creates new audit record)

**Authentication:** Required (JWT)

**Authorization:** Users can only update their own consents unless they are admin

**Parameters:**
- `id` (path): User ID
- `type` (path): Consent type (`essential`, `analytics`, `marketing`)

**Request Body:**
```json
{
  "granted": true
}
```

**Response:**
```json
{
  "id": "uuid",
  "user_id": "uuid",
  "consent_type": "analytics",
  "granted": true,
  "ip_address": "192.168.1.1",
  "user_agent": "Mozilla/5.0...",
  "created_at": "2024-01-15T10:35:00Z",
  "updated_at": "2024-01-15T10:35:00Z"
}
```

**Error Cases:**
- `400 Bad Request`: Attempting to revoke essential consent
- `403 Forbidden`: Attempting to modify another user's consent
- `401 Unauthorized`: Missing or invalid JWT token

### 3. Get Consent History

**Endpoint:** `GET /api/users/:id/consents/:type/history`

**Description:** Get complete consent history for a specific type

**Authentication:** Required (JWT)

**Authorization:** Users can only access their own history unless they are admin

**Parameters:**
- `id` (path): User ID
- `type` (path): Consent type (`essential`, `analytics`, `marketing`)

**Response:**
```json
[
  {
    "id": "uuid-3",
    "user_id": "uuid",
    "consent_type": "analytics",
    "granted": false,
    "ip_address": "192.168.1.1",
    "created_at": "2024-01-15T14:00:00Z"
  },
  {
    "id": "uuid-2",
    "user_id": "uuid",
    "consent_type": "analytics",
    "granted": true,
    "ip_address": "192.168.1.1",
    "created_at": "2024-01-15T10:30:00Z"
  }
]
```

## Service Methods

### ConsentsService

**Location:** `src/modules/consents/consents.service.ts`

#### logConsent()
```typescript
async logConsent(
  userId: string,
  type: ConsentType,
  granted: boolean,
  ipAddress: string | null = null,
  userAgent: string | null = null,
): Promise<UserConsent>
```
Creates a new consent audit record.

#### getConsents()
```typescript
async getConsents(userId: string): Promise<UserConsent[]>
```
Returns all consent records for a user, ordered by most recent first.

#### getCurrentConsent()
```typescript
async getCurrentConsent(userId: string, type: ConsentType): Promise<UserConsent | null>
```
Returns the most recent consent record for a specific type.

#### updateConsent()
```typescript
async updateConsent(
  userId: string,
  type: ConsentType,
  granted: boolean,
  ipAddress: string | null = null,
  userAgent: string | null = null,
): Promise<UserConsent>
```
Updates consent by creating a new audit record. Throws error if attempting to revoke essential consent.

#### getConsentHistory()
```typescript
async getConsentHistory(userId: string, type: ConsentType): Promise<UserConsent[]>
```
Returns complete history for a specific consent type.

#### hasActiveConsent()
```typescript
async hasActiveConsent(userId: string, type: ConsentType): Promise<boolean>
```
Checks if user has active consent. Essential consent returns true by default.

## Frontend Component

### ConsentManagement Component

**Location:** `frontend/src/components/Settings/ConsentManagement.tsx`

**Features:**
- Toggle switches for each consent type
- Real-time updates via API
- Visual indicators for required vs optional consents
- Expandable consent history table
- Error handling and loading states
- Responsive design using Material-UI

**Usage:**
```tsx
import ConsentManagement from '@/components/Settings/ConsentManagement';

function SettingsPage() {
  return (
    <div>
      <ConsentManagement />
    </div>
  );
}
```

**UI Elements:**
- **Essential Consent**: Displayed with "Required" chip, switch is disabled
- **Optional Consents**: Displayed with "Optional" chip, toggleable
- **Consent History**: Collapsible table showing all consent changes with timestamps and IP addresses
- **Privacy Policy Link**: Direct link to full privacy policy

## Implementation Examples

### Check if User Has Analytics Consent

```typescript
import { Injectable } from '@nestjs/common';
import { ConsentsService } from './modules/consents/consents.service';
import { ConsentType } from './modules/consents/entities/user-consent.entity';

@Injectable()
export class AnalyticsService {
  constructor(private readonly consentsService: ConsentsService) {}

  async trackEvent(userId: string, eventName: string, data: any) {
    // Check if user has granted analytics consent
    const hasConsent = await this.consentsService.hasActiveConsent(
      userId,
      ConsentType.ANALYTICS
    );

    if (!hasConsent) {
      // Skip tracking if user hasn't consented
      return;
    }

    // Proceed with analytics tracking
    this.logAnalyticsEvent(eventName, data);
  }
}
```

### Grant Initial Consent During Registration

```typescript
import { Injectable } from '@nestjs/common';
import { ConsentsService } from './modules/consents/consents.service';
import { ConsentType } from './modules/consents/entities/user-consent.entity';

@Injectable()
export class AuthService {
  constructor(private readonly consentsService: ConsentsService) {}

  async register(userData: RegisterDto, ipAddress: string, userAgent: string) {
    // Create user account
    const user = await this.usersService.create(userData);

    // Log essential consent (always granted during registration)
    await this.consentsService.logConsent(
      user.id,
      ConsentType.ESSENTIAL,
      true,
      ipAddress,
      userAgent
    );

    return user;
  }
}
```

### Send Marketing Email Only to Consented Users

```typescript
import { Injectable } from '@nestjs/common';
import { ConsentsService } from './modules/consents/consents.service';
import { ConsentType } from './modules/consents/entities/user-consent.entity';

@Injectable()
export class EmailService {
  constructor(private readonly consentsService: ConsentsService) {}

  async sendMarketingEmail(userId: string, subject: string, body: string) {
    // Check marketing consent before sending
    const hasConsent = await this.consentsService.hasActiveConsent(
      userId,
      ConsentType.MARKETING
    );

    if (!hasConsent) {
      console.log(`Skipping marketing email for user ${userId} - no consent`);
      return false;
    }

    // Send email
    await this.sendEmail(userId, subject, body);
    return true;
  }
}
```

## GDPR Compliance

### Article 7: Conditions for Consent
- ✅ Clear and distinguishable consent requests
- ✅ Separate consent for different purposes (granular)
- ✅ Easy to withdraw consent as it was to give
- ✅ No pre-ticked boxes (essential consent is explicit)

### Article 13: Information to be Provided
- ✅ Clear explanation of each consent type
- ✅ Purpose of data processing for each type
- ✅ Link to full Privacy Policy

### Consent Requirements
- ✅ **Freely given**: Users can decline optional consents
- ✅ **Specific**: Each consent type has a clear purpose
- ✅ **Informed**: Detailed descriptions provided
- ✅ **Unambiguous**: Explicit action required (toggle switch)
- ✅ **Withdrawable**: Users can change consent at any time

### Audit Trail
Every consent change is logged with:
- Timestamp (when)
- User ID (who)
- Consent type (what)
- Granted/withdrawn status
- IP address (where)
- User agent (how)

## Testing

### Unit Tests

**Service Tests:** `src/modules/consents/consents.service.spec.ts` (18 tests)

```bash
npm test consents.service.spec.ts
```

**Controller Tests:** `src/modules/consents/consents.controller.spec.ts` (11 tests)

```bash
npm test consents.controller.spec.ts
```

### Test Coverage
- ✅ Log consent with all fields
- ✅ Log consent with null IP/user agent
- ✅ Retrieve all consents for user
- ✅ Get current consent for specific type
- ✅ Update consent (create new record)
- ✅ Prevent revoking essential consent
- ✅ Get consent history
- ✅ Check active consent status
- ✅ Authorization checks (self-access only)
- ✅ Admin can access any user data

## Privacy Policy Update

Update your Privacy Policy to include:

```markdown
## Your Consent Choices

You can manage your consent preferences at any time from your account settings:

1. **Essential Processing** (Required): Necessary for the application to function
2. **Analytics and Improvement** (Optional): Help us improve the service
3. **Marketing Communications** (Optional): Receive updates and promotional content

You can view your complete consent history, including timestamps and IP addresses,
in your privacy settings. All consent changes are logged for compliance purposes.

To manage your consents, visit: [Your Account] > [Privacy Settings] > [Consent Management]
```

## Security Considerations

### IP Address Storage
- IP addresses are stored for audit purposes (GDPR compliance)
- IPv4 and IPv6 addresses supported (VARCHAR(45))
- IP addresses may be considered personal data under GDPR

### User Agent Storage
- Full user agent strings stored as TEXT
- Used to identify the device/browser used to grant consent
- Helps detect suspicious consent changes

### Access Control
- Users can only access/modify their own consents
- Admin role can access all user consents for support
- JWT authentication required for all endpoints

### Data Retention
- Consent records should be retained for 3-7 years after user deletion
- Check local regulations for specific retention requirements
- Implement separate archival process for deleted users

## Troubleshooting

### Essential Consent Cannot Be Revoked
**Error:** `BadRequestException: Essential consent cannot be revoked`

**Solution:** This is by design. Essential consent is required for the application to function. Users attempting to disable it will see this error. The UI prevents this action, but the backend validates as well.

### 403 Forbidden When Accessing Consents
**Error:** `ForbiddenException: You can only access your own consent data`

**Solution:** Ensure the JWT token matches the user ID in the URL path. Users can only access their own data unless they have admin role.

### Missing IP Address in Consent Record
**Issue:** IP address shows as `null` in consent records

**Solution:** Ensure your reverse proxy (nginx, CloudFront, etc.) forwards the client IP address via `X-Forwarded-For` or `X-Real-IP` headers. Configure Express to trust proxy:

```typescript
app.set('trust proxy', true);
```

## Migration Guide

### Running the Migration

```bash
# Generate migration (if needed)
npm run typeorm migration:generate -- -n CreateUserConsentsTable

# Run migration
npm run typeorm migration:run

# Revert migration (if needed)
npm run typeorm migration:revert
```

### Existing Users

For existing users, you may want to create initial consent records:

```sql
-- Grant essential consent to all existing users
INSERT INTO user_consents (user_id, consent_type, granted, created_at)
SELECT id, 'essential', true, NOW()
FROM users
WHERE id NOT IN (
  SELECT DISTINCT user_id
  FROM user_consents
  WHERE consent_type = 'essential'
);
```

## Future Enhancements

1. **Consent Banner**: Cookie consent banner for first-time visitors
2. **Consent Versioning**: Track changes to consent text/purposes over time
3. **Bulk Consent Management**: Admin tool to manage consents for multiple users
4. **Consent Expiration**: Automatically expire consents after X months, require re-confirmation
5. **Consent Import/Export**: GDPR data portability for consent history
6. **Webhook Notifications**: Notify external systems when consent changes
7. **Consent Analytics Dashboard**: Admin view of consent statistics

## Support

For questions or issues related to consent management:
- Technical issues: Check the test suite and error logs
- Legal/compliance questions: Consult with your legal team
- GDPR questions: Refer to official GDPR documentation (gdpr.eu)

## References

- [GDPR Article 7: Conditions for Consent](https://gdpr.eu/article-7-how-to-get-consent-to-collect-personal-data/)
- [GDPR Article 13: Information to be Provided](https://gdpr.eu/article-13-personal-data-collected/)
- [ICO Guide to Consent](https://ico.org.uk/for-organisations/guide-to-data-protection/guide-to-the-general-data-protection-regulation-gdpr/consent/)
- [TypeORM Documentation](https://typeorm.io/)
- [NestJS Documentation](https://docs.nestjs.com/)
