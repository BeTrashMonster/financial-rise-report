# Secrets Management Documentation

## Overview

This document describes the secrets management system for the Financial RISE application, implementing Work Stream 51 (CRIT-001) to remediate hardcoded secrets vulnerability.

## Security Requirements

### Critical Security Finding
- **CRIT-001:** Hardcoded JWT secrets in version control
- **OWASP:** A02:2021 - Cryptographic Failures
- **CWE:** CWE-798 - Use of Hard-coded Credentials

### Secret Strength Requirements

#### Development Environment
- **JWT_SECRET:** Minimum 32 characters
- **REFRESH_TOKEN_SECRET:** Minimum 32 characters
- **DATABASE_PASSWORD:** Recommended 16+ characters

#### Production Environment
- **JWT_SECRET:** Minimum 64 characters (REQUIRED)
- **REFRESH_TOKEN_SECRET:** Minimum 64 characters (REQUIRED)
- **DATABASE_PASSWORD:** Minimum 16 characters (REQUIRED)

### Forbidden Values
The following default secrets are BLOCKED and will cause application startup failure:
- `dev-jwt-secret-change-in-production`
- `dev-refresh-secret-change-in-production`
- `financial_rise_dev`

## Generating Secure Secrets

### Using the Built-in Generator

The application provides a cryptographically secure secret generator:

```typescript
import { SecretsValidationService } from './config/secrets-validation.service';

// Generate 64-character hex secret (32 bytes)
const jwtSecret = SecretsValidationService.generateSecureSecret();
console.log('JWT_SECRET=' + jwtSecret);

// Generate 128-character hex secret (64 bytes)
const refreshSecret = SecretsValidationService.generateSecureSecret(64);
console.log('REFRESH_TOKEN_SECRET=' + refreshSecret);
```

### Using Command Line

```bash
# Generate JWT_SECRET (64 characters)
node -e "console.log('JWT_SECRET=' + require('crypto').randomBytes(32).toString('hex'))"

# Generate REFRESH_TOKEN_SECRET (64 characters)
node -e "console.log('REFRESH_TOKEN_SECRET=' + require('crypto').randomBytes(32).toString('hex'))"

# Generate DATABASE_PASSWORD (32 characters)
node -e "console.log('DATABASE_PASSWORD=' + require('crypto').randomBytes(16).toString('hex'))"
```

### Example Output

```env
JWT_SECRET=a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456
REFRESH_TOKEN_SECRET=9876543210fedcba9876543210fedcba0123456789abcdef0123456789abcdef
DATABASE_PASSWORD=secure-prod-password-2024
```

## Secret Validation

### Automatic Validation on Startup

The application automatically validates all secrets on startup:

```typescript
// In main.ts or bootstrap
import { SecretsValidationService } from './config/secrets-validation.service';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Validate secrets before starting server
  const secretsValidator = app.get(SecretsValidationService);
  secretsValidator.validateSecrets(); // Throws error if validation fails

  await app.listen(3000);
}
```

### Validation Rules

1. **Non-empty:** All required secrets must be defined and non-empty
2. **Minimum length:** Secrets must meet minimum character requirements
3. **No defaults:** Default development secrets are rejected in all environments
4. **Production requirements:** Production secrets must be 64+ characters

### Validation Success

```
✅ Secret validation passed - All secrets meet security requirements
```

### Validation Failure Examples

```
Error: JWT_SECRET is required and must not be empty
Error: JWT_SECRET must be at least 32 characters long
Error: Default JWT_SECRET detected. This secret must be changed before deployment!
Error: Production JWT_SECRET must be at least 64 characters
Error: DATABASE_PASSWORD is required in production
```

## GCP Secret Manager Integration

### Setup Instructions

1. **Install GCP Secret Manager Client**

```bash
npm install @google-cloud/secret-manager
```

2. **Configure GCP Project**

Add to your `.env` file:

```env
GCP_PROJECT_ID=your-project-id
GOOGLE_APPLICATION_CREDENTIALS=./path/to/service-account-key.json
```

3. **Create Secrets in GCP**

```bash
# Create JWT_SECRET
echo -n "your-64-char-jwt-secret" | gcloud secrets create JWT_SECRET --data-file=-

# Create REFRESH_TOKEN_SECRET
echo -n "your-64-char-refresh-secret" | gcloud secrets create REFRESH_TOKEN_SECRET --data-file=-

# Create DATABASE_PASSWORD
echo -n "your-secure-db-password" | gcloud secrets create DATABASE_PASSWORD --data-file=-
```

4. **Grant Access to Service Account**

```bash
gcloud secrets add-iam-policy-binding JWT_SECRET \
  --member="serviceAccount:your-service-account@project.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

### Loading Secrets from GCP

```typescript
import { SecretsService } from './config/secrets.service';

// In your module
@Module({
  providers: [
    SecretsService,
    {
      provide: 'SECRET_MANAGER_CLIENT',
      useFactory: () => new SecretManagerServiceClient(),
    },
  ],
})
export class AppModule {}

// Loading secrets
const secretsService = app.get(SecretsService);
const allSecrets = await secretsService.loadAllSecrets();

// Access individual secret
const jwtSecret = await secretsService.getSecret('JWT_SECRET');
```

### Secret Caching

The `SecretsService` implements in-memory caching to reduce GCP API calls:

- Secrets are cached after first retrieval
- Cache is automatically cleared after secret rotation
- No expiration time (secrets are loaded once on startup)

## Secret Rotation

### Rotation Policy

- **JWT_SECRET:** Rotate every 90 days
- **REFRESH_TOKEN_SECRET:** Rotate every 90 days
- **DATABASE_PASSWORD:** Rotate every 180 days

### Automated Rotation

```typescript
import { SecretsService } from './config/secrets.service';
import { SecretsValidationService } from './config/secrets-validation.service';

async function rotateJwtSecret() {
  const secretsService = app.get(SecretsService);

  // Generate new secure secret
  const newSecret = SecretsValidationService.generateSecureSecret(32); // 64 chars

  // Rotate in GCP Secret Manager
  await secretsService.rotateSecret('JWT_SECRET', newSecret);

  console.log('JWT_SECRET rotated successfully');
}
```

### Manual Rotation via GCP Console

1. Navigate to **Secret Manager** in GCP Console
2. Select the secret (e.g., `JWT_SECRET`)
3. Click **New Version**
4. Enter the new secret value (use generator above)
5. Click **Add New Version**
6. Restart the application to load new secret

### Rotation Impact

- **JWT_SECRET:** Active user sessions will be invalidated (users must re-login)
- **REFRESH_TOKEN_SECRET:** All refresh tokens become invalid
- **DATABASE_PASSWORD:** Database connection will be terminated and reconnected

## Environment File Management

### Development (.env.local)

**IMPORTANT:** `.env.local` is now in `.gitignore` and should NEVER be committed to version control.

Create your local `.env.local` file:

```bash
# Copy example file
cp .env.example .env.local

# Generate secure secrets
node -e "console.log('JWT_SECRET=' + require('crypto').randomBytes(32).toString('hex'))" >> .env.local
node -e "console.log('REFRESH_TOKEN_SECRET=' + require('crypto').randomBytes(32).toString('hex'))" >> .env.local
```

### Production

**Use GCP Secret Manager exclusively in production. Never use .env files in production.**

Environment variables should be loaded from Secret Manager on application startup.

### .gitignore Configuration

```gitignore
# Environment variables - CRITICAL SECURITY
.env
.env.local
.env.*.local
.env.development.local
.env.test.local
.env.production.local

# GCP Service Account Keys - CRITICAL SECURITY
service-account-key*.json
*-credentials.json
gcloud-service-key.json
```

## Removing Secrets from Git History

If secrets were accidentally committed, follow these steps:

### 1. Remove from Git History

```bash
# WARNING: This rewrites git history
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch financial-rise-app/backend/.env.local" \
  --prune-empty --tag-name-filter cat -- --all
```

### 2. Force Push (Coordinate with Team)

```bash
# WARNING: Coordinate with all team members before force push
git push origin --force --all
git push origin --force --tags
```

### 3. Rotate All Exposed Secrets

Generate and deploy new secrets immediately:

```bash
# All exposed secrets are now compromised and must be replaced
# Follow the "Generating Secure Secrets" section above
```

### 4. Garbage Collection

```bash
# Clean up repository
git reflog expire --expire=now --all
git gc --prune=now --aggressive
```

## Testing Secret Validation

### Unit Tests

Tests are located in `src/config/secrets.config.spec.ts`:

```bash
npm test -- secrets.config.spec.ts
```

### Test Coverage

- ✅ Empty secret detection
- ✅ Short secret detection (<32 chars)
- ✅ Default secret detection
- ✅ Production secret validation (64+ chars)
- ✅ Database password validation
- ✅ Secure secret generation
- ✅ GCP Secret Manager integration
- ✅ Secret caching
- ✅ Secret rotation

### Current Test Results

```
Test Suites: 1 passed, 1 total
Tests:       23 passed, 23 total
```

## Deployment Checklist

Before deploying to production:

- [ ] All secrets removed from version control (verified with `git log`)
- [ ] `.gitignore` includes all secret files
- [ ] Secrets created in GCP Secret Manager
- [ ] Service account has `secretmanager.secretAccessor` role
- [ ] `GCP_PROJECT_ID` environment variable set
- [ ] Application startup includes `validateSecrets()` call
- [ ] All secrets are 64+ characters
- [ ] No default secrets in use
- [ ] Secret rotation policy documented and scheduled
- [ ] Team trained on secret management procedures

## Security Best Practices

1. **Never commit secrets to version control**
2. **Use GCP Secret Manager in production**
3. **Rotate secrets regularly (90-day policy)**
4. **Use cryptographically secure random generators**
5. **Validate secrets on application startup**
6. **Monitor secret access logs in GCP**
7. **Implement least-privilege access control**
8. **Document secret rotation procedures**
9. **Train team on secret management**
10. **Audit git history for exposed secrets**

## Compliance

This secrets management system supports:

- **OWASP Top 10 2021:** A02 - Cryptographic Failures
- **CWE-798:** Use of Hard-coded Credentials
- **NIST SP 800-53:** IA-5 (Authenticator Management)
- **GDPR:** Article 32 (Security of Processing)
- **SOC 2:** CC6.1 (Logical and Physical Access Controls)

## References

- [GCP Secret Manager Documentation](https://cloud.google.com/secret-manager/docs)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [NIST Password Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

---

**Document Version:** 1.0
**Last Updated:** 2025-12-28
**Author:** TDD Security Agent (Work Stream 51)
