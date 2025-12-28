# Database SSL/TLS Configuration Guide

## Overview

This document describes how to configure SSL/TLS encryption for database connections in the Financial RISE Report application. SSL/TLS encryption ensures that all data transmitted between the application and the PostgreSQL database is encrypted, protecting sensitive financial information and DISC personality data from network eavesdropping.

**Security Finding Addressed:** MED-005 - No database connection encryption
**OWASP:** A02:2021 - Cryptographic Failures
**CWE:** CWE-319 - Cleartext Transmission of Sensitive Information

## Table of Contents

1. [Why SSL/TLS Matters](#why-ssltls-matters)
2. [Environment Variables](#environment-variables)
3. [Local Development Setup](#local-development-setup)
4. [Production Deployment (GCP Cloud SQL)](#production-deployment-gcp-cloud-sql)
5. [Staging Environment](#staging-environment)
6. [Testing SSL Configuration](#testing-ssl-configuration)
7. [Troubleshooting](#troubleshooting)
8. [Security Best Practices](#security-best-practices)

## Why SSL/TLS Matters

Without SSL/TLS encryption, database connections transmit data in cleartext, including:

- **Database credentials** (username and password)
- **Client financial data** (income, expenses, debt amounts)
- **DISC personality assessment responses**
- **Personally Identifiable Information (PII)**
- **Business financial health metrics**

SSL/TLS encryption protects this data from:

- **Network sniffing/eavesdropping**
- **Man-in-the-middle (MITM) attacks**
- **Credential theft**
- **Data interception on public networks**

## Environment Variables

### DATABASE_SSL

**Type:** String (`'true'` or `'false'`)
**Default:** `false`
**Required:** Yes (must be `'true'` in production)

Enables or disables SSL/TLS for database connections.

```env
# Development (local PostgreSQL)
DATABASE_SSL=false

# Production (GCP Cloud SQL)
DATABASE_SSL=true
```

### DATABASE_SSL_REJECT_UNAUTHORIZED

**Type:** String (`'true'` or `'false'`)
**Default:** `false`
**Required:** Recommended for production

When set to `'true'`, the application will reject connections to databases with invalid or untrusted SSL certificates. This prevents MITM attacks but requires a valid CA certificate.

```env
# Development (self-signed certificates)
DATABASE_SSL_REJECT_UNAUTHORIZED=false

# Production (trusted CA certificates)
DATABASE_SSL_REJECT_UNAUTHORIZED=true
```

### DATABASE_SSL_CA

**Type:** String (file path)
**Default:** None
**Required:** Required in production when `DATABASE_SSL_REJECT_UNAUTHORIZED=true`

Path to the CA (Certificate Authority) certificate file that signed the database server's SSL certificate. For GCP Cloud SQL, this is the server CA certificate downloaded from the Google Cloud Console.

```env
# Production
DATABASE_SSL_CA=/etc/secrets/gcp-cloud-sql-server-ca.pem
```

## Local Development Setup

For local development with PostgreSQL running on localhost, SSL is typically not required:

```env
# .env.local
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_USER=financial_rise
DATABASE_PASSWORD=dev_secure_pass_2024_local_only
DATABASE_NAME=financial_rise_dev
DATABASE_SSL=false
```

### Enabling SSL Locally (Optional)

If you want to test SSL locally:

1. **Generate self-signed certificates for PostgreSQL:**

```bash
# On your PostgreSQL server
openssl req -new -x509 -days 365 -nodes -text \
  -out server.crt \
  -keyout server.key \
  -subj "/CN=localhost"

chmod 600 server.key
chown postgres:postgres server.key server.crt
```

2. **Configure PostgreSQL to use SSL:**

Edit `postgresql.conf`:
```
ssl = on
ssl_cert_file = 'server.crt'
ssl_key_file = 'server.key'
```

3. **Update `.env.local`:**

```env
DATABASE_SSL=true
DATABASE_SSL_REJECT_UNAUTHORIZED=false  # Self-signed cert
```

## Production Deployment (GCP Cloud SQL)

### Step 1: Obtain Cloud SQL CA Certificate

1. **Navigate to Cloud SQL in Google Cloud Console**
2. **Select your instance** (e.g., `financial-rise-prod`)
3. **Go to "Connections" → "Security"**
4. **Download the "Server CA certificate"** (saves as `server-ca.pem`)

### Step 2: Store CA Certificate Securely

**Option A: Kubernetes Secret (Recommended)**

```bash
# Create Kubernetes secret
kubectl create secret generic cloudsql-ssl-cert \
  --from-file=server-ca.pem=./server-ca.pem \
  --namespace=financial-rise-prod

# Mount in deployment.yaml
spec:
  containers:
  - name: backend
    volumeMounts:
    - name: cloudsql-ssl-cert
      mountPath: /etc/secrets/cloudsql
      readOnly: true
  volumes:
  - name: cloudsql-ssl-cert
    secret:
      secretName: cloudsql-ssl-cert
```

**Option B: Google Secret Manager**

```bash
# Store in Secret Manager
gcloud secrets create cloudsql-server-ca \
  --data-file=server-ca.pem \
  --replication-policy=automatic

# Grant access to service account
gcloud secrets add-iam-policy-binding cloudsql-server-ca \
  --member="serviceAccount:financial-rise-backend@project.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

### Step 3: Configure Environment Variables

```env
# Production .env
NODE_ENV=production
DATABASE_HOST=10.0.0.3  # Cloud SQL private IP
DATABASE_PORT=5432
DATABASE_USER=financial_rise_prod
DATABASE_PASSWORD=<stored-in-secrets-manager>
DATABASE_NAME=financial_rise_prod

# SSL Configuration
DATABASE_SSL=true
DATABASE_SSL_REJECT_UNAUTHORIZED=true
DATABASE_SSL_CA=/etc/secrets/cloudsql/server-ca.pem
```

### Step 4: Verify SSL Connection

```bash
# SSH into production pod
kubectl exec -it <pod-name> -- /bin/bash

# Test database connection
psql "sslmode=require host=$DATABASE_HOST user=$DATABASE_USER dbname=$DATABASE_NAME"

# Verify SSL is active
SELECT * FROM pg_stat_ssl WHERE pid = pg_backend_pid();
```

Expected output:
```
 pid  | ssl | version |         cipher          | bits | compression | client_dn
------+-----+---------+-------------------------+------+-------------+-----------
 1234 | t   | TLSv1.3 | TLS_AES_256_GCM_SHA384 |  256 | f           |
```

## Staging Environment

Staging environments may use relaxed SSL settings for testing:

```env
# .env.staging
DATABASE_SSL=true
DATABASE_SSL_REJECT_UNAUTHORIZED=false  # Allow self-signed certificates
```

**Note:** In staging, you can still enable SSL without strict certificate validation to test SSL-related code paths without requiring production CA certificates.

## Testing SSL Configuration

### Unit Tests

Run the SSL configuration test suite:

```bash
npm test -- typeorm-ssl.config.spec.ts
```

Expected output:
```
Test Suites: 1 passed
Tests:       27 passed
```

### Integration Tests

Test actual database connection with SSL:

```bash
# Set SSL environment variables
export DATABASE_SSL=true
export DATABASE_SSL_REJECT_UNAUTHORIZED=true
export DATABASE_SSL_CA=/path/to/server-ca.pem

# Run backend
npm run start:dev

# Check logs for SSL connection
# Should see: [TypeORM] Connection established with SSL
```

### Manual Verification

**Test 1: SSL Enabled Connection**
```bash
psql "postgresql://user:pass@host:5432/dbname?sslmode=require"
```

**Test 2: Verify Certificate Validation**
```bash
# Should fail with invalid certificate
psql "postgresql://user:pass@host:5432/dbname?sslmode=verify-ca&sslrootcert=invalid.pem"
```

**Test 3: Check Active SSL Session**
```sql
SELECT ssl, version, cipher
FROM pg_stat_ssl
WHERE pid = pg_backend_pid();
```

## Troubleshooting

### Error: "CA certificate file not found"

**Symptom:**
```
[TypeORM SSL] CA certificate file not found: /etc/secrets/server-ca.pem
```

**Solution:**
1. Verify the file path is correct
2. Check file permissions: `chmod 644 /etc/secrets/server-ca.pem`
3. Ensure the Kubernetes secret/volume is mounted correctly
4. Verify the pod has access to the secret

### Error: "ECONNREFUSED"

**Symptom:**
```
Error: connect ECONNREFUSED 10.0.0.3:5432
```

**Solution:**
1. Verify `DATABASE_HOST` is correct
2. Check if Cloud SQL instance is running
3. Verify network connectivity (firewall rules, VPC peering)
4. Check if Cloud SQL instance allows SSL connections

### Error: "SSL SYSCALL error: EOF detected"

**Symptom:**
```
SSL SYSCALL error: EOF detected
```

**Solution:**
1. Database server may not support SSL - check Cloud SQL SSL settings
2. Firewall may be blocking SSL connections
3. Try setting `DATABASE_SSL_REJECT_UNAUTHORIZED=false` temporarily

### Error: "self signed certificate"

**Symptom:**
```
Error: self signed certificate in certificate chain
```

**Solution:**
1. This occurs when `DATABASE_SSL_REJECT_UNAUTHORIZED=true` but CA cert is self-signed
2. **Production:** Use a valid CA certificate from Cloud SQL
3. **Development:** Set `DATABASE_SSL_REJECT_UNAUTHORIZED=false`

### Error: "certificate verify failed"

**Symptom:**
```
Error: certificate verify failed
```

**Solution:**
1. Verify the CA certificate matches the database server's certificate
2. Download the latest CA certificate from Cloud SQL console
3. Check that the certificate file is not corrupted
4. Ensure certificate has not expired

## Security Best Practices

### Production Requirements

1. **ALWAYS enable SSL in production**
   ```env
   DATABASE_SSL=true
   ```

2. **ALWAYS enable certificate validation in production**
   ```env
   DATABASE_SSL_REJECT_UNAUTHORIZED=true
   ```

3. **Use trusted CA certificates**
   - Download from GCP Cloud SQL console
   - Do not use self-signed certificates in production

4. **Secure certificate storage**
   - Store in Kubernetes secrets
   - Use Google Secret Manager
   - Never commit certificates to version control
   - Set proper file permissions (644 for CA certs)

5. **Regular certificate rotation**
   - Monitor certificate expiration dates
   - Rotate certificates annually or as recommended by GCP
   - Update CA certificates when Cloud SQL rotates them

### Development Best Practices

1. **Disable SSL for local development**
   ```env
   DATABASE_SSL=false
   ```

2. **Test SSL configuration in staging**
   - Use staging environment to test SSL before production
   - Test both successful and failed SSL connections

3. **Never commit .env files with production secrets**
   - Add `.env.production` to `.gitignore`
   - Use environment-specific configuration

### Monitoring and Alerts

1. **Monitor SSL connection status**
   ```sql
   SELECT COUNT(*) FROM pg_stat_ssl WHERE ssl = true;
   ```

2. **Alert on SSL disabled connections in production**
   ```sql
   SELECT COUNT(*) FROM pg_stat_ssl WHERE ssl = false;
   -- Should be 0 in production
   ```

3. **Monitor certificate expiration**
   - Set up alerts 30 days before certificate expiration
   - GCP Cloud SQL typically auto-renews, but verify

## Additional Resources

- [PostgreSQL SSL Support](https://www.postgresql.org/docs/current/ssl-tcp.html)
- [GCP Cloud SQL SSL/TLS](https://cloud.google.com/sql/docs/postgres/configure-ssl-instance)
- [OWASP - Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [CWE-319 - Cleartext Transmission](https://cwe.mitre.org/data/definitions/319.html)

## Support

For issues related to SSL/TLS configuration:

1. Check the [Troubleshooting](#troubleshooting) section
2. Review application logs for SSL-related errors
3. Verify Cloud SQL instance configuration
4. Contact DevOps team for infrastructure issues

---

**Last Updated:** 2025-12-28
**Work Stream:** 65 - Database SSL/TLS Enforcement (MED-005)
**Security Audit:** SECURITY-AUDIT-REPORT.md Lines 1128-1172
