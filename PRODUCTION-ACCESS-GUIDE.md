# Production Access Guide

**Production URL:** http://34.72.61.170

---

## Current Status

✅ **Infrastructure:** Running
✅ **Backend API:** Healthy (`/api/v1/health` responds with `{"status":"ok"}`)
✅ **Frontend:** Serving pages
⚠️ **User Registration:** Experiencing 500 error (database migration issue)

---

## Issue Identified: Database Tables Not Created

The registration endpoint is returning a 500 error because the database migrations failed during deployment. The TypeORM migrations tried to run using TypeScript source files, but the production Docker image only contains compiled JavaScript.

### Error During Deployment:
```
Error: Unable to open file: "/app/src/config/typeorm.config.ts"
Cannot find module '/app/src/config/typeorm.config.ts'
```

This was ignored by the workflow (`|| echo 'Migrations completed'`), but it means the database tables were never created.

---

## Solution Options

### Option 1: Run Migrations Manually (Recommended)

Use PowerShell to connect to the production VM and run migrations using the compiled JavaScript files:

```powershell
# Run this script (already created for you)
.\run-production-migrations.ps1
```

This script will:
1. Connect to the production VM
2. Run migrations using the compiled `dist/config/typeorm.config.js` file
3. Create all necessary database tables
4. Test the registration endpoint

### Option 2: Run Migrations via Cloud Console

1. Go to [GCP VM Console](https://console.cloud.google.com/compute/instancesDetail/zones/us-central1-a/instances/financial-rise-production-vm?project=financial-rise-prod)

2. Click "SSH" to open a terminal

3. Run:
   ```bash
   cd /opt/financial-rise
   docker compose -f docker-compose.prod.yml exec backend sh -c \
     'cd /app && npm run build && npx typeorm migration:run -d dist/config/typeorm.config.js'
   ```

4. Verify migrations ran successfully

### Option 3: Redeploy with Fixed Migration Script

Update the deployment workflow to run migrations correctly using the compiled JavaScript files instead of TypeScript source files.

---

## Once Migrations Are Fixed

### Creating Your First Account

#### Via API (using PowerShell):
```powershell
$body = @{
    email = "your.email@example.com"
    password = "YourSecurePass123!"
    first_name = "Your"
    last_name = "Name"
    role = "consultant"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://34.72.61.170/api/v1/auth/register" `
    -Method Post `
    -Body $body `
    -ContentType "application/json"
```

#### Via API (using curl in Git Bash):
```bash
curl -X POST "http://34.72.61.170/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "your.email@example.com",
    "password": "YourSecurePass123!",
    "first_name": "Your",
    "last_name": "Name",
    "role": "consultant"
  }'
```

**Password Requirements:**
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character (@$!%*?&#)

### Logging In

Once your account is created:

1. Open your browser and go to: **http://34.72.61.170/login**

2. Enter your credentials:
   - Email: (the email you registered with)
   - Password: (the password you set)

3. Click "Sign In"

4. You'll be redirected to the dashboard at: **http://34.72.61.170/dashboard**

---

## Available User Roles

When registering, you can choose between:

- **consultant** (default) - Financial consultant/advisor role
- **admin** - Administrator role with elevated permissions

---

## API Endpoints Available

Once logged in, you can access:

- `GET /api/v1/health` - Health check
- `POST /api/v1/auth/login` - Login
- `POST /api/v1/auth/logout` - Logout
- `POST /api/v1/auth/refresh` - Refresh access token
- `POST /api/v1/auth/forgot-password` - Request password reset
- `POST /api/v1/auth/reset-password` - Reset password

Additional endpoints will be available based on implemented features.

---

## Troubleshooting

### 500 Error on Registration
**Cause:** Database tables not created (migrations didn't run)
**Fix:** Run migrations manually using Option 1 or 2 above

### Can't Connect to Database
**Cause:** Cloud SQL connection issue
**Fix:** Already fixed! VM is authorized in Cloud SQL networks

### Frontend Not Loading
**Cause:** Nginx configuration or container issue
**Check:** Run `.\check-production-status.sh` to verify all containers are running

---

## Next Steps

1. **Run migrations** using `.\run-production-migrations.ps1`
2. **Create your account** via the API
3. **Log in** at http://34.72.61.170/login
4. **Explore** the Financial RISE application!

---

## Support Scripts Created

All scripts are in the repository root:

- `run-production-migrations.ps1` - Run database migrations
- `create-demo-account.sh` - Create a demo account (run after migrations)
- `check-production-status.sh` - Check container health
- `diagnose-cloud-sql-connectivity.sh` - Test database connectivity

---

**Need Help?**

Check the production deployment summary: `PRODUCTION-DEPLOYMENT-SUCCESS.md`

Or view error logs: `ERROR-LOGS.md`
