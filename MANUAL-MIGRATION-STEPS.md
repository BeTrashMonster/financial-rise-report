# Manual Database Migration Steps

The automated migration script isn't working due to Windows/Git Bash limitations. Here's how to run the migrations manually through the GCP Console (takes about 2 minutes):

---

## Step 1: Open SSH Terminal

1. Go to your VM instance in GCP Console:
   https://console.cloud.google.com/compute/instancesDetail/zones/us-central1-a/instances/financial-rise-production-vm?project=financial-rise-prod

2. Click the **"SSH"** button in the top toolbar
   - This will open a browser-based terminal window

---

## Step 2: Run the Migration Command

Once the SSH terminal opens, copy and paste this entire command:

```bash
docker exec financial-rise-backend-prod sh -c 'cd /app && npm run build && npx typeorm migration:run -d dist/config/typeorm.config.js'
```

Press Enter and wait for it to complete. You should see output like:

```
query: SELECT * FROM "information_schema"."tables" WHERE "table_schema" = 'public' AND "table_name" = 'migrations'
query: CREATE TABLE "migrations" ...
query: CREATE TABLE "users" ...
query: CREATE TABLE "clients" ...
query: CREATE TABLE "assessments" ...
... (more migration output)
Migration CreateInitialSchema1703600000000 has been executed successfully.
Migration CreateQuestions1703700000001 has been executed successfully.
... (all migrations completed)
```

---

## Step 3: Create Your Account

After migrations complete, run this command in the **same SSH terminal**:

```bash
curl -X POST "http://localhost:4000/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "info@thegracefulpenny.com",
    "password": "DemoPass123!",
    "first_name": "Audrey",
    "last_name": "Heesch",
    "role": "consultant"
  }'
```

You should see a response with an `access_token`, which means your account was created successfully!

---

## Step 4: Log In

1. Open your browser and go to: **http://34.72.61.170/login**

2. Enter your credentials:
   - **Email:** info@thegracefulpenny.com
   - **Password:** DemoPass123!

3. Click **"Sign In"**

4. You'll be redirected to your dashboard!

---

## Troubleshooting

### If migrations fail:
Check that the backend container is running:
```bash
docker ps | grep backend
```

If it's not running, restart it:
```bash
cd /opt/financial-rise
docker compose -f docker-compose.prod.yml restart backend
```

### If account creation fails:
Check the backend logs:
```bash
docker logs financial-rise-backend-prod --tail=50
```

---

## Why This Happened

The deployment workflow tried to run migrations using TypeScript source files (`src/config/typeorm.config.ts`), but the production Docker image only contains compiled JavaScript in the `dist/` folder. The error was ignored by the workflow (`|| echo 'Migrations completed'`), so the tables were never created.

This will be fixed in the next deployment by updating the migration command to use the correct path.

---

**Estimated Time:** 2-3 minutes total

Once you complete these steps, you'll have full access to the Financial RISE application!
