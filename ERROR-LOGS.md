# GCP Deployment Error Logs & Lessons Learned

**Last Updated:** 2026-01-02
**Project:** Financial RISE Report - Production Deployment
**Status:** Production Infrastructure Complete ✅

---

## Current Deployment Status

**Production Infrastructure:**
- **VM:** `financial-rise-production-vm` (34.72.61.170)
- **Cloud SQL:** PostgreSQL 14 with Private IP (ZONAL)
- **Secret Manager:** Version 3 (malformed - workflow aggressively cleans on deploy)
- **Latest Commit:** `550eca8` - Aggressive .env cleaning for production
- **Deployment:** Testing production deployment (staging ✅ working)

**Infrastructure Cost:** $103/month (budget optimized)

**Deployment Status:**
- ✅ **Staging:** Working (commit 75be3ad)
- 🔄 **Production:** Testing aggressive cleaning approach (commit 550eca8)

---

## Recent Issues & Resolutions

### 11. Staging VM Connectivity + .env Parsing (RESOLVED ✅)
**Date:** 2026-01-02

**Problem 1:** Error 4003: 'failed to connect to backend' when SSH to staging VM
**Root Cause 1:** Preemptible staging VM shuts down after 24 hours, status = TERMINATED
**Solution 1:** Modified workflow to check VM status and auto-start before SSH attempts
**Commit:** `75be3ad` - Added "Ensure staging VM is running" step
**Status:** ✅ Staging deployment working

**Problem 2:** `failed to read .env: line 12: unexpected character "+" in variable name "NRpc8sfc1zWS2lJCbyq+kA=\"\""`
**Root Cause 2:** Secret Manager contains inconsistent formatting (some lines clean, some with escaped quotes)
**Solution 2 (Staging):** Basic sed cleaning worked
```bash
sed -i 's/\\\"/\"/g' .env  # Remove escaped quotes
sed -i '/^$/d' .env         # Remove blank lines
```
**Status:** ✅ Staging working with basic cleaning

**Solution 2 (Production):** Aggressive cleaning needed due to worse formatting
```bash
# Strip ALL backslashes and quotes, then re-add clean quotes
sed 's/\\//g' .env.raw | sed 's/\"//g' | sed '/^$/d' > .env.stripped
awk -F= '/^[^#]/ && NF==2 {print $1"=\""$2"\""} /^#/ {print}' .env.stripped > .env
```
**Commit:** `550eca8` - Aggressive .env cleaning for production
**Status:** Testing production deployment

**Lesson:** Production Secret Manager needs to be rebuilt from scratch with clean formatting (future task)

### 10. Docker Compose .env Parsing Error (ATTEMPTED FIX ⚠️)
**Date:** 2026-01-02
**Problem:** `failed to read .env: line 12: unexpected character "+" in variable name`
**Root Cause:** Base64-encoded secrets (JWT tokens) contain special characters (`+`, `/`, `=`) that Docker Compose's `.env` parser can't handle
**Attempted Fix:** Multiple scripts to fix Secret Manager formatting (versions 2 and 3)
**Result:** Secret Manager still contains escaped quotes after multiple fix attempts
**Workaround:** Workflow now cleans .env file after pulling (issue #11)
**Lesson:** Always quote environment variable values, but use clean quotes `="..."` not escaped `=\"...\"`

---

## Key Lessons Learned (Historical)

### 1. Docker Compose File Merging
**Lesson:** Docker Compose v3.8 **merges** arrays (like `volumes`) from base + override files instead of replacing them.
**Best Practice:** Use separate, standalone compose files for dev and prod. Don't merge files in production.

### 2. TypeORM Index Decorators
**Lesson:** Class-level `@Index(['columnName'])` expects database column names, not TypeScript property names.
**Best Practice:** Use property-level `@Index()` decorators for single-column indexes.

### 3. Environment Variable Naming Consistency
**Lesson:** Backend validation must match environment variable names exactly.
**Best Practice:** Provide backwards compatibility mappings (e.g., both `JWT_SECRET` and `TOKEN_SECRET`).

### 4. Secret Manager Version Management
**Lesson:** Secret Manager creates new versions when updated. Always verify latest version after updates.
**Best Practice:** Use `gcloud secrets versions access latest` to verify changes deployed correctly.

### 5. Cloud SQL Networking
**Lesson:** Public IP + authorized networks works for staging but is less secure.
**Best Practice:** Production uses Private IP via VPC peering for security.

### 6. Disk Space Management
**Lesson:** Docker images and volumes accumulate quickly on VMs.
**Best Practice:** Aggressive cleanup in deployment workflow: `docker image prune -a -f && docker volume prune -f`.

### 7. Base64 Secrets in .env Files
**Lesson:** Base64-encoded values with `+`, `/`, or `=` break Docker Compose's `.env` parser.
**Best Practice:** Always quote values in `.env` files, especially base64-encoded secrets.

### 8. Preemptible VM Limitations
**Lesson:** Preemptible VMs restart every 24 hours, causing deployment failures.
**Best Practice:** Use standard VMs for production, preemptible only for development/staging.

### 9. Migration Scripts in Production
**Lesson:** TypeScript migration configs don't work in production builds (only compiled JS exists).
**Best Practice:** Migrations handled via `npm run migration:run` in running backend container.

---

## Production Infrastructure Setup

**Completed Phases:**
1. ✅ Cloud SQL with Private IP (ZONAL - cost optimized)
2. ✅ Standard Production VM (e2-standard-2, non-preemptible)
3. ✅ SSL/HTTPS Certificates (configured)
4. ✅ Production Secret Manager (all credentials secure)
5. ✅ Monitoring & Alerting (email notifications)
6. ✅ Database Backup Strategy (daily + weekly off-site)
7. ✅ GitHub Secrets Configuration (CI/CD ready)

**Total Setup Time:** ~24 hours
**Monthly Cost:** $103 (under $118 budget)

---

## Quick Reference Commands

### Production VM

**SSH into production:**
```bash
gcloud compute ssh financial-rise-production-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod
```

**Check container status:**
```bash
gcloud compute ssh financial-rise-production-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod \
  --command="docker ps"
```

**Check backend logs:**
```bash
gcloud compute ssh financial-rise-production-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod \
  --command="docker logs financial-rise-backend-prod --tail 50"
```

### Secret Manager

**View current secret:**
```bash
gcloud secrets versions access latest \
  --secret=financial-rise-production-env \
  --project=financial-rise-prod | head -20
```

**Update secret:**
```bash
gcloud secrets versions add financial-rise-production-env \
  --data-file=.env.production \
  --project=financial-rise-prod
```

### Health Checks

**API health:**
```bash
curl http://34.72.61.170/api/v1/health
```

**Frontend:**
```bash
curl -I http://34.72.61.170/
```

### Monitoring

**View logs:**
```
https://console.cloud.google.com/logs?project=financial-rise-prod
```

**Monitoring dashboard:**
```
https://console.cloud.google.com/monitoring?project=financial-rise-prod
```

---

## Historical Issues (All Resolved)

**Issues 1-9 (2025-12-31 to 2026-01-01):**
- Volume mount conflicts
- DB_ENCRYPTION_KEY format
- Cloud SQL connection timeouts
- Preemptible VM shutdowns
- TypeORM index errors
- JWT environment variable naming
- Node.js crypto polyfill
- Frontend health check endpoints

**All historical issues documented in git history and Senior Developer Checklist.**

---

Run gcloud compute ssh *** \
Updating project ssh metadata...
.failed.
WARNING: 

To increase the performance of the tunnel, consider installing NumPy. For instructions,
please see https://cloud.google.com/iap/docs/using-tcp-forwarding#increasing_the_tcp_upload_bandwidth

.env file cleaned and ready:
DATABASE_HOST="34.134.76.171"
DATABASE_PORT="5432"
DATABASE_USER="financial_rise"
DATABASE_PASSWORD="ENY0j6eAnRNBUjupSduEeMTL3VGnjsvFrifnhBeXIYE="
DATABASE_NAME="financial_rise_production"
JWT_SECRET="K7+X7LOckZ6pAmf1lEU+7hckdex6C16dF8jqqg5GgNboYkEPUc4WRwwLqQuLRbzb1Q1PtjaTmfbaipteA53zEQ=="
JWT_REFRESH_SECRET="nKqbXDP7aWiWRMKjHFIqijE/ZCEH1rPhRGf3BJExRbpgGyvHwm+H3p0F988oY3bzNRpc8sfc1zWS2lJCbyq+kA=="
TOKEN_SECRET="K7+X7LOckZ6pAmf1lEU+7hckdex6C16dF8jqqg5GgNboYkEPUc4WRwwLqQuLRbzb1Q1PtjaTmfbaipteA53zEQ=="
REFRESH_TOKEN_SECRET="nKqbXDP7aWiWRMKjHFIqijE/ZCEH1rPhRGf3BJExRbpgGyvHwm+H3p0F988oY3bzNRpc8sfc1zWS2lJCbyq+kA=="
GCS_BUCKET="financial-rise-reports-production"
WARNING: Your config file at [/home/runner/.docker/config.json] contains these credential helper entries:

{
  "credHelpers": {
    "us-central1-docker.pkg.dev": "gcloud"
  }
}
Adding credentials for: us-central1-docker.pkg.dev
gcloud credential helpers already registered correctly.
92732c58c75a
7aa90c724485
a37c3ac1dc00
92732c58c75a
7aa90c724485
a37c3ac1dc00
 Volume financial-rise_redis_data  Removing
 Network financial-rise_financial-rise-network  Removing
 Volume financial-rise_redis_data  Removed
 Network financial-rise_financial-rise-network  Removed
Deleted Images:
untagged: redis:7-alpine
deleted: sha256:ee64a64eaab618d88051c3ade8f6352d11531fcf79d9a4818b9b183d8c1d18ba
deleted: sha256:4706ecab5371690fecfdd782268929c94ad5b5ce9ce0b35bfdfe191c4ad17851
deleted: sha256:0aee8a08a4509640029b3dcd2b55d9b1529994b9be897eb4cde35d4a39f74af1
untagged: us-central1-docker.pkg.dev/financial-rise-prod/financial-rise-docker/backend:latest
deleted: sha256:df4dfcc05b356c85879d528f201accfa00e6611f1307dcb3b1ef78c6d69de213
untagged: us-central1-docker.pkg.dev/financial-rise-prod/financial-rise-docker/frontend:latest
deleted: sha256:3820dd558ea9234b79c4a47811ad78845bd0731ace79d37366c1d7353f6246f5

Total reclaimed space: 458.4MB
Total reclaimed space: 0B
 frontend Pulling 
 backend Pulling 
 redis Pulling 
 d75b3becd998 Pulling fs layer 
 f637881d1138 Pulling fs layer 
 60c57c0072ef Pulling fs layer 
 fc4343b4accd Pulling fs layer 
 380e8aa8b1fd Pulling fs layer 
 c70aae7b5e0d Pulling fs layer 
 232f7549c9b0 Pulling fs layer 
 4f4fb700ef54 Pulling fs layer 
 d75b3becd998 Download complete 
 60c57c0072ef Download complete 
 fc4343b4accd Downloading [==================================================>]  173.2kB/173.2kB
 95050f4fb536 Download complete 
 380e8aa8b1fd Download complete 
 232f7549c9b0 Download complete 
 4f4fb700ef54 Download complete 
 f637881d1138 Downloading [============================>                      ]  2.097MB/3.643MB
 5f8375faf7cb Download complete 
 f637881d1138 Download complete 
 fc4343b4accd Download complete 
 c70aae7b5e0d Downloading [============>                                      ]  3.146MB/12.41MB
 f637881d1138 Extracting 1 s
 c70aae7b5e0d Downloading [=========================>                         ]  6.291MB/12.41MB
 f637881d1138 Extracting 1 s
 c70aae7b5e0d Downloading [=================================================> ]  12.33MB/12.41MB
 f637881d1138 Extracting 1 s
 c70aae7b5e0d Download complete 
 f637881d1138 Extracting 1 s
 60c57c0072ef Pull complete 
 f637881d1138 Pull complete 
 fc4343b4accd Extracting 1 s
 380e8aa8b1fd Pull complete 
 fc4343b4accd Pull complete 
 c70aae7b5e0d Extracting 1 s
 3bbef1cb92b5 Pulling fs layer 
 f18232174bc9 Pulling fs layer 
 1e5a4c89cee5 Pulling fs layer 
 25ff2da83641 Pulling fs layer 
 d0c04bd925be Pulling fs layer 
 a2efb84d4d81 Pulling fs layer 
 c340f398a2a7 Pulling fs layer 
 3ffe231b9118 Pulling fs layer 
 17f5814a975f Pulling fs layer 
 dd71dde834b5 Pulling fs layer 
 c70aae7b5e0d Extracting 1 s
 5e169bdae0b6 Pulling fs layer 
 0873dea1b8b3 Pulling fs layer 
 33f95a0f3229 Pulling fs layer 
 1074353eec0d Pulling fs layer 
 25f453064fd3 Pulling fs layer 
 567f84da6fbd Pulling fs layer 
 da7c973d8b92 Pulling fs layer 
 0abf9e567266 Pulling fs layer 
 085c5e5aaa8e Pulling fs layer 
 de54cb821236 Pulling fs layer 
 c70aae7b5e0d Extracting 1 s
 3bbef1cb92b5 Download complete 
 dd71dde834b5 Downloading [===>                                               ]  3.146MB/40.01MB
 f18232174bc9 Downloading [==================================================>]  3.642MB/3.642MB
 25ff2da83641 Download complete 
 d0c04bd925be Downloading [==================================================>]     978B/978B
 c340f398a2a7 Downloading [==================================================>]  122.8kB/122.8kB
 1e5a4c89cee5 Downloading [==================================================>]  1.261MB/1.261MB
 c70aae7b5e0d Extracting 1 s
 d0c04bd925be Downloading [==================================================>]     978B/978B
 a2efb84d4d81 Downloading [>                                                  ]  2.441MB/290.9MB
 c340f398a2a7 Downloading [==================================================>]  122.8kB/122.8kB
 3ffe231b9118 Downloading [=>                                                 ]  3.146MB/80.93MB
 17f5814a975f Downloading [==================================================>]     52kB/52kB
 1e5a4c89cee5 Download complete 
 dd71dde834b5 Downloading [=======>                                           ]  6.291MB/40.01MB
 f18232174bc9 Download complete 
 f18232174bc9 Extracting 1 s
 c70aae7b5e0d Pull complete 
 a2efb84d4d81 Downloading [=>                                                 ]  6.291MB/290.9MB
 c340f398a2a7 Download complete 
 5e169bdae0b6 Download complete 
 33f95a0f3229 Downloading [==================================================>]     403B/403B
 3ffe231b9118 Downloading [===>                                               ]  6.291MB/80.93MB
 da7c973d8b92 Download complete 
 de54cb821236 Downloading [===>                                               ]  1.049MB/17.26MB
 0abf9e567266 Downloading [==================================================>]  1.398kB/1.398kB
 0873dea1b8b3 Downloading [==================================================>]     835B/835B
 17f5814a975f Download complete 
 dd71dde834b5 Downloading [=============>                                     ]  10.49MB/40.01MB
 d0c04bd925be Download complete 
 f18232174bc9 Extracting 1 s
 567f84da6fbd Download complete 
 de54cb821236 Downloading [=========>                                         ]  3.146MB/17.26MB
 1074353eec0d Downloading [=======================>                           ]  1.839MB/3.86MB
 25f453064fd3 Downloading [==================================================>]  1.856MB/1.856MB
 0abf9e567266 Download complete 
 085c5e5aaa8e Downloading [==================================================>]  1.208kB/1.208kB
 3ffe231b9118 Downloading [=====>                                             ]  9.437MB/80.93MB
 dd71dde834b5 Downloading [===============>                                   ]  12.58MB/40.01MB
 a2efb84d4d81 Downloading [=>                                                 ]  8.389MB/290.9MB
 0873dea1b8b3 Download complete 
 33f95a0f3229 Download complete 
 f18232174bc9 Extracting 1 s
 232f7549c9b0 Pull complete 
 dd71dde834b5 Downloading [==================>                                ]  14.68MB/40.01MB
 a2efb84d4d81 Downloading [=>                                                 ]  9.437MB/290.9MB
 3ffe231b9118 Downloading [=======>                                           ]  11.53MB/80.93MB
 25f453064fd3 Download complete 
 085c5e5aaa8e Download complete 
 de54cb821236 Downloading [===============>                                   ]  5.243MB/17.26MB
 f18232174bc9 Extracting 1 s
 4f4fb700ef54 Pull complete 
 de54cb821236 Downloading [==================>                                ]  6.291MB/17.26MB
 1074353eec0d Download complete 
 a2efb84d4d81 Downloading [==>                                                ]  12.58MB/290.9MB
 3ffe231b9118 Downloading [========>                                          ]  13.63MB/80.93MB
 dd71dde834b5 Downloading [====================>                              ]  16.54MB/40.01MB
 f18232174bc9 Extracting 1 s
 1074353eec0d Extracting 1 s
 d75b3becd998 Pull complete 
 a2efb84d4d81 Downloading [==>                                                ]  14.68MB/290.9MB
 3ffe231b9118 Downloading [==========>                                        ]  16.78MB/80.93MB
 dd71dde834b5 Downloading [=======================>                           ]  18.87MB/40.01MB
 de54cb821236 Downloading [==============================>                    ]  10.49MB/17.26MB
 f18232174bc9 Extracting 1 s
 1074353eec0d Extracting 1 s
 de54cb821236 Downloading [====================================>              ]  12.58MB/17.26MB
 dd71dde834b5 Downloading [============================>                      ]  23.07MB/40.01MB
 a2efb84d4d81 Downloading [===>                                               ]  17.83MB/290.9MB
 3ffe231b9118 Downloading [============>                                      ]  19.92MB/80.93MB
 f18232174bc9 Pull complete 
 1074353eec0d Extracting 1 s
 de54cb821236 Downloading [==================================================>]  17.26MB/17.26MB
 dd71dde834b5 Downloading [=================================>                 ]  26.54MB/40.01MB
 a2efb84d4d81 Downloading [===>                                               ]  22.02MB/290.9MB
 3ffe231b9118 Downloading [==============>                                    ]  23.07MB/80.93MB
 redis Pulled 
 1074353eec0d Extracting 1 s
 de54cb821236 Download complete 
 dd71dde834b5 Downloading [=======================================>           ]  31.46MB/40.01MB
 a2efb84d4d81 Downloading [====>                                              ]  26.21MB/290.9MB
 3ffe231b9118 Downloading [================>                                  ]  27.26MB/80.93MB
 25f453064fd3 Extracting 1 s
 1074353eec0d Pull complete 
 dd71dde834b5 Downloading [=============================================>     ]   36.7MB/40.01MB
 a2efb84d4d81 Downloading [=====>                                             ]  31.46MB/290.9MB
 3ffe231b9118 Downloading [===================>                               ]  31.09MB/80.93MB
 25f453064fd3 Extracting 1 s
 dd71dde834b5 Downloading [================================================>  ]   38.8MB/40.01MB
 a2efb84d4d81 Downloading [=====>                                             ]   34.6MB/290.9MB
 3ffe231b9118 Downloading [=====================>                             ]   34.6MB/80.93MB
 25f453064fd3 Extracting 1 s
 a2efb84d4d81 Downloading [======>                                            ]   38.8MB/290.9MB
 3ffe231b9118 Downloading [=======================>                           ]  37.82MB/80.93MB
 dd71dde834b5 Downloading [==================================================>]  40.01MB/40.01MB
 25f453064fd3 Extracting 1 s
 567f84da6fbd Extracting 1 s
 a2efb84d4d81 Downloading [=======>                                           ]  42.99MB/290.9MB
 3ffe231b9118 Downloading [=========================>                         ]  40.89MB/80.93MB
 dd71dde834b5 Download complete 
 25f453064fd3 Pull complete 
 dd71dde834b5 Extracting 1 s
 a2efb84d4d81 Downloading [=======>                                           ]  46.38MB/290.9MB
 3ffe231b9118 Downloading [===========================>                       ]  43.91MB/80.93MB
 da7c973d8b92 Pull complete 
 567f84da6fbd Pull complete 
 dd71dde834b5 Extracting 1 s
 a2efb84d4d81 Downloading [========>                                          ]  48.98MB/290.9MB
 3ffe231b9118 Downloading [============================>                      ]  46.14MB/80.93MB
 33f95a0f3229 Pull complete 
 085c5e5aaa8e Pull complete 
 dd71dde834b5 Extracting 1 s
 0abf9e567266 Pull complete 
 a2efb84d4d81 Downloading [=========>                                         ]  53.48MB/290.9MB
 3ffe231b9118 Downloading [===============================>                   ]  50.33MB/80.93MB
 de54cb821236 Extracting 1 s
 dd71dde834b5 Extracting 1 s
 de54cb821236 Extracting 1 s
 a2efb84d4d81 Downloading [=========>                                         ]  58.06MB/290.9MB
 3ffe231b9118 Downloading [=================================>                 ]  54.82MB/80.93MB
 dd71dde834b5 Extracting 1 s
 de54cb821236 Extracting 1 s
 a2efb84d4d81 Downloading [==========>                                        ]  61.87MB/290.9MB
 3ffe231b9118 Downloading [====================================>              ]  58.72MB/80.93MB
 dd71dde834b5 Extracting 1 s
 a2efb84d4d81 Downloading [===========>                                       ]  68.01MB/290.9MB
 3ffe231b9118 Downloading [========================================>          ]  66.06MB/80.93MB
 de54cb821236 Extracting 1 s
 dd71dde834b5 Extracting 1 s
 a2efb84d4d81 Downloading [============>                                      ]  72.35MB/290.9MB
 3ffe231b9118 Downloading [============================================>      ]  71.82MB/80.93MB
 de54cb821236 Extracting 1 s
 dd71dde834b5 Extracting 1 s
 a2efb84d4d81 Downloading [=============>                                     ]  77.59MB/290.9MB
 3ffe231b9118 Downloading [================================================>  ]  78.64MB/80.93MB
 de54cb821236 Extracting 1 s
 dd71dde834b5 Extracting 1 s
 a2efb84d4d81 Downloading [==============>                                    ]  83.89MB/290.9MB
 3ffe231b9118 Downloading [==================================================>]  80.93MB/80.93MB
 de54cb821236 Extracting 1 s
 dd71dde834b5 Extracting 1 s
 a2efb84d4d81 Downloading [===============>                                   ]  90.27MB/290.9MB
 3ffe231b9118 Downloading [==================================================>]  80.93MB/80.93MB
 de54cb821236 Extracting 1 s
 dd71dde834b5 Extracting 1 s
 de54cb821236 Extracting 1 s
 a2efb84d4d81 Downloading [=================>                                 ]  99.61MB/290.9MB
 3ffe231b9118 Download complete 
 dd71dde834b5 Extracting 2 s
 a2efb84d4d81 Downloading [=================>                                 ]  103.8MB/290.9MB
 de54cb821236 Extracting 1 s
 dd71dde834b5 Extracting 2 s
 de54cb821236 Extracting 1 s
 a2efb84d4d81 Downloading [==================>                                ]  110.1MB/290.9MB
 dd71dde834b5 Extracting 2 s
 a2efb84d4d81 Downloading [===================>                               ]  114.4MB/290.9MB
 de54cb821236 Extracting 2 s
 dd71dde834b5 Extracting 2 s
 de54cb821236 Extracting 2 s
 a2efb84d4d81 Downloading [====================>                              ]  119.5MB/290.9MB
 dd71dde834b5 Extracting 2 s
 a2efb84d4d81 Downloading [=====================>                             ]  123.7MB/290.9MB
 de54cb821236 Extracting 2 s
 dd71dde834b5 Extracting 2 s
 a2efb84d4d81 Downloading [======================>                            ]    129MB/290.9MB
 de54cb821236 Extracting 2 s
 dd71dde834b5 Extracting 2 s
 de54cb821236 Extracting 2 s
 a2efb84d4d81 Downloading [=======================>                           ]  135.3MB/290.9MB
 dd71dde834b5 Extracting 2 s
 de54cb821236 Extracting 2 s
 a2efb84d4d81 Downloading [========================>                          ]  141.3MB/290.9MB
 dd71dde834b5 Extracting 2 s
 5e169bdae0b6 Extracting 1 s
 0873dea1b8b3 Pull complete 
 a2efb84d4d81 Downloading [=========================>                         ]  148.9MB/290.9MB
 de54cb821236 Pull complete 
 dd71dde834b5 Extracting 2 s
 a2efb84d4d81 Downloading [==========================>                        ]  155.1MB/290.9MB
 5e169bdae0b6 Pull complete 
 frontend Pulled 
 dd71dde834b5 Extracting 3 s
 a2efb84d4d81 Downloading [===========================>                       ]  160.4MB/290.9MB
 dd71dde834b5 Extracting 3 s
 a2efb84d4d81 Downloading [=============================>                     ]  168.8MB/290.9MB
 dd71dde834b5 Extracting 3 s
 a2efb84d4d81 Downloading [===============================>                   ]  182.5MB/290.9MB
 dd71dde834b5 Extracting 3 s
 a2efb84d4d81 Downloading [=================================>                 ]    195MB/290.9MB
 dd71dde834b5 Extracting 3 s
 a2efb84d4d81 Downloading [===================================>               ]  204.5MB/290.9MB
 dd71dde834b5 Extracting 3 s
 a2efb84d4d81 Downloading [====================================>              ]    215MB/290.9MB
 dd71dde834b5 Extracting 3 s
 a2efb84d4d81 Downloading [=======================================>           ]  227.5MB/290.9MB
 dd71dde834b5 Extracting 3 s
 a2efb84d4d81 Downloading [========================================>          ]  237.2MB/290.9MB
 dd71dde834b5 Extracting 3 s
 a2efb84d4d81 Downloading [=========================================>         ]  241.6MB/290.9MB
 dd71dde834b5 Extracting 3 s
 a2efb84d4d81 Downloading [==========================================>        ]  245.4MB/290.9MB
 dd71dde834b5 Extracting 4 s
 a2efb84d4d81 Downloading [===========================================>       ]  250.6MB/290.9MB
 dd71dde834b5 Extracting 4 s
 a2efb84d4d81 Downloading [===========================================>       ]  254.4MB/290.9MB
 dd71dde834b5 Extracting 4 s
 a2efb84d4d81 Downloading [============================================>      ]  259.6MB/290.9MB
 dd71dde834b5 Extracting 4 s
 a2efb84d4d81 Downloading [=============================================>     ]  264.3MB/290.9MB
 dd71dde834b5 Extracting 4 s
 a2efb84d4d81 Downloading [==============================================>    ]  269.5MB/290.9MB
 dd71dde834b5 Extracting 4 s
 a2efb84d4d81 Downloading [===============================================>   ]  273.7MB/290.9MB
 dd71dde834b5 Extracting 4 s
 a2efb84d4d81 Downloading [===============================================>   ]    276MB/290.9MB
 dd71dde834b5 Extracting 4 s
 a2efb84d4d81 Downloading [================================================>  ]  280.8MB/290.9MB
 dd71dde834b5 Extracting 4 s
 a2efb84d4d81 Downloading [=================================================> ]  285.2MB/290.9MB
 dd71dde834b5 Extracting 4 s
 a2efb84d4d81 Downloading [==================================================>]  290.9MB/290.9MB
 dd71dde834b5 Extracting 5 s
 a2efb84d4d81 Downloading [==================================================>]  290.9MB/290.9MB
 dd71dde834b5 Extracting 5 s
 a2efb84d4d81 Downloading [==================================================>]  290.9MB/290.9MB
 dd71dde834b5 Extracting 5 s
 a2efb84d4d81 Downloading [==================================================>]  290.9MB/290.9MB
 a2efb84d4d81 Downloading [==================================================>]  290.9MB/290.9MB
 a2efb84d4d81 Downloading [==================================================>]  290.9MB/290.9MB
 dd71dde834b5 Pull complete 
 a2efb84d4d81 Downloading [==================================================>]  290.9MB/290.9MB
 a2efb84d4d81 Downloading [==================================================>]  290.9MB/290.9MB
 a2efb84d4d81 Downloading [==================================================>]  290.9MB/290.9MB
 a2efb84d4d81 Downloading [==================================================>]  290.9MB/290.9MB
 a2efb84d4d81 Downloading [==================================================>]  290.9MB/290.9MB
 a2efb84d4d81 Download complete 
 1e5a4c89cee5 Extracting 1 s
 1e5a4c89cee5 Pull complete 
 3bbef1cb92b5 Pull complete 
 25ff2da83641 Pull complete 
 a2efb84d4d81 Extracting 1 s
 a2efb84d4d81 Extracting 1 s
 a2efb84d4d81 Extracting 1 s
 a2efb84d4d81 Extracting 1 s
 a2efb84d4d81 Extracting 1 s
 a2efb84d4d81 Extracting 1 s
 a2efb84d4d81 Extracting 1 s
 a2efb84d4d81 Extracting 1 s
 a2efb84d4d81 Extracting 1 s
 a2efb84d4d81 Extracting 1 s
 a2efb84d4d81 Extracting 1 s
 a2efb84d4d81 Extracting 2 s
 a2efb84d4d81 Extracting 2 s
 a2efb84d4d81 Extracting 2 s
 a2efb84d4d81 Extracting 2 s
 a2efb84d4d81 Extracting 2 s
 a2efb84d4d81 Extracting 2 s
 a2efb84d4d81 Extracting 2 s
 a2efb84d4d81 Extracting 2 s
 a2efb84d4d81 Extracting 2 s
 a2efb84d4d81 Extracting 2 s
 a2efb84d4d81 Extracting 3 s
 a2efb84d4d81 Extracting 3 s
 a2efb84d4d81 Extracting 3 s
 a2efb84d4d81 Extracting 3 s
 a2efb84d4d81 Extracting 3 s
 a2efb84d4d81 Extracting 3 s
 a2efb84d4d81 Extracting 3 s
 a2efb84d4d81 Extracting 3 s
 a2efb84d4d81 Extracting 3 s
 a2efb84d4d81 Extracting 3 s
 a2efb84d4d81 Extracting 4 s
 a2efb84d4d81 Extracting 4 s
 a2efb84d4d81 Extracting 4 s
 a2efb84d4d81 Extracting 4 s
 a2efb84d4d81 Extracting 4 s
 a2efb84d4d81 Extracting 4 s
 a2efb84d4d81 Extracting 4 s
 a2efb84d4d81 Extracting 4 s
 a2efb84d4d81 Extracting 4 s
 a2efb84d4d81 Extracting 4 s
 a2efb84d4d81 Extracting 5 s
 a2efb84d4d81 Extracting 5 s
 a2efb84d4d81 Extracting 5 s
 a2efb84d4d81 Extracting 5 s
 a2efb84d4d81 Extracting 5 s
 a2efb84d4d81 Extracting 5 s
 a2efb84d4d81 Extracting 5 s
 a2efb84d4d81 Extracting 5 s
 a2efb84d4d81 Extracting 5 s
 a2efb84d4d81 Extracting 6 s
 a2efb84d4d81 Extracting 6 s
 a2efb84d4d81 Extracting 6 s
 a2efb84d4d81 Extracting 6 s
 a2efb84d4d81 Extracting 6 s
 a2efb84d4d81 Extracting 6 s
 a2efb84d4d81 Extracting 6 s
 a2efb84d4d81 Extracting 6 s
 a2efb84d4d81 Extracting 6 s
 a2efb84d4d81 Extracting 6 s
 a2efb84d4d81 Extracting 6 s
 a2efb84d4d81 Extracting 7 s
 a2efb84d4d81 Extracting 7 s
 a2efb84d4d81 Extracting 7 s
 a2efb84d4d81 Extracting 7 s
 a2efb84d4d81 Extracting 7 s
 a2efb84d4d81 Extracting 7 s
 a2efb84d4d81 Extracting 7 s
 a2efb84d4d81 Extracting 7 s
 a2efb84d4d81 Extracting 7 s
 a2efb84d4d81 Extracting 8 s
 a2efb84d4d81 Extracting 8 s
 a2efb84d4d81 Extracting 8 s
 a2efb84d4d81 Extracting 8 s
 a2efb84d4d81 Extracting 8 s
 a2efb84d4d81 Extracting 8 s
 a2efb84d4d81 Extracting 8 s
 a2efb84d4d81 Extracting 8 s
 a2efb84d4d81 Extracting 8 s
 a2efb84d4d81 Extracting 8 s
 a2efb84d4d81 Extracting 9 s
 a2efb84d4d81 Extracting 9 s
 a2efb84d4d81 Extracting 9 s
 a2efb84d4d81 Extracting 9 s
 a2efb84d4d81 Extracting 9 s
 a2efb84d4d81 Extracting 9 s
 a2efb84d4d81 Extracting 9 s
 a2efb84d4d81 Extracting 9 s
 a2efb84d4d81 Extracting 9 s
 a2efb84d4d81 Extracting 9 s
 a2efb84d4d81 Extracting 9 s
 a2efb84d4d81 Extracting 10 s
 a2efb84d4d81 Extracting 10 s
 a2efb84d4d81 Extracting 10 s
 a2efb84d4d81 Extracting 10 s
 a2efb84d4d81 Extracting 10 s
 a2efb84d4d81 Extracting 10 s
 a2efb84d4d81 Extracting 10 s
 a2efb84d4d81 Extracting 10 s
 a2efb84d4d81 Extracting 10 s
 a2efb84d4d81 Extracting 10 s
 a2efb84d4d81 Extracting 11 s
 a2efb84d4d81 Extracting 11 s
 a2efb84d4d81 Extracting 11 s
 a2efb84d4d81 Extracting 11 s
 a2efb84d4d81 Extracting 11 s
 a2efb84d4d81 Extracting 11 s
 a2efb84d4d81 Extracting 11 s
 a2efb84d4d81 Extracting 11 s
 a2efb84d4d81 Extracting 11 s
 a2efb84d4d81 Extracting 11 s
 a2efb84d4d81 Extracting 12 s
 a2efb84d4d81 Extracting 12 s
 a2efb84d4d81 Extracting 12 s
 a2efb84d4d81 Extracting 12 s
 a2efb84d4d81 Extracting 12 s
 a2efb84d4d81 Extracting 12 s
 a2efb84d4d81 Extracting 12 s
 a2efb84d4d81 Extracting 12 s
 a2efb84d4d81 Extracting 12 s
 a2efb84d4d81 Extracting 12 s
 a2efb84d4d81 Extracting 13 s
 a2efb84d4d81 Extracting 13 s
 a2efb84d4d81 Extracting 13 s
 a2efb84d4d81 Extracting 13 s
 a2efb84d4d81 Extracting 13 s
 a2efb84d4d81 Extracting 13 s
 a2efb84d4d81 Extracting 13 s
 a2efb84d4d81 Extracting 13 s
 a2efb84d4d81 Extracting 13 s
 a2efb84d4d81 Extracting 13 s
 a2efb84d4d81 Extracting 14 s
 a2efb84d4d81 Extracting 14 s
 a2efb84d4d81 Extracting 14 s
 a2efb84d4d81 Extracting 14 s
 a2efb84d4d81 Extracting 14 s
 a2efb84d4d81 Extracting 14 s
 a2efb84d4d81 Extracting 14 s
 a2efb84d4d81 Extracting 14 s
 a2efb84d4d81 Extracting 14 s
 a2efb84d4d81 Extracting 14 s
 a2efb84d4d81 Extracting 15 s
 a2efb84d4d81 Extracting 15 s
 a2efb84d4d81 Extracting 15 s
 a2efb84d4d81 Extracting 15 s
 a2efb84d4d81 Extracting 15 s
 a2efb84d4d81 Extracting 15 s
 a2efb84d4d81 Extracting 15 s
 a2efb84d4d81 Extracting 15 s
 c340f398a2a7 Extracting 1 s
 a2efb84d4d81 Pull complete 
 c340f398a2a7 Pull complete 
 3ffe231b9118 Extracting 1 s
 3ffe231b9118 Extracting 1 s
 3ffe231b9118 Extracting 1 s
 3ffe231b9118 Extracting 1 s
 3ffe231b9118 Extracting 1 s
 3ffe231b9118 Extracting 1 s
 3ffe231b9118 Extracting 1 s
 3ffe231b9118 Extracting 1 s
 3ffe231b9118 Extracting 1 s
 3ffe231b9118 Extracting 1 s
 3ffe231b9118 Extracting 1 s
 3ffe231b9118 Extracting 2 s
 3ffe231b9118 Extracting 2 s
 3ffe231b9118 Extracting 2 s
 3ffe231b9118 Extracting 2 s
 3ffe231b9118 Extracting 2 s
 3ffe231b9118 Extracting 2 s
 3ffe231b9118 Extracting 2 s
 3ffe231b9118 Extracting 2 s
 3ffe231b9118 Extracting 2 s
 3ffe231b9118 Extracting 3 s
 3ffe231b9118 Extracting 3 s
 3ffe231b9118 Extracting 3 s
 3ffe231b9118 Extracting 3 s
 3ffe231b9118 Extracting 3 s
 3ffe231b9118 Extracting 3 s
 3ffe231b9118 Extracting 3 s
 3ffe231b9118 Extracting 3 s
 3ffe231b9118 Extracting 3 s
 3ffe231b9118 Extracting 3 s
 3ffe231b9118 Extracting 3 s
 3ffe231b9118 Extracting 4 s
 3ffe231b9118 Extracting 4 s
 3ffe231b9118 Extracting 4 s
 3ffe231b9118 Extracting 4 s
 3ffe231b9118 Extracting 4 s
 3ffe231b9118 Extracting 4 s
 3ffe231b9118 Extracting 4 s
 3ffe231b9118 Extracting 4 s
 3ffe231b9118 Extracting 4 s
 3ffe231b9118 Extracting 4 s
 3ffe231b9118 Extracting 5 s
 3ffe231b9118 Extracting 5 s
 3ffe231b9118 Extracting 5 s
 3ffe231b9118 Extracting 5 s
 3ffe231b9118 Extracting 5 s
 3ffe231b9118 Extracting 5 s
 3ffe231b9118 Extracting 5 s
 3ffe231b9118 Extracting 5 s
 3ffe231b9118 Extracting 5 s
 3ffe231b9118 Extracting 5 s
 3ffe231b9118 Extracting 6 s
 3ffe231b9118 Extracting 6 s
 3ffe231b9118 Extracting 6 s
 3ffe231b9118 Extracting 6 s
 3ffe231b9118 Extracting 6 s
 3ffe231b9118 Extracting 6 s
 3ffe231b9118 Extracting 6 s
 3ffe231b9118 Extracting 6 s
 3ffe231b9118 Extracting 6 s
 3ffe231b9118 Extracting 6 s
 3ffe231b9118 Extracting 7 s
 3ffe231b9118 Extracting 7 s
 3ffe231b9118 Extracting 7 s
 3ffe231b9118 Extracting 7 s
 3ffe231b9118 Extracting 7 s
 3ffe231b9118 Extracting 7 s
 3ffe231b9118 Extracting 7 s
 3ffe231b9118 Extracting 7 s
 3ffe231b9118 Extracting 7 s
 3ffe231b9118 Extracting 7 s
 3ffe231b9118 Extracting 8 s
 3ffe231b9118 Extracting 8 s
 3ffe231b9118 Extracting 8 s
 3ffe231b9118 Extracting 8 s
 3ffe231b9118 Extracting 8 s
 3ffe231b9118 Extracting 8 s
 3ffe231b9118 Extracting 8 s
 3ffe231b9118 Extracting 8 s
 3ffe231b9118 Extracting 8 s
 3ffe231b9118 Extracting 9 s
 3ffe231b9118 Extracting 9 s
 3ffe231b9118 Extracting 9 s
 3ffe231b9118 Extracting 9 s
 3ffe231b9118 Extracting 9 s
 3ffe231b9118 Extracting 9 s
 3ffe231b9118 Extracting 9 s
 3ffe231b9118 Extracting 9 s
 3ffe231b9118 Extracting 9 s
 3ffe231b9118 Extracting 9 s
 3ffe231b9118 Extracting 10 s
 3ffe231b9118 Extracting 10 s
 3ffe231b9118 Extracting 10 s
 3ffe231b9118 Extracting 10 s
 3ffe231b9118 Extracting 10 s
 3ffe231b9118 Extracting 10 s
 3ffe231b9118 Extracting 10 s
 3ffe231b9118 Extracting 10 s
 3ffe231b9118 Extracting 10 s
 3ffe231b9118 Extracting 10 s
 3ffe231b9118 Extracting 11 s
 3ffe231b9118 Extracting 11 s
 3ffe231b9118 Extracting 11 s
 3ffe231b9118 Extracting 11 s
 3ffe231b9118 Extracting 11 s
 3ffe231b9118 Extracting 11 s
 3ffe231b9118 Extracting 11 s
 3ffe231b9118 Extracting 11 s
 3ffe231b9118 Extracting 11 s
 3ffe231b9118 Extracting 11 s
 3ffe231b9118 Extracting 11 s
 17f5814a975f Pull complete 
 d0c04bd925be Pull complete 
 3ffe231b9118 Pull complete 
 backend Pulled 
Restarting backend...
 Network financial-rise_financial-rise-network  Creating
 Network financial-rise_financial-rise-network  Created
 Volume "financial-rise_redis_data"  Creating
 Volume "financial-rise_redis_data"  Created
 Container financial-rise-backend-prod  Creating
 Container financial-rise-backend-prod  Created
 Container financial-rise-backend-prod  Starting
 Container financial-rise-backend-prod  Started

> financial-rise-backend@1.0.0 migration:run
> npm run typeorm migration:run -- -d src/config/typeorm.config.ts


> financial-rise-backend@1.0.0 typeorm
> typeorm-ts-node-commonjs migration:run -d src/config/typeorm.config.ts

Error during migration run:
Error: Unable to open file: "/app/src/config/typeorm.config.ts". Cannot find module '/app/src/config/typeorm.config.ts'
Require stack:
- /app/node_modules/typeorm/util/ImportUtils.js
- /app/node_modules/typeorm/commands/CommandUtils.js
- /app/node_modules/typeorm/commands/SchemaSyncCommand.js
- /app/node_modules/typeorm/cli.js
- /app/node_modules/typeorm/cli-ts-node-commonjs.js
    at Function.loadDataSource (/app/node_modules/src/commands/CommandUtils.ts:21:19)
    at async Object.handler (/app/node_modules/src/commands/MigrationRunCommand.ts:42:26)
npm notice
npm notice New major version of npm available! 10.8.2 -> 11.7.0
npm notice Changelog: https://github.com/npm/cli/releases/tag/v11.7.0
npm notice To update run: npm install -g npm@11.7.0
npm notice
Migrations completed
Restarting frontend...
 Container financial-rise-frontend-prod  Creating
 Container financial-rise-frontend-prod  Created
 Container financial-rise-frontend-prod  Starting
 Container financial-rise-frontend-prod  Started
CONTAINER ID   IMAGE                                                                                  COMMAND                  CREATED          STATUS                             PORTS                                                                          NAMES
fb6809075f2d   us-central1-docker.pkg.dev/financial-rise-prod/financial-rise-docker/frontend:latest   "/docker-entrypoint.…"   11 seconds ago   Up 10 seconds (health: starting)   0.0.0.0:80->80/tcp, [::]:80->80/tcp, 0.0.0.0:443->443/tcp, [::]:443->443/tcp   financial-rise-frontend-prod
237633390cfa   us-central1-docker.pkg.dev/financial-rise-prod/financial-rise-docker/backend:latest    "docker-entrypoint.s…"   29 seconds ago   Up 28 seconds                      3000/tcp, 4000/tcp                                                             financial-rise-backend-prod

---

## ✅ RESOLUTION: Production Cloud SQL Connectivity Issue - FIXED (2026-01-03)

### Issue Identified
Backend container deployed successfully but could not connect to Cloud SQL database:
```
Error: connect ETIMEDOUT 34.134.76.171:5432
[TypeOrmModule] Unable to connect to the database. Retrying (1-5)...
```

### Root Cause
Diagnostic investigation using `diagnose-cloud-sql-connectivity.sh` revealed:
1. Cloud SQL instance `financial-rise-production-db` had **NO private IP configured** - only public IP (34.134.76.171)
2. VM's public IP (34.72.61.170) was **not in Cloud SQL authorized networks**
3. VPC peering did not exist because private IP was never set up during infrastructure provisioning
4. ICMP (ping) worked but TCP port 5432 was blocked by Cloud SQL firewall

### Fix Applied
**Script:** `quick-fix-cloud-sql-access.sh`

**Actions:**
1. Retrieved production VM's public IP: `34.72.61.170`
2. Added VM IP to Cloud SQL authorized networks:
   ```bash
   gcloud sql instances patch financial-rise-production-db \
     --authorized-networks=34.72.61.170 \
     --project=financial-rise-prod
   ```
3. Restarted backend container to establish connection

### Verification
✅ **Production Health Check PASSED:**
```bash
$ curl http://34.72.61.170/api/v1/health
{"status":"ok","timestamp":"2026-01-03T19:18:09.818Z","service":"financial-rise-api"}
```

**Services Status:**
- ✅ Frontend: Responding (HTTP 200)
- ✅ Backend: Healthy and connected to database
- ✅ Database: Connected and accessible

### Production Status
🎉 **PRODUCTION IS LIVE at http://34.72.61.170**

**Current Configuration:**
- Connection Type: Public IP with authorized networks (temporary)
- Authorized IP: 34.72.61.170 (production VM)

**Recommended Next Step:**
Run `fix-cloud-sql-private-ip.sh` to configure private IP with VPC peering for proper production security. Requires ~30-45 minutes for database restart.

**Full deployment summary:** See `PRODUCTION-DEPLOYMENT-SUCCESS.md`

---

*All production deployment issues resolved. Application is live and operational.*

Run npm run test:cov

> financial-rise-backend@1.0.0 test:cov
> jest --coverage

ts-jest[ts-jest-transformer] (WARN) Define `ts-jest` config under `globals` is deprecated. Please do
transform: {
    <transform_regex>: ['ts-jest', { /* ts-jest config goes here in Jest */ }],
},
See more at https://kulshekhar.github.io/ts-jest/docs/getting-started/presets#advanced
ts-jest[ts-jest-transformer] (WARN) Define `ts-jest` config under `globals` is deprecated. Please do
transform: {
    <transform_regex>: ['ts-jest', { /* ts-jest config goes here in Jest */ }],
},
See more at https://kulshekhar.github.io/ts-jest/docs/getting-started/presets#advanced
ts-jest[ts-jest-transformer] (WARN) Define `ts-jest` config under `globals` is deprecated. Please do
transform: {
    <transform_regex>: ['ts-jest', { /* ts-jest config goes here in Jest */ }],
},
See more at https://kulshekhar.github.io/ts-jest/docs/getting-started/presets#advanced
PASS src/common/utils/log-sanitizer.spec.ts (10.364 s)
PASS src/modules/assessments/services/validation.service.spec.ts
PASS src/modules/users/users-processing-restriction.spec.ts (13.091 s)
PASS src/modules/auth/auth.service.spec.ts (14.104 s)
PASS src/config/typeorm-ssl.config.spec.ts
  ● Console

    console.warn
      [TypeORM SSL] CA certificate file not found: /invalid/path/that/does/not/exist.pem

      46 |       } else {
      47 |         // Log warning but don't fail - connection attempt will reveal if cert is actually needed
    > 48 |         console.warn(`[TypeORM SSL] CA certificate file not found: ${caPath}`);
         |                 ^
      49 |       }
      50 |     } catch (error) {
      51 |       // Log error but don't throw - allow TypeORM to handle connection failure

      at warn (config/typeorm.config.ts:48:17)
      at getSSLConfig (config/typeorm.config.ts:81:8)
      at config/typeorm-ssl.config.spec.ts:389:33
      at Object.<anonymous> (../node_modules/expect/build/toThrowMatchers.js:74:11)
      at Object.throwingMatcher [as toThrow] (../node_modules/expect/build/index.js:320:21)
      at Object.<anonymous> (config/typeorm-ssl.config.spec.ts:389:58)

    console.warn
      [TypeORM SSL] CA certificate file not found: /invalid/path/that/does/not/exist.pem

      46 |       } else {
      47 |         // Log warning but don't fail - connection attempt will reveal if cert is actually needed
    > 48 |         console.warn(`[TypeORM SSL] CA certificate file not found: ${caPath}`);
         |                 ^
      49 |       }
      50 |     } catch (error) {
      51 |       // Log error but don't throw - allow TypeORM to handle connection failure

      at warn (config/typeorm.config.ts:48:17)
      at getSSLConfig (config/typeorm.config.ts:81:8)
      at Object.<anonymous> (config/typeorm-ssl.config.spec.ts:391:40)

[Nest] 3582  - 01/04/2026, 7:57:42 PM   ERROR [ExceptionsHandler] request entity too large
PayloadTooLargeError: request entity too large
    at readStream (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:163:17)
    at getRawBody (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:116:12)
    at read (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/read.js:79:3)
    at jsonParser (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/types/json.js:138:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at expressInit (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/init.js:40:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at query (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/query.js:45:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:175:3)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/application.js:181:10)
    at Server.app (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/express.js:39:9)
    at Server.emit (node:events:517:28)
    at parserOnIncoming (node:_http_server:1130:12)
    at HTTPParser.parserOnHeadersComplete (node:_http_common:119:17)
[Nest] 3582  - 01/04/2026, 7:57:42 PM   ERROR [ExceptionsHandler] request entity too large
PayloadTooLargeError: request entity too large
    at readStream (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:163:17)
    at getRawBody (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:116:12)
    at read (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/read.js:79:3)
    at jsonParser (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/types/json.js:138:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at expressInit (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/init.js:40:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at query (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/query.js:45:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:175:3)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/application.js:181:10)
    at Server.app (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/express.js:39:9)
    at Server.emit (node:events:517:28)
    at parserOnIncoming (node:_http_server:1130:12)
    at HTTPParser.parserOnHeadersComplete (node:_http_common:119:17)
PASS src/modules/assessments/services/progress.service.spec.ts
[Nest] 3582  - 01/04/2026, 7:57:43 PM   ERROR [ExceptionsHandler] request entity too large
PayloadTooLargeError: request entity too large
    at readStream (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:163:17)
    at getRawBody (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:116:12)
    at read (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/read.js:79:3)
    at urlencodedParser (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/types/urlencoded.js:119:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at jsonParser (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/types/json.js:122:7)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at expressInit (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/init.js:40:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at query (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/query.js:45:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:175:3)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/application.js:181:10)
    at Server.app (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/express.js:39:9)
    at Server.emit (node:events:517:28)
    at parserOnIncoming (node:_http_server:1130:12)
    at HTTPParser.parserOnHeadersComplete (node:_http_common:119:17)
PASS src/modules/questionnaire/questionnaire.service.spec.ts
PASS src/modules/consents/consents.service.spec.ts
PASS src/modules/users/users.service.spec.ts
[Nest] 3582  - 01/04/2026, 7:57:44 PM   ERROR [ExceptionsHandler] request entity too large
PayloadTooLargeError: request entity too large
    at readStream (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:163:17)
    at getRawBody (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:116:12)
    at read (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/read.js:79:3)
    at jsonParser (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/types/json.js:138:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at expressInit (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/init.js:40:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at query (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/query.js:45:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:175:3)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/application.js:181:10)
    at Server.app (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/express.js:39:9)
    at Server.emit (node:events:517:28)
    at parserOnIncoming (node:_http_server:1130:12)
    at HTTPParser.parserOnHeadersComplete (node:_http_common:119:17)
[Nest] 3582  - 01/04/2026, 7:57:44 PM   ERROR [ExceptionsHandler] request entity too large
PayloadTooLargeError: request entity too large
    at readStream (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:163:17)
    at getRawBody (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:116:12)
    at read (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/read.js:79:3)
    at urlencodedParser (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/types/urlencoded.js:119:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at jsonParser (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/types/json.js:122:7)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at expressInit (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/init.js:40:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at query (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/query.js:45:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:175:3)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/application.js:181:10)
    at Server.app (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/express.js:39:9)
    at Server.emit (node:events:517:28)
    at parserOnIncoming (node:_http_server:1130:12)
    at HTTPParser.parserOnHeadersComplete (node:_http_common:119:17)
[Nest] 3582  - 01/04/2026, 7:57:45 PM   ERROR [ExceptionsHandler] request entity too large
PayloadTooLargeError: request entity too large
    at readStream (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:163:17)
    at getRawBody (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:116:12)
    at read (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/read.js:79:3)
    at jsonParser (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/types/json.js:138:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at expressInit (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/init.js:40:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at query (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/query.js:45:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:175:3)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/application.js:181:10)
    at Server.app (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/express.js:39:9)
    at Server.emit (node:events:517:28)
    at parserOnIncoming (node:_http_server:1130:12)
    at HTTPParser.parserOnHeadersComplete (node:_http_common:119:17)
[Nest] 3582  - 01/04/2026, 7:57:45 PM   ERROR [ExceptionsHandler] request entity too large
PayloadTooLargeError: request entity too large
    at readStream (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:163:17)
    at getRawBody (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:116:12)
    at read (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/read.js:79:3)
    at jsonParser (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/types/json.js:138:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at expressInit (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/init.js:40:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at query (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/query.js:45:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:175:3)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/application.js:181:10)
    at Server.app (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/express.js:39:9)
    at Server.emit (node:events:517:28)
    at parserOnIncoming (node:_http_server:1130:12)
    at HTTPParser.parserOnHeadersComplete (node:_http_common:119:17)
PASS src/modules/algorithms/entities/disc-profile.encryption.spec.ts
[Nest] 3582  - 01/04/2026, 7:57:45 PM   ERROR [ExceptionsHandler] request entity too large
PayloadTooLargeError: request entity too large
    at readStream (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:163:17)
    at getRawBody (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:116:12)
    at read (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/read.js:79:3)
    at jsonParser (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/types/json.js:138:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at expressInit (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/init.js:40:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at query (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/query.js:45:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:175:3)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/application.js:181:10)
    at Server.app (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/express.js:39:9)
    at Server.emit (node:events:517:28)
    at parserOnIncoming (node:_http_server:1130:12)
    at HTTPParser.parserOnHeadersComplete (node:_http_common:119:17)
PASS src/modules/algorithms/phase/phase-calculator.service.spec.ts
[Nest] 3582  - 01/04/2026, 7:57:45 PM   ERROR [ExceptionsHandler] request entity too large
PayloadTooLargeError: request entity too large
    at readStream (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:163:17)
    at getRawBody (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:116:12)
    at read (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/read.js:79:3)
    at jsonParser (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/types/json.js:138:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at expressInit (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/init.js:40:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at query (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/query.js:45:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:175:3)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/application.js:181:10)
    at Server.app (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/express.js:39:9)
    at Server.emit (node:events:517:28)
    at parserOnIncoming (node:_http_server:1130:12)
    at HTTPParser.parserOnHeadersComplete (node:_http_common:119:17)
[Nest] 3582  - 01/04/2026, 7:57:45 PM   ERROR [ExceptionsHandler] request entity too large
PayloadTooLargeError: request entity too large
    at readStream (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:163:17)
    at getRawBody (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:116:12)
    at read (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/read.js:79:3)
    at jsonParser (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/types/json.js:138:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at expressInit (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/init.js:40:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at query (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/query.js:45:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:175:3)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/application.js:181:10)
    at Server.app (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/express.js:39:9)
    at Server.emit (node:events:517:28)
    at parserOnIncoming (node:_http_server:1130:12)
    at HTTPParser.parserOnHeadersComplete (node:_http_common:119:17)
PASS src/security/request-size-limits.spec.ts
PASS src/modules/auth/strategies/jwt.strategy.spec.ts
PASS src/modules/auth/refresh-token.service.spec.ts
PASS src/modules/algorithms/disc/disc-calculator.service.spec.ts
PASS src/config/cors.config.spec.ts
[Nest] 3582  - 01/04/2026, 7:57:47 PM     LOG [CORSConfiguration] CORS: Configured 2 allowed origins
[Nest] 3582  - 01/04/2026, 7:57:47 PM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:3001
[Nest] 3582  - 01/04/2026, 7:57:47 PM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:5173
[Nest] 3582  - 01/04/2026, 7:57:47 PM   DEBUG [CORSConfiguration] CORS: Allowed request from whitelisted origin: http://localhost:3001
[Nest] 3582  - 01/04/2026, 7:57:47 PM     LOG [CORSConfiguration] CORS: Configured 2 allowed origins
[Nest] 3582  - 01/04/2026, 7:57:47 PM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:3001
[Nest] 3582  - 01/04/2026, 7:57:47 PM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:5173
[Nest] 3582  - 01/04/2026, 7:57:47 PM   DEBUG [CORSConfiguration] CORS: Allowed request from whitelisted origin: http://localhost:5173
[Nest] 3582  - 01/04/2026, 7:57:47 PM     LOG [CORSConfiguration] CORS: Configured 3 allowed origins
[Nest] 3582  - 01/04/2026, 7:57:47 PM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:3001
[Nest] 3582  - 01/04/2026, 7:57:47 PM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:5173
[Nest] 3582  - 01/04/2026, 7:57:47 PM     LOG [CORSConfiguration] CORS: Whitelisted origin - https://app.financialrise.com
[Nest] 3582  - 01/04/2026, 7:57:47 PM   DEBUG [CORSConfiguration] CORS: Allowed request from whitelisted origin: https://app.financialrise.com
[Nest] 3582  - 01/04/2026, 7:57:47 PM     LOG [CORSConfiguration] CORS: Configured 3 allowed origins
[Nest] 3582  - 01/04/2026, 7:57:47 PM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:3001
[Nest] 3582  - 01/04/2026, 7:57:47 PM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:5173
[Nest] 3582  - 01/04/2026, 7:57:47 PM     LOG [CORSConfiguration] CORS: Whitelisted origin - https://staging.financialrise.com
[Nest] 3582  - 01/04/2026, 7:57:47 PM   DEBUG [CORSConfiguration] CORS: Allowed request from whitelisted origin: https://staging.financialrise.com
[Nest] 3582  - 01/04/2026, 7:57:47 PM     LOG [CORSConfiguration] CORS: Configured 2 allowed origins
[Nest] 3582  - 01/04/2026, 7:57:47 PM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:3001
[Nest] 3582  - 01/04/2026, 7:57:47 PM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:5173
[Nest] 3582  - 01/04/2026, 7:57:47 PM    WARN [CORSConfiguration] 🚫 CORS: Blocked request from unauthorized origin: http://evil.com
[Nest] 3582  - 01/04/2026, 7:57:47 PM    WARN [CORSConfiguration] Object:
{
  "origin": "http://evil.com",
  "timestamp": "2026-01-04T19:57:47.481Z",
  "securityEvent": "CORS_ORIGIN_BLOCKED",
  "severity": "MEDIUM"
}

[Nest] 3582  - 01/04/2026, 7:57:47 PM     LOG [CORSConfiguration] CORS: Configured 2 allowed origins
[Nest] 3582  - 01/04/2026, 7:57:47 PM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:3001
[Nest] 3582  - 01/04/2026, 7:57:47 PM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:5173
[Nest] 3582  - 01/04/2026, 7:57:47 PM    WARN [CORSConfiguration] 🚫 CORS: Blocked request from unauthorized origin: http://localhost:9999
[Nest] 3582  - 01/04/2026, 7:57:47 PM    WARN [CORSConfiguration] Object:
{
  "origin": "http://localhost:9999",
  "timestamp": "2026-01-04T19:57:47.483Z",
  "securityEvent": "CORS_ORIGIN_BLOCKED",
  "severity": "MEDIUM"
}

[Nest] 3582  - 01/04/2026, 7:57:47 PM     LOG [CORSConfiguration] CORS: Configured 2 allowed origins
[Nest] 3582  - 01/04/2026, 7:57:47 PM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:3001
[Nest] 3582  - 01/04/2026, 7:57:47 PM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:5173
[Nest] 3582  - 01/04/2026, 7:57:47 PM    WARN [CORSConfiguration] 🚫 CORS: Blocked request from unauthorized origin: https://localhost:3001
[Nest] 3582  - 01/04/2026, 7:57:47 PM    WARN [CORSConfiguration] Object:
{
  "origin": "https://localhost:3001",
  "timestamp": "2026-01-04T19:57:47.484Z",
  "securityEvent": "CORS_ORIGIN_BLOCKED",
  "severity": "MEDIUM"
}

[Nest] 3582  - 01/04/2026, 7:57:47 PM     LOG [CORSConfiguration] CORS: Configured 2 allowed origins
[Nest] 3582  - 01/04/2026, 7:57:47 PM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:3001
[Nest] 3582  - 01/04/2026, 7:57:47 PM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:5173
[Nest] 3582  - 01/04/2026, 7:57:47 PM   DEBUG [CORSConfiguration] CORS: Request with no origin header - allowing
[Nest] 3582  - 01/04/2026, 7:57:47 PM     LOG [CORSConfiguration] CORS: Configured 2 allowed origins
[Nest] 3582  - 01/04/2026, 7:57:47 PM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:3001
[Nest] 3582  - 01/04/2026, 7:57:47 PM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:5173
[Nest] 3582  - 01/04/2026, 7:57:47 PM    WARN [CORSConfiguration] 🚫 CORS: Blocked request from unauthorized origin: http://LOCALHOST:3001
[Nest] 3582  - 01/04/2026, 7:57:47 PM    WARN [CORSConfiguration] Object:
{
  "origin": "http://LOCALHOST:3001",
  "timestamp": "2026-01-04T19:57:47.485Z",
  "securityEvent": "CORS_ORIGIN_BLOCKED",
  "severity": "MEDIUM"
}

[Nest] 3582  - 01/04/2026, 7:57:47 PM     LOG [CORSConfiguration] CORS: Configured 2 allowed origins
[Nest] 3582  - 01/04/2026, 7:57:47 PM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:3001
[Nest] 3582  - 01/04/2026, 7:57:47 PM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:5173
[Nest] 3582  - 01/04/2026, 7:57:47 PM    WARN [CORSConfiguration] 🚫 CORS: Blocked request from unauthorized origin: http://malicious.localhost:3001
[Nest] 3582  - 01/04/2026, 7:57:47 PM    WARN [CORSConfiguration] Object:
{
  "origin": "http://malicious.localhost:3001",
  "timestamp": "2026-01-04T19:57:47.486Z",
  "securityEvent": "CORS_ORIGIN_BLOCKED",
  "severity": "MEDIUM"
}

[Nest] 3582  - 01/04/2026, 7:57:47 PM     LOG [CORSConfiguration] CORS: Configured 2 allowed origins
[Nest] 3582  - 01/04/2026, 7:57:47 PM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:3001
[Nest] 3582  - 01/04/2026, 7:57:47 PM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:5173
[Nest] 3582  - 01/04/2026, 7:57:47 PM    WARN [CORSConfiguration] 🚫 CORS: Blocked request from unauthorized origin: http://127.0.0.1:3001
[Nest] 3582  - 01/04/2026, 7:57:47 PM    WARN [CORSConfiguration] Object:
{
  "origin": "http://127.0.0.1:3001",
  "timestamp": "2026-01-04T19:57:47.487Z",
  "securityEvent": "CORS_ORIGIN_BLOCKED",
  "severity": "MEDIUM"
}

PASS src/modules/users/users-data-export.spec.ts
PASS src/config/secrets.config.spec.ts
  ● Console

    console.log
      ✅ Secret validation passed - All secrets meet security requirements

      at SecretsValidationService.log [as validateSecrets] (config/secrets-validation.service.ts:48:13)

    console.log
      ✅ Secret validation passed - All secrets meet security requirements

      at SecretsValidationService.log [as validateSecrets] (config/secrets-validation.service.ts:48:13)

PASS src/security/sql-injection-prevention.spec.ts
PASS src/modules/assessments/assessments.service.spec.ts
PASS src/modules/consents/consents.controller.spec.ts
PASS src/common/services/encryption.service.spec.ts
FAIL src/common/interceptors/csrf.interceptor.spec.ts
  ● CsrfInterceptor › intercept › should set secure flag in production

    expect(received).toBe(expected) // Object.is equality

    Expected: true
    Received: false

      104 |       const [, , options] = (response.cookie as jest.Mock).mock.calls[0];
      105 |
    > 106 |       expect(options.secure).toBe(true);
          |                              ^
      107 |
      108 |       process.env.NODE_ENV = originalEnv;
      109 |     });

      at Object.<anonymous> (common/interceptors/csrf.interceptor.spec.ts:106:30)

  ● CsrfInterceptor › intercept › Security › should use secure cookies in production

    expect(received).toBe(expected) // Object.is equality

    Expected: true
    Received: false

      338 |         const options = (response.cookie as jest.Mock).mock.calls[0][2];
      339 |
    > 340 |         expect(options.secure).toBe(true);
          |                                ^
      341 |
      342 |         process.env.NODE_ENV = originalEnv;
      343 |       });

      at Object.<anonymous> (common/interceptors/csrf.interceptor.spec.ts:340:32)

PASS src/modules/users/users-account-deletion.spec.ts
PASS src/common/guards/csrf.guard.spec.ts
PASS src/config/request-size-limits.config.spec.ts
PASS src/common/guards/report-ownership.guard.spec.ts
PASS src/modules/algorithms/algorithms.service.spec.ts
[Nest] 3588  - 01/04/2026, 7:57:52 PM   ERROR [DataRetentionService] [GDPR COMPLIANCE ERROR] Data retention enforcement failed: Database connection lost
Error: Database connection lost
    at Object.<anonymous> (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/src/common/services/data-retention.service.spec.ts:140:9)
    at Promise.then.completed (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/jest-circus/build/utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/jest-circus/build/utils.js:231:10)
    at _callCircusTest (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/jest-circus/build/run.js:316:40)
    at processTicksAndRejections (node:internal/process/task_queues:95:5)
    at _runTest (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/jest-circus/build/run.js:252:3)
    at _runTestsForDescribeBlock (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/jest-circus/build/run.js:126:9)
    at _runTestsForDescribeBlock (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/jest-circus/build/run.js:121:9)
    at _runTestsForDescribeBlock (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/jest-circus/build/run.js:121:9)
    at run (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/jest-circus/build/run.js:71:3)
    at runAndTransformResultsToJestFormat (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/jest-circus/build/legacy-code-todo-rewrite/jestAdapterInit.js:122:21)
    at jestAdapter (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/jest-circus/build/legacy-code-todo-rewrite/jestAdapter.js:79:19)
    at runTestInternal (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/jest-runner/build/runTest.js:367:16)
    at runTest (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/jest-runner/build/runTest.js:444:34)
    at Object.worker (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/jest-runner/build/testWorker.js:106:12)
PASS src/common/services/data-retention.service.spec.ts
PASS src/common/guards/assessment-ownership.guard.spec.ts
PASS src/modules/auth/services/token-blacklist.service.spec.ts (5.237 s)
PASS src/modules/questionnaire/questionnaire.controller.spec.ts
PASS src/modules/auth/strategies/local.strategy.spec.ts
PASS src/common/guards/processing-restriction.guard.spec.ts
[Nest] 3581  - 01/04/2026, 7:57:54 PM   ERROR [HTTP] Request failed: POST /api/test
[Nest] 3581  - 01/04/2026, 7:57:54 PM   ERROR [HTTP] Object:
{
  "method": "POST",
  "url": "/api/test",
  "error": "Test error",
  "statusCode": 500,
  "duration": "1ms",
  "timestamp": "2026-01-04T19:57:54.382Z"
}

PASS src/common/interceptors/logging.interceptor.spec.ts
[Nest] 3581  - 01/04/2026, 7:57:54 PM     LOG [HTTP] Incoming request: POST /api/test
[Nest] 3581  - 01/04/2026, 7:57:54 PM     LOG [HTTP] Object:
{
  "controller": "TestController",
  "handler": "testHandler",
  "method": "POST",
  "url": "/api/test",
  "body": {
    "email": "***@example.com",
    "password": "[REDACTED - PASSWORD]",
    "name": "J***"
  },
  "user": {
    "id": "user-123",
    "email": "***@test.com"
  },
  "timestamp": "2026-01-04T19:57:54.366Z"
}

[Nest] 3581  - 01/04/2026, 7:57:54 PM     LOG [HTTP] Request completed: POST /api/test
[Nest] 3581  - 01/04/2026, 7:57:54 PM     LOG [HTTP] Object:
{
  "method": "POST",
  "url": "/api/test",
  "statusCode": 200,
  "duration": "5ms",
  "timestamp": "2026-01-04T19:57:54.371Z"
}

[Nest] 3581  - 01/04/2026, 7:57:54 PM     LOG [HTTP] Incoming request: POST /api/test
[Nest] 3581  - 01/04/2026, 7:57:54 PM     LOG [HTTP] Object:
{
  "controller": "TestController",
  "handler": "testHandler",
  "method": "POST",
  "url": "/api/test",
  "body": {
    "email": "***@example.com",
    "password": "[REDACTED - PASSWORD]",
    "name": "J***"
  },
  "user": {
    "id": "user-123",
    "email": "***@test.com"
  },
  "timestamp": "2026-01-04T19:57:54.373Z"
}

[Nest] 3581  - 01/04/2026, 7:57:54 PM     LOG [HTTP] Request completed: POST /api/test
[Nest] 3581  - 01/04/2026, 7:57:54 PM     LOG [HTTP] Object:
{
  "method": "POST",
  "url": "/api/test",
  "statusCode": 200,
  "duration": "0ms",
  "timestamp": "2026-01-04T19:57:54.373Z"
}

[Nest] 3581  - 01/04/2026, 7:57:54 PM     LOG [HTTP] Incoming request: POST /api/test
[Nest] 3581  - 01/04/2026, 7:57:54 PM     LOG [HTTP] Object:
{
  "controller": "TestController",
  "handler": "testHandler",
  "method": "POST",
  "url": "/api/test",
  "body": {
    "email": "***@example.com",
    "password": "[REDACTED - PASSWORD]",
    "name": "J***"
  },
  "user": {
    "id": "user-123",
    "email": "***@test.com"
  },
  "timestamp": "2026-01-04T19:57:54.376Z"
}

[Nest] 3581  - 01/04/2026, 7:57:54 PM     LOG [HTTP] Request completed: POST /api/test
[Nest] 3581  - 01/04/2026, 7:57:54 PM     LOG [HTTP] Object:
{
  "method": "POST",
  "url": "/api/test",
  "statusCode": 200,
  "duration": "1ms",
  "timestamp": "2026-01-04T19:57:54.377Z"
}

[Nest] 3581  - 01/04/2026, 7:57:54 PM     LOG [HTTP] Incoming request: POST /api/auth/login
[Nest] 3581  - 01/04/2026, 7:57:54 PM     LOG [HTTP] Object:
{
  "controller": "TestController",
  "handler": "testHandler",
  "method": "POST",
  "url": "/api/auth/login",
  "body": {
    "email": "***@test.com",
    "password": "[REDACTED - PASSWORD]"
  },
  "timestamp": "2026-01-04T19:57:54.379Z"
}

[Nest] 3581  - 01/04/2026, 7:57:54 PM     LOG [HTTP] Request completed: POST /api/auth/login
[Nest] 3581  - 01/04/2026, 7:57:54 PM     LOG [HTTP] Object:
{
  "method": "POST",
  "url": "/api/auth/login",
  "statusCode": 200,
  "duration": "0ms",
  "timestamp": "2026-01-04T19:57:54.379Z"
}

[Nest] 3581  - 01/04/2026, 7:57:54 PM     LOG [HTTP] Incoming request: POST /api/test
[Nest] 3581  - 01/04/2026, 7:57:54 PM     LOG [HTTP] Object:
{
  "controller": "TestController",
  "handler": "testHandler",
  "method": "POST",
  "url": "/api/test",
  "body": {
    "email": "***@example.com",
    "password": "[REDACTED - PASSWORD]",
    "name": "J***"
  },
  "user": {
    "id": "user-123",
    "email": "***@test.com"
  },
  "timestamp": "2026-01-04T19:57:54.381Z"
}

[Nest] 3581  - 01/04/2026, 7:57:54 PM     LOG [HTTP] Incoming request: POST /api/test
[Nest] 3581  - 01/04/2026, 7:57:54 PM     LOG [HTTP] Object:
{
  "controller": "TestController",
  "handler": "testHandler",
  "method": "POST",
  "url": "/api/test",
  "body": {
    "email": "***@example.com",
    "password": "[REDACTED - PASSWORD]",
    "name": "J***"
  },
  "user": {
    "id": "user-123",
    "email": "***@test.com"
  },
  "timestamp": "2026-01-04T19:57:54.384Z"
}

[Nest] 3581  - 01/04/2026, 7:57:54 PM     LOG [HTTP] Request completed: POST /api/test
[Nest] 3581  - 01/04/2026, 7:57:54 PM     LOG [HTTP] Object:
{
  "method": "POST",
  "url": "/api/test",
  "statusCode": 200,
  "duration": "0ms",
  "timestamp": "2026-01-04T19:57:54.384Z"
}

[Nest] 3581  - 01/04/2026, 7:57:54 PM     LOG [HTTP] Incoming request: POST /api/test
[Nest] 3581  - 01/04/2026, 7:57:54 PM     LOG [HTTP] Object:
{
  "controller": "TestController",
  "handler": "testHandler",
  "method": "POST",
  "url": "/api/test",
  "body": {
    "email": "***@example.com",
    "password": "[REDACTED - PASSWORD]",
    "name": "J***"
  },
  "user": {
    "id": "user-123",
    "email": "***@test.com"
  },
  "timestamp": "2026-01-04T19:57:54.386Z"
}

[Nest] 3581  - 01/04/2026, 7:57:54 PM     LOG [HTTP] Request completed: POST /api/test
[Nest] 3581  - 01/04/2026, 7:57:54 PM     LOG [HTTP] Object:
{
  "method": "POST",
  "url": "/api/test",
  "statusCode": 200,
  "duration": "1ms",
  "timestamp": "2026-01-04T19:57:54.386Z"
}

PASS src/modules/algorithms/algorithms.controller.spec.ts
PASS src/modules/auth/guards/roles.guard.spec.ts
PASS src/modules/users/users.controller.spec.ts
PASS src/modules/assessments/assessments.controller.spec.ts
PASS src/modules/auth/guards/jwt-auth.guard.spec.ts
PASS src/modules/questions/questions.service.spec.ts
PASS src/modules/questions/questions.controller.spec.ts
PASS src/modules/auth/guards/local-auth.guard.spec.ts
PASS src/common/transformers/encrypted-column.transformer.spec.ts
A worker process has failed to exit gracefully and has been force exited. This is likely caused by tests leaking due to improper teardown. Try running with --detectOpenHandles to find leaks. Active timers can also cause this, ensure that .unref() was called on them.
-------------------------------------|---------|----------|---------|---------|-------------------------------------------
File                                 | % Stmts | % Branch | % Funcs | % Lines | Uncovered Line #s                         
-------------------------------------|---------|----------|---------|---------|-------------------------------------------
All files                            |   86.97 |    79.31 |   83.21 |   86.91 |                                           
 common/decorators                   |      90 |      100 |      50 |     100 |                                           
  allow-when-restricted.decorator.ts |     100 |      100 |     100 |     100 |                                           
  public.decorator.ts                |      80 |      100 |       0 |     100 |                                           
 common/guards                       |     100 |      100 |     100 |     100 |                                           
  assessment-ownership.guard.ts      |     100 |      100 |     100 |     100 |                                           
  csrf.guard.ts                      |     100 |      100 |     100 |     100 |                                           
  processing-restriction.guard.ts    |     100 |      100 |     100 |     100 |                                           
  report-ownership.guard.ts          |     100 |      100 |     100 |     100 |                                           
 common/interceptors                 |   97.29 |       75 |     100 |   97.05 |                                           
  csrf.interceptor.ts                |     100 |      100 |     100 |     100 |                                           
  logging.interceptor.ts             |   95.65 |    66.66 |     100 |   95.23 | 22                                        
 common/services                     |    98.8 |       76 |     100 |   98.75 |                                           
  data-retention.service.ts          |     100 |    66.66 |     100 |     100 | 155-160                                   
  encryption.service.ts              |    97.5 |    84.61 |     100 |   97.36 | 71                                        
 common/transformers                 |     100 |      100 |     100 |     100 |                                           
  encrypted-column.transformer.ts    |     100 |      100 |     100 |     100 |                                           
 common/utils                        |   77.59 |    83.33 |   58.82 |   79.65 |                                           
  log-sanitizer.ts                   |   95.94 |    96.15 |   95.23 |   96.47 | 149,266,306,345,426                       
  pii-safe-logger.ts                 |       0 |        0 |       0 |       0 | 1-130                                     
 config                              |   80.87 |     70.9 |   73.07 |   80.44 |                                           
  cors.config.ts                     |    87.5 |    66.66 |      80 |    87.5 | 36-39                                     
  request-size-limits.config.ts      |   58.69 |    57.14 |   42.85 |   58.69 | 114-128,147-164                           
  secrets-validation.service.ts      |   90.47 |       84 |     100 |   90.24 | 79,83,93,112                              
  secrets.service.ts                 |   96.77 |    44.44 |     100 |   96.66 | 92                                        
  security-headers.config.ts         |       0 |      100 |       0 |       0 | 22-101                                    
  typeorm.config.ts                  |   96.96 |      100 |     100 |   96.77 | 52                                        
 modules/algorithms                  |   95.41 |    71.87 |     100 |   95.14 |                                           
  algorithms.controller.ts           |     100 |       75 |     100 |     100 | 184                                       
  algorithms.service.ts              |   93.42 |    71.42 |     100 |   93.05 | 194,223-224,248-249                       
 modules/algorithms/disc             |    97.5 |    95.65 |     100 |   97.29 |                                           
  disc-calculator.service.ts         |    97.5 |    95.65 |     100 |   97.29 | 62-63                                     
 modules/algorithms/phase            |   97.14 |    90.47 |     100 |   96.92 |                                           
  phase-calculator.service.ts        |   97.14 |    90.47 |     100 |   96.92 | 249-250                                   
 modules/assessments                 |   94.18 |    80.64 |     100 |    97.4 |                                           
  assessments.controller.ts          |     100 |      100 |     100 |     100 |                                           
  assessments.service.ts             |   91.93 |    77.77 |     100 |   96.36 | 76,175                                    
 modules/assessments/services        |   98.29 |    85.45 |     100 |   98.11 |                                           
  progress.service.ts                |     100 |       70 |     100 |     100 | 70,116-163                                
  validation.service.ts              |   97.36 |    88.88 |     100 |   97.14 | 100,154                                   
 modules/auth                        |    64.2 |    62.79 |      60 |   64.11 |                                           
  auth.controller.ts                 |       0 |        0 |       0 |       0 | 1-105                                     
  auth.service.ts                    |   71.79 |       60 |   77.77 |    71.3 | 34-73,155,185,196,265-292,299,307,312-313 
  refresh-token.service.ts           |     100 |      100 |     100 |     100 |                                           
 modules/auth/decorators             |   66.66 |      100 |       0 |   71.42 |                                           
  get-user.decorator.ts              |      50 |      100 |       0 |      50 | 4-5                                       
  roles.decorator.ts                 |      80 |      100 |       0 |     100 |                                           
 modules/auth/guards                 |     100 |      100 |     100 |     100 |                                           
  jwt-auth.guard.ts                  |     100 |      100 |     100 |     100 |                                           
  local-auth.guard.ts                |     100 |      100 |     100 |     100 |                                           
  roles.guard.ts                     |     100 |      100 |     100 |     100 |                                           
 modules/auth/services               |     100 |      100 |     100 |     100 |                                           
  token-blacklist.service.ts         |     100 |      100 |     100 |     100 |                                           
 modules/auth/strategies             |     100 |      100 |     100 |     100 |                                           
  jwt.strategy.ts                    |     100 |      100 |     100 |     100 |                                           
  local.strategy.ts                  |     100 |      100 |     100 |     100 |                                           
 modules/consents                    |     100 |    76.19 |     100 |     100 |                                           
  consents.controller.ts             |     100 |     92.3 |     100 |     100 | 53                                        
  consents.service.ts                |     100 |       50 |     100 |     100 | 21-65                                     
 modules/questionnaire               |     100 |    94.11 |     100 |     100 |                                           
  questionnaire.controller.ts        |     100 |      100 |     100 |     100 |                                           
  questionnaire.service.ts           |     100 |    94.11 |     100 |     100 | 70                                        
 modules/questions                   |     100 |      100 |     100 |     100 |                                           
  questions.controller.ts            |     100 |      100 |     100 |     100 |                                           
  questions.service.ts               |     100 |      100 |     100 |     100 |                                           
 modules/users                       |   69.66 |    61.11 |   65.85 |   69.18 |                                           
  users.controller.ts                |   79.54 |     62.5 |      70 |   78.57 | 132-136,152-156,173-177                   
  users.service.ts                   |   66.41 |       60 |   64.51 |   66.15 | 147,265,280-303,333-334,350-445           
-------------------------------------|---------|----------|---------|---------|-------------------------------------------

Summary of all failing tests
FAIL common/interceptors/csrf.interceptor.spec.ts
  ● CsrfInterceptor › intercept › should set secure flag in production

    expect(received).toBe(expected) // Object.is equality

    Expected: true
    Received: false

      104 |       const [, , options] = (response.cookie as jest.Mock).mock.calls[0];
      105 |
    > 106 |       expect(options.secure).toBe(true);
          |                              ^
      107 |
      108 |       process.env.NODE_ENV = originalEnv;
      109 |     });

      at Object.<anonymous> (common/interceptors/csrf.interceptor.spec.ts:106:30)

  ● CsrfInterceptor › intercept › Security › should use secure cookies in production

    expect(received).toBe(expected) // Object.is equality

    Expected: true
    Received: false

      338 |         const options = (response.cookie as jest.Mock).mock.calls[0][2];
      339 |
    > 340 |         expect(options.secure).toBe(true);
          |                                ^
      341 |
      342 |         process.env.NODE_ENV = originalEnv;
      343 |       });

      at Object.<anonymous> (common/interceptors/csrf.interceptor.spec.ts:340:32)


Test Suites: 1 failed, 43 passed, 44 total
Tests:       2 failed, 906 passed, 908 total
Snapshots:   0 total
Time:        36.967 s
Ran all test suites.
Error: Process completed with exit code 1.
