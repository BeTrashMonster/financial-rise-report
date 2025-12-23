# Load Testing Guide - Financial RISE

**Version:** 1.0
**Date:** 2025-12-22

## Tools

- **k6** (recommended) - Modern load testing tool
- **Artillery** - Alternative load testing tool
- **Apache JMeter** - Traditional load testing tool

## Installation

```bash
# k6 (recommended)
# macOS
brew install k6

# Windows
choco install k6

# Linux
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
echo "deb https://dl.k6.io/deb stable main" | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update
sudo apt-get install k6
```

## Load Test Scripts

### Test 1: API Endpoints (k6)

**File: `load-tests/api-load-test.js`**

```javascript
import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '2m', target: 10 }, // Ramp up to 10 users
    { duration: '5m', target: 50 }, // Stay at 50 users
    { duration: '2m', target: 0 }, // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'], // 95% of requests < 500ms
    http_req_failed: ['rate<0.01'], // Error rate < 1%
  },
};

const BASE_URL = 'http://localhost:3000';

export default function () {
  // Login
  const loginRes = http.post(`${BASE_URL}/api/v1/auth/login`, JSON.stringify({
    email: 'test@example.com',
    password: 'Test123!',
  }), {
    headers: { 'Content-Type': 'application/json' },
  });

  check(loginRes, {
    'login successful': (r) => r.status === 200,
    'login response time OK': (r) => r.timings.duration < 1000,
  });

  const token = loginRes.json('token');

  // Get assessments
  const assessmentsRes = http.get(`${BASE_URL}/api/v1/assessments`, {
    headers: { 'Authorization': `Bearer ${token}` },
  });

  check(assessmentsRes, {
    'assessments retrieved': (r) => r.status === 200,
    'assessments response time OK': (r) => r.timings.duration < 500,
  });

  sleep(1);
}
```

### Test 2: Report Generation (50 concurrent users)

**File: `load-tests/report-generation-test.js`**

```javascript
import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  vus: 50, // 50 concurrent users
  duration: '5m',
  thresholds: {
    'http_req_duration{endpoint:report}': ['p(95)<5000'], // REQ-PERF-002
  },
};

const BASE_URL = 'http://localhost:3000';
const TOKEN = __ENV.AUTH_TOKEN;

export default function () {
  const res = http.post(
    `${BASE_URL}/api/v1/reports/generate`,
    JSON.stringify({ assessmentId: 1, type: 'consultant' }),
    {
      headers: {
        'Authorization': `Bearer ${TOKEN}`,
        'Content-Type': 'application/json',
      },
      tags: { endpoint: 'report' },
    }
  );

  check(res, {
    'report generated': (r) => r.status === 200,
    'report generation < 5s': (r) => r.timings.duration < 5000,
  });

  sleep(10); // Wait between requests
}
```

## Running Load Tests

```bash
# API load test
k6 run load-tests/api-load-test.js

# Report generation test (set AUTH_TOKEN first)
AUTH_TOKEN="your-jwt-token" k6 run load-tests/report-generation-test.js

# Custom duration/users
k6 run --vus 100 --duration 10m load-tests/api-load-test.js

# Output results to file
k6 run --out json=results.json load-tests/api-load-test.js
```

## Performance Targets

- Page loads: < 3 seconds (REQ-PERF-001)
- Report generation: < 5 seconds (REQ-PERF-002)
- API response: < 500ms (95th percentile)
- Error rate: < 1%
- Concurrent users: 50+ without degradation

## Benchmarks

Run after optimizations to verify improvements:

```bash
# Before optimization
k6 run --summary-export=before.json load-tests/api-load-test.js

# After optimization
k6 run --summary-export=after.json load-tests/api-load-test.js

# Compare results
k6 compare before.json after.json
```
