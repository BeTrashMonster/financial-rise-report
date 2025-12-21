#!/bin/bash
sed -i \
  -e 's/- \[ \] Implement DISC calculation algorithm/- [x] Implement DISC calculation algorithm/' \
  -e 's/- \[ \]   - \[ \] Parse question responses/- [x]   - [x] Parse question responses/' \
  -e 's/- \[ \]   - \[ \] Calculate D, I, S, C scores/- [x]   - [x] Calculate D, I, S, C scores/' \
  -e 's/- \[ \]   - \[ \] Determine primary type/- [x]   - [x] Determine primary type/' \
  -e 's/- \[ \]   - \[ \] Store results in database/- [x]   - [x] Store results in database/' \
  -e 's/- \[ \] Implement phase determination algorithm/- [x] Implement phase determination algorithm/' \
  -e 's/- \[ \]   - \[ \] Weighted scoring by phase/- [x]   - [x] Weighted scoring by phase/' \
  -e 's/- \[ \]   - \[ \] Identify primary focus phase/- [x]   - [x] Identify primary focus phase/' \
  -e 's/- \[ \] Create algorithm endpoints:/- [x] Create algorithm endpoints:/' \
  -e 's|- \[ \]   - \[ \] POST /api/v1/assessments/:id/calculate|- [x]   - [x] POST /api/v1/assessments/:id/calculate|' \
  -e 's|- \[ \]   - \[ \] GET /api/v1/assessments/:id/disc-profile|- [x]   - [x] GET /api/v1/assessments/:id/disc-profile|' \
  -e 's|- \[ \]   - \[ \] GET /api/v1/assessments/:id/phase-results|- [x]   - [x] GET /api/v1/assessments/:id/phase-results|' \
  -e 's/- \[ \] DISC calculation service/- [x] DISC calculation service/' \
  -e 's/- \[ \] Phase determination service/- [x] Phase determination service/' \
  -e 's/- \[ \] API endpoints/- [x] API endpoints/' \
  roadmap.md
