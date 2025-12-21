# Algorithm Tests - Financial RISE Report

This directory contains comprehensive tests for the DISC & Phase algorithms implementation (Work Stream 7).

## Test Structure

```
test/
├── test-db.config.ts          # SQLite in-memory database configuration
├── fixtures/
│   └── test-data.ts           # Test data fixtures and scenarios
└── README.md                  # This file

src/modules/algorithms/
├── algorithms.controller.spec.ts          # Integration tests (API endpoints)
├── disc/disc-calculator.service.spec.ts   # Unit tests (DISC service)
└── phase/phase-calculator.service.spec.ts # Unit tests (Phase service)
```

## Test Coverage

### Integration Tests (`algorithms.controller.spec.ts`)

**3 API Endpoints Tested:**
- `POST /api/v1/assessments/:id/calculate`
- `GET /api/v1/assessments/:id/disc-profile`
- `GET /api/v1/assessments/:id/phase-results`

**Test Scenarios:**
- ✅ Successful calculation with valid data
- ✅ DISC profile data validation (scores 0-100, valid types)
- ✅ Phase results data validation (scores 0-100, valid phases)
- ✅ Conflict detection (duplicate calculations)
- ✅ All 4 DISC types (D, I, S, C) correctly identified
- ✅ All 5 phases (Stabilize, Organize, Build, Grow, Systemic) correctly identified
- ✅ Secondary trait identification
- ✅ Insufficient DISC data handling
- ✅ Personality summary enrichment
- ✅ Phase details enrichment
- ✅ NotFoundException for missing profiles
- ✅ Database persistence verification
- ✅ Concurrent request handling

**Total Test Cases:** 35+

### Unit Tests - DISC Calculator (`disc-calculator.service.spec.ts`)

**Methods Tested:**
- `validateInputs()` - Input validation logic
- `aggregateScores()` - Score aggregation from responses
- `normalizeScores()` - Normalization to 0-100 scale
- `determinePrimaryType()` - Primary DISC type selection
- `identifySecondaryTraits()` - Secondary trait detection
- `calculateConfidenceLevel()` - Confidence level calculation
- `calculate()` - Full integration workflow
- `getProfile()` - Profile retrieval
- `profileExists()` - Existence check

**Test Scenarios:**
- ✅ Score aggregation accuracy
- ✅ Normalization edge cases (zero total, even distribution)
- ✅ Primary type determination for all types
- ✅ Secondary trait threshold logic (10-point threshold)
- ✅ Confidence levels (high/moderate/low)
- ✅ Insufficient data handling (<12 questions)
- ✅ Even score distribution (25/25/25/25)
- ✅ Missing weights handling

**Total Test Cases:** 25+

### Unit Tests - Phase Calculator (`phase-calculator.service.spec.ts`)

**Methods Tested:**
- `validateInputs()` - Input validation
- `aggregateScores()` - Phase score aggregation
- `normalizeScores()` - Normalization to 0-100 scale
- `rankPhases()` - Phase ranking by score
- `applySequencingLogic()` - Sequential logic + primary/secondary selection
- `calculate()` - Full integration workflow
- `getResult()` - Result retrieval
- `resultExists()` - Existence check

**Test Scenarios:**
- ✅ Score aggregation accuracy
- ✅ Normalization edge cases
- ✅ Phase ranking correctness
- ✅ Critical stabilization override (<40 score)
- ✅ Sequential dependency logic
- ✅ Secondary phase identification (15-point threshold)
- ✅ Transition state detection
- ✅ Even score distribution default (stabilize)
- ✅ All phase types as primary

**Total Test Cases:** 20+

## Running Tests

### Run All Tests

```bash
npm test
```

### Run Tests in Watch Mode

```bash
npm run test:watch
```

### Run with Coverage Report

```bash
npm run test:cov
```

**Coverage Target:** 80%+ (branches, functions, lines, statements)

### Run Specific Test File

```bash
# Integration tests
npm test -- algorithms.controller.spec

# DISC unit tests
npm test -- disc-calculator.service.spec

# Phase unit tests
npm test -- phase-calculator.service.spec
```

### Debug Tests

```bash
npm run test:debug
```

Then attach your debugger to the Node process.

## Test Database

**Type:** SQLite in-memory database

**Benefits:**
- ✅ Fast test execution (no external database required)
- ✅ Isolated tests (fresh database for each run)
- ✅ No setup/teardown overhead
- ✅ CI/CD friendly

**Configuration:** `test/test-db.config.ts`

**Auto-setup:**
- Database created automatically when tests start
- Tables created via TypeORM synchronize
- Cleaned up automatically when tests complete

## Test Data Fixtures

**Location:** `test/fixtures/test-data.ts`

**Available Fixtures:**
- `highDominanceResponses` - 15 DISC questions for D-type
- `highInfluenceResponses` - 15 DISC questions for I-type
- `highSteadinessResponses` - 15 DISC questions for S-type
- `highComplianceResponses` - 15 DISC questions for C-type
- `stabilizePhaseResponses` - Phase questions indicating Stabilize needs
- `organizePhaseResponses` - Phase questions indicating Organize needs
- `buildPhaseResponses` - Phase questions indicating Build needs
- `growPhaseResponses` - Phase questions indicating Grow needs
- `insufficientDISCResponses` - Only 8 questions (edge case)
- `mixedDISCResponses` - Mixed D+I scores for secondary traits
- `fullAssessmentResponses` - Combined DISC + Phase scenarios

## Test Scenarios Covered

### DISC Algorithm Edge Cases

1. **Insufficient Data (<12 questions)**
   - Expected: Low confidence level
   - Test: `insufficientDISCResponses`

2. **Perfectly Even Scores (25/25/25/25)**
   - Expected: Default to 'C' type, low confidence
   - Test: Constructed in unit tests

3. **Close Scores (Secondary Traits)**
   - Expected: Identify secondary type within 10-point threshold
   - Test: `mixedDISCResponses`

4. **Missing Weights**
   - Expected: Treat as 0, continue calculation
   - Test: Unit tests with undefined values

### Phase Algorithm Edge Cases

1. **Critical Stabilization (<40 score)**
   - Expected: Override to 'stabilize' phase
   - Test: Low stabilize scores in unit tests

2. **Sequential Dependencies**
   - Expected: Can't Build without Organize
   - Test: High build score with low organize score

3. **Transition States**
   - Expected: Multiple secondary phases identified
   - Test: Scores within 15-point threshold

4. **Perfectly Even Scores (20/20/20/20/20)**
   - Expected: Default to 'stabilize', all others secondary
   - Test: Constructed in unit tests

## Expected Test Results

### Coverage Targets

| Metric | Target | Expected |
|--------|--------|----------|
| Statements | 80% | 85-95% |
| Branches | 80% | 80-90% |
| Functions | 80% | 85-95% |
| Lines | 80% | 85-95% |

### Test Execution Time

- Unit tests: <5 seconds
- Integration tests: <10 seconds
- Total: <15 seconds

### Success Criteria

✅ All 80+ test cases pass
✅ No flaky tests (consistent results)
✅ Coverage above 80% threshold
✅ Database setup/teardown works correctly
✅ All edge cases handled properly

## Debugging Failed Tests

### Common Issues

**1. Database Connection Issues**
```bash
# Check if sqlite3 is installed
npm list sqlite3

# Reinstall if needed
npm install --save-dev sqlite3
```

**2. Module Import Errors**
```bash
# Clear Jest cache
npx jest --clearCache

# Run tests again
npm test
```

**3. Test Timeout**
```bash
# Increase timeout in test file
jest.setTimeout(10000); // 10 seconds
```

**4. Coverage Not Meeting Threshold**
```bash
# Generate detailed coverage report
npm run test:cov

# Open coverage/lcov-report/index.html in browser
```

## Continuous Integration

These tests are designed to run in CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Run Tests
  run: |
    npm install
    npm run test:cov
```

**CI Requirements:**
- Node.js 18+
- No external database required
- All dependencies in package.json

## Next Steps

After tests pass:

1. ✅ Verify 80%+ coverage achieved
2. ✅ Review coverage report for gaps
3. ✅ Add additional test cases as needed
4. ✅ Create validation dataset (20-30 real scenarios)
5. ✅ Run validation testing with SME review
6. ✅ Generate validation report

## Validation Testing (Future)

**Planned:** Validation dataset with SME-reviewed scenarios

**Target:** 85%+ accuracy match with expert assessment

**Location:** `test/validation/` (to be created)

**Process:**
1. Create 20-30 realistic assessment scenarios
2. Have financial consultant SME + DISC expert manually determine expected results
3. Run algorithms on scenarios
4. Compare results with expert expectations
5. Document accuracy and edge case handling
6. Tune algorithms if needed

---

**Last Updated:** 2025-12-20
**Test Suite Version:** 1.0
**Work Stream:** 7 (DISC & Phase Algorithms)
