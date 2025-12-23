# Secondary DISC Traits - Technical Specification

**Version:** 1.0
**Date:** 2025-12-22
**Work Stream:** 36 - Secondary DISC Traits
**Phase:** 2 - Enhanced Engagement
**Dependency Level:** 2

## Overview

The Secondary DISC Traits enhancement improves DISC profiling accuracy by identifying not just the primary personality trait but also the secondary trait. This provides consultants with a more nuanced understanding of client communication preferences and decision-making styles.

### Key Features

1. **Enhanced Algorithm** - Calculate both primary and secondary DISC scores
2. **Composite Profile** - Display as "D/I", "S/C", etc.
3. **Consultant Report Integration** - Show both traits with percentages
4. **Tie Handling** - Clear rules for equal scores
5. **Backward Compatibility** - Existing assessments remain valid

## DISC Profile Theory

### Single vs. Composite Profiles

**Current (Primary Only):**
- D (Dominance) - 45%
- I (Influence) - 35%
- S (Steadiness) - 12%
- C (Compliance) - 8%
- **Result:** Primary = D

**Enhanced (Primary + Secondary):**
- D (Dominance) - 45%
- I (Influence) - 35%
- S (Steadiness) - 12%
- C (Compliance) - 8%
- **Result:** Primary = D, Secondary = I
- **Display:** "D/I" (Dominant with Influential tendencies)

### Business Value

Understanding secondary traits helps consultants:
- Adapt communication style more precisely
- Predict decision-making patterns better
- Tailor recommendations with greater personalization
- Handle edge cases where scores are close

## Algorithm Design

### Enhanced DISC Calculation

```typescript
interface DISCScores {
  D: number; // Dominance
  I: number; // Influence
  S: number; // Steadiness
  C: number; // Compliance
}

interface DISCProfile {
  primary: 'D' | 'I' | 'S' | 'C';
  secondary: 'D' | 'I' | 'S' | 'C' | null;
  scores: DISCScores;
  profile_string: string; // "D/I" or "D" if no secondary
  primary_percentage: number;
  secondary_percentage: number | null;
}

export function calculateDISCProfile(responses: AssessmentResponse[]): DISCProfile {
  // Extract DISC questions
  const discQuestions = responses.filter(r =>
    r.question.question_category === 'DISC'
  );

  if (discQuestions.length < 12) {
    throw new Error('Minimum 12 DISC questions required for reliable profiling');
  }

  // Initialize scores
  const scores: DISCScores = { D: 0, I: 0, S: 0, C: 0 };

  // Calculate raw scores
  discQuestions.forEach(response => {
    const mappings = response.question.disc_mappings;

    // Each answer choice maps to DISC traits with weights
    // Example: { "D": 3, "I": 1, "S": 0, "C": 0 }
    const selectedAnswer = response.response_value.answer;
    const weights = mappings[selectedAnswer];

    scores.D += weights.D || 0;
    scores.I += weights.I || 0;
    scores.S += weights.S || 0;
    scores.C += weights.C || 0;
  });

  // Calculate total
  const total = scores.D + scores.I + scores.S + scores.C;

  // Convert to percentages
  const percentages = {
    D: (scores.D / total) * 100,
    I: (scores.I / total) * 100,
    S: (scores.S / total) * 100,
    C: (scores.C / total) * 100
  };

  // Sort by score descending
  const sorted = Object.entries(percentages)
    .sort(([, a], [, b]) => b - a)
    .map(([trait, score]) => ({ trait: trait as keyof DISCScores, score }));

  // Primary trait (highest score)
  const primary = sorted[0].trait;
  const primary_percentage = sorted[0].score;

  // Secondary trait rules:
  // 1. Must be at least 20% to be meaningful
  // 2. Must not be within 5% of primary (too close = single trait)
  // 3. Must be at least 10% higher than third trait
  let secondary: 'D' | 'I' | 'S' | 'C' | null = null;
  let secondary_percentage: number | null = null;

  const secondScore = sorted[1].score;
  const thirdScore = sorted[2].score;

  const isSignificant = secondScore >= 20;
  const notTooCloseToFirst = (primary_percentage - secondScore) >= 5;
  const clearlyAheadOfThird = (secondScore - thirdScore) >= 10;

  if (isSignificant && notTooCloseToFirst && clearlyAheadOfThird) {
    secondary = sorted[1].trait;
    secondary_percentage = sorted[1].score;
  }

  // Format profile string
  const profile_string = secondary ? `${primary}/${secondary}` : primary;

  return {
    primary,
    secondary,
    scores: percentages,
    profile_string,
    primary_percentage: Math.round(primary_percentage),
    secondary_percentage: secondary_percentage ? Math.round(secondary_percentage) : null
  };
}
```

### Example Scenarios

**Scenario 1: Clear Primary + Secondary**
```typescript
Scores: { D: 42%, I: 33%, S: 15%, C: 10% }
Result: {
  primary: "D",
  secondary: "I",
  profile_string: "D/I",
  primary_percentage: 42,
  secondary_percentage: 33
}
```

**Scenario 2: Dominant Single Trait**
```typescript
Scores: { D: 68%, I: 18%, S: 8%, C: 6% }
Result: {
  primary: "D",
  secondary: null,
  profile_string: "D",
  primary_percentage: 68,
  secondary_percentage: null
}
// Secondary not assigned: I is only 18% (below 20% threshold)
```

**Scenario 3: Close Race (no clear secondary)**
```typescript
Scores: { D: 38%, I: 35%, S: 15%, C: 12% }
Result: {
  primary: "D",
  secondary: null,
  profile_string: "D",
  primary_percentage: 38,
  secondary_percentage: null
}
// Secondary not assigned: D and I are too close (only 3% apart, need 5%)
```

**Scenario 4: Three-way split (no clear secondary)**
```typescript
Scores: { D: 35%, I: 28%, S: 25%, C: 12% }
Result: {
  primary: "D",
  secondary: null,
  profile_string: "D",
  primary_percentage: 35,
  secondary_percentage: null
}
// Secondary not assigned: I (28%) and S (25%) too close (only 3% apart, need 10%)
```

## Database Schema

### assessments Table (extension)

```sql
ALTER TABLE assessments ADD COLUMN IF NOT EXISTS disc_secondary TEXT DEFAULT NULL;
ALTER TABLE assessments ADD COLUMN IF NOT EXISTS disc_scores JSONB DEFAULT NULL;

-- Update existing column to support composite profiles
-- disc_profile can now be: "D", "I", "S", "C" OR "D/I", "S/C", etc.

-- Example disc_scores JSONB:
-- {
--   "D": 42,
--   "I": 33,
--   "S": 15,
--   "C": 10
-- }
```

**Updated Schema:**
```sql
CREATE TABLE assessments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  consultant_id UUID NOT NULL REFERENCES consultants(id),
  client_email VARCHAR(255) NOT NULL,
  status VARCHAR(50) DEFAULT 'Draft',
  disc_profile VARCHAR(10), -- "D/I", "S/C", etc.
  disc_primary VARCHAR(1), -- "D", "I", "S", "C"
  disc_secondary VARCHAR(1) DEFAULT NULL, -- "D", "I", "S", "C" or NULL
  disc_scores JSONB DEFAULT NULL, -- { "D": 42, "I": 33, "S": 15, "C": 10 }
  primary_phase VARCHAR(50),
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Add index for querying by secondary trait
CREATE INDEX idx_assessments_disc_secondary ON assessments(disc_secondary)
WHERE disc_secondary IS NOT NULL;
```

## API Changes

### Assessment Response (updated)

```json
GET /api/v1/assessments/:id

{
  "id": "assess_123",
  "client_name": "John Smith",
  "disc_profile": "D/I",
  "disc_primary": "D",
  "disc_secondary": "I",
  "disc_scores": {
    "D": 42,
    "I": 33,
    "S": 15,
    "C": 10
  },
  "disc_percentages": {
    "primary": 42,
    "secondary": 33
  },
  "primary_phase": "BUILD",
  "status": "Completed"
}
```

**Backward Compatibility:**
- Old assessments have `disc_secondary: null`
- `disc_profile` shows single letter for legacy assessments
- Frontend handles both formats gracefully

## Backend Implementation

### DISC Service (Enhanced)

```typescript
import { AssessmentResponse } from '../models/AssessmentResponse';
import { Assessment } from '../models/Assessment';

export class DISCService {
  async calculateAndSave(assessmentId: string): Promise<DISCProfile> {
    const assessment = await Assessment.findByPk(assessmentId, {
      include: [
        {
          model: AssessmentResponse,
          include: [{ model: Question }]
        }
      ]
    });

    const profile = calculateDISCProfile(assessment.responses);

    // Save to database
    assessment.disc_profile = profile.profile_string;
    assessment.disc_primary = profile.primary;
    assessment.disc_secondary = profile.secondary;
    assessment.disc_scores = profile.scores;

    await assessment.save();

    return profile;
  }

  async recalculateExistingAssessments(): Promise<void> {
    // Migration script to add secondary traits to existing assessments
    const assessments = await Assessment.findAll({
      where: { disc_secondary: null, status: 'Completed' },
      include: [
        {
          model: AssessmentResponse,
          include: [{ model: Question }]
        }
      ]
    });

    console.log(`Recalculating ${assessments.length} assessments...`);

    for (const assessment of assessments) {
      try {
        const profile = calculateDISCProfile(assessment.responses);

        assessment.disc_profile = profile.profile_string;
        assessment.disc_primary = profile.primary;
        assessment.disc_secondary = profile.secondary;
        assessment.disc_scores = profile.scores;

        await assessment.save();
      } catch (error) {
        console.error(`Failed to recalculate assessment ${assessment.id}:`, error);
      }
    }

    console.log('Recalculation complete.');
  }
}
```

## Frontend Implementation

### DISC Profile Display Component

```typescript
import React from 'react';
import { Box, Typography, Chip, Tooltip } from '@mui/material';

interface DISCProfileDisplayProps {
  profile: string; // "D/I" or "D"
  scores?: {
    D: number;
    I: number;
    S: number;
    C: number;
  };
  showScores?: boolean;
}

export function DISCProfileDisplay({
  profile,
  scores,
  showScores = false
}: DISCProfileDisplayProps) {
  const [primary, secondary] = profile.split('/');

  const traitNames = {
    D: 'Dominance',
    I: 'Influence',
    S: 'Steadiness',
    C: 'Compliance'
  };

  const traitColors = {
    D: '#D32F2F', // Red
    I: '#FFA000', // Orange
    S: '#388E3C', // Green
    C: '#1976D2'  // Blue
  };

  return (
    <Box>
      <Box display="flex" alignItems="center" gap={1}>
        <Tooltip title={traitNames[primary]}>
          <Chip
            label={primary}
            sx={{
              bgcolor: traitColors[primary],
              color: 'white',
              fontWeight: 'bold',
              fontSize: '1rem'
            }}
          />
        </Tooltip>

        {secondary && (
          <>
            <Typography variant="body2" color="text.secondary">/</Typography>
            <Tooltip title={traitNames[secondary]}>
              <Chip
                label={secondary}
                size="small"
                sx={{
                  bgcolor: traitColors[secondary],
                  color: 'white',
                  fontWeight: 'bold'
                }}
              />
            </Tooltip>
          </>
        )}
      </Box>

      {showScores && scores && (
        <Box mt={2}>
          <Typography variant="caption" color="text.secondary" display="block" mb={1}>
            DISC Score Breakdown:
          </Typography>

          {Object.entries(scores)
            .sort(([, a], [, b]) => b - a)
            .map(([trait, score]) => (
              <Box key={trait} display="flex" alignItems="center" gap={1} mb={0.5}>
                <Typography variant="caption" sx={{ minWidth: 120 }}>
                  {traitNames[trait]}:
                </Typography>
                <Box
                  sx={{
                    height: 8,
                    width: `${score}%`,
                    bgcolor: traitColors[trait],
                    borderRadius: 1
                  }}
                />
                <Typography variant="caption" fontWeight="bold">
                  {Math.round(score)}%
                </Typography>
              </Box>
            ))}
        </Box>
      )}
    </Box>
  );
}
```

### Consultant Report Template (Enhanced)

```handlebars
<div class="disc-profile-section">
  <h2>DISC Personality Profile</h2>

  <div class="profile-summary">
    <div class="primary-trait">
      <span class="trait-badge trait-{{disc_primary}}">{{disc_primary}}</span>
      <span class="trait-name">{{disc_primary_name}}</span>
      <span class="trait-percentage">{{disc_percentages.primary}}%</span>
    </div>

    {{#if disc_secondary}}
      <div class="secondary-trait">
        <span class="trait-badge trait-{{disc_secondary}}">{{disc_secondary}}</span>
        <span class="trait-name">{{disc_secondary_name}}</span>
        <span class="trait-percentage">{{disc_percentages.secondary}}%</span>
      </div>
    {{/if}}
  </div>

  <h3>Score Breakdown</h3>
  <table class="disc-scores-table">
    <tr>
      <th>Trait</th>
      <th>Score</th>
      <th>Percentage</th>
    </tr>
    <tr>
      <td><strong>Dominance (D)</strong></td>
      <td><div class="score-bar" style="width: {{disc_scores.D}}%"></div></td>
      <td>{{disc_scores.D}}%</td>
    </tr>
    <tr>
      <td><strong>Influence (I)</strong></td>
      <td><div class="score-bar" style="width: {{disc_scores.I}}%"></div></td>
      <td>{{disc_scores.I}}%</td>
    </tr>
    <tr>
      <td><strong>Steadiness (S)</strong></td>
      <td><div class="score-bar" style="width: {{disc_scores.S}}%"></div></td>
      <td>{{disc_scores.S}}%</td>
    </tr>
    <tr>
      <td><strong>Compliance (C)</strong></td>
      <td><div class="score-bar" style="width: {{disc_scores.C}}%"></div></td>
      <td>{{disc_scores.C}}%</td>
    </tr>
  </table>

  <h3>Interpretation</h3>
  <p>
    {{#if disc_secondary}}
      This client has a <strong>{{disc_primary}}/{{disc_secondary}}</strong> profile,
      meaning they primarily exhibit <strong>{{disc_primary_name}}</strong> traits
      with secondary <strong>{{disc_secondary_name}}</strong> characteristics.
    {{else}}
      This client has a clear <strong>{{disc_primary}}</strong> profile,
      strongly exhibiting <strong>{{disc_primary_name}}</strong> traits.
    {{/if}}
  </p>

  <h4>Communication Recommendations</h4>
  {{> disc_communication_tips}}
</div>
```

## Testing

### Unit Tests

```typescript
describe('Enhanced DISC Algorithm', () => {
  test('identifies primary and secondary traits', () => {
    const responses = mockDISCResponses({
      D: 42,
      I: 33,
      S: 15,
      C: 10
    });

    const profile = calculateDISCProfile(responses);

    expect(profile.primary).toBe('D');
    expect(profile.secondary).toBe('I');
    expect(profile.profile_string).toBe('D/I');
    expect(profile.primary_percentage).toBe(42);
    expect(profile.secondary_percentage).toBe(33);
  });

  test('handles dominant single trait (no secondary)', () => {
    const responses = mockDISCResponses({
      D: 68,
      I: 18,
      S: 8,
      C: 6
    });

    const profile = calculateDISCProfile(responses);

    expect(profile.primary).toBe('D');
    expect(profile.secondary).toBeNull();
    expect(profile.profile_string).toBe('D');
  });

  test('handles close race (no clear secondary)', () => {
    const responses = mockDISCResponses({
      D: 38,
      I: 35,
      S: 15,
      C: 12
    });

    const profile = calculateDISCProfile(responses);

    expect(profile.primary).toBe('D');
    expect(profile.secondary).toBeNull();
    expect(profile.profile_string).toBe('D');
  });

  test('requires minimum 12 DISC questions', () => {
    const responses = mockDISCResponses({ D: 50, I: 30, S: 10, C: 10 }, 8);

    expect(() => calculateDISCProfile(responses)).toThrow(
      'Minimum 12 DISC questions required'
    );
  });

  test('handles ties with consistent ordering', () => {
    const responses = mockDISCResponses({
      D: 25,
      I: 25,
      S: 25,
      C: 25
    });

    const profile = calculateDISCProfile(responses);

    // Should pick first alphabetically as primary when tied
    expect(profile.primary).toBe('D');
    expect(profile.secondary).toBeNull();
  });
});
```

### Integration Tests

```typescript
test('consultant report shows secondary trait', async ({ page }) => {
  await page.goto('/assessments/assess_123/report/consultant');

  // Verify primary trait
  await expect(page.locator('.trait-badge.trait-D')).toBeVisible();

  // Verify secondary trait
  await expect(page.locator('.trait-badge.trait-I')).toBeVisible();

  // Verify score breakdown
  await expect(page.locator('text=/Dominance.*42%/')).toBeVisible();
  await expect(page.locator('text=/Influence.*33%/')).toBeVisible();
});

test('handles legacy assessments without secondary trait', async ({ page }) => {
  await page.goto('/assessments/legacy_123/report/consultant');

  // Should show single trait
  await expect(page.locator('.trait-badge.trait-D')).toBeVisible();

  // Should not show secondary
  await expect(page.locator('.secondary-trait')).not.toBeVisible();
});
```

## Migration Script

### Recalculate Existing Assessments

```typescript
import { DISCService } from './services/discService';

async function migrateSecondaryTraits() {
  const discService = new DISCService();

  console.log('Starting secondary trait migration...');
  await discService.recalculateExistingAssessments();
  console.log('Migration complete!');
}

// Run migration
migrateSecondaryTraits().catch(console.error);
```

## Documentation Updates

### Requirements Mapping

- **REQ-DISC-001**: Enhanced to calculate secondary traits
- **REQ-DISC-002**: Minimum 12 questions still enforced
- **REQ-REPORT-C-002**: Consultant report shows both primary and secondary

### User Guide Updates

**For Consultants:**
> **Understanding Composite DISC Profiles**
>
> Some clients may have a composite profile like "D/I" or "S/C". This means:
> - The first letter is their **primary trait** (strongest characteristic)
> - The second letter is their **secondary trait** (influences behavior, but less dominant)
>
> **Example: D/I Profile**
> - Primary: Dominance (42%) - Direct, results-oriented, decisive
> - Secondary: Influence (33%) - Also values collaboration and enthusiasm
>
> **Communication Tips:**
> - Lead with the primary trait approach (brief, results-focused)
> - Incorporate secondary trait elements (add collaborative language)

---

**Document Version:** 1.0
**Author:** Backend Developer 2
**Last Updated:** 2025-12-22
**Status:** Ready for Implementation
