# Multiple Phase Identification - Technical Specification

**Version:** 1.0
**Date:** 2025-12-22
**Work Stream:** 42 - Multiple Phase Identification
**Phase:** 3 - Advanced Features
**Dependency Level:** 0

## Overview

The Multiple Phase Identification feature enhances the phase determination algorithm to identify when clients are in transition between financial phases. Instead of forcing a single phase, the system can report "BUILD/GROW" for clients who have characteristics of multiple phases.

### Business Value

Many clients are not cleanly in one phase - they may have:
- Strong organizational foundations (ORGANIZE complete)
- Starting to build operational systems (BUILD in progress)
- Beginning cash flow planning (GROW starting)

Reporting multiple phases provides:
- More accurate assessment results
- Better roadmap recommendations
- Clearer path forward for consultants

## Requirements Mapping

**REQ-PHASE-004:** Support multiple phases for clients in transition
**REQ-REPORT-CL-004:** Multi-phase roadmap in client reports
**REQ-REPORT-C-004:** Multi-phase analysis in consultant reports

## Phase Determination Logic

### Current (Single Phase) Algorithm

```typescript
// Current: Assigns only the highest-scoring phase
function determinePhase(scores: PhaseScores): string {
  const phases = Object.entries(scores)
    .sort(([, a], [, b]) => b - a);

  return phases[0][0]; // Return only the top phase
}

// Example:
// Scores: { STABILIZE: 60, ORGANIZE: 85, BUILD: 75, GROW: 40, SYSTEMIC: 20 }
// Result: "ORGANIZE" (single phase, ignores BUILD even though it's close)
```

### Enhanced (Multiple Phase) Algorithm

```typescript
interface PhaseIdentification {
  primary_phase: string;
  secondary_phases: string[];
  all_phases: string[]; // primary + secondary
  phase_string: string; // "BUILD/GROW" or "ORGANIZE"
  scores: PhaseScores;
  phase_percentages: { [key: string]: number };
  transition_status: 'single' | 'transitioning' | 'multi';
}

function determinePhases(scores: PhaseScores): PhaseIdentification {
  // Convert raw scores to percentages
  const total = Object.values(scores).reduce((sum, score) => sum + score, 0);
  const percentages = {};
  Object.entries(scores).forEach(([phase, score]) => {
    percentages[phase] = Math.round((score / total) * 100);
  });

  // Sort by score descending
  const sorted = Object.entries(percentages)
    .sort(([, a], [, b]) => b - a)
    .map(([phase, pct]) => ({ phase, percentage: pct }));

  const primary = sorted[0];
  const secondary: string[] = [];

  // Secondary phase rules:
  // 1. Must be ≥20% to be meaningful
  // 2. Must be within 15% of primary (indicates transition)
  // 3. Must be ≥10% ahead of next phase (clear separation)

  for (let i = 1; i < sorted.length; i++) {
    const current = sorted[i];
    const next = sorted[i + 1];

    const isSignificant = current.percentage >= 20;
    const closeToFirst = (primary.percentage - current.percentage) <= 15;
    const aheadOfNext = next ? (current.percentage - next.percentage) >= 10 : true;

    if (isSignificant && closeToFirst && aheadOfNext) {
      secondary.push(current.phase);
    }
  }

  // Determine transition status
  let transition_status: 'single' | 'transitioning' | 'multi';
  if (secondary.length === 0) {
    transition_status = 'single';
  } else if (secondary.length === 1) {
    transition_status = 'transitioning';
  } else {
    transition_status = 'multi';
  }

  // Format phase string
  const all_phases = [primary.phase, ...secondary];
  const phase_string = all_phases.join('/');

  return {
    primary_phase: primary.phase,
    secondary_phases: secondary,
    all_phases,
    phase_string,
    scores,
    phase_percentages: percentages,
    transition_status
  };
}
```

### Example Scenarios

**Scenario 1: Clear Single Phase**
```typescript
Scores: { STABILIZE: 15, ORGANIZE: 80, BUILD: 20, GROW: 10, SYSTEMIC: 5 }
Percentages: { STABILIZE: 12%, ORGANIZE: 62%, BUILD: 15%, GROW: 8%, SYSTEMIC: 4% }

Result: {
  primary_phase: "ORGANIZE",
  secondary_phases: [],
  phase_string: "ORGANIZE",
  transition_status: "single"
}
// ORGANIZE is dominant (62%), no other phases close enough
```

**Scenario 2: Transition Between Two Phases**
```typescript
Scores: { STABILIZE: 20, ORGANIZE: 55, BUILD: 48, GROW: 15, SYSTEMIC: 12 }
Percentages: { STABILIZE: 13%, ORGANIZE: 37%, BUILD: 32%, GROW: 10%, SYSTEMIC: 8% }

Result: {
  primary_phase: "ORGANIZE",
  secondary_phases: ["BUILD"],
  phase_string: "ORGANIZE/BUILD",
  transition_status: "transitioning"
}
// ORGANIZE (37%) and BUILD (32%) are close (only 5% apart)
// Client is transitioning from ORGANIZE to BUILD
```

**Scenario 3: Multi-Phase Spread**
```typescript
Scores: { STABILIZE: 25, ORGANIZE: 45, BUILD: 42, GROW: 38, SYSTEMIC: 10 }
Percentages: { STABILIZE: 16%, ORGANIZE: 28%, BUILD: 26%, GROW: 24%, SYSTEMIC: 6% }

Result: {
  primary_phase: "ORGANIZE",
  secondary_phases: ["BUILD", "GROW"],
  phase_string: "ORGANIZE/BUILD/GROW",
  transition_status: "multi"
}
// Three phases within 15% range - complex situation
```

**Scenario 4: No Secondary (Even if Close)**
```typescript
Scores: { STABILIZE: 10, ORGANIZE: 52, BUILD: 45, GROW: 42, SYSTEMIC: 6 }
Percentages: { STABILIZE: 6%, ORGANIZE: 33%, BUILD: 29%, GROW: 27%, SYSTEMIC: 4% }

Result: {
  primary_phase: "ORGANIZE",
  secondary_phases: [],
  phase_string: "ORGANIZE",
  transition_status: "single"
}
// BUILD (29%) fails "≥10% ahead of next" rule
// GROW is only 2% behind BUILD, so BUILD is not clearly separated
```

## Database Schema

### assessments Table (extension)

```sql
ALTER TABLE assessments
ADD COLUMN IF NOT EXISTS secondary_phases TEXT[] DEFAULT '{}',
ADD COLUMN IF NOT EXISTS phase_percentages JSONB DEFAULT NULL,
ADD COLUMN IF NOT EXISTS transition_status VARCHAR(20) DEFAULT 'single';

-- Update existing column to support multi-phase
-- primary_phase remains as the highest-scoring phase

-- Example phase_percentages:
-- {
--   "STABILIZE": 15,
--   "ORGANIZE": 38,
--   "BUILD": 32,
--   "GROW": 12,
--   "SYSTEMIC": 3
-- }

-- Add index for querying by secondary phases
CREATE INDEX idx_assessments_secondary_phases
ON assessments USING GIN (secondary_phases);

-- Add index for transition status
CREATE INDEX idx_assessments_transition_status
ON assessments(transition_status);
```

## API Changes

### Assessment Response (Updated)

```json
GET /api/v1/assessments/:id

{
  "id": "assess_123",
  "client_name": "John Smith",
  "primary_phase": "ORGANIZE",
  "secondary_phases": ["BUILD"],
  "phase_string": "ORGANIZE/BUILD",
  "phase_percentages": {
    "STABILIZE": 13,
    "ORGANIZE": 37,
    "BUILD": 32,
    "GROW": 10,
    "SYSTEMIC": 8
  },
  "transition_status": "transitioning",
  "disc_profile": "D/I",
  "status": "Completed"
}
```

## Backend Implementation

### Enhanced Phase Service

```typescript
export class PhaseService {
  /**
   * Calculates phase identification with multiple phase support
   */
  async calculatePhases(assessmentId: string): Promise<PhaseIdentification> {
    const assessment = await Assessment.findByPk(assessmentId, {
      include: [{ model: AssessmentResponse, include: [{ model: Question }] }]
    });

    // Calculate raw scores for each phase
    const scores = this.calculatePhaseScores(assessment.responses);

    // Determine primary and secondary phases
    const identification = this.determinePhases(scores);

    // Save to database
    assessment.primary_phase = identification.primary_phase;
    assessment.secondary_phases = identification.secondary_phases;
    assessment.phase_percentages = identification.phase_percentages;
    assessment.transition_status = identification.transition_status;
    await assessment.save();

    return identification;
  }

  /**
   * Calculates raw scores for each phase based on responses
   */
  private calculatePhaseScores(responses: AssessmentResponse[]): PhaseScores {
    const scores = {
      STABILIZE: 0,
      ORGANIZE: 0,
      BUILD: 0,
      GROW: 0,
      SYSTEMIC: 0
    };

    responses.forEach(response => {
      const question = response.question;
      const answer = response.response_value;

      // Each question has weights for each phase
      // Example: {STABILIZE: 0, ORGANIZE: 3, BUILD: 2, GROW: 0, SYSTEMIC: 0}
      const weights = question.phase_weights || {};

      Object.entries(weights).forEach(([phase, weight]) => {
        scores[phase] += Number(weight);
      });
    });

    return scores;
  }

  /**
   * Determines primary and secondary phases
   */
  private determinePhases(scores: PhaseScores): PhaseIdentification {
    // Convert to percentages
    const total = Object.values(scores).reduce((sum, score) => sum + score, 0);
    const percentages: { [key: string]: number } = {};

    Object.entries(scores).forEach(([phase, score]) => {
      percentages[phase] = Math.round((score / total) * 100);
    });

    // Sort by percentage descending
    const sorted = Object.entries(percentages)
      .sort(([, a], [, b]) => b - a)
      .map(([phase, pct]) => ({ phase, percentage: pct }));

    const primary = sorted[0];
    const secondary: string[] = [];

    // Apply secondary phase rules
    for (let i = 1; i < sorted.length; i++) {
      const current = sorted[i];
      const next = sorted[i + 1];

      const isSignificant = current.percentage >= 20;
      const closeToFirst = (primary.percentage - current.percentage) <= 15;
      const aheadOfNext = next ? (current.percentage - next.percentage) >= 10 : true;

      if (isSignificant && closeToFirst && aheadOfNext) {
        secondary.push(current.phase);
      }
    }

    // Determine transition status
    let transition_status: 'single' | 'transitioning' | 'multi';
    if (secondary.length === 0) {
      transition_status = 'single';
    } else if (secondary.length === 1) {
      transition_status = 'transitioning';
    } else {
      transition_status = 'multi';
    }

    const all_phases = [primary.phase, ...secondary];
    const phase_string = all_phases.join('/');

    return {
      primary_phase: primary.phase,
      secondary_phases: secondary,
      all_phases,
      phase_string,
      scores,
      phase_percentages: percentages,
      transition_status
    };
  }
}
```

## Report Template Updates

### Consultant Report - Multi-Phase Section

```handlebars
<h2>Phase Identification</h2>

<div class="phase-summary">
  <h3>Primary Phase: {{primary_phase}}</h3>

  {{#if secondary_phases}}
    <p class="transition-notice">
      <strong>Transition Status:</strong>
      {{#if (eq transition_status 'transitioning')}}
        Client is transitioning between phases
      {{else}}
        Client shows characteristics across multiple phases
      {{/if}}
    </p>

    <h4>Secondary Phases:</h4>
    <ul>
      {{#each secondary_phases}}
        <li>{{this}} ({{lookup ../phase_percentages this}}%)</li>
      {{/each}}
    </ul>
  {{else}}
    <p>Client is clearly in the <strong>{{primary_phase}}</strong> phase.</p>
  {{/if}}
</div>

<h3>Score Breakdown</h3>
<table class="phase-scores-table">
  <tr>
    <th>Phase</th>
    <th>Score</th>
    <th>Percentage</th>
  </tr>
  {{#each phase_percentages}}
    <tr {{#if (includes ../all_phases @key)}}class="highlighted-phase"{{/if}}>
      <td><strong>{{@key}}</strong></td>
      <td><div class="score-bar" style="width: {{this}}%"></div></td>
      <td>{{this}}%</td>
    </tr>
  {{/each}}
</table>

<h3>Interpretation</h3>
{{#if (eq transition_status 'single')}}
  <p>
    This client is clearly in the <strong>{{primary_phase}}</strong> phase.
    Focus recommendations on {{primary_phase}}-specific actions.
  </p>
{{else if (eq transition_status 'transitioning')}}
  <p>
    This client is transitioning from <strong>{{primary_phase}}</strong> to
    <strong>{{secondary_phases.[0]}}</strong>. They have completed many
    {{primary_phase}} fundamentals and are ready to advance to {{secondary_phases.[0]}}.
  </p>
  <p>
    <strong>Recommended Approach:</strong> Finish any remaining {{primary_phase}}
    items while beginning {{secondary_phases.[0]}} initiatives.
  </p>
{{else}}
  <p>
    This client shows characteristics across multiple phases:
    <strong>{{phase_string}}</strong>. This suggests uneven development
    across different financial areas.
  </p>
  <p>
    <strong>Recommended Approach:</strong> Prioritize building consistency.
    Strengthen foundations in earlier phases while selectively advancing in later phases.
  </p>
{{/if}}
```

### Client Report - Multi-Phase Roadmap

```handlebars
<h2>Your Financial Journey</h2>

{{#if (eq transition_status 'single')}}
  <p>
    You are currently in the <strong>{{primary_phase}}</strong> phase.
    Here's your roadmap for moving forward:
  </p>

  {{> phase_roadmap phase=primary_phase}}

{{else}}
  <p>
    You're making great progress! You've completed many <strong>{{primary_phase}}</strong>
    fundamentals and are beginning to work on <strong>{{secondary_phases.[0]}}</strong> initiatives.
  </p>

  <h3>Current Focus: {{primary_phase}}</h3>
  <p>Complete these remaining items to solidify your foundation:</p>
  {{> phase_roadmap phase=primary_phase show_remaining_only=true}}

  <h3>Next Steps: {{secondary_phases.[0]}}</h3>
  <p>You're ready to begin working on these advanced initiatives:</p>
  {{> phase_roadmap phase=secondary_phases.[0] show_intro_only=true}}

{{/if}}
```

## Frontend Implementation

### Phase Display Component

```typescript
import React from 'react';
import { Box, Chip, Typography, Tooltip } from '@mui/material';

interface PhaseDisplayProps {
  primary_phase: string;
  secondary_phases?: string[];
  phase_percentages?: { [key: string]: number };
  transition_status?: 'single' | 'transitioning' | 'multi';
}

export function PhaseDisplay({
  primary_phase,
  secondary_phases = [],
  phase_percentages,
  transition_status = 'single'
}: PhaseDisplayProps) {
  const phaseColors = {
    STABILIZE: '#D32F2F',
    ORGANIZE: '#FF6B35',
    BUILD: '#FFA000',
    GROW: '#388E3C',
    SYSTEMIC: '#1976D2'
  };

  const transitionLabels = {
    single: 'Single Phase',
    transitioning: 'Transitioning',
    multi: 'Multi-Phase'
  };

  return (
    <Box>
      <Box display="flex" alignItems="center" gap={1} mb={2}>
        <Tooltip title={`Primary phase: ${phase_percentages?.[primary_phase]}%`}>
          <Chip
            label={primary_phase}
            sx={{
              bgcolor: phaseColors[primary_phase],
              color: 'white',
              fontWeight: 'bold',
              fontSize: '1rem'
            }}
          />
        </Tooltip>

        {secondary_phases.map(phase => (
          <React.Fragment key={phase}>
            <Typography variant="body2" color="text.secondary">/</Typography>
            <Tooltip title={`Secondary phase: ${phase_percentages?.[phase]}%`}>
              <Chip
                label={phase}
                size="small"
                sx={{
                  bgcolor: phaseColors[phase],
                  color: 'white',
                  fontWeight: 'bold'
                }}
              />
            </Tooltip>
          </React.Fragment>
        ))}

        <Chip
          label={transitionLabels[transition_status]}
          size="small"
          variant="outlined"
          sx={{ ml: 1 }}
        />
      </Box>

      {phase_percentages && (
        <Box>
          <Typography variant="caption" color="text.secondary" display="block" mb={1}>
            Phase Score Breakdown:
          </Typography>

          {Object.entries(phase_percentages)
            .sort(([, a], [, b]) => b - a)
            .map(([phase, pct]) => (
              <Box key={phase} display="flex" alignItems="center" gap={1} mb={0.5}>
                <Typography variant="caption" sx={{ minWidth: 100 }}>
                  {phase}:
                </Typography>
                <Box
                  sx={{
                    height: 8,
                    width: `${pct}%`,
                    bgcolor: phaseColors[phase],
                    borderRadius: 1
                  }}
                />
                <Typography variant="caption" fontWeight="bold">
                  {pct}%
                </Typography>
              </Box>
            ))}
        </Box>
      )}
    </Box>
  );
}
```

## Testing

### Unit Tests

```typescript
describe('Phase Identification', () => {
  test('identifies single clear phase', () => {
    const scores = {
      STABILIZE: 15,
      ORGANIZE: 80,
      BUILD: 20,
      GROW: 10,
      SYSTEMIC: 5
    };

    const service = new PhaseService();
    const result = service['determinePhases'](scores);

    expect(result.primary_phase).toBe('ORGANIZE');
    expect(result.secondary_phases).toEqual([]);
    expect(result.phase_string).toBe('ORGANIZE');
    expect(result.transition_status).toBe('single');
  });

  test('identifies transition between two phases', () => {
    const scores = {
      STABILIZE: 20,
      ORGANIZE: 55,
      BUILD: 48,
      GROW: 15,
      SYSTEMIC: 12
    };

    const service = new PhaseService();
    const result = service['determinePhases'](scores);

    expect(result.primary_phase).toBe('ORGANIZE');
    expect(result.secondary_phases).toContain('BUILD');
    expect(result.phase_string).toBe('ORGANIZE/BUILD');
    expect(result.transition_status).toBe('transitioning');
  });

  test('identifies multi-phase scenario', () => {
    const scores = {
      STABILIZE: 25,
      ORGANIZE: 45,
      BUILD: 42,
      GROW: 38,
      SYSTEMIC: 10
    };

    const service = new PhaseService();
    const result = service['determinePhases'](scores);

    expect(result.primary_phase).toBe('ORGANIZE');
    expect(result.secondary_phases.length).toBeGreaterThan(1);
    expect(result.transition_status).toBe('multi');
  });

  test('respects 20% minimum threshold', () => {
    const scores = {
      STABILIZE: 5,
      ORGANIZE: 70,
      BUILD: 15,
      GROW: 7,
      SYSTEMIC: 3
    };

    const service = new PhaseService();
    const result = service['determinePhases'](scores);

    expect(result.secondary_phases).toEqual([]);
    // BUILD is 15%, below 20% threshold
  });
});
```

---

**Document Version:** 1.0
**Author:** Backend Developer 2
**Last Updated:** 2025-12-22
**Status:** Ready for Implementation
