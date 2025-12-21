# Financial Phase Determination Algorithm

**Version:** 1.0
**Last Updated:** 2025-12-19
**Requirement Reference:** REQ-PHASE-002, REQ-PHASE-004, REQ-PHASE-005

## Overview

The Phase Determination Algorithm calculates a client's current position across 5 financial readiness phases using weighted scoring. The algorithm supports **multiple active phases** for clients in transition (REQ-PHASE-004).

## The 5 Financial Phases

### 1. Stabilize Phase
**Focus:** Basic financial order and compliance
- Accounting health and current bookkeeping
- Debt management and credit health
- Tax compliance and filing status
- Historical data cleanup
- Business/personal finance separation

### 2. Organize Phase
**Focus:** Foundational systems and processes
- Chart of Accounts customization
- System integration (banking, accounting, payroll)
- Expense categorization and tracking
- Document organization and storage
- Revenue and vendor management

### 3. Build Phase
**Focus:** Robust operational systems
- Financial SOPs and procedures
- Month-end/year-end close processes
- Approval workflows and internal controls
- Team roles and responsibilities
- Payroll management and data security

### 4. Grow Phase
**Focus:** Strategic financial planning
- Cash flow projections and forecasting
- Revenue/expense modeling
- KPI tracking and analysis
- Working capital management
- Scenario planning and variance analysis
- Capital investment evaluation

### 5. Systemic Phase (Cross-cutting)
**Focus:** Financial literacy and interpretation
- P&L, Balance Sheet, Cash Flow comprehension
- Regular financial report review
- Data-driven decision making
- Financial ratio understanding
- Stakeholder communication confidence

## Calculation Steps

### Step 1: Initialize Phase Score Accumulators

```javascript
const phaseScores = {
  stabilize: 0,
  organize: 0,
  build: 0,
  grow: 0,
  systemic: 0
};

const phaseQuestionCounts = {
  stabilize: 0,
  organize: 0,
  build: 0,
  grow: 0,
  systemic: 0
};

const maxPossibleScores = {
  stabilize: 0,
  organize: 0,
  build: 0,
  grow: 0,
  systemic: 0
};
```

### Step 2: Aggregate Scores from All Questions

#### For Multiple Choice Questions

```javascript
// Iterate through all answered questions from questions.json
questions.forEach(question => {
  const selectedOption = getUserResponse(question.id);

  // Add scores for each phase
  phaseScores.stabilize += selectedOption.stabilize_score;
  phaseScores.organize += selectedOption.organize_score;
  phaseScores.build += selectedOption.build_score;
  phaseScores.grow += selectedOption.grow_score;
  phaseScores.systemic += selectedOption.systemic_score;

  // Track max possible for percentage calculation
  maxPossibleScores.stabilize += 10;  // Max score per option
  maxPossibleScores.organize += 10;
  maxPossibleScores.build += 10;
  maxPossibleScores.grow += 10;
  maxPossibleScores.systemic += 10;

  // Count questions contributing to each phase
  if (selectedOption.stabilize_score > 0) phaseQuestionCounts.stabilize++;
  if (selectedOption.organize_score > 0) phaseQuestionCounts.organize++;
  if (selectedOption.build_score > 0) phaseQuestionCounts.build++;
  if (selectedOption.grow_score > 0) phaseQuestionCounts.grow++;
  if (selectedOption.systemic_score > 0) phaseQuestionCounts.systemic++;
});
```

#### For Scale Questions (1-10 rating)

Scale questions use a multiplier approach defined in the question metadata:

```javascript
// Example: sys-001, sys-002, sys-003 (comfort with financial statements)
const scaleQuestions = questions.filter(q => q.question_type === 'scale');

scaleQuestions.forEach(question => {
  const userRating = getUserResponse(question.id);  // 1-10

  // Apply multipliers from question.score_multiplier
  phaseScores.stabilize += userRating * question.score_multiplier.stabilize_score;
  phaseScores.organize += userRating * question.score_multiplier.organize_score;
  phaseScores.build += userRating * question.score_multiplier.build_score;
  phaseScores.grow += userRating * question.score_multiplier.grow_score;
  phaseScores.systemic += userRating * question.score_multiplier.systemic_score;

  // Max possible is 10 (max rating) * multiplier
  maxPossibleScores.stabilize += 10 * question.score_multiplier.stabilize_score;
  maxPossibleScores.organize += 10 * question.score_multiplier.organize_score;
  maxPossibleScores.build += 10 * question.score_multiplier.build_score;
  maxPossibleScores.grow += 10 * question.score_multiplier.grow_score;
  maxPossibleScores.systemic += 10 * question.score_multiplier.systemic_score;

  // Count for each phase where multiplier > 0
  Object.keys(question.score_multiplier).forEach(phase => {
    const phaseKey = phase.replace('_score', '');
    if (question.score_multiplier[phase] > 0) {
      phaseQuestionCounts[phaseKey]++;
    }
  });
});
```

#### Include Special Questions (S-Corp Payroll, etc.)

```javascript
// Add scores from special-questions.json if applicable
const entityType = getUserResponse('special-entity-type');

if (entityType === 's_corp') {
  const sCorpPayroll = getUserResponse('special-scorp-payroll');
  const payrollOption = getOption('special-scorp-payroll', sCorpPayroll);

  phaseScores.stabilize += payrollOption.stabilize_score;
  phaseScores.organize += payrollOption.organize_score;
  phaseScores.build += payrollOption.build_score;
  phaseScores.grow += payrollOption.grow_score;
  phaseScores.systemic += payrollOption.systemic_score;

  // Add to max possible
  maxPossibleScores.stabilize += 10;
  maxPossibleScores.organize += 5;
  maxPossibleScores.build += 3;
  maxPossibleScores.grow += 2;
  maxPossibleScores.systemic += 2;
}
```

### Step 3: Calculate Percentage Scores

Convert raw scores to percentages (0-100%):

```javascript
const phasePercentages = {
  stabilize: (phaseScores.stabilize / maxPossibleScores.stabilize) * 100,
  organize: (phaseScores.organize / maxPossibleScores.organize) * 100,
  build: (phaseScores.build / maxPossibleScores.build) * 100,
  grow: (phaseScores.grow / maxPossibleScores.grow) * 100,
  systemic: (phaseScores.systemic / maxPossibleScores.systemic) * 100
};

// Round to 1 decimal place
Object.keys(phasePercentages).forEach(phase => {
  phasePercentages[phase] = Math.round(phasePercentages[phase] * 10) / 10;
});
```

### Step 4: Determine Primary Phase

The primary phase is the highest percentage score:

```javascript
const sortedPhases = Object.entries(phasePercentages)
  .sort((a, b) => b[1] - a[1]);  // Sort descending

const primaryPhase = sortedPhases[0][0];
const primaryScore = sortedPhases[0][1];
```

**Primary Phase Thresholds:**
- **Excellent:** ≥ 80%
- **Good:** 60-79%
- **Fair:** 40-59%
- **Needs Work:** 20-39%
- **Critical:** < 20%

### Step 5: Identify Secondary Phases (Transition States)

Per REQ-PHASE-004, clients can be in multiple phases simultaneously during transition:

```javascript
const secondaryPhases = [];

// A phase is considered "active" if:
// 1. Score >= 50% (moderate competency)
// 2. Not the primary phase
// 3. Within 20 percentage points of primary phase

sortedPhases.forEach(([phase, score]) => {
  if (phase !== primaryPhase &&
      score >= 50 &&
      (primaryScore - score) <= 20) {
    secondaryPhases.push({
      phase: phase,
      score: score,
      relationship: 'concurrent'
    });
  }
});
```

**Transition Pattern Detection:**

```javascript
function detectTransitionPattern(primaryPhase, secondaryPhases, percentages) {
  const phaseOrder = ['stabilize', 'organize', 'build', 'grow'];
  const primaryIndex = phaseOrder.indexOf(primaryPhase);

  // Check if client is progressing forward
  const forwardTransition = secondaryPhases.some(sec =>
    phaseOrder.indexOf(sec.phase) === primaryIndex + 1
  );

  // Check if client is backsliding
  const backwardTransition = secondaryPhases.some(sec =>
    phaseOrder.indexOf(sec.phase) === primaryIndex - 1
  );

  if (forwardTransition) {
    return {
      pattern: 'advancing',
      description: `Transitioning from ${primaryPhase} to next phase`,
      recommendation: 'Continue building on current strengths'
    };
  }

  if (backwardTransition) {
    return {
      pattern: 'foundational_gaps',
      description: `Strong in ${primaryPhase} but foundational needs remain`,
      recommendation: 'Address foundational items while maintaining current level'
    };
  }

  if (secondaryPhases.length > 0) {
    return {
      pattern: 'multi_focus',
      description: 'Working across multiple phase areas',
      recommendation: 'Balance efforts across identified areas'
    };
  }

  return {
    pattern: 'single_focus',
    description: `Clear focus on ${primaryPhase}`,
    recommendation: 'Continue depth in this phase'
  };
}
```

### Step 6: Apply Phase-Specific Criteria (REQ-PHASE-005)

Validate phase determination against specific criteria:

```javascript
const phaseCriteria = {
  stabilize: {
    required: [
      { question: 'stab-001', minValue: 'recent' },      // Bookkeeping current
      { question: 'stab-002', minValue: 'mostly_separated' }, // Finances separated
      { question: 'stab-004', minValue: 'mostly_current' }    // Tax compliance
    ],
    description: 'Basic accounting health and compliance'
  },
  organize: {
    required: [
      { question: 'org-001', minValue: 'standard' },     // Chart of Accounts
      { question: 'org-003', minValue: 'basic_categories' }, // Expense tracking
      { question: 'org-005', minValue: 'digital_basic' }      // Document storage
    ],
    dependencies: ['stabilize >= 60%'],
    description: 'Foundational systems setup'
  },
  build: {
    required: [
      { question: 'build-001', minValue: 'basic_docs' },  // SOPs documented
      { question: 'build-002', minValue: 'regular_routine' }, // Close process
      { question: 'build-005', minValue: 'basic_controls' }   // Internal controls
    ],
    dependencies: ['stabilize >= 60%', 'organize >= 60%'],
    description: 'Operational systems and workflows'
  },
  grow: {
    required: [
      { question: 'grow-001', minValue: 'quarterly' },    // Cash flow projections
      { question: 'grow-003', minValue: 'regular_review' }, // KPI tracking
      { question: 'grow-007', minValue: 'regular_comparison' } // Variance analysis
    ],
    dependencies: ['stabilize >= 70%', 'organize >= 70%', 'build >= 60%'],
    description: 'Strategic planning and forecasting'
  },
  systemic: {
    required: [
      { question: 'sys-001', minScale: 6 },  // P&L comfort
      { question: 'sys-002', minScale: 6 },  // Balance Sheet comfort
      { question: 'sys-004', minValue: 'monthly' } // Review frequency
    ],
    description: 'Financial literacy and interpretation',
    note: 'Cross-cutting phase, can be developed independently'
  }
};

function validatePhaseCriteria(phase, userResponses, phasePercentages) {
  const criteria = phaseCriteria[phase];
  const meetsRequired = criteria.required.every(req => {
    const userResponse = userResponses[req.question];

    if (req.minScale) {
      return userResponse >= req.minScale;
    }

    if (req.minValue) {
      // Check if response meets minimum threshold
      return isResponseAdequate(req.question, userResponse, req.minValue);
    }

    return true;
  });

  const meetsDependencies = (criteria.dependencies || []).every(dep => {
    // Parse dependency like "stabilize >= 60%"
    const [depPhase, threshold] = parseDependency(dep);
    return phasePercentages[depPhase] >= threshold;
  });

  return {
    phase: phase,
    meetsRequired: meetsRequired,
    meetsDependencies: meetsDependencies,
    isQualified: meetsRequired && meetsDependencies
  };
}
```

### Step 7: Generate Phase Summary

Create final phase determination summary:

```javascript
const phaseSummary = {
  primary: {
    phase: primaryPhase,
    score: primaryScore,
    rating: getRating(primaryScore),  // Excellent/Good/Fair/etc.
    criteriaMet: validatePhaseCriteria(primaryPhase, responses, phasePercentages)
  },
  secondary: secondaryPhases.map(sec => ({
    phase: sec.phase,
    score: sec.score,
    rating: getRating(sec.score),
    criteriaMet: validatePhaseCriteria(sec.phase, responses, phasePercentages)
  })),
  transitionPattern: detectTransitionPattern(primaryPhase, secondaryPhases, phasePercentages),
  allScores: phasePercentages,
  rawScores: phaseScores,
  questionCounts: phaseQuestionCounts
};
```

## Edge Cases and Special Handling

### Case 1: All Phases Low Scores (< 40%)

```javascript
if (Math.max(...Object.values(phasePercentages)) < 40) {
  return {
    ...phaseSummary,
    specialFlag: 'FOUNDATIONAL_WORK_NEEDED',
    message: 'Significant opportunity to strengthen financial foundations',
    recommendedFocus: 'stabilize',
    note: 'Start with Stabilize phase regardless of highest score'
  };
}
```

### Case 2: Systemic Phase Highest but Other Phases Low

```javascript
if (primaryPhase === 'systemic' && phasePercentages.stabilize < 60) {
  return {
    ...phaseSummary,
    specialFlag: 'KNOWLEDGE_EXCEEDS_SYSTEMS',
    message: 'Financial literacy is strong, but systems need development',
    recommendedFocus: 'stabilize',
    note: 'Apply financial knowledge to build foundational systems'
  };
}
```

### Case 3: High Grow Phase but Low Build Phase

```javascript
const phaseOrder = ['stabilize', 'organize', 'build', 'grow'];
const primaryIndex = phaseOrder.indexOf(primaryPhase);

// Check for gaps in earlier phases
const hasGaps = phaseOrder.slice(0, primaryIndex).some(phase =>
  phasePercentages[phase] < 60
);

if (hasGaps && primaryPhase === 'grow') {
  return {
    ...phaseSummary,
    specialFlag: 'FOUNDATIONAL_GAPS',
    message: 'Advanced in planning but foundational systems need strengthening',
    recommendedSecondaryFocus: phaseOrder.slice(0, primaryIndex).filter(p =>
      phasePercentages[p] < 60
    ),
    note: 'Address foundational gaps to support growth activities'
  };
}
```

### Case 4: Near-Equal Scores Across Multiple Phases

```javascript
const scoreRange = Math.max(...Object.values(phasePercentages)) -
                   Math.min(...Object.values(phasePercentages));

if (scoreRange < 15) {
  return {
    ...phaseSummary,
    specialFlag: 'BALANCED_ACROSS_PHASES',
    message: 'Relatively balanced financial operations',
    recommendedFocus: primaryPhase,
    note: 'Focus on identified gaps within current highest phase'
  };
}
```

## Weighting Considerations

### Question-Level Weighting

Some questions have higher impact on specific phases:

```javascript
const weightedQuestions = {
  'stab-004': { weight: 1.5 },  // Tax compliance - critical for Stabilize
  'build-005': { weight: 1.3 },  // Internal controls - critical for Build
  'grow-001': { weight: 1.5 }    // Cash flow projections - critical for Grow
};

// Apply weights during scoring
Object.keys(weightedQuestions).forEach(questionId => {
  const weight = weightedQuestions[questionId].weight;
  const question = getQuestion(questionId);

  // Multiply phase scores by weight
  phaseScores[question.phase] *= weight;
  maxPossibleScores[question.phase] *= weight;
});
```

### Phase Dependency Weighting

Grow phase requires strong foundation in earlier phases:

```javascript
function applyDependencyWeighting(phasePercentages) {
  const adjusted = { ...phasePercentages };

  // If Grow phase is high but earlier phases are weak, reduce Grow score
  if (adjusted.grow > 70) {
    const foundationScore = (
      phasePercentages.stabilize * 0.4 +
      phasePercentages.organize * 0.3 +
      phasePercentages.build * 0.3
    );

    if (foundationScore < 60) {
      // Cap Grow phase at foundationScore + 20
      adjusted.grow = Math.min(adjusted.grow, foundationScore + 20);
    }
  }

  return adjusted;
}
```

## Output Structure

```javascript
{
  primary: {
    phase: "organize",
    score: 72.5,
    rating: "good",
    criteriaMet: {
      phase: "organize",
      meetsRequired: true,
      meetsDependencies: true,
      isQualified: true
    }
  },
  secondary: [
    {
      phase: "build",
      score: 58.3,
      rating: "fair",
      relationship: "concurrent"
    }
  ],
  transitionPattern: {
    pattern: "advancing",
    description: "Transitioning from organize to build phase",
    recommendation: "Continue building on organizational foundations"
  },
  allScores: {
    stabilize: 78.2,
    organize: 72.5,
    build: 58.3,
    grow: 42.1,
    systemic: 65.0
  },
  rawScores: {
    stabilize: 234,
    organize: 217,
    build: 175,
    grow: 126,
    systemic: 195
  },
  questionCounts: {
    stabilize: 30,
    organize: 30,
    build: 30,
    grow: 30,
    systemic: 30
  },
  specialFlag: null,
  calculatedAt: "2025-12-19T14:32:00Z"
}
```

## Validation and Testing

### Test Case 1: New Business (< 1 year)
- Expected Primary: Stabilize (40-60%)
- Expected Secondary: Organize (30-50%)
- Pattern: Single focus on stabilization

### Test Case 2: Established Business (5+ years)
- Expected Primary: Build or Grow (60-80%)
- Expected Secondary: Organize (70-85%)
- Pattern: Advancing or multi-focus

### Test Case 3: Financial Literacy Strong, Systems Weak
- Expected Primary: Systemic (70%+)
- Expected Secondaries: Stabilize/Organize (40-60%)
- Special Flag: KNOWLEDGE_EXCEEDS_SYSTEMS

### Test Case 4: All Low Scores
- Expected Primary: Stabilize (20-40%)
- Expected Secondaries: None
- Special Flag: FOUNDATIONAL_WORK_NEEDED

## Integration with Report Generation

The phase determination results are used to:

1. **Generate Executive Summary** - Highlight primary phase and transition state
2. **Prioritize Recommendations** - Focus on primary and secondary phases
3. **Create Action Plan** - Phase-specific quick wins and strategic priorities
4. **Display Phase Visualization** - Show scores across all 5 phases
5. **Customize Report Sections** - Include relevant content for active phases

## Performance Optimization

- **Calculation Time:** O(n) where n = number of questions answered
- **Caching:** Cache phase results with response hash to avoid recalculation
- **Lazy Loading:** Calculate detailed criteria validation only when generating full report

## References

- Requirements: REQ-PHASE-002, REQ-PHASE-004, REQ-PHASE-005
- Question Bank: `../questions.json`
- Special Questions: `../special-questions.json`
- Report Integration: `recommendation-engine.md`
