# DISC Personality Type Calculation Algorithm

**Version:** 1.0
**Last Updated:** 2025-12-19
**Requirement Reference:** REQ-QUEST-002, REQ-QUEST-003, REQ-REPORT-CL-007, Appendix B

## Overview

The DISC algorithm determines a client's personality profile to customize report language, detail level, and communication strategies. DISC questions are **hidden from clients** during the assessment (REQ-QUEST-003) to ensure authentic responses.

## DISC Profile Types

- **D (Dominance):** Results-oriented, direct, competitive, decisive
- **I (Influence):** Enthusiastic, optimistic, collaborative, people-focused
- **S (Steadiness):** Patient, supportive, stable, team-oriented
- **C (Compliance):** Analytical, precise, detail-oriented, systematic

## Minimum Question Requirement

**Requirement:** Minimum 12 DISC questions for statistical reliability (REQ-QUEST-002)
**Current Implementation:** 15 questions in `disc-questions.json`

## Calculation Steps

### Step 1: Initialize Score Accumulators

```javascript
const discScores = {
  D: 0,  // Dominance
  I: 0,  // Influence
  S: 0,  // Steadiness
  C: 0   // Compliance
};

const questionCount = 0;
```

### Step 2: Aggregate Scores Across All DISC Questions

For each DISC question answered:

```javascript
// For each question response
const selectedOption = getSelectedOption(questionId, userResponse);

discScores.D += selectedOption.disc_d_score;
discScores.I += selectedOption.disc_i_score;
discScores.S += selectedOption.disc_s_score;
discScores.C += selectedOption.disc_c_score;

questionCount++;
```

**Validation:** Ensure all required DISC questions are answered before calculating profile.

### Step 3: Calculate Average Scores

Normalize scores by the number of questions to get average scores per type:

```javascript
const avgScores = {
  D: discScores.D / questionCount,
  I: discScores.I / questionCount,
  S: discScores.S / questionCount,
  C: discScores.C / questionCount
};
```

**Expected Range:** Average scores should typically fall between 0-10 per type.

### Step 4: Determine Primary Type

The primary type is the highest average score:

```javascript
const sortedTypes = Object.entries(avgScores)
  .sort((a, b) => b[1] - a[1]);  // Sort descending by score

const primaryType = sortedTypes[0][0];      // Highest score
const primaryScore = sortedTypes[0][1];
```

**Minimum Score Threshold:**
- Primary type score must be ≥ 4.0 (out of 10) to be considered significant
- If no type meets threshold, classify as "Balanced" profile

### Step 5: Determine Secondary Type

The secondary type is the second-highest score:

```javascript
const secondaryType = sortedTypes[1][0];    // Second highest
const secondaryScore = sortedTypes[1][1];
```

**Secondary Type Significance Threshold:**
- Secondary type is considered significant if:
  - `secondaryScore >= 4.0` AND
  - `(primaryScore - secondaryScore) <= 3.0`
- If difference is > 3.0, secondary type is not significant (strong single profile)

### Step 6: Handle Ties

If two or more types have identical highest scores:

```javascript
if (primaryScore === secondaryScore) {
  // Tie scenario - use combination profile
  const tiedTypes = sortedTypes
    .filter(([type, score]) => score === primaryScore)
    .map(([type, score]) => type);

  // Create combination label (e.g., "D/I" or "S/C")
  const profileType = tiedTypes.join('/');

  // Use blended communication strategy
  return {
    profileType: profileType,
    primaryType: tiedTypes[0],
    secondaryType: tiedTypes[1],
    isTie: true,
    scores: avgScores
  };
}
```

**Tie Resolution Priority (if 3+ types tied):**
1. D (Dominance)
2. I (Influence)
3. S (Steadiness)
4. C (Compliance)

### Step 7: Classify Profile Pattern

Determine overall profile pattern:

```javascript
function classifyProfile(primaryType, primaryScore, secondaryType, secondaryScore) {
  const scoreDifference = primaryScore - secondaryScore;

  if (primaryScore < 4.0) {
    return {
      pattern: "balanced",
      description: "No strongly dominant personality type"
    };
  }

  if (scoreDifference > 3.0) {
    return {
      pattern: "strong_primary",
      description: `Strong ${primaryType} profile`,
      communicationStyle: primaryType
    };
  }

  if (secondaryScore >= 4.0 && scoreDifference <= 3.0) {
    return {
      pattern: "dual_profile",
      description: `${primaryType}/${secondaryType} combination`,
      communicationStyle: "blended"
    };
  }

  return {
    pattern: "moderate_primary",
    description: `${primaryType} with ${secondaryType} tendencies`,
    communicationStyle: primaryType
  };
}
```

## Final Output Structure

```javascript
{
  profileType: "D",              // Primary type or combination (e.g., "D/I")
  primaryType: "D",              // Highest scoring type
  primaryScore: 7.8,             // Average score for primary type
  secondaryType: "I",            // Second highest type
  secondaryScore: 5.2,           // Average score for secondary type
  pattern: "dual_profile",       // Profile classification
  isTie: false,                  // Whether top scores are tied
  scores: {                      // All average scores
    D: 7.8,
    I: 5.2,
    S: 3.1,
    C: 2.9
  },
  communicationStrategy: "D",    // Which strategy to use for reports
  confidenceLevel: "high"        // Based on score separation
}
```

## Confidence Level Calculation

Determine confidence in profile classification:

```javascript
function calculateConfidence(primaryScore, secondaryScore, pattern) {
  const scoreDifference = primaryScore - secondaryScore;

  if (primaryScore < 4.0) {
    return "low";  // Balanced profile, no clear preference
  }

  if (scoreDifference > 4.0) {
    return "high"; // Clear dominant type
  }

  if (scoreDifference > 2.0) {
    return "medium"; // Moderate preference
  }

  return "low";  // Close scores, uncertain
}
```

## Communication Strategy Mapping

Based on the final profile, map to communication strategy:

| Profile Type | Communication Strategy | Report Characteristics |
|--------------|------------------------|------------------------|
| D (Strong) | Direct & Results-Oriented | Brief, ROI-focused, quick wins, bullet points |
| I (Strong) | Collaborative & Visual | Big picture, opportunities, colorful visuals, engaging |
| S (Strong) | Supportive & Methodical | Step-by-step, reassuring, gentle pace, clear timelines |
| C (Strong) | Analytical & Detailed | Comprehensive data, thorough analysis, documentation |
| D/I Combo | Balanced: Results + Vision | Concise with vision, action-oriented opportunities |
| D/C Combo | Balanced: Results + Data | Data-driven with clear ROI and action items |
| I/S Combo | Balanced: People + Process | Collaborative with clear guidance and support |
| S/C Combo | Balanced: Stability + Precision | Methodical with detailed documentation |
| Balanced | Moderate all approaches | Standard format with balanced detail level |

## Edge Cases and Special Handling

### Case 1: Incomplete DISC Assessment
```javascript
if (answeredQuestionCount < 12) {
  return {
    error: "INSUFFICIENT_DATA",
    message: "Minimum 12 DISC questions required for reliable profiling",
    fallbackStrategy: "balanced"
  };
}
```

### Case 2: All Scores Below Threshold
```javascript
if (Math.max(...Object.values(avgScores)) < 4.0) {
  return {
    profileType: "balanced",
    pattern: "no_strong_preference",
    communicationStrategy: "balanced",
    note: "Client shows balanced preferences across all types"
  };
}
```

### Case 3: Opposing Types Tied (D/S or I/C)
```javascript
const opposingPairs = [['D', 'S'], ['I', 'C']];

function isOpposingTie(type1, type2) {
  return opposingPairs.some(pair =>
    (pair.includes(type1) && pair.includes(type2))
  );
}

if (isTie && isOpposingTie(primaryType, secondaryType)) {
  // Use adaptive strategy - include elements of both
  return {
    ...profile,
    communicationStrategy: "adaptive",
    note: "Combination of opposing tendencies - use flexible approach"
  };
}
```

## Validation Rules

Before finalizing DISC profile:

1. **Question Completeness:** All 15 DISC questions answered
2. **Score Range Validation:** All scores between 0-10
3. **Sum Validation:** Total raw scores should be reasonable (typically 200-600 total across all types)
4. **Answer Consistency:** Flag if user selected all identical positions (potential invalid data)

## Integration with Report Generation

The calculated DISC profile is used to:

1. **Select Report Template Variant** (REQ-REPORT-CL-007)
   - Load appropriate language templates from `report-templates/client-report-sections.json`

2. **Customize Communication Style** (REQ-REPORT-C-003)
   - Apply communication strategies from `disc-communication-strategies.json`

3. **Adjust Detail Level**
   - D-type: Minimal detail, executive summary style
   - I-type: Visual-heavy, narrative style
   - S-type: Step-by-step, moderate detail
   - C-type: Maximum detail, comprehensive analysis

4. **Prioritize Action Items**
   - D-type: Quick wins first
   - I-type: Collaborative opportunities first
   - S-type: Low-risk, clear-path items first
   - C-type: Well-researched, systematic approaches first

## Testing Recommendations

### Test Case 1: Strong D Profile
- Expected: All D-scored options selected
- Result: Primary D (9.0+), Secondary I or C (3.0-5.0)
- Strategy: Direct & Results-Oriented

### Test Case 2: Balanced Profile
- Expected: Mix of responses, no clear preference
- Result: All scores 4.0-6.0, pattern: "balanced"
- Strategy: Moderate all approaches

### Test Case 3: D/I Combination
- Expected: Mix of D and I high-scoring options
- Result: D (7.5), I (6.8), dual profile
- Strategy: Blended D/I

### Test Case 4: Opposing Tie (D/S)
- Expected: Equal D and S scores
- Result: Adaptive strategy flag
- Strategy: Flexible approach

## Performance Considerations

- **Calculation Time:** O(n) where n = number of DISC questions (15)
- **Memory:** Store only aggregated scores, not individual responses (privacy)
- **Caching:** Cache calculated profile with user response set for report regeneration

## Privacy and Security

Per REQ-QUEST-003:

1. **DISC questions hidden from client** during assessment UI
2. **DISC scores not displayed** to client in any report
3. **Profile type not explicitly labeled** in client report (only consultant sees "D-type" label)
4. **Client sees only:** Communication style adapted to their preferences without explanation

## References

- Requirements: REQ-QUEST-002, REQ-QUEST-003, REQ-REPORT-CL-007
- Appendix B: DISC Integration Details
- Communication Strategies: `../disc-communication-strategies.json`
- Question Bank: `../disc-questions.json`
