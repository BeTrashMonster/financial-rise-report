# Financial RISE Assessment - Scoring Framework

**Version:** 1.0
**Date:** 2026-01-05
**Purpose:** Guidelines for maintaining scoring integrity when adjusting questions

---

## 📊 Scoring System Overview

### Two Parallel Scoring Systems

**1. Phase Scoring** - Determines financial readiness phase
**2. DISC Scoring** - Determines personality type for report customization

These are **completely independent** - phase scores don't affect DISC, DISC doesn't affect phase.

---

## 🎯 PHASE SCORING SYSTEM

### Score Ranges by Question Type

#### **Single Choice Questions (Most Common)**

Each option has a `phase_scores` object with 0-5 points per phase:

```json
{
  "value": "option_id",
  "label": "Display text",
  "phase_scores": {
    "stabilize": 5,
    "organize": 0,
    "build": 0,
    "grow": 0,
    "systemic": 0
  }
}
```

**Scoring Scale (0-5 points):**
- **5 points** = Excellent/Best practice/Optimal state
- **4 points** = Good/Above average
- **3 points** = Adequate/Acceptable
- **2 points** = Below average/Needs improvement
- **1 point** = Poor/Barely functional
- **0 points** = Non-existent/Critical gap

**Key Principle:** Each question typically scores ONE primary phase (the phase it's testing), but can award secondary points to other phases.

**Examples:**

```sql
-- STAB-001: Financial statement review
-- Primary phase: Stabilize
('STAB-001', 'How often do you review financial statements?', 'single_choice',
 '{"options": [
   {"value": "weekly", "label": "Weekly", "phase_scores": {"stabilize": 5}},
   {"value": "monthly", "label": "Monthly", "phase_scores": {"stabilize": 4}},
   {"value": "quarterly", "label": "Quarterly", "phase_scores": {"stabilize": 2}},
   {"value": "annually", "label": "Annually or less", "phase_scores": {"stabilize": 0}},
   {"value": "never", "label": "I don't review them", "phase_scores": {"stabilize": 0}}
 ]}')

-- STAB-012: Emergency fund
-- Primary phase: Stabilize, Secondary: Grow
('STAB-012', 'Does your business have an emergency fund?', 'single_choice',
 '{"options": [
   {"value": "3_months_plus", "label": "Yes, 3+ months", "phase_scores": {"stabilize": 5, "grow": 3}},
   {"value": "1_3_months", "label": "1-3 months", "phase_scores": {"stabilize": 4, "grow": 2}},
   {"value": "under_1_month", "label": "Less than 1 month", "phase_scores": {"stabilize": 2, "grow": 1}},
   {"value": "no", "label": "No emergency fund", "phase_scores": {"stabilize": 0, "grow": 0}}
 ]}')
```

#### **Rating Scale Questions**

Use `phase_scoring` with value `"linear"` to distribute scores across the 1-5 range:

```json
{
  "min": 1,
  "max": 5,
  "min_label": "Completely disorganized",
  "max_label": "Highly organized",
  "phase_scoring": {"stabilize": "linear"}
}
```

**Linear scoring calculation:**
- Rating 1 = 0 points
- Rating 2 = 1.25 points
- Rating 3 = 2.5 points
- Rating 4 = 3.75 points
- Rating 5 = 5 points

**Formula:** `(rating - 1) / (max - min) × max_points`

**Examples:**
- STAB-011: Financial records organization (Stabilize)
- ORG-010: Financial workflow clarity (Organize)
- BUILD-008: Expense categorization consistency (Build)
- SYS-001: Comfort reading financial statements (Systemic)
- SYS-008: Overall financial awareness (Systemic)

#### **Multiple Choice Questions (Select All)**

Each selected option adds points:

```json
{
  "options": [
    {"value": "bill_pay", "label": "Bill payment", "phase_scores": {"build": 1}},
    {"value": "invoicing", "label": "Invoicing", "phase_scores": {"build": 1}},
    {"value": "expense_tracking", "label": "Expense tracking", "phase_scores": {"build": 1}},
    {"value": "none", "label": "None - all manual", "phase_scores": {"build": 0}}
  ]
}
```

**Scoring:** Cumulative - each selection adds its points

**Examples:**
- BUILD-010: Automated financial processes (max 6 points if all 6 selected)
- ORG-007: Payment processing methods (informational only, no scoring)
- SYS-006: Financial education methods (informational only, no scoring)

**Note:** Not all multiple choice questions have scoring. Some are purely informational.

---

## 📈 Phase Score Targets & Ranges

### Maximum Possible Scores by Phase

Based on current question bank:

| Phase | Questions | Max Points | Notes |
|-------|-----------|------------|-------|
| **Stabilize** | 12 primary | ~60 points | Some questions score multiple phases |
| **Organize** | 10 primary | ~50 points | Includes conditional ORG-002 |
| **Build** | 10 primary | ~55 points | BUILD-010 can add up to 6 points |
| **Grow** | 10 primary | ~50 points | Several overlap with Systemic |
| **Systemic** | 8 primary | ~40 points | Several overlap with other phases |

### Phase Determination Algorithm (Conceptual)

**Step 1: Calculate percentage scores**
```
Phase % = (Points Earned / Max Possible Points) × 100
```

**Step 2: Determine primary phase**
- Highest % score = Primary phase
- Can have multiple phases if scores are close (within 10-15%)

**Step 3: Interpret results**

| Score Range | Interpretation |
|-------------|----------------|
| **80-100%** | Excellent - Exceeding standards for this phase |
| **60-79%** | Good - Meeting most standards for this phase |
| **40-59%** | Fair - Making progress, needs work |
| **20-39%** | Poor - Significant gaps in this area |
| **0-19%** | Critical - Urgent attention needed |

**Example:**
```
Stabilize: 45/60 = 75% (Good)
Organize: 30/50 = 60% (Good)
Build: 15/55 = 27% (Poor)
Grow: 8/50 = 16% (Critical)
Systemic: 12/40 = 30% (Poor)

Primary Phase: STABILIZE (highest score)
Secondary: ORGANIZE (close to Stabilize)
Next Focus: BUILD (needs work before Grow)
```

---

## 🎨 DISC SCORING SYSTEM

### DISC Score Structure

Each DISC question awards **2 points** to exactly **ONE trait**:

```json
{
  "value": "option_id",
  "label": "Display text",
  "disc_scores": {
    "D": 2,  // Dominance
    "I": 0,  // Influence
    "S": 0,  // Steadiness
    "C": 0   // Compliance
  }
}
```

### DISC Scoring Calculation

**Total possible per trait:**
- 12 questions × 2 points = **24 max points** per trait

**Percentage calculation:**
```
D% = (D points / 24) × 100
I% = (I points / 24) × 100
S% = (S points / 24) × 100
C% = (C points / 24) × 100
```

**Primary DISC type** = Highest percentage

**Example:**
```
D: 18/24 = 75% (High Dominance)
I: 8/24 = 33%
S: 4/24 = 17%
C: 14/24 = 58% (Moderate Compliance)

Primary: D (Dominance)
Secondary: C (Compliance)
Profile: DC (Dominant-Compliant)
```

### DISC Profile Interpretation

| Score | Interpretation |
|-------|----------------|
| **70-100%** | High - Strong preference for this trait |
| **50-69%** | Moderate - Noticeable preference |
| **30-49%** | Balanced - Adaptable |
| **0-29%** | Low - Minimal preference |

**Pure Profiles:** One trait 70%+, others <40%
**Blended Profiles:** Two traits 50%+
**Balanced:** All traits 40-60%

---

## ✅ Scoring Integrity Guidelines

### When Adjusting Questions

**1. Maintain Score Distribution**

If you change an option's score, maintain the overall range:

❌ **Bad:** All options score 4-5 (no differentiation)
```json
{"value": "a", "label": "Option A", "phase_scores": {"stabilize": 5}},
{"value": "b", "label": "Option B", "phase_scores": {"stabilize": 5}},
{"value": "c", "label": "Option C", "phase_scores": {"stabilize": 4}}
```

✅ **Good:** Clear progression from 0-5
```json
{"value": "excellent", "label": "Excellent", "phase_scores": {"stabilize": 5}},
{"value": "good", "label": "Good", "phase_scores": {"stabilize": 3}},
{"value": "poor", "label": "Poor", "phase_scores": {"stabilize": 1}},
{"value": "none", "label": "None", "phase_scores": {"stabilize": 0}}
```

**2. Preserve Maximum Scores**

If you add/remove questions, document the new max scores:

```
Original: Stabilize max = 60 points
After removing STAB-011 (5 pts): Stabilize max = 55 points
After adding new question (5 pts): Stabilize max = 60 points
```

**3. Use Consistent Scoring Logic**

Similar questions should use similar scoring:

- "Weekly" review = 5 points across all questions
- "Monthly" review = 4 points across all questions
- "Never" = 0 points across all questions

**4. Award Primary Phase Points**

Each question should primarily score ONE phase:

✅ **Good:**
```json
{"value": "yes", "label": "Yes", "phase_scores": {"build": 5}}
```

⚠️ **Use Sparingly:**
```json
{"value": "yes", "label": "Yes", "phase_scores": {"build": 5, "grow": 2, "systemic": 3}}
```

**Exception:** Questions that genuinely span phases (emergency fund affects both Stabilize and Grow)

**5. DISC Questions: Always 2 Points**

Never change DISC scoring:

✅ **Correct:**
```json
{"value": "direct", "label": "Direct", "disc_scores": {"D": 2}}
```

❌ **Wrong:**
```json
{"value": "direct", "label": "Direct", "disc_scores": {"D": 3}}
```

**6. Rating Scales: Keep 1-5 Range**

All rating questions use 1-5 scale for consistency.

---

## 🔧 Common Adjustments

### Changing Question Wording

**Safe:** Change wording without changing meaning
```
Before: "How often do you review your financial statements?"
After: "How frequently do you look at your Profit & Loss and Balance Sheet?"
```
✅ No scoring change needed

### Changing Option Labels

**Safe:** Clarify labels without changing meaning
```
Before: "Yes, automated"
After: "Yes, using automated software"
```
✅ No scoring change needed

### Adding New Options

**Requires scoring adjustment:**
```json
// Original
{"value": "yes", "label": "Yes", "phase_scores": {"organize": 5}},
{"value": "no", "label": "No", "phase_scores": {"organize": 0}}

// After adding "Partial"
{"value": "yes", "label": "Yes", "phase_scores": {"organize": 5}},
{"value": "partial", "label": "Partial", "phase_scores": {"organize": 3}},  // NEW
{"value": "no", "label": "No", "phase_scores": {"organize": 0}}
```

### Removing Options

**May require rescoring remaining options:**
```json
// Original (4 options: 5, 3, 1, 0)
{"value": "excellent", "phase_scores": {"build": 5}},
{"value": "good", "phase_scores": {"build": 3}},
{"value": "poor", "phase_scores": {"build": 1}},
{"value": "none", "phase_scores": {"build": 0}}

// After removing "poor" - rescore to maintain spread
{"value": "excellent", "phase_scores": {"build": 5}},
{"value": "good", "phase_scores": {"build": 3}},  // Could increase to 4
{"value": "none", "phase_scores": {"build": 0}}
```

### Adding New Questions

**Impact on max scores:**
- Adding a 5-point Stabilize question increases Stabilize max from 60 → 65
- Update phase determination algorithm to use new max

### Removing Questions

**Impact on max scores:**
- Removing a 5-point Build question decreases Build max from 55 → 50
- Update phase determination algorithm to use new max

---

## 📋 Pre-Change Checklist

Before modifying any question:

- [ ] Understand current scoring (0-5 scale, DISC = 2 points)
- [ ] Identify which phase(s) the question scores
- [ ] Check if change affects max possible score
- [ ] Ensure new scores maintain 0-5 distribution
- [ ] Verify DISC questions stay at 2 points per option
- [ ] Test scoring logic with example responses
- [ ] Document changes to max scores

---

## 💾 Tracking Score Changes

If you modify scoring, document it:

```markdown
## Scoring Changes Log

**2026-01-05 - Question Adjustments**
- STAB-001: Changed "Weekly" from 5 → 4 points (too high)
- BUILD-002: Added "Quarterly" option (2 points)
- Removed GROW-011 (was 5 points max)

**New Max Scores:**
- Stabilize: 60 → 59 points
- Build: 55 points (no change)
- Grow: 50 → 45 points

**Rationale:** Weekly financial review is good but not "excellent" (5 pts)
```

---

## 🎯 Summary

**Phase Scoring:**
- Single choice: 0-5 points per option
- Rating scale: Linear 0-5 based on 1-5 rating
- Multiple choice: Cumulative (each adds points)
- Each question primarily scores ONE phase
- Max scores: ~40-60 points per phase

**DISC Scoring:**
- Always 2 points per option
- Exactly ONE trait per option
- 12 questions × 2 = 24 max per trait
- Never change DISC point values

**Golden Rules:**
1. Maintain 0-5 scoring range for phase questions
2. Keep DISC at 2 points per option
3. Preserve score distribution (avoid clustering at 4-5)
4. Update max scores if adding/removing questions
5. Document all scoring changes
