# Financial RISE Report - Content Documentation

**Version:** 1.0
**Last Updated:** 2025-12-19
**Project:** Financial RISE Report (Readiness Insights for Sustainable Entrepreneurship)

## Overview

This directory contains all assessment content, algorithms, and report templates for the Financial RISE Report application. The content is designed to be consumed by the application's backend and frontend to generate personalized financial readiness assessments and reports.

## Directory Structure

```
content/
├── README.md                          # This file
├── questions.json                     # Main question bank (44 questions)
├── disc-questions.json                # DISC personality questions (15 questions)
├── special-questions.json             # Special assessment questions (7 questions)
├── disc-communication-strategies.json # DISC-based communication adaptations
├── algorithms/
│   ├── disc-algorithm.md             # DISC profile calculation logic
│   ├── phase-algorithm.md            # Financial phase determination logic
│   └── recommendation-engine.md      # Recommendation generation logic
└── report-templates/
    ├── consultant-report-sections.json  # Consultant-facing report content
    └── client-report-sections.json      # Client-facing report content
```

## Content Files

### 1. questions.json
**Purpose:** Main question bank covering 5 financial phases
**Total Questions:** 44
**Coverage:**
- Stabilize Phase: 8 questions (stab-001 through stab-008)
- Organize Phase: 8 questions (org-001 through org-008)
- Build Phase: 8 questions (build-001 through build-008)
- Grow Phase: 8 questions (grow-001 through grow-008)
- Systemic Phase: 8 questions (sys-001 through sys-008)
- General/Cross-cutting: 4 questions (general-001 through general-004)

**Question Types:**
- `multiple_choice`: Standard multiple choice with 4-5 options
- `scale`: 1-10 rating scale (used for comfort/confidence levels)

**Scoring:**
Each option includes scores for all 5 phases:
- `stabilize_score` (0-10)
- `organize_score` (0-10)
- `build_score` (0-10)
- `grow_score` (0-10)
- `systemic_score` (0-10)

Scale questions use `score_multiplier` objects to calculate phase scores.

### 2. disc-questions.json
**Purpose:** Personality assessment to customize report communication
**Total Questions:** 15 (exceeds REQ-QUEST-002 minimum of 12)
**Critical:** These questions are **hidden from clients** during assessment (REQ-QUEST-003)

**Scoring:**
Each option includes DISC type scores:
- `disc_d_score` (0-10) - Dominance
- `disc_i_score` (0-10) - Influence
- `disc_s_score` (0-10) - Steadiness
- `disc_c_score` (0-10) - Compliance

**Usage:**
Results are used to adapt report language, detail level, and communication style but are NEVER shown to clients as DISC labels.

### 3. special-questions.json
**Purpose:** Special assessment questions with specific requirements
**Questions:**
- `special-confidence-before`: Pre-assessment confidence (1-10 scale) - REQ-QUEST-009
- `special-confidence-after`: Post-report confidence (1-10 scale) - REQ-QUEST-009
- `special-entity-type`: Business entity type with conditional logic - REQ-QUEST-010
- `special-scorp-payroll`: S-Corp payroll question (conditional) - REQ-QUEST-010
- `special-primary-goal`: Client's primary 12-month goal
- `special-biggest-challenge`: Current biggest financial challenge
- `special-consultant-relationship`: Current professional relationship status

**Conditional Logic:**
The S-Corp payroll question (`special-scorp-payroll`) only displays if entity type is "S-Corp" selected.

### 4. disc-communication-strategies.json
**Purpose:** Define how to adapt report communication for each DISC type
**DISC Types:**
- **D (Dominance):** Direct, results-oriented, brief
- **I (Influence):** Enthusiastic, collaborative, visual
- **S (Steadiness):** Supportive, methodical, reassuring
- **C (Compliance):** Analytical, detailed, precise
- **Balanced:** Moderate approach when no dominant type

**Includes:**
- Communication style guidelines
- Report customization rules
- Language examples and phrases to avoid
- Visual preferences
- Sample opening/closing phrases
- Combination profile strategies (DI, DC, IS, SC)

### 5. Algorithm Specifications

#### algorithms/disc-algorithm.md
**Purpose:** Calculate DISC personality profile from question responses
**Process:**
1. Aggregate scores across all 15 DISC questions
2. Calculate average scores for each type
3. Determine primary type (highest score)
4. Determine secondary type (second highest)
5. Handle ties and edge cases
6. Calculate confidence level
7. Map to communication strategy

**Output:** DISC profile object with primary type, scores, pattern classification

#### algorithms/phase-algorithm.md
**Purpose:** Determine client's financial readiness phase(s)
**Process:**
1. Aggregate scores from all questions across 5 phases
2. Calculate percentage scores (0-100%)
3. Determine primary phase (highest percentage)
4. Identify secondary phases (transition states) - REQ-PHASE-004
5. Detect transition patterns
6. Validate against phase-specific criteria - REQ-PHASE-005
7. Handle edge cases (all low, gaps, etc.)

**Output:** Phase summary with primary, secondary, scores, and transition pattern

#### algorithms/recommendation-engine.md
**Purpose:** Generate personalized action items based on assessment results
**Process:**
1. Analyze phase scores and identify gaps
2. Map gaps to recommendation library
3. Prioritize by impact, effort, phase alignment, and DISC fit
4. Adapt language for DISC profile
5. Generate checklist items - REQ-CHECKLIST-001

**Output:** Categorized recommendations (quick wins, strategic priorities, long-term goals) with DISC-adapted language

**Recommendation Library:** Contains 20+ pre-defined recommendations mapped to common gap patterns

### 6. Report Templates

#### report-templates/consultant-report-sections.json
**Purpose:** Define structure and content for consultant-facing reports
**Audience:** Financial consultants, fractional CFOs, advisors
**Key Features:**
- DISC profile explicitly shown with coaching
- Detailed scoring and question-level responses
- Communication do's and don'ts
- Engagement roadmap and pricing suggestions
- Red flags and urgent attention items
- Meeting preparation guidance

**Major Sections:**
1. Executive Summary (with confidential DISC profile)
2. Detailed Phase Analysis (all 5 phases)
3. DISC Communication Coaching (confidential)
4. Recommendations & Action Plan
5. Detailed Question Responses (appendix)
6. Next Steps & Engagement
7. Appendices (methodology, resources)

#### report-templates/client-report-sections.json
**Purpose:** Define structure and content for client-facing reports
**Audience:** Business owners receiving the assessment
**Key Features:**
- DISC profile **hidden** - only used to adapt communication
- Encouraging, non-judgmental language (REQ-REPORT-CL-002)
- Benefit-focused recommendations
- DISC-adapted content variants for every section
- Actionable items with clear steps
- Visual phase snapshot

**Major Sections:**
1. Your Financial Journey (executive summary)
2. Understanding Your Scores (phase visualization)
3. Your Action Plan (recommendations by category)
4. Next Steps (with scheduler integration - REQ-SCHEDULER-001)
5. Resources & Additional Information

**DISC Adaptation:**
Every section includes variants for D, I, S, and C types with different:
- Titles
- Tone and language
- Length and detail level
- Structure and format
- Visual elements

## Key Requirements Fulfilled

### Assessment Questions
- **REQ-QUEST-002:** 15 DISC questions (exceeds minimum 12)
- **REQ-QUEST-003:** DISC questions hidden from client
- **REQ-QUEST-009:** Before/after confidence assessment
- **REQ-QUEST-010:** Entity type with S-Corp conditional

### Phase Determination
- **REQ-PHASE-002:** Weighted scoring methodology implemented
- **REQ-PHASE-004:** Support for multiple active phases
- **REQ-PHASE-005:** Phase-specific criteria defined

### Reports
- **REQ-REPORT-CL-002:** Non-judgmental, encouraging language
- **REQ-REPORT-CL-003:** Actionable recommendations with clear steps
- **REQ-REPORT-CL-004:** Prioritized by impact and feasibility
- **REQ-REPORT-CL-007:** DISC-adapted language and detail levels
- **REQ-REPORT-C-003:** Communication strategies per DISC type
- **REQ-CHECKLIST-001:** Checklist generation from recommendations

### UI/Branding
- **REQ-UI-002:** Brand colors specified (Purple #4B006E, Gold #D4AF37)
- **REQ-UI-003:** Calibri font, 14px minimum specified

### Integration
- **REQ-SCHEDULER-001:** Scheduler integration points defined

## Language Guidelines

### Non-Judgmental Language (REQ-REPORT-CL-002)

**NEVER USE:**
- "You failed to..."
- "You're behind..."
- "This is a problem..."
- "You should have..."
- "You neglected..."

**ALWAYS USE:**
- "Opportunity to..."
- "Room to strengthen..."
- "Consider implementing..."
- "Next step is to..."
- "Enhance this area by..."

### Tone by DISC Type

- **D:** Confident, direct, results-focused, energizing
- **I:** Enthusiastic, positive, collaborative, inspiring
- **S:** Supportive, reassuring, patient, encouraging
- **C:** Professional, precise, thorough, respectful

## Data Flow

```
User completes assessment
    ↓
Questions (questions.json + disc-questions.json + special-questions.json)
    ↓
Responses stored in database
    ↓
[DISC Algorithm] → DISC Profile (hidden from client)
    ↓
[Phase Algorithm] → Phase Determination
    ↓
[Recommendation Engine] → Personalized Action Items
    ↓
[Report Generator]
    ├→ Consultant Report (with DISC coaching)
    └→ Client Report (DISC-adapted, profile hidden)
```

## Implementation Notes

### For Backend Developers

1. **Question Delivery:** Serve questions from JSON files via API endpoints
2. **Conditional Logic:** Implement conditional display for `special-scorp-payroll`
3. **Scoring Engine:** Implement algorithms as defined in `algorithms/` directory
4. **Report Generation:** Use templates as base, populate with calculated data
5. **DISC Privacy:** Never expose DISC type labels in client-facing APIs

### For Frontend Developers

1. **Question Flow:** Display questions in order, handle conditional logic
2. **DISC Hiding:** Never show DISC questions as "personality questions"
3. **Progress Tracking:** Show progress through assessment (66 total questions)
4. **Report Display:** Render appropriate template variant based on DISC profile
5. **Scheduler Integration:** Implement external scheduler embedding (Calendly, etc.)

### For Content/SME Contributors

1. **Question Updates:** Maintain scoring consistency when editing questions
2. **Recommendation Library:** Add new recommendations following existing pattern
3. **Language Review:** Ensure all language is non-judgmental and encouraging
4. **DISC Variants:** Provide content variants for all DISC types when adding sections

## Testing Recommendations

### Content Validation Tests

1. **Question Completeness:** Verify all 66 questions have required fields
2. **Scoring Validity:** Ensure all scores are 0-10 range
3. **DISC Balance:** Verify DISC questions test all 4 types
4. **Conditional Logic:** Test S-Corp conditional display
5. **Language Audit:** Scan for judgmental language in client templates

### Algorithm Tests

1. **DISC Edge Cases:** Test ties, balanced profiles, opposing types
2. **Phase Edge Cases:** Test all low scores, gaps, high grow with low build
3. **Recommendation Prioritization:** Verify scoring algorithm produces sensible order

### Report Generation Tests

1. **DISC Adaptation:** Generate reports for each DISC type, verify variants applied
2. **Phase Variations:** Test reports for each primary phase
3. **Content Length:** Verify D-type reports are briefer, C-type more detailed
4. **Privacy:** Ensure DISC labels never appear in client reports

## Version History

- **v1.0 (2025-12-19):** Initial content creation
  - 44 main questions covering 5 phases
  - 15 DISC questions with 4-type scoring
  - 7 special questions including confidence and entity type
  - Complete algorithm specifications
  - Full report templates with DISC variants
  - Communication strategies and language guidelines

## Future Enhancements

### Potential Content Additions

1. **Industry-Specific Questions:** Variants for retail, professional services, manufacturing
2. **Advanced Recommendations:** ML-driven recommendation matching
3. **Progress Tracking:** Questions to measure improvement in follow-up assessments
4. **Team Assessments:** Multi-user assessments for team financial literacy
5. **Benchmarking:** Industry and size-based benchmark comparisons

### Localization Considerations

- Current content is US English
- All dollar amounts in USD
- Tax and compliance questions assume US jurisdiction
- Future: Support for international variants

## Support and Maintenance

### Content Ownership

- **Questions:** Maintained by SMEs (financial consultants, fractional CFOs)
- **Algorithms:** Maintained by engineering team with SME review
- **Report Templates:** Joint maintenance (SMEs for content, UX for formatting)
- **DISC Strategies:** Maintained by SMEs with DISC certification

### Update Process

1. Propose content changes via issue/PR
2. SME review for accuracy and tone
3. Update version number in metadata
4. Test with sample data before deployment
5. Document changes in this README

## Contact

For questions about content:
- **Financial Content:** Contact SME team
- **DISC Framework:** Contact certified DISC consultant on team
- **Technical Implementation:** Contact engineering team
- **Language/Tone:** Contact UX writing team

## License and Usage

This content is proprietary to the Financial RISE Report project. Do not distribute or use outside of this application without authorization.

---

**Note:** All content follows requirements specified in `plans/requirements.md` version 1.1. Always refer to the main requirements document for authoritative specifications.
