# Financial RISE Report - Style Guide

**Version:** 1.0
**Last Updated:** 2025-12-22
**Purpose:** Comprehensive style guide for generating Financial RISE consultant and client reports

---

## Table of Contents

1. [Brand Identity](#brand-identity)
2. [Typography](#typography)
3. [Color Palette](#color-palette)
4. [Report Structure](#report-structure)
5. [DISC Adaptation Guidelines](#disc-adaptation-guidelines)
6. [Content Guidelines](#content-guidelines)
7. [Visual Assets](#visual-assets)
8. [Accessibility Requirements](#accessibility-requirements)
9. [Template Variables](#template-variables)
10. [PDF Generation Specifications](#pdf-generation-specifications)

---

## Brand Identity

### Logo and Tagline

**Primary Logo Text:** Financial RISE Report
**Tagline:** Readiness Insights for Sustainable Entrepreneurship

**Usage:**
- Logo appears in header of every page
- Color: Primary Purple (#4B006E)
- Tagline in Gold (#D4AF37), italic style

### Brand Voice

**Consultant Report:**
- Professional, analytical, data-driven
- Confidential and strategic
- Uses industry terminology

**Client Report:**
- Encouraging, non-judgmental, confidence-building
- Accessible language (avoid jargon)
- Solution-focused and actionable
- DISC-adapted tone (see DISC Adaptation Guidelines)

---

## Typography

### Font Family

**Primary Font:** Calibri
**Fallback Stack:** Calibri, 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif

### Font Sizes

| Element | Size | Weight | Usage |
|---------|------|--------|-------|
| H1 (Report Title) | 32-36px | Bold | Main report title |
| H2 (Section Title) | 24-26px | Bold | Major sections |
| H3 (Subsection) | 18-22px | Bold | Subsections |
| H4 (Item Title) | 16-18px | Bold | List items, cards |
| Body Text | 14-16px | Normal | Paragraphs, descriptions |
| Small Text | 12px | Normal | Footer, metadata |

### Line Height

- **Body text:** 1.6-1.8 (improved readability)
- **Headings:** 1.2-1.4 (tighter spacing)

### Minimum Font Size

**REQ-UI-003:** All body text must be minimum 14px for accessibility.

---

## Color Palette

### Primary Colors

| Color Name | Hex Code | Usage |
|------------|----------|-------|
| Primary Purple | #4B006E | Headers, titles, brand elements, primary actions |
| Gold | #D4AF37 | Accents, highlights, secondary elements |
| Black | #000000 | Body text |
| White | #FFFFFF | Backgrounds, negative space |

### Secondary Colors

| Color Name | Hex Code | Usage |
|------------|----------|-------|
| Light Gray | #F5F5F5 | Background boxes, subtle sections |
| Medium Gray | #666666 | Secondary text, labels |
| Dark Gray | #333333 | Headings, important text |
| Success Green | #2E7D32 | Completed phases, positive indicators |
| Info Blue | #1976D2 | Informational elements (use sparingly) |

### Gradient

**Primary Purple Gradient:**
- Start: #4B006E
- End: #6B2390
- Direction: 135deg (diagonal)
- Usage: DISC profile boxes, phase indicators, call-to-action sections

### Color Accessibility

**WCAG 2.1 Level AA Compliance:**
- Purple (#4B006E) on White: 11.36:1 ✓
- Gold (#D4AF37) on Purple: 4.52:1 ✓
- Black on White: 21:1 ✓
- Medium Gray (#666666) on White: 5.74:1 ✓

**Never use:**
- Gold text on white background (insufficient contrast)
- Light gray text on colored backgrounds

---

## Report Structure

### Consultant Report

**Page 1: Executive Summary**
1. Header with logo and tagline
2. Report title: "Consultant Report"
3. Client information box
4. Executive summary text
5. DISC profile (confidential)
6. Key findings (5 bullet points)
7. Phase assessment results (all 5 phases with scores)
8. Top 3 priority recommendations
9. Footer with page number

**Page 2+: Detailed Analysis** (Future enhancement)
- Full question-by-question breakdown
- Detailed DISC analysis
- Phase-specific insights
- Communication strategy recommendations

### Client Report

**Page 1: Welcome and Journey**
1. Header with logo and tagline
2. Welcome message with client name
3. Confidence growth visualization (before/after)
4. Phase journey diagram (visual)
5. Current phase highlight box
6. Footer

**Page 2: Quick Wins**
1. Header
2. Section title: "Your Quick Wins"
3. 5 quick win cards with:
   - Icon/emoji
   - Title
   - Description
   - "Why this matters" explanation
4. Footer

**Page 3: Personalized Roadmap**
1. Header
2. Section title: "Your Personalized Roadmap"
3. DISC-adapted intro text
4. 3 roadmap items with:
   - Number badge
   - Title
   - Description
   - Key actions (3 per item)
5. Footer

**Page 4: Next Steps**
1. Header
2. Next steps section (purple gradient box)
3. Encouragement message (DISC-adapted)
4. Additional resources section
5. Phase descriptions reference
6. Footer with thank you

---

## DISC Adaptation Guidelines

### D (Dominance) Type

**Tone:** Brief, results-oriented, ROI-focused
**Language:** Direct, action verbs, competitive
**Structure:** Executive summaries, bullet points, bottom-line first

**Key Phrases:**
- "Bottom line:"
- "Quick win:"
- "Execute on:"
- "Competitive advantage:"
- "Maximum ROI:"

**Avoid:**
- Lengthy explanations
- Emotional appeals
- Unnecessary details

### I (Influence) Type

**Tone:** Collaborative, enthusiastic, big-picture
**Language:** Positive, team-oriented, visionary
**Structure:** Story-driven, visual, relationship-focused

**Key Phrases:**
- "Imagine the possibilities!"
- "Together, we'll..."
- "Exciting opportunity:"
- "Let's collaborate:"
- "Your team will love:"

**Avoid:**
- Overly technical jargon
- Pessimistic framing
- Isolation language

### S (Steadiness) Type

**Tone:** Reassuring, step-by-step, patient
**Language:** Gentle, supportive, clear process
**Structure:** Sequential steps, manageable chunks, no pressure

**Key Phrases:**
- "One step at a time"
- "You're in good hands"
- "At your pace"
- "No rush or pressure"
- "We'll work through this together"

**Avoid:**
- Aggressive timelines
- High-pressure language
- Sudden changes

### C (Compliance) Type

**Tone:** Detailed, analytical, data-driven
**Language:** Precise, technical, evidence-based
**Structure:** Systematic, thorough, documented

**Key Phrases:**
- "Based on analysis:"
- "Data shows:"
- "Systematic approach:"
- "Documented methodology:"
- "Quantitative evidence:"

**Avoid:**
- Vague statements
- Emotional appeals
- Incomplete information

---

## Content Guidelines

### Non-Judgmental Language (REQ-REPORT-CL-002)

**DO:**
- "You're currently in the Stabilize phase" ✓
- "This is an opportunity to strengthen..." ✓
- "Your next step is to..." ✓

**DON'T:**
- "You're behind where you should be" ✗
- "This is a problem that needs fixing" ✗
- "You failed to implement..." ✗

### Encouraging Tone

**Principle:** Every statement should build confidence, not diminish it.

**Examples:**
- Gap identified → "Opportunity for improvement"
- Missing system → "Next system to implement"
- Low score → "Area with high growth potential"

### Action-Oriented

**Format:** Every recommendation should include:
1. **What:** Clear action item
2. **Why:** Benefit/impact
3. **How:** Specific steps

**Example:**
> **What:** Set up a dedicated business bank account
> **Why:** This separates personal and business finances, making tax filing easier and providing clearer insights into business performance
> **How:** Choose a bank, gather your EIN and business documents, schedule an appointment

---

## Visual Assets

### Phase Diagram

**File:** `assets/phase-diagram.svg`
**Purpose:** Show client's position in the 5-phase journey
**States:**
- Inactive (gray border, white fill)
- Current (purple gradient fill, gold border, glow)
- Completed (green fill, green border, checkmark)

### Icons

**Available Icons:**
- `icon-checkmark.svg` - Completed items, achievements
- `icon-lightbulb.svg` - Quick wins, ideas
- `icon-target.svg` - Goals, objectives
- `icon-chart-up.svg` - Growth, progress
- `icon-shield.svg` - Stabilize phase
- `icon-gear.svg` - Organize phase
- `icon-building.svg` - Build phase

**Usage:**
- Size: 24px-48px inline, 80px-100px standalone
- Color: Match brand palette
- Always include alt text for accessibility

### Progress Indicators

**File:** `assets/progress-bar.svg`
**Purpose:** Visual representation of phase scores
**Style:** Gradient fill (purple to lighter purple), rounded ends

---

## Accessibility Requirements

### WCAG 2.1 Level AA Compliance (REQ-ACCESS-001)

**Contrast Ratios:**
- Normal text (14px+): Minimum 4.5:1
- Large text (18px+ or 14px+ bold): Minimum 3:1
- All brand colors meet or exceed these requirements

**Semantic HTML:**
- Use proper heading hierarchy (H1 → H2 → H3)
- Use `<section>`, `<article>`, `<aside>` appropriately
- Use `<ul>`/`<ol>` for lists

**Alternative Text:**
- All images must have descriptive alt text
- Decorative images: `alt=""`
- Informational images: Describe purpose and content

**Print Accessibility:**
```css
@media print {
    body {
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
    }
}
```

---

## Template Variables

### Standard Variables (All Reports)

| Variable | Format | Example |
|----------|--------|---------|
| `{{clientName}}` | String | "Jane Smith" |
| `{{businessName}}` | String | "Smith Consulting LLC" |
| `{{assessmentDate}}` | Date | "December 22, 2025" |
| `{{generatedDate}}` | DateTime | "December 22, 2025 at 3:45 PM" |
| `{{consultantName}}` | String | "John Advisor, CFP" |
| `{{assessmentId}}` | String | "ASM-2025-001234" |

### DISC Variables

| Variable | Format | Example |
|----------|--------|---------|
| `{{discType}}` | Char | "D" |
| `{{discTypeFullName}}` | String | "Dominance" |
| `{{discCommunicationStrategy}}` | Text | "Be brief and results-focused..." |

### Phase Variables

| Variable | Format | Example |
|----------|--------|---------|
| `{{primaryPhase}}` | String | "Stabilize" |
| `{{primaryPhaseName}}` | String | "Stabilize" |
| `{{stabilizeScore}}` | Integer | "45" |
| `{{organizeScore}}` | Integer | "62" |
| `{{buildScore}}` | Integer | "38" |
| `{{growScore}}` | Integer | "25" |
| `{{systemicScore}}` | Integer | "51" |

### Confidence Variables

| Variable | Format | Example |
|----------|--------|---------|
| `{{beforeConfidence}}` | Integer (1-10) | "6" |
| `{{afterConfidence}}` | Integer (1-10) | "8" |
| `{{confidenceMessage}}` | Text | DISC-adapted message |

### Content Variables

| Variable | Format | Example |
|----------|--------|---------|
| `{{executiveSummaryText}}` | Text (200-300 words) | - |
| `{{currentPhaseDescription}}` | Text (100-150 words) | - |
| `{{roadmapIntro}}` | Text (50-100 words) | DISC-adapted |
| `{{encouragementMessage}}` | Text (100-150 words) | DISC-adapted |
| `{{nextStepsDescription}}` | Text (100-150 words) | DISC-adapted |
| `{{callToAction}}` | String | DISC-adapted |

### Quick Wins (5 required)

Each quick win includes:
- `{{quickWin1Title}}` through `{{quickWin5Title}}`
- `{{quickWin1Description}}` through `{{quickWin5Description}}`
- `{{quickWin1Why}}` through `{{quickWin5Why}}`

### Roadmap Steps (3 required)

Each roadmap step includes:
- `{{roadmapStep1Title}}` through `{{roadmapStep3Title}}`
- `{{roadmapStep1Description}}` through `{{roadmapStep3Description}}`
- `{{roadmapStep1Action1}}` through `{{roadmapStep3Action3}}` (3 actions per step)

### Key Findings (5 required)

- `{{keyFinding1}}` through `{{keyFinding5}}`

### Recommendations (3 required)

Each recommendation includes:
- `{{recommendation1Title}}` through `{{recommendation3Title}}`
- `{{recommendation1Description}}` through `{{recommendation3Description}}`

---

## PDF Generation Specifications

### Page Setup

**Dimensions:** 8.5" × 11" (US Letter)
**Orientation:** Portrait
**Margins:** 0.75" (top, right, bottom, left)
**Bleed:** None required

### Print Styles

```css
@media print {
    .page {
        width: 8.5in;
        min-height: 11in;
        padding: 0.75in;
        margin: 0;
        page-break-after: always;
    }

    .page:last-child {
        page-break-after: auto;
    }
}
```

### Performance Requirements

**REQ-PERF-002:** Report generation must complete in <5 seconds

**Optimization techniques:**
- Use embedded CSS (no external stylesheets)
- Optimize SVG file sizes
- Limit images to essential visuals only
- Use system fonts (Calibri)

### Puppeteer Configuration

```javascript
{
  format: 'Letter',
  printBackground: true,
  margin: {
    top: '0.75in',
    right: '0.75in',
    bottom: '0.75in',
    left: '0.75in'
  }
}
```

---

## Testing Checklist

### Visual Testing

- [ ] All brand colors render correctly
- [ ] Font sizes meet minimum requirements (14px body text)
- [ ] Gradients display properly
- [ ] SVG icons load and scale correctly
- [ ] Page breaks occur in appropriate places
- [ ] Headers and footers appear on all pages

### Content Testing

- [ ] All template variables populate correctly
- [ ] DISC adaptation works for all 4 types
- [ ] Phase descriptions match assessment results
- [ ] No placeholder text remains (e.g., {{variable}})
- [ ] Grammar and spelling are correct
- [ ] Non-judgmental language throughout

### Accessibility Testing

- [ ] Contrast ratios meet WCAG 2.1 Level AA
- [ ] Heading hierarchy is logical
- [ ] All images have alt text
- [ ] Document is navigable without mouse
- [ ] Print preserves colors and backgrounds

### Performance Testing

- [ ] PDF generation completes in <5 seconds
- [ ] File size is reasonable (<2MB per report)
- [ ] No memory leaks in generation process

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-12-22 | Initial style guide creation |

---

## References

- **Requirements Document:** `plans/requirements.md`
- **Design System:** `financial-rise-frontend/docs/design-system.md`
- **DISC Content Variations:** `src/templates/disc-content.json`
- **Template Files:**
  - `src/templates/consultant-report.html`
  - `src/templates/client-report.html`
  - `src/templates/assets/*.svg`

---

**Document Maintainer:** Implementation Team
**Review Cycle:** Quarterly or after major template changes
