# Recommendation Engine Algorithm

**Version:** 1.0
**Last Updated:** 2025-12-19
**Requirement Reference:** REQ-REPORT-CL-003, REQ-REPORT-CL-004, REQ-REPORT-C-004, REQ-CHECKLIST-001

## Overview

The Recommendation Engine generates personalized action items and quick wins based on:
1. **Phase Determination** results (primary and secondary phases)
2. **DISC Profile** (communication style adaptation)
3. **Specific Question Responses** (gap identification)
4. **Client Goals** (from special questions)

## Core Principles

1. **Non-judgmental Language** (REQ-REPORT-CL-002) - Use encouraging, opportunity-focused language
2. **Actionable Items** (REQ-REPORT-CL-003) - Every recommendation must be concrete and achievable
3. **Prioritized by Impact** (REQ-REPORT-CL-004) - Order by business value and feasibility
4. **DISC-Adapted** - Customize language and detail level per personality type

## Recommendation Types

### 1. Quick Wins
- **Definition:** Low-effort, high-impact actions achievable in 1-4 weeks
- **Quantity:** 3-5 recommendations per report
- **Criteria:**
  - Requires < 10 hours of effort
  - Minimal cost (< $500)
  - No dependencies on other systems
  - Immediate visibility of results

### 2. Strategic Priorities
- **Definition:** High-impact initiatives requiring 1-6 months
- **Quantity:** 3-7 recommendations per report
- **Criteria:**
  - Significant business impact
  - May require investment or external help
  - Foundational for next phase advancement

### 3. Long-Term Goals
- **Definition:** Transformational projects over 6+ months
- **Quantity:** 2-4 recommendations per report
- **Criteria:**
  - Strategic business transformation
  - Multiple dependencies
  - Requires sustained commitment

## Recommendation Generation Process

### Step 1: Analyze Phase Scores and Identify Gaps

```javascript
function identifyGaps(phaseResults, questionResponses) {
  const gaps = [];

  // Analyze each phase
  Object.keys(phaseResults.allScores).forEach(phase => {
    const score = phaseResults.allScores[phase];

    // Identify low-scoring areas within each phase
    const phaseQuestions = getQuestionsForPhase(phase);

    phaseQuestions.forEach(question => {
      const response = questionResponses[question.id];
      const selectedOption = getOption(question, response);

      // If response scored low for this phase, it's a gap
      const phaseScoreKey = `${phase}_score`;
      if (selectedOption[phaseScoreKey] < 5) {
        gaps.push({
          phase: phase,
          questionId: question.id,
          questionText: question.question_text,
          currentScore: selectedOption[phaseScoreKey],
          maxScore: 10,
          severity: calculateSeverity(selectedOption[phaseScoreKey]),
          category: categorizeQuestion(question)
        });
      }
    });
  });

  return gaps.sort((a, b) => a.currentScore - b.currentScore);
}
```

### Step 2: Map Gaps to Recommendations

```javascript
const recommendationLibrary = {
  // Stabilize Phase Recommendations
  'stab-001-behind': {
    id: 'rec-stab-bookkeeping',
    phase: 'stabilize',
    category: 'quick_win',
    title: 'Catch Up on Bookkeeping',
    description: 'Bring your bookkeeping current within the next 30 days',
    actions: [
      'Block 2 hours this week to categorize recent transactions',
      'Set up automatic bank feeds to reduce manual entry',
      'Schedule recurring weekly bookkeeping sessions (1-2 hours)',
      'Consider hiring a part-time bookkeeper if volume is high'
    ],
    impact: 'high',
    effort: 'medium',
    timeframe: '2-4 weeks',
    cost_range: '$0-500',
    benefits: [
      'Clear visibility into current financial position',
      'Reduced stress and last-minute scrambling',
      'Better decision-making with current data',
      'Easier tax preparation'
    ],
    triggers: [
      { question: 'stab-001', values: ['behind', 'very_behind'] }
    ]
  },

  'stab-002-not-separated': {
    id: 'rec-stab-separate-accounts',
    phase: 'stabilize',
    category: 'quick_win',
    title: 'Separate Business and Personal Finances',
    description: 'Open dedicated business bank accounts this month',
    actions: [
      'Research business checking accounts (compare 3-5 banks)',
      'Open dedicated business checking and savings accounts',
      'Apply for business credit card',
      'Transfer all business transactions to new accounts',
      'Document any personal expenses needing reimbursement'
    ],
    impact: 'high',
    effort: 'low',
    timeframe: '1-2 weeks',
    cost_range: '$0-100',
    benefits: [
      'Simplified bookkeeping and tax preparation',
      'Better legal protection (corporate veil)',
      'Clearer financial picture of business health',
      'Professional appearance with vendors and clients'
    ],
    triggers: [
      { question: 'stab-002', values: ['partially_separated', 'not_separated'] }
    ]
  },

  'stab-003-debt-struggling': {
    id: 'rec-stab-debt-plan',
    phase: 'stabilize',
    category: 'strategic_priority',
    title: 'Create Debt Management Plan',
    description: 'Develop a structured approach to manage business debt',
    actions: [
      'List all business debts with balances, rates, and terms',
      'Calculate total monthly debt service',
      'Prioritize: highest interest rate or smallest balance (snowball)',
      'Contact creditors to negotiate better terms if needed',
      'Set up automatic payments to avoid late fees',
      'Consider debt consolidation if beneficial'
    ],
    impact: 'high',
    effort: 'medium',
    timeframe: '4-8 weeks',
    cost_range: '$0-1000',
    benefits: [
      'Reduced financial stress and clearer path forward',
      'Lower interest costs over time',
      'Improved cash flow predictability',
      'Better credit standing for future needs'
    ],
    triggers: [
      { question: 'stab-003', values: ['challenging'] }
    ]
  },

  'stab-007-no-reconciliation': {
    id: 'rec-stab-bank-reconciliation',
    phase: 'stabilize',
    category: 'quick_win',
    title: 'Implement Monthly Bank Reconciliation',
    description: 'Start reconciling bank accounts monthly to catch errors',
    actions: [
      'Reconcile current month first (while memory is fresh)',
      'Schedule recurring monthly reconciliation (last day of month)',
      'Create simple checklist: match deposits, match withdrawals, verify balance',
      'Flag and research any discrepancies immediately',
      'Use accounting software reconciliation tools if available'
    ],
    impact: 'medium',
    effort: 'low',
    timeframe: '1-2 weeks',
    cost_range: '$0',
    benefits: [
      'Catch errors and fraud early',
      'Confidence in financial data accuracy',
      'Easier month-end close process',
      'Better foundation for financial reporting'
    ],
    triggers: [
      { question: 'stab-007', values: ['annual', 'never'] }
    ]
  },

  // Organize Phase Recommendations
  'org-001-no-coa': {
    id: 'rec-org-chart-of-accounts',
    phase: 'organize',
    category: 'strategic_priority',
    title: 'Customize Your Chart of Accounts',
    description: 'Tailor your Chart of Accounts to reflect your business structure',
    actions: [
      'Review current Chart of Accounts structure',
      'Identify accounts that need renaming or consolidating',
      'Add accounts specific to your industry (e.g., job costs, service categories)',
      'Organize expense categories by department or function',
      'Document account usage guidelines for consistency',
      'Train team on new account structure'
    ],
    impact: 'high',
    effort: 'medium',
    timeframe: '3-6 weeks',
    cost_range: '$0-500',
    benefits: [
      'Financial reports that actually reflect your business',
      'Better departmental or product-level tracking',
      'Easier to spot trends and anomalies',
      'More meaningful financial analysis'
    ],
    triggers: [
      { question: 'org-001', values: ['unclear', 'none'] }
    ]
  },

  'org-002-disconnected-systems': {
    id: 'rec-org-integrate-systems',
    phase: 'organize',
    category: 'strategic_priority',
    title: 'Integrate Financial Systems',
    description: 'Connect your accounting, banking, and payroll systems',
    actions: [
      'Audit current financial software and tools',
      'Research integration options (native, Zapier, APIs)',
      'Connect bank accounts to accounting software',
      'Link payroll system to accounting',
      'Set up automatic transaction imports',
      'Test integrations for accuracy'
    ],
    impact: 'high',
    effort: 'high',
    timeframe: '6-12 weeks',
    cost_range: '$100-1000',
    benefits: [
      'Eliminate manual data entry and errors',
      'Real-time financial visibility',
      'Save 5-10 hours per month on data entry',
      'Better data consistency across systems'
    ],
    triggers: [
      { question: 'org-002', values: ['disconnected'] }
    ]
  },

  'org-005-disorganized-docs': {
    id: 'rec-org-document-system',
    phase: 'organize',
    category: 'quick_win',
    title: 'Set Up Digital Document Storage',
    description: 'Create organized digital filing system for financial documents',
    actions: [
      'Choose cloud storage solution (Google Drive, Dropbox, OneDrive)',
      'Create folder structure: by year, then by category',
      'Scan and upload current year\'s paper documents',
      'Set up automatic forwarding of financial emails to storage',
      'Implement naming convention (YYYY-MM-DD-Vendor-Description)',
      'Schedule quarterly document cleanup sessions'
    ],
    impact: 'medium',
    effort: 'low',
    timeframe: '2-4 weeks',
    cost_range: '$0-200/year',
    benefits: [
      'Find documents in seconds, not hours',
      'Better backup and disaster recovery',
      'Easier collaboration with accountant/team',
      'Reduced physical storage needs'
    ],
    triggers: [
      { question: 'org-005', values: ['mixed_disorganized'] }
    ]
  },

  // Build Phase Recommendations
  'build-001-no-sops': {
    id: 'rec-build-financial-sops',
    phase: 'build',
    category: 'strategic_priority',
    title: 'Document Financial Procedures',
    description: 'Create Standard Operating Procedures for key financial processes',
    actions: [
      'Identify top 5 critical financial processes (e.g., invoicing, month-end close)',
      'Document current process for each (even if imperfect)',
      'Use simple format: purpose, steps, responsible party, timeline',
      'Review with team members who perform tasks',
      'Store in accessible shared location',
      'Update quarterly as processes improve'
    ],
    impact: 'high',
    effort: 'medium',
    timeframe: '6-10 weeks',
    cost_range: '$0-500',
    benefits: [
      'Consistency in financial processes',
      'Easier to train new team members',
      'Reduces key person dependency',
      'Foundation for process improvement'
    ],
    triggers: [
      { question: 'build-001', values: ['informal', 'none'] }
    ]
  },

  'build-002-no-close-process': {
    id: 'rec-build-month-end-close',
    phase: 'build',
    category: 'strategic_priority',
    title: 'Implement Month-End Close Checklist',
    description: 'Create systematic month-end financial close process',
    actions: [
      'List all month-end tasks currently performed',
      'Add missing tasks (reconciliations, accruals, reviews)',
      'Assign responsible parties and deadlines',
      'Create sequential workflow (what must happen before what)',
      'Build checklist template in spreadsheet or project management tool',
      'Test for 2-3 months and refine'
    ],
    impact: 'high',
    effort: 'medium',
    timeframe: '4-6 weeks',
    cost_range: '$0-300',
    benefits: [
      'Financial reports ready by 5th business day',
      'Fewer corrections and adjustments',
      'Better trend visibility month-to-month',
      'Professional discipline and accountability'
    ],
    triggers: [
      { question: 'build-002', values: ['ad_hoc', 'no_formal_close'] }
    ]
  },

  'build-005-no-controls': {
    id: 'rec-build-internal-controls',
    phase: 'build',
    category: 'strategic_priority',
    title: 'Establish Basic Internal Controls',
    description: 'Implement controls to prevent errors and fraud',
    actions: [
      'Require dual signatures on checks over $5,000',
      'Separate duties: person paying bills ≠ person reconciling bank',
      'Implement purchase approval workflow',
      'Review all bank/credit card statements monthly',
      'Restrict accounting system access by role',
      'Perform surprise audits of petty cash/expenses'
    ],
    impact: 'high',
    effort: 'medium',
    timeframe: '4-8 weeks',
    cost_range: '$0-500',
    benefits: [
      'Protection against fraud and theft',
      'Reduced errors in financial data',
      'Better accountability across team',
      'Peace of mind and risk mitigation'
    ],
    triggers: [
      { question: 'build-005', values: ['minimal', 'none'] }
    ]
  },

  // Grow Phase Recommendations
  'grow-001-no-projections': {
    id: 'rec-grow-cash-flow-forecast',
    phase: 'grow',
    category: 'strategic_priority',
    title: 'Build 12-Month Cash Flow Forecast',
    description: 'Create rolling cash flow projection to anticipate needs',
    actions: [
      'Download cash flow forecast template or use Excel',
      'Enter beginning cash balance',
      'Project monthly revenue based on pipeline and history',
      'List all recurring monthly expenses',
      'Add known one-time expenses (equipment, taxes, etc.)',
      'Calculate monthly net cash flow and ending balance',
      'Update weekly with actuals vs. projections'
    ],
    impact: 'very_high',
    effort: 'medium',
    timeframe: '2-4 weeks',
    cost_range: '$0-500',
    benefits: [
      'Never surprised by cash shortfalls',
      'Better timing for major purchases',
      'Data for financing conversations',
      'Strategic visibility 3-12 months ahead'
    ],
    triggers: [
      { question: 'grow-001', values: ['annual_only', 'no_projections'] }
    ]
  },

  'grow-003-no-kpis': {
    id: 'rec-grow-kpi-dashboard',
    phase: 'grow',
    category: 'strategic_priority',
    title: 'Create KPI Tracking Dashboard',
    description: 'Identify and track key performance indicators weekly',
    actions: [
      'Identify 5-10 KPIs critical to your business (revenue, margin, CAC, etc.)',
      'Define how each will be calculated',
      'Set up simple dashboard (spreadsheet or BI tool)',
      'Establish targets/benchmarks for each KPI',
      'Schedule weekly 15-minute review',
      'Link KPIs to strategic goals and action plans'
    ],
    impact: 'very_high',
    effort: 'medium',
    timeframe: '4-6 weeks',
    cost_range: '$0-1000',
    benefits: [
      'Data-driven decision making',
      'Early warning system for problems',
      'Team alignment around metrics',
      'Track progress toward goals'
    ],
    triggers: [
      { question: 'grow-003', values: ['basic_metrics', 'no_kpis'] }
    ]
  },

  'grow-005-no-scenarios': {
    id: 'rec-grow-scenario-planning',
    phase: 'grow',
    category: 'long_term_goal',
    title: 'Implement Scenario Planning',
    description: 'Model best case, worst case, and most likely scenarios',
    actions: [
      'Start with base case (most likely) annual forecast',
      'Create worst case: revenue down 20%, key expenses up',
      'Create best case: revenue up 30%, improved margins',
      'Identify actions to take if worst case materializes',
      'Identify investments to make if best case occurs',
      'Review quarterly and adjust scenarios'
    ],
    impact: 'high',
    effort: 'high',
    timeframe: '8-12 weeks',
    cost_range: '$0-2000',
    benefits: [
      'Preparedness for multiple futures',
      'Strategic agility and faster decisions',
      'Better risk management',
      'Confidence in uncertain times'
    ],
    triggers: [
      { question: 'grow-005', values: ['informal', 'no_scenarios'] }
    ]
  },

  // Systemic Phase Recommendations
  'sys-low-comfort': {
    id: 'rec-sys-financial-literacy',
    phase: 'systemic',
    category: 'long_term_goal',
    title: 'Improve Financial Statement Literacy',
    description: 'Build confidence in reading and interpreting financial reports',
    actions: [
      'Take online course on financial statements (Coursera, LinkedIn Learning)',
      'Schedule monthly 30-minute review session with accountant',
      'Practice: review your own statements and write summary',
      'Join peer group or forum to discuss financials',
      'Read "Financial Intelligence" or similar book',
      'Ask "why" questions about every number'
    ],
    impact: 'very_high',
    effort: 'medium',
    timeframe: '12-24 weeks',
    cost_range: '$100-1000',
    benefits: [
      'Confidence in business financial health',
      'Better strategic decisions',
      'Effective communication with stakeholders',
      'Spot opportunities and risks earlier'
    ],
    triggers: [
      { question: 'sys-001', scale_below: 5 },
      { question: 'sys-002', scale_below: 5 },
      { question: 'sys-003', scale_below: 5 }
    ]
  },

  'sys-004-rarely-review': {
    id: 'rec-sys-regular-review',
    phase: 'systemic',
    category: 'quick_win',
    title: 'Establish Monthly Financial Review Ritual',
    description: 'Schedule recurring time to review financial performance',
    actions: [
      'Block 1 hour on calendar on 10th of each month',
      'Create review agenda: P&L, Balance Sheet, Cash Flow, KPIs',
      'Prepare 3 questions before each session',
      'Note observations and action items',
      'Invite key team member or advisor to join',
      'Track questions and learnings over time'
    ],
    impact: 'high',
    effort: 'low',
    timeframe: '1 week',
    cost_range: '$0',
    benefits: [
      'Consistent financial awareness',
      'Build financial literacy through practice',
      'Catch issues within 30 days',
      'Better financial discipline'
    ],
    triggers: [
      { question: 'sys-004', values: ['quarterly', 'annually', 'rarely'] }
    ]
  }
};
```

### Step 3: Prioritize Recommendations

```javascript
function prioritizeRecommendations(gaps, phaseResults, discProfile, clientGoals) {
  const allRecommendations = [];

  // Match gaps to recommendations from library
  gaps.forEach(gap => {
    const matchingRecs = findMatchingRecommendations(gap, recommendationLibrary);
    allRecommendations.push(...matchingRecs);
  });

  // Remove duplicates
  const uniqueRecs = deduplicateRecommendations(allRecommendations);

  // Score each recommendation
  const scoredRecs = uniqueRecs.map(rec => {
    const score = calculateRecommendationScore(
      rec,
      phaseResults,
      clientGoals,
      discProfile
    );

    return {
      ...rec,
      priorityScore: score
    };
  });

  // Sort by priority score (descending)
  return scoredRecs.sort((a, b) => b.priorityScore - a.priorityScore);
}

function calculateRecommendationScore(rec, phaseResults, goals, discProfile) {
  let score = 0;

  // Phase alignment (0-30 points)
  if (rec.phase === phaseResults.primary.phase) {
    score += 30;  // Primary phase
  } else if (phaseResults.secondary.some(s => s.phase === rec.phase)) {
    score += 20;  // Secondary phase
  } else {
    score += 5;   // Other phases
  }

  // Impact (0-25 points)
  const impactScores = {
    very_high: 25,
    high: 20,
    medium: 12,
    low: 5
  };
  score += impactScores[rec.impact] || 10;

  // Effort (inverse - lower effort = higher score) (0-20 points)
  const effortScores = {
    low: 20,
    medium: 12,
    high: 5
  };
  score += effortScores[rec.effort] || 10;

  // Client goal alignment (0-15 points)
  if (goals && rec.phase === goals.goal_alignment) {
    score += 15;
  }

  // DISC profile fit (0-10 points)
  score += calculateDISCFit(rec, discProfile);

  return score;
}

function calculateDISCFit(rec, discProfile) {
  // D-types prefer quick wins
  if (discProfile.primaryType === 'D' && rec.category === 'quick_win') {
    return 10;
  }

  // C-types prefer systematic, detailed projects
  if (discProfile.primaryType === 'C' && rec.effort === 'high' && rec.impact === 'very_high') {
    return 10;
  }

  // I-types prefer collaborative, visible wins
  if (discProfile.primaryType === 'I' && rec.category === 'strategic_priority') {
    return 8;
  }

  // S-types prefer steady, low-risk changes
  if (discProfile.primaryType === 'S' && rec.effort === 'low') {
    return 10;
  }

  return 5;  // Neutral fit
}
```

### Step 4: Adapt Language for DISC Profile

```javascript
function adaptRecommendationForDISC(recommendation, discProfile) {
  const adapted = { ...recommendation };
  const primaryType = discProfile.primaryType;

  // Adapt title and description
  if (primaryType === 'D') {
    // Brief, results-focused
    adapted.title = makeDirectAndBrief(adapted.title);
    adapted.description = `${adapted.description} - Drive results in ${adapted.timeframe}`;
    adapted.emphasisArea = 'ROI and bottom-line impact';
  }

  if (primaryType === 'I') {
    // Collaborative, opportunity-focused
    adapted.title = makeCollaborativeAndPositive(adapted.title);
    adapted.description = `${adapted.description} - Exciting opportunity to enhance your business`;
    adapted.emphasisArea = 'Collaboration opportunities and big-picture vision';
  }

  if (primaryType === 'S') {
    // Step-by-step, reassuring
    adapted.title = makeSupportiveAndClear(adapted.title);
    adapted.description = `${adapted.description} - Follow our step-by-step guidance`;
    adapted.emphasisArea = 'Clear process with support available';
  }

  if (primaryType === 'C') {
    // Detailed, analytical
    adapted.title = makeAnalyticalAndPrecise(adapted.title);
    adapted.description = `${adapted.description} - Systematic approach with measurable outcomes`;
    adapted.emphasisArea = 'Data-driven methodology and thorough analysis';
  }

  // Adapt action list presentation
  adapted.actions = adapted.actions.map(action =>
    adaptActionForDISC(action, primaryType)
  );

  return adapted;
}
```

### Step 5: Generate Checklist Items

Per REQ-CHECKLIST-001, convert recommendations to actionable checklist items:

```javascript
function generateChecklist(recommendations, discProfile) {
  const checklistItems = [];

  recommendations.forEach((rec, index) => {
    rec.actions.forEach((action, actionIndex) => {
      checklistItems.push({
        id: `${rec.id}-action-${actionIndex}`,
        recommendationId: rec.id,
        title: action,
        description: '',
        phase: rec.phase,
        category: rec.category,
        order: (index * 100) + actionIndex,
        completed: false,
        dueDate: calculateDueDate(rec.timeframe, actionIndex, rec.actions.length),
        estimatedHours: estimateEffort(action),
        resources: extractResources(action),
        dependencies: []
      });
    });
  });

  return checklistItems;
}
```

## Output Structure

```javascript
{
  summary: {
    totalRecommendations: 12,
    quickWins: 4,
    strategicPriorities: 5,
    longTermGoals: 3,
    primaryFocus: "organize",
    discProfile: "D"
  },
  quickWins: [
    {
      id: "rec-stab-bank-reconciliation",
      phase: "stabilize",
      category: "quick_win",
      title: "Implement Monthly Bank Reconciliation",
      description: "Start reconciling bank accounts monthly to catch errors",
      actions: [...],
      impact: "medium",
      effort: "low",
      timeframe: "1-2 weeks",
      cost_range: "$0",
      benefits: [...],
      priorityScore: 78,
      discAdaptation: "D"
    },
    // ... 3-4 more quick wins
  ],
  strategicPriorities: [
    // ... 3-7 strategic priorities
  ],
  longTermGoals: [
    // ... 2-4 long-term goals
  ],
  checklist: [
    {
      id: "rec-stab-bank-reconciliation-action-0",
      recommendationId: "rec-stab-bank-reconciliation",
      title: "Reconcile current month first (while memory is fresh)",
      phase: "stabilize",
      completed: false,
      dueDate: "2025-12-26",
      estimatedHours: 2
    },
    // ... all checklist items from all recommendations
  ]
}
```

## Language Guidelines

### Non-Judgmental Framing (REQ-REPORT-CL-002)

❌ **AVOID:**
- "You're behind on bookkeeping" → ✅ "Opportunity to bring bookkeeping current"
- "Your systems are a mess" → ✅ "Room to streamline and organize your systems"
- "You failed to implement controls" → ✅ "Adding internal controls will strengthen your operations"
- "This is critical" → ✅ "This is a high-impact opportunity"

### Encouraging Language

- Use "opportunity" instead of "problem"
- Use "strengthen" instead of "fix"
- Use "enhance" instead of "correct"
- Use "build on" instead of "lacking"
- Use "next step" instead of "must do"

### Action-Oriented Language

- Start with verbs: "Implement," "Create," "Build," "Establish," "Set up"
- Be specific: "Monthly bank reconciliation" not "Better accounting"
- Include timeframes: "This week," "By month-end," "Over next 30 days"
- Quantify when possible: "Save 5 hours/month," "Reduce errors by 50%"

## DISC-Specific Language Adaptations

### D-Type (Dominance)
```javascript
const D_adaptations = {
  tone: "Direct, brief, results-oriented",
  structure: "Executive summary style, bullet points",
  emphasis: "ROI, competitive advantage, bottom-line impact",
  examples: [
    "Implement now to gain competitive edge",
    "Drive 20% efficiency improvement",
    "Bottom line: Save $5K annually"
  ]
};
```

### I-Type (Influence)
```javascript
const I_adaptations = {
  tone: "Enthusiastic, collaborative, opportunity-focused",
  structure: "Narrative style, visuals, stories",
  emphasis: "Collaboration, innovation, positive impact",
  examples: [
    "Exciting opportunity to transform your business",
    "Work together with your team to achieve this",
    "Imagine the possibilities when you have real-time data"
  ]
};
```

### S-Type (Steadiness)
```javascript
const S_adaptations = {
  tone: "Supportive, reassuring, methodical",
  structure: "Step-by-step instructions, clear timelines",
  emphasis: "Stability, process, support available",
  examples: [
    "Follow these simple steps at your own pace",
    "We'll support you every step of the way",
    "This gradual approach ensures smooth transition"
  ]
};
```

### C-Type (Compliance)
```javascript
const C_adaptations = {
  tone: "Analytical, precise, detailed",
  structure: "Comprehensive documentation, data-driven",
  emphasis: "Accuracy, quality, systematic approach",
  examples: [
    "Detailed analysis shows 35% improvement potential",
    "Systematic implementation ensures accuracy",
    "Comprehensive documentation included for reference"
  ]
};
```

## Integration with Checklist System

Per REQ-CHECKLIST-001-006, recommendations feed into the checklist management system:

1. **Generate Checklist Items** - Each action becomes a trackable item
2. **Assign Due Dates** - Based on timeframe and sequence
3. **Enable Tracking** - Consultants mark items complete
4. **Show Progress** - Visual progress bars and completion percentages
5. **Update Recommendations** - As items complete, recommendations evolve

## Performance and Caching

- **Pre-generate common recommendations** for typical gap patterns
- **Cache adapted recommendations** by DISC profile
- **Lazy load full details** - Summary first, details on demand
- **Update incrementally** - Recalculate only when responses change

## References

- Requirements: REQ-REPORT-CL-002, REQ-REPORT-CL-003, REQ-REPORT-CL-004, REQ-CHECKLIST-001
- Phase Algorithm: `phase-algorithm.md`
- DISC Algorithm: `disc-algorithm.md`
- Communication Strategies: `../disc-communication-strategies.json`
