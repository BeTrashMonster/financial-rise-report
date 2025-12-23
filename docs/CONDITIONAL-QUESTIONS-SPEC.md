# Conditional Questions Logic - Technical Specification

**Version:** 1.0
**Date:** 2025-12-22
**Work Stream:** 41 - Conditional Questions Logic
**Phase:** 3 - Advanced Features
**Dependency Level:** 0

## Overview

The Conditional Questions Logic feature enables dynamic questionnaires where certain questions only appear based on previous answers. This reduces questionnaire length, improves user experience, and allows for more sophisticated assessment flows.

### Key Use Case

**From requirements.md REQ-QUEST-010:**
> Entity type question with S-Corp payroll conditional follow-up
> - "What is your business entity type?" (LLC, S-Corp, C-Corp, Sole Proprietor)
> - IF S-Corp selected → Show: "Do you have payroll set up?"

### Key Features

1. **Conditional Logic Engine** - Rule-based question visibility
2. **Dynamic Question Loading** - Questions appear/hide based on answers
3. **Progress Calculation** - Accurate progress with conditional questions
4. **Rule Builder** - Define conditions without coding
5. **Nested Conditions** - Support for complex logic chains

## Requirements Mapping

**REQ-QUEST-010:** S-Corp payroll conditional follow-up
**REQ-QUEST-011:** Conditional question support (general)
**REQ-UI-005:** Dynamic form updates without page refresh

## Conditional Logic Model

### Rule Structure

```typescript
interface ConditionalRule {
  id: string;
  question_id: string; // The question that has this condition
  condition_type: 'show_if' | 'hide_if';
  logic_operator: 'AND' | 'OR';
  conditions: Condition[];
  created_at: Date;
  updated_at: Date;
}

interface Condition {
  target_question_id: string; // The question we're checking
  operator: 'equals' | 'not_equals' | 'contains' | 'greater_than' | 'less_than' | 'in' | 'not_in';
  value: any; // The value to compare against
}
```

### Example Rules

**Rule 1: Show payroll question if S-Corp selected**
```json
{
  "id": "rule_001",
  "question_id": "q_payroll_setup",
  "condition_type": "show_if",
  "logic_operator": "AND",
  "conditions": [
    {
      "target_question_id": "q_entity_type",
      "operator": "equals",
      "value": "S-Corp"
    }
  ]
}
```

**Rule 2: Show inventory questions only if client has physical products**
```json
{
  "id": "rule_002",
  "question_id": "q_inventory_tracking",
  "condition_type": "show_if",
  "logic_operator": "AND",
  "conditions": [
    {
      "target_question_id": "q_business_type",
      "operator": "in",
      "value": ["Retail", "Manufacturing", "Wholesale"]
    }
  ]
}
```

**Rule 3: Complex rule with multiple conditions**
```json
{
  "id": "rule_003",
  "question_id": "q_advanced_forecasting",
  "condition_type": "show_if",
  "logic_operator": "AND",
  "conditions": [
    {
      "target_question_id": "q_annual_revenue",
      "operator": "greater_than",
      "value": 1000000
    },
    {
      "target_question_id": "q_has_financial_projections",
      "operator": "equals",
      "value": "Yes"
    }
  ]
}
```

## Database Schema

### questions Table (extension)

```sql
ALTER TABLE questions
ADD COLUMN IF NOT EXISTS is_conditional BOOLEAN DEFAULT false,
ADD COLUMN IF NOT EXISTS conditional_rules JSONB DEFAULT NULL;

-- Example conditional_rules structure:
-- {
--   "condition_type": "show_if",
--   "logic_operator": "AND",
--   "conditions": [
--     {
--       "target_question_id": "q_entity_type",
--       "operator": "equals",
--       "value": "S-Corp"
--     }
--   ]
-- }

-- Add index for querying conditional questions
CREATE INDEX idx_questions_conditional ON questions(is_conditional)
WHERE is_conditional = true;
```

### Questionnaire Flow Table (new)

```sql
CREATE TABLE questionnaire_flow (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  assessment_id UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  question_id UUID NOT NULL REFERENCES questions(id),
  is_visible BOOLEAN DEFAULT true,
  visibility_determined_at TIMESTAMP DEFAULT NOW(),
  trigger_question_id UUID REFERENCES questions(id), -- Which question triggered this visibility change
  trigger_answer JSONB, -- The answer that triggered the change
  created_at TIMESTAMP DEFAULT NOW()
);

-- Index for fast visibility lookups
CREATE INDEX idx_questionnaire_flow_assessment
ON questionnaire_flow(assessment_id, is_visible);
```

## API Endpoints

### 1. Get Questionnaire with Conditional Logic

```
GET /api/v1/assessments/:assessment_id/questionnaire
Authorization: Bearer <jwt_token>
```

**Response 200:**
```json
{
  "assessment_id": "assess_123",
  "questions": [
    {
      "id": "q_entity_type",
      "question_text": "What is your business entity type?",
      "question_type": "single_choice",
      "choices": ["LLC", "S-Corp", "C-Corp", "Sole Proprietor"],
      "is_visible": true,
      "is_conditional": false,
      "sort_order": 1
    },
    {
      "id": "q_payroll_setup",
      "question_text": "Do you have payroll set up?",
      "question_type": "yes_no",
      "is_visible": false,
      "is_conditional": true,
      "conditional_rules": {
        "condition_type": "show_if",
        "logic_operator": "AND",
        "conditions": [
          {
            "target_question_id": "q_entity_type",
            "operator": "equals",
            "value": "S-Corp"
          }
        ]
      },
      "sort_order": 2
    }
  ],
  "total_questions": 50,
  "visible_questions": 49,
  "progress": {
    "answered": 5,
    "total_visible": 49,
    "percentage": 10
  }
}
```

### 2. Evaluate Conditional Rules

```
POST /api/v1/assessments/:assessment_id/questionnaire/evaluate
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "question_id": "q_entity_type",
  "answer": { "value": "S-Corp" }
}
```

**Description:** Evaluates all conditional rules that depend on this question and returns visibility updates.

**Response 200:**
```json
{
  "visibility_changes": [
    {
      "question_id": "q_payroll_setup",
      "is_visible": true,
      "reason": "Condition met: entity_type equals S-Corp"
    }
  ],
  "affected_questions": 1,
  "total_visible": 50
}
```

### 3. Create Conditional Rule (Admin/Content)

```
POST /api/v1/admin/questions/:question_id/conditional-rules
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "condition_type": "show_if",
  "logic_operator": "AND",
  "conditions": [
    {
      "target_question_id": "q_entity_type",
      "operator": "equals",
      "value": "S-Corp"
    }
  ]
}
```

**Response 201:**
```json
{
  "question_id": "q_payroll_setup",
  "is_conditional": true,
  "conditional_rules": {
    "condition_type": "show_if",
    "logic_operator": "AND",
    "conditions": [
      {
        "target_question_id": "q_entity_type",
        "operator": "equals",
        "value": "S-Corp"
      }
    ]
  }
}
```

## Backend Implementation

### Conditional Logic Engine

```typescript
export class ConditionalLogicEngine {
  /**
   * Evaluates all conditional rules for an assessment
   * Returns map of question_id → is_visible
   */
  async evaluateAllRules(
    assessmentId: string,
    responses: Map<string, any>
  ): Promise<Map<string, boolean>> {
    const questions = await Question.findAll({
      where: { is_conditional: true },
      order: [['sort_order', 'ASC']]
    });

    const visibility = new Map<string, boolean>();

    for (const question of questions) {
      const isVisible = this.evaluateQuestion(question, responses);
      visibility.set(question.id, isVisible);

      // Log visibility change
      await QuestionnaireFlow.create({
        assessment_id: assessmentId,
        question_id: question.id,
        is_visible: isVisible,
        visibility_determined_at: new Date()
      });
    }

    return visibility;
  }

  /**
   * Evaluates a single question's conditional rules
   */
  private evaluateQuestion(
    question: Question,
    responses: Map<string, any>
  ): boolean {
    if (!question.is_conditional || !question.conditional_rules) {
      return true; // Non-conditional questions are always visible
    }

    const rules = question.conditional_rules;
    const { condition_type, logic_operator, conditions } = rules;

    // Evaluate all conditions
    const results = conditions.map(condition =>
      this.evaluateCondition(condition, responses)
    );

    // Apply logic operator
    let conditionMet: boolean;
    if (logic_operator === 'AND') {
      conditionMet = results.every(r => r === true);
    } else {
      // OR
      conditionMet = results.some(r => r === true);
    }

    // Apply condition type
    if (condition_type === 'show_if') {
      return conditionMet;
    } else {
      // hide_if
      return !conditionMet;
    }
  }

  /**
   * Evaluates a single condition
   */
  private evaluateCondition(
    condition: Condition,
    responses: Map<string, any>
  ): boolean {
    const { target_question_id, operator, value } = condition;

    const response = responses.get(target_question_id);

    if (!response) {
      return false; // Question not answered yet
    }

    const answerValue = response.value;

    switch (operator) {
      case 'equals':
        return answerValue === value;

      case 'not_equals':
        return answerValue !== value;

      case 'contains':
        if (typeof answerValue === 'string') {
          return answerValue.includes(value);
        }
        if (Array.isArray(answerValue)) {
          return answerValue.includes(value);
        }
        return false;

      case 'greater_than':
        return Number(answerValue) > Number(value);

      case 'less_than':
        return Number(answerValue) < Number(value);

      case 'in':
        if (!Array.isArray(value)) {
          throw new Error('Operator "in" requires array value');
        }
        return value.includes(answerValue);

      case 'not_in':
        if (!Array.isArray(value)) {
          throw new Error('Operator "not_in" requires array value');
        }
        return !value.includes(answerValue);

      default:
        throw new Error(`Unknown operator: ${operator}`);
    }
  }

  /**
   * Re-evaluates rules after an answer is submitted
   */
  async onAnswerSubmitted(
    assessmentId: string,
    questionId: string,
    answer: any
  ): Promise<VisibilityChanges> {
    // Get all responses for this assessment
    const responses = await this.getResponses(assessmentId);
    responses.set(questionId, { value: answer });

    // Find questions that depend on this question
    const dependentQuestions = await Question.findAll({
      where: {
        is_conditional: true,
        conditional_rules: {
          conditions: {
            [Op.contains]: [{ target_question_id: questionId }]
          }
        }
      }
    });

    const changes: VisibilityChange[] = [];

    for (const question of dependentQuestions) {
      const wasVisible = await this.getLastVisibility(assessmentId, question.id);
      const isVisible = this.evaluateQuestion(question, responses);

      if (wasVisible !== isVisible) {
        changes.push({
          question_id: question.id,
          was_visible: wasVisible,
          is_visible: isVisible,
          trigger_question_id: questionId
        });

        // Update visibility in database
        await QuestionnaireFlow.create({
          assessment_id: assessmentId,
          question_id: question.id,
          is_visible: isVisible,
          trigger_question_id: questionId,
          trigger_answer: answer
        });
      }
    }

    return {
      visibility_changes: changes,
      affected_questions: changes.length
    };
  }

  private async getResponses(assessmentId: string): Promise<Map<string, any>> {
    const responses = await AssessmentResponse.findAll({
      where: { assessment_id: assessmentId }
    });

    const map = new Map();
    responses.forEach(r => {
      map.set(r.question_id, r.response_value);
    });

    return map;
  }

  private async getLastVisibility(
    assessmentId: string,
    questionId: string
  ): Promise<boolean> {
    const flow = await QuestionnaireFlow.findOne({
      where: { assessment_id: assessmentId, question_id: questionId },
      order: [['created_at', 'DESC']]
    });

    return flow?.is_visible ?? true;
  }
}
```

### Questionnaire Controller (Updated)

```typescript
export class QuestionnaireController {
  private conditionalEngine = new ConditionalLogicEngine();

  async getQuestionnaire(req: Request, res: Response) {
    const { assessment_id } = req.params;

    // Get all questions
    const questions = await Question.findAll({
      order: [['sort_order', 'ASC']]
    });

    // Get current responses
    const responses = await this.conditionalEngine.getResponses(assessment_id);

    // Evaluate visibility for all questions
    const visibility = await this.conditionalEngine.evaluateAllRules(
      assessment_id,
      responses
    );

    // Format questions with visibility
    const questionsWithVisibility = questions.map(q => ({
      id: q.id,
      question_text: q.question_text,
      question_type: q.question_type,
      choices: q.choices,
      is_visible: visibility.get(q.id) ?? true,
      is_conditional: q.is_conditional,
      conditional_rules: q.conditional_rules,
      sort_order: q.sort_order
    }));

    const visibleQuestions = questionsWithVisibility.filter(q => q.is_visible);

    const answered = Array.from(responses.keys()).filter(qid =>
      visibility.get(qid) !== false
    ).length;

    return res.json({
      assessment_id,
      questions: questionsWithVisibility,
      total_questions: questions.length,
      visible_questions: visibleQuestions.length,
      progress: {
        answered,
        total_visible: visibleQuestions.length,
        percentage: Math.round((answered / visibleQuestions.length) * 100)
      }
    });
  }

  async submitAnswer(req: Request, res: Response) {
    const { assessment_id, question_id } = req.params;
    const { answer } = req.body;

    // Save response
    await AssessmentResponse.upsert({
      assessment_id,
      question_id,
      response_value: answer
    });

    // Evaluate conditional rules
    const changes = await this.conditionalEngine.onAnswerSubmitted(
      assessment_id,
      question_id,
      answer
    );

    return res.json({
      success: true,
      visibility_changes: changes.visibility_changes,
      affected_questions: changes.affected_questions
    });
  }
}
```

## Frontend Implementation

### useConditionalQuestionnaire Hook

```typescript
import { useState, useEffect, useCallback } from 'react';
import { questionnaireApi } from '../services/questionnaireApi';

export function useConditionalQuestionnaire(assessmentId: string) {
  const [questions, setQuestions] = useState([]);
  const [visibleQuestions, setVisibleQuestions] = useState([]);
  const [progress, setProgress] = useState({ answered: 0, total_visible: 0, percentage: 0 });

  const fetchQuestionnaire = useCallback(async () => {
    const data = await questionnaireApi.getQuestionnaire(assessmentId);

    setQuestions(data.questions);
    setVisibleQuestions(data.questions.filter(q => q.is_visible));
    setProgress(data.progress);
  }, [assessmentId]);

  useEffect(() => {
    fetchQuestionnaire();
  }, [fetchQuestionnaire]);

  const submitAnswer = async (questionId: string, answer: any) => {
    const result = await questionnaireApi.submitAnswer(assessmentId, questionId, answer);

    // Handle visibility changes
    if (result.visibility_changes && result.visibility_changes.length > 0) {
      // Re-fetch questionnaire to get updated visibility
      await fetchQuestionnaire();

      // Notify user if questions appeared/disappeared
      const appeared = result.visibility_changes.filter(c => c.is_visible).length;
      const disappeared = result.visibility_changes.filter(c => !c.is_visible).length;

      if (appeared > 0) {
        showToast(`${appeared} new question(s) appeared based on your answer`, 'info');
      }
      if (disappeared > 0) {
        showToast(`${disappeared} question(s) hidden based on your answer`, 'info');
      }
    }

    return result;
  };

  return {
    questions,
    visibleQuestions,
    progress,
    submitAnswer,
    refetch: fetchQuestionnaire
  };
}
```

### ConditionalQuestionnaire Component

```typescript
import React, { useState } from 'react';
import { Box, LinearProgress, Typography, Collapse } from '@mui/material';
import { useConditionalQuestionnaire } from '../hooks/useConditionalQuestionnaire';
import { QuestionCard } from './QuestionCard';
import { AnimatePresence, motion } from 'framer-motion';

export function ConditionalQuestionnaire({ assessmentId }: Props) {
  const { visibleQuestions, progress, submitAnswer } = useConditionalQuestionnaire(assessmentId);
  const [currentIndex, setCurrentIndex] = useState(0);

  const currentQuestion = visibleQuestions[currentIndex];

  const handleAnswer = async (answer: any) => {
    await submitAnswer(currentQuestion.id, answer);

    // Move to next visible question
    if (currentIndex < visibleQuestions.length - 1) {
      setCurrentIndex(currentIndex + 1);
    }
  };

  return (
    <Box maxWidth="800px" mx="auto" p={3}>
      {/* Progress Bar */}
      <Box mb={4}>
        <Typography variant="body2" color="text.secondary" mb={1}>
          Progress: {progress.answered} of {progress.total_visible} questions ({progress.percentage}%)
        </Typography>
        <LinearProgress
          variant="determinate"
          value={progress.percentage}
          sx={{ height: 8, borderRadius: 4 }}
        />
      </Box>

      {/* Question Display with Animation */}
      <AnimatePresence mode="wait">
        <motion.div
          key={currentQuestion?.id}
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: -20 }}
          transition={{ duration: 0.3 }}
        >
          <QuestionCard
            question={currentQuestion}
            onAnswer={handleAnswer}
            questionNumber={currentIndex + 1}
            totalQuestions={visibleQuestions.length}
          />
        </motion.div>
      </AnimatePresence>

      {/* Navigation */}
      <Box mt={3} display="flex" justifyContent="space-between">
        <Button
          onClick={() => setCurrentIndex(Math.max(0, currentIndex - 1))}
          disabled={currentIndex === 0}
        >
          Previous
        </Button>

        <Typography variant="body2" color="text.secondary">
          Question {currentIndex + 1} of {visibleQuestions.length}
        </Typography>

        <Button
          onClick={() => setCurrentIndex(Math.min(visibleQuestions.length - 1, currentIndex + 1))}
          disabled={currentIndex === visibleQuestions.length - 1}
        >
          Next
        </Button>
      </Box>
    </Box>
  );
}
```

## Testing

### Unit Tests

```typescript
describe('ConditionalLogicEngine', () => {
  test('shows question when condition met', () => {
    const question = {
      id: 'q_payroll',
      is_conditional: true,
      conditional_rules: {
        condition_type: 'show_if',
        logic_operator: 'AND',
        conditions: [
          { target_question_id: 'q_entity_type', operator: 'equals', value: 'S-Corp' }
        ]
      }
    };

    const responses = new Map([
      ['q_entity_type', { value: 'S-Corp' }]
    ]);

    const engine = new ConditionalLogicEngine();
    const isVisible = engine['evaluateQuestion'](question, responses);

    expect(isVisible).toBe(true);
  });

  test('hides question when condition not met', () => {
    const question = {
      id: 'q_payroll',
      is_conditional: true,
      conditional_rules: {
        condition_type: 'show_if',
        logic_operator: 'AND',
        conditions: [
          { target_question_id: 'q_entity_type', operator: 'equals', value: 'S-Corp' }
        ]
      }
    };

    const responses = new Map([
      ['q_entity_type', { value: 'LLC' }]
    ]);

    const engine = new ConditionalLogicEngine();
    const isVisible = engine['evaluateQuestion'](question, responses);

    expect(isVisible).toBe(false);
  });

  test('handles AND logic with multiple conditions', () => {
    const question = {
      id: 'q_advanced',
      is_conditional: true,
      conditional_rules: {
        condition_type: 'show_if',
        logic_operator: 'AND',
        conditions: [
          { target_question_id: 'q_revenue', operator: 'greater_than', value: 1000000 },
          { target_question_id: 'q_has_projections', operator: 'equals', value: 'Yes' }
        ]
      }
    };

    const responses = new Map([
      ['q_revenue', { value: 1500000 }],
      ['q_has_projections', { value: 'Yes' }]
    ]);

    const engine = new ConditionalLogicEngine();
    const isVisible = engine['evaluateQuestion'](question, responses);

    expect(isVisible).toBe(true);
  });

  test('handles OR logic', () => {
    const question = {
      id: 'q_inventory',
      is_conditional: true,
      conditional_rules: {
        condition_type: 'show_if',
        logic_operator: 'OR',
        conditions: [
          { target_question_id: 'q_business_type', operator: 'equals', value: 'Retail' },
          { target_question_id: 'q_business_type', operator: 'equals', value: 'Manufacturing' }
        ]
      }
    };

    const responses = new Map([
      ['q_business_type', { value: 'Retail' }]
    ]);

    const engine = new ConditionalLogicEngine();
    const isVisible = engine['evaluateQuestion'](question, responses);

    expect(isVisible).toBe(true);
  });
});
```

### Integration Tests

```typescript
test('conditional question appears when condition met', async ({ page }) => {
  await page.goto('/assessments/assess_123/questionnaire');

  // Answer entity type question
  await page.selectOption('select[name="q_entity_type"]', 'S-Corp');
  await page.click('button:has-text("Next")');

  // Wait for conditional question to appear
  await expect(page.locator('text=Do you have payroll set up?')).toBeVisible();
});

test('progress updates correctly with conditional questions', async ({ page }) => {
  await page.goto('/assessments/assess_123/questionnaire');

  // Check initial progress (excludes hidden conditional questions)
  await expect(page.locator('text=/Progress.*49/')).toBeVisible();

  // Answer question that triggers conditional
  await page.selectOption('select[name="q_entity_type"]', 'S-Corp');
  await page.click('button:has-text("Next")');

  // Progress should now include newly visible question
  await expect(page.locator('text=/Progress.*50/')).toBeVisible();
});
```

---

**Document Version:** 1.0
**Author:** Backend Developer 1 + Frontend Developer 1
**Last Updated:** 2025-12-22
**Status:** Ready for Implementation
