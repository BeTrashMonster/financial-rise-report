# Consultant Notes - Technical Specification

**Version:** 1.0
**Date:** 2025-12-22
**Work Stream:** 35 - Consultant Notes
**Phase:** 2 - Enhanced Engagement
**Dependency Level:** 2

## Overview

The Consultant Notes feature allows consultants to add private notes to each question during client assessments. These notes are auto-saved, visible only to consultants, and included in the consultant-facing report for internal reference and client conversation preparation.

### Key Features

1. **Question-Level Notes** - Add notes to any assessment question
2. **Auto-Save** - Automatic saving with debounce (2-second delay)
3. **Private Visibility** - Notes never shown to clients
4. **Consultant Report Integration** - Display notes alongside responses
5. **Rich Text Support** - Basic formatting (optional enhancement)

## Requirements

**From requirements.md:**
- REQ-QUEST-013: Consultant notes field for each question
- REQ-REPORT-C-006: Include consultant notes in consultant report only

## Database Schema

### assessment_responses Table (extension)

```sql
ALTER TABLE assessment_responses
ADD COLUMN IF NOT EXISTS consultant_notes TEXT DEFAULT NULL;

-- Add index for searching notes
CREATE INDEX idx_assessment_responses_notes
ON assessment_responses USING gin(to_tsvector('english', consultant_notes))
WHERE consultant_notes IS NOT NULL;
```

**Updated Schema:**
```sql
CREATE TABLE assessment_responses (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  assessment_id UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  question_id UUID NOT NULL REFERENCES questions(id),
  response_value JSONB NOT NULL,
  consultant_notes TEXT DEFAULT NULL, -- NEW FIELD
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);
```

## API Endpoints

### 1. Save Consultant Note

```
PATCH /api/v1/assessments/:assessment_id/responses/:question_id/notes
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "consultant_notes": "Client mentioned they're considering S-Corp election next quarter. Follow up on payroll setup timeline."
}
```

**Validation:**
- Only consultants can add/edit notes
- assessment_id must belong to the consultant
- Max length: 5000 characters

**Response 200:**
```json
{
  "question_id": "q_123",
  "consultant_notes": "Client mentioned they're considering S-Corp election next quarter. Follow up on payroll setup timeline.",
  "updated_at": "2025-12-22T10:30:45Z"
}
```

**Response 403:**
```json
{
  "error": "Only consultants can edit notes on assessments they created",
  "code": "FORBIDDEN"
}
```

### 2. Get Assessment with Notes

```
GET /api/v1/assessments/:assessment_id
Authorization: Bearer <jwt_token>
```

**Response 200 (includes notes):**
```json
{
  "id": "assess_123",
  "status": "In Progress",
  "responses": [
    {
      "question_id": "q_phase_organize_1",
      "question_text": "Do you have a Chart of Accounts set up?",
      "response_value": { "answer": "Partially" },
      "consultant_notes": "Using default QuickBooks COA. Needs customization for industry.",
      "created_at": "2025-12-20T14:30:00Z",
      "updated_at": "2025-12-20T14:32:15Z"
    }
  ]
}
```

**Note:** Notes only included if:
- User is the consultant who created the assessment
- User has consultant role

## Backend Implementation

### Notes Controller

```typescript
import { Request, Response } from 'express';
import { AssessmentResponse } from '../models/AssessmentResponse';
import { Assessment } from '../models/Assessment';

export class NotesController {
  async saveNote(req: Request, res: Response) {
    const { assessment_id, question_id } = req.params;
    const { consultant_notes } = req.body;
    const consultantId = req.user.id;

    // Validate max length
    if (consultant_notes && consultant_notes.length > 5000) {
      return res.status(400).json({
        error: 'Notes cannot exceed 5000 characters',
        code: 'NOTES_TOO_LONG'
      });
    }

    // Verify ownership
    const assessment = await Assessment.findByPk(assessment_id);

    if (!assessment) {
      return res.status(404).json({
        error: 'Assessment not found',
        code: 'NOT_FOUND'
      });
    }

    if (assessment.consultant_id !== consultantId) {
      return res.status(403).json({
        error: 'Only consultants can edit notes on assessments they created',
        code: 'FORBIDDEN'
      });
    }

    // Update or create response with notes
    const [response, created] = await AssessmentResponse.findOrCreate({
      where: {
        assessment_id,
        question_id
      },
      defaults: {
        assessment_id,
        question_id,
        response_value: {},
        consultant_notes
      }
    });

    if (!created) {
      response.consultant_notes = consultant_notes;
      response.updated_at = new Date();
      await response.save();
    }

    return res.json({
      question_id,
      consultant_notes: response.consultant_notes,
      updated_at: response.updated_at
    });
  }

  async getNotes(req: Request, res: Response) {
    const { assessment_id } = req.params;
    const consultantId = req.user.id;

    // Verify ownership
    const assessment = await Assessment.findByPk(assessment_id);

    if (!assessment) {
      return res.status(404).json({
        error: 'Assessment not found',
        code: 'NOT_FOUND'
      });
    }

    if (assessment.consultant_id !== consultantId) {
      return res.status(403).json({
        error: 'Access denied',
        code: 'FORBIDDEN'
      });
    }

    // Get all responses with notes
    const responses = await AssessmentResponse.findAll({
      where: { assessment_id },
      attributes: ['question_id', 'consultant_notes', 'updated_at'],
      order: [['created_at', 'ASC']]
    });

    return res.json({
      notes: responses.filter(r => r.consultant_notes).map(r => ({
        question_id: r.question_id,
        consultant_notes: r.consultant_notes,
        updated_at: r.updated_at
      }))
    });
  }
}
```

### Assessment API Extension

```typescript
export class AssessmentController {
  async getAssessment(req: Request, res: Response) {
    const { assessment_id } = req.params;
    const userId = req.user.id;
    const userRole = req.user.role;

    const assessment = await Assessment.findByPk(assessment_id, {
      include: [
        {
          model: AssessmentResponse,
          include: [{ model: Question }]
        }
      ]
    });

    if (!assessment) {
      return res.status(404).json({ error: 'Assessment not found' });
    }

    // Check access
    const isConsultant = assessment.consultant_id === userId;
    const isClient = assessment.client_email === req.user.email;

    if (!isConsultant && !isClient) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Format responses - include notes only for consultant
    const responses = assessment.responses.map(r => ({
      question_id: r.question_id,
      question_text: r.question.question_text,
      response_value: r.response_value,
      ...(isConsultant && { consultant_notes: r.consultant_notes }), // Only for consultant
      created_at: r.created_at,
      updated_at: r.updated_at
    }));

    return res.json({
      id: assessment.id,
      status: assessment.status,
      responses,
      // ... other assessment data
    });
  }
}
```

### Report Generation Integration

```typescript
import Handlebars from 'handlebars';

export async function generateConsultantReport(assessmentId: string): Promise<Buffer> {
  const assessment = await Assessment.findByPk(assessmentId, {
    include: [
      {
        model: AssessmentResponse,
        include: [{ model: Question }]
      }
    ]
  });

  // Group responses by phase
  const responsesByPhase = groupByPhase(assessment.responses);

  // Format for template - include notes
  const templateData = {
    assessment_id: assessment.id,
    client_name: assessment.client_name,
    business_name: assessment.business_name,
    phases: Object.entries(responsesByPhase).map(([phase, responses]) => ({
      name: phase,
      responses: responses.map(r => ({
        question_text: r.question.question_text,
        answer: formatAnswer(r.response_value),
        consultant_notes: r.consultant_notes || '', // Include notes
        has_notes: !!r.consultant_notes
      }))
    }))
  };

  const html = await renderTemplate('consultant-report', templateData);
  const pdf = await generatePDF(html);

  return pdf;
}
```

## Frontend Implementation

### Notes Textarea Component

```typescript
import React, { useState, useEffect, useCallback } from 'react';
import { TextField, Box, Typography } from '@mui/material';
import { debounce } from 'lodash';
import { useNotesApi } from '../hooks/useNotesApi';

interface ConsultantNotesProps {
  assessmentId: string;
  questionId: string;
  initialNotes?: string;
}

export function ConsultantNotes({
  assessmentId,
  questionId,
  initialNotes = ''
}: ConsultantNotesProps) {
  const [notes, setNotes] = useState(initialNotes);
  const [saveStatus, setSaveStatus] = useState<'idle' | 'saving' | 'saved'>('idle');
  const { saveNotes } = useNotesApi();

  // Debounced save function
  const debouncedSave = useCallback(
    debounce(async (value: string) => {
      setSaveStatus('saving');
      try {
        await saveNotes(assessmentId, questionId, value);
        setSaveStatus('saved');
        setTimeout(() => setSaveStatus('idle'), 2000);
      } catch (error) {
        console.error('Failed to save notes:', error);
        setSaveStatus('idle');
      }
    }, 2000),
    [assessmentId, questionId]
  );

  const handleChange = (event: React.ChangeEvent<HTMLTextAreaElement>) => {
    const value = event.target.value;
    setNotes(value);
    debouncedSave(value);
  };

  useEffect(() => {
    setNotes(initialNotes);
  }, [initialNotes]);

  return (
    <Box mt={1}>
      <Typography variant="caption" color="text.secondary" gutterBottom>
        Private notes (visible only to you)
      </Typography>

      <TextField
        multiline
        rows={3}
        fullWidth
        placeholder="Add private notes about this response for your reference..."
        value={notes}
        onChange={handleChange}
        variant="outlined"
        size="small"
        inputProps={{ maxLength: 5000 }}
        helperText={
          saveStatus === 'saving'
            ? 'Saving...'
            : saveStatus === 'saved'
            ? 'Saved ✓'
            : `${notes.length}/5000 characters`
        }
        sx={{
          bgcolor: 'background.paper',
          '& .MuiOutlinedInput-root': {
            fontSize: '0.875rem'
          }
        }}
      />
    </Box>
  );
}
```

### Integration with Assessment Questions

```typescript
import React from 'react';
import { Box, Card, CardContent, Typography } from '@mui/material';
import { QuestionInput } from './QuestionInput';
import { ConsultantNotes } from './ConsultantNotes';
import { useAuth } from '../hooks/useAuth';

interface AssessmentQuestionCardProps {
  assessmentId: string;
  question: {
    id: string;
    question_text: string;
    question_type: string;
  };
  response?: {
    response_value: any;
    consultant_notes?: string;
  };
  onResponseChange: (questionId: string, value: any) => void;
}

export function AssessmentQuestionCard({
  assessmentId,
  question,
  response,
  onResponseChange
}: AssessmentQuestionCardProps) {
  const { user } = useAuth();
  const isConsultant = user.role === 'consultant';

  return (
    <Card>
      <CardContent>
        <Typography variant="h6" gutterBottom>
          {question.question_text}
        </Typography>

        <QuestionInput
          questionType={question.question_type}
          value={response?.response_value}
          onChange={(value) => onResponseChange(question.id, value)}
        />

        {/* Only show notes field to consultants */}
        {isConsultant && (
          <ConsultantNotes
            assessmentId={assessmentId}
            questionId={question.id}
            initialNotes={response?.consultant_notes}
          />
        )}
      </CardContent>
    </Card>
  );
}
```

### useNotesApi Hook

```typescript
import { notesApi } from '../services/notesApi';

export function useNotesApi() {
  const saveNotes = async (
    assessmentId: string,
    questionId: string,
    notes: string
  ) => {
    return await notesApi.saveNote(assessmentId, questionId, notes);
  };

  const getNotes = async (assessmentId: string) => {
    return await notesApi.getNotes(assessmentId);
  };

  return { saveNotes, getNotes };
}
```

### Notes API Service

```typescript
import axios from 'axios';

export const notesApi = {
  async saveNote(
    assessmentId: string,
    questionId: string,
    consultant_notes: string
  ) {
    const response = await axios.patch(
      `/api/v1/assessments/${assessmentId}/responses/${questionId}/notes`,
      { consultant_notes }
    );
    return response.data;
  },

  async getNotes(assessmentId: string) {
    const response = await axios.get(
      `/api/v1/assessments/${assessmentId}/notes`
    );
    return response.data;
  }
};
```

## Consultant Report Template

### Handlebars Template with Notes

```handlebars
<h2>Assessment Responses with Notes</h2>

{{#each phases}}
  <div class="phase-section">
    <h3 class="phase-header">{{name}}</h3>

    {{#each responses}}
      <div class="question-response">
        <p class="question"><strong>Q:</strong> {{question_text}}</p>
        <p class="answer"><strong>A:</strong> {{answer}}</p>

        {{#if has_notes}}
          <div class="consultant-notes">
            <p class="notes-label"><strong>Your Notes:</strong></p>
            <p class="notes-content">{{consultant_notes}}</p>
          </div>
        {{/if}}
      </div>
    {{/each}}
  </div>
{{/each}}

<style>
  .consultant-notes {
    background-color: #FFF9E6;
    border-left: 4px solid #FFB800;
    padding: 10px 15px;
    margin-top: 10px;
    margin-bottom: 15px;
  }

  .notes-label {
    color: #B8860B;
    font-size: 12px;
    font-weight: bold;
    margin: 0 0 5px 0;
    text-transform: uppercase;
  }

  .notes-content {
    color: #333;
    font-size: 14px;
    margin: 0;
    white-space: pre-wrap;
  }
</style>
```

## Testing

### Backend Tests

```typescript
describe('Consultant Notes API', () => {
  test('saves note successfully', async () => {
    const response = await request(app)
      .patch('/api/v1/assessments/assess_123/responses/q_123/notes')
      .set('Authorization', `Bearer ${consultantToken}`)
      .send({
        consultant_notes: 'Follow up on payroll setup'
      });

    expect(response.status).toBe(200);
    expect(response.body.consultant_notes).toBe('Follow up on payroll setup');
  });

  test('prevents clients from saving notes', async () => {
    const response = await request(app)
      .patch('/api/v1/assessments/assess_123/responses/q_123/notes')
      .set('Authorization', `Bearer ${clientToken}`)
      .send({
        consultant_notes: 'Trying to add notes'
      });

    expect(response.status).toBe(403);
  });

  test('enforces max length', async () => {
    const longNote = 'a'.repeat(5001);

    const response = await request(app)
      .patch('/api/v1/assessments/assess_123/responses/q_123/notes')
      .set('Authorization', `Bearer ${consultantToken}`)
      .send({
        consultant_notes: longNote
      });

    expect(response.status).toBe(400);
    expect(response.body.code).toBe('NOTES_TOO_LONG');
  });

  test('notes not included in client assessment view', async () => {
    // Consultant adds notes
    await request(app)
      .patch('/api/v1/assessments/assess_123/responses/q_123/notes')
      .set('Authorization', `Bearer ${consultantToken}`)
      .send({
        consultant_notes: 'Private consultant note'
      });

    // Client fetches assessment
    const response = await request(app)
      .get('/api/v1/assessments/assess_123')
      .set('Authorization', `Bearer ${clientToken}`);

    expect(response.status).toBe(200);

    const questionResponse = response.body.responses.find(
      r => r.question_id === 'q_123'
    );

    expect(questionResponse.consultant_notes).toBeUndefined();
  });
});
```

### Frontend Tests

```typescript
test('auto-saves notes after typing', async ({ page }) => {
  await page.goto('/assessments/assess_123');

  // Find notes textarea
  const notesField = page.locator('textarea[placeholder*="private notes"]').first();

  // Type notes
  await notesField.fill('Client needs help with Chart of Accounts');

  // Wait for auto-save (2 second debounce)
  await page.waitForTimeout(2500);

  // Verify save indicator
  await expect(page.locator('text=Saved ✓')).toBeVisible();

  // Reload page and verify notes persisted
  await page.reload();
  await expect(notesField).toHaveValue('Client needs help with Chart of Accounts');
});

test('notes not visible to clients', async ({ page }) => {
  // Login as client
  await loginAsClient(page);
  await page.goto('/client/assessments/assess_123');

  // Verify notes field doesn't exist
  await expect(page.locator('textarea[placeholder*="private notes"]')).not.toBeVisible();
});

test('shows character count', async ({ page }) => {
  await page.goto('/assessments/assess_123');

  const notesField = page.locator('textarea[placeholder*="private notes"]').first();
  await notesField.fill('Test note');

  await expect(page.locator('text=/9\\/5000 characters/')).toBeVisible();
});
```

## Accessibility

- Notes textarea has `aria-label="Private consultant notes"`
- Character count is announced to screen readers
- Save status changes are announced via `aria-live="polite"`

```typescript
<TextField
  multiline
  aria-label="Private consultant notes"
  helperText={
    <span aria-live="polite">
      {saveStatus === 'saving'
        ? 'Saving notes'
        : saveStatus === 'saved'
        ? 'Notes saved successfully'
        : `${notes.length} of 5000 characters`}
    </span>
  }
/>
```

---

**Document Version:** 1.0
**Author:** Backend Developer 2 + Frontend Developer 2
**Last Updated:** 2025-12-22
**Status:** Ready for Implementation
