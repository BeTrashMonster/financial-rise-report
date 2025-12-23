# Action Item Checklist Backend - Technical Specification

**Version:** 1.0
**Date:** 2025-12-22
**Work Stream:** 26 - Action Item Checklist Backend
**Phase:** 2 - Enhanced Engagement
**Dependency Level:** 0

## Table of Contents

1. [Overview](#overview)
2. [Database Schema](#database-schema)
3. [API Specification](#api-specification)
4. [Auto-Generation Logic](#auto-generation-logic)
5. [Collaborative Editing](#collaborative-editing)
6. [Implementation Guide](#implementation-guide)
7. [Testing Strategy](#testing-strategy)

---

## Overview

### Purpose

The Action Item Checklist system enables consultants and clients to collaboratively track action items recommended in assessment reports. Items are automatically generated from report recommendations but can be edited, added, or removed by the consultant.

### Key Features

1. **Auto-Generation:** Automatically create checklist items from report recommendations
2. **Collaborative Editing:** Both consultant and client can mark items complete
3. **Phase Categorization:** Items grouped by financial phase
4. **Progress Tracking:** Visual progress indicators (X of Y complete)
5. **Edit History:** Track who edited what and when
6. **Flexible Management:** Add, edit, delete, reorder items

### Requirements

From REQ-CHECKLIST-001 through REQ-CHECKLIST-006:
- Auto-generate from report recommendations
- Allow consultant to edit before sharing
- Track completion status with timestamps
- Both consultant and client can mark complete
- Group by phase, show progress
- Client can add notes to each item

---

## Database Schema

### Table: `checklist_items`

```sql
CREATE TABLE checklist_items (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  assessment_id UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,

  -- Item content
  title VARCHAR(500) NOT NULL,
  description TEXT,
  phase VARCHAR(50) NOT NULL, -- 'Stabilize', 'Organize', 'Build', 'Grow', 'Systemic'
  priority INT DEFAULT 0, -- 0=none, 1=low, 2=medium, 3=high
  sort_order INT NOT NULL DEFAULT 0,

  -- Completion tracking
  is_completed BOOLEAN DEFAULT FALSE,
  completed_at TIMESTAMPTZ,
  completed_by UUID REFERENCES users(id), -- consultant or client who marked it complete

  -- Client notes
  client_notes TEXT,
  client_notes_updated_at TIMESTAMPTZ,

  -- Auto-generation metadata
  auto_generated BOOLEAN DEFAULT FALSE,
  source_recommendation_id VARCHAR(100), -- Reference to report recommendation section

  -- Audit fields
  created_at TIMESTAMPTZ DEFAULT NOW(),
  created_by UUID NOT NULL REFERENCES users(id),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  updated_by UUID REFERENCES users(id),
  deleted_at TIMESTAMPTZ, -- Soft delete

  CONSTRAINT checklist_items_phase_check CHECK (
    phase IN ('Stabilize', 'Organize', 'Build', 'Grow', 'Systemic')
  ),
  CONSTRAINT checklist_items_priority_check CHECK (
    priority BETWEEN 0 AND 3
  )
);

-- Indexes
CREATE INDEX idx_checklist_items_assessment_id ON checklist_items(assessment_id);
CREATE INDEX idx_checklist_items_phase ON checklist_items(phase);
CREATE INDEX idx_checklist_items_completed ON checklist_items(is_completed);
CREATE INDEX idx_checklist_items_sort_order ON checklist_items(assessment_id, sort_order);
CREATE INDEX idx_checklist_items_deleted_at ON checklist_items(deleted_at);
```

### Table: `checklist_edit_history`

```sql
CREATE TABLE checklist_edit_history (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  checklist_item_id UUID NOT NULL REFERENCES checklist_items(id) ON DELETE CASCADE,

  -- Change tracking
  action VARCHAR(50) NOT NULL, -- 'created', 'updated', 'completed', 'uncompleted', 'deleted'
  field_name VARCHAR(100), -- Which field was changed
  old_value TEXT,
  new_value TEXT,

  -- Audit
  changed_by UUID NOT NULL REFERENCES users(id),
  changed_at TIMESTAMPTZ DEFAULT NOW(),
  ip_address INET,
  user_agent TEXT
);

-- Index
CREATE INDEX idx_checklist_history_item_id ON checklist_edit_history(checklist_item_id);
CREATE INDEX idx_checklist_history_changed_at ON checklist_edit_history(changed_at);
```

---

## API Specification

### Base URL

```
/api/v1
```

### Authentication

All endpoints require JWT authentication. User role determines permissions:
- **Consultant:** Full CRUD on their assessments' checklists
- **Client:** Read + mark complete + add notes on assessments shared with them

---

### GET /assessments/:assessmentId/checklist

**Description:** Retrieve all checklist items for an assessment

**Auth:** Required (consultant or client associated with assessment)

**Request:**
```http
GET /api/v1/assessments/a7b3c4d5-e6f7-8901-2345-6789abcdef01/checklist
Authorization: Bearer <jwt_token>

Query Parameters:
  ?phase=Build           # Filter by phase (optional)
  ?completed=true        # Filter by completion status (optional)
  ?include_deleted=false # Include soft-deleted items (default: false)
```

**Response:** 200 OK
```json
{
  "success": true,
  "data": {
    "assessment_id": "a7b3c4d5-e6f7-8901-2345-6789abcdef01",
    "total_items": 12,
    "completed_items": 5,
    "progress_percentage": 42,
    "items_by_phase": {
      "Stabilize": {
        "total": 2,
        "completed": 2,
        "items": [
          {
            "id": "c1d2e3f4-a5b6-7890-1234-567890abcdef",
            "title": "Reconcile bank accounts for last 6 months",
            "description": "Review and reconcile all bank accounts to ensure accuracy of historical records",
            "phase": "Stabilize",
            "priority": 3,
            "sort_order": 0,
            "is_completed": true,
            "completed_at": "2025-12-20T15:30:00Z",
            "completed_by": {
              "id": "user123",
              "name": "John Smith",
              "role": "client"
            },
            "client_notes": "Completed with help from bookkeeper. Found $500 discrepancy that was resolved.",
            "client_notes_updated_at": "2025-12-20T15:35:00Z",
            "auto_generated": true,
            "created_at": "2025-12-15T10:00:00Z",
            "updated_at": "2025-12-20T15:30:00Z"
          }
        ]
      },
      "Build": {
        "total": 5,
        "completed": 1,
        "items": [...]
      },
      "Grow": {
        "total": 3,
        "completed": 0,
        "items": [...]
      },
      "Systemic": {
        "total": 2,
        "completed": 2,
        "items": [...]
      }
    }
  }
}
```

**Error Responses:**
- `401 Unauthorized` - Invalid or missing token
- `403 Forbidden` - User doesn't have access to this assessment
- `404 Not Found` - Assessment doesn't exist

---

### POST /assessments/:assessmentId/checklist

**Description:** Create a new checklist item or auto-generate from report

**Auth:** Required (consultant only)

**Request:**
```http
POST /api/v1/assessments/a7b3c4d5-e6f7-8901-2345-6789abcdef01/checklist
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "title": "Implement monthly financial review meeting",
  "description": "Schedule and conduct monthly meeting to review P&L, balance sheet, and key metrics",
  "phase": "Build",
  "priority": 2,
  "auto_generate": false
}
```

**Auto-Generation Request:**
```http
POST /api/v1/assessments/a7b3c4d5-e6f7-8901-2345-6789abcdef01/checklist
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "auto_generate": true
}
```

**Response:** 201 Created
```json
{
  "success": true,
  "data": {
    "items_created": 12,
    "checklist": {
      "assessment_id": "a7b3c4d5-e6f7-8901-2345-6789abcdef01",
      "total_items": 12,
      "items_by_phase": {...}
    }
  },
  "message": "Checklist auto-generated from report recommendations"
}
```

**Validation:**
- `title` required, 1-500 characters
- `phase` must be one of: Stabilize, Organize, Build, Grow, Systemic
- `priority` must be 0-3
- Auto-generation only works if report already generated

**Error Responses:**
- `400 Bad Request` - Validation error or report not yet generated
- `401 Unauthorized` - Invalid token
- `403 Forbidden` - Only consultant can create items
- `409 Conflict` - Checklist already exists (for auto-generate)

---

### PATCH /checklist/:itemId

**Description:** Update a checklist item

**Auth:** Required (consultant or client)

**Permissions:**
- **Consultant:** Can update all fields
- **Client:** Can only update `client_notes`

**Request:**
```http
PATCH /api/v1/checklist/c1d2e3f4-a5b6-7890-1234-567890abcdef
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "title": "Updated title",
  "description": "Updated description",
  "priority": 3,
  "sort_order": 5
}
```

**Client Note Update:**
```http
PATCH /api/v1/checklist/c1d2e3f4-a5b6-7890-1234-567890abcdef
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "client_notes": "Working on this with my accountant. Should be done by end of month."
}
```

**Response:** 200 OK
```json
{
  "success": true,
  "data": {
    "id": "c1d2e3f4-a5b6-7890-1234-567890abcdef",
    "title": "Updated title",
    "description": "Updated description",
    "phase": "Build",
    "priority": 3,
    "sort_order": 5,
    "updated_at": "2025-12-22T14:20:00Z"
  }
}
```

**Error Responses:**
- `400 Bad Request` - Validation error
- `401 Unauthorized` - Invalid token
- `403 Forbidden` - Client trying to update restricted field
- `404 Not Found` - Item doesn't exist

---

### DELETE /checklist/:itemId

**Description:** Soft delete a checklist item

**Auth:** Required (consultant only)

**Request:**
```http
DELETE /api/v1/checklist/c1d2e3f4-a5b6-7890-1234-567890abcdef
Authorization: Bearer <jwt_token>
```

**Response:** 200 OK
```json
{
  "success": true,
  "message": "Checklist item deleted successfully"
}
```

**Note:** Soft delete sets `deleted_at` timestamp. Item can be restored by consultant.

**Error Responses:**
- `401 Unauthorized` - Invalid token
- `403 Forbidden` - Only consultant can delete
- `404 Not Found` - Item doesn't exist

---

### POST /checklist/:itemId/complete

**Description:** Mark an item as complete

**Auth:** Required (consultant or client)

**Request:**
```http
POST /api/v1/checklist/c1d2e3f4-a5b6-7890-1234-567890abcdef/complete
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "completed": true
}
```

**Response:** 200 OK
```json
{
  "success": true,
  "data": {
    "id": "c1d2e3f4-a5b6-7890-1234-567890abcdef",
    "is_completed": true,
    "completed_at": "2025-12-22T14:25:00Z",
    "completed_by": {
      "id": "user123",
      "name": "John Smith",
      "role": "client"
    }
  }
}
```

**Un-complete Request:**
```http
POST /api/v1/checklist/c1d2e3f4-a5b6-7890-1234-567890abcdef/complete
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "completed": false
}
```

**Error Responses:**
- `401 Unauthorized` - Invalid token
- `403 Forbidden` - No access to this assessment
- `404 Not Found` - Item doesn't exist

---

### PATCH /assessments/:assessmentId/checklist/reorder

**Description:** Reorder multiple checklist items

**Auth:** Required (consultant only)

**Request:**
```http
PATCH /api/v1/assessments/a7b3c4d5-e6f7-8901-2345-6789abcdef01/checklist/reorder
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "items": [
    {"id": "item1", "sort_order": 0},
    {"id": "item2", "sort_order": 1},
    {"id": "item3", "sort_order": 2}
  ]
}
```

**Response:** 200 OK
```json
{
  "success": true,
  "message": "Checklist items reordered successfully"
}
```

---

## Auto-Generation Logic

### Overview

When a consultant generates a report, the system extracts recommended action items and automatically creates checklist items. This happens **after** report generation.

### Extraction Rules

**Source:** Client report's "Action Plan" section

**For each DISC profile, action items are formatted differently:**
- **D-Profile:** Bullet points with ROI metrics
- **I-Profile:** Numbered steps with collaborative language
- **S-Profile:** Week-by-week timeline
- **C-Profile:** Detailed numbered actions with impact/effort analysis

### Parsing Strategy

```typescript
interface RecommendationItem {
  title: string;
  description?: string;
  phase: string;
  priority: number;
  sourceSection: string;
}

async function extractRecommendations(
  reportData: ReportData
): Promise<RecommendationItem[]> {
  const recommendations: RecommendationItem[] = [];

  // Extract from each phase section in the report
  for (const phase of ['Stabilize', 'Organize', 'Build', 'Grow', 'Systemic']) {
    const phaseRecommendations = reportData.recommendations[phase];

    if (!phaseRecommendations || phaseRecommendations.length === 0) {
      continue;
    }

    for (const rec of phaseRecommendations) {
      recommendations.push({
        title: rec.title,
        description: rec.description || rec.details,
        phase: phase,
        priority: rec.priority || determinePriority(rec, reportData.primaryPhase),
        sourceSection: `${phase}-${rec.id}`
      });
    }
  }

  return recommendations;
}

function determinePriority(
  recommendation: any,
  primaryPhase: string
): number {
  // Priority logic:
  // 3 (High) = Primary phase recommendations
  // 2 (Medium) = Adjacent phase recommendations
  // 1 (Low) = Future phase recommendations
  // 0 (None) = General recommendations

  if (recommendation.phase === primaryPhase) {
    return 3;
  }

  const phaseOrder = ['Stabilize', 'Organize', 'Build', 'Grow', 'Systemic'];
  const primaryIndex = phaseOrder.indexOf(primaryPhase);
  const recIndex = phaseOrder.indexOf(recommendation.phase);

  const distance = Math.abs(primaryIndex - recIndex);

  if (distance === 1) return 2; // Adjacent phase
  if (distance >= 2) return 1; // Future phase

  return 0;
}
```

### Auto-Generation Endpoint Logic

```typescript
async function autoGenerateChecklist(
  assessmentId: string,
  consultantId: string
): Promise<ChecklistResponse> {
  // 1. Verify report exists
  const report = await getReport(assessmentId, 'client');
  if (!report) {
    throw new Error('Report must be generated before creating checklist');
  }

  // 2. Check if checklist already exists
  const existingChecklist = await getChecklist(assessmentId);
  if (existingChecklist.length > 0) {
    throw new ConflictError('Checklist already exists for this assessment');
  }

  // 3. Extract recommendations from report
  const recommendations = await extractRecommendations(report.data);

  // 4. Create checklist items
  const items = await Promise.all(
    recommendations.map((rec, index) =>
      createChecklistItem({
        assessment_id: assessmentId,
        title: rec.title,
        description: rec.description,
        phase: rec.phase,
        priority: rec.priority,
        sort_order: index,
        auto_generated: true,
        source_recommendation_id: rec.sourceSection,
        created_by: consultantId
      })
    )
  );

  // 5. Log auto-generation
  await logActivity({
    user_id: consultantId,
    action: 'checklist_auto_generated',
    assessment_id: assessmentId,
    metadata: { items_created: items.length }
  });

  return {
    items_created: items.length,
    checklist: await getChecklist(assessmentId)
  };
}
```

---

## Collaborative Editing

### Permission Model

| Action | Consultant | Client |
|--------|-----------|--------|
| View checklist | ✅ | ✅ |
| Create item | ✅ | ❌ |
| Edit item (title, description, priority) | ✅ | ❌ |
| Delete item | ✅ | ❌ |
| Reorder items | ✅ | ❌ |
| Mark complete/incomplete | ✅ | ✅ |
| Add/edit client notes | ❌ | ✅ |

### Real-Time Updates (Optional)

For real-time collaborative editing, consider implementing WebSocket updates:

```typescript
// Server-side: Broadcast changes to all connected clients
io.to(`assessment-${assessmentId}`).emit('checklist:updated', {
  action: 'item_completed',
  item_id: itemId,
  completed_by: user.name,
  timestamp: new Date()
});

// Client-side: Listen for updates
socket.on('checklist:updated', (data) => {
  // Update UI to reflect changes
  updateChecklistItem(data.item_id, data);
  showToast(`${data.completed_by} marked an item as complete`);
});
```

**Alternative:** Polling every 30-60 seconds for updates (simpler implementation)

---

## Implementation Guide

### Step 1: Database Migration

Create migration file: `2025-12-22-create-checklist-tables.sql`

```sql
-- See Database Schema section above
```

Run migration:
```bash
npm run migrate:up
```

### Step 2: Create Data Models

**File:** `src/models/ChecklistItem.ts`

```typescript
import { Model, DataTypes } from 'sequelize';
import { sequelize } from '../config/database';

export class ChecklistItem extends Model {
  public id!: string;
  public assessment_id!: string;
  public title!: string;
  public description?: string;
  public phase!: string;
  public priority!: number;
  public sort_order!: number;
  public is_completed!: boolean;
  public completed_at?: Date;
  public completed_by?: string;
  public client_notes?: string;
  public client_notes_updated_at?: Date;
  public auto_generated!: boolean;
  public source_recommendation_id?: string;
  public created_at!: Date;
  public created_by!: string;
  public updated_at!: Date;
  public updated_by?: string;
  public deleted_at?: Date;
}

ChecklistItem.init(
  {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true
    },
    assessment_id: {
      type: DataTypes.UUID,
      allowNull: false,
      references: { model: 'assessments', key: 'id' }
    },
    title: {
      type: DataTypes.STRING(500),
      allowNull: false,
      validate: { len: [1, 500] }
    },
    description: {
      type: DataTypes.TEXT
    },
    phase: {
      type: DataTypes.STRING(50),
      allowNull: false,
      validate: {
        isIn: [['Stabilize', 'Organize', 'Build', 'Grow', 'Systemic']]
      }
    },
    priority: {
      type: DataTypes.INTEGER,
      defaultValue: 0,
      validate: { min: 0, max: 3 }
    },
    sort_order: {
      type: DataTypes.INTEGER,
      allowNull: false,
      defaultValue: 0
    },
    is_completed: {
      type: DataTypes.BOOLEAN,
      defaultValue: false
    },
    completed_at: {
      type: DataTypes.DATE
    },
    completed_by: {
      type: DataTypes.UUID,
      references: { model: 'users', key: 'id' }
    },
    client_notes: {
      type: DataTypes.TEXT
    },
    client_notes_updated_at: {
      type: DataTypes.DATE
    },
    auto_generated: {
      type: DataTypes.BOOLEAN,
      defaultValue: false
    },
    source_recommendation_id: {
      type: DataTypes.STRING(100)
    },
    created_at: {
      type: DataTypes.DATE,
      defaultValue: DataTypes.NOW
    },
    created_by: {
      type: DataTypes.UUID,
      allowNull: false,
      references: { model: 'users', key: 'id' }
    },
    updated_at: {
      type: DataTypes.DATE,
      defaultValue: DataTypes.NOW
    },
    updated_by: {
      type: DataTypes.UUID,
      references: { model: 'users', key: 'id' }
    },
    deleted_at: {
      type: DataTypes.DATE
    }
  },
  {
    sequelize,
    tableName: 'checklist_items',
    timestamps: true,
    paranoid: true, // Soft delete
    underscored: true
  }
);
```

### Step 3: Create Service Layer

**File:** `src/services/checklistService.ts`

```typescript
import { ChecklistItem } from '../models/ChecklistItem';
import { getReport } from './reportService';
import { extractRecommendations, determinePriority } from './recommendationExtractor';
import { Op } from 'sequelize';

export class ChecklistService {
  /**
   * Get all checklist items for an assessment
   */
  async getChecklist(
    assessmentId: string,
    options: {
      phase?: string;
      completed?: boolean;
      includeDeleted?: boolean;
    } = {}
  ) {
    const where: any = { assessment_id: assessmentId };

    if (options.phase) {
      where.phase = options.phase;
    }

    if (options.completed !== undefined) {
      where.is_completed = options.completed;
    }

    const items = await ChecklistItem.findAll({
      where,
      paranoid: !options.includeDeleted,
      order: [['sort_order', 'ASC']],
      include: [
        {
          model: User,
          as: 'completedBy',
          attributes: ['id', 'name', 'role']
        }
      ]
    });

    // Group by phase
    const itemsByPhase = this.groupByPhase(items);

    return {
      assessment_id: assessmentId,
      total_items: items.length,
      completed_items: items.filter(i => i.is_completed).length,
      progress_percentage: Math.round(
        (items.filter(i => i.is_completed).length / items.length) * 100
      ),
      items_by_phase: itemsByPhase
    };
  }

  /**
   * Auto-generate checklist from report
   */
  async autoGenerateChecklist(
    assessmentId: string,
    consultantId: string
  ) {
    // Check if report exists
    const report = await getReport(assessmentId, 'client');
    if (!report) {
      throw new Error('Report must be generated before creating checklist');
    }

    // Check if checklist already exists
    const existing = await ChecklistItem.count({
      where: { assessment_id: assessmentId }
    });

    if (existing > 0) {
      throw new ConflictError('Checklist already exists');
    }

    // Extract recommendations
    const recommendations = await extractRecommendations(report.data);

    // Create items
    const items = await Promise.all(
      recommendations.map((rec, index) =>
        ChecklistItem.create({
          assessment_id: assessmentId,
          title: rec.title,
          description: rec.description,
          phase: rec.phase,
          priority: rec.priority,
          sort_order: index,
          auto_generated: true,
          source_recommendation_id: rec.sourceSection,
          created_by: consultantId
        })
      )
    );

    return {
      items_created: items.length,
      checklist: await this.getChecklist(assessmentId)
    };
  }

  /**
   * Create a single checklist item
   */
  async createItem(data: {
    assessment_id: string;
    title: string;
    description?: string;
    phase: string;
    priority?: number;
    created_by: string;
  }) {
    // Get next sort_order
    const maxSortOrder = await ChecklistItem.max('sort_order', {
      where: { assessment_id: data.assessment_id }
    });

    return await ChecklistItem.create({
      ...data,
      sort_order: (maxSortOrder || 0) + 1
    });
  }

  /**
   * Update checklist item
   */
  async updateItem(
    itemId: string,
    updates: Partial<ChecklistItem>,
    userId: string,
    userRole: string
  ) {
    const item = await ChecklistItem.findByPk(itemId);
    if (!item) {
      throw new NotFoundError('Checklist item not found');
    }

    // Permission check
    if (userRole === 'client') {
      // Clients can only update client_notes
      const allowedFields = ['client_notes'];
      const updateFields = Object.keys(updates);

      if (!updateFields.every(f => allowedFields.includes(f))) {
        throw new ForbiddenError('Clients can only update notes');
      }

      if (updates.client_notes !== undefined) {
        updates.client_notes_updated_at = new Date();
      }
    }

    updates.updated_by = userId;
    updates.updated_at = new Date();

    await item.update(updates);

    return item;
  }

  /**
   * Mark item complete/incomplete
   */
  async toggleComplete(
    itemId: string,
    completed: boolean,
    userId: string
  ) {
    const item = await ChecklistItem.findByPk(itemId);
    if (!item) {
      throw new NotFoundError('Checklist item not found');
    }

    await item.update({
      is_completed: completed,
      completed_at: completed ? new Date() : null,
      completed_by: completed ? userId : null,
      updated_by: userId,
      updated_at: new Date()
    });

    // Log history
    await this.logHistory(itemId, completed ? 'completed' : 'uncompleted', userId);

    return item;
  }

  /**
   * Soft delete item
   */
  async deleteItem(itemId: string, userId: string) {
    const item = await ChecklistItem.findByPk(itemId);
    if (!item) {
      throw new NotFoundError('Checklist item not found');
    }

    await item.update({
      deleted_at: new Date(),
      updated_by: userId
    });

    await this.logHistory(itemId, 'deleted', userId);
  }

  /**
   * Reorder items
   */
  async reorderItems(
    assessmentId: string,
    items: Array<{ id: string; sort_order: number }>
  ) {
    await Promise.all(
      items.map(({ id, sort_order }) =>
        ChecklistItem.update(
          { sort_order },
          { where: { id, assessment_id: assessmentId } }
        )
      )
    );
  }

  // Helper methods

  private groupByPhase(items: ChecklistItem[]) {
    const phases = ['Stabilize', 'Organize', 'Build', 'Grow', 'Systemic'];
    const grouped: any = {};

    for (const phase of phases) {
      const phaseItems = items.filter(i => i.phase === phase);
      grouped[phase] = {
        total: phaseItems.length,
        completed: phaseItems.filter(i => i.is_completed).length,
        items: phaseItems
      };
    }

    return grouped;
  }

  private async logHistory(
    itemId: string,
    action: string,
    userId: string
  ) {
    // Implementation for edit history tracking
    // Insert into checklist_edit_history table
  }
}
```

### Step 4: Create Controller

**File:** `src/controllers/checklistController.ts`

```typescript
import { Request, Response } from 'express';
import { ChecklistService } from '../services/checklistService';
import { asyncHandler } from '../middleware/asyncHandler';
import { validateChecklistPermission } from '../middleware/permissions';

const checklistService = new ChecklistService();

export const checklistController = {
  /**
   * GET /api/v1/assessments/:assessmentId/checklist
   */
  getChecklist: asyncHandler(async (req: Request, res: Response) => {
    const { assessmentId } = req.params;
    const { phase, completed, include_deleted } = req.query;

    await validateChecklistPermission(req.user.id, assessmentId, 'read');

    const checklist = await checklistService.getChecklist(assessmentId, {
      phase: phase as string,
      completed: completed === 'true',
      includeDeleted: include_deleted === 'true'
    });

    res.json({ success: true, data: checklist });
  }),

  /**
   * POST /api/v1/assessments/:assessmentId/checklist
   */
  createChecklist: asyncHandler(async (req: Request, res: Response) => {
    const { assessmentId } = req.params;
    const { auto_generate, title, description, phase, priority } = req.body;

    await validateChecklistPermission(req.user.id, assessmentId, 'write');

    if (auto_generate) {
      const result = await checklistService.autoGenerateChecklist(
        assessmentId,
        req.user.id
      );
      return res.status(201).json({
        success: true,
        data: result,
        message: 'Checklist auto-generated from report recommendations'
      });
    }

    const item = await checklistService.createItem({
      assessment_id: assessmentId,
      title,
      description,
      phase,
      priority,
      created_by: req.user.id
    });

    res.status(201).json({ success: true, data: item });
  }),

  /**
   * PATCH /api/v1/checklist/:itemId
   */
  updateItem: asyncHandler(async (req: Request, res: Response) => {
    const { itemId } = req.params;

    const item = await checklistService.updateItem(
      itemId,
      req.body,
      req.user.id,
      req.user.role
    );

    res.json({ success: true, data: item });
  }),

  /**
   * DELETE /api/v1/checklist/:itemId
   */
  deleteItem: asyncHandler(async (req: Request, res: Response) => {
    const { itemId } = req.params;

    if (req.user.role !== 'consultant') {
      throw new ForbiddenError('Only consultants can delete items');
    }

    await checklistService.deleteItem(itemId, req.user.id);

    res.json({
      success: true,
      message: 'Checklist item deleted successfully'
    });
  }),

  /**
   * POST /api/v1/checklist/:itemId/complete
   */
  toggleComplete: asyncHandler(async (req: Request, res: Response) => {
    const { itemId } = req.params;
    const { completed } = req.body;

    const item = await checklistService.toggleComplete(
      itemId,
      completed,
      req.user.id
    );

    res.json({ success: true, data: item });
  }),

  /**
   * PATCH /api/v1/assessments/:assessmentId/checklist/reorder
   */
  reorderItems: asyncHandler(async (req: Request, res: Response) => {
    const { assessmentId } = req.params;
    const { items } = req.body;

    if (req.user.role !== 'consultant') {
      throw new ForbiddenError('Only consultants can reorder items');
    }

    await checklistService.reorderItems(assessmentId, items);

    res.json({
      success: true,
      message: 'Checklist items reordered successfully'
    });
  })
};
```

### Step 5: Create Routes

**File:** `src/routes/checklistRoutes.ts`

```typescript
import express from 'express';
import { checklistController } from '../controllers/checklistController';
import { authenticate } from '../middleware/auth';
import { validateRequest } from '../middleware/validation';
import { checklistValidation } from '../validators/checklistValidator';

const router = express.Router();

// All routes require authentication
router.use(authenticate);

// GET /api/v1/assessments/:assessmentId/checklist
router.get(
  '/assessments/:assessmentId/checklist',
  checklistController.getChecklist
);

// POST /api/v1/assessments/:assessmentId/checklist
router.post(
  '/assessments/:assessmentId/checklist',
  validateRequest(checklistValidation.create),
  checklistController.createChecklist
);

// PATCH /api/v1/checklist/:itemId
router.patch(
  '/checklist/:itemId',
  validateRequest(checklistValidation.update),
  checklistController.updateItem
);

// DELETE /api/v1/checklist/:itemId
router.delete(
  '/checklist/:itemId',
  checklistController.deleteItem
);

// POST /api/v1/checklist/:itemId/complete
router.post(
  '/checklist/:itemId/complete',
  validateRequest(checklistValidation.toggleComplete),
  checklistController.toggleComplete
);

// PATCH /api/v1/assessments/:assessmentId/checklist/reorder
router.patch(
  '/assessments/:assessmentId/checklist/reorder',
  validateRequest(checklistValidation.reorder),
  checklistController.reorderItems
);

export default router;
```

### Step 6: Add to Main App

**File:** `src/app.ts`

```typescript
import checklistRoutes from './routes/checklistRoutes';

app.use('/api/v1', checklistRoutes);
```

---

## Testing Strategy

### Unit Tests

**File:** `src/services/__tests__/checklistService.test.ts`

```typescript
import { ChecklistService } from '../checklistService';
import { ChecklistItem } from '../../models/ChecklistItem';

describe('ChecklistService', () => {
  let service: ChecklistService;

  beforeEach(() => {
    service = new ChecklistService();
  });

  describe('autoGenerateChecklist', () => {
    it('should create checklist items from report recommendations', async () => {
      const assessmentId = 'test-assessment-id';
      const consultantId = 'test-consultant-id';

      const result = await service.autoGenerateChecklist(
        assessmentId,
        consultantId
      );

      expect(result.items_created).toBeGreaterThan(0);
      expect(result.checklist.total_items).toBe(result.items_created);
    });

    it('should throw error if report not generated', async () => {
      await expect(
        service.autoGenerateChecklist('no-report', 'consultant-id')
      ).rejects.toThrow('Report must be generated');
    });

    it('should throw conflict if checklist already exists', async () => {
      // Create existing checklist
      await ChecklistItem.create({...});

      await expect(
        service.autoGenerateChecklist('assessment-id', 'consultant-id')
      ).rejects.toThrow('Checklist already exists');
    });
  });

  describe('getChecklist', () => {
    it('should return checklist grouped by phase', async () => {
      const result = await service.getChecklist('assessment-id');

      expect(result).toHaveProperty('items_by_phase');
      expect(result.items_by_phase).toHaveProperty('Stabilize');
      expect(result.items_by_phase).toHaveProperty('Build');
    });

    it('should calculate progress percentage correctly', async () => {
      // Create 10 items, 3 completed
      const result = await service.getChecklist('assessment-id');

      expect(result.progress_percentage).toBe(30);
    });
  });

  describe('toggleComplete', () => {
    it('should mark item as complete', async () => {
      const item = await ChecklistItem.create({...});

      const result = await service.toggleComplete(
        item.id,
        true,
        'user-id'
      );

      expect(result.is_completed).toBe(true);
      expect(result.completed_at).toBeTruthy();
      expect(result.completed_by).toBe('user-id');
    });

    it('should unmark completed item', async () => {
      const item = await ChecklistItem.create({
        is_completed: true,
        completed_at: new Date()
      });

      const result = await service.toggleComplete(
        item.id,
        false,
        'user-id'
      );

      expect(result.is_completed).toBe(false);
      expect(result.completed_at).toBeNull();
    });
  });
});
```

### Integration Tests

**File:** `src/controllers/__tests__/checklistController.test.ts`

```typescript
import request from 'supertest';
import app from '../../app';

describe('Checklist API', () => {
  let authToken: string;
  let assessmentId: string;

  beforeAll(async () => {
    // Set up test data
    authToken = await getTestAuthToken();
    assessmentId = await createTestAssessment();
  });

  describe('POST /assessments/:id/checklist (auto-generate)', () => {
    it('should auto-generate checklist from report', async () => {
      const res = await request(app)
        .post(`/api/v1/assessments/${assessmentId}/checklist`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({ auto_generate: true });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.items_created).toBeGreaterThan(0);
    });
  });

  describe('GET /assessments/:id/checklist', () => {
    it('should return checklist for assessment', async () => {
      const res = await request(app)
        .get(`/api/v1/assessments/${assessmentId}/checklist`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveProperty('items_by_phase');
    });

    it('should filter by phase', async () => {
      const res = await request(app)
        .get(`/api/v1/assessments/${assessmentId}/checklist?phase=Build`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      // Verify only Build phase items returned
    });
  });

  describe('POST /checklist/:id/complete', () => {
    it('should mark item as complete', async () => {
      const itemId = 'test-item-id';

      const res = await request(app)
        .post(`/api/v1/checklist/${itemId}/complete`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({ completed: true });

      expect(res.status).toBe(200);
      expect(res.body.data.is_completed).toBe(true);
    });
  });
});
```

### E2E Tests

**File:** `tests/e2e/checklist.spec.ts` (Playwright)

```typescript
import { test, expect } from '@playwright/test';

test.describe('Checklist Feature', () => {
  test('consultant can auto-generate checklist from report', async ({ page }) => {
    await page.goto('/assessments/123');
    await page.click('button:has-text("Generate Checklist")');

    await expect(page.locator('.checklist-items')).toBeVisible();
    await expect(page.locator('.checklist-item')).toHaveCount(12);
  });

  test('client can mark items complete and add notes', async ({ page }) => {
    await page.goto('/client/assessments/123/checklist');

    // Mark first item complete
    await page.check('.checklist-item:first-child input[type="checkbox"]');
    await expect(page.locator('.checklist-item:first-child')).toHaveClass(/completed/);

    // Add notes
    await page.click('.checklist-item:first-child button:has-text("Add Note")');
    await page.fill('textarea[name="client_notes"]', 'Completed with help from accountant');
    await page.click('button:has-text("Save Note")');

    await expect(page.locator('.client-note')).toContainText('Completed with help');
  });

  test('progress indicator updates as items are completed', async ({ page }) => {
    await page.goto('/assessments/123/checklist');

    const initialProgress = await page.locator('.progress-percentage').textContent();
    expect(initialProgress).toBe('0%');

    // Complete 5 out of 10 items
    for (let i = 0; i < 5; i++) {
      await page.check(`.checklist-item:nth-child(${i + 1}) input[type="checkbox"]`);
    }

    await expect(page.locator('.progress-percentage')).toHaveText('50%');
  });
});
```

---

**Document Version:** 1.0
**Author:** Backend Developer 1
**Last Updated:** 2025-12-22
**Status:** Ready for Implementation
