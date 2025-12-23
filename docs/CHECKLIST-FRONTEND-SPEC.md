# Checklist Frontend - Technical Specification

**Version:** 1.0
**Date:** 2025-12-22
**Work Stream:** 30 - Checklist Frontend
**Phase:** 2 - Enhanced Engagement
**Dependency Level:** 1

## Table of Contents

1. [Overview](#overview)
2. [Component Architecture](#component-architecture)
3. [UI/UX Design Specifications](#uiux-design-specifications)
4. [State Management](#state-management)
5. [API Integration](#api-integration)
6. [Real-Time Updates](#real-time-updates)
7. [Accessibility Implementation](#accessibility-implementation)
8. [Implementation Guide](#implementation-guide)
9. [Testing Strategy](#testing-strategy)

---

## Overview

### Purpose

The Checklist Frontend provides an intuitive, collaborative interface for consultants and clients to manage action items derived from assessment reports. The interface adapts based on user role (consultant vs client) with appropriate permissions.

### Key Features

1. **Role-Based UI:**
   - Consultants: Full CRUD operations
   - Clients: Mark complete, add notes

2. **Visual Progress Tracking:**
   - Progress bars by phase
   - Overall completion percentage
   - Visual completion indicators

3. **Collaborative Editing:**
   - Real-time updates (optional polling)
   - Activity indicators ("John marked item complete")
   - Optimistic UI updates

4. **Phase Organization:**
   - Items grouped by financial phase
   - Collapsible sections
   - Phase-specific colors

5. **Mobile-Responsive:**
   - Touch-friendly checkboxes
   - Swipe gestures for quick actions
   - Responsive card layout

### Requirements

From Work Stream 30:
- Create checklist UI components
- Implement collaborative editing UI
- Add checklist to report view
- Add checklist to dashboard quick actions
- Implement real-time updates (polling)
- Accessibility compliance (WCAG 2.1 Level AA)

---

## Component Architecture

### Component Hierarchy

```
ChecklistContainer
├── ChecklistHeader
│   ├── ProgressOverview
│   └── ChecklistActions (consultant only)
│       ├── AddItemButton
│       ├── GenerateFromReportButton
│       └── ReorderModeToggle
├── ChecklistPhaseSection (x5 phases)
│   ├── PhaseSectionHeader
│   │   ├── PhaseTitle
│   │   ├── PhaseProgress
│   │   └── CollapseToggle
│   └── ChecklistItemList
│       └── ChecklistItem (x N items)
│           ├── ItemCheckbox
│           ├── ItemContent
│           │   ├── ItemTitle
│           │   ├── ItemDescription
│           │   └── ItemMetadata (priority, completed date)
│           ├── ClientNotes (client only)
│           │   ├── NotesTextarea
│           │   └── NotesSaveButton
│           └── ItemActions (consultant only)
│               ├── EditButton
│               ├── DeleteButton
│               └── DragHandle (reorder mode)
└── EmptyState (when no items)
```

### File Structure

```
src/
├── components/
│   └── Checklist/
│       ├── ChecklistContainer.tsx
│       ├── ChecklistHeader.tsx
│       ├── ProgressOverview.tsx
│       ├── ChecklistActions.tsx
│       ├── ChecklistPhaseSection.tsx
│       ├── PhaseSectionHeader.tsx
│       ├── ChecklistItemList.tsx
│       ├── ChecklistItem.tsx
│       ├── ItemCheckbox.tsx
│       ├── ItemContent.tsx
│       ├── ClientNotes.tsx
│       ├── ItemActions.tsx
│       ├── AddItemModal.tsx
│       ├── EditItemModal.tsx
│       ├── EmptyState.tsx
│       └── __tests__/
│           ├── ChecklistContainer.test.tsx
│           ├── ChecklistItem.test.tsx
│           └── ClientNotes.test.tsx
├── hooks/
│   ├── useChecklist.ts
│   ├── useChecklistItem.ts
│   ├── useChecklistPolling.ts
│   └── __tests__/
│       └── useChecklist.test.ts
├── services/
│   └── api/
│       └── checklistApi.ts
└── types/
    └── checklist.types.ts
```

---

## UI/UX Design Specifications

### Color Scheme by Phase

```typescript
const PHASE_COLORS = {
  Stabilize: {
    primary: '#DC3545',    // Red
    light: '#F8D7DA',
    dark: '#C82333'
  },
  Organize: {
    primary: '#FD7E14',    // Orange
    light: '#FFE5D0',
    dark: '#E66A00'
  },
  Build: {
    primary: '#FFC107',    // Gold
    light: '#FFF3CD',
    dark: '#E0A800'
  },
  Grow: {
    primary: '#28A745',    // Green
    light: '#D4EDDA',
    dark: '#218838'
  },
  Systemic: {
    primary: '#007BFF',    // Blue
    light: '#CCE5FF',
    dark: '#0056B3'
  }
};
```

### Layout - Consultant View

```
┌──────────────────────────────────────────────────────────┐
│  Action Item Checklist                                    │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│                                                            │
│  Overall Progress: 7 of 12 items complete (58%)           │
│  ████████████████░░░░░░░░                                 │
│                                                            │
│  [+ Add Item] [↻ Generate from Report] [⇅ Reorder]       │
│                                                            │
├──────────────────────────────────────────────────────────┤
│  ▼ STABILIZE (2/2 complete) ────────────────────────     │
│     ████████████████████████ 100%                         │
│                                                            │
│     ☑ Reconcile bank accounts for last 6 months          │
│        Priority: High | Completed: Dec 20, 2025          │
│        [Edit] [Delete]                                    │
│                                                            │
│     ☑ Set up emergency fund (3 months expenses)          │
│        Priority: High | Completed: Dec 21, 2025          │
│        [Edit] [Delete]                                    │
│                                                            │
├──────────────────────────────────────────────────────────┤
│  ▼ BUILD (3/5 complete) ─────────────────────────────    │
│     ████████████░░░░░░░░ 60%                              │
│                                                            │
│     ☑ Create SOPs for month-end close                    │
│        Priority: High | Completed: Dec 22, 2025          │
│        [Edit] [Delete]                                    │
│                                                            │
│     ☐ Implement invoice automation                        │
│        Priority: Medium                                   │
│        [Edit] [Delete]                                    │
│                                                            │
│     ☐ Set up financial dashboard (QuickBooks Online)     │
│        Priority: Medium                                   │
│        [Edit] [Delete]                                    │
│                                                            │
└──────────────────────────────────────────────────────────┘
```

### Layout - Client View

```
┌──────────────────────────────────────────────────────────┐
│  Your Action Plan                                         │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│                                                            │
│  You're making great progress!                            │
│  7 of 12 items complete (58%)                             │
│  ████████████████░░░░░░░░                                 │
│                                                            │
├──────────────────────────────────────────────────────────┤
│  ▼ STABILIZE - Foundation (All done! ✓)                  │
│                                                            │
│     ☑ Reconcile bank accounts for last 6 months          │
│        Completed: Dec 20, 2025                            │
│                                                            │
│        💬 My Notes:                                        │
│        "Completed with help from bookkeeper. Found $500   │
│         discrepancy that was resolved."                   │
│                                                            │
├──────────────────────────────────────────────────────────┤
│  ▼ BUILD - Operational Systems (3 of 5 complete)         │
│     ████████████░░░░░░░░ 60%                              │
│                                                            │
│     ☑ Create SOPs for month-end close                    │
│        Completed: Dec 22, 2025                            │
│                                                            │
│     ☐ Implement invoice automation                        │
│        [✓ Mark as Complete]                               │
│        💬 Add a note (optional)                           │
│        ┌─────────────────────────────────────────┐       │
│        │ Working on this with my accountant...   │       │
│        └─────────────────────────────────────────┘       │
│        [Save Note]                                        │
│                                                            │
└──────────────────────────────────────────────────────────┘
```

### Mobile Layout (< 768px)

```
┌─────────────────────────┐
│  Action Plan            │
│  ━━━━━━━━━━━━━━━━━━━  │
│                         │
│  7/12 complete          │
│  ████████░░░            │
│                         │
│  [+ Add] [↻] [⇅]       │
│                         │
├─────────────────────────┤
│  ▼ STABILIZE (2/2) ✓   │
│                         │
│  ☑ Reconcile banks     │
│     Dec 20, 2025        │
│     [···]               │
│                         │
│  ☑ Emergency fund      │
│     Dec 21, 2025        │
│     [···]               │
│                         │
├─────────────────────────┤
│  ▼ BUILD (3/5)         │
│  ████░░ 60%            │
│                         │
│  ☑ Create SOPs         │
│     [···]               │
│                         │
│  ☐ Invoice automation  │
│     [···]               │
│                         │
└─────────────────────────┘
```

### Component Design Specs

#### ChecklistItem - Consultant View

```tsx
<Card className="checklist-item">
  <CardContent>
    <Box display="flex" alignItems="start" gap={2}>
      {/* Drag handle (reorder mode only) */}
      {isReorderMode && (
        <DragHandle className="drag-handle" />
      )}

      {/* Checkbox */}
      <Checkbox
        checked={item.is_completed}
        onChange={handleToggleComplete}
        size="large"
        sx={{ mt: -1 }}
      />

      {/* Content */}
      <Box flex={1}>
        <Typography
          variant="h6"
          sx={{
            textDecoration: item.is_completed ? 'line-through' : 'none',
            color: item.is_completed ? 'text.secondary' : 'text.primary'
          }}
        >
          {item.title}
        </Typography>

        {item.description && (
          <Typography variant="body2" color="text.secondary" mt={0.5}>
            {item.description}
          </Typography>
        )}

        {/* Metadata */}
        <Box display="flex" gap={2} mt={1} flexWrap="wrap">
          {/* Priority badge */}
          <Chip
            label={getPriorityLabel(item.priority)}
            size="small"
            color={getPriorityColor(item.priority)}
          />

          {/* Phase badge */}
          <Chip
            label={item.phase}
            size="small"
            sx={{
              bgcolor: PHASE_COLORS[item.phase].light,
              color: PHASE_COLORS[item.phase].dark
            }}
          />

          {/* Completion date */}
          {item.completed_at && (
            <Typography variant="caption" color="text.secondary">
              ✓ Completed: {formatDate(item.completed_at)}
            </Typography>
          )}
        </Box>
      </Box>

      {/* Actions (consultant only) */}
      <Box display="flex" gap={1}>
        <IconButton onClick={handleEdit} size="small">
          <EditIcon />
        </IconButton>
        <IconButton onClick={handleDelete} size="small" color="error">
          <DeleteIcon />
        </IconButton>
      </Box>
    </Box>
  </CardContent>
</Card>
```

#### ChecklistItem - Client View with Notes

```tsx
<Card className="checklist-item client-view">
  <CardContent>
    <Box display="flex" alignItems="start" gap={2}>
      {/* Checkbox */}
      <Checkbox
        checked={item.is_completed}
        onChange={handleToggleComplete}
        size="large"
        sx={{ mt: -1 }}
      />

      {/* Content */}
      <Box flex={1}>
        <Typography
          variant="h6"
          sx={{
            textDecoration: item.is_completed ? 'line-through' : 'none'
          }}
        >
          {item.title}
        </Typography>

        {item.description && (
          <Typography variant="body2" color="text.secondary" mt={0.5}>
            {item.description}
          </Typography>
        )}

        {/* Completion date */}
        {item.completed_at && (
          <Typography variant="caption" color="success.main" mt={1} display="block">
            ✓ Completed on {formatDate(item.completed_at)}
          </Typography>
        )}

        {/* Client notes section */}
        <Box mt={2} p={2} bgcolor="grey.50" borderRadius={1}>
          <Typography variant="subtitle2" gutterBottom>
            💬 My Notes
          </Typography>

          {isEditingNotes ? (
            <>
              <TextField
                multiline
                rows={3}
                fullWidth
                value={notesValue}
                onChange={(e) => setNotesValue(e.target.value)}
                placeholder="Add notes about your progress on this item..."
                variant="outlined"
                size="small"
              />
              <Box mt={1} display="flex" gap={1} justifyContent="flex-end">
                <Button size="small" onClick={handleCancelNotes}>
                  Cancel
                </Button>
                <Button
                  size="small"
                  variant="contained"
                  onClick={handleSaveNotes}
                  disabled={isSaving}
                >
                  {isSaving ? 'Saving...' : 'Save Note'}
                </Button>
              </Box>
            </>
          ) : (
            <>
              {item.client_notes ? (
                <Typography variant="body2" whiteSpace="pre-wrap">
                  {item.client_notes}
                </Typography>
              ) : (
                <Typography variant="body2" color="text.secondary" fontStyle="italic">
                  No notes yet. Click to add notes about your progress.
                </Typography>
              )}
              <Button
                size="small"
                onClick={() => setIsEditingNotes(true)}
                sx={{ mt: 1 }}
              >
                {item.client_notes ? 'Edit Note' : 'Add Note'}
              </Button>
            </>
          )}

          {item.client_notes_updated_at && (
            <Typography variant="caption" color="text.secondary" display="block" mt={1}>
              Last updated: {formatDate(item.client_notes_updated_at)}
            </Typography>
          )}
        </Box>
      </Box>
    </Box>
  </CardContent>
</Card>
```

#### Progress Overview Component

```tsx
<Box className="progress-overview" mb={3}>
  <Typography variant="h6" gutterBottom>
    {userRole === 'consultant'
      ? 'Overall Progress'
      : "You're making great progress!"}
  </Typography>

  <Box display="flex" alignItems="center" gap={2} mb={2}>
    <Box flex={1}>
      <LinearProgress
        variant="determinate"
        value={progressPercentage}
        sx={{
          height: 12,
          borderRadius: 6,
          bgcolor: 'grey.200',
          '& .MuiLinearProgress-bar': {
            borderRadius: 6,
            bgcolor: getProgressColor(progressPercentage)
          }
        }}
      />
    </Box>
    <Typography variant="h6" color="text.secondary" minWidth={80}>
      {progressPercentage}%
    </Typography>
  </Box>

  <Typography variant="body2" color="text.secondary">
    {completedCount} of {totalCount} items complete
  </Typography>

  {/* Phase breakdown */}
  <Grid container spacing={2} mt={2}>
    {PHASES.map(phase => (
      <Grid item xs={12} sm={6} md={4} key={phase}>
        <Box
          p={1.5}
          borderRadius={1}
          bgcolor={PHASE_COLORS[phase].light}
          borderLeft={`4px solid ${PHASE_COLORS[phase].primary}`}
        >
          <Typography variant="subtitle2" fontWeight="bold">
            {phase}
          </Typography>
          <Typography variant="caption" color="text.secondary">
            {getPhaseProgress(phase).completed} of{' '}
            {getPhaseProgress(phase).total} complete
          </Typography>
        </Box>
      </Grid>
    ))}
  </Grid>
</Box>
```

---

## State Management

### Custom Hook: `useChecklist`

**File:** `src/hooks/useChecklist.ts`

```typescript
import { useState, useEffect, useCallback } from 'react';
import { checklistApi } from '@/services/api/checklistApi';
import { ChecklistData, ChecklistItem } from '@/types/checklist.types';

export function useChecklist(assessmentId: string) {
  const [checklist, setChecklist] = useState<ChecklistData | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const [isPolling, setIsPolling] = useState(false);

  // Fetch checklist
  const fetchChecklist = useCallback(async () => {
    try {
      setError(null);
      const data = await checklistApi.getChecklist(assessmentId);
      setChecklist(data);
    } catch (err) {
      setError(err as Error);
    } finally {
      setIsLoading(false);
    }
  }, [assessmentId]);

  // Auto-generate checklist from report
  const generateFromReport = useCallback(async () => {
    try {
      setIsLoading(true);
      const data = await checklistApi.generateFromReport(assessmentId);
      setChecklist(data.checklist);
      return data;
    } catch (err) {
      setError(err as Error);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [assessmentId]);

  // Toggle item completion
  const toggleItemComplete = useCallback(async (
    itemId: string,
    completed: boolean
  ) => {
    // Optimistic update
    setChecklist(prev => {
      if (!prev) return prev;
      return updateItemInChecklist(prev, itemId, { is_completed: completed });
    });

    try {
      await checklistApi.toggleComplete(itemId, completed);
      // Refetch to get server state (completed_at, completed_by)
      await fetchChecklist();
    } catch (err) {
      // Rollback optimistic update
      setChecklist(prev => {
        if (!prev) return prev;
        return updateItemInChecklist(prev, itemId, { is_completed: !completed });
      });
      throw err;
    }
  }, [fetchChecklist]);

  // Update client notes
  const updateClientNotes = useCallback(async (
    itemId: string,
    notes: string
  ) => {
    try {
      await checklistApi.updateItem(itemId, { client_notes: notes });
      await fetchChecklist();
    } catch (err) {
      setError(err as Error);
      throw err;
    }
  }, [fetchChecklist]);

  // Add new item (consultant only)
  const addItem = useCallback(async (
    itemData: Partial<ChecklistItem>
  ) => {
    try {
      await checklistApi.createItem(assessmentId, itemData);
      await fetchChecklist();
    } catch (err) {
      setError(err as Error);
      throw err;
    }
  }, [assessmentId, fetchChecklist]);

  // Update item (consultant only)
  const updateItem = useCallback(async (
    itemId: string,
    updates: Partial<ChecklistItem>
  ) => {
    try {
      await checklistApi.updateItem(itemId, updates);
      await fetchChecklist();
    } catch (err) {
      setError(err as Error);
      throw err;
    }
  }, [fetchChecklist]);

  // Delete item (consultant only)
  const deleteItem = useCallback(async (itemId: string) => {
    try {
      await checklistApi.deleteItem(itemId);
      await fetchChecklist();
    } catch (err) {
      setError(err as Error);
      throw err;
    }
  }, [fetchChecklist]);

  // Reorder items (consultant only)
  const reorderItems = useCallback(async (
    items: Array<{ id: string; sort_order: number }>
  ) => {
    try {
      await checklistApi.reorderItems(assessmentId, items);
      await fetchChecklist();
    } catch (err) {
      setError(err as Error);
      throw err;
    }
  }, [assessmentId, fetchChecklist]);

  // Initial fetch
  useEffect(() => {
    fetchChecklist();
  }, [fetchChecklist]);

  // Polling for real-time updates (every 30 seconds)
  useEffect(() => {
    if (!isPolling) return;

    const interval = setInterval(() => {
      fetchChecklist();
    }, 30000); // 30 seconds

    return () => clearInterval(interval);
  }, [isPolling, fetchChecklist]);

  return {
    checklist,
    isLoading,
    error,
    isPolling,
    setIsPolling,
    actions: {
      fetchChecklist,
      generateFromReport,
      toggleItemComplete,
      updateClientNotes,
      addItem,
      updateItem,
      deleteItem,
      reorderItems
    }
  };
}

// Helper function
function updateItemInChecklist(
  checklist: ChecklistData,
  itemId: string,
  updates: Partial<ChecklistItem>
): ChecklistData {
  const updatedItemsByPhase = { ...checklist.items_by_phase };

  Object.keys(updatedItemsByPhase).forEach(phase => {
    updatedItemsByPhase[phase] = {
      ...updatedItemsByPhase[phase],
      items: updatedItemsByPhase[phase].items.map(item =>
        item.id === itemId ? { ...item, ...updates } : item
      )
    };
  });

  return { ...checklist, items_by_phase: updatedItemsByPhase };
}
```

---

## API Integration

### API Service Layer

**File:** `src/services/api/checklistApi.ts`

```typescript
import { apiClient } from './client';
import { ChecklistData, ChecklistItem } from '@/types/checklist.types';

export const checklistApi = {
  /**
   * Get checklist for an assessment
   */
  async getChecklist(assessmentId: string): Promise<ChecklistData> {
    const response = await apiClient.get(
      `/assessments/${assessmentId}/checklist`
    );
    return response.data.data;
  },

  /**
   * Auto-generate checklist from report
   */
  async generateFromReport(assessmentId: string) {
    const response = await apiClient.post(
      `/assessments/${assessmentId}/checklist`,
      { auto_generate: true }
    );
    return response.data.data;
  },

  /**
   * Create a new checklist item
   */
  async createItem(
    assessmentId: string,
    itemData: Partial<ChecklistItem>
  ): Promise<ChecklistItem> {
    const response = await apiClient.post(
      `/assessments/${assessmentId}/checklist`,
      itemData
    );
    return response.data.data;
  },

  /**
   * Update checklist item
   */
  async updateItem(
    itemId: string,
    updates: Partial<ChecklistItem>
  ): Promise<ChecklistItem> {
    const response = await apiClient.patch(`/checklist/${itemId}`, updates);
    return response.data.data;
  },

  /**
   * Delete checklist item
   */
  async deleteItem(itemId: string): Promise<void> {
    await apiClient.delete(`/checklist/${itemId}`);
  },

  /**
   * Toggle item completion
   */
  async toggleComplete(
    itemId: string,
    completed: boolean
  ): Promise<ChecklistItem> {
    const response = await apiClient.post(`/checklist/${itemId}/complete`, {
      completed
    });
    return response.data.data;
  },

  /**
   * Reorder checklist items
   */
  async reorderItems(
    assessmentId: string,
    items: Array<{ id: string; sort_order: number }>
  ): Promise<void> {
    await apiClient.patch(`/assessments/${assessmentId}/checklist/reorder`, {
      items
    });
  }
};
```

---

## Real-Time Updates

### Polling Implementation

```typescript
// In ChecklistContainer component
export function ChecklistContainer({ assessmentId, userRole }: Props) {
  const {
    checklist,
    isLoading,
    isPolling,
    setIsPolling,
    actions
  } = useChecklist(assessmentId);

  // Enable polling when component mounts, disable on unmount
  useEffect(() => {
    setIsPolling(true);
    return () => setIsPolling(false);
  }, [setIsPolling]);

  // Show update notification when changes detected
  const [lastUpdateTime, setLastUpdateTime] = useState<Date | null>(null);
  const [showUpdateNotification, setShowUpdateNotification] = useState(false);

  useEffect(() => {
    if (checklist && lastUpdateTime) {
      const hasUpdates = checklist.items_by_phase.some(phase =>
        phase.items.some(item =>
          new Date(item.updated_at) > lastUpdateTime
        )
      );

      if (hasUpdates) {
        setShowUpdateNotification(true);
        setTimeout(() => setShowUpdateNotification(false), 5000);
      }
    }

    if (checklist) {
      setLastUpdateTime(new Date());
    }
  }, [checklist]);

  return (
    <>
      {/* Update notification */}
      <Snackbar
        open={showUpdateNotification}
        autoHideDuration={5000}
        onClose={() => setShowUpdateNotification(false)}
        message="Checklist updated"
      />

      {/* Checklist content */}
      {/* ... */}
    </>
  );
}
```

### WebSocket Alternative (Future Enhancement)

```typescript
// WebSocket hook for real-time updates
export function useChecklistWebSocket(assessmentId: string) {
  const [socket, setSocket] = useState<WebSocket | null>(null);

  useEffect(() => {
    const ws = new WebSocket(
      `${process.env.REACT_APP_WS_URL}/checklist/${assessmentId}`
    );

    ws.onmessage = (event) => {
      const message = JSON.parse(event.data);

      switch (message.type) {
        case 'item_completed':
          // Update UI
          showNotification(`${message.user_name} marked an item as complete`);
          break;
        case 'item_added':
          // Refetch checklist
          break;
        case 'item_updated':
          // Update specific item
          break;
      }
    };

    setSocket(ws);

    return () => {
      ws.close();
    };
  }, [assessmentId]);

  return socket;
}
```

---

## Accessibility Implementation

### WCAG 2.1 Level AA Compliance

#### Keyboard Navigation

```typescript
// ChecklistItem component
export function ChecklistItem({ item, onToggle }: Props) {
  const handleKeyDown = (e: React.KeyboardEvent) => {
    // Space or Enter to toggle checkbox
    if (e.key === ' ' || e.key === 'Enter') {
      e.preventDefault();
      onToggle(item.id, !item.is_completed);
    }
  };

  return (
    <div
      role="checkbox"
      aria-checked={item.is_completed}
      tabIndex={0}
      onKeyDown={handleKeyDown}
      aria-label={`${item.title}. ${item.is_completed ? 'Completed' : 'Not completed'}`}
    >
      {/* ... */}
    </div>
  );
}
```

#### ARIA Labels

```tsx
<Checkbox
  checked={item.is_completed}
  onChange={handleToggle}
  inputProps={{
    'aria-label': `Mark "${item.title}" as ${item.is_completed ? 'incomplete' : 'complete'}`
  }}
/>

<IconButton
  onClick={handleEdit}
  aria-label={`Edit ${item.title}`}
>
  <EditIcon />
</IconButton>

<IconButton
  onClick={handleDelete}
  aria-label={`Delete ${item.title}`}
>
  <DeleteIcon />
</IconButton>
```

#### Screen Reader Announcements

```typescript
// Use aria-live for dynamic updates
<div
  aria-live="polite"
  aria-atomic="true"
  className="sr-only"
>
  {announcement}
</div>

// Update announcement when item completed
const handleToggle = async (itemId: string, completed: boolean) => {
  await actions.toggleItemComplete(itemId, completed);

  setAnnouncement(
    completed
      ? `${item.title} marked as complete`
      : `${item.title} marked as incomplete`
  );
};
```

#### Color Contrast

- Ensure all text meets WCAG AA contrast ratios:
  - Normal text: 4.5:1
  - Large text (18px+): 3:1
  - UI components: 3:1

```typescript
// Use theme colors that meet contrast requirements
const theme = createTheme({
  palette: {
    primary: {
      main: '#4B006E', // Contrast ratio: 8.59:1 on white
    },
    text: {
      primary: '#000000', // 21:1 on white
      secondary: '#666666', // 5.74:1 on white
    }
  }
});
```

---

## Implementation Guide

### Step 1: Type Definitions

**File:** `src/types/checklist.types.ts`

```typescript
export interface ChecklistItem {
  id: string;
  assessment_id: string;
  title: string;
  description?: string;
  phase: 'Stabilize' | 'Organize' | 'Build' | 'Grow' | 'Systemic';
  priority: 0 | 1 | 2 | 3;
  sort_order: number;
  is_completed: boolean;
  completed_at?: string;
  completed_by?: {
    id: string;
    name: string;
    role: string;
  };
  client_notes?: string;
  client_notes_updated_at?: string;
  auto_generated: boolean;
  created_at: string;
  updated_at: string;
}

export interface PhaseItems {
  total: number;
  completed: number;
  items: ChecklistItem[];
}

export interface ChecklistData {
  assessment_id: string;
  total_items: number;
  completed_items: number;
  progress_percentage: number;
  items_by_phase: {
    Stabilize: PhaseItems;
    Organize: PhaseItems;
    Build: PhaseItems;
    Grow: PhaseItems;
    Systemic: PhaseItems;
  };
}
```

### Step 2: Main Container Component

**File:** `src/components/Checklist/ChecklistContainer.tsx`

```typescript
import React, { useState } from 'react';
import { Box, Alert, CircularProgress } from '@mui/material';
import { useChecklist } from '@/hooks/useChecklist';
import { useAuth } from '@/hooks/useAuth';
import { ChecklistHeader } from './ChecklistHeader';
import { ChecklistPhaseSection } from './ChecklistPhaseSection';
import { EmptyState } from './EmptyState';

interface Props {
  assessmentId: string;
}

export function ChecklistContainer({ assessmentId }: Props) {
  const { user } = useAuth();
  const {
    checklist,
    isLoading,
    error,
    setIsPolling,
    actions
  } = useChecklist(assessmentId);

  const [isReorderMode, setIsReorderMode] = useState(false);

  React.useEffect(() => {
    setIsPolling(true);
    return () => setIsPolling(false);
  }, [setIsPolling]);

  if (isLoading && !checklist) {
    return (
      <Box display="flex" justifyContent="center" py={8}>
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Alert severity="error">
        Failed to load checklist: {error.message}
      </Alert>
    );
  }

  if (!checklist) {
    return (
      <EmptyState
        userRole={user.role}
        onGenerateFromReport={actions.generateFromReport}
      />
    );
  }

  const phases = ['Stabilize', 'Organize', 'Build', 'Grow', 'Systemic'] as const;

  return (
    <Box>
      <ChecklistHeader
        checklist={checklist}
        userRole={user.role}
        isReorderMode={isReorderMode}
        onToggleReorderMode={() => setIsReorderMode(!isReorderMode)}
        onGenerateFromReport={actions.generateFromReport}
        onAddItem={actions.addItem}
      />

      {phases.map(phase => (
        <ChecklistPhaseSection
          key={phase}
          phase={phase}
          phaseData={checklist.items_by_phase[phase]}
          userRole={user.role}
          isReorderMode={isReorderMode}
          onToggleComplete={actions.toggleItemComplete}
          onUpdateNotes={actions.updateClientNotes}
          onEditItem={actions.updateItem}
          onDeleteItem={actions.deleteItem}
          onReorderItems={actions.reorderItems}
        />
      ))}
    </Box>
  );
}
```

### Step 3: Integration with Report View

```typescript
// In AssessmentReportView component
import { ChecklistContainer } from '@/components/Checklist/ChecklistContainer';

export function AssessmentReportView({ assessmentId }: Props) {
  const [activeTab, setActiveTab] = useState<'report' | 'checklist'>('report');

  return (
    <Box>
      <Tabs value={activeTab} onChange={(e, v) => setActiveTab(v)}>
        <Tab label="Report" value="report" />
        <Tab label="Action Items" value="checklist" />
      </Tabs>

      <TabPanel value="report" currentValue={activeTab}>
        <ReportContent assessmentId={assessmentId} />
      </TabPanel>

      <TabPanel value="checklist" currentValue={activeTab}>
        <ChecklistContainer assessmentId={assessmentId} />
      </TabPanel>
    </Box>
  );
}
```

### Step 4: Dashboard Quick Actions

```typescript
// In Dashboard component
<Card>
  <CardContent>
    <Typography variant="h6" gutterBottom>
      Recent Assessments
    </Typography>

    {assessments.map(assessment => (
      <Box key={assessment.id} display="flex" alignItems="center" py={1}>
        <Box flex={1}>
          <Typography variant="subtitle1">
            {assessment.client_name}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            {assessment.business_name}
          </Typography>
        </Box>

        {/* Quick checklist preview */}
        <Box>
          <Chip
            label={`${assessment.checklist_completed}/${assessment.checklist_total}`}
            size="small"
            color={
              assessment.checklist_completed === assessment.checklist_total
                ? 'success'
                : 'default'
            }
            icon={<ChecklistIcon />}
          />
        </Box>

        <IconButton
          component={Link}
          to={`/assessments/${assessment.id}/checklist`}
        >
          <ArrowForwardIcon />
        </IconButton>
      </Box>
    ))}
  </CardContent>
</Card>
```

---

## Testing Strategy

### Unit Tests

**File:** `src/components/Checklist/__tests__/ChecklistItem.test.tsx`

```typescript
import { render, screen, fireEvent } from '@testing-library/react';
import { ChecklistItem } from '../ChecklistItem';

describe('ChecklistItem', () => {
  const mockItem = {
    id: 'item-1',
    title: 'Test item',
    description: 'Test description',
    phase: 'Build',
    priority: 2,
    is_completed: false,
    // ... other required fields
  };

  it('renders item title and description', () => {
    render(<ChecklistItem item={mockItem} onToggle={jest.fn()} />);

    expect(screen.getByText('Test item')).toBeInTheDocument();
    expect(screen.getByText('Test description')).toBeInTheDocument();
  });

  it('calls onToggle when checkbox clicked', () => {
    const onToggle = jest.fn();
    render(<ChecklistItem item={mockItem} onToggle={onToggle} />);

    const checkbox = screen.getByRole('checkbox');
    fireEvent.click(checkbox);

    expect(onToggle).toHaveBeenCalledWith('item-1', true);
  });

  it('shows completed state correctly', () => {
    const completedItem = { ...mockItem, is_completed: true };
    render(<ChecklistItem item={completedItem} onToggle={jest.fn()} />);

    const checkbox = screen.getByRole('checkbox');
    expect(checkbox).toBeChecked();
  });

  it('shows client notes section for clients', () => {
    render(
      <ChecklistItem
        item={mockItem}
        userRole="client"
        onToggle={jest.fn()}
        onUpdateNotes={jest.fn()}
      />
    );

    expect(screen.getByText('My Notes')).toBeInTheDocument();
  });

  it('hides edit/delete actions for clients', () => {
    render(
      <ChecklistItem
        item={mockItem}
        userRole="client"
        onToggle={jest.fn()}
      />
    );

    expect(screen.queryByLabelText(/edit/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/delete/i)).not.toBeInTheDocument();
  });
});
```

### Integration Tests

```typescript
import { render, screen, waitFor } from '@testing-library/react';
import { ChecklistContainer } from '../ChecklistContainer';
import { checklistApi } from '@/services/api/checklistApi';

jest.mock('@/services/api/checklistApi');

describe('ChecklistContainer Integration', () => {
  it('loads and displays checklist', async () => {
    (checklistApi.getChecklist as jest.Mock).mockResolvedValue({
      total_items: 5,
      completed_items: 2,
      progress_percentage: 40,
      items_by_phase: {
        Build: {
          total: 3,
          completed: 1,
          items: [
            { id: '1', title: 'Item 1', is_completed: true },
            { id: '2', title: 'Item 2', is_completed: false }
          ]
        }
      }
    });

    render(<ChecklistContainer assessmentId="test-id" />);

    await waitFor(() => {
      expect(screen.getByText('Item 1')).toBeInTheDocument();
      expect(screen.getByText('Item 2')).toBeInTheDocument();
    });
  });

  it('handles item completion', async () => {
    // Test implementation
  });
});
```

### E2E Tests (Playwright)

```typescript
test('consultant can manage checklist items', async ({ page }) => {
  await page.goto('/assessments/123/checklist');

  // Add new item
  await page.click('button:has-text("Add Item")');
  await page.fill('input[name="title"]', 'New action item');
  await page.selectOption('select[name="phase"]', 'Build');
  await page.click('button:has-text("Save")');

  await expect(page.locator('text=New action item')).toBeVisible();

  // Mark item complete
  await page.check('input[type="checkbox"]');
  await expect(page.locator('.checklist-item')).toHaveClass(/completed/);
});

test('client can complete items and add notes', async ({ page }) => {
  await page.goto('/client/assessments/123/checklist');

  // Mark item complete
  await page.check('input[type="checkbox"] >> nth=0');

  // Add note
  await page.click('button:has-text("Add Note")');
  await page.fill('textarea', 'Completed this with my accountant');
  await page.click('button:has-text("Save Note")');

  await expect(page.locator('text=Completed this with my accountant')).toBeVisible();
});
```

---

**Document Version:** 1.0
**Author:** Frontend Developer 1
**Last Updated:** 2025-12-22
**Status:** Ready for Implementation
