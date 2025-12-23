# Scheduler Integration Frontend - Technical Specification

**Version:** 1.0
**Date:** 2025-12-22
**Work Stream:** 31 - Scheduler Integration Frontend
**Phase:** 2 - Enhanced Engagement
**Dependency Level:** 1

## Table of Contents

1. [Overview](#overview)
2. [Component Architecture](#component-architecture)
3. [UI/UX Design Specifications](#uiux-design-specifications)
4. [Scheduler Settings Page](#scheduler-settings-page)
5. [Client Report Integration](#client-report-integration)
6. [Implementation Guide](#implementation-guide)
7. [Testing Strategy](#testing-strategy)

---

## Overview

### Purpose

The Scheduler Integration Frontend enables consultants to configure external scheduler links (Calendly, Acuity, etc.) and automatically displays these in client reports with phase-appropriate meeting recommendations.

### Key Features

1. **Scheduler Configuration:**
   - Add/edit scheduler provider settings
   - Configure multiple meeting types
   - Preview how scheduler appears in reports

2. **Meeting Type Management:**
   - Create meeting types with durations
   - Assign to specific financial phases
   - Set priority order

3. **Report Integration:**
   - Automatically embed scheduler in client reports
   - DISC-adapted copy for scheduler section
   - Click tracking

4. **Analytics Dashboard:**
   - Track scheduler link clicks
   - Monitor booking conversion rates
   - View engagement by phase

### Requirements

From Work Stream 31:
- Create scheduler settings page
- Add/edit scheduler links
- Configure meeting types
- Preview scheduler display
- Add scheduler links to client report display
- Create scheduler recommendation UI
- Test iframe/URL embedding
- Accessibility compliance

---

## Component Architecture

### Component Hierarchy

```
SchedulerSettings
├── SchedulerConfigurationCard
│   ├── ProviderSelection
│   ├── URLInput
│   ├── EmbedCodeInput
│   └── DisplaySettings
├── MeetingTypesManager
│   ├── MeetingTypesList
│   │   └── MeetingTypeCard (x N)
│   │       ├── MeetingTypeForm
│   │       ├── PhaseSelector
│   │       └── PrioritySlider
│   └── AddMeetingTypeButton
├── SchedulerPreview
│   ├── PreviewByPhase
│   └── IframeEmbed
└── SchedulerAnalytics
    ├── ClicksChart
    ├── BookingsChart
    └── ConversionMetrics

ClientReportScheduler
├── SchedulerSectionHeader (DISC-adapted)
├── RecommendedMeetingsList
│   └── MeetingTypeDisplay
│       ├── MeetingDetails
│       ├── ScheduleButton (tracked)
│       └── DurationBadge
└── EmbeddedScheduler (optional iframe)
```

### File Structure

```
src/
├── components/
│   └── Scheduler/
│       ├── Settings/
│       │   ├── SchedulerSettings.tsx
│       │   ├── SchedulerConfigurationCard.tsx
│       │   ├── MeetingTypesManager.tsx
│       │   ├── MeetingTypeCard.tsx
│       │   ├── MeetingTypeForm.tsx
│       │   └── SchedulerPreview.tsx
│       ├── Report/
│       │   ├── ClientReportScheduler.tsx
│       │   ├── SchedulerSectionHeader.tsx
│       │   ├── RecommendedMeetingsList.tsx
│       │   ├── MeetingTypeDisplay.tsx
│       │   └── EmbeddedScheduler.tsx
│       ├── Analytics/
│       │   └── SchedulerAnalytics.tsx
│       └── __tests__/
│           ├── SchedulerSettings.test.tsx
│           ├── ClientReportScheduler.test.tsx
│           └── MeetingTypeForm.test.tsx
├── hooks/
│   ├── useSchedulerSettings.ts
│   ├── useMeetingTypes.ts
│   └── useSchedulerTracking.ts
├── services/
│   └── api/
│       └── schedulerApi.ts
└── types/
    └── scheduler.types.ts
```

---

## UI/UX Design Specifications

### Scheduler Settings Page Layout

```
┌────────────────────────────────────────────────────────────┐
│  Scheduler Integration Settings                            │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│                                                              │
│  Configure your scheduler links to appear automatically in  │
│  client reports. Clients can book follow-up calls directly. │
│                                                              │
├────────────────────────────────────────────────────────────┤
│  1. SCHEDULER PROVIDER                                      │
│  ┌────────────────────────────────────────────────────┐    │
│  │  Provider: [Calendly ▼]                            │    │
│  │                                                      │    │
│  │  Scheduler URL: *                                   │    │
│  │  ┌────────────────────────────────────────────┐    │    │
│  │  │ https://calendly.com/johndoe-consulting   │    │    │
│  │  └────────────────────────────────────────────┘    │    │
│  │                                                      │    │
│  │  Display Name:                                      │    │
│  │  ┌────────────────────────────────────────────┐    │    │
│  │  │ Book a Call with John                      │    │    │
│  │  └────────────────────────────────────────────┘    │    │
│  │                                                      │    │
│  │  Description:                                       │    │
│  │  ┌────────────────────────────────────────────┐    │    │
│  │  │ Schedule time to discuss your action plan │    │    │
│  │  │ and next steps.                            │    │    │
│  │  └────────────────────────────────────────────┘    │    │
│  │                                                      │    │
│  │  ☑ Show in client reports                          │    │
│  │  ☐ Embed iframe (shows calendar directly)          │    │
│  │                                                      │    │
│  │  [Save Settings]                                    │    │
│  └────────────────────────────────────────────────────┘    │
│                                                              │
├────────────────────────────────────────────────────────────┤
│  2. MEETING TYPES                                           │
│                                                              │
│  Define different meeting types for different phases.       │
│  [+ Add Meeting Type]                                       │
│                                                              │
│  ┌────────────────────────────────────────────────────┐    │
│  │  30-Minute Strategy Session                        │    │
│  │  Duration: 30 minutes                               │    │
│  │  Recommended for: Stabilize, Organize, Build       │    │
│  │  Priority: ████████░░ 8                            │    │
│  │  URL: calendly.com/johndoe/30min-strategy          │    │
│  │                                                      │    │
│  │  Description:                                       │    │
│  │  "Discuss your top priorities and create an        │    │
│  │   implementation plan"                              │    │
│  │                                                      │    │
│  │  [Edit] [Delete] [↑ ↓]                             │    │
│  └────────────────────────────────────────────────────┘    │
│                                                              │
│  ┌────────────────────────────────────────────────────┐    │
│  │  60-Minute Deep Dive                               │    │
│  │  Duration: 60 minutes                               │    │
│  │  Recommended for: Build, Grow                       │    │
│  │  Priority: ██████░░░░ 6                            │    │
│  │  URL: calendly.com/johndoe/60min-deepdive          │    │
│  │  [Edit] [Delete] [↑ ↓]                             │    │
│  └────────────────────────────────────────────────────┘    │
│                                                              │
├────────────────────────────────────────────────────────────┤
│  3. PREVIEW                                                  │
│                                                              │
│  Preview for: [Build Phase ▼] [D-Profile ▼]               │
│                                                              │
│  ┌────────────────────────────────────────────────────┐    │
│  │  Let's Discuss Your Next Steps                     │    │
│  │                                                      │    │
│  │  Ready to move forward? Book a strategy session    │    │
│  │  to create your implementation plan.                │    │
│  │                                                      │    │
│  │  30-Minute Strategy Session                         │    │
│  │  Duration: 30 minutes                               │    │
│  │  Discuss your top priorities and create an         │    │
│  │  implementation plan                                │    │
│  │  [Schedule Your Strategy Session →]                │    │
│  │                                                      │    │
│  │  60-Minute Deep Dive                                │    │
│  │  Duration: 60 minutes                               │    │
│  │  Comprehensive review and roadmap                   │    │
│  │  [Schedule a Deep Dive →]                          │    │
│  └────────────────────────────────────────────────────┘    │
│                                                              │
└────────────────────────────────────────────────────────────┘
```

### Client Report Scheduler Section

**D-Profile, Build Phase:**

```
┌────────────────────────────────────────────────────────────┐
│  Let's Discuss Your Next Steps                             │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│                                                              │
│  Ready to move forward? Book a strategy session to create   │
│  your implementation plan and hit the ground running.       │
│                                                              │
│  ┌────────────────────────────────────────────────────┐    │
│  │  ⏱ 30-Minute Strategy Session                      │    │
│  │  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │    │
│  │  What We'll Cover:                                  │    │
│  │  • Review your top 3 priority actions               │    │
│  │  • Create a 90-day implementation timeline          │    │
│  │  • Identify quick wins to build momentum            │    │
│  │                                                      │    │
│  │  [Schedule Your Strategy Session →]                │    │
│  └────────────────────────────────────────────────────┘    │
│                                                              │
│  ┌────────────────────────────────────────────────────┐    │
│  │  ⏱ 60-Minute Deep Dive (Optional)                  │    │
│  │  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │    │
│  │  What We'll Cover:                                  │    │
│  │  • Comprehensive review of financial systems        │    │
│  │  • Detailed implementation roadmap                  │    │
│  │  • Team roles and responsibilities                  │    │
│  │                                                      │    │
│  │  [Schedule a Deep Dive →]                          │    │
│  └────────────────────────────────────────────────────┘    │
│                                                              │
└────────────────────────────────────────────────────────────┘
```

**S-Profile, Stabilize Phase (with embedded iframe):**

```
┌────────────────────────────────────────────────────────────┐
│  Let's Work Together on Your Next Steps                    │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│                                                              │
│  You don't have to do this alone. I'm here to support you  │
│  every step of the way.                                     │
│                                                              │
│  Let's schedule a call to review your action plan and make │
│  sure you feel comfortable with the next steps.             │
│                                                              │
│  ┌────────────────────────────────────────────────────┐    │
│  │  ⏱ 30-Minute Support Call                          │    │
│  │  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │    │
│  │  What We'll Discuss:                                │    │
│  │  • Walk through your action items at a             │    │
│  │    comfortable pace                                 │    │
│  │  • Answer any questions you have                    │    │
│  │  • Create a step-by-step plan that works for you   │    │
│  │                                                      │    │
│  │  No pressure, no rush. We'll take this at your     │    │
│  │  pace.                                              │    │
│  │                                                      │    │
│  │  [Schedule a Call When You're Ready →]             │    │
│  └────────────────────────────────────────────────────┘    │
│                                                              │
│  ┌────────────────────────────────────────────────────┐    │
│  │  📅 Or pick a time directly:                        │    │
│  │                                                      │    │
│  │  ┌──────────────────────────────────────────────┐  │    │
│  │  │  [Embedded Calendly iframe]                  │  │    │
│  │  │                                              │  │    │
│  │  │  December 2025                               │  │    │
│  │  │  ┌────┬────┬────┬────┬────┬────┬────┐      │  │    │
│  │  │  │ Mo │ Tu │ We │ Th │ Fr │ Sa │ Su │      │  │    │
│  │  │  ├────┼────┼────┼────┼────┼────┼────┤      │  │    │
│  │  │  │ 23 │ 24 │ 25 │ 26 │ 27 │ 28 │ 29 │      │  │    │
│  │  │  └────┴────┴────┴────┴────┴────┴────┘      │  │    │
│  │  │                                              │  │    │
│  │  │  Available times on Dec 26:                 │  │    │
│  │  │  [10:00 AM] [2:00 PM] [4:00 PM]            │  │    │
│  │  └──────────────────────────────────────────────┘  │    │
│  └────────────────────────────────────────────────────┘    │
│                                                              │
└────────────────────────────────────────────────────────────┘
```

---

## Scheduler Settings Page

### Main Component

**File:** `src/components/Scheduler/Settings/SchedulerSettings.tsx`

```typescript
import React, { useState } from 'react';
import {
  Box,
  Container,
  Typography,
  Paper,
  Alert,
  CircularProgress
} from '@mui/material';
import { useSchedulerSettings } from '@/hooks/useSchedulerSettings';
import { useMeetingTypes } from '@/hooks/useMeetingTypes';
import { SchedulerConfigurationCard } from './SchedulerConfigurationCard';
import { MeetingTypesManager } from './MeetingTypesManager';
import { SchedulerPreview } from './SchedulerPreview';

export function SchedulerSettings() {
  const {
    settings,
    isLoading: settingsLoading,
    error: settingsError,
    updateSettings
  } = useSchedulerSettings();

  const {
    meetingTypes,
    isLoading: typesLoading,
    error: typesError,
    addMeetingType,
    updateMeetingType,
    deleteMeetingType
  } = useMeetingTypes();

  const [previewPhase, setPreviewPhase] = useState<string>('Build');
  const [previewProfile, setPreviewProfile] = useState<string>('D');

  if (settingsLoading || typesLoading) {
    return (
      <Box display="flex" justifyContent="center" py={8}>
        <CircularProgress />
      </Box>
    );
  }

  const error = settingsError || typesError;

  return (
    <Container maxWidth="lg">
      <Box py={4}>
        <Typography variant="h4" gutterBottom>
          Scheduler Integration Settings
        </Typography>
        <Typography variant="body1" color="text.secondary" paragraph>
          Configure your scheduler links to appear automatically in client reports.
          Clients can book follow-up calls directly.
        </Typography>

        {error && (
          <Alert severity="error" sx={{ mb: 3 }}>
            {error.message}
          </Alert>
        )}

        {/* 1. Scheduler Configuration */}
        <Paper sx={{ p: 3, mb: 3 }}>
          <Typography variant="h6" gutterBottom>
            1. Scheduler Provider
          </Typography>
          <SchedulerConfigurationCard
            settings={settings}
            onUpdate={updateSettings}
          />
        </Paper>

        {/* 2. Meeting Types */}
        <Paper sx={{ p: 3, mb: 3 }}>
          <Typography variant="h6" gutterBottom>
            2. Meeting Types
          </Typography>
          <Typography variant="body2" color="text.secondary" paragraph>
            Define different meeting types for different phases.
          </Typography>
          <MeetingTypesManager
            meetingTypes={meetingTypes}
            onAdd={addMeetingType}
            onUpdate={updateMeetingType}
            onDelete={deleteMeetingType}
          />
        </Paper>

        {/* 3. Preview */}
        <Paper sx={{ p: 3 }}>
          <Typography variant="h6" gutterBottom>
            3. Preview
          </Typography>
          <SchedulerPreview
            settings={settings}
            meetingTypes={meetingTypes}
            phase={previewPhase}
            discProfile={previewProfile}
            onPhaseChange={setPreviewPhase}
            onProfileChange={setPreviewProfile}
          />
        </Paper>
      </Box>
    </Container>
  );
}
```

### Meeting Type Form

```typescript
export function MeetingTypeForm({
  meetingType,
  onSave,
  onCancel
}: Props) {
  const [formData, setFormData] = useState({
    name: meetingType?.name || '',
    duration_minutes: meetingType?.duration_minutes || 30,
    description: meetingType?.description || '',
    scheduler_event_url: meetingType?.scheduler_event_url || '',
    recommended_phases: meetingType?.recommended_phases || [],
    priority: meetingType?.priority || 5
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    await onSave(formData);
  };

  return (
    <form onSubmit={handleSubmit}>
      <TextField
        label="Meeting Name *"
        value={formData.name}
        onChange={(e) => setFormData({ ...formData, name: e.target.value })}
        fullWidth
        required
        margin="normal"
        placeholder="30-Minute Strategy Session"
      />

      <FormControl fullWidth margin="normal">
        <InputLabel>Duration</InputLabel>
        <Select
          value={formData.duration_minutes}
          onChange={(e) => setFormData({
            ...formData,
            duration_minutes: e.target.value as number
          })}
        >
          <MenuItem value={15}>15 minutes</MenuItem>
          <MenuItem value={30}>30 minutes</MenuItem>
          <MenuItem value={45}>45 minutes</MenuItem>
          <MenuItem value={60}>60 minutes</MenuItem>
          <MenuItem value={90}>90 minutes</MenuItem>
        </Select>
      </FormControl>

      <TextField
        label="Description"
        value={formData.description}
        onChange={(e) => setFormData({ ...formData, description: e.target.value })}
        fullWidth
        multiline
        rows={3}
        margin="normal"
        placeholder="Discuss your top priorities and create an implementation plan"
      />

      <TextField
        label="Scheduler Event URL"
        value={formData.scheduler_event_url}
        onChange={(e) => setFormData({
          ...formData,
          scheduler_event_url: e.target.value
        })}
        fullWidth
        margin="normal"
        placeholder="https://calendly.com/johndoe/30min-strategy"
      />

      <FormControl fullWidth margin="normal">
        <InputLabel>Recommended for Phases</InputLabel>
        <Select
          multiple
          value={formData.recommended_phases}
          onChange={(e) => setFormData({
            ...formData,
            recommended_phases: e.target.value as string[]
          })}
          renderValue={(selected) => (
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
              {selected.map((value) => (
                <Chip key={value} label={value} size="small" />
              ))}
            </Box>
          )}
        >
          {['Stabilize', 'Organize', 'Build', 'Grow', 'Systemic'].map((phase) => (
            <MenuItem key={phase} value={phase}>
              <Checkbox checked={formData.recommended_phases.includes(phase)} />
              <ListItemText primary={phase} />
            </MenuItem>
          ))}
        </Select>
        <FormHelperText>
          This meeting will be recommended for clients in these phases
        </FormHelperText>
      </FormControl>

      <Box mt={2}>
        <Typography gutterBottom>Priority: {formData.priority}</Typography>
        <Slider
          value={formData.priority}
          onChange={(e, value) => setFormData({ ...formData, priority: value as number })}
          min={0}
          max={10}
          marks
          valueLabelDisplay="auto"
        />
        <FormHelperText>
          Higher priority meetings appear first (0-10)
        </FormHelperText>
      </Box>

      <Box mt={3} display="flex" gap={2} justifyContent="flex-end">
        <Button onClick={onCancel}>Cancel</Button>
        <Button type="submit" variant="contained">
          Save Meeting Type
        </Button>
      </Box>
    </form>
  );
}
```

---

## Client Report Integration

### Scheduler Section Component

**File:** `src/components/Scheduler/Report/ClientReportScheduler.tsx`

```typescript
import React, { useEffect } from 'react';
import { Box, Typography, Paper } from '@mui/material';
import { useSchedulerSettings } from '@/hooks/useSchedulerSettings';
import { useMeetingTypes } from '@/hooks/useMeetingTypes';
import { useSchedulerTracking } from '@/hooks/useSchedulerTracking';
import { SchedulerSectionHeader } from './SchedulerSectionHeader';
import { RecommendedMeetingsList } from './RecommendedMeetingsList';
import { EmbeddedScheduler } from './EmbeddedScheduler';

interface Props {
  assessmentId: string;
  consultantId: string;
  primaryPhase: string;
  discProfile: string;
}

export function ClientReportScheduler({
  assessmentId,
  consultantId,
  primaryPhase,
  discProfile
}: Props) {
  const { settings } = useSchedulerSettings(consultantId);
  const { meetingTypes } = useMeetingTypes(consultantId);
  const { trackClick } = useSchedulerTracking();

  // Don't show if consultant hasn't configured scheduler
  if (!settings?.show_in_reports) {
    return null;
  }

  // Filter meeting types recommended for this phase
  const recommendedMeetings = meetingTypes
    .filter(mt =>
      mt.recommended_phases.includes(primaryPhase) && mt.is_active
    )
    .sort((a, b) => b.priority - a.priority)
    .slice(0, 3); // Show top 3

  // Fallback to top meetings if no phase-specific recommendations
  const meetings = recommendedMeetings.length > 0
    ? recommendedMeetings
    : meetingTypes.filter(mt => mt.is_active).slice(0, 2);

  const handleMeetingClick = (meetingTypeId: string) => {
    trackClick({
      assessment_id: assessmentId,
      consultant_id: consultantId,
      meeting_type_id: meetingTypeId
    });
  };

  return (
    <Paper sx={{ p: 4, my: 4 }}>
      <SchedulerSectionHeader
        discProfile={discProfile}
        primaryPhase={primaryPhase}
        consultantName={settings.display_name}
      />

      <RecommendedMeetingsList
        meetings={meetings}
        discProfile={discProfile}
        onMeetingClick={handleMeetingClick}
      />

      {settings.embed_in_reports && settings.embed_code && (
        <EmbeddedScheduler embedCode={settings.embed_code} />
      )}
    </Paper>
  );
}
```

### DISC-Adapted Headers

```typescript
export function SchedulerSectionHeader({
  discProfile,
  primaryPhase,
  consultantName
}: Props) {
  const headers = {
    D: "Let's Discuss Your Next Steps",
    I: "Let's Connect and Create Your Action Plan Together!",
    S: "Let's Work Together on Your Next Steps",
    C: "Schedule a Detailed Implementation Review"
  };

  const intros = {
    D: "Ready to move forward? Book a strategy session to create your implementation plan and hit the ground running.",
    I: "This is exciting! Let's schedule a call to discuss your roadmap and get you on the path to success.",
    S: `You don't have to do this alone. I'm here to support you every step of the way. Let's schedule a call to review your action plan at a comfortable pace.`,
    C: `Based on your ${primaryPhase} phase assessment, I recommend scheduling a detailed review to analyze implementation strategies and success metrics.`
  };

  return (
    <Box mb={3}>
      <Typography variant="h5" gutterBottom fontWeight="bold">
        {headers[discProfile]}
      </Typography>
      <Typography variant="body1" color="text.secondary">
        {intros[discProfile]}
      </Typography>
    </Box>
  );
}
```

### Meeting Type Display with Tracking

```typescript
export function MeetingTypeDisplay({
  meeting,
  onMeetingClick
}: Props) {
  const handleClick = () => {
    onMeetingClick(meeting.id);
    // Open scheduler URL
    window.open(meeting.scheduler_event_url, '_blank');
  };

  return (
    <Paper
      variant="outlined"
      sx={{
        p: 3,
        mb: 2,
        cursor: 'pointer',
        '&:hover': {
          bgcolor: 'action.hover',
          borderColor: 'primary.main'
        }
      }}
    >
      <Box display="flex" alignItems="start" gap={2}>
        <Box
          sx={{
            minWidth: 48,
            height: 48,
            borderRadius: '50%',
            bgcolor: 'primary.light',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}
        >
          <Typography variant="h6" color="primary.main">
            ⏱
          </Typography>
        </Box>

        <Box flex={1}>
          <Typography variant="h6" gutterBottom>
            {meeting.name}
          </Typography>

          <Chip
            label={`${meeting.duration_minutes} minutes`}
            size="small"
            sx={{ mb: 1 }}
          />

          {meeting.description && (
            <Typography variant="body2" color="text.secondary" paragraph>
              {meeting.description}
            </Typography>
          )}

          <Button
            variant="contained"
            onClick={handleClick}
            endIcon={<ArrowForwardIcon />}
            fullWidth
            sx={{ mt: 2 }}
          >
            Schedule Your {meeting.name}
          </Button>
        </Box>
      </Box>
    </Paper>
  );
}
```

---

## Implementation Guide

### Step 1: Type Definitions

```typescript
export interface SchedulerSettings {
  id: string;
  consultant_id: string;
  scheduler_provider: 'calendly' | 'acuity' | 'scheduleonce' | 'custom';
  scheduler_url: string;
  embed_code?: string;
  display_name?: string;
  description?: string;
  show_in_reports: boolean;
  embed_in_reports: boolean;
  created_at: string;
  updated_at: string;
}

export interface MeetingType {
  id: string;
  consultant_id: string;
  name: string;
  duration_minutes: 15 | 30 | 45 | 60 | 90 | 120;
  description?: string;
  scheduler_event_url?: string;
  recommended_phases: string[];
  priority: number;
  is_active: boolean;
  sort_order: number;
  created_at: string;
  updated_at: string;
}
```

### Step 2: Custom Hooks

```typescript
export function useSchedulerSettings(consultantId?: string) {
  const [settings, setSettings] = useState<SchedulerSettings | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  const fetchSettings = useCallback(async () => {
    try {
      const id = consultantId || getCurrentUserId();
      const data = await schedulerApi.getSettings(id);
      setSettings(data);
    } catch (err) {
      setError(err as Error);
    } finally {
      setIsLoading(false);
    }
  }, [consultantId]);

  const updateSettings = useCallback(async (
    updates: Partial<SchedulerSettings>
  ) => {
    try {
      const id = consultantId || getCurrentUserId();
      const updated = await schedulerApi.updateSettings(id, updates);
      setSettings(updated);
    } catch (err) {
      setError(err as Error);
      throw err;
    }
  }, [consultantId]);

  useEffect(() => {
    fetchSettings();
  }, [fetchSettings]);

  return {
    settings,
    isLoading,
    error,
    updateSettings,
    refetch: fetchSettings
  };
}
```

### Step 3: Tracking Implementation

```typescript
export function useSchedulerTracking() {
  const trackClick = useCallback(async (data: {
    assessment_id: string;
    consultant_id: string;
    meeting_type_id?: string;
  }) => {
    try {
      await schedulerApi.trackClick(data);
    } catch (err) {
      console.error('Failed to track scheduler click:', err);
      // Don't throw - tracking failure shouldn't break UX
    }
  }, []);

  return { trackClick };
}
```

---

## Testing Strategy

### Unit Tests

```typescript
describe('SchedulerSettings', () => {
  it('renders scheduler configuration form', () => {
    render(<SchedulerSettings />);
    expect(screen.getByLabelText(/scheduler url/i)).toBeInTheDocument();
  });

  it('saves scheduler settings', async () => {
    const onUpdate = jest.fn();
    render(<SchedulerConfigurationCard settings={mockSettings} onUpdate={onUpdate} />);

    fireEvent.change(screen.getByLabelText(/scheduler url/i), {
      target: { value: 'https://calendly.com/test' }
    });
    fireEvent.click(screen.getByText(/save settings/i));

    await waitFor(() => {
      expect(onUpdate).toHaveBeenCalledWith({
        scheduler_url: 'https://calendly.com/test'
      });
    });
  });
});
```

### E2E Tests

```typescript
test('consultant can configure scheduler', async ({ page }) => {
  await page.goto('/settings/scheduler');

  await page.fill('input[name="scheduler_url"]', 'https://calendly.com/test');
  await page.fill('input[name="display_name"]', 'Book a Call');
  await page.check('input[name="show_in_reports"]');
  await page.click('button:has-text("Save Settings")');

  await expect(page.locator('text=Settings saved')).toBeVisible();
});

test('client sees scheduler in report', async ({ page }) => {
  await page.goto('/client/reports/123');

  await expect(page.locator('text=Let\'s Discuss Your Next Steps')).toBeVisible();
  await expect(page.locator('text=30-Minute Strategy Session')).toBeVisible();

  // Click should open scheduler
  await page.click('button:has-text("Schedule")');
  // Verify new tab opened with Calendly URL
});
```

---

**Document Version:** 1.0
**Author:** Frontend Developer 2
**Last Updated:** 2025-12-22
**Status:** Ready for Implementation
