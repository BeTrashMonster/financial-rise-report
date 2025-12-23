# Scheduler Integration Backend - Technical Specification

**Version:** 1.0
**Date:** 2025-12-22
**Work Stream:** 27 - Scheduler Integration Backend
**Phase:** 2 - Enhanced Engagement
**Dependency Level:** 0

## Table of Contents

1. [Overview](#overview)
2. [Database Schema](#database-schema)
3. [API Specification](#api-specification)
4. [Report Integration](#report-integration)
5. [Scheduler Recommendation Logic](#scheduler-recommendation-logic)
6. [Implementation Guide](#implementation-guide)
7. [Testing Strategy](#testing-strategy)

---

## Overview

### Purpose

The Scheduler Integration system allows consultants to configure external scheduler links (Calendly, Acuity Scheduling, etc.) that are automatically embedded in client reports. Based on the client's financial phase, the system recommends appropriate meeting types to encourage follow-up engagements.

### Key Features

1. **Multi-Scheduler Support:** Configure links for Calendly, Acuity, ScheduleOnce, or custom URLs
2. **Meeting Type Configuration:** Define multiple meeting types with durations and descriptions
3. **Phase-Based Recommendations:** Automatically suggest relevant meeting types based on assessment phase
4. **Report Embedding:** Include scheduler links and embedded widgets in client reports
5. **Tracking:** Track which clients book meetings via scheduler links

### Requirements

From REQ-SCHEDULER-001 through REQ-SCHEDULER-003:
- Support external scheduler integrations (Calendly, Acuity, etc.)
- Include scheduler links in client reports
- Recommend meeting types based on financial phase
- Track scheduler engagement analytics

---

## Database Schema

### Table: `consultant_scheduler_settings`

```sql
CREATE TABLE consultant_scheduler_settings (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  consultant_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

  -- Scheduler configuration
  scheduler_provider VARCHAR(50) NOT NULL, -- 'calendly', 'acuity', 'scheduleonce', 'custom'
  scheduler_url VARCHAR(500) NOT NULL, -- Base scheduler URL
  embed_code TEXT, -- Optional iframe embed code

  -- Display settings
  display_name VARCHAR(200), -- e.g., "Book a Follow-Up Call"
  description TEXT, -- Description shown to clients
  show_in_reports BOOLEAN DEFAULT TRUE,
  embed_in_reports BOOLEAN DEFAULT FALSE, -- Show as iframe vs link

  -- Audit fields
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),

  CONSTRAINT scheduler_settings_provider_check CHECK (
    scheduler_provider IN ('calendly', 'acuity', 'scheduleonce', 'custom')
  ),
  CONSTRAINT scheduler_settings_unique_consultant UNIQUE (consultant_id)
);

-- Index
CREATE INDEX idx_scheduler_settings_consultant_id ON consultant_scheduler_settings(consultant_id);
```

### Table: `scheduler_meeting_types`

```sql
CREATE TABLE scheduler_meeting_types (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  consultant_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

  -- Meeting type details
  name VARCHAR(200) NOT NULL, -- e.g., "30-Minute Strategy Session"
  duration_minutes INT NOT NULL, -- 15, 30, 45, 60
  description TEXT,
  scheduler_event_url VARCHAR(500), -- Specific URL for this meeting type

  -- Phase recommendations
  recommended_phases TEXT[], -- Array of phases: ['Stabilize', 'Organize', 'Build']
  priority INT DEFAULT 0, -- Higher priority = shown first (0-10)

  -- Display settings
  is_active BOOLEAN DEFAULT TRUE,
  sort_order INT DEFAULT 0,

  -- Audit fields
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),

  CONSTRAINT meeting_types_duration_check CHECK (
    duration_minutes IN (15, 30, 45, 60, 90, 120)
  ),
  CONSTRAINT meeting_types_priority_check CHECK (
    priority BETWEEN 0 AND 10
  )
);

-- Indexes
CREATE INDEX idx_meeting_types_consultant_id ON scheduler_meeting_types(consultant_id);
CREATE INDEX idx_meeting_types_active ON scheduler_meeting_types(is_active);
CREATE INDEX idx_meeting_types_phases ON scheduler_meeting_types USING GIN(recommended_phases);
```

### Table: `scheduler_engagement_tracking`

```sql
CREATE TABLE scheduler_engagement_tracking (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  assessment_id UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  consultant_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  client_id UUID REFERENCES users(id) ON DELETE SET NULL,

  -- Tracking data
  meeting_type_id UUID REFERENCES scheduler_meeting_types(id) ON DELETE SET NULL,
  event_type VARCHAR(50) NOT NULL, -- 'link_clicked', 'meeting_booked', 'meeting_completed'
  scheduler_event_id VARCHAR(200), -- External scheduler's event ID (if available)

  -- Metadata
  clicked_at TIMESTAMPTZ,
  booked_at TIMESTAMPTZ,
  scheduled_for TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,

  -- Technical details
  ip_address INET,
  user_agent TEXT,
  referrer VARCHAR(500),

  -- Audit
  created_at TIMESTAMPTZ DEFAULT NOW(),

  CONSTRAINT tracking_event_type_check CHECK (
    event_type IN ('link_clicked', 'meeting_booked', 'meeting_completed', 'meeting_cancelled')
  )
);

-- Indexes
CREATE INDEX idx_scheduler_tracking_assessment_id ON scheduler_engagement_tracking(assessment_id);
CREATE INDEX idx_scheduler_tracking_consultant_id ON scheduler_engagement_tracking(consultant_id);
CREATE INDEX idx_scheduler_tracking_event_type ON scheduler_engagement_tracking(event_type);
CREATE INDEX idx_scheduler_tracking_created_at ON scheduler_engagement_tracking(created_at);
```

---

## API Specification

### Base URL

```
/api/v1
```

### Authentication

All endpoints require JWT authentication. Consultants can manage their own scheduler settings. Clients have read-only access when viewing reports.

---

### GET /consultants/:consultantId/scheduler-settings

**Description:** Retrieve consultant's scheduler configuration

**Auth:** Required (consultant must be accessing own settings or admin)

**Request:**
```http
GET /api/v1/consultants/c1a2b3c4-d5e6-7890-1234-567890abcdef/scheduler-settings
Authorization: Bearer <jwt_token>
```

**Response:** 200 OK
```json
{
  "success": true,
  "data": {
    "id": "s1a2b3c4-d5e6-7890-1234-567890abcdef",
    "consultant_id": "c1a2b3c4-d5e6-7890-1234-567890abcdef",
    "scheduler_provider": "calendly",
    "scheduler_url": "https://calendly.com/johndoe-consulting",
    "embed_code": "<iframe src=\"https://calendly.com/johndoe-consulting\" width=\"100%\" height=\"600\"></iframe>",
    "display_name": "Book a Follow-Up Call with John",
    "description": "Schedule a 30-minute call to discuss your action plan and next steps.",
    "show_in_reports": true,
    "embed_in_reports": true,
    "meeting_types": [
      {
        "id": "m1a2b3c4-d5e6-7890-1234-567890abcdef",
        "name": "30-Minute Strategy Session",
        "duration_minutes": 30,
        "description": "Discuss your top priorities and create an implementation plan",
        "scheduler_event_url": "https://calendly.com/johndoe-consulting/30min-strategy",
        "recommended_phases": ["Stabilize", "Organize", "Build"],
        "priority": 10,
        "is_active": true,
        "sort_order": 0
      },
      {
        "id": "m2a3b4c5-d6e7-8901-2345-67890abcdef1",
        "name": "60-Minute Deep Dive",
        "duration_minutes": 60,
        "description": "In-depth review of your financial systems and growth strategy",
        "scheduler_event_url": "https://calendly.com/johndoe-consulting/60min-deepdive",
        "recommended_phases": ["Build", "Grow"],
        "priority": 8,
        "is_active": true,
        "sort_order": 1
      }
    ],
    "created_at": "2025-12-15T10:00:00Z",
    "updated_at": "2025-12-20T14:30:00Z"
  }
}
```

**Error Responses:**
- `401 Unauthorized` - Invalid token
- `403 Forbidden` - Accessing another consultant's settings
- `404 Not Found` - Scheduler settings not configured

---

### PATCH /consultants/:consultantId/scheduler-settings

**Description:** Update scheduler configuration

**Auth:** Required (consultant updating own settings)

**Request:**
```http
PATCH /api/v1/consultants/c1a2b3c4-d5e6-7890-1234-567890abcdef/scheduler-settings
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "scheduler_provider": "calendly",
  "scheduler_url": "https://calendly.com/johndoe-consulting",
  "embed_code": "<iframe src=\"https://calendly.com/johndoe-consulting\" width=\"100%\" height=\"600\"></iframe>",
  "display_name": "Book a Call with John",
  "description": "Let's discuss your financial roadmap",
  "show_in_reports": true,
  "embed_in_reports": true
}
```

**Response:** 200 OK
```json
{
  "success": true,
  "data": {
    "id": "s1a2b3c4-d5e6-7890-1234-567890abcdef",
    "consultant_id": "c1a2b3c4-d5e6-7890-1234-567890abcdef",
    "scheduler_provider": "calendly",
    "scheduler_url": "https://calendly.com/johndoe-consulting",
    "display_name": "Book a Call with John",
    "show_in_reports": true,
    "updated_at": "2025-12-22T15:45:00Z"
  },
  "message": "Scheduler settings updated successfully"
}
```

**Validation:**
- `scheduler_provider` must be one of: calendly, acuity, scheduleonce, custom
- `scheduler_url` must be valid URL (2048 char max)
- `display_name` max 200 characters
- `embed_code` max 5000 characters

**Error Responses:**
- `400 Bad Request` - Validation error
- `401 Unauthorized` - Invalid token
- `403 Forbidden` - Updating another consultant's settings

---

### POST /consultants/:consultantId/scheduler-settings/meeting-types

**Description:** Create a new meeting type

**Auth:** Required (consultant)

**Request:**
```http
POST /api/v1/consultants/c1a2b3c4-d5e6-7890-1234-567890abcdef/scheduler-settings/meeting-types
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "name": "15-Minute Quick Check-In",
  "duration_minutes": 15,
  "description": "Quick call to answer questions and check progress",
  "scheduler_event_url": "https://calendly.com/johndoe-consulting/15min-checkin",
  "recommended_phases": ["Build", "Grow", "Systemic"],
  "priority": 5,
  "is_active": true
}
```

**Response:** 201 Created
```json
{
  "success": true,
  "data": {
    "id": "m3a4b5c6-d7e8-9012-3456-7890abcdef12",
    "consultant_id": "c1a2b3c4-d5e6-7890-1234-567890abcdef",
    "name": "15-Minute Quick Check-In",
    "duration_minutes": 15,
    "description": "Quick call to answer questions and check progress",
    "scheduler_event_url": "https://calendly.com/johndoe-consulting/15min-checkin",
    "recommended_phases": ["Build", "Grow", "Systemic"],
    "priority": 5,
    "is_active": true,
    "sort_order": 2,
    "created_at": "2025-12-22T16:00:00Z"
  }
}
```

**Validation:**
- `name` required, 1-200 characters
- `duration_minutes` must be 15, 30, 45, 60, 90, or 120
- `scheduler_event_url` valid URL
- `recommended_phases` array of valid phases
- `priority` 0-10

---

### PATCH /scheduler-settings/meeting-types/:meetingTypeId

**Description:** Update a meeting type

**Auth:** Required (consultant who owns the meeting type)

**Request:**
```http
PATCH /api/v1/scheduler-settings/meeting-types/m3a4b5c6-d7e8-9012-3456-7890abcdef12
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "name": "15-Minute Check-In (Updated)",
  "priority": 7,
  "is_active": false
}
```

**Response:** 200 OK

---

### DELETE /scheduler-settings/meeting-types/:meetingTypeId

**Description:** Delete a meeting type

**Auth:** Required (consultant)

**Request:**
```http
DELETE /api/v1/scheduler-settings/meeting-types/m3a4b5c6-d7e8-9012-3456-7890abcdef12
Authorization: Bearer <jwt_token>
```

**Response:** 200 OK
```json
{
  "success": true,
  "message": "Meeting type deleted successfully"
}
```

---

### POST /scheduler/track-click

**Description:** Track when a client clicks a scheduler link (called from client report)

**Auth:** Optional (can be tracked anonymously or with client token)

**Request:**
```http
POST /api/v1/scheduler/track-click
Content-Type: application/json

{
  "assessment_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
  "consultant_id": "c1a2b3c4-d5e6-7890-1234-567890abcdef",
  "meeting_type_id": "m1a2b3c4-d5e6-7890-1234-567890abcdef",
  "referrer": "https://financialrise.com/client/reports/a1b2c3d4"
}
```

**Response:** 200 OK
```json
{
  "success": true,
  "message": "Click tracked successfully"
}
```

---

### GET /consultants/:consultantId/scheduler-analytics

**Description:** Get scheduler engagement analytics for consultant

**Auth:** Required (consultant or admin)

**Request:**
```http
GET /api/v1/consultants/c1a2b3c4-d5e6-7890-1234-567890abcdef/scheduler-analytics
Authorization: Bearer <jwt_token>

Query Parameters:
  ?start_date=2025-12-01  # Filter by date range
  ?end_date=2025-12-31
```

**Response:** 200 OK
```json
{
  "success": true,
  "data": {
    "summary": {
      "total_clicks": 47,
      "total_bookings": 12,
      "conversion_rate": 25.5,
      "total_completed": 9
    },
    "by_meeting_type": [
      {
        "meeting_type_id": "m1a2b3c4-d5e6-7890-1234-567890abcdef",
        "name": "30-Minute Strategy Session",
        "clicks": 32,
        "bookings": 10,
        "completed": 7,
        "conversion_rate": 31.25
      },
      {
        "meeting_type_id": "m2a3b4c5-d6e7-8901-2345-67890abcdef1",
        "name": "60-Minute Deep Dive",
        "clicks": 15,
        "bookings": 2,
        "completed": 2,
        "conversion_rate": 13.33
      }
    ],
    "by_phase": {
      "Stabilize": { "clicks": 8, "bookings": 2 },
      "Organize": { "clicks": 5, "bookings": 1 },
      "Build": { "clicks": 23, "bookings": 6 },
      "Grow": { "clicks": 11, "bookings": 3 }
    },
    "recent_bookings": [
      {
        "assessment_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
        "client_name": "ABC Corp",
        "meeting_type": "30-Minute Strategy Session",
        "booked_at": "2025-12-20T14:30:00Z",
        "scheduled_for": "2025-12-27T10:00:00Z",
        "status": "scheduled"
      }
    ]
  }
}
```

---

## Report Integration

### How Scheduler Links Appear in Reports

When a client report is generated, the system includes scheduler links/embeds based on:
1. Consultant's scheduler settings (`show_in_reports = true`)
2. Client's primary financial phase
3. Meeting types recommended for that phase

### Report Section Structure

**Location in Client Report:** After "Action Plan" section, before "Resources & Support"

**Section Title:** "Let's Discuss Your Next Steps"

**Example (DISC D-Profile, Build Phase):**

```markdown
## Let's Discuss Your Next Steps

**Ready to move forward?** Book a strategy session to create your implementation plan.

Based on your BUILD phase priorities, I recommend:

### 30-Minute Strategy Session
**Duration:** 30 minutes
**What We'll Cover:**
- Review your top 3 priority actions
- Create a 90-day implementation timeline
- Identify quick wins to build momentum

[Schedule Your Strategy Session →](https://calendly.com/johndoe-consulting/30min-strategy)

---

### Optional: 60-Minute Deep Dive
**Duration:** 60 minutes
**What We'll Cover:**
- Comprehensive review of financial systems
- Detailed implementation roadmap
- Team roles and responsibilities

[Schedule a Deep Dive →](https://calendly.com/johndoe-consulting/60min-deepdive)
```

**Example (DISC S-Profile, Stabilize Phase):**

```markdown
## Let's Work Together on Your Next Steps

**You don't have to do this alone.** I'm here to support you every step of the way.

Let's schedule a call to review your action plan and make sure you feel comfortable with the next steps.

### 30-Minute Support Call
**Duration:** 30 minutes
**What We'll Discuss:**
- Walk through your action items at a comfortable pace
- Answer any questions you have
- Create a step-by-step plan that works for you

**No pressure, no rush.** We'll take this at your pace.

[Schedule a Call When You're Ready →](https://calendly.com/johndoe-consulting/30min-strategy)

<iframe src="https://calendly.com/johndoe-consulting/30min-strategy" width="100%" height="600" frameborder="0"></iframe>
```

### Implementation in Report Generation

**File:** `src/services/reportGenerationService.ts`

```typescript
async function generateClientReport(assessmentId: string) {
  // ... existing report generation logic

  // Get consultant's scheduler settings
  const schedulerSettings = await getSchedulerSettings(assessment.consultant_id);

  if (schedulerSettings && schedulerSettings.show_in_reports) {
    // Get recommended meeting types for this phase
    const recommendedMeetings = await getRecommendedMeetingTypes(
      assessment.consultant_id,
      assessment.primary_phase
    );

    // Generate scheduler section
    const schedulerSection = generateSchedulerSection(
      schedulerSettings,
      recommendedMeetings,
      assessment.disc_profile,
      assessment.primary_phase
    );

    // Insert into report before "Resources & Support"
    reportData.sections.splice(-2, 0, schedulerSection);
  }

  return reportData;
}

function generateSchedulerSection(
  settings: SchedulerSettings,
  meetings: MeetingType[],
  discProfile: string,
  phase: string
) {
  // DISC-adapted copy
  const sectionTitle = getSchedulerTitle(discProfile);
  const sectionIntro = getSchedulerIntro(discProfile, phase);

  let sectionHTML = `
    <div class="scheduler-section">
      <h2>${sectionTitle}</h2>
      <p>${sectionIntro}</p>
  `;

  // Add each recommended meeting type
  for (const meeting of meetings) {
    sectionHTML += `
      <div class="meeting-type">
        <h3>${meeting.name}</h3>
        <p><strong>Duration:</strong> ${meeting.duration_minutes} minutes</p>
        <p>${meeting.description}</p>
        <a href="${meeting.scheduler_event_url}?utm_source=financial_rise&utm_medium=report&utm_campaign=phase_${phase.toLowerCase()}"
           class="scheduler-link btn btn-primary"
           onclick="trackSchedulerClick('${meeting.id}')">
          Schedule Your ${meeting.name} →
        </a>
      </div>
    `;
  }

  // Optionally embed iframe
  if (settings.embed_in_reports && settings.embed_code) {
    sectionHTML += `
      <div class="scheduler-embed">
        ${settings.embed_code}
      </div>
    `;
  }

  sectionHTML += `</div>`;

  return sectionHTML;
}
```

---

## Scheduler Recommendation Logic

### Phase-Based Meeting Type Recommendations

The system recommends meeting types based on the client's primary phase:

| Phase | Recommended Meeting Types | Priority |
|-------|-------------------------|----------|
| **Stabilize** | Quick check-in calls (15-30 min) | Address urgent concerns |
| **Organize** | Strategy sessions (30-45 min) | Plan foundational setup |
| **Build** | Deep dives (60 min) | Detailed implementation planning |
| **Grow** | Growth strategy sessions (60-90 min) | Long-term planning |
| **Systemic** | Advisory retainer calls (30 min recurring) | Ongoing support |

### Recommendation Algorithm

```typescript
async function getRecommendedMeetingTypes(
  consultantId: string,
  clientPhase: string
): Promise<MeetingType[]> {
  // Get all active meeting types for this consultant
  const allMeetingTypes = await MeetingType.findAll({
    where: {
      consultant_id: consultantId,
      is_active: true
    },
    order: [['priority', 'DESC'], ['sort_order', 'ASC']]
  });

  // Filter to those recommended for this phase
  const recommendedTypes = allMeetingTypes.filter(mt =>
    mt.recommended_phases.includes(clientPhase)
  );

  // If no phase-specific recommendations, return top 2 by priority
  if (recommendedTypes.length === 0) {
    return allMeetingTypes.slice(0, 2);
  }

  // Return top 3 recommended types
  return recommendedTypes.slice(0, 3);
}
```

### DISC-Adapted Scheduler Copy

```typescript
function getSchedulerTitle(discProfile: string): string {
  const titles = {
    D: "Let's Discuss Your Next Steps",
    I: "Let's Connect and Create Your Action Plan Together!",
    S: "Let's Work Together on Your Next Steps",
    C: "Schedule a Detailed Implementation Review"
  };
  return titles[discProfile] || "Schedule a Follow-Up Call";
}

function getSchedulerIntro(discProfile: string, phase: string): string {
  const intros = {
    D: `Ready to move forward? Book a strategy session to create your implementation plan and hit the ground running.`,
    I: `This is exciting! Let's schedule a call to discuss your roadmap and get you on the path to success.`,
    S: `You don't have to do this alone. I'm here to support you every step of the way. Let's schedule a call to review your action plan at a comfortable pace.`,
    C: `Based on your ${phase} phase assessment, I recommend scheduling a detailed review to analyze implementation strategies and success metrics.`
  };
  return intros[discProfile] || "Schedule a call to discuss your next steps.";
}
```

---

## Implementation Guide

### Step 1: Database Migration

**File:** `migrations/2025-12-22-create-scheduler-tables.sql`

```sql
-- See Database Schema section above
```

Run migration:
```bash
npm run migrate:up
```

### Step 2: Create Data Models

**File:** `src/models/SchedulerSettings.ts`

```typescript
import { Model, DataTypes } from 'sequelize';
import { sequelize } from '../config/database';

export class SchedulerSettings extends Model {
  public id!: string;
  public consultant_id!: string;
  public scheduler_provider!: string;
  public scheduler_url!: string;
  public embed_code?: string;
  public display_name?: string;
  public description?: string;
  public show_in_reports!: boolean;
  public embed_in_reports!: boolean;
  public created_at!: Date;
  public updated_at!: Date;
}

SchedulerSettings.init(
  {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true
    },
    consultant_id: {
      type: DataTypes.UUID,
      allowNull: false,
      unique: true,
      references: { model: 'users', key: 'id' }
    },
    scheduler_provider: {
      type: DataTypes.STRING(50),
      allowNull: false,
      validate: {
        isIn: [['calendly', 'acuity', 'scheduleonce', 'custom']]
      }
    },
    scheduler_url: {
      type: DataTypes.STRING(500),
      allowNull: false,
      validate: { isUrl: true }
    },
    embed_code: {
      type: DataTypes.TEXT
    },
    display_name: {
      type: DataTypes.STRING(200)
    },
    description: {
      type: DataTypes.TEXT
    },
    show_in_reports: {
      type: DataTypes.BOOLEAN,
      defaultValue: true
    },
    embed_in_reports: {
      type: DataTypes.BOOLEAN,
      defaultValue: false
    }
  },
  {
    sequelize,
    tableName: 'consultant_scheduler_settings',
    timestamps: true,
    underscored: true
  }
);
```

**File:** `src/models/MeetingType.ts`

```typescript
import { Model, DataTypes } from 'sequelize';
import { sequelize } from '../config/database';

export class MeetingType extends Model {
  public id!: string;
  public consultant_id!: string;
  public name!: string;
  public duration_minutes!: number;
  public description?: string;
  public scheduler_event_url?: string;
  public recommended_phases!: string[];
  public priority!: number;
  public is_active!: boolean;
  public sort_order!: number;
  public created_at!: Date;
  public updated_at!: Date;
}

MeetingType.init(
  {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true
    },
    consultant_id: {
      type: DataTypes.UUID,
      allowNull: false,
      references: { model: 'users', key: 'id' }
    },
    name: {
      type: DataTypes.STRING(200),
      allowNull: false
    },
    duration_minutes: {
      type: DataTypes.INTEGER,
      allowNull: false,
      validate: {
        isIn: [[15, 30, 45, 60, 90, 120]]
      }
    },
    description: {
      type: DataTypes.TEXT
    },
    scheduler_event_url: {
      type: DataTypes.STRING(500),
      validate: { isUrl: true }
    },
    recommended_phases: {
      type: DataTypes.ARRAY(DataTypes.STRING),
      defaultValue: []
    },
    priority: {
      type: DataTypes.INTEGER,
      defaultValue: 0,
      validate: { min: 0, max: 10 }
    },
    is_active: {
      type: DataTypes.BOOLEAN,
      defaultValue: true
    },
    sort_order: {
      type: DataTypes.INTEGER,
      defaultValue: 0
    }
  },
  {
    sequelize,
    tableName: 'scheduler_meeting_types',
    timestamps: true,
    underscored: true
  }
);
```

### Step 3: Create Service Layer

**File:** `src/services/schedulerService.ts`

```typescript
import { SchedulerSettings } from '../models/SchedulerSettings';
import { MeetingType } from '../models/MeetingType';

export class SchedulerService {
  async getSchedulerSettings(consultantId: string) {
    const settings = await SchedulerSettings.findOne({
      where: { consultant_id: consultantId },
      include: [
        {
          model: MeetingType,
          as: 'meeting_types',
          where: { is_active: true },
          required: false,
          order: [['priority', 'DESC'], ['sort_order', 'ASC']]
        }
      ]
    });

    return settings;
  }

  async updateSchedulerSettings(
    consultantId: string,
    updates: Partial<SchedulerSettings>
  ) {
    const [settings, created] = await SchedulerSettings.upsert({
      consultant_id: consultantId,
      ...updates
    });

    return settings;
  }

  async getRecommendedMeetingTypes(
    consultantId: string,
    clientPhase: string
  ) {
    const allTypes = await MeetingType.findAll({
      where: {
        consultant_id: consultantId,
        is_active: true
      },
      order: [['priority', 'DESC'], ['sort_order', 'ASC']]
    });

    // Filter by phase
    const recommended = allTypes.filter(mt =>
      mt.recommended_phases.includes(clientPhase)
    );

    return recommended.length > 0 ? recommended.slice(0, 3) : allTypes.slice(0, 2);
  }

  async trackSchedulerClick(data: {
    assessment_id: string;
    consultant_id: string;
    meeting_type_id?: string;
    referrer?: string;
  }) {
    // Insert into tracking table
    await SchedulerEngagementTracking.create({
      ...data,
      event_type: 'link_clicked',
      clicked_at: new Date()
    });
  }

  async getSchedulerAnalytics(
    consultantId: string,
    startDate?: Date,
    endDate?: Date
  ) {
    // Implementation for analytics queries
    // Aggregate clicks, bookings, conversion rates
  }
}
```

### Step 4: Create Routes and Controllers

**File:** `src/controllers/schedulerController.ts`
**File:** `src/routes/schedulerRoutes.ts`

(Similar structure to checklist - see full implementation in codebase)

---

## Testing Strategy

### Unit Tests

```typescript
describe('SchedulerService', () => {
  describe('getRecommendedMeetingTypes', () => {
    it('should return phase-specific meeting types', async () => {
      const types = await service.getRecommendedMeetingTypes(
        'consultant-id',
        'Build'
      );

      expect(types.every(t => t.recommended_phases.includes('Build'))).toBe(true);
    });

    it('should return top 2 types if no phase match', async () => {
      const types = await service.getRecommendedMeetingTypes(
        'consultant-id',
        'NonExistentPhase'
      );

      expect(types.length).toBe(2);
    });
  });
});
```

### Integration Tests

```typescript
describe('Scheduler API', () => {
  it('should update scheduler settings', async () => {
    const res = await request(app)
      .patch(`/api/v1/consultants/${consultantId}/scheduler-settings`)
      .send({
        scheduler_provider: 'calendly',
        scheduler_url: 'https://calendly.com/test'
      });

    expect(res.status).toBe(200);
  });
});
```

---

**Document Version:** 1.0
**Author:** Backend Developer 2
**Last Updated:** 2025-12-22
**Status:** Ready for Implementation
