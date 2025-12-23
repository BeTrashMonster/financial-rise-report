# Dashboard Enhancements Backend - Technical Specification

**Version:** 1.0
**Date:** 2025-12-22
**Work Stream:** 28 - Dashboard Enhancements Backend
**Phase:** 2 - Enhanced Engagement
**Dependency Level:** 0

## Table of Contents

1. [Overview](#overview)
2. [Database Schema Updates](#database-schema-updates)
3. [API Specification](#api-specification)
4. [Search Implementation](#search-implementation)
5. [Filtering Logic](#filtering-logic)
6. [Archive System](#archive-system)
7. [Performance Optimization](#performance-optimization)
8. [Implementation Guide](#implementation-guide)
9. [Testing Strategy](#testing-strategy)

---

## Overview

### Purpose

Dashboard Enhancements improve the consultant's ability to manage multiple assessments by adding powerful filtering, search, and archiving capabilities to the assessment list.

### Key Features

1. **Advanced Filtering:**
   - Filter by status (Draft, In Progress, Completed)
   - Filter by date range (created date, completion date)
   - Filter by client name
   - Combine multiple filters

2. **Full-Text Search:**
   - Search by client name, business name, or assessment notes
   - Auto-complete suggestions
   - Fast, indexed search

3. **Archive Management:**
   - Archive completed assessments
   - View archived assessments separately
   - Restore from archive
   - Bulk archive operations

4. **Completion Tracking:**
   - Display completion date/time
   - Track time-to-completion metrics
   - Show assessment duration

### Requirements

From Work Stream 28:
- Add filtering to assessment list endpoint
- Add search endpoint with auto-complete
- Add archive functionality
- Optimize query performance for large datasets

---

## Database Schema Updates

### Table Updates: `assessments`

Add new fields to existing `assessments` table:

```sql
ALTER TABLE assessments ADD COLUMN IF NOT EXISTS archived BOOLEAN DEFAULT FALSE;
ALTER TABLE assessments ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ;
ALTER TABLE assessments ADD COLUMN IF NOT EXISTS archived_by UUID REFERENCES users(id);
ALTER TABLE assessments ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ;
ALTER TABLE assessments ADD COLUMN IF NOT EXISTS search_vector TSVECTOR;

-- Create GIN index for full-text search
CREATE INDEX IF NOT EXISTS idx_assessments_search_vector ON assessments USING GIN(search_vector);

-- Indexes for filtering
CREATE INDEX IF NOT EXISTS idx_assessments_status ON assessments(status);
CREATE INDEX IF NOT EXISTS idx_assessments_created_at ON assessments(created_at);
CREATE INDEX IF NOT EXISTS idx_assessments_completed_at ON assessments(completed_at);
CREATE INDEX IF NOT EXISTS idx_assessments_archived ON assessments(archived);

-- Composite indexes for common filter combinations
CREATE INDEX IF NOT EXISTS idx_assessments_consultant_status_archived
  ON assessments(consultant_id, status, archived);

CREATE INDEX IF NOT EXISTS idx_assessments_consultant_created
  ON assessments(consultant_id, created_at DESC);
```

### Trigger: Update Search Vector

```sql
-- Function to update search vector
CREATE OR REPLACE FUNCTION assessments_search_vector_update()
RETURNS TRIGGER AS $$
BEGIN
  NEW.search_vector :=
    setweight(to_tsvector('english', COALESCE(NEW.client_name, '')), 'A') ||
    setweight(to_tsvector('english', COALESCE(NEW.business_name, '')), 'A') ||
    setweight(to_tsvector('english', COALESCE(NEW.notes, '')), 'B');
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to automatically update search vector
CREATE TRIGGER assessments_search_vector_trigger
  BEFORE INSERT OR UPDATE ON assessments
  FOR EACH ROW EXECUTE FUNCTION assessments_search_vector_update();

-- Backfill existing records
UPDATE assessments SET search_vector =
  setweight(to_tsvector('english', COALESCE(client_name, '')), 'A') ||
  setweight(to_tsvector('english', COALESCE(business_name, '')), 'A') ||
  setweight(to_tsvector('english', COALESCE(notes, '')), 'B')
WHERE search_vector IS NULL;
```

### New Table: `assessment_activity_log`

Track assessment lifecycle events for analytics:

```sql
CREATE TABLE assessment_activity_log (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  assessment_id UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,

  -- Event tracking
  event_type VARCHAR(50) NOT NULL, -- 'created', 'started', 'completed', 'archived', 'restored'
  event_timestamp TIMESTAMPTZ DEFAULT NOW(),

  -- User context
  user_id UUID REFERENCES users(id),
  user_role VARCHAR(50), -- 'consultant', 'client'

  -- Metadata
  metadata JSONB, -- Flexible field for event-specific data

  -- Audit
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_activity_log_assessment_id ON assessment_activity_log(assessment_id);
CREATE INDEX idx_activity_log_event_type ON assessment_activity_log(event_type);
CREATE INDEX idx_activity_log_event_timestamp ON assessment_activity_log(event_timestamp);
```

---

## API Specification

### Base URL

```
/api/v1
```

### Authentication

All endpoints require JWT authentication. Consultants can only access their own assessments.

---

### GET /assessments (Enhanced)

**Description:** Retrieve assessments with filtering, search, and pagination

**Auth:** Required (consultant)

**Query Parameters:**

| Parameter | Type | Description | Example |
|-----------|------|-------------|---------|
| `status` | string | Filter by status | `?status=In Progress` |
| `archived` | boolean | Include/exclude archived | `?archived=false` (default) |
| `start_date` | ISO date | Filter by created_at >= date | `?start_date=2025-12-01` |
| `end_date` | ISO date | Filter by created_at <= date | `?end_date=2025-12-31` |
| `completed_after` | ISO date | Filter by completed_at >= date | `?completed_after=2025-12-01` |
| `completed_before` | ISO date | Filter by completed_at <= date | `?completed_before=2025-12-31` |
| `client_name` | string | Filter by exact client name | `?client_name=John Smith` |
| `search` | string | Full-text search | `?search=ABC Corp` |
| `sort` | string | Sort field | `?sort=created_at` (default), `completed_at`, `client_name` |
| `order` | string | Sort order | `?order=desc` (default), `asc` |
| `page` | number | Page number (1-indexed) | `?page=1` |
| `limit` | number | Items per page (max 100) | `?limit=20` (default) |

**Request Examples:**

```http
# Get all active assessments (not archived)
GET /api/v1/assessments
Authorization: Bearer <jwt_token>

# Get completed assessments in December 2025
GET /api/v1/assessments?status=Completed&start_date=2025-12-01&end_date=2025-12-31
Authorization: Bearer <jwt_token>

# Search for "ABC Corp"
GET /api/v1/assessments?search=ABC Corp
Authorization: Bearer <jwt_token>

# Get archived assessments
GET /api/v1/assessments?archived=true
Authorization: Bearer <jwt_token>

# Multiple filters combined
GET /api/v1/assessments?status=Completed&completed_after=2025-12-01&sort=completed_at&order=desc
Authorization: Bearer <jwt_token>
```

**Response:** 200 OK

```json
{
  "success": true,
  "data": {
    "assessments": [
      {
        "id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
        "client_name": "John Smith",
        "business_name": "ABC Corporation",
        "status": "Completed",
        "primary_phase": "Build",
        "disc_profile": "D",
        "created_at": "2025-12-15T10:00:00Z",
        "updated_at": "2025-12-20T14:30:00Z",
        "completed_at": "2025-12-20T14:30:00Z",
        "time_to_complete_hours": 5.5,
        "archived": false,
        "progress_percentage": 100
      },
      {
        "id": "b2c3d4e5-f6a7-8901-2345-67890abcdef1",
        "client_name": "Jane Doe",
        "business_name": "XYZ Enterprises",
        "status": "In Progress",
        "primary_phase": null,
        "disc_profile": null,
        "created_at": "2025-12-18T09:00:00Z",
        "updated_at": "2025-12-21T11:15:00Z",
        "completed_at": null,
        "time_to_complete_hours": null,
        "archived": false,
        "progress_percentage": 65
      }
    ],
    "pagination": {
      "current_page": 1,
      "total_pages": 3,
      "total_items": 47,
      "items_per_page": 20,
      "has_next": true,
      "has_prev": false
    },
    "filters_applied": {
      "status": null,
      "archived": false,
      "date_range": null,
      "search_query": null
    },
    "summary": {
      "total_assessments": 47,
      "draft": 5,
      "in_progress": 12,
      "completed": 30,
      "archived": 0
    }
  }
}
```

**Performance Notes:**
- Results are cached for 60 seconds per consultant
- Pagination is required for >100 total results
- Complex queries may be slower; optimize indexes for common filter combinations

**Error Responses:**
- `400 Bad Request` - Invalid query parameters
- `401 Unauthorized` - Invalid token

---

### GET /assessments/search

**Description:** Search assessments with auto-complete suggestions

**Auth:** Required (consultant)

**Request:**

```http
GET /api/v1/assessments/search?q=ABC&limit=10
Authorization: Bearer <jwt_token>

Query Parameters:
  q      - Search query (required, min 2 characters)
  limit  - Max results (default 10, max 50)
```

**Response:** 200 OK

```json
{
  "success": true,
  "data": {
    "query": "ABC",
    "results": [
      {
        "id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
        "client_name": "John Smith",
        "business_name": "ABC Corporation",
        "status": "Completed",
        "match_field": "business_name",
        "highlight": "<mark>ABC</mark> Corporation"
      },
      {
        "id": "b2c3d4e5-f6a7-8901-2345-67890abcdef1",
        "client_name": "Alice Brown",
        "business_name": "ABC Industries",
        "status": "In Progress",
        "match_field": "business_name",
        "highlight": "<mark>ABC</mark> Industries"
      }
    ],
    "total_results": 2
  }
}
```

**Search Behavior:**
- Case-insensitive
- Searches client_name, business_name, and notes
- Returns results ranked by relevance (business/client name matches ranked higher)
- Highlights matched terms in results

**Error Responses:**
- `400 Bad Request` - Query too short (<2 chars)
- `401 Unauthorized` - Invalid token

---

### PATCH /assessments/:assessmentId/archive

**Description:** Archive or restore an assessment

**Auth:** Required (consultant who owns assessment)

**Request:**

```http
PATCH /api/v1/assessments/a1b2c3d4-e5f6-7890-1234-567890abcdef/archive
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "archived": true
}
```

**Response:** 200 OK

```json
{
  "success": true,
  "data": {
    "id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
    "archived": true,
    "archived_at": "2025-12-22T16:30:00Z",
    "archived_by": "consultant-user-id"
  },
  "message": "Assessment archived successfully"
}
```

**Restore Request:**

```json
{
  "archived": false
}
```

**Response:** 200 OK

```json
{
  "success": true,
  "data": {
    "id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
    "archived": false,
    "archived_at": null,
    "archived_by": null
  },
  "message": "Assessment restored successfully"
}
```

**Business Rules:**
- Only consultants can archive/restore
- Archived assessments are hidden from default list view
- Archived assessments can still be accessed directly by ID
- Clients can still access archived assessments they were invited to

**Error Responses:**
- `401 Unauthorized` - Invalid token
- `403 Forbidden` - Not the assessment owner
- `404 Not Found` - Assessment doesn't exist

---

### POST /assessments/bulk-archive

**Description:** Archive multiple assessments at once

**Auth:** Required (consultant)

**Request:**

```http
POST /api/v1/assessments/bulk-archive
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "assessment_ids": [
    "a1b2c3d4-e5f6-7890-1234-567890abcdef",
    "b2c3d4e5-f6a7-8901-2345-67890abcdef1",
    "c3d4e5f6-a7b8-9012-3456-7890abcdef12"
  ],
  "archived": true
}
```

**Response:** 200 OK

```json
{
  "success": true,
  "data": {
    "archived_count": 3,
    "failed_count": 0,
    "archived_ids": [
      "a1b2c3d4-e5f6-7890-1234-567890abcdef",
      "b2c3d4e5-f6a7-8901-2345-67890abcdef1",
      "c3d4e5f6-a7b8-9012-3456-7890abcdef12"
    ],
    "failed_ids": []
  },
  "message": "3 assessments archived successfully"
}
```

**Validation:**
- Max 50 assessments per request
- All assessments must belong to the requesting consultant
- Partial failures are reported

**Error Responses:**
- `400 Bad Request` - Too many IDs or invalid format
- `403 Forbidden` - Some assessments don't belong to consultant

---

### GET /assessments/stats

**Description:** Get assessment statistics for dashboard

**Auth:** Required (consultant)

**Request:**

```http
GET /api/v1/assessments/stats?period=30d
Authorization: Bearer <jwt_token>

Query Parameters:
  period - Time period (7d, 30d, 90d, all) - default: 30d
```

**Response:** 200 OK

```json
{
  "success": true,
  "data": {
    "period": "30d",
    "summary": {
      "total_assessments": 47,
      "active_assessments": 17,
      "completed_assessments": 30,
      "archived_assessments": 5,
      "draft_assessments": 5,
      "in_progress_assessments": 12
    },
    "completion_metrics": {
      "average_time_to_complete_hours": 48.5,
      "median_time_to_complete_hours": 36.0,
      "fastest_completion_hours": 12.0,
      "slowest_completion_hours": 120.0,
      "completion_rate_percentage": 63.8
    },
    "trends": {
      "assessments_created_this_period": 15,
      "assessments_completed_this_period": 12,
      "assessments_created_previous_period": 10,
      "assessments_completed_previous_period": 8,
      "growth_rate_percentage": 50.0
    },
    "by_phase": {
      "Stabilize": 8,
      "Organize": 12,
      "Build": 18,
      "Grow": 7,
      "Systemic": 2
    },
    "by_disc_profile": {
      "D": 15,
      "I": 10,
      "S": 12,
      "C": 10
    }
  }
}
```

---

## Search Implementation

### Full-Text Search with PostgreSQL

Using PostgreSQL's built-in `tsvector` for fast full-text search:

```typescript
async function searchAssessments(
  consultantId: string,
  query: string,
  limit: number = 10
): Promise<SearchResult[]> {
  // Sanitize query
  const sanitizedQuery = query.replace(/[^\w\s]/gi, '');
  const tsQuery = sanitizedQuery.split(/\s+/).join(' & ');

  const results = await sequelize.query(
    `
    SELECT
      id,
      client_name,
      business_name,
      status,
      ts_rank(search_vector, to_tsquery('english', :query)) AS rank,
      ts_headline('english',
        COALESCE(business_name, '') || ' ' || COALESCE(client_name, ''),
        to_tsquery('english', :query),
        'StartSel=<mark>, StopSel=</mark>'
      ) AS highlight
    FROM assessments
    WHERE
      consultant_id = :consultantId
      AND search_vector @@ to_tsquery('english', :query)
      AND archived = false
    ORDER BY rank DESC
    LIMIT :limit
    `,
    {
      replacements: {
        consultantId,
        query: tsQuery,
        limit
      },
      type: QueryTypes.SELECT
    }
  );

  return results.map(r => ({
    id: r.id,
    client_name: r.client_name,
    business_name: r.business_name,
    status: r.status,
    match_field: determineMatchField(r),
    highlight: r.highlight,
    rank: r.rank
  }));
}
```

### Auto-Complete Implementation

```typescript
async function autocompleteSearch(
  consultantId: string,
  prefix: string,
  limit: number = 10
): Promise<string[]> {
  const results = await Assessment.findAll({
    attributes: [
      [sequelize.fn('DISTINCT', sequelize.col('business_name')), 'suggestion']
    ],
    where: {
      consultant_id: consultantId,
      archived: false,
      business_name: {
        [Op.iLike]: `${prefix}%`
      }
    },
    limit,
    order: [['business_name', 'ASC']]
  });

  return results.map(r => r.suggestion);
}
```

---

## Filtering Logic

### Filter Builder Service

```typescript
class AssessmentFilterBuilder {
  private where: any = {};
  private consultantId: string;

  constructor(consultantId: string) {
    this.consultantId = consultantId;
    this.where.consultant_id = consultantId;
  }

  status(status?: string) {
    if (status) {
      this.where.status = status;
    }
    return this;
  }

  archived(archived: boolean = false) {
    this.where.archived = archived;
    return this;
  }

  dateRange(startDate?: string, endDate?: string) {
    if (startDate || endDate) {
      this.where.created_at = {};
      if (startDate) {
        this.where.created_at[Op.gte] = new Date(startDate);
      }
      if (endDate) {
        this.where.created_at[Op.lte] = new Date(endDate);
      }
    }
    return this;
  }

  completedDateRange(completedAfter?: string, completedBefore?: string) {
    if (completedAfter || completedBefore) {
      this.where.completed_at = {};
      if (completedAfter) {
        this.where.completed_at[Op.gte] = new Date(completedAfter);
      }
      if (completedBefore) {
        this.where.completed_at[Op.lte] = new Date(completedBefore);
      }
    }
    return this;
  }

  clientName(name?: string) {
    if (name) {
      this.where.client_name = { [Op.iLike]: `%${name}%` };
    }
    return this;
  }

  search(query?: string) {
    if (query) {
      const tsQuery = query.split(/\s+/).join(' & ');
      this.where[Op.and] = sequelize.literal(
        `search_vector @@ to_tsquery('english', '${tsQuery}')`
      );
    }
    return this;
  }

  build() {
    return this.where;
  }
}

// Usage
const filters = new AssessmentFilterBuilder(consultantId)
  .status(req.query.status)
  .archived(req.query.archived === 'true')
  .dateRange(req.query.start_date, req.query.end_date)
  .completedDateRange(req.query.completed_after, req.query.completed_before)
  .clientName(req.query.client_name)
  .search(req.query.search)
  .build();

const assessments = await Assessment.findAll({ where: filters });
```

---

## Archive System

### Archive Workflow

```typescript
class ArchiveService {
  async archiveAssessment(
    assessmentId: string,
    consultantId: string
  ) {
    const assessment = await Assessment.findOne({
      where: {
        id: assessmentId,
        consultant_id: consultantId
      }
    });

    if (!assessment) {
      throw new NotFoundError('Assessment not found');
    }

    await assessment.update({
      archived: true,
      archived_at: new Date(),
      archived_by: consultantId
    });

    // Log activity
    await this.logActivity(assessmentId, 'archived', consultantId);

    return assessment;
  }

  async restoreAssessment(
    assessmentId: string,
    consultantId: string
  ) {
    const assessment = await Assessment.findOne({
      where: {
        id: assessmentId,
        consultant_id: consultantId
      }
    });

    if (!assessment) {
      throw new NotFoundError('Assessment not found');
    }

    await assessment.update({
      archived: false,
      archived_at: null,
      archived_by: null
    });

    // Log activity
    await this.logActivity(assessmentId, 'restored', consultantId);

    return assessment;
  }

  async bulkArchive(
    assessmentIds: string[],
    consultantId: string
  ) {
    // Verify all assessments belong to consultant
    const assessments = await Assessment.findAll({
      where: {
        id: { [Op.in]: assessmentIds },
        consultant_id: consultantId
      }
    });

    const foundIds = assessments.map(a => a.id);
    const failedIds = assessmentIds.filter(id => !foundIds.includes(id));

    // Archive all found assessments
    await Assessment.update(
      {
        archived: true,
        archived_at: new Date(),
        archived_by: consultantId
      },
      {
        where: {
          id: { [Op.in]: foundIds }
        }
      }
    );

    // Log activity for each
    await Promise.all(
      foundIds.map(id => this.logActivity(id, 'archived', consultantId))
    );

    return {
      archived_count: foundIds.length,
      failed_count: failedIds.length,
      archived_ids: foundIds,
      failed_ids: failedIds
    };
  }

  private async logActivity(
    assessmentId: string,
    eventType: string,
    userId: string
  ) {
    await AssessmentActivityLog.create({
      assessment_id: assessmentId,
      event_type: eventType,
      event_timestamp: new Date(),
      user_id: userId,
      user_role: 'consultant'
    });
  }
}
```

---

## Performance Optimization

### Caching Strategy

```typescript
import Redis from 'ioredis';

const redis = new Redis(process.env.REDIS_URL);

class AssessmentCacheService {
  private cacheKeyPrefix = 'assessments:list';
  private cacheTTL = 60; // seconds

  async getAssessments(
    consultantId: string,
    filters: any,
    page: number,
    limit: number
  ) {
    // Generate cache key from filters
    const cacheKey = this.generateCacheKey(consultantId, filters, page, limit);

    // Try cache first
    const cached = await redis.get(cacheKey);
    if (cached) {
      return JSON.parse(cached);
    }

    // Query database
    const results = await this.queryDatabase(consultantId, filters, page, limit);

    // Cache results
    await redis.setex(cacheKey, this.cacheTTL, JSON.stringify(results));

    return results;
  }

  async invalidateCache(consultantId: string) {
    const pattern = `${this.cacheKeyPrefix}:${consultantId}:*`;
    const keys = await redis.keys(pattern);

    if (keys.length > 0) {
      await redis.del(...keys);
    }
  }

  private generateCacheKey(
    consultantId: string,
    filters: any,
    page: number,
    limit: number
  ): string {
    const filterHash = crypto
      .createHash('md5')
      .update(JSON.stringify(filters))
      .digest('hex');

    return `${this.cacheKeyPrefix}:${consultantId}:${filterHash}:${page}:${limit}`;
  }
}
```

### Database Query Optimization

```sql
-- Materialized view for assessment summaries (refresh periodically)
CREATE MATERIALIZED VIEW assessment_summaries AS
SELECT
  consultant_id,
  COUNT(*) AS total_assessments,
  COUNT(*) FILTER (WHERE status = 'Draft') AS draft_count,
  COUNT(*) FILTER (WHERE status = 'In Progress') AS in_progress_count,
  COUNT(*) FILTER (WHERE status = 'Completed') AS completed_count,
  COUNT(*) FILTER (WHERE archived = true) AS archived_count,
  AVG(EXTRACT(EPOCH FROM (completed_at - created_at)) / 3600) FILTER (WHERE completed_at IS NOT NULL) AS avg_completion_hours
FROM assessments
GROUP BY consultant_id;

-- Index on materialized view
CREATE UNIQUE INDEX idx_assessment_summaries_consultant ON assessment_summaries(consultant_id);

-- Refresh materialized view (run via cron every hour)
REFRESH MATERIALIZED VIEW CONCURRENTLY assessment_summaries;
```

---

## Implementation Guide

### Step 1: Database Migration

```bash
npm run migrate:up -- 2025-12-22-dashboard-enhancements
```

### Step 2: Update Assessment Model

```typescript
// Add new fields to Assessment model
Assessment.init({
  // ... existing fields
  archived: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  },
  archived_at: {
    type: DataTypes.DATE
  },
  archived_by: {
    type: DataTypes.UUID,
    references: { model: 'users', key: 'id' }
  },
  completed_at: {
    type: DataTypes.DATE
  },
  search_vector: {
    type: 'TSVECTOR' // Special PostgreSQL type
  }
});
```

### Step 3: Create Enhanced Service

**File:** `src/services/assessmentEnhancedService.ts`

(See implementation sections above)

### Step 4: Update Controller

**File:** `src/controllers/assessmentController.ts`

```typescript
// Update existing getAssessments endpoint
export const getAssessments = asyncHandler(async (req, res) => {
  const consultantId = req.user.id;
  const {
    status,
    archived = 'false',
    start_date,
    end_date,
    completed_after,
    completed_before,
    client_name,
    search,
    sort = 'created_at',
    order = 'desc',
    page = 1,
    limit = 20
  } = req.query;

  const filters = new AssessmentFilterBuilder(consultantId)
    .status(status)
    .archived(archived === 'true')
    .dateRange(start_date, end_date)
    .completedDateRange(completed_after, completed_before)
    .clientName(client_name)
    .search(search)
    .build();

  const results = await Assessment.findAndCountAll({
    where: filters,
    order: [[sort, order.toUpperCase()]],
    limit: parseInt(limit),
    offset: (parseInt(page) - 1) * parseInt(limit)
  });

  res.json({
    success: true,
    data: {
      assessments: results.rows,
      pagination: {
        current_page: parseInt(page),
        total_pages: Math.ceil(results.count / parseInt(limit)),
        total_items: results.count,
        items_per_page: parseInt(limit),
        has_next: page * limit < results.count,
        has_prev: page > 1
      }
    }
  });
});
```

---

## Testing Strategy

### Unit Tests

```typescript
describe('AssessmentFilterBuilder', () => {
  it('should build filters correctly', () => {
    const filters = new AssessmentFilterBuilder('consultant-id')
      .status('Completed')
      .archived(false)
      .dateRange('2025-12-01', '2025-12-31')
      .build();

    expect(filters.consultant_id).toBe('consultant-id');
    expect(filters.status).toBe('Completed');
    expect(filters.archived).toBe(false);
  });
});

describe('ArchiveService', () => {
  it('should archive assessment', async () => {
    const result = await archiveService.archiveAssessment(
      'assessment-id',
      'consultant-id'
    );

    expect(result.archived).toBe(true);
    expect(result.archived_at).toBeTruthy();
  });

  it('should bulk archive multiple assessments', async () => {
    const result = await archiveService.bulkArchive(
      ['id1', 'id2', 'id3'],
      'consultant-id'
    );

    expect(result.archived_count).toBe(3);
  });
});
```

### Integration Tests

```typescript
describe('GET /assessments (enhanced)', () => {
  it('should filter by status', async () => {
    const res = await request(app)
      .get('/api/v1/assessments?status=Completed')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.data.assessments.every(a => a.status === 'Completed')).toBe(true);
  });

  it('should search assessments', async () => {
    const res = await request(app)
      .get('/api/v1/assessments/search?q=ABC')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.data.results.length).toBeGreaterThan(0);
  });
});
```

---

**Document Version:** 1.0
**Author:** Backend Developer 1
**Last Updated:** 2025-12-22
**Status:** Ready for Implementation
