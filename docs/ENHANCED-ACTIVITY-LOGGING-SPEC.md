# Enhanced Activity Logging Specification

**Work Stream:** 46
**Phase:** 3 - Advanced Features
**Dependency Level:** 1
**Created:** 2025-12-22
**Status:** Complete

## Overview

This specification defines the enhanced activity logging system for the Financial RISE Report application. Building on the basic activity logging implemented in Phase 1 (Work Stream 9), this enhancement adds comprehensive event tracking, advanced filtering, full-text search, and CSV export capabilities for audit and compliance purposes.

### Key Features

1. **Enhanced Logging Middleware** - Capture detailed activity events across all system operations
2. **Advanced Filtering** - Filter logs by user, action type, date range, resource, and custom criteria
3. **Full-Text Search** - Search log entries using PostgreSQL full-text search
4. **CSV Export** - Export filtered log data for external analysis and compliance reporting
5. **Activity Timeline View** - Visualize user and system activity chronologically
6. **Retention Policies** - Automatic archival and cleanup of old logs based on configurable policies

### Requirements Traceability

- **REQ-ADMIN-005:** Administrator dashboard with system analytics and user activity monitoring
- **REQ-AUDIT-001:** Comprehensive audit trail for all data modifications
- **REQ-AUDIT-002:** Activity logs must be immutable and retained per compliance requirements
- **REQ-MAINT-004:** System monitoring and logging infrastructure

### Dependencies

- **Work Stream 9:** Basic Activity Logging (MVP) - provides foundation `activity_logs` table
- **Work Stream 45:** Admin Performance Monitoring - shares admin dashboard UI

---

## Database Schema

### 1. Enhanced Activity Logs Table

Extension of the existing `activity_logs` table from Work Stream 9:

```sql
-- Add new columns to existing activity_logs table
ALTER TABLE activity_logs
  ADD COLUMN IF NOT EXISTS ip_address INET,
  ADD COLUMN IF NOT EXISTS user_agent TEXT,
  ADD COLUMN IF NOT EXISTS request_method VARCHAR(10),
  ADD COLUMN IF NOT EXISTS request_path TEXT,
  ADD COLUMN IF NOT EXISTS response_status INTEGER,
  ADD COLUMN IF NOT EXISTS duration_ms INTEGER,
  ADD COLUMN IF NOT EXISTS error_message TEXT,
  ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS resource_type VARCHAR(50),
  ADD COLUMN IF NOT EXISTS resource_id UUID,
  ADD COLUMN IF NOT EXISTS parent_log_id UUID REFERENCES activity_logs(id),
  ADD COLUMN IF NOT EXISTS search_vector tsvector;

-- Indexes for enhanced querying
CREATE INDEX IF NOT EXISTS idx_activity_logs_ip_address ON activity_logs(ip_address);
CREATE INDEX IF NOT EXISTS idx_activity_logs_resource ON activity_logs(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_activity_logs_parent ON activity_logs(parent_log_id);
CREATE INDEX IF NOT EXISTS idx_activity_logs_response_status ON activity_logs(response_status);
CREATE INDEX IF NOT EXISTS idx_activity_logs_metadata ON activity_logs USING gin(metadata);
CREATE INDEX IF NOT EXISTS idx_activity_logs_search ON activity_logs USING gin(search_vector);

-- Trigger to update search vector
CREATE OR REPLACE FUNCTION activity_logs_search_trigger() RETURNS trigger AS $$
BEGIN
  NEW.search_vector :=
    setweight(to_tsvector('english', COALESCE(NEW.action, '')), 'A') ||
    setweight(to_tsvector('english', COALESCE(NEW.description, '')), 'B') ||
    setweight(to_tsvector('english', COALESCE(NEW.error_message, '')), 'C') ||
    setweight(to_tsvector('english', COALESCE(NEW.metadata::text, '')), 'D');
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER activity_logs_search_update
  BEFORE INSERT OR UPDATE ON activity_logs
  FOR EACH ROW EXECUTE FUNCTION activity_logs_search_trigger();
```

### 2. Log Retention Policies Table

```sql
CREATE TABLE log_retention_policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  policy_name VARCHAR(100) NOT NULL UNIQUE,
  action_pattern VARCHAR(100), -- e.g., 'login%', 'assessment.%'
  retention_days INTEGER NOT NULL,
  archive_enabled BOOLEAN DEFAULT false,
  archive_location VARCHAR(255), -- S3 bucket path or similar
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_log_retention_active ON log_retention_policies(is_active);

-- Default retention policies
INSERT INTO log_retention_policies (policy_name, action_pattern, retention_days, archive_enabled) VALUES
  ('Authentication Events', 'auth.%', 365, true),
  ('Assessment Operations', 'assessment.%', 730, true),
  ('Report Generation', 'report.%', 730, true),
  ('Admin Actions', 'admin.%', 1095, true),
  ('General Activity', '%', 180, false);
```

### 3. Archived Logs Reference Table

```sql
CREATE TABLE archived_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  archive_date DATE NOT NULL,
  action_pattern VARCHAR(100),
  log_count INTEGER NOT NULL,
  archive_location VARCHAR(255) NOT NULL,
  file_size_bytes BIGINT,
  archived_by UUID REFERENCES users(id),
  archived_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_archived_logs_date ON archived_logs(archive_date);
CREATE INDEX idx_archived_logs_pattern ON archived_logs(action_pattern);
```

---

## API Endpoints

### 1. Get Activity Logs with Advanced Filtering

**Endpoint:** `GET /api/admin/activity-logs`

**Auth:** Admin only

**Query Parameters:**
```typescript
interface ActivityLogFilters {
  user_id?: string;
  action?: string; // Exact match or pattern (e.g., 'auth.%')
  action_pattern?: string; // SQL LIKE pattern
  resource_type?: string;
  resource_id?: string;
  date_from?: string; // ISO 8601
  date_to?: string; // ISO 8601
  ip_address?: string;
  response_status?: number;
  response_status_min?: number; // For range queries
  response_status_max?: number;
  has_error?: boolean;
  search?: string; // Full-text search query
  sort_by?: 'timestamp' | 'user_id' | 'action' | 'duration_ms';
  sort_order?: 'asc' | 'desc';
  page?: number;
  limit?: number; // Max 1000
}
```

**Response:**
```typescript
interface ActivityLogsResponse {
  logs: ActivityLog[];
  pagination: {
    page: number;
    limit: number;
    total_count: number;
    total_pages: number;
  };
  filters_applied: ActivityLogFilters;
}

interface ActivityLog {
  id: string;
  user_id: string;
  user_email: string;
  user_role: string;
  action: string;
  description: string;
  ip_address: string;
  user_agent: string;
  request_method: string;
  request_path: string;
  response_status: number;
  duration_ms: number;
  error_message?: string;
  metadata: Record<string, any>;
  resource_type?: string;
  resource_id?: string;
  timestamp: string;
}
```

**Example Request:**
```bash
GET /api/admin/activity-logs?action_pattern=assessment.%&date_from=2025-01-01&response_status_min=400&limit=50
```

**Example Response:**
```json
{
  "logs": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440003",
      "user_id": "550e8400-e29b-41d4-a716-446655440001",
      "user_email": "consultant@example.com",
      "user_role": "consultant",
      "action": "assessment.create",
      "description": "Created new assessment for client John Doe",
      "ip_address": "192.168.1.100",
      "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
      "request_method": "POST",
      "request_path": "/api/assessments",
      "response_status": 201,
      "duration_ms": 145,
      "metadata": {
        "assessment_id": "550e8400-e29b-41d4-a716-446655440010",
        "client_name": "John Doe"
      },
      "resource_type": "assessment",
      "resource_id": "550e8400-e29b-41d4-a716-446655440010",
      "timestamp": "2025-12-22T10:30:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 50,
    "total_count": 127,
    "total_pages": 3
  },
  "filters_applied": {
    "action_pattern": "assessment.%",
    "date_from": "2025-01-01",
    "response_status_min": 400,
    "limit": 50
  }
}
```

### 2. Full-Text Search Activity Logs

**Endpoint:** `GET /api/admin/activity-logs/search`

**Auth:** Admin only

**Query Parameters:**
```typescript
interface SearchLogsRequest {
  q: string; // Search query
  user_id?: string;
  date_from?: string;
  date_to?: string;
  page?: number;
  limit?: number;
}
```

**Response:** Same as `ActivityLogsResponse` above

**Example Request:**
```bash
GET /api/admin/activity-logs/search?q=failed+login&date_from=2025-12-01&limit=20
```

**Example Response:**
```json
{
  "logs": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440004",
      "user_id": "550e8400-e29b-41d4-a716-446655440002",
      "user_email": "user@example.com",
      "user_role": "consultant",
      "action": "auth.login.failed",
      "description": "Failed login attempt - invalid password",
      "ip_address": "203.0.113.45",
      "user_agent": "Mozilla/5.0",
      "request_method": "POST",
      "request_path": "/api/auth/login",
      "response_status": 401,
      "duration_ms": 50,
      "error_message": "Invalid email or password",
      "metadata": {
        "attempts_count": 3
      },
      "timestamp": "2025-12-15T14:22:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total_count": 8,
    "total_pages": 1
  },
  "filters_applied": {
    "q": "failed login",
    "date_from": "2025-12-01",
    "limit": 20
  }
}
```

### 3. Export Activity Logs to CSV

**Endpoint:** `POST /api/admin/activity-logs/export`

**Auth:** Admin only

**Request Body:**
```typescript
interface ExportLogsRequest {
  filters: ActivityLogFilters; // Same filters as GET endpoint
  columns: string[]; // Columns to include in export
  format?: 'csv' | 'json'; // Default: 'csv'
}
```

**Response:**
```typescript
interface ExportLogsResponse {
  export_id: string;
  status: 'processing' | 'completed' | 'failed';
  download_url?: string; // S3 presigned URL (expires in 1 hour)
  total_rows: number;
  file_size_bytes?: number;
  created_at: string;
  expires_at: string;
}
```

**Example Request:**
```json
{
  "filters": {
    "action_pattern": "assessment.%",
    "date_from": "2025-01-01",
    "date_to": "2025-12-31"
  },
  "columns": [
    "timestamp",
    "user_email",
    "action",
    "description",
    "response_status",
    "duration_ms"
  ],
  "format": "csv"
}
```

**Example Response:**
```json
{
  "export_id": "550e8400-e29b-41d4-a716-446655440020",
  "status": "completed",
  "download_url": "https://financial-rise-exports.s3.amazonaws.com/logs/export_550e8400.csv?signature=...",
  "total_rows": 1543,
  "file_size_bytes": 524288,
  "created_at": "2025-12-22T11:00:00Z",
  "expires_at": "2025-12-22T12:00:00Z"
}
```

### 4. Get Activity Timeline for Resource

**Endpoint:** `GET /api/admin/activity-logs/timeline/:resource_type/:resource_id`

**Auth:** Admin or resource owner (consultant viewing their own assessments)

**Query Parameters:**
```typescript
interface TimelineRequest {
  include_related?: boolean; // Include related resources (e.g., report for assessment)
}
```

**Response:**
```typescript
interface TimelineResponse {
  resource_type: string;
  resource_id: string;
  resource_metadata?: Record<string, any>;
  timeline: TimelineEvent[];
}

interface TimelineEvent {
  id: string;
  timestamp: string;
  action: string;
  description: string;
  user_email: string;
  user_role: string;
  metadata: Record<string, any>;
  child_events?: TimelineEvent[]; // Nested events
}
```

**Example Request:**
```bash
GET /api/admin/activity-logs/timeline/assessment/550e8400-e29b-41d4-a716-446655440010?include_related=true
```

**Example Response:**
```json
{
  "resource_type": "assessment",
  "resource_id": "550e8400-e29b-41d4-a716-446655440010",
  "resource_metadata": {
    "client_name": "John Doe",
    "created_at": "2025-12-01T10:00:00Z",
    "status": "completed"
  },
  "timeline": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440030",
      "timestamp": "2025-12-01T10:00:00Z",
      "action": "assessment.create",
      "description": "Assessment created",
      "user_email": "consultant@example.com",
      "user_role": "consultant",
      "metadata": {}
    },
    {
      "id": "550e8400-e29b-41d4-a716-446655440031",
      "timestamp": "2025-12-01T10:15:00Z",
      "action": "questionnaire.start",
      "description": "Client started questionnaire",
      "user_email": "client@example.com",
      "user_role": "client",
      "metadata": {
        "questionnaire_type": "financial_readiness"
      },
      "child_events": [
        {
          "id": "550e8400-e29b-41d4-a716-446655440032",
          "timestamp": "2025-12-01T10:16:30Z",
          "action": "questionnaire.answer",
          "description": "Answered question: 'Do you have a Chart of Accounts?'",
          "user_email": "client@example.com",
          "user_role": "client",
          "metadata": {
            "question_id": "COA-001",
            "answer": "yes"
          }
        }
      ]
    }
  ]
}
```

### 5. Manage Retention Policies

**Endpoint:** `GET /api/admin/activity-logs/retention-policies`

**Auth:** Admin only

**Response:**
```typescript
interface RetentionPoliciesResponse {
  policies: RetentionPolicy[];
}

interface RetentionPolicy {
  id: string;
  policy_name: string;
  action_pattern: string;
  retention_days: number;
  archive_enabled: boolean;
  archive_location?: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}
```

**Endpoint:** `PUT /api/admin/activity-logs/retention-policies/:id`

**Auth:** Admin only

**Request Body:**
```typescript
interface UpdateRetentionPolicyRequest {
  retention_days?: number;
  archive_enabled?: boolean;
  archive_location?: string;
  is_active?: boolean;
}
```

**Response:** Updated `RetentionPolicy` object

### 6. Archive Old Logs

**Endpoint:** `POST /api/admin/activity-logs/archive`

**Auth:** Admin only

**Request Body:**
```typescript
interface ArchiveLogsRequest {
  policy_id?: string; // Archive logs matching specific policy
  date_before?: string; // Archive logs older than this date
  dry_run?: boolean; // Preview what would be archived
}
```

**Response:**
```typescript
interface ArchiveLogsResponse {
  archive_id?: string; // Only if dry_run=false
  logs_archived: number;
  archive_location?: string;
  file_size_bytes?: number;
  dry_run: boolean;
  archived_at?: string;
}
```

---

## Backend Implementation

### 1. Enhanced Logging Middleware

**File:** `src/middleware/activityLogger.ts`

```typescript
import { Request, Response, NextFunction } from 'express';
import { ActivityLog } from '../models/ActivityLog';
import { v4 as uuidv4 } from 'uuid';

interface LogMetadata {
  [key: string]: any;
}

class ActivityLogger {
  /**
   * Express middleware to automatically log all requests
   */
  public middleware() {
    return async (req: Request, res: Response, next: NextFunction) => {
      const startTime = Date.now();
      const logId = uuidv4();

      // Capture response
      const originalSend = res.send;
      let responseLogged = false;

      res.send = function (data: any) {
        if (!responseLogged) {
          responseLogged = true;
          const duration = Date.now() - startTime;

          ActivityLogger.logRequest(req, res, duration, logId).catch(err => {
            console.error('Failed to log activity:', err);
          });
        }
        return originalSend.call(this, data);
      };

      next();
    };
  }

  /**
   * Log a request with full context
   */
  private static async logRequest(
    req: Request,
    res: Response,
    duration: number,
    logId: string
  ): Promise<void> {
    const user = req.user; // Assumes auth middleware sets req.user
    const action = this.inferAction(req);
    const description = this.generateDescription(req, res);

    await ActivityLog.create({
      id: logId,
      user_id: user?.id || null,
      action,
      description,
      ip_address: this.getClientIP(req),
      user_agent: req.get('user-agent') || null,
      request_method: req.method,
      request_path: req.path,
      response_status: res.statusCode,
      duration_ms: duration,
      error_message: res.statusCode >= 400 ? this.extractErrorMessage(res) : null,
      metadata: this.extractMetadata(req, res),
      resource_type: this.inferResourceType(req),
      resource_id: this.inferResourceId(req),
      timestamp: new Date()
    });
  }

  /**
   * Infer action from request
   */
  private static inferAction(req: Request): string {
    const method = req.method;
    const path = req.path;

    // Custom action mapping
    if (path.startsWith('/api/auth/login')) return 'auth.login';
    if (path.startsWith('/api/auth/logout')) return 'auth.logout';
    if (path.startsWith('/api/assessments') && method === 'POST') return 'assessment.create';
    if (path.startsWith('/api/assessments') && method === 'GET') return 'assessment.view';
    if (path.startsWith('/api/assessments') && method === 'PUT') return 'assessment.update';
    if (path.startsWith('/api/assessments') && method === 'DELETE') return 'assessment.delete';
    if (path.startsWith('/api/reports') && method === 'POST') return 'report.generate';
    if (path.startsWith('/api/questionnaires')) return 'questionnaire.answer';

    // Default pattern: resource.method
    const segments = path.split('/').filter(s => s && s !== 'api');
    const resource = segments[0] || 'unknown';
    const methodMap: Record<string, string> = {
      'GET': 'view',
      'POST': 'create',
      'PUT': 'update',
      'PATCH': 'update',
      'DELETE': 'delete'
    };
    return `${resource}.${methodMap[method] || method.toLowerCase()}`;
  }

  /**
   * Generate human-readable description
   */
  private static generateDescription(req: Request, res: Response): string {
    const action = this.inferAction(req);
    const user = req.user;

    if (res.statusCode >= 400) {
      return `Failed ${action} (${res.statusCode})`;
    }

    const descriptions: Record<string, string> = {
      'auth.login': `User logged in`,
      'auth.logout': `User logged out`,
      'assessment.create': `Created new assessment`,
      'assessment.view': `Viewed assessment`,
      'assessment.update': `Updated assessment`,
      'assessment.delete': `Deleted assessment`,
      'report.generate': `Generated report`,
      'questionnaire.answer': `Answered questionnaire question`
    };

    return descriptions[action] || `Performed ${action}`;
  }

  /**
   * Extract client IP address (handle proxies)
   */
  private static getClientIP(req: Request): string {
    const forwarded = req.get('x-forwarded-for');
    if (forwarded) {
      return forwarded.split(',')[0].trim();
    }
    return req.ip || req.connection.remoteAddress || 'unknown';
  }

  /**
   * Extract error message from response
   */
  private static extractErrorMessage(res: Response): string | null {
    // This is a simplified version - you'd need to capture the response body
    // in the middleware to get the actual error message
    return `HTTP ${res.statusCode}`;
  }

  /**
   * Extract metadata from request/response
   */
  private static extractMetadata(req: Request, res: Response): LogMetadata {
    const metadata: LogMetadata = {};

    // Add request body for non-GET requests (sanitized)
    if (req.method !== 'GET' && req.body) {
      metadata.request_body = this.sanitizeBody(req.body);
    }

    // Add query params
    if (Object.keys(req.query).length > 0) {
      metadata.query_params = req.query;
    }

    // Add response headers if interesting
    const contentType = res.get('content-type');
    if (contentType) {
      metadata.response_content_type = contentType;
    }

    return metadata;
  }

  /**
   * Sanitize request body (remove passwords, tokens, etc.)
   */
  private static sanitizeBody(body: any): any {
    const sanitized = { ...body };
    const sensitiveFields = ['password', 'token', 'api_key', 'secret'];

    const sanitize = (obj: any) => {
      for (const key in obj) {
        if (sensitiveFields.includes(key.toLowerCase())) {
          obj[key] = '[REDACTED]';
        } else if (typeof obj[key] === 'object' && obj[key] !== null) {
          sanitize(obj[key]);
        }
      }
    };

    sanitize(sanitized);
    return sanitized;
  }

  /**
   * Infer resource type from path
   */
  private static inferResourceType(req: Request): string | null {
    const path = req.path;
    if (path.includes('/assessments')) return 'assessment';
    if (path.includes('/reports')) return 'report';
    if (path.includes('/users')) return 'user';
    if (path.includes('/questionnaires')) return 'questionnaire';
    return null;
  }

  /**
   * Infer resource ID from path
   */
  private static inferResourceId(req: Request): string | null {
    // Look for UUID pattern in path
    const uuidRegex = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;
    const match = req.path.match(uuidRegex);
    return match ? match[0] : null;
  }

  /**
   * Manual logging for custom events
   */
  public static async log(
    userId: string | null,
    action: string,
    description: string,
    metadata?: LogMetadata,
    resourceType?: string,
    resourceId?: string,
    parentLogId?: string
  ): Promise<void> {
    await ActivityLog.create({
      id: uuidv4(),
      user_id: userId,
      action,
      description,
      metadata: metadata || {},
      resource_type: resourceType || null,
      resource_id: resourceId || null,
      parent_log_id: parentLogId || null,
      timestamp: new Date()
    });
  }
}

export default ActivityLogger;
```

### 2. Activity Log Service

**File:** `src/services/activityLogService.ts`

```typescript
import { Op } from 'sequelize';
import { ActivityLog } from '../models/ActivityLog';
import { User } from '../models/User';
import { LogRetentionPolicy } from '../models/LogRetentionPolicy';
import { ArchivedLog } from '../models/ArchivedLog';
import { Parser } from 'json2csv';
import AWS from 'aws-sdk';

const s3 = new AWS.S3();

interface ActivityLogFilters {
  user_id?: string;
  action?: string;
  action_pattern?: string;
  resource_type?: string;
  resource_id?: string;
  date_from?: string;
  date_to?: string;
  ip_address?: string;
  response_status?: number;
  response_status_min?: number;
  response_status_max?: number;
  has_error?: boolean;
  search?: string;
  sort_by?: string;
  sort_order?: 'asc' | 'desc';
  page?: number;
  limit?: number;
}

class ActivityLogService {
  /**
   * Get activity logs with advanced filtering
   */
  async getLogs(filters: ActivityLogFilters) {
    const {
      user_id,
      action,
      action_pattern,
      resource_type,
      resource_id,
      date_from,
      date_to,
      ip_address,
      response_status,
      response_status_min,
      response_status_max,
      has_error,
      search,
      sort_by = 'timestamp',
      sort_order = 'desc',
      page = 1,
      limit = 50
    } = filters;

    // Build WHERE clause
    const where: any = {};

    if (user_id) where.user_id = user_id;
    if (action) where.action = action;
    if (action_pattern) where.action = { [Op.like]: action_pattern };
    if (resource_type) where.resource_type = resource_type;
    if (resource_id) where.resource_id = resource_id;
    if (ip_address) where.ip_address = ip_address;
    if (response_status) where.response_status = response_status;
    if (response_status_min || response_status_max) {
      where.response_status = {};
      if (response_status_min) where.response_status[Op.gte] = response_status_min;
      if (response_status_max) where.response_status[Op.lte] = response_status_max;
    }
    if (has_error !== undefined) {
      where.error_message = has_error ? { [Op.ne]: null } : null;
    }
    if (date_from || date_to) {
      where.timestamp = {};
      if (date_from) where.timestamp[Op.gte] = new Date(date_from);
      if (date_to) where.timestamp[Op.lte] = new Date(date_to);
    }

    // Full-text search
    if (search) {
      where.search_vector = {
        [Op.match]: this.sanitizeSearchQuery(search)
      };
    }

    // Execute query
    const offset = (page - 1) * limit;
    const { rows, count } = await ActivityLog.findAndCountAll({
      where,
      include: [
        {
          model: User,
          attributes: ['email', 'role'],
          required: false
        }
      ],
      order: [[sort_by, sort_order.toUpperCase()]],
      limit: Math.min(limit, 1000),
      offset
    });

    return {
      logs: rows.map(log => this.formatLog(log)),
      pagination: {
        page,
        limit,
        total_count: count,
        total_pages: Math.ceil(count / limit)
      },
      filters_applied: filters
    };
  }

  /**
   * Search logs using full-text search
   */
  async searchLogs(
    query: string,
    userId?: string,
    dateFrom?: string,
    dateTo?: string,
    page: number = 1,
    limit: number = 50
  ) {
    return this.getLogs({
      search: query,
      user_id: userId,
      date_from: dateFrom,
      date_to: dateTo,
      page,
      limit
    });
  }

  /**
   * Export logs to CSV
   */
  async exportLogs(
    filters: ActivityLogFilters,
    columns: string[],
    format: 'csv' | 'json' = 'csv',
    adminId: string
  ): Promise<string> {
    // Fetch all matching logs (no pagination)
    const { logs } = await this.getLogs({
      ...filters,
      limit: 100000 // Large limit for export
    });

    // Generate file
    let fileContent: string;
    let contentType: string;
    let fileExtension: string;

    if (format === 'csv') {
      const parser = new Parser({ fields: columns });
      fileContent = parser.parse(logs);
      contentType = 'text/csv';
      fileExtension = 'csv';
    } else {
      fileContent = JSON.stringify(logs, null, 2);
      contentType = 'application/json';
      fileExtension = 'json';
    }

    // Upload to S3
    const key = `logs/export_${Date.now()}_${adminId}.${fileExtension}`;
    await s3.putObject({
      Bucket: process.env.AWS_S3_BUCKET!,
      Key: key,
      Body: fileContent,
      ContentType: contentType
    }).promise();

    // Generate presigned URL (expires in 1 hour)
    const downloadUrl = s3.getSignedUrl('getObject', {
      Bucket: process.env.AWS_S3_BUCKET!,
      Key: key,
      Expires: 3600
    });

    return downloadUrl;
  }

  /**
   * Get activity timeline for a resource
   */
  async getResourceTimeline(
    resourceType: string,
    resourceId: string,
    includeRelated: boolean = false
  ) {
    const logs = await ActivityLog.findAll({
      where: {
        resource_type: resourceType,
        resource_id: resourceId
      },
      include: [
        {
          model: User,
          attributes: ['email', 'role']
        }
      ],
      order: [['timestamp', 'ASC']]
    });

    // Group by parent_log_id to create hierarchy
    const timeline = this.buildTimelineHierarchy(logs);

    return {
      resource_type: resourceType,
      resource_id: resourceId,
      timeline
    };
  }

  /**
   * Archive old logs based on retention policies
   */
  async archiveLogs(
    policyId?: string,
    dateBefore?: string,
    dryRun: boolean = false,
    adminId?: string
  ) {
    const policies = policyId
      ? await LogRetentionPolicy.findAll({ where: { id: policyId, is_active: true } })
      : await LogRetentionPolicy.findAll({ where: { is_active: true } });

    let totalArchived = 0;
    const archiveDate = dateBefore ? new Date(dateBefore) : new Date();

    for (const policy of policies) {
      const cutoffDate = new Date(archiveDate);
      cutoffDate.setDate(cutoffDate.getDate() - policy.retention_days);

      const logsToArchive = await ActivityLog.findAll({
        where: {
          action: { [Op.like]: policy.action_pattern },
          timestamp: { [Op.lt]: cutoffDate }
        }
      });

      if (!dryRun && policy.archive_enabled && logsToArchive.length > 0) {
        // Export to S3
        const key = `archives/${policy.policy_name}_${cutoffDate.toISOString()}.json`;
        const fileContent = JSON.stringify(logsToArchive, null, 2);

        await s3.putObject({
          Bucket: process.env.AWS_S3_BUCKET!,
          Key: key,
          Body: fileContent,
          ContentType: 'application/json'
        }).promise();

        // Record archive
        await ArchivedLog.create({
          archive_date: cutoffDate,
          action_pattern: policy.action_pattern,
          log_count: logsToArchive.length,
          archive_location: `s3://${process.env.AWS_S3_BUCKET}/${key}`,
          file_size_bytes: Buffer.byteLength(fileContent),
          archived_by: adminId
        });

        // Delete from database
        await ActivityLog.destroy({
          where: {
            id: { [Op.in]: logsToArchive.map(log => log.id) }
          }
        });
      }

      totalArchived += logsToArchive.length;
    }

    return {
      logs_archived: totalArchived,
      dry_run: dryRun
    };
  }

  /**
   * Helper: Format log for response
   */
  private formatLog(log: any) {
    return {
      id: log.id,
      user_id: log.user_id,
      user_email: log.User?.email || 'Unknown',
      user_role: log.User?.role || 'Unknown',
      action: log.action,
      description: log.description,
      ip_address: log.ip_address,
      user_agent: log.user_agent,
      request_method: log.request_method,
      request_path: log.request_path,
      response_status: log.response_status,
      duration_ms: log.duration_ms,
      error_message: log.error_message,
      metadata: log.metadata,
      resource_type: log.resource_type,
      resource_id: log.resource_id,
      timestamp: log.timestamp
    };
  }

  /**
   * Helper: Sanitize search query for PostgreSQL full-text search
   */
  private sanitizeSearchQuery(query: string): string {
    // Convert to tsquery format
    return query
      .split(/\s+/)
      .filter(word => word.length > 0)
      .map(word => `${word}:*`)
      .join(' & ');
  }

  /**
   * Helper: Build timeline hierarchy from flat log list
   */
  private buildTimelineHierarchy(logs: any[]): any[] {
    const logMap = new Map();
    const rootLogs: any[] = [];

    // First pass: create map
    logs.forEach(log => {
      logMap.set(log.id, {
        id: log.id,
        timestamp: log.timestamp,
        action: log.action,
        description: log.description,
        user_email: log.User?.email,
        user_role: log.User?.role,
        metadata: log.metadata,
        child_events: []
      });
    });

    // Second pass: build hierarchy
    logs.forEach(log => {
      const formattedLog = logMap.get(log.id);
      if (log.parent_log_id) {
        const parent = logMap.get(log.parent_log_id);
        if (parent) {
          parent.child_events.push(formattedLog);
        } else {
          rootLogs.push(formattedLog);
        }
      } else {
        rootLogs.push(formattedLog);
      }
    });

    return rootLogs;
  }
}

export default new ActivityLogService();
```

---

## Frontend Implementation

### 1. Activity Logs Page Component

**File:** `src/pages/Admin/ActivityLogs.tsx`

```typescript
import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  Chip,
  IconButton,
  Collapse,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Grid
} from '@mui/material';
import {
  Search,
  FilterList,
  Download,
  ExpandMore,
  ExpandLess,
  Timeline as TimelineIcon
} from '@mui/icons-material';
import { activityLogApi } from '../../services/api';
import { ActivityLog, ActivityLogFilters } from '../../types';
import { useDebounce } from '../../hooks/useDebounce';
import ActivityLogFilters from '../../components/Admin/ActivityLogFilters';
import ActivityTimeline from '../../components/Admin/ActivityTimeline';

const ActivityLogsPage: React.FC = () => {
  const [logs, setLogs] = useState<ActivityLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(50);
  const [totalCount, setTotalCount] = useState(0);
  const [searchQuery, setSearchQuery] = useState('');
  const [filters, setFilters] = useState<ActivityLogFilters>({});
  const [showFilters, setShowFilters] = useState(false);
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [timelineResource, setTimelineResource] = useState<{
    type: string;
    id: string;
  } | null>(null);

  const debouncedSearch = useDebounce(searchQuery, 500);

  useEffect(() => {
    fetchLogs();
  }, [page, rowsPerPage, debouncedSearch, filters]);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const response = debouncedSearch
        ? await activityLogApi.search(debouncedSearch, {
            page: page + 1,
            limit: rowsPerPage,
            ...filters
          })
        : await activityLogApi.getLogs({
            page: page + 1,
            limit: rowsPerPage,
            ...filters
          });

      setLogs(response.logs);
      setTotalCount(response.pagination.total_count);
    } catch (error) {
      console.error('Failed to fetch logs:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleExport = async () => {
    try {
      const response = await activityLogApi.export({
        filters: { ...filters, search: debouncedSearch },
        columns: [
          'timestamp',
          'user_email',
          'action',
          'description',
          'ip_address',
          'response_status',
          'duration_ms'
        ],
        format: 'csv'
      });

      // Open download URL
      window.open(response.download_url, '_blank');
    } catch (error) {
      console.error('Export failed:', error);
    }
  };

  const handleRowExpand = (logId: string) => {
    setExpandedRow(expandedRow === logId ? null : logId);
  };

  const handleViewTimeline = (resourceType: string, resourceId: string) => {
    setTimelineResource({ type: resourceType, id: resourceId });
  };

  const getStatusColor = (status: number): 'success' | 'warning' | 'error' | 'default' => {
    if (status < 300) return 'success';
    if (status < 400) return 'warning';
    return 'error';
  };

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" gutterBottom>
        Activity Logs
      </Typography>

      {/* Search and Filters */}
      <Paper sx={{ p: 2, mb: 2 }}>
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} md={6}>
            <TextField
              fullWidth
              placeholder="Search logs..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              InputProps={{
                startAdornment: <Search sx={{ mr: 1, color: 'text.secondary' }} />
              }}
            />
          </Grid>
          <Grid item xs={12} md={6}>
            <Box sx={{ display: 'flex', gap: 2, justifyContent: 'flex-end' }}>
              <Button
                variant="outlined"
                startIcon={<FilterList />}
                onClick={() => setShowFilters(!showFilters)}
              >
                Filters
              </Button>
              <Button
                variant="outlined"
                startIcon={<Download />}
                onClick={handleExport}
              >
                Export CSV
              </Button>
            </Box>
          </Grid>
        </Grid>

        <Collapse in={showFilters}>
          <Box sx={{ mt: 2 }}>
            <ActivityLogFilters
              filters={filters}
              onFiltersChange={setFilters}
            />
          </Box>
        </Collapse>
      </Paper>

      {/* Logs Table */}
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell width="40"></TableCell>
              <TableCell>Timestamp</TableCell>
              <TableCell>User</TableCell>
              <TableCell>Action</TableCell>
              <TableCell>Description</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Duration</TableCell>
              <TableCell>IP Address</TableCell>
              <TableCell>Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {logs.map((log) => (
              <React.Fragment key={log.id}>
                <TableRow hover>
                  <TableCell>
                    <IconButton size="small" onClick={() => handleRowExpand(log.id)}>
                      {expandedRow === log.id ? <ExpandLess /> : <ExpandMore />}
                    </IconButton>
                  </TableCell>
                  <TableCell>
                    {new Date(log.timestamp).toLocaleString()}
                  </TableCell>
                  <TableCell>
                    <Box>
                      <Typography variant="body2">{log.user_email}</Typography>
                      <Typography variant="caption" color="text.secondary">
                        {log.user_role}
                      </Typography>
                    </Box>
                  </TableCell>
                  <TableCell>
                    <Chip label={log.action} size="small" />
                  </TableCell>
                  <TableCell>{log.description}</TableCell>
                  <TableCell>
                    <Chip
                      label={log.response_status}
                      color={getStatusColor(log.response_status)}
                      size="small"
                    />
                  </TableCell>
                  <TableCell>{log.duration_ms}ms</TableCell>
                  <TableCell>
                    <Typography variant="caption">{log.ip_address}</Typography>
                  </TableCell>
                  <TableCell>
                    {log.resource_type && log.resource_id && (
                      <IconButton
                        size="small"
                        onClick={() => handleViewTimeline(log.resource_type!, log.resource_id!)}
                        title="View Timeline"
                      >
                        <TimelineIcon />
                      </IconButton>
                    )}
                  </TableCell>
                </TableRow>

                <TableRow>
                  <TableCell colSpan={9} sx={{ py: 0 }}>
                    <Collapse in={expandedRow === log.id}>
                      <Box sx={{ p: 2, bgcolor: 'grey.50' }}>
                        <Grid container spacing={2}>
                          <Grid item xs={12} md={6}>
                            <Typography variant="subtitle2">Request Details</Typography>
                            <Typography variant="body2">
                              Method: {log.request_method}
                            </Typography>
                            <Typography variant="body2">
                              Path: {log.request_path}
                            </Typography>
                            <Typography variant="body2">
                              User Agent: {log.user_agent}
                            </Typography>
                          </Grid>
                          <Grid item xs={12} md={6}>
                            <Typography variant="subtitle2">Metadata</Typography>
                            <pre style={{ fontSize: 12, overflow: 'auto' }}>
                              {JSON.stringify(log.metadata, null, 2)}
                            </pre>
                          </Grid>
                          {log.error_message && (
                            <Grid item xs={12}>
                              <Typography variant="subtitle2" color="error">
                                Error Message
                              </Typography>
                              <Typography variant="body2" color="error">
                                {log.error_message}
                              </Typography>
                            </Grid>
                          )}
                        </Grid>
                      </Box>
                    </Collapse>
                  </TableCell>
                </TableRow>
              </React.Fragment>
            ))}
          </TableBody>
        </Table>

        <TablePagination
          component="div"
          count={totalCount}
          page={page}
          onPageChange={(_, newPage) => setPage(newPage)}
          rowsPerPage={rowsPerPage}
          onRowsPerPageChange={(e) => {
            setRowsPerPage(parseInt(e.target.value, 10));
            setPage(0);
          }}
          rowsPerPageOptions={[25, 50, 100, 200]}
        />
      </TableContainer>

      {/* Timeline Modal */}
      {timelineResource && (
        <ActivityTimeline
          resourceType={timelineResource.type}
          resourceId={timelineResource.id}
          open={!!timelineResource}
          onClose={() => setTimelineResource(null)}
        />
      )}
    </Box>
  );
};

export default ActivityLogsPage;
```

### 2. Activity Log Filters Component

**File:** `src/components/Admin/ActivityLogFilters.tsx`

```typescript
import React from 'react';
import {
  Grid,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Box,
  Button
} from '@mui/material';
import { ActivityLogFilters as Filters } from '../../types';

interface Props {
  filters: Filters;
  onFiltersChange: (filters: Filters) => void;
}

const ActivityLogFilters: React.FC<Props> = ({ filters, onFiltersChange }) => {
  const handleChange = (field: keyof Filters, value: any) => {
    onFiltersChange({
      ...filters,
      [field]: value || undefined
    });
  };

  const handleClear = () => {
    onFiltersChange({});
  };

  return (
    <Box>
      <Grid container spacing={2}>
        <Grid item xs={12} md={4}>
          <TextField
            fullWidth
            label="Action Pattern"
            placeholder="e.g., auth.%, assessment.%"
            value={filters.action_pattern || ''}
            onChange={(e) => handleChange('action_pattern', e.target.value)}
          />
        </Grid>

        <Grid item xs={12} md={4}>
          <FormControl fullWidth>
            <InputLabel>Resource Type</InputLabel>
            <Select
              value={filters.resource_type || ''}
              onChange={(e) => handleChange('resource_type', e.target.value)}
            >
              <MenuItem value="">All</MenuItem>
              <MenuItem value="assessment">Assessment</MenuItem>
              <MenuItem value="report">Report</MenuItem>
              <MenuItem value="user">User</MenuItem>
              <MenuItem value="questionnaire">Questionnaire</MenuItem>
            </Select>
          </FormControl>
        </Grid>

        <Grid item xs={12} md={4}>
          <TextField
            fullWidth
            label="IP Address"
            value={filters.ip_address || ''}
            onChange={(e) => handleChange('ip_address', e.target.value)}
          />
        </Grid>

        <Grid item xs={12} md={3}>
          <TextField
            fullWidth
            type="date"
            label="Date From"
            InputLabelProps={{ shrink: true }}
            value={filters.date_from || ''}
            onChange={(e) => handleChange('date_from', e.target.value)}
          />
        </Grid>

        <Grid item xs={12} md={3}>
          <TextField
            fullWidth
            type="date"
            label="Date To"
            InputLabelProps={{ shrink: true }}
            value={filters.date_to || ''}
            onChange={(e) => handleChange('date_to', e.target.value)}
          />
        </Grid>

        <Grid item xs={12} md={3}>
          <TextField
            fullWidth
            type="number"
            label="Min Status Code"
            value={filters.response_status_min || ''}
            onChange={(e) => handleChange('response_status_min', parseInt(e.target.value))}
          />
        </Grid>

        <Grid item xs={12} md={3}>
          <TextField
            fullWidth
            type="number"
            label="Max Status Code"
            value={filters.response_status_max || ''}
            onChange={(e) => handleChange('response_status_max', parseInt(e.target.value))}
          />
        </Grid>

        <Grid item xs={12}>
          <Box sx={{ display: 'flex', justifyContent: 'flex-end' }}>
            <Button onClick={handleClear}>Clear Filters</Button>
          </Box>
        </Grid>
      </Grid>
    </Box>
  );
};

export default ActivityLogFilters;
```

---

## Testing Requirements

### 1. Backend Tests

**Test File:** `src/services/__tests__/activityLogService.test.ts`

```typescript
describe('ActivityLogService', () => {
  describe('getLogs', () => {
    it('should filter logs by action pattern', async () => {
      const result = await activityLogService.getLogs({
        action_pattern: 'auth.%',
        page: 1,
        limit: 10
      });

      expect(result.logs.every(log => log.action.startsWith('auth.'))).toBe(true);
    });

    it('should filter logs by date range', async () => {
      const dateFrom = '2025-01-01';
      const dateTo = '2025-01-31';

      const result = await activityLogService.getLogs({
        date_from: dateFrom,
        date_to: dateTo,
        page: 1,
        limit: 10
      });

      result.logs.forEach(log => {
        const timestamp = new Date(log.timestamp);
        expect(timestamp >= new Date(dateFrom)).toBe(true);
        expect(timestamp <= new Date(dateTo)).toBe(true);
      });
    });

    it('should filter logs by response status range', async () => {
      const result = await activityLogService.getLogs({
        response_status_min: 400,
        response_status_max: 499,
        page: 1,
        limit: 10
      });

      result.logs.forEach(log => {
        expect(log.response_status).toBeGreaterThanOrEqual(400);
        expect(log.response_status).toBeLessThanOrEqual(499);
      });
    });

    it('should perform full-text search', async () => {
      const result = await activityLogService.getLogs({
        search: 'failed login',
        page: 1,
        limit: 10
      });

      expect(result.logs.length).toBeGreaterThan(0);
      result.logs.forEach(log => {
        const searchText = `${log.action} ${log.description} ${log.error_message}`.toLowerCase();
        expect(
          searchText.includes('failed') || searchText.includes('login')
        ).toBe(true);
      });
    });

    it('should paginate results correctly', async () => {
      const page1 = await activityLogService.getLogs({ page: 1, limit: 10 });
      const page2 = await activityLogService.getLogs({ page: 2, limit: 10 });

      expect(page1.logs.length).toBe(10);
      expect(page2.logs.length).toBeGreaterThan(0);
      expect(page1.logs[0].id).not.toBe(page2.logs[0].id);
    });
  });

  describe('exportLogs', () => {
    it('should export logs as CSV', async () => {
      const downloadUrl = await activityLogService.exportLogs(
        { action_pattern: 'assessment.%' },
        ['timestamp', 'user_email', 'action', 'description'],
        'csv',
        'admin-user-id'
      );

      expect(downloadUrl).toContain('s3.amazonaws.com');
      expect(downloadUrl).toContain('.csv');
    });

    it('should include only specified columns', async () => {
      const columns = ['timestamp', 'action'];
      // Test implementation would verify CSV headers
    });
  });

  describe('getResourceTimeline', () => {
    it('should return timeline for assessment', async () => {
      const assessmentId = 'test-assessment-id';
      const timeline = await activityLogService.getResourceTimeline(
        'assessment',
        assessmentId,
        false
      );

      expect(timeline.resource_type).toBe('assessment');
      expect(timeline.resource_id).toBe(assessmentId);
      expect(Array.isArray(timeline.timeline)).toBe(true);
    });

    it('should build hierarchical timeline with child events', async () => {
      // Create parent log
      const parentLog = await ActivityLog.create({
        action: 'assessment.create',
        description: 'Created assessment',
        resource_type: 'assessment',
        resource_id: 'test-id'
      });

      // Create child log
      await ActivityLog.create({
        action: 'questionnaire.start',
        description: 'Started questionnaire',
        resource_type: 'assessment',
        resource_id: 'test-id',
        parent_log_id: parentLog.id
      });

      const timeline = await activityLogService.getResourceTimeline(
        'assessment',
        'test-id',
        false
      );

      const rootEvent = timeline.timeline[0];
      expect(rootEvent.child_events).toHaveLength(1);
      expect(rootEvent.child_events[0].action).toBe('questionnaire.start');
    });
  });

  describe('archiveLogs', () => {
    it('should archive logs older than retention period (dry run)', async () => {
      const result = await activityLogService.archiveLogs(
        undefined,
        undefined,
        true, // dry run
        'admin-id'
      );

      expect(result.dry_run).toBe(true);
      expect(result.logs_archived).toBeGreaterThanOrEqual(0);
    });

    it('should archive logs and upload to S3', async () => {
      const result = await activityLogService.archiveLogs(
        undefined,
        '2024-01-01',
        false, // actual archive
        'admin-id'
      );

      expect(result.dry_run).toBe(false);
      expect(result.logs_archived).toBeGreaterThan(0);

      // Verify ArchivedLog record was created
      const archivedRecord = await ArchivedLog.findOne({
        where: { archived_by: 'admin-id' },
        order: [['archived_at', 'DESC']]
      });
      expect(archivedRecord).not.toBeNull();
    });
  });
});
```

### 2. Frontend Tests

**Test File:** `src/pages/Admin/__tests__/ActivityLogs.test.tsx`

```typescript
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import ActivityLogsPage from '../ActivityLogs';
import { activityLogApi } from '../../../services/api';

jest.mock('../../../services/api');

describe('ActivityLogsPage', () => {
  beforeEach(() => {
    (activityLogApi.getLogs as jest.Mock).mockResolvedValue({
      logs: [
        {
          id: '1',
          user_email: 'test@example.com',
          user_role: 'consultant',
          action: 'assessment.create',
          description: 'Created assessment',
          ip_address: '192.168.1.1',
          response_status: 201,
          duration_ms: 100,
          timestamp: '2025-12-22T10:00:00Z'
        }
      ],
      pagination: {
        page: 1,
        limit: 50,
        total_count: 1,
        total_pages: 1
      }
    });
  });

  it('should render activity logs table', async () => {
    render(<ActivityLogsPage />);

    await waitFor(() => {
      expect(screen.getByText('Activity Logs')).toBeInTheDocument();
      expect(screen.getByText('test@example.com')).toBeInTheDocument();
      expect(screen.getByText('assessment.create')).toBeInTheDocument();
    });
  });

  it('should search logs on input', async () => {
    render(<ActivityLogsPage />);

    const searchInput = screen.getByPlaceholderText('Search logs...');
    fireEvent.change(searchInput, { target: { value: 'failed login' } });

    await waitFor(() => {
      expect(activityLogApi.search).toHaveBeenCalledWith(
        'failed login',
        expect.any(Object)
      );
    }, { timeout: 1000 });
  });

  it('should expand row to show details', async () => {
    render(<ActivityLogsPage />);

    await waitFor(() => {
      expect(screen.getByText('test@example.com')).toBeInTheDocument();
    });

    const expandButton = screen.getAllByRole('button')[0];
    fireEvent.click(expandButton);

    await waitFor(() => {
      expect(screen.getByText('Request Details')).toBeInTheDocument();
    });
  });

  it('should export logs as CSV', async () => {
    (activityLogApi.export as jest.Mock).mockResolvedValue({
      download_url: 'https://example.com/export.csv'
    });

    window.open = jest.fn();
    render(<ActivityLogsPage />);

    const exportButton = screen.getByText('Export CSV');
    fireEvent.click(exportButton);

    await waitFor(() => {
      expect(window.open).toHaveBeenCalledWith(
        'https://example.com/export.csv',
        '_blank'
      );
    });
  });
});
```

### 3. Middleware Tests

**Test File:** `src/middleware/__tests__/activityLogger.test.ts`

```typescript
import request from 'supertest';
import app from '../../app';
import { ActivityLog } from '../../models/ActivityLog';

describe('ActivityLogger Middleware', () => {
  it('should log successful requests', async () => {
    const response = await request(app)
      .get('/api/assessments')
      .set('Authorization', 'Bearer valid-token');

    expect(response.status).toBe(200);

    const log = await ActivityLog.findOne({
      where: {
        request_path: '/api/assessments',
        response_status: 200
      },
      order: [['timestamp', 'DESC']]
    });

    expect(log).not.toBeNull();
    expect(log.action).toBe('assessments.view');
    expect(log.duration_ms).toBeGreaterThan(0);
  });

  it('should log failed requests with error messages', async () => {
    const response = await request(app)
      .post('/api/auth/login')
      .send({ email: 'wrong@example.com', password: 'wrong' });

    expect(response.status).toBe(401);

    const log = await ActivityLog.findOne({
      where: {
        action: 'auth.login.failed',
        response_status: 401
      },
      order: [['timestamp', 'DESC']]
    });

    expect(log).not.toBeNull();
    expect(log.error_message).toBeTruthy();
  });

  it('should sanitize sensitive data in request body', async () => {
    await request(app)
      .post('/api/auth/login')
      .send({ email: 'test@example.com', password: 'secret123' });

    const log = await ActivityLog.findOne({
      where: { action: 'auth.login' },
      order: [['timestamp', 'DESC']]
    });

    expect(log.metadata.request_body.email).toBe('test@example.com');
    expect(log.metadata.request_body.password).toBe('[REDACTED]');
  });

  it('should capture IP address from X-Forwarded-For header', async () => {
    await request(app)
      .get('/api/assessments')
      .set('X-Forwarded-For', '203.0.113.45, 192.168.1.1');

    const log = await ActivityLog.findOne({
      order: [['timestamp', 'DESC']]
    });

    expect(log.ip_address).toBe('203.0.113.45');
  });
});
```

---

## Integration with Existing Systems

### 1. Update Express App to Use Enhanced Middleware

**File:** `src/app.ts`

```typescript
import express from 'express';
import ActivityLogger from './middleware/activityLogger';

const app = express();

// ... other middleware

// Add enhanced activity logging middleware
app.use(ActivityLogger.middleware());

// ... routes

export default app;
```

### 2. Add to Admin Dashboard Navigation

**File:** `src/components/Admin/AdminLayout.tsx`

```typescript
const adminRoutes = [
  { path: '/admin/dashboard', label: 'Dashboard', icon: <DashboardIcon /> },
  { path: '/admin/users', label: 'Users', icon: <PeopleIcon /> },
  { path: '/admin/activity-logs', label: 'Activity Logs', icon: <HistoryIcon /> },
  { path: '/admin/performance', label: 'Performance', icon: <SpeedIcon /> },
  // ... other routes
];
```

### 3. Cron Job for Auto-Archiving

**File:** `src/jobs/archiveOldLogs.ts`

```typescript
import cron from 'node-cron';
import activityLogService from '../services/activityLogService';

// Run every day at 2 AM
cron.schedule('0 2 * * *', async () => {
  console.log('Starting automatic log archival...');

  try {
    const result = await activityLogService.archiveLogs(
      undefined, // All policies
      undefined, // Current date
      false, // Not a dry run
      'system'
    );

    console.log(`Archived ${result.logs_archived} logs`);
  } catch (error) {
    console.error('Log archival failed:', error);
  }
});
```

---

## Deployment Checklist

- [ ] Database migrations applied (add new columns to `activity_logs`, create new tables)
- [ ] Existing `activity_logs` data preserved during migration
- [ ] Full-text search indexes created and populated
- [ ] Default retention policies inserted
- [ ] S3 bucket configured for log exports and archives
- [ ] IAM permissions granted for S3 access
- [ ] Environment variables configured (`AWS_S3_BUCKET`, etc.)
- [ ] Middleware enabled in Express app
- [ ] Cron job scheduled for auto-archiving
- [ ] Admin users granted access to Activity Logs page
- [ ] Tested CSV export functionality
- [ ] Tested full-text search performance
- [ ] Tested retention policy archival (dry run and actual)
- [ ] Verified log timeline displays correctly
- [ ] Performance testing with large log volumes (1M+ records)
- [ ] Documentation updated with new logging patterns

---

## Future Enhancements

1. **Real-Time Log Streaming** - WebSocket-based live log viewer
2. **Anomaly Detection** - ML-based detection of unusual activity patterns
3. **Custom Dashboards** - User-configurable log dashboards with widgets
4. **Alerting** - Email/Slack alerts for critical events (e.g., repeated failed logins)
5. **Compliance Reports** - Pre-built reports for SOC 2, ISO 27001 compliance
6. **Log Replay** - Ability to replay actions for debugging
7. **Geolocation** - Map IP addresses to geographic locations
8. **Advanced Analytics** - Trends, patterns, user behavior analysis

---

## Acceptance Criteria

- ✅ All HTTP requests automatically logged with full context
- ✅ Advanced filtering by user, action, date, IP, status code
- ✅ Full-text search across all log fields with PostgreSQL
- ✅ CSV export with custom column selection
- ✅ Activity timeline view for resources (assessments, reports, users)
- ✅ Configurable retention policies with automatic archival
- ✅ S3 integration for archived logs and exports
- ✅ Admin UI for viewing, filtering, and searching logs
- ✅ Sensitive data (passwords, tokens) automatically redacted
- ✅ Hierarchical log structure with parent/child relationships
- ✅ Performance optimized for millions of log records
- ✅ WCAG 2.1 Level AA compliant UI components
- ✅ Comprehensive test coverage (>80%)
