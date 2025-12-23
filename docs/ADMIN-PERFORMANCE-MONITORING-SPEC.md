# Admin Performance Monitoring - Technical Specification

**Version:** 1.0
**Date:** 2025-12-22
**Work Stream:** 45 - Admin Performance Monitoring
**Phase:** 3 - Advanced Features
**Dependency Level:** 1

## Overview

The Admin Performance Monitoring feature provides system administrators with comprehensive dashboards to monitor application health, user activity, performance metrics, and business KPIs. This enables proactive issue detection and data-driven decision making.

### Key Features

1. **System Health Dashboard** - Server metrics, database performance, API health
2. **User Activity Monitoring** - Active users, engagement metrics, feature adoption
3. **Business KPIs** - Revenue metrics, conversion rates, retention
4. **Performance Metrics** - Response times, error rates, throughput
5. **Real-time Alerts** - Automated notifications for critical issues

## Requirements Mapping

**REQ-ADMIN-005:** Admin performance monitoring dashboard
**REQ-PERF-001:** Page load times <3 seconds (monitoring)
**REQ-PERF-002:** Report generation <5 seconds (monitoring)

## Metrics Categories

### 1. System Health Metrics

**Server Metrics:**
- CPU usage (%)
- Memory usage (%)
- Disk usage (%)
- Network I/O (MB/s)
- Active connections

**Database Metrics:**
- Query response time (ms)
- Connection pool usage
- Slow queries (>1s)
- Database size (MB)
- Index efficiency

**API Health:**
- Uptime (%)
- Request rate (req/s)
- Average response time (ms)
- Error rate (%)
- 5xx error count

### 2. User Activity Metrics

**Active Users:**
- Current online users
- Daily active users (DAU)
- Weekly active users (WAU)
- Monthly active users (MAU)
- User growth rate

**Engagement:**
- Sessions per user
- Average session duration
- Pages per session
- Bounce rate (%)
- Return visitor rate (%)

**Feature Adoption:**
- Assessments created per day
- Reports generated per day
- Checklists created per day
- Emails sent per day
- Shared links created per day

### 3. Business KPIs

**Conversion Metrics:**
- Trial-to-paid conversion rate
- Assessment completion rate
- Time to first assessment
- Activation rate (first report generated)

**Revenue Metrics:**
- Monthly recurring revenue (MRR)
- Annual recurring revenue (ARR)
- Average revenue per user (ARPU)
- Customer lifetime value (LTV)
- Churn rate (%)

**Usage Metrics:**
- Total assessments
- Total consultants
- Total clients
- Reports generated
- Storage used (GB)

### 4. Performance Metrics

**Response Times:**
- Dashboard load time (P50, P95, P99)
- API endpoint response times
- Database query times
- Report generation time

**Error Tracking:**
- 4xx errors (client errors)
- 5xx errors (server errors)
- JavaScript errors
- Failed API requests
- Timeout errors

## Database Schema

### system_metrics Table (new)

```sql
CREATE TABLE system_metrics (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  recorded_at TIMESTAMP DEFAULT NOW(),
  metric_type VARCHAR(50) NOT NULL, -- 'cpu', 'memory', 'disk', 'network'

  -- Server metrics
  cpu_usage_percent DECIMAL(5,2),
  memory_usage_percent DECIMAL(5,2),
  disk_usage_percent DECIMAL(5,2),
  network_in_mbps DECIMAL(10,2),
  network_out_mbps DECIMAL(10,2),

  -- Database metrics
  db_connections_active INTEGER,
  db_connections_total INTEGER,
  db_query_avg_ms DECIMAL(10,2),
  db_slow_queries_count INTEGER,

  -- API metrics
  api_request_rate DECIMAL(10,2),
  api_avg_response_ms DECIMAL(10,2),
  api_error_rate DECIMAL(5,2),
  api_5xx_count INTEGER
);

-- Partition by month for efficient querying
CREATE INDEX idx_system_metrics_recorded_at
ON system_metrics(recorded_at DESC);

CREATE INDEX idx_system_metrics_type
ON system_metrics(metric_type, recorded_at DESC);
```

### user_activity_metrics Table (new)

```sql
CREATE TABLE user_activity_metrics (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  recorded_at TIMESTAMP DEFAULT NOW(),
  date DATE NOT NULL,

  -- Active users
  dau INTEGER DEFAULT 0, -- Daily active users
  wau INTEGER DEFAULT 0, -- Weekly active users
  mau INTEGER DEFAULT 0, -- Monthly active users

  -- Engagement
  total_sessions INTEGER DEFAULT 0,
  avg_session_duration_minutes DECIMAL(10,2),
  pages_per_session DECIMAL(5,2),
  bounce_rate DECIMAL(5,2),

  -- Feature usage
  assessments_created INTEGER DEFAULT 0,
  reports_generated INTEGER DEFAULT 0,
  checklists_created INTEGER DEFAULT 0,
  emails_sent INTEGER DEFAULT 0,
  shared_links_created INTEGER DEFAULT 0
);

-- One record per day
CREATE UNIQUE INDEX idx_user_activity_date
ON user_activity_metrics(date);
```

### performance_metrics Table (new)

```sql
CREATE TABLE performance_metrics (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  recorded_at TIMESTAMP DEFAULT NOW(),
  metric_name VARCHAR(100) NOT NULL,
  endpoint VARCHAR(255), -- For API metrics

  -- Latency metrics (milliseconds)
  p50 DECIMAL(10,2),
  p95 DECIMAL(10,2),
  p99 DECIMAL(10,2),
  avg DECIMAL(10,2),
  min DECIMAL(10,2),
  max DECIMAL(10,2),

  -- Count metrics
  request_count INTEGER,
  error_count INTEGER,
  timeout_count INTEGER
);

CREATE INDEX idx_performance_metrics_recorded_at
ON performance_metrics(recorded_at DESC);

CREATE INDEX idx_performance_metrics_name
ON performance_metrics(metric_name, recorded_at DESC);
```

## API Endpoints

### 1. Get System Health Overview

```
GET /api/v1/admin/monitoring/health
Authorization: Bearer <admin_jwt_token>
```

**Response 200:**
```json
{
  "timestamp": "2025-12-22T15:30:00Z",
  "status": "healthy",
  "uptime_seconds": 8640000,
  "server": {
    "cpu_usage": 45.2,
    "memory_usage": 68.5,
    "disk_usage": 52.3,
    "load_average": [1.5, 1.8, 2.1]
  },
  "database": {
    "status": "connected",
    "connections_active": 15,
    "connections_max": 100,
    "query_avg_ms": 45.3,
    "slow_queries_last_hour": 3
  },
  "api": {
    "status": "operational",
    "uptime_percent": 99.98,
    "request_rate": 125.5,
    "avg_response_ms": 235,
    "error_rate": 0.15
  }
}
```

### 2. Get User Activity Metrics

```
GET /api/v1/admin/monitoring/users?period=30d
Authorization: Bearer <admin_jwt_token>
```

**Response 200:**
```json
{
  "period": "30d",
  "summary": {
    "total_users": 1250,
    "active_users_30d": 890,
    "new_users_30d": 125,
    "dau_avg": 420,
    "wau_avg": 750,
    "mau": 890
  },
  "daily_active_users": [
    { "date": "2025-11-22", "count": 385 },
    { "date": "2025-11-23", "count": 412 },
    { "date": "2025-11-24", "count": 398 }
    // ... 30 days
  ],
  "feature_adoption": {
    "assessments_created": 856,
    "reports_generated": 742,
    "checklists_created": 428,
    "emails_sent": 1245,
    "shared_links_created": 156
  },
  "engagement": {
    "avg_session_duration_minutes": 18.5,
    "pages_per_session": 12.3,
    "bounce_rate": 15.2,
    "return_visitor_rate": 68.5
  }
}
```

### 3. Get Performance Metrics

```
GET /api/v1/admin/monitoring/performance?period=24h
Authorization: Bearer <admin_jwt_token>
```

**Response 200:**
```json
{
  "period": "24h",
  "endpoints": [
    {
      "endpoint": "GET /api/v1/assessments",
      "request_count": 15420,
      "avg_response_ms": 145,
      "p50": 125,
      "p95": 320,
      "p99": 650,
      "error_count": 12,
      "error_rate": 0.08
    },
    {
      "endpoint": "POST /api/v1/assessments/:id/report",
      "request_count": 3240,
      "avg_response_ms": 3200,
      "p50": 2800,
      "p95": 4500,
      "p99": 6200,
      "error_count": 5,
      "error_rate": 0.15
    }
  ],
  "slowest_endpoints": [
    { "endpoint": "POST /api/v1/assessments/:id/report", "avg_ms": 3200 },
    { "endpoint": "GET /api/v1/assessments/:id/checklist", "avg_ms": 420 }
  ],
  "error_breakdown": {
    "4xx": 145,
    "5xx": 23
  }
}
```

### 4. Get Business KPIs

```
GET /api/v1/admin/monitoring/kpis?period=30d
Authorization: Bearer <admin_jwt_token>
```

**Response 200:**
```json
{
  "period": "30d",
  "revenue": {
    "mrr": 45600,
    "arr": 547200,
    "arpu": 36.48,
    "growth_rate": 12.5
  },
  "conversion": {
    "trial_to_paid_rate": 18.5,
    "assessment_completion_rate": 72.3,
    "time_to_first_assessment_hours": 2.8,
    "activation_rate": 85.6
  },
  "retention": {
    "churn_rate": 3.2,
    "retention_rate_30d": 96.8,
    "ltv": 1248
  },
  "usage": {
    "total_assessments": 12450,
    "total_consultants": 1250,
    "total_clients": 8960,
    "reports_generated": 10230,
    "storage_used_gb": 145.8
  }
}
```

### 5. Get Real-time Metrics (WebSocket)

```
WS /ws/admin/monitoring
Authorization: Bearer <admin_jwt_token>
```

**Server pushes updates every 5 seconds:**
```json
{
  "timestamp": "2025-12-22T15:30:05Z",
  "active_users": 125,
  "request_rate": 132.5,
  "avg_response_ms": 242,
  "error_count_last_minute": 2,
  "cpu_usage": 46.8,
  "memory_usage": 69.2
}
```

## Backend Implementation

### Metrics Collection Service

```typescript
import os from 'os';
import { promisify } from 'util';
import { exec } from 'child_process';

const execAsync = promisify(exec);

export class MetricsCollectionService {
  /**
   * Collects system metrics every 60 seconds
   */
  async collectSystemMetrics(): Promise<void> {
    const metrics = {
      cpu_usage_percent: await this.getCPUUsage(),
      memory_usage_percent: this.getMemoryUsage(),
      disk_usage_percent: await this.getDiskUsage(),
      db_connections_active: await this.getDBConnections(),
      db_query_avg_ms: await this.getAvgQueryTime(),
      api_request_rate: await this.getRequestRate(),
      api_avg_response_ms: await this.getAvgResponseTime(),
      api_error_rate: await this.getErrorRate()
    };

    await SystemMetrics.create({
      recorded_at: new Date(),
      metric_type: 'system',
      ...metrics
    });
  }

  private getCPUUsage(): number {
    const cpus = os.cpus();
    let totalIdle = 0;
    let totalTick = 0;

    cpus.forEach(cpu => {
      for (const type in cpu.times) {
        totalTick += cpu.times[type];
      }
      totalIdle += cpu.times.idle;
    });

    const idle = totalIdle / cpus.length;
    const total = totalTick / cpus.length;
    const usage = 100 - ~~(100 * idle / total);

    return usage;
  }

  private getMemoryUsage(): number {
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;
    return Math.round((usedMem / totalMem) * 100 * 100) / 100;
  }

  private async getDiskUsage(): Promise<number> {
    try {
      const { stdout } = await execAsync("df -h / | tail -1 | awk '{print $5}' | sed 's/%//'");
      return parseFloat(stdout.trim());
    } catch {
      return 0;
    }
  }

  private async getDBConnections(): Promise<number> {
    const result = await sequelize.query(
      'SELECT count(*) as count FROM pg_stat_activity',
      { type: QueryTypes.SELECT }
    );
    return result[0].count;
  }

  private async getAvgQueryTime(): Promise<number> {
    // Get average query time from last 1000 queries
    const result = await sequelize.query(`
      SELECT AVG(total_time) as avg_time
      FROM pg_stat_statements
      ORDER BY total_time DESC
      LIMIT 1000
    `, { type: QueryTypes.SELECT });

    return result[0]?.avg_time || 0;
  }

  private async getRequestRate(): Promise<number> {
    // Calculate from access logs or in-memory counter
    const now = Date.now();
    const oneMinuteAgo = now - 60000;

    // Assuming you have request logging
    const count = await RequestLog.count({
      where: {
        timestamp: { [Op.gte]: new Date(oneMinuteAgo) }
      }
    });

    return count / 60; // Requests per second
  }

  private async getAvgResponseTime(): Promise<number> {
    const oneMinuteAgo = new Date(Date.now() - 60000);

    const result = await RequestLog.findAll({
      where: {
        timestamp: { [Op.gte]: oneMinuteAgo }
      },
      attributes: [
        [sequelize.fn('AVG', sequelize.col('response_time_ms')), 'avg']
      ]
    });

    return result[0]?.get('avg') || 0;
  }

  private async getErrorRate(): Promise<number> {
    const oneMinuteAgo = new Date(Date.now() - 60000);

    const total = await RequestLog.count({
      where: {
        timestamp: { [Op.gte]: oneMinuteAgo }
      }
    });

    const errors = await RequestLog.count({
      where: {
        timestamp: { [Op.gte]: oneMinuteAgo },
        status_code: { [Op.gte]: 500 }
      }
    });

    return total > 0 ? (errors / total) * 100 : 0;
  }

  /**
   * Collects user activity metrics daily
   */
  async collectUserActivityMetrics(): Promise<void> {
    const today = new Date().toISOString().split('T')[0];

    // Calculate DAU (distinct users who logged in today)
    const dau = await sequelize.query(`
      SELECT COUNT(DISTINCT user_id) as count
      FROM activity_logs
      WHERE DATE(created_at) = :today
    `, {
      replacements: { today },
      type: QueryTypes.SELECT
    });

    // Calculate MAU (distinct users in last 30 days)
    const mau = await sequelize.query(`
      SELECT COUNT(DISTINCT user_id) as count
      FROM activity_logs
      WHERE created_at >= NOW() - INTERVAL '30 days'
    `, { type: QueryTypes.SELECT });

    // Feature usage counts
    const assessmentsCreated = await Assessment.count({
      where: {
        created_at: {
          [Op.gte]: new Date(today),
          [Op.lt]: new Date(new Date(today).getTime() + 24 * 60 * 60 * 1000)
        }
      }
    });

    await UserActivityMetrics.upsert({
      date: today,
      dau: dau[0].count,
      mau: mau[0].count,
      assessments_created: assessmentsCreated
      // ... other metrics
    });
  }
}

// Start metrics collection
const metricsService = new MetricsCollectionService();

// Collect system metrics every 60 seconds
setInterval(() => {
  metricsService.collectSystemMetrics().catch(console.error);
}, 60000);

// Collect user activity metrics daily at midnight
cron.schedule('0 0 * * *', () => {
  metricsService.collectUserActivityMetrics().catch(console.error);
});
```

### Admin Monitoring Controller

```typescript
export class AdminMonitoringController {
  async getHealthOverview(req: Request, res: Response) {
    // Get latest system metrics
    const latestMetrics = await SystemMetrics.findOne({
      order: [['recorded_at', 'DESC']]
    });

    // Get database status
    const dbStatus = await this.checkDatabaseHealth();

    // Get API status
    const apiStatus = await this.getAPIStatus();

    return res.json({
      timestamp: new Date().toISOString(),
      status: this.determineOverallStatus(latestMetrics, dbStatus, apiStatus),
      uptime_seconds: process.uptime(),
      server: {
        cpu_usage: latestMetrics?.cpu_usage_percent,
        memory_usage: latestMetrics?.memory_usage_percent,
        disk_usage: latestMetrics?.disk_usage_percent,
        load_average: os.loadavg()
      },
      database: dbStatus,
      api: apiStatus
    });
  }

  async getUserActivityMetrics(req: Request, res: Response) {
    const { period = '30d' } = req.query;
    const days = parseInt(period.replace('d', ''));

    const metrics = await UserActivityMetrics.findAll({
      where: {
        date: {
          [Op.gte]: new Date(Date.now() - days * 24 * 60 * 60 * 1000)
        }
      },
      order: [['date', 'ASC']]
    });

    // Calculate summary
    const summary = {
      total_users: await User.count(),
      active_users_30d: metrics[metrics.length - 1]?.mau || 0,
      dau_avg: Math.round(
        metrics.reduce((sum, m) => sum + m.dau, 0) / metrics.length
      )
    };

    return res.json({
      period,
      summary,
      daily_active_users: metrics.map(m => ({
        date: m.date,
        count: m.dau
      })),
      feature_adoption: {
        assessments_created: metrics.reduce((sum, m) => sum + m.assessments_created, 0)
        // ... other features
      }
    });
  }

  private async checkDatabaseHealth(): Promise<any> {
    try {
      await sequelize.authenticate();

      const connections = await sequelize.query(
        'SELECT count(*) as active, max_connections FROM pg_stat_activity, (SELECT setting::int as max_connections FROM pg_settings WHERE name = \'max_connections\') a GROUP BY max_connections',
        { type: QueryTypes.SELECT }
      );

      return {
        status: 'connected',
        connections_active: connections[0]?.active || 0,
        connections_max: connections[0]?.max_connections || 100
      };
    } catch (error) {
      return {
        status: 'disconnected',
        error: error.message
      };
    }
  }
}
```

## Frontend Implementation

### Admin Monitoring Dashboard

```typescript
import React, { useEffect, useState } from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography
} from '@mui/material';
import { Line, Doughnut } from 'react-chartjs-2';
import { useAdminMetrics } from '../hooks/useAdminMetrics';

export function AdminMonitoringDashboard() {
  const { health, userActivity, performance, kpis } = useAdminMetrics('30d');

  return (
    <Box p={3}>
      <Typography variant="h4" gutterBottom>
        System Monitoring Dashboard
      </Typography>

      {/* System Health */}
      <Grid container spacing={3} mb={4}>
        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Typography variant="body2" color="text.secondary">CPU Usage</Typography>
              <Typography variant="h4">{health?.server.cpu_usage}%</Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Typography variant="body2" color="text.secondary">Memory Usage</Typography>
              <Typography variant="h4">{health?.server.memory_usage}%</Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Typography variant="body2" color="text.secondary">Active Users</Typography>
              <Typography variant="h4">{userActivity?.summary.dau_avg}</Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Typography variant="body2" color="text.secondary">API Response Time</Typography>
              <Typography variant="h4">{health?.api.avg_response_ms}ms</Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Charts */}
      <Grid container spacing={3}>
        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>Daily Active Users (30d)</Typography>
              <Line
                data={{
                  labels: userActivity?.daily_active_users.map(d => d.date) || [],
                  datasets: [{
                    label: 'DAU',
                    data: userActivity?.daily_active_users.map(d => d.count) || [],
                    borderColor: '#1976D2',
                    backgroundColor: 'rgba(25, 118, 210, 0.1)'
                  }]
                }}
              />
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>Feature Adoption</Typography>
              <Doughnut
                data={{
                  labels: ['Assessments', 'Reports', 'Checklists', 'Emails'],
                  datasets: [{
                    data: [
                      userActivity?.feature_adoption.assessments_created || 0,
                      userActivity?.feature_adoption.reports_generated || 0,
                      userActivity?.feature_adoption.checklists_created || 0,
                      userActivity?.feature_adoption.emails_sent || 0
                    ],
                    backgroundColor: ['#D32F2F', '#FF6B35', '#FFA000', '#388E3C']
                  }]
                }}
              />
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
}
```

---

**Document Version:** 1.0
**Author:** Backend Developer 2 + Frontend Developer 2
**Last Updated:** 2025-12-22
**Status:** Ready for Implementation
