# CSV Export & Basic Analytics - Technical Specification

**Version:** 1.0
**Date:** 2025-12-22
**Work Stream:** 43 - CSV Export & Basic Analytics
**Phase:** 3 - Advanced Features
**Dependency Level:** 0

## Overview

The CSV Export & Basic Analytics feature enables consultants to export assessment data for external analysis and provides built-in analytics dashboards to track business metrics, client progress, and usage patterns.

### Key Features

1. **CSV Export** - Download assessments, responses, and analytics data
2. **Analytics Dashboard** - Visual metrics and insights
3. **Data Aggregation** - Summary statistics across all assessments
4. **Trend Analysis** - Track metrics over time
5. **Client Segmentation** - Group clients by phase, DISC, industry

## CSV Export Capabilities

### Export Types

**1. Assessments Export**
- All assessment metadata
- Fields: ID, client name, business name, email, status, dates, phase, DISC
- Use case: Client list management, CRM integration

**2. Assessment Responses Export**
- Detailed question-by-question responses
- Fields: Assessment ID, question, answer, phase, timestamp
- Use case: Deep analysis, academic research

**3. Analytics Summary Export**
- Aggregated metrics
- Fields: Total assessments, completion rate, average time, phase distribution
- Use case: Business reporting, investor updates

### CSV Format Standards

- UTF-8 encoding
- Comma-separated values
- Quoted strings (handle commas in text)
- Header row with column names
- ISO 8601 date format (YYYY-MM-DD HH:MM:SS)
- Boolean values: "true" / "false"

## API Endpoints

### 1. Export Assessments to CSV

```
GET /api/v1/consultants/me/assessments/export?format=csv&date_from=2025-01-01&date_to=2025-12-31
Authorization: Bearer <jwt_token>
```

**Query Parameters:**
- `format`: "csv" (default)
- `date_from`: Filter start date (optional)
- `date_to`: Filter end date (optional)
- `status`: Filter by status (optional)
- `phase`: Filter by phase (optional)

**Response 200:**
```csv
id,client_name,business_name,client_email,status,primary_phase,disc_profile,created_at,completed_at
assess_001,John Smith,ABC Corp,john@abc.com,Completed,ORGANIZE,D,2025-10-15 09:30:00,2025-10-15 10:45:00
assess_002,Jane Doe,XYZ Inc,jane@xyz.com,In Progress,BUILD,I/S,2025-11-20 14:00:00,
assess_003,Bob Johnson,Tech Start,bob@techstart.com,Completed,GROW,C,2025-12-01 11:15:00,2025-12-01 12:30:00
```

**Response Headers:**
```
Content-Type: text/csv; charset=utf-8
Content-Disposition: attachment; filename="assessments_2025-12-22.csv"
```

### 2. Export Assessment Responses to CSV

```
GET /api/v1/assessments/:assessment_id/responses/export?format=csv
Authorization: Bearer <jwt_token>
```

**Response 200:**
```csv
assessment_id,question_id,question_text,question_type,response_value,phase_category,disc_category,created_at
assess_001,q_001,"Do you have a Chart of Accounts?",single_choice,Yes,ORGANIZE,,2025-10-15 09:35:00
assess_001,q_002,"What is your annual revenue?",numeric,1500000,GROW,,2025-10-15 09:36:00
assess_001,q_disc_01,"I prefer to make quick decisions",scale_1_5,5,,D,2025-10-15 09:40:00
```

### 3. Get Analytics Summary

```
GET /api/v1/consultants/me/analytics/summary?period=30d
Authorization: Bearer <jwt_token>
```

**Response 200:**
```json
{
  "period": "30d",
  "date_range": {
    "start": "2025-11-22",
    "end": "2025-12-22"
  },
  "totals": {
    "assessments_created": 45,
    "assessments_completed": 32,
    "completion_rate": 71.1,
    "avg_completion_time_minutes": 42,
    "total_checklist_items": 384,
    "checklist_completion_rate": 65.2
  },
  "phase_distribution": {
    "STABILIZE": 3,
    "ORGANIZE": 12,
    "BUILD": 14,
    "GROW": 8,
    "SYSTEMIC": 0
  },
  "disc_distribution": {
    "D": 10,
    "I": 8,
    "S": 9,
    "C": 7,
    "D/I": 3,
    "S/C": 2
  },
  "trend": {
    "assessments_per_day": 1.5,
    "completions_per_week": 7.5
  }
}
```

### 4. Get Time Series Data

```
GET /api/v1/consultants/me/analytics/timeseries?metric=assessments_created&period=90d&interval=week
Authorization: Bearer <jwt_token>
```

**Response 200:**
```json
{
  "metric": "assessments_created",
  "period": "90d",
  "interval": "week",
  "data": [
    { "date": "2025-09-22", "value": 8 },
    { "date": "2025-09-29", "value": 12 },
    { "date": "2025-10-06", "value": 10 },
    { "date": "2025-10-13", "value": 15 },
    { "date": "2025-10-20", "value": 11 },
    { "date": "2025-10-27", "value": 9 },
    { "date": "2025-11-03", "value": 14 },
    { "date": "2025-11-10", "value": 13 },
    { "date": "2025-11-17", "value": 16 },
    { "date": "2025-11-24", "value": 10 },
    { "date": "2025-12-01", "value": 12 },
    { "date": "2025-12-08", "value": 15 },
    { "date": "2025-12-15", "value": 18 }
  ]
}
```

## Backend Implementation

### CSV Export Service

```typescript
import { Parser } from 'json2csv';
import { Response } from 'express';

export class CSVExportService {
  /**
   * Exports assessments to CSV
   */
  async exportAssessments(
    consultantId: string,
    filters: ExportFilters,
    res: Response
  ): Promise<void> {
    // Build query
    const where: any = { consultant_id: consultantId };

    if (filters.date_from) {
      where.created_at = { [Op.gte]: new Date(filters.date_from) };
    }
    if (filters.date_to) {
      where.created_at = { ...where.created_at, [Op.lte]: new Date(filters.date_to) };
    }
    if (filters.status) {
      where.status = filters.status;
    }
    if (filters.phase) {
      where.primary_phase = filters.phase;
    }

    // Fetch data
    const assessments = await Assessment.findAll({
      where,
      attributes: [
        'id',
        'client_name',
        'business_name',
        'client_email',
        'status',
        'primary_phase',
        'disc_profile',
        'created_at',
        'completed_at'
      ],
      order: [['created_at', 'DESC']]
    });

    // Convert to plain objects
    const data = assessments.map(a => ({
      id: a.id,
      client_name: a.client_name,
      business_name: a.business_name || '',
      client_email: a.client_email,
      status: a.status,
      primary_phase: a.primary_phase || '',
      disc_profile: a.disc_profile || '',
      created_at: a.created_at ? a.created_at.toISOString() : '',
      completed_at: a.completed_at ? a.completed_at.toISOString() : ''
    }));

    // Generate CSV
    const parser = new Parser({
      fields: [
        'id',
        'client_name',
        'business_name',
        'client_email',
        'status',
        'primary_phase',
        'disc_profile',
        'created_at',
        'completed_at'
      ]
    });

    const csv = parser.parse(data);

    // Set headers and send
    const filename = `assessments_${new Date().toISOString().split('T')[0]}.csv`;

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(csv);
  }

  /**
   * Exports assessment responses to CSV
   */
  async exportResponses(
    assessmentId: string,
    res: Response
  ): Promise<void> {
    const responses = await AssessmentResponse.findAll({
      where: { assessment_id: assessmentId },
      include: [{ model: Question }],
      order: [['created_at', 'ASC']]
    });

    const data = responses.map(r => ({
      assessment_id: r.assessment_id,
      question_id: r.question_id,
      question_text: r.question.question_text,
      question_type: r.question.question_type,
      response_value: JSON.stringify(r.response_value),
      phase_category: r.question.phase_category || '',
      disc_category: r.question.disc_category || '',
      created_at: r.created_at.toISOString()
    }));

    const parser = new Parser();
    const csv = parser.parse(data);

    const filename = `responses_${assessmentId}_${new Date().toISOString().split('T')[0]}.csv`;

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(csv);
  }
}
```

### Analytics Service

```typescript
export class AnalyticsService {
  /**
   * Gets summary analytics for a consultant
   */
  async getSummary(
    consultantId: string,
    period: string
  ): Promise<AnalyticsSummary> {
    const { startDate, endDate } = this.parsePeriod(period);

    // Total assessments
    const totalAssessments = await Assessment.count({
      where: {
        consultant_id: consultantId,
        created_at: { [Op.between]: [startDate, endDate] }
      }
    });

    // Completed assessments
    const completedAssessments = await Assessment.count({
      where: {
        consultant_id: consultantId,
        status: 'Completed',
        created_at: { [Op.between]: [startDate, endDate] }
      }
    });

    // Completion rate
    const completionRate = totalAssessments > 0
      ? Math.round((completedAssessments / totalAssessments) * 100 * 10) / 10
      : 0;

    // Average completion time
    const completed = await Assessment.findAll({
      where: {
        consultant_id: consultantId,
        status: 'Completed',
        completed_at: { [Op.not]: null },
        created_at: { [Op.between]: [startDate, endDate] }
      },
      attributes: ['created_at', 'completed_at']
    });

    const avgCompletionTime = completed.length > 0
      ? completed.reduce((sum, a) => {
          const duration = a.completed_at.getTime() - a.created_at.getTime();
          return sum + duration;
        }, 0) / completed.length / 1000 / 60 // Convert to minutes
      : 0;

    // Phase distribution
    const phaseDistribution = await this.getPhaseDistribution(
      consultantId,
      startDate,
      endDate
    );

    // DISC distribution
    const discDistribution = await this.getDISCDistribution(
      consultantId,
      startDate,
      endDate
    );

    // Checklist stats
    const checklistStats = await this.getChecklistStats(
      consultantId,
      startDate,
      endDate
    );

    // Trend
    const daysInPeriod = Math.ceil(
      (endDate.getTime() - startDate.getTime()) / (1000 * 60 * 60 * 24)
    );

    return {
      period,
      date_range: {
        start: startDate.toISOString().split('T')[0],
        end: endDate.toISOString().split('T')[0]
      },
      totals: {
        assessments_created: totalAssessments,
        assessments_completed: completedAssessments,
        completion_rate: completionRate,
        avg_completion_time_minutes: Math.round(avgCompletionTime),
        total_checklist_items: checklistStats.total,
        checklist_completion_rate: checklistStats.completion_rate
      },
      phase_distribution: phaseDistribution,
      disc_distribution: discDistribution,
      trend: {
        assessments_per_day: Math.round((totalAssessments / daysInPeriod) * 10) / 10,
        completions_per_week: Math.round((completedAssessments / (daysInPeriod / 7)) * 10) / 10
      }
    };
  }

  private parsePeriod(period: string): { startDate: Date; endDate: Date } {
    const endDate = new Date();
    let startDate = new Date();

    if (period === '7d') {
      startDate.setDate(startDate.getDate() - 7);
    } else if (period === '30d') {
      startDate.setDate(startDate.getDate() - 30);
    } else if (period === '90d') {
      startDate.setDate(startDate.getDate() - 90);
    } else if (period === '1y') {
      startDate.setFullYear(startDate.getFullYear() - 1);
    }

    return { startDate, endDate };
  }

  private async getPhaseDistribution(
    consultantId: string,
    startDate: Date,
    endDate: Date
  ): Promise<{ [key: string]: number }> {
    const results = await Assessment.findAll({
      where: {
        consultant_id: consultantId,
        status: 'Completed',
        created_at: { [Op.between]: [startDate, endDate] }
      },
      attributes: [
        'primary_phase',
        [sequelize.fn('COUNT', sequelize.col('id')), 'count']
      ],
      group: ['primary_phase']
    });

    const distribution = {
      STABILIZE: 0,
      ORGANIZE: 0,
      BUILD: 0,
      GROW: 0,
      SYSTEMIC: 0
    };

    results.forEach((r: any) => {
      distribution[r.primary_phase] = parseInt(r.get('count'));
    });

    return distribution;
  }

  private async getDISCDistribution(
    consultantId: string,
    startDate: Date,
    endDate: Date
  ): Promise<{ [key: string]: number }> {
    const results = await Assessment.findAll({
      where: {
        consultant_id: consultantId,
        status: 'Completed',
        disc_profile: { [Op.not]: null },
        created_at: { [Op.between]: [startDate, endDate] }
      },
      attributes: [
        'disc_profile',
        [sequelize.fn('COUNT', sequelize.col('id')), 'count']
      ],
      group: ['disc_profile']
    });

    const distribution = {};
    results.forEach((r: any) => {
      distribution[r.disc_profile] = parseInt(r.get('count'));
    });

    return distribution;
  }

  /**
   * Gets time series data for charts
   */
  async getTimeSeries(
    consultantId: string,
    metric: string,
    period: string,
    interval: 'day' | 'week' | 'month'
  ): Promise<TimeSeriesData> {
    const { startDate, endDate } = this.parsePeriod(period);

    const data: { date: string; value: number }[] = [];

    if (metric === 'assessments_created') {
      // Group by interval
      const results = await Assessment.findAll({
        where: {
          consultant_id: consultantId,
          created_at: { [Op.between]: [startDate, endDate] }
        },
        attributes: [
          [sequelize.fn('DATE_TRUNC', interval, sequelize.col('created_at')), 'date'],
          [sequelize.fn('COUNT', sequelize.col('id')), 'count']
        ],
        group: [sequelize.fn('DATE_TRUNC', interval, sequelize.col('created_at'))],
        order: [[sequelize.fn('DATE_TRUNC', interval, sequelize.col('created_at')), 'ASC']]
      });

      results.forEach((r: any) => {
        data.push({
          date: r.get('date').toISOString().split('T')[0],
          value: parseInt(r.get('count'))
        });
      });
    }

    return {
      metric,
      period,
      interval,
      data
    };
  }
}
```

## Frontend Implementation

### Analytics Dashboard

```typescript
import React, { useEffect, useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  Select,
  MenuItem,
  Button
} from '@mui/material';
import { Line, Pie } from 'react-chartjs-2';
import { Download as DownloadIcon } from '@mui/icons-material';
import { useAnalytics } from '../hooks/useAnalytics';

export function AnalyticsDashboard() {
  const [period, setPeriod] = useState('30d');
  const { summary, timeSeries, isLoading } = useAnalytics(period);

  const handleExport = () => {
    window.location.href = '/api/v1/consultants/me/assessments/export?format=csv';
  };

  if (isLoading) {
    return <div>Loading...</div>;
  }

  return (
    <Box maxWidth="1200px" mx="auto" p={3}>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4">Analytics Dashboard</Typography>

        <Box display="flex" gap={2}>
          <Select value={period} onChange={(e) => setPeriod(e.target.value)}>
            <MenuItem value="7d">Last 7 Days</MenuItem>
            <MenuItem value="30d">Last 30 Days</MenuItem>
            <MenuItem value="90d">Last 90 Days</MenuItem>
            <MenuItem value="1y">Last Year</MenuItem>
          </Select>

          <Button
            variant="outlined"
            startIcon={<DownloadIcon />}
            onClick={handleExport}
          >
            Export to CSV
          </Button>
        </Box>
      </Box>

      {/* Summary Cards */}
      <Grid container spacing={3} mb={4}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography variant="body2" color="text.secondary">
                Assessments Created
              </Typography>
              <Typography variant="h4">{summary?.totals.assessments_created}</Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography variant="body2" color="text.secondary">
                Completion Rate
              </Typography>
              <Typography variant="h4">{summary?.totals.completion_rate}%</Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography variant="body2" color="text.secondary">
                Avg Completion Time
              </Typography>
              <Typography variant="h4">
                {summary?.totals.avg_completion_time_minutes} min
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography variant="body2" color="text.secondary">
                Checklist Completion
              </Typography>
              <Typography variant="h4">
                {summary?.totals.checklist_completion_rate}%
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Charts */}
      <Grid container spacing={3}>
        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Assessments Over Time
              </Typography>
              <Line
                data={{
                  labels: timeSeries?.data.map(d => d.date) || [],
                  datasets: [
                    {
                      label: 'Assessments Created',
                      data: timeSeries?.data.map(d => d.value) || [],
                      borderColor: '#1976D2',
                      backgroundColor: 'rgba(25, 118, 210, 0.1)'
                    }
                  ]
                }}
                options={{
                  responsive: true,
                  plugins: {
                    legend: { display: false }
                  }
                }}
              />
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Phase Distribution
              </Typography>
              <Pie
                data={{
                  labels: Object.keys(summary?.phase_distribution || {}),
                  datasets: [
                    {
                      data: Object.values(summary?.phase_distribution || {}),
                      backgroundColor: [
                        '#D32F2F',
                        '#FF6B35',
                        '#FFA000',
                        '#388E3C',
                        '#1976D2'
                      ]
                    }
                  ]
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

## Testing

### API Tests

```typescript
test('exports assessments to CSV', async () => {
  const response = await request(app)
    .get('/api/v1/consultants/me/assessments/export?format=csv')
    .set('Authorization', `Bearer ${consultantToken}`);

  expect(response.status).toBe(200);
  expect(response.headers['content-type']).toContain('text/csv');
  expect(response.text).toContain('id,client_name,business_name');
});

test('gets analytics summary', async () => {
  const response = await request(app)
    .get('/api/v1/consultants/me/analytics/summary?period=30d')
    .set('Authorization', `Bearer ${consultantToken}`);

  expect(response.status).toBe(200);
  expect(response.body).toHaveProperty('totals');
  expect(response.body).toHaveProperty('phase_distribution');
  expect(response.body).toHaveProperty('disc_distribution');
});
```

---

**Document Version:** 1.0
**Author:** Backend Developer 2 + Frontend Developer 2
**Last Updated:** 2025-12-22
**Status:** Ready for Implementation
