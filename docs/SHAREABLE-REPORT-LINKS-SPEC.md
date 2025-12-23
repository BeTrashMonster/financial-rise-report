# Shareable Report Links - Technical Specification

**Version:** 1.0
**Date:** 2025-12-22
**Work Stream:** 44 - Shareable Report Links
**Phase:** 3 - Advanced Features
**Dependency Level:** 1

## Overview

The Shareable Report Links feature enables consultants to generate secure, time-limited links to share client reports with stakeholders (business partners, investors, lenders) without requiring user accounts. Links can be password-protected and have configurable expiration dates.

### Business Value

Consultants often need to share reports with:
- Business partners who need to review financials
- Lenders evaluating loan applications
- Investors conducting due diligence
- Board members reviewing progress

Creating user accounts for these stakeholders is cumbersome. Shareable links provide:
- Easy sharing (just send a URL)
- Access control (password protection, expiration)
- View tracking (know who accessed the report)
- Revocation capability (disable links anytime)

## Key Features

1. **Shareable Link Generation** - Create unique URLs for each report
2. **Access Control** - Password protection, expiration dates
3. **View Tracking** - Track who accessed the link and when
4. **Link Management** - List, revoke, and regenerate links
5. **Public Report Viewer** - Mobile-optimized viewer (no login required)
6. **Branding Preserved** - Shared reports maintain consultant branding

## Database Schema

### shareable_links Table (new)

```sql
CREATE TABLE shareable_links (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  token VARCHAR(64) UNIQUE NOT NULL, -- Random secure token
  assessment_id UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  consultant_id UUID NOT NULL REFERENCES consultants(id),
  report_type VARCHAR(20) NOT NULL, -- 'client' or 'consultant'

  -- Access control
  password_hash VARCHAR(255), -- Bcrypt hash, NULL if no password
  expires_at TIMESTAMP, -- NULL for no expiration
  max_views INTEGER, -- NULL for unlimited
  current_views INTEGER DEFAULT 0,
  is_active BOOLEAN DEFAULT true,

  -- Metadata
  created_by UUID REFERENCES users(id),
  created_at TIMESTAMP DEFAULT NOW(),
  revoked_at TIMESTAMP,
  revoked_by UUID REFERENCES users(id),
  last_accessed_at TIMESTAMP,

  -- Tracking
  access_count INTEGER DEFAULT 0,
  unique_visitors INTEGER DEFAULT 0
);

-- Indexes
CREATE INDEX idx_shareable_links_token ON shareable_links(token);
CREATE INDEX idx_shareable_links_assessment ON shareable_links(assessment_id);
CREATE INDEX idx_shareable_links_consultant ON shareable_links(consultant_id);
CREATE INDEX idx_shareable_links_active ON shareable_links(is_active)
WHERE is_active = true;
```

### link_access_log Table (new)

```sql
CREATE TABLE link_access_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  link_id UUID NOT NULL REFERENCES shareable_links(id) ON DELETE CASCADE,

  -- Access details
  accessed_at TIMESTAMP DEFAULT NOW(),
  ip_address VARCHAR(45), -- IPv4 or IPv6
  user_agent TEXT,
  referrer TEXT,

  -- Geolocation (optional)
  country VARCHAR(2),
  city VARCHAR(100),

  -- Session tracking
  session_id VARCHAR(64), -- To identify unique visitors

  -- Success/failure
  access_granted BOOLEAN DEFAULT true,
  failure_reason VARCHAR(100) -- 'expired', 'wrong_password', 'max_views_exceeded'
);

-- Indexes
CREATE INDEX idx_link_access_log_link ON link_access_log(link_id);
CREATE INDEX idx_link_access_log_timestamp ON link_access_log(accessed_at DESC);
```

## API Endpoints

### 1. Create Shareable Link

```
POST /api/v1/assessments/:assessment_id/share
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "report_type": "client",
  "password": "SecurePass123",
  "expires_at": "2026-01-15T23:59:59Z",
  "max_views": 50
}
```

**Response 201:**
```json
{
  "id": "link_abc123",
  "token": "d4f9a8b2c1e3f7g6h5i4j3k2l1m0n9o8p7q6r5s4t3u2v1w0x9y8z7",
  "url": "https://app.financialrise.com/shared/d4f9a8b2c1e3f7g6h5i4j3k2l1m0n9o8p7q6r5s4t3u2v1w0x9y8z7",
  "assessment_id": "assess_123",
  "report_type": "client",
  "has_password": true,
  "expires_at": "2026-01-15T23:59:59Z",
  "max_views": 50,
  "current_views": 0,
  "is_active": true,
  "created_at": "2025-12-22T15:30:00Z"
}
```

### 2. List Shareable Links

```
GET /api/v1/assessments/:assessment_id/shares
Authorization: Bearer <jwt_token>
```

**Response 200:**
```json
{
  "links": [
    {
      "id": "link_abc123",
      "token": "d4f9a8b2...",
      "url": "https://app.financialrise.com/shared/d4f9a8b2...",
      "report_type": "client",
      "has_password": true,
      "expires_at": "2026-01-15T23:59:59Z",
      "max_views": 50,
      "current_views": 12,
      "is_active": true,
      "access_count": 12,
      "unique_visitors": 5,
      "last_accessed_at": "2025-12-20T10:15:00Z",
      "created_at": "2025-12-22T15:30:00Z"
    }
  ]
}
```

### 3. Revoke Shareable Link

```
DELETE /api/v1/shares/:link_id
Authorization: Bearer <jwt_token>
```

**Response 200:**
```json
{
  "id": "link_abc123",
  "is_active": false,
  "revoked_at": "2025-12-22T16:00:00Z"
}
```

### 4. Access Shared Report (Public - No Auth)

```
GET /shared/:token
Content-Type: text/html
```

**If password protected:**
Shows password entry form first

**Response 200:**
Returns HTML page with report content

**Response 401:**
```json
{
  "error": "Invalid or expired link",
  "code": "LINK_EXPIRED"
}
```

### 5. Verify Link Password (Public - No Auth)

```
POST /shared/:token/verify
Content-Type: application/json

{
  "password": "SecurePass123"
}
```

**Response 200:**
```json
{
  "access_granted": true,
  "session_token": "session_xyz789"
}
```

**Response 401:**
```json
{
  "error": "Incorrect password",
  "code": "WRONG_PASSWORD"
}
```

### 6. Get Link Analytics

```
GET /api/v1/shares/:link_id/analytics
Authorization: Bearer <jwt_token>
```

**Response 200:**
```json
{
  "link_id": "link_abc123",
  "total_access_count": 12,
  "unique_visitors": 5,
  "access_by_day": [
    { "date": "2025-12-18", "count": 3 },
    { "date": "2025-12-19", "count": 5 },
    { "date": "2025-12-20", "count": 4 }
  ],
  "top_locations": [
    { "country": "US", "city": "San Francisco", "count": 7 },
    { "country": "US", "city": "New York", "count": 3 },
    { "country": "UK", "city": "London", "count": 2 }
  ],
  "devices": [
    { "type": "Desktop", "count": 8 },
    { "type": "Mobile", "count": 4 }
  ]
}
```

## Backend Implementation

### Shareable Link Service

```typescript
import crypto from 'crypto';
import bcrypt from 'bcrypt';

export class ShareableLinkService {
  /**
   * Generates a secure shareable link
   */
  async createShareableLink(
    assessmentId: string,
    consultantId: string,
    options: ShareLinkOptions
  ): Promise<ShareableLink> {
    // Generate secure random token (64 characters)
    const token = crypto.randomBytes(32).toString('hex');

    // Hash password if provided
    let password_hash = null;
    if (options.password) {
      password_hash = await bcrypt.hash(options.password, 10);
    }

    // Create link
    const link = await ShareableLink.create({
      token,
      assessment_id: assessmentId,
      consultant_id: consultantId,
      report_type: options.report_type,
      password_hash,
      expires_at: options.expires_at,
      max_views: options.max_views,
      created_by: consultantId,
      is_active: true
    });

    return link;
  }

  /**
   * Validates access to a shared link
   */
  async validateAccess(
    token: string,
    password?: string,
    sessionToken?: string
  ): Promise<AccessValidation> {
    const link = await ShareableLink.findOne({ where: { token } });

    if (!link) {
      return { granted: false, reason: 'LINK_NOT_FOUND' };
    }

    if (!link.is_active) {
      return { granted: false, reason: 'LINK_REVOKED' };
    }

    // Check expiration
    if (link.expires_at && new Date() > link.expires_at) {
      return { granted: false, reason: 'LINK_EXPIRED' };
    }

    // Check max views
    if (link.max_views && link.current_views >= link.max_views) {
      return { granted: false, reason: 'MAX_VIEWS_EXCEEDED' };
    }

    // Check password
    if (link.password_hash) {
      // If session token provided, validate it
      if (sessionToken) {
        const isValid = await this.validateSessionToken(token, sessionToken);
        if (!isValid) {
          return { granted: false, reason: 'INVALID_SESSION' };
        }
      } else if (!password) {
        return { granted: false, reason: 'PASSWORD_REQUIRED' };
      } else {
        const isValid = await bcrypt.compare(password, link.password_hash);
        if (!isValid) {
          return { granted: false, reason: 'WRONG_PASSWORD' };
        }
      }
    }

    return { granted: true, link };
  }

  /**
   * Logs access to a shared link
   */
  async logAccess(
    linkId: string,
    req: Request,
    granted: boolean,
    failureReason?: string
  ): Promise<void> {
    const ip_address = req.ip;
    const user_agent = req.headers['user-agent'];
    const referrer = req.headers['referer'];

    // Generate or retrieve session ID from cookie
    const session_id = req.cookies?.['share_session'] || crypto.randomBytes(16).toString('hex');

    // Log access
    await LinkAccessLog.create({
      link_id: linkId,
      accessed_at: new Date(),
      ip_address,
      user_agent,
      referrer,
      session_id,
      access_granted: granted,
      failure_reason: failureReason
    });

    if (granted) {
      // Increment counters
      await ShareableLink.increment('access_count', { where: { id: linkId } });
      await ShareableLink.increment('current_views', { where: { id: linkId } });

      // Update last accessed
      await ShareableLink.update(
        { last_accessed_at: new Date() },
        { where: { id: linkId } }
      );

      // Update unique visitors count
      const uniqueCount = await LinkAccessLog.count({
        where: { link_id: linkId, access_granted: true },
        distinct: true,
        col: 'session_id'
      });

      await ShareableLink.update(
        { unique_visitors: uniqueCount },
        { where: { id: linkId } }
      );
    }
  }

  /**
   * Generates a session token after successful password verification
   */
  async generateSessionToken(token: string): Promise<string> {
    const sessionToken = crypto.randomBytes(32).toString('hex');

    // Store in Redis with 24-hour expiration
    await redis.setex(
      `share_session:${token}:${sessionToken}`,
      24 * 60 * 60,
      'valid'
    );

    return sessionToken;
  }

  /**
   * Validates a session token
   */
  private async validateSessionToken(token: string, sessionToken: string): Promise<boolean> {
    const key = `share_session:${token}:${sessionToken}`;
    const value = await redis.get(key);
    return value === 'valid';
  }

  /**
   * Revokes a shareable link
   */
  async revokeLink(linkId: string, revokedBy: string): Promise<void> {
    await ShareableLink.update(
      {
        is_active: false,
        revoked_at: new Date(),
        revoked_by: revokedBy
      },
      { where: { id: linkId } }
    );
  }

  /**
   * Gets analytics for a shareable link
   */
  async getAnalytics(linkId: string): Promise<LinkAnalytics> {
    const link = await ShareableLink.findByPk(linkId);

    if (!link) {
      throw new Error('Link not found');
    }

    // Access by day (last 30 days)
    const accessByDay = await LinkAccessLog.findAll({
      where: {
        link_id: linkId,
        access_granted: true,
        accessed_at: { [Op.gte]: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
      },
      attributes: [
        [sequelize.fn('DATE', sequelize.col('accessed_at')), 'date'],
        [sequelize.fn('COUNT', sequelize.col('id')), 'count']
      ],
      group: [sequelize.fn('DATE', sequelize.col('accessed_at'))],
      order: [[sequelize.fn('DATE', sequelize.col('accessed_at')), 'ASC']]
    });

    return {
      link_id: linkId,
      total_access_count: link.access_count,
      unique_visitors: link.unique_visitors,
      access_by_day: accessByDay.map((row: any) => ({
        date: row.get('date'),
        count: parseInt(row.get('count'))
      })),
      top_locations: [], // Implement with IP geolocation service
      devices: [] // Parse from user_agent
    };
  }
}
```

### Public Share Controller

```typescript
export class ShareController {
  private shareService = new ShareableLinkService();

  /**
   * Renders the shared report page
   */
  async viewSharedReport(req: Request, res: Response) {
    const { token } = req.params;
    const password = req.body?.password;
    const sessionToken = req.cookies?.['share_session_' + token];

    // Validate access
    const validation = await this.shareService.validateAccess(token, password, sessionToken);

    if (!validation.granted) {
      // Log failed access
      await this.shareService.logAccess(
        validation.link?.id,
        req,
        false,
        validation.reason
      );

      if (validation.reason === 'PASSWORD_REQUIRED') {
        // Show password form
        return res.render('share/password-prompt', { token });
      } else {
        return res.status(401).render('share/access-denied', {
          reason: validation.reason
        });
      }
    }

    const link = validation.link;

    // Log successful access
    await this.shareService.logAccess(link.id, req, true);

    // Get report data
    const assessment = await Assessment.findByPk(link.assessment_id, {
      include: [/* all necessary data */]
    });

    const reportData = await generateReportData(assessment, link.report_type);

    // Render report
    return res.render('share/report-viewer', {
      report: reportData,
      token,
      isSharedView: true
    });
  }

  /**
   * Verifies password for password-protected links
   */
  async verifyPassword(req: Request, res: Response) {
    const { token } = req.params;
    const { password } = req.body;

    const validation = await this.shareService.validateAccess(token, password);

    if (!validation.granted) {
      await this.shareService.logAccess(
        validation.link?.id,
        req,
        false,
        validation.reason
      );

      return res.status(401).json({
        error: 'Incorrect password',
        code: 'WRONG_PASSWORD'
      });
    }

    // Generate session token
    const sessionToken = await this.shareService.generateSessionToken(token);

    // Set cookie
    res.cookie(`share_session_${token}`, sessionToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });

    return res.json({
      access_granted: true,
      session_token: sessionToken
    });
  }
}
```

## Frontend Implementation

### Share Modal Component

```typescript
import React, { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  Switch,
  FormControlLabel,
  Box,
  Typography,
  IconButton,
  Tooltip
} from '@mui/material';
import { ContentCopy as CopyIcon } from '@mui/icons-material';
import { useShareableLink } from '../hooks/useShareableLink';

export function ShareReportModal({ assessmentId, open, onClose }: Props) {
  const [password, setPassword] = useState('');
  const [usePassword, setUsePassword] = useState(false);
  const [expiresAt, setExpiresAt] = useState('');
  const [maxViews, setMaxViews] = useState('');

  const { createLink, isCreating, createdLink } = useShareableLink(assessmentId);

  const handleCreate = async () => {
    await createLink({
      report_type: 'client',
      password: usePassword ? password : undefined,
      expires_at: expiresAt || undefined,
      max_views: maxViews ? parseInt(maxViews) : undefined
    });
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(createdLink.url);
    showToast('Link copied to clipboard!', 'success');
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>Share Report</DialogTitle>

      <DialogContent>
        {!createdLink ? (
          <>
            <Typography variant="body2" color="text.secondary" mb={2}>
              Create a shareable link to send this report to stakeholders.
            </Typography>

            <FormControlLabel
              control={
                <Switch
                  checked={usePassword}
                  onChange={(e) => setUsePassword(e.target.checked)}
                />
              }
              label="Password protect link"
            />

            {usePassword && (
              <TextField
                label="Password"
                type="password"
                fullWidth
                margin="normal"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                helperText="Recipients will need this password to view the report"
              />
            )}

            <TextField
              label="Expiration Date (optional)"
              type="datetime-local"
              fullWidth
              margin="normal"
              value={expiresAt}
              onChange={(e) => setExpiresAt(e.target.value)}
              InputLabelProps={{ shrink: true }}
              helperText="Link will expire after this date"
            />

            <TextField
              label="Maximum Views (optional)"
              type="number"
              fullWidth
              margin="normal"
              value={maxViews}
              onChange={(e) => setMaxViews(e.target.value)}
              helperText="Link will deactivate after this many views"
            />
          </>
        ) : (
          <Box>
            <Typography variant="body2" color="success.main" mb={2}>
              ✓ Shareable link created successfully!
            </Typography>

            <Box
              display="flex"
              alignItems="center"
              gap={1}
              p={2}
              bgcolor="grey.100"
              borderRadius={1}
            >
              <TextField
                value={createdLink.url}
                fullWidth
                InputProps={{ readOnly: true }}
                size="small"
              />
              <Tooltip title="Copy link">
                <IconButton onClick={handleCopy} color="primary">
                  <CopyIcon />
                </IconButton>
              </Tooltip>
            </Box>

            {createdLink.has_password && (
              <Typography variant="caption" color="text.secondary" mt={1} display="block">
                🔒 This link is password-protected. Share the password separately.
              </Typography>
            )}

            {createdLink.expires_at && (
              <Typography variant="caption" color="text.secondary" mt={1} display="block">
                ⏰ Expires: {new Date(createdLink.expires_at).toLocaleString()}
              </Typography>
            )}
          </Box>
        )}
      </DialogContent>

      <DialogActions>
        <Button onClick={onClose}>Close</Button>
        {!createdLink && (
          <Button
            onClick={handleCreate}
            variant="contained"
            disabled={isCreating || (usePassword && !password)}
          >
            Create Link
          </Button>
        )}
      </DialogActions>
    </Dialog>
  );
}
```

### Link Management Table

```typescript
export function ShareableLinksTable({ assessmentId }: Props) {
  const { links, revokeLink, getAnalytics } = useShareableLinks(assessmentId);

  return (
    <TableContainer>
      <Table>
        <TableHead>
          <TableRow>
            <TableCell>Created</TableCell>
            <TableCell>Status</TableCell>
            <TableCell>Views</TableCell>
            <TableCell>Expires</TableCell>
            <TableCell>Actions</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {links.map(link => (
            <TableRow key={link.id}>
              <TableCell>{new Date(link.created_at).toLocaleDateString()}</TableCell>
              <TableCell>
                <Chip
                  label={link.is_active ? 'Active' : 'Revoked'}
                  color={link.is_active ? 'success' : 'default'}
                  size="small"
                />
              </TableCell>
              <TableCell>
                {link.current_views} / {link.max_views || '∞'}
                <Typography variant="caption" display="block">
                  {link.unique_visitors} unique
                </Typography>
              </TableCell>
              <TableCell>
                {link.expires_at
                  ? new Date(link.expires_at).toLocaleDateString()
                  : 'Never'}
              </TableCell>
              <TableCell>
                <Button size="small" onClick={() => handleCopy(link.url)}>
                  Copy
                </Button>
                {link.is_active && (
                  <Button
                    size="small"
                    color="error"
                    onClick={() => revokeLink(link.id)}
                  >
                    Revoke
                  </Button>
                )}
                <Button size="small" onClick={() => getAnalytics(link.id)}>
                  Analytics
                </Button>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
}
```

## Testing

```typescript
test('creates shareable link with password', async () => {
  const response = await request(app)
    .post('/api/v1/assessments/assess_123/share')
    .set('Authorization', `Bearer ${consultantToken}`)
    .send({
      report_type: 'client',
      password: 'SecurePass123',
      expires_at: '2026-01-15T23:59:59Z'
    });

  expect(response.status).toBe(201);
  expect(response.body.url).toContain('/shared/');
  expect(response.body.has_password).toBe(true);
});

test('denies access with wrong password', async () => {
  const link = await createTestLink({ password: 'correct' });

  const response = await request(app)
    .post(`/shared/${link.token}/verify`)
    .send({ password: 'wrong' });

  expect(response.status).toBe(401);
  expect(response.body.code).toBe('WRONG_PASSWORD');
});

test('tracks access analytics', async () => {
  const link = await createTestLink();

  // Access link 3 times
  await request(app).get(`/shared/${link.token}`);
  await request(app).get(`/shared/${link.token}`);
  await request(app).get(`/shared/${link.token}`);

  const analytics = await request(app)
    .get(`/api/v1/shares/${link.id}/analytics`)
    .set('Authorization', `Bearer ${consultantToken}`);

  expect(analytics.body.total_access_count).toBe(3);
});
```

---

**Document Version:** 1.0
**Author:** Backend Developer 1 + Frontend Developer 1
**Last Updated:** 2025-12-22
**Status:** Ready for Implementation
