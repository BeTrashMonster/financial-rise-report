# Branding Customization - Technical Specification

**Version:** 1.0
**Date:** 2025-12-22
**Work Stream:** 34 - Branding Customization
**Phase:** 2 - Enhanced Engagement
**Dependency Level:** 2

## Overview

The Branding Customization feature allows consultants to personalize client reports with their company logo, brand colors, and business information. This creates a professional, branded experience and reinforces the consultant's identity.

### Key Features

1. **Logo Upload** - S3-based file upload with image validation
2. **Brand Color Picker** - Custom color selection with live preview
3. **Company Information** - Business name, tagline, contact details
4. **Report Branding** - Automatic integration into PDF reports
5. **Brand Preview** - Real-time preview of branded report header

## Database Schema

### consultants Table (extension)

```sql
ALTER TABLE consultants ADD COLUMN IF NOT EXISTS branding_settings JSONB DEFAULT '{}'::jsonb;

-- Branding settings structure:
-- {
--   "logo_url": "https://s3.amazonaws.com/financial-rise/logos/consultant_123.png",
--   "brand_color": "#4B006E",
--   "company_name": "Smith Financial Consulting",
--   "tagline": "Your Partner in Financial Growth",
--   "contact_email": "jane@smithfinancial.com",
--   "contact_phone": "(555) 123-4567",
--   "website": "https://smithfinancial.com",
--   "logo_uploaded_at": "2025-12-22T10:30:00Z"
-- }

-- Add index for querying
CREATE INDEX idx_consultants_branding ON consultants USING GIN (branding_settings);
```

## API Endpoints

### 1. Get Branding Settings

```
GET /api/v1/consultants/me/branding
Authorization: Bearer <jwt_token>
```

**Response 200:**
```json
{
  "branding": {
    "logo_url": "https://s3.amazonaws.com/financial-rise/logos/consultant_123.png",
    "brand_color": "#4B006E",
    "company_name": "Smith Financial Consulting",
    "tagline": "Your Partner in Financial Growth",
    "contact_email": "jane@smithfinancial.com",
    "contact_phone": "(555) 123-4567",
    "website": "https://smithfinancial.com",
    "logo_uploaded_at": "2025-12-22T10:30:00Z"
  }
}
```

### 2. Update Branding Settings

```
PATCH /api/v1/consultants/me/branding
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "brand_color": "#FF6B35",
  "company_name": "Acme Consulting",
  "tagline": "Excellence in Every Number"
}
```

**Response 200:**
```json
{
  "branding": {
    "logo_url": "https://s3.amazonaws.com/financial-rise/logos/consultant_123.png",
    "brand_color": "#FF6B35",
    "company_name": "Acme Consulting",
    "tagline": "Excellence in Every Number",
    "contact_email": "jane@smithfinancial.com",
    "contact_phone": "(555) 123-4567",
    "website": "https://smithfinancial.com",
    "logo_uploaded_at": "2025-12-22T10:30:00Z"
  }
}
```

### 3. Upload Logo

```
POST /api/v1/consultants/me/branding/logo
Authorization: Bearer <jwt_token>
Content-Type: multipart/form-data

logo: <file>
```

**Validation:**
- File types: PNG, JPG, JPEG, SVG
- Max size: 2MB
- Recommended dimensions: 400x150px (aspect ratio 8:3)
- Minimum dimensions: 200x75px

**Response 200:**
```json
{
  "logo_url": "https://s3.amazonaws.com/financial-rise/logos/consultant_123_20251222103045.png",
  "uploaded_at": "2025-12-22T10:30:45Z"
}
```

**Response 400:**
```json
{
  "error": "Invalid file type. Allowed: PNG, JPG, JPEG, SVG",
  "code": "INVALID_FILE_TYPE"
}
```

### 4. Delete Logo

```
DELETE /api/v1/consultants/me/branding/logo
Authorization: Bearer <jwt_token>
```

**Response 204:** No Content

## Backend Implementation

### Logo Upload Service

```typescript
import AWS from 'aws-sdk';
import sharp from 'sharp';
import { v4 as uuidv4 } from 'uuid';

const s3 = new AWS.S3({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION || 'us-east-1'
});

export class LogoUploadService {
  private readonly BUCKET = process.env.S3_BUCKET_NAME || 'financial-rise';
  private readonly MAX_SIZE = 2 * 1024 * 1024; // 2MB
  private readonly ALLOWED_TYPES = ['image/png', 'image/jpeg', 'image/jpg', 'image/svg+xml'];

  async uploadLogo(
    consultantId: string,
    file: Express.Multer.File
  ): Promise<{ logo_url: string; uploaded_at: string }> {
    // Validate file type
    if (!this.ALLOWED_TYPES.includes(file.mimetype)) {
      throw new ValidationError('Invalid file type. Allowed: PNG, JPG, JPEG, SVG');
    }

    // Validate file size
    if (file.size > this.MAX_SIZE) {
      throw new ValidationError(`File size exceeds maximum of ${this.MAX_SIZE / 1024 / 1024}MB`);
    }

    // Optimize image (PNG/JPG only)
    let buffer = file.buffer;
    if (file.mimetype !== 'image/svg+xml') {
      const metadata = await sharp(file.buffer).metadata();

      // Validate minimum dimensions
      if (metadata.width < 200 || metadata.height < 75) {
        throw new ValidationError('Logo must be at least 200x75 pixels');
      }

      // Resize if too large (max 800px width)
      if (metadata.width > 800) {
        buffer = await sharp(file.buffer)
          .resize(800, null, { withoutEnlargement: true })
          .toBuffer();
      }
    }

    // Generate unique filename
    const timestamp = new Date().toISOString().replace(/[-:]/g, '').split('.')[0];
    const extension = file.mimetype.split('/')[1];
    const key = `logos/consultant_${consultantId}_${timestamp}.${extension}`;

    // Upload to S3
    await s3.putObject({
      Bucket: this.BUCKET,
      Key: key,
      Body: buffer,
      ContentType: file.mimetype,
      ACL: 'public-read',
      CacheControl: 'max-age=31536000' // 1 year
    }).promise();

    const logo_url = `https://${this.BUCKET}.s3.amazonaws.com/${key}`;
    const uploaded_at = new Date().toISOString();

    return { logo_url, uploaded_at };
  }

  async deleteLogo(logoUrl: string): Promise<void> {
    // Extract key from URL
    const key = logoUrl.split('.com/')[1];

    if (!key || !key.startsWith('logos/')) {
      throw new ValidationError('Invalid logo URL');
    }

    await s3.deleteObject({
      Bucket: this.BUCKET,
      Key: key
    }).promise();
  }
}
```

### Branding Controller

```typescript
import { Request, Response } from 'express';
import { LogoUploadService } from '../services/logoUploadService';
import { Consultant } from '../models/Consultant';

export class BrandingController {
  private logoService = new LogoUploadService();

  async getBranding(req: Request, res: Response) {
    const consultantId = req.user.id;

    const consultant = await Consultant.findByPk(consultantId, {
      attributes: ['id', 'branding_settings']
    });

    const branding = consultant.branding_settings || {};

    return res.json({ branding });
  }

  async updateBranding(req: Request, res: Response) {
    const consultantId = req.user.id;
    const updates = req.body;

    // Validate brand color (hex format)
    if (updates.brand_color && !/^#[0-9A-F]{6}$/i.test(updates.brand_color)) {
      return res.status(400).json({
        error: 'Invalid brand color. Must be hex format (e.g., #4B006E)',
        code: 'INVALID_COLOR_FORMAT'
      });
    }

    const consultant = await Consultant.findByPk(consultantId);
    const currentBranding = consultant.branding_settings || {};

    // Merge updates
    const newBranding = {
      ...currentBranding,
      ...updates
    };

    consultant.branding_settings = newBranding;
    await consultant.save();

    return res.json({ branding: newBranding });
  }

  async uploadLogo(req: Request, res: Response) {
    const consultantId = req.user.id;
    const file = req.file;

    if (!file) {
      return res.status(400).json({
        error: 'No file uploaded',
        code: 'NO_FILE'
      });
    }

    try {
      // Delete old logo if exists
      const consultant = await Consultant.findByPk(consultantId);
      const currentBranding = consultant.branding_settings || {};

      if (currentBranding.logo_url) {
        await this.logoService.deleteLogo(currentBranding.logo_url);
      }

      // Upload new logo
      const { logo_url, uploaded_at } = await this.logoService.uploadLogo(
        consultantId,
        file
      );

      // Update consultant branding
      consultant.branding_settings = {
        ...currentBranding,
        logo_url,
        logo_uploaded_at: uploaded_at
      };
      await consultant.save();

      return res.json({ logo_url, uploaded_at });
    } catch (error) {
      if (error.name === 'ValidationError') {
        return res.status(400).json({
          error: error.message,
          code: 'VALIDATION_ERROR'
        });
      }
      throw error;
    }
  }

  async deleteLogo(req: Request, res: Response) {
    const consultantId = req.user.id;

    const consultant = await Consultant.findByPk(consultantId);
    const currentBranding = consultant.branding_settings || {};

    if (currentBranding.logo_url) {
      await this.logoService.deleteLogo(currentBranding.logo_url);

      // Remove logo from branding settings
      delete currentBranding.logo_url;
      delete currentBranding.logo_uploaded_at;

      consultant.branding_settings = currentBranding;
      await consultant.save();
    }

    return res.status(204).send();
  }
}
```

### Report Integration

```typescript
import Handlebars from 'handlebars';

export async function generateBrandedReport(
  assessmentId: string,
  reportType: 'client' | 'consultant'
): Promise<Buffer> {
  const assessment = await Assessment.findByPk(assessmentId, {
    include: [
      {
        model: Consultant,
        attributes: ['id', 'name', 'email', 'branding_settings']
      }
    ]
  });

  const branding = assessment.consultant.branding_settings || {};

  // Apply default branding if not customized
  const reportBranding = {
    logo_url: branding.logo_url || null,
    brand_color: branding.brand_color || '#4B006E',
    company_name: branding.company_name || assessment.consultant.name,
    tagline: branding.tagline || '',
    contact_email: branding.contact_email || assessment.consultant.email,
    contact_phone: branding.contact_phone || '',
    website: branding.website || ''
  };

  // Pass to template
  const templateData = {
    ...reportData,
    branding: reportBranding
  };

  const html = await renderReportTemplate(reportType, templateData);
  const pdf = await generatePDF(html);

  return pdf;
}
```

## Frontend Implementation

### Branding Settings Page

```typescript
import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  TextField,
  Button,
  Avatar,
  Alert,
  CircularProgress
} from '@mui/material';
import { ColorPicker } from '../components/ColorPicker';
import { LogoUploader } from '../components/LogoUploader';
import { BrandPreview } from '../components/BrandPreview';
import { useBranding } from '../hooks/useBranding';

export function BrandingSettingsPage() {
  const {
    branding,
    isLoading,
    updateBranding,
    uploadLogo,
    deleteLogo
  } = useBranding();

  const [formData, setFormData] = useState({
    brand_color: '#4B006E',
    company_name: '',
    tagline: '',
    contact_email: '',
    contact_phone: '',
    website: ''
  });

  const [saveStatus, setSaveStatus] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle');

  useEffect(() => {
    if (branding) {
      setFormData({
        brand_color: branding.brand_color || '#4B006E',
        company_name: branding.company_name || '',
        tagline: branding.tagline || '',
        contact_email: branding.contact_email || '',
        contact_phone: branding.contact_phone || '',
        website: branding.website || ''
      });
    }
  }, [branding]);

  const handleSave = async () => {
    setSaveStatus('saving');
    try {
      await updateBranding(formData);
      setSaveStatus('saved');
      setTimeout(() => setSaveStatus('idle'), 2000);
    } catch (error) {
      setSaveStatus('error');
    }
  };

  const handleLogoUpload = async (file: File) => {
    try {
      await uploadLogo(file);
      setSaveStatus('saved');
      setTimeout(() => setSaveStatus('idle'), 2000);
    } catch (error) {
      setSaveStatus('error');
    }
  };

  if (isLoading) {
    return (
      <Box display="flex" justifyContent="center" p={4}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box maxWidth="1200px" mx="auto" p={3}>
      <Typography variant="h4" gutterBottom>
        Branding Settings
      </Typography>
      <Typography variant="body1" color="text.secondary" mb={3}>
        Customize your reports with your company logo and brand colors
      </Typography>

      <Box display="grid" gridTemplateColumns={{ xs: '1fr', md: '1fr 1fr' }} gap={3}>
        {/* Left Column - Settings */}
        <Box>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Company Information
              </Typography>

              <TextField
                label="Company Name"
                fullWidth
                margin="normal"
                value={formData.company_name}
                onChange={(e) => setFormData({ ...formData, company_name: e.target.value })}
                placeholder="Smith Financial Consulting"
              />

              <TextField
                label="Tagline (optional)"
                fullWidth
                margin="normal"
                value={formData.tagline}
                onChange={(e) => setFormData({ ...formData, tagline: e.target.value })}
                placeholder="Your Partner in Financial Growth"
              />

              <TextField
                label="Contact Email"
                fullWidth
                margin="normal"
                type="email"
                value={formData.contact_email}
                onChange={(e) => setFormData({ ...formData, contact_email: e.target.value })}
                placeholder="contact@yourcompany.com"
              />

              <TextField
                label="Contact Phone (optional)"
                fullWidth
                margin="normal"
                value={formData.contact_phone}
                onChange={(e) => setFormData({ ...formData, contact_phone: e.target.value })}
                placeholder="(555) 123-4567"
              />

              <TextField
                label="Website (optional)"
                fullWidth
                margin="normal"
                type="url"
                value={formData.website}
                onChange={(e) => setFormData({ ...formData, website: e.target.value })}
                placeholder="https://yourcompany.com"
              />

              <Box mt={3}>
                <Typography variant="subtitle2" gutterBottom>
                  Brand Color
                </Typography>
                <ColorPicker
                  value={formData.brand_color}
                  onChange={(color) => setFormData({ ...formData, brand_color: color })}
                />
              </Box>

              <Box mt={3}>
                <Typography variant="subtitle2" gutterBottom>
                  Company Logo
                </Typography>
                <LogoUploader
                  currentLogoUrl={branding?.logo_url}
                  onUpload={handleLogoUpload}
                  onDelete={deleteLogo}
                />
                <Typography variant="caption" color="text.secondary" display="block" mt={1}>
                  Recommended: 400x150px PNG or SVG. Max 2MB.
                </Typography>
              </Box>

              {saveStatus === 'saved' && (
                <Alert severity="success" sx={{ mt: 2 }}>
                  Branding settings saved successfully!
                </Alert>
              )}

              {saveStatus === 'error' && (
                <Alert severity="error" sx={{ mt: 2 }}>
                  Failed to save branding settings. Please try again.
                </Alert>
              )}

              <Button
                variant="contained"
                fullWidth
                sx={{ mt: 3 }}
                onClick={handleSave}
                disabled={saveStatus === 'saving'}
              >
                {saveStatus === 'saving' ? 'Saving...' : 'Save Branding Settings'}
              </Button>
            </CardContent>
          </Card>
        </Box>

        {/* Right Column - Preview */}
        <Box>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Report Preview
              </Typography>
              <Typography variant="body2" color="text.secondary" mb={2}>
                This is how your branding will appear on client reports
              </Typography>

              <BrandPreview
                logoUrl={branding?.logo_url}
                brandColor={formData.brand_color}
                companyName={formData.company_name}
                tagline={formData.tagline}
              />
            </CardContent>
          </Card>
        </Box>
      </Box>
    </Box>
  );
}
```

### Logo Uploader Component

```typescript
import React, { useRef } from 'react';
import { Box, Button, IconButton, Avatar } from '@mui/material';
import { Upload as UploadIcon, Delete as DeleteIcon } from '@mui/icons-material';

interface LogoUploaderProps {
  currentLogoUrl?: string;
  onUpload: (file: File) => Promise<void>;
  onDelete: () => Promise<void>;
}

export function LogoUploader({ currentLogoUrl, onUpload, onDelete }: LogoUploaderProps) {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [uploading, setUploading] = React.useState(false);

  const handleFileSelect = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    // Validate file type
    const validTypes = ['image/png', 'image/jpeg', 'image/jpg', 'image/svg+xml'];
    if (!validTypes.includes(file.type)) {
      alert('Invalid file type. Please upload PNG, JPG, or SVG.');
      return;
    }

    // Validate file size (2MB)
    if (file.size > 2 * 1024 * 1024) {
      alert('File too large. Maximum size is 2MB.');
      return;
    }

    setUploading(true);
    try {
      await onUpload(file);
    } finally {
      setUploading(false);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  };

  const handleDelete = async () => {
    if (confirm('Are you sure you want to delete your logo?')) {
      await onDelete();
    }
  };

  return (
    <Box display="flex" alignItems="center" gap={2}>
      {currentLogoUrl ? (
        <>
          <Avatar
            src={currentLogoUrl}
            variant="square"
            sx={{ width: 120, height: 60, objectFit: 'contain' }}
          />
          <Box>
            <Button
              size="small"
              onClick={() => fileInputRef.current?.click()}
              disabled={uploading}
            >
              Replace
            </Button>
            <IconButton size="small" onClick={handleDelete} color="error">
              <DeleteIcon />
            </IconButton>
          </Box>
        </>
      ) : (
        <Button
          variant="outlined"
          startIcon={<UploadIcon />}
          onClick={() => fileInputRef.current?.click()}
          disabled={uploading}
        >
          {uploading ? 'Uploading...' : 'Upload Logo'}
        </Button>
      )}

      <input
        ref={fileInputRef}
        type="file"
        accept="image/png,image/jpeg,image/jpg,image/svg+xml"
        style={{ display: 'none' }}
        onChange={handleFileSelect}
      />
    </Box>
  );
}
```

### Color Picker Component

```typescript
import React from 'react';
import { Box, TextField } from '@mui/material';
import { HexColorPicker } from 'react-colorful';

interface ColorPickerProps {
  value: string;
  onChange: (color: string) => void;
}

export function ColorPicker({ value, onChange }: ColorPickerProps) {
  return (
    <Box>
      <HexColorPicker color={value} onChange={onChange} />
      <TextField
        value={value}
        onChange={(e) => onChange(e.target.value)}
        size="small"
        sx={{ mt: 2, width: 120 }}
        inputProps={{ maxLength: 7, pattern: '#[0-9A-Fa-f]{6}' }}
      />
    </Box>
  );
}
```

### Brand Preview Component

```typescript
import React from 'react';
import { Box, Typography, Paper } from '@mui/material';

interface BrandPreviewProps {
  logoUrl?: string;
  brandColor: string;
  companyName: string;
  tagline: string;
}

export function BrandPreview({
  logoUrl,
  brandColor,
  companyName,
  tagline
}: BrandPreviewProps) {
  return (
    <Paper
      elevation={0}
      sx={{
        border: '1px solid',
        borderColor: 'divider',
        p: 3,
        bgcolor: 'background.default'
      }}
    >
      {/* Report Header Preview */}
      <Box
        sx={{
          borderBottom: `4px solid ${brandColor}`,
          pb: 2,
          mb: 2
        }}
      >
        {logoUrl && (
          <Box mb={1}>
            <img
              src={logoUrl}
              alt="Company Logo"
              style={{ maxHeight: '60px', maxWidth: '200px', objectFit: 'contain' }}
            />
          </Box>
        )}

        <Typography variant="h6" sx={{ color: brandColor, fontWeight: 'bold' }}>
          {companyName || 'Your Company Name'}
        </Typography>

        {tagline && (
          <Typography variant="body2" color="text.secondary">
            {tagline}
          </Typography>
        )}
      </Box>

      {/* Sample Report Content */}
      <Typography variant="h5" gutterBottom sx={{ color: brandColor }}>
        Financial RISE Assessment Report
      </Typography>
      <Typography variant="body2" color="text.secondary">
        Sample client report content appears here...
      </Typography>
    </Paper>
  );
}
```

### useBranding Hook

```typescript
import { useState, useEffect } from 'react';
import { brandingApi } from '../services/brandingApi';

interface Branding {
  logo_url?: string;
  brand_color: string;
  company_name: string;
  tagline?: string;
  contact_email?: string;
  contact_phone?: string;
  website?: string;
  logo_uploaded_at?: string;
}

export function useBranding() {
  const [branding, setBranding] = useState<Branding | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  const fetchBranding = async () => {
    setIsLoading(true);
    try {
      const data = await brandingApi.getBranding();
      setBranding(data.branding);
    } catch (err) {
      setError(err as Error);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchBranding();
  }, []);

  const updateBranding = async (updates: Partial<Branding>) => {
    const data = await brandingApi.updateBranding(updates);
    setBranding(data.branding);
  };

  const uploadLogo = async (file: File) => {
    const formData = new FormData();
    formData.append('logo', file);

    const data = await brandingApi.uploadLogo(formData);

    // Refetch to get updated branding
    await fetchBranding();

    return data;
  };

  const deleteLogo = async () => {
    await brandingApi.deleteLogo();
    await fetchBranding();
  };

  return {
    branding,
    isLoading,
    error,
    updateBranding,
    uploadLogo,
    deleteLogo,
    refetch: fetchBranding
  };
}
```

## Testing

### Backend Tests

```typescript
describe('Logo Upload Service', () => {
  test('validates file type', async () => {
    const invalidFile = {
      buffer: Buffer.from('test'),
      mimetype: 'application/pdf',
      size: 1024
    } as Express.Multer.File;

    await expect(
      logoService.uploadLogo('consultant_123', invalidFile)
    ).rejects.toThrow('Invalid file type');
  });

  test('validates file size', async () => {
    const largeFile = {
      buffer: Buffer.alloc(3 * 1024 * 1024), // 3MB
      mimetype: 'image/png',
      size: 3 * 1024 * 1024
    } as Express.Multer.File;

    await expect(
      logoService.uploadLogo('consultant_123', largeFile)
    ).rejects.toThrow('File size exceeds maximum');
  });

  test('uploads logo to S3 successfully', async () => {
    const validFile = {
      buffer: await sharp({
        create: {
          width: 400,
          height: 150,
          channels: 4,
          background: { r: 255, g: 255, b: 255, alpha: 1 }
        }
      }).png().toBuffer(),
      mimetype: 'image/png',
      size: 1024
    } as Express.Multer.File;

    const result = await logoService.uploadLogo('consultant_123', validFile);

    expect(result.logo_url).toContain('s3.amazonaws.com');
    expect(result.logo_url).toContain('logos/consultant_123');
  });
});
```

### Frontend Tests

```typescript
test('uploads logo successfully', async ({ page }) => {
  await page.goto('/settings/branding');

  // Upload logo
  const fileInput = page.locator('input[type="file"]');
  await fileInput.setInputFiles('test-logo.png');

  // Wait for upload
  await expect(page.locator('text=saved successfully')).toBeVisible();

  // Verify logo appears in preview
  await expect(page.locator('img[alt="Company Logo"]')).toBeVisible();
});

test('updates brand color', async ({ page }) => {
  await page.goto('/settings/branding');

  // Change color
  await page.fill('input[type="text"][value^="#"]', '#FF6B35');

  // Save
  await page.click('button:has-text("Save Branding Settings")');

  await expect(page.locator('text=saved successfully')).toBeVisible();
});
```

## Report Template Integration

### Handlebars Template Header

```handlebars
<!DOCTYPE html>
<html>
<head>
  <style>
    .report-header {
      border-bottom: 4px solid {{branding.brand_color}};
      padding-bottom: 20px;
      margin-bottom: 30px;
    }
    .company-logo {
      max-height: 60px;
      max-width: 200px;
      margin-bottom: 10px;
    }
    .company-name {
      color: {{branding.brand_color}};
      font-size: 20px;
      font-weight: bold;
      margin: 0;
    }
    .company-tagline {
      color: #666;
      font-size: 14px;
      margin: 5px 0 0 0;
    }
    .section-header {
      color: {{branding.brand_color}};
      border-left: 4px solid {{branding.brand_color}};
      padding-left: 15px;
      margin-top: 30px;
    }
  </style>
</head>
<body>
  <div class="report-header">
    {{#if branding.logo_url}}
      <img src="{{branding.logo_url}}" alt="Company Logo" class="company-logo" />
    {{/if}}

    <h1 class="company-name">{{branding.company_name}}</h1>

    {{#if branding.tagline}}
      <p class="company-tagline">{{branding.tagline}}</p>
    {{/if}}
  </div>

  <!-- Rest of report content -->
</body>
</html>
```

---

**Document Version:** 1.0
**Author:** Backend Developer 1 + Frontend Developer 1
**Last Updated:** 2025-12-22
**Status:** Ready for Implementation
