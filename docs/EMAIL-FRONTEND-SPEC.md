# Email Delivery Frontend - Technical Specification

**Version:** 1.0
**Date:** 2025-12-22
**Work Stream:** 33 - Email Delivery Frontend
**Phase:** 2 - Enhanced Engagement
**Dependency Level:** 1

## Overview

The Email Delivery Frontend enables consultants to send assessment invitations and reports via email with customizable templates.

### Key Features

1. **Email Composition** - Rich text editor with template variables
2. **Template Management** - Save, edit, and reuse custom templates
3. **Email Preview** - Preview before sending
4. **Send Confirmation** - Delivery tracking and confirmation
5. **Report Email Integration** - One-click "Email Report" button

## Component Architecture

```
EmailComposer
├── EmailComposerModal
│   ├── TemplateSelector
│   ├── RecipientInput
│   ├── SubjectInput
│   ├── EmailEditor (WYSIWYG)
│   │   ├── ToolbarButtons
│   │   └── VariableInserter
│   ├── EmailPreview
│   └── SendActions
│       ├── SendButton
│       ├── SaveTemplateButton
│       └── ScheduleSendButton
├── TemplateManager
│   ├── TemplateList
│   │   └── TemplateCard (x N)
│   ├── CreateTemplateButton
│   └── EditTemplateModal
└── EmailHistory
    └── SentEmailsList
        └── EmailLogCard (x N)
```

## UI Design - Email Composer

```
┌──────────────────────────────────────────────────────────────┐
│  Email Report to Client                                  [×]  │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│                                                                │
│  Template: [Report Ready (Default) ▼] [Save as new template]  │
│                                                                │
│  To: john@abccorp.com (John Smith)                            │
│  Subject: Your Financial RISE Assessment Results are Ready    │
│                                                                │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ [B] [I] [U] [Link] [List] [Insert Variable ▼]         │  │
│  ├────────────────────────────────────────────────────────┤  │
│  │                                                          │  │
│  │ Hi John,                                                │  │
│  │                                                          │  │
│  │ Great news! Your financial readiness assessment has    │  │
│  │ been completed and your personalized report is ready.  │  │
│  │                                                          │  │
│  │ Your Assessment Results:                                │  │
│  │ • Current Phase: BUILD                                  │  │
│  │ • DISC Profile: D (Dominance)                          │  │
│  │ • Action Items: 12 priority recommendations            │  │
│  │                                                          │  │
│  │ [View Your Report]                                      │  │
│  │                                                          │  │
│  │ Ready to discuss your results? [Schedule a Call]       │  │
│  │                                                          │  │
│  │ Best regards,                                           │  │
│  │ Jane Doe                                                │  │
│  │                                                          │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                                │
│  [Preview] [Send Email] [Cancel]                             │
│                                                                │
└──────────────────────────────────────────────────────────────┘
```

## Implementation

### Email Composer Modal

```typescript
export function EmailComposerModal({
  open,
  onClose,
  assessmentId,
  recipientEmail,
  recipientName
}: Props) {
  const [selectedTemplate, setSelectedTemplate] = useState('report-ready');
  const [subject, setSubject] = useState('');
  const [body, setBody] = useState('');
  const [showPreview, setShowPreview] = useState(false);
  const { sendEmail } = useEmailApi();

  const handleSend = async () => {
    try {
      await sendEmail({
        to: { email: recipientEmail, name: recipientName },
        template: selectedTemplate,
        variables: {
          consultant_name: getCurrentUser().name,
          client_name: recipientName,
          report_url: `${APP_URL}/client/reports/${assessmentId}`
        },
        assessment_id: assessmentId
      });

      showToast('Email sent successfully!');
      onClose();
    } catch (error) {
      showToast('Failed to send email', 'error');
    }
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>Email Report to Client</DialogTitle>

      <DialogContent>
        <TemplateSelector
          value={selectedTemplate}
          onChange={setSelectedTemplate}
        />

        <TextField
          label="To"
          value={`${recipientEmail} (${recipientName})`}
          disabled
          fullWidth
          margin="normal"
        />

        <TextField
          label="Subject"
          value={subject}
          onChange={(e) => setSubject(e.target.value)}
          fullWidth
          margin="normal"
        />

        <Box mt={2}>
          <RichTextEditor
            value={body}
            onChange={setBody}
            variables={AVAILABLE_VARIABLES}
          />
        </Box>

        {showPreview && (
          <EmailPreview
            subject={subject}
            body={body}
            variables={{
              client_name: recipientName,
              consultant_name: getCurrentUser().name
            }}
          />
        )}
      </DialogContent>

      <DialogActions>
        <Button onClick={() => setShowPreview(!showPreview)}>
          {showPreview ? 'Edit' : 'Preview'}
        </Button>
        <Button onClick={onClose}>Cancel</Button>
        <Button onClick={handleSend} variant="contained">
          Send Email
        </Button>
      </DialogActions>
    </Dialog>
  );
}
```

### Variable Inserter

```typescript
export function VariableInserter({ onInsert }: Props) {
  const variables = [
    { key: '{{consultant_name}}', label: 'Your Name' },
    { key: '{{client_name}}', label: 'Client Name' },
    { key: '{{business_name}}', label: 'Business Name' },
    { key: '{{primary_phase}}', label: 'Financial Phase' },
    { key: '{{disc_profile}}', label: 'DISC Profile' },
    { key: '{{report_url}}', label: 'Report Link' },
    { key: '{{assessment_url}}', label: 'Assessment Link' },
    { key: '{{scheduler_url}}', label: 'Scheduler Link' }
  ];

  return (
    <Menu>
      <MenuButton>
        Insert Variable
      </MenuButton>
      <MenuList>
        {variables.map(v => (
          <MenuItem
            key={v.key}
            onClick={() => onInsert(v.key)}
          >
            {v.label} ({v.key})
          </MenuItem>
        ))}
      </MenuList>
    </Menu>
  );
}
```

### Report View Integration

```typescript
export function ReportActions({ assessmentId, reportId }: Props) {
  const [emailModalOpen, setEmailModalOpen] = useState(false);
  const { assessment } = useAssessment(assessmentId);

  return (
    <>
      <Button
        variant="contained"
        startIcon={<EmailIcon />}
        onClick={() => setEmailModalOpen(true)}
      >
        Email Report
      </Button>

      <EmailComposerModal
        open={emailModalOpen}
        onClose={() => setEmailModalOpen(false)}
        assessmentId={assessmentId}
        recipientEmail={assessment.client_email}
        recipientName={assessment.client_name}
      />
    </>
  );
}
```

### Template Manager

```typescript
export function TemplateManager() {
  const { templates, createTemplate, updateTemplate, deleteTemplate } = useEmailTemplates();

  return (
    <Box>
      <Typography variant="h5" gutterBottom>
        Email Templates
      </Typography>

      <Button
        variant="contained"
        onClick={() => setCreateModalOpen(true)}
        startIcon={<AddIcon />}
      >
        Create Template
      </Button>

      <Grid container spacing={2} mt={2}>
        {templates.map(template => (
          <Grid item xs={12} md={6} key={template.id}>
            <Card>
              <CardContent>
                <Typography variant="h6">{template.name}</Typography>
                <Typography variant="body2" color="text.secondary">
                  {template.subject}
                </Typography>
                <Box mt={2}>
                  <Button size="small" onClick={() => handleEdit(template)}>
                    Edit
                  </Button>
                  <Button size="small" color="error" onClick={() => handleDelete(template.id)}>
                    Delete
                  </Button>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>
    </Box>
  );
}
```

## Testing

```typescript
test('consultant can email report to client', async ({ page }) => {
  await page.goto('/assessments/123/report');

  await page.click('button:has-text("Email Report")');

  await page.selectOption('select[name="template"]', 'report-ready');
  await page.fill('input[name="subject"]', 'Your results are ready');

  await page.click('button:has-text("Send Email")');

  await expect(page.locator('text=Email sent successfully')).toBeVisible();
});

test('shows email preview before sending', async ({ page }) => {
  await page.goto('/assessments/123/report');
  await page.click('button:has-text("Email Report")');

  await page.click('button:has-text("Preview")');

  await expect(page.locator('.email-preview')).toBeVisible();
  await expect(page.locator('.email-preview')).toContainText('John Smith');
});
```

---

**Document Version:** 1.0
**Author:** Frontend Developer 2
**Last Updated:** 2025-12-22
**Status:** Ready for Implementation
