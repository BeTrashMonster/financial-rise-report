# Phase 2 Documentation - Technical Specification

**Version:** 1.0
**Date:** 2025-12-22
**Work Stream:** 39 - Phase 2 Documentation
**Phase:** 2 - Enhanced Engagement
**Dependency Level:** 3

## Overview

The Phase 2 Documentation work stream creates comprehensive user guides, video tutorials, API documentation, and release notes for all Phase 2 features. This ensures consultants and clients can effectively use new features and understand their value.

### Scope

**Documentation to Create/Update:**
1. User Guides (consultant + client)
2. Video Tutorials
3. API Documentation
4. Release Notes
5. In-App Help Text
6. FAQ Updates

**Phase 2 Features to Document:**
- Action Item Checklist
- Scheduler Integration
- Dashboard Enhancements
- Email Delivery
- Branding Customization
- Consultant Notes
- Secondary DISC Traits

## 1. User Guides

### Consultant User Guide

**File:** `docs/user-guides/consultant-guide.md`

**New Sections to Add:**

#### Chapter 7: Action Item Checklists

```markdown
# Chapter 7: Action Item Checklists

## Overview

The Action Item Checklist helps you and your clients track progress on recommended actions from the Financial RISE assessment. Checklists are automatically generated from report recommendations and can be customized.

## Auto-Generating a Checklist

After completing an assessment and generating the client report:

1. Navigate to the assessment detail page
2. Click the **"Checklist"** tab
3. Click **"Generate from Report"**
4. The system creates 8-15 action items based on the report recommendations
5. Items are organized by financial phase (Stabilize, Organize, Build, Grow, Systemic)

**Example Checklist Items:**
- Set up Chart of Accounts in QuickBooks
- Implement monthly financial review process
- Create cash flow forecasting spreadsheet
- Schedule quarterly P&L review meetings

## Adding Custom Items

To add a custom checklist item:

1. Click **"+ Add Item"** button
2. Enter:
   - **Title:** Brief description (e.g., "Review insurance policies")
   - **Description:** Detailed explanation (optional)
   - **Phase:** Which financial phase this relates to
   - **Priority:** High, Medium, or Low
3. Click **"Save"**
4. Item appears in the list, auto-sorted by priority

## Editing and Deleting Items

- **Edit:** Click the pencil icon, make changes, click "Save"
- **Delete:** Click the trash icon, confirm deletion
- **Reorder:** Drag items up/down to change order

## Client Collaboration

Clients can:
- ✅ View all checklist items
- ✅ Mark items as complete
- ✅ Add notes to items
- ❌ Add, edit, or delete items (consultant-only)

**Real-time Updates:**
When either you or your client marks an item complete, the change appears for the other user within 30 seconds (auto-refresh).

## Progress Tracking

The checklist header shows:
- **Overall Progress:** "5 of 12 items complete (42%)"
- **By Phase:** Progress per financial phase
- **Completion Dates:** When each item was completed

## Tips for Effective Checklists

- Keep items specific and actionable
- Add due dates in item descriptions
- Use priority to highlight urgent items
- Review with clients during follow-up calls
- Mark items complete as they finish tasks
```

#### Chapter 8: Scheduler Integration

```markdown
# Chapter 8: Scheduler Integration

## Overview

The Scheduler Integration feature embeds your scheduling link (Calendly, Acuity, ScheduleOnce) directly in client reports, making it easy for clients to book follow-up meetings.

## Setting Up Your Scheduler

### Step 1: Configure Scheduler Settings

1. Navigate to **Settings → Scheduler**
2. Enter your scheduler URL:
   - Calendly: `https://calendly.com/yourname/30min`
   - Acuity: `https://acuityscheduling.com/yourname`
   - ScheduleOnce: `https://scheduleonce.com/yourname`
3. Choose **Display Type:**
   - **Embedded Widget:** Shows scheduler directly in report
   - **Link Button:** Shows "Schedule a Call" button
4. Click **"Save Settings"**

### Step 2: Configure Meeting Types

Add the types of meetings you offer:

1. Click **"+ Add Meeting Type"**
2. Enter:
   - **Name:** "Initial Consultation" or "Follow-up Review"
   - **Duration:** 30 min, 60 min, etc.
   - **Description:** What the meeting covers
   - **Recommended Phases:** Which phases this meeting is for
3. Click **"Save"**

**Example Meeting Types:**
- **Assessment Debrief** (30 min) - Recommended for: BUILD, GROW
- **Implementation Planning** (60 min) - Recommended for: all phases
- **Monthly Check-in** (15 min) - Recommended for: GROW, SYSTEMIC

### Step 3: Preview

Use the preview pane to see how your scheduler will appear in client reports.

## How It Appears to Clients

When clients view their report:
- **Personalized Header:** Text adapted to their DISC profile
  - D (Dominance): "Let's Discuss Your Next Steps"
  - I (Influence): "Let's Connect and Create Your Action Plan Together!"
  - S (Steadiness): "Let's Work Together on Your Next Steps"
  - C (Compliance): "Schedule a Detailed Implementation Review"
- **Meeting Recommendations:** Shows 2-3 meeting types relevant to their phase
- **Scheduling Widget:** Embedded or linked scheduler

## Tracking Engagement

View scheduler engagement metrics on the dashboard:
- **Total Clicks:** How many clients clicked scheduler links
- **By Assessment:** Which assessments generated bookings
- **By Phase:** Which phases have highest booking rates

## Best Practices

- Keep meeting names clear and specific
- Match meeting types to phases (e.g., "Cash Flow Planning" for GROW)
- Test your scheduler link before going live
- Update availability regularly in your scheduler tool
```

#### Chapter 9: Dashboard Enhancements

```markdown
# Chapter 9: Dashboard Enhancements

## Overview

The enhanced dashboard helps you find and manage assessments more efficiently with powerful filtering, searching, and archiving capabilities.

## Filtering Assessments

Use filters to narrow down your assessment list:

**Status Filter:**
- Draft
- In Progress
- Completed

**Date Range Filter:**
- Last 7 days
- Last 30 days
- Last 90 days
- Custom range

**Client Name Filter:**
- Type partial client name
- Case-insensitive search

**Clear Filters:**
Click "Clear All Filters" to reset

## Search with Autocomplete

The search bar provides instant suggestions:

1. Start typing (minimum 2 characters)
2. Autocomplete suggests matching:
   - Client names
   - Business names
   - Email addresses
3. Click a suggestion to jump to that assessment

**Example:**
Type "ABC" → Suggestions show "ABC Corp", "ABC Enterprises"

## Archiving Assessments

Keep your dashboard clean by archiving old or completed assessments:

**Archive Single Assessment:**
1. Click the ⋮ menu on an assessment row
2. Select "Archive"
3. Confirm

**Bulk Archive:**
1. Check boxes next to multiple assessments
2. Click "Archive Selected"
3. Confirm archiving X assessments

**View Archived:**
1. Click "Show Archived" toggle
2. See all archived assessments
3. Click "Restore" to unarchive

## View Modes

Switch between view modes:
- **Table View:** Compact, data-dense
- **Card View:** Visual, better for mobile

## Sorting

Click column headers to sort:
- Created Date (newest/oldest)
- Client Name (A-Z, Z-A)
- Status
- Completion %
```

(Continue with chapters for Email Delivery, Branding, Notes, Secondary DISC...)

```

### Client User Guide

**File:** `docs/user-guides/client-guide.md`

**New Sections:**

```markdown
# Using Your Action Checklist

After your consultant completes your Financial RISE assessment, you'll receive a personalized action checklist.

## Viewing Your Checklist

1. Log into your client portal
2. Navigate to **My Assessment → Checklist**
3. See all recommended action items

## Completing Items

As you complete actions:
1. Check the box next to the item
2. (Optional) Add notes about what you did
3. The item is marked complete with timestamp
4. Your consultant sees the update automatically

## Adding Notes

Share progress with your consultant:
1. Click "Add Note" on any checklist item
2. Type your update (e.g., "Completed with QuickBooks on 12/15")
3. Notes save automatically
4. Your consultant sees your notes

## Scheduling a Follow-Up

Ready to discuss next steps?
1. Scroll to the **"Schedule a Call"** section in your report
2. Choose a meeting type that fits your needs
3. Pick a time that works for you
4. You'll receive a calendar invite

## Questions?

Contact your consultant:
- **Email:** [shown in report]
- **Phone:** [shown in report]
```

## 2. Video Tutorials

### Tutorial Scripts

**Tutorial 1: "Setting Up Checklists" (3 minutes)**

*Script:*
```
[00:00] Opening: "Welcome to Financial RISE! Today I'll show you how to create and manage action item checklists for your clients."

[00:15] Generate Checklist: "After completing an assessment, navigate to the Checklist tab. Click 'Generate from Report' to automatically create items based on your recommendations."

[00:45] Review Items: "The system extracts 8-15 action items organized by financial phase. Review each item for accuracy."

[01:15] Customize: "Add custom items by clicking 'Add Item'. Include a clear title, detailed description, and priority level."

[01:45] Client View: "Your client sees the same checklist but can only mark items complete and add notes. They can't edit or delete."

[02:15] Track Progress: "Monitor completion percentage and see when items were finished. Use this during follow-up calls."

[02:45] Closing: "Checklists keep you and your clients aligned on next steps. Try it on your next assessment!"
```

**Tutorial 2: "Branding Your Reports" (2 minutes)**

*Script:*
```
[00:00] Opening: "Make your Financial RISE reports uniquely yours with custom branding."

[00:15] Upload Logo: "Navigate to Settings > Branding. Upload your company logo - PNG or SVG, under 2MB works best."

[00:35] Choose Colors: "Select your brand color. This appears in report headers and section dividers."

[00:55] Company Info: "Add your company name, tagline, and contact details. This personalizes every report."

[01:15] Preview: "Use the live preview to see exactly how your branding will appear."

[01:30] Save: "Click 'Save Branding Settings'. All future reports use your custom branding automatically."

[01:45] Closing: "Professional branding reinforces your identity and builds client trust. Set it up once, use it forever!"
```

(Create 6-8 total tutorials covering all Phase 2 features)

### Production Details

**Format:** MP4, 1080p, 30fps
**Length:** 2-4 minutes each
**Hosting:** YouTube (unlisted), embedded in app
**Thumbnail:** Consistent branded template
**Captions:** Auto-generated + manually reviewed

## 3. API Documentation

### Updated Endpoints

**File:** `docs/api/phase2-endpoints.md`

```markdown
# Phase 2 API Endpoints

## Checklist Endpoints

### Generate Checklist from Report

```
POST /api/v1/assessments/:assessment_id/checklist/generate
Authorization: Bearer <jwt_token>
```

**Description:** Auto-generates checklist items from report recommendations.

**Request:** (No body required)

**Response 200:**
```json
{
  "items_created": 12,
  "checklist": {
    "assessment_id": "assess_123",
    "items": [
      {
        "id": "item_456",
        "title": "Set up Chart of Accounts",
        "description": "Create industry-specific COA in QuickBooks",
        "phase": "ORGANIZE",
        "priority": "High",
        "is_completed": false,
        "sort_order": 1,
        "created_by": "consultant_789",
        "created_at": "2025-12-22T10:00:00Z"
      }
    ]
  }
}
```

**Error Responses:**
- `400`: Report must be generated first
- `409`: Checklist already exists (use GET instead)

### Get Checklist

```
GET /api/v1/assessments/:assessment_id/checklist
Authorization: Bearer <jwt_token>
```

(Continue documenting all Phase 2 endpoints...)

## 4. Release Notes

**File:** `docs/releases/phase2-release-notes.md`

```markdown
# Financial RISE Phase 2 Release Notes

**Release Date:** January 15, 2026
**Version:** 2.0.0

## 🎉 New Features

### Action Item Checklists

Turn assessment recommendations into actionable checklists that you and your clients can track together.

**Key Capabilities:**
- Auto-generate checklists from reports (8-15 items)
- Add custom checklist items
- Client can mark items complete and add notes
- Real-time progress tracking
- Organized by financial phase

**Benefits:**
- Increase client engagement and accountability
- Track implementation progress
- Reduce follow-up admin work

### Scheduler Integration

Embed your scheduling link directly in client reports to make booking follow-up meetings effortless.

**Supported Schedulers:**
- Calendly
- Acuity Scheduling
- ScheduleOnce

**Key Features:**
- DISC-adapted section headers (personalized copy)
- Phase-based meeting recommendations
- Click tracking and engagement analytics
- Embedded widget or button link

**Benefits:**
- Increase booking rates by 30%+
- Reduce back-and-forth scheduling
- Professional client experience

### Dashboard Enhancements

Find and manage assessments faster with powerful filtering, search, and archiving.

**New Capabilities:**
- Filter by status, date range, client name
- Autocomplete search
- Bulk archive operations
- Table and card view modes

**Benefits:**
- Manage 100+ assessments efficiently
- Find clients instantly
- Keep dashboard organized

### Email Delivery

Send professional, branded assessment invitations and reports directly from the platform.

**Features:**
- Pre-designed email templates
- Custom template creation
- Variable substitution ({{client_name}}, etc.)
- Email preview before sending
- Delivery tracking

**Benefits:**
- Save time with templates
- Professional email design
- Track email engagement

### Branding Customization

Make every report reflect your brand identity.

**Customize:**
- Company logo
- Brand colors
- Company name and tagline
- Contact information

**Benefits:**
- Reinforce your brand
- Professional appearance
- Client trust and recognition

### Consultant Notes

Add private notes to any assessment question for internal reference.

**Features:**
- Notes visible only to consultants
- Auto-save (no manual save needed)
- Included in consultant reports
- 5000 character limit

**Benefits:**
- Capture insights during assessments
- Prepare for client conversations
- Remember important context

### Secondary DISC Traits

Get more nuanced personality insights with composite DISC profiles.

**Enhancement:**
- Primary + secondary trait calculation (e.g., "D/I")
- Score breakdown visualization
- Backward compatible with existing assessments

**Benefits:**
- More accurate client profiling
- Better communication strategies
- Handle edge cases (close scores)

## 🐛 Bug Fixes

- Fixed checklist auto-save on slow connections
- Improved dashboard search accuracy
- Resolved DISC calculation tie-breaking
- Fixed email template variable escaping

## ⚡ Performance Improvements

- Dashboard loads 40% faster with 100+ assessments
- Email template rendering optimized (caching)
- Logo delivery via CDN (faster loading)
- Database query optimization (N+1 fixes)

## 📚 Documentation

- New user guides for all Phase 2 features
- 8 video tutorials (2-4 minutes each)
- Updated API documentation
- In-app help text and tooltips

## 🔄 Migration Notes

**For Existing Users:**
- All existing assessments compatible
- Branding settings optional (uses defaults)
- DISC profiles recalculated to add secondary traits
- No action required - features available immediately

## 📖 Learn More

- [User Guide](https://docs.financialrise.com/phase2)
- [Video Tutorials](https://youtube.com/financialrise-tutorials)
- [API Docs](https://api-docs.financialrise.com)

## 🆘 Support

Questions? Contact support@financialrise.com
```

## 5. In-App Help Text

### Tooltip Text

**File:** `src/constants/helpText.ts`

```typescript
export const HELP_TEXT = {
  CHECKLIST: {
    GENERATE: "Automatically creates 8-15 action items based on the report recommendations. Items are organized by financial phase and can be customized.",

    PRIORITY: "Priority affects sort order. High-priority items appear at the top of the checklist.",

    CLIENT_NOTES: "Clients can add notes to share progress updates with you. You'll see their notes here.",

    AUTO_SAVE: "Changes save automatically after 2 seconds. Look for the 'Saved ✓' indicator."
  },

  SCHEDULER: {
    URL: "Enter your Calendly, Acuity, or ScheduleOnce link. Example: https://calendly.com/yourname/30min",

    MEETING_TYPES: "Create meeting types for different purposes. Recommended phases help show relevant meetings to clients.",

    DISPLAY_TYPE: "Embedded shows the scheduler directly in the report. Link shows a button that opens your scheduler in a new tab."
  },

  BRANDING: {
    LOGO: "Upload PNG, JPG, or SVG. Max 2MB. Recommended dimensions: 400x150px. Logo appears in report headers.",

    COLOR: "Your brand color appears in report headers, section dividers, and accents. Must be hex format (#FF6B35).",

    PREVIEW: "This preview shows how your branding will appear on client reports. Changes update in real-time."
  },

  NOTES: {
    CONSULTANT_ONLY: "These notes are private. Clients never see them. Use for conversation prep, follow-up reminders, or internal documentation.",

    CHARACTER_LIMIT: "Notes can be up to 5000 characters. Use for detailed observations if needed."
  }
};
```

### Contextual Help Panels

```typescript
<HelpPanel>
  <Typography variant="h6">About Action Checklists</Typography>
  <Typography variant="body2">
    Checklists help you and your clients stay aligned on next steps.
    Auto-generate from reports or create custom items. Clients can
    mark items complete and add progress notes.
  </Typography>
  <Link href="/docs/checklists">Learn more →</Link>
</HelpPanel>
```

## 6. FAQ Updates

**File:** `docs/faq.md`

**New Questions:**

**Q: How do checklist permissions work?**
A: Consultants can create, edit, and delete checklist items. Clients can only mark items complete and add notes. This ensures you control the action plan while giving clients ownership of execution.

**Q: Which schedulers are supported?**
A: Calendly, Acuity Scheduling, and ScheduleOnce. Any scheduler that provides an embeddable iframe or direct link will work.

**Q: Will my existing assessments get secondary DISC traits?**
A: Yes! We automatically recalculated all existing assessments to add secondary traits where applicable. You don't need to do anything.

**Q: Can clients see my consultant notes?**
A: No. Notes are 100% private and only visible to you. They never appear in client reports or the client portal.

**Q: How long does it take to upload a logo?**
A: Most logos upload in 1-2 seconds. Large files (approaching 2MB) may take 3-5 seconds. You'll see a progress bar during upload.

**Q: What happens if I don't configure branding?**
A: Reports use the default Financial RISE branding with your consultant name. You can add custom branding anytime.

## Documentation Review Process

**Review Checklist:**
- [ ] Technical accuracy verified
- [ ] Screenshots up-to-date
- [ ] Links tested (no 404s)
- [ ] Grammar and spelling checked
- [ ] Consistent terminology
- [ ] Accessible (WCAG 2.1 AA)
- [ ] Search-optimized (keywords)
- [ ] Mobile-friendly formatting

**Reviewers:**
- Product Manager: Content accuracy
- Senior Developer: Technical accuracy
- UX Writer: Language clarity
- QA Tester: Step-by-step validation

## Sign-Off Criteria

**Phase 2 documentation is complete when:**
- [ ] All user guides updated
- [ ] 6+ video tutorials recorded and published
- [ ] API documentation updated
- [ ] Release notes written and approved
- [ ] In-app help text added to all new features
- [ ] FAQ updated with 10+ Phase 2 questions
- [ ] Documentation reviewed by all stakeholders
- [ ] Links tested and working
- [ ] Published to docs site

---

**Document Version:** 1.0
**Author:** Product Manager
**Last Updated:** 2025-12-22
**Status:** Ready for Execution
