# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository contains planning documentation and infrastructure for the **Financial RISE Report** (Readiness Insights for Sustainable Entrepreneurship) project - a web-based assessment tool for financial consultants to evaluate client business financial health and provide personalized action plans.

This is a **planning and coordination repository**, not a code implementation repository. The actual application code will be developed separately based on the requirements and roadmap defined here.

## Repository Structure

```
src/
├── agent-chat/              # MCP server for AI agent coordination via NATS JetStream
│   ├── index.js            # FastMCP server implementation
│   ├── package.json        # Dependencies (fast-mcp, nats)
│   └── README.md           # MCP server documentation
├── mcp.json                # MCP server configuration
├── plans/                  # Project planning documentation
│   ├── requirements.md     # Complete requirements specification (2200+ lines)
│   ├── roadmap.md          # Active work only (gardened by project manager agent)
│   ├── priorities.md       # Business analysis and prioritization
│   └── completed/          # Archived completed work
│       └── roadmap-archive.md  # Completed work streams with dates
└── .claude/
    └── agents/             # Agent prompt templates
        ├── project-manager.md      # Roadmap management and work coordination
        ├── business-analyst.md     # Feature analysis and prioritization
        └── requirements-reviewer.md

```

## Key Documents

### 1. Requirements Specification (`plans/requirements.md`)
**Version:** 1.1 (Updated 2025-12-19)

The comprehensive requirements document defines:
- **Application name:** Financial RISE Report (formerly FRAT)
- **Target users:** Fractional CFOs, accountants, bookkeepers, financial advisors
- **Core functionality:** DISC personality-based financial readiness assessment with dual-report generation
- **5 Financial phases:** Stabilize → Organize → Build → Grow → Systemic
- **Technology stack suggestions:** React/Vue, Node.js/Python, PostgreSQL/MySQL, AWS/Azure

**Critical requirements to know:**
- REQ-QUEST-009: Before/after confidence assessment to measure value delivered
- REQ-QUEST-010: Entity type question with S-Corp payroll conditional follow-up
- REQ-CHECKLIST-001-006: Action item checklist management system
- REQ-SCHEDULER-001-003: External scheduler integration (Calendly, Acuity, etc.)
- REQ-UI-002: Brand colors: Purple #4B006E, metallic gold, black on white
- REQ-UI-003: Primary font: Calibri (14px minimum)

### 2. Implementation Roadmap (`plans/roadmap.md`)
**Version:** 3.1 (Active Work Only)

A detailed parallel execution roadmap organized into:
- **Phase 1: MVP Foundation** - Remaining work streams (core assessment + reports)
- **Phase 2: Enhanced Engagement** - 15 work streams (checklists, scheduler, email)
- **Phase 3: Advanced Features** - 10 work streams (conditional questions, analytics, admin tools)

**Work streams are organized by dependency levels** (0-5) to maximize parallelization. Each work stream includes status tracking (⚪ Not Started, 🟡 In Progress, ✅ Complete, 🔴 Blocked), agent assignments, tasks, deliverables, and dependencies.

**Roadmap Structure:**
- `plans/roadmap.md` - Contains ONLY incomplete/active work
- `plans/completed/roadmap-archive.md` - Contains all completed work with dates

**When working on implementation:**
- Update the roadmap directly by checking off tasks `[x]` and updating status indicators as work progresses
- **Project manager agent automatically gardens the roadmap** by moving completed items to the archive
- Main roadmap stays clean and focused on work that still needs to be done

### 3. Priorities Document (`plans/priorities.md`)
Business value analysis and feature prioritization using frameworks like RICE scoring, Impact/Effort Matrix, and Balanced Scorecard.

## Agent Coordination System

This repository uses an **MCP-based agent chat system** for coordinating parallel work across multiple AI agents.

### MCP Server: `agent-chat`

**Purpose:** Enable AI agents to communicate via persistent NATS JetStream channels.

**Channels:**
- `roadmap` - Discuss project roadmap and planning
- `coordination` - Coordinate parallel work between agents
- `errors` - Report and discuss errors

**Prerequisites:**
1. NATS Server with JetStream enabled:
   ```bash
   # macOS
   brew install nats-server

   # Run with JetStream
   nats-server -js
   ```

2. Install dependencies:
   ```bash
   cd agent-chat
   npm install
   ```

**Configuration:**
The MCP server is configured in `mcp.json` to connect to `nats://localhost:4222` by default. Modify `NATS_SERVER` environment variable to use a different server.

**Available MCP Tools:**
- `set_handle` - Set your agent handle/username
- `get_handle` - Get your current handle
- `publish_message` - Send message to a channel
- `read_messages` - Read recent messages from a channel
- `list_channels` - List available channels
- `subscribe_channel` - Subscribe to live updates

**Usage Pattern:**
```javascript
// Set your handle first
set_handle({ handle: "implementation-agent" })

// Coordinate work
publish_message({
  channel: "coordination",
  message: "Starting Work Stream 6: Assessment API implementation"
})

// Check for updates
read_messages({ channel: "coordination", limit: 10 })
```

## Development Workflow for Future Implementations

When implementing the Financial RISE application:

1. **Review Requirements First**
   - Read `plans/requirements.md` sections 1-4 for context
   - Identify relevant functional and non-functional requirements
   - Pay special attention to DISC integration and phase determination logic

2. **Check the Roadmap**
   - Review `plans/roadmap.md` to understand work stream dependencies
   - Identify which dependency level you're working in
   - Mark work streams as 🟡 In Progress when starting
   - Update task checkboxes `[x]` as you complete them
   - Move to ✅ Complete when all deliverables are done

3. **Use the Agent Chat System**
   - Set your agent handle (e.g., "backend-dev-1", "frontend-dev-2")
   - Publish updates to `#coordination` when starting/completing work streams
   - Report blockers or errors to `#errors`
   - Check messages before starting to avoid duplicate work

4. **Architecture Constraints**
   - Minimum 80% code coverage for business logic (REQ-MAINT-002)
   - WCAG 2.1 Level AA accessibility compliance (REQ-ACCESS-001)
   - <3 second page loads, <5 second report generation (REQ-PERF-001, REQ-PERF-002)
   - RESTful API design with JWT authentication (REQ-TECH-007, REQ-TECH-011)

5. **DISC Integration is Critical**
   - DISC questions must be hidden from clients (REQ-QUEST-003)
   - Minimum 12 questions for statistical reliability (REQ-QUEST-002)
   - Reports must adapt language/detail based on DISC profile (REQ-REPORT-CL-007)
   - Communication strategies must be tailored per profile (REQ-REPORT-C-003)

6. **Phase Determination Algorithm**
   - Use weighted scoring across 5 phases (REQ-PHASE-002)
   - Support multiple phases for clients in transition (REQ-PHASE-004)
   - Each phase has specific criteria (REQ-PHASE-005):
     - **Stabilize:** Accounting health, compliance, debt management
     - **Organize:** Foundational setup, system integration
     - **Build:** Operational systems, financial workflows, SOPs
     - **Grow:** Cash flow planning, forecasting, projections
     - **Systemic:** Financial literacy, report interpretation

## Common Commands

Since this is a planning repository, there are no build/test commands for application code. However:

**Run the MCP server locally:**
```bash
cd agent-chat
node index.js
```

**Test NATS connectivity:**
```bash
# Check if NATS is running
nats-server -js
```

## Important Context

- **Application renamed:** Originally "FRAT", now "Financial RISE Report" (Version 1.1, Dec 2025)
- **No time estimates:** The roadmap uses dependency levels and S/M/L effort sizing, not time durations
- **Parallel execution focus:** Work streams are designed to run concurrently where dependencies allow
- **Client confidentiality:** DISC profiling is intentionally hidden from clients during assessment
- **Non-judgmental approach:** All language must be encouraging and avoid shaming (US-009, REQ-REPORT-CL-002)
- **Privacy compliance:** Must comply with GDPR, CCPA, and all applicable state privacy laws

## Financial Readiness Framework

The assessment evaluates clients across 5 sequential phases. Understanding this framework is essential for implementing the questionnaire, scoring algorithms, and report generation:

**Phase 1: Stabilize** - Basic financial order and compliance (accounting health, debt management, historical cleanup)

**Phase 2: Organize** - Foundational systems and processes (Chart of Accounts setup, system integration, inventory management)

**Phase 3: Build** - Robust operational systems (financial SOPs, team workflows, custom tools)

**Phase 4: Grow** - Strategic financial planning (cash flow projections, revenue forecasting, scenario planning)

**Systemic (Cross-cutting): Financial Literacy** - Ability to read, interpret, and act on financial reports

## DISC Personality Framework

Reports adapt based on client's DISC profile:

- **D (Dominance):** Brief, results-oriented, ROI-focused, quick wins
- **I (Influence):** Collaborative, big-picture, opportunities, colorful visuals
- **S (Steadiness):** Step-by-step, reassuring, gentle pace, clear timelines
- **C (Compliance):** Detailed, analytical, data-driven, thorough documentation

See Appendix B in requirements.md for full DISC integration details.

## Technology Stack (Recommended)

From REQ-TECH-005, the suggested stack:

**Frontend:**
- React 18+ or Vue 3+
- Material-UI or Ant Design
- Redux/Vuex/Pinia for state management
- Formik or React Hook Form
- Axios or Fetch API

**Backend:**
- Node.js 18 LTS+ (Express/NestJS) OR Python 3.10+ (FastAPI/Django)
- PostgreSQL 14+ OR MySQL 8.0+
- JWT authentication with refresh tokens
- RESTful API design

**Infrastructure:**
- AWS, Azure, or Google Cloud
- Docker containerization recommended
- S3/Blob Storage for PDF reports
- Puppeteer/PDFKit for PDF generation

## Next Steps for Implementation

If you're starting implementation work:

1. Set up the development environment following the tech stack recommendations
2. Begin with **Dependency Level 0** work streams (can run in parallel):
   - Work Stream 1: Infrastructure & DevOps
   - Work Stream 2: Database Schema & Data Model
   - Work Stream 3: Authentication System
   - Work Stream 4: Design System & UI Foundation
   - Work Stream 5: Content Development (requires SME input)

3. Use the agent-chat MCP server to coordinate with other agents working in parallel

4. Update `plans/roadmap.md` directly as you make progress

5. Refer to the requirements document for detailed acceptance criteria and testability guidelines
