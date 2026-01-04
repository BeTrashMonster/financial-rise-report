-- Comprehensive Question Bank for Financial RISE Assessment
-- This script seeds 50+ questions across all 5 phases plus DISC profiling questions
-- Total: ~60 questions

-- First, delete any existing sample questions
DELETE FROM questions WHERE question_key LIKE 'START-%';
DELETE FROM questions WHERE question_key LIKE 'FIN-%';

-- =============================================================================
-- METADATA SECTION - Getting Started (4 questions)
-- =============================================================================

INSERT INTO questions (question_key, question_text, question_type, options, required, display_order, created_at, updated_at)
VALUES
  -- Industry identification
  ('META-001', 'What industry is your business in?', 'single_choice',
   '{"options": [
     {"value": "retail", "label": "Retail"},
     {"value": "services", "label": "Professional Services"},
     {"value": "manufacturing", "label": "Manufacturing"},
     {"value": "technology", "label": "Technology/Software"},
     {"value": "healthcare", "label": "Healthcare"},
     {"value": "hospitality", "label": "Hospitality/Food Service"},
     {"value": "construction", "label": "Construction/Trades"},
     {"value": "other", "label": "Other"}
   ]}',
   true, 1, NOW(), NOW()),

  -- Business age
  ('META-002', 'How long has your business been operating?', 'single_choice',
   '{"options": [
     {"value": "under_1_year", "label": "Less than 1 year"},
     {"value": "1_3_years", "label": "1-3 years"},
     {"value": "3_5_years", "label": "3-5 years"},
     {"value": "5_10_years", "label": "5-10 years"},
     {"value": "over_10_years", "label": "More than 10 years"}
   ]}',
   true, 2, NOW(), NOW()),

  -- Revenue range
  ('META-003', 'What is your approximate annual revenue?', 'single_choice',
   '{"options": [
     {"value": "under_100k", "label": "Under $100,000"},
     {"value": "100k_250k", "label": "$100,000 - $250,000"},
     {"value": "250k_500k", "label": "$250,000 - $500,000"},
     {"value": "500k_1m", "label": "$500,000 - $1 million"},
     {"value": "1m_5m", "label": "$1 million - $5 million"},
     {"value": "over_5m", "label": "Over $5 million"}
   ]}',
   true, 3, NOW(), NOW()),

  -- Number of employees
  ('META-004', 'How many employees do you have?', 'single_choice',
   '{"options": [
     {"value": "just_me", "label": "Just me (sole proprietor)"},
     {"value": "1_5", "label": "1-5 employees"},
     {"value": "6_10", "label": "6-10 employees"},
     {"value": "11_25", "label": "11-25 employees"},
     {"value": "26_50", "label": "26-50 employees"},
     {"value": "over_50", "label": "More than 50 employees"}
   ]}',
   true, 4, NOW(), NOW())

ON CONFLICT (question_key) DO NOTHING;

-- =============================================================================
-- STABILIZE PHASE - Accounting Health & Compliance (12 questions)
-- =============================================================================

INSERT INTO questions (question_key, question_text, question_type, options, required, display_order, created_at, updated_at)
VALUES
  -- Financial statements review
  ('STAB-001', 'How often do you review your financial statements (Profit & Loss, Balance Sheet)?', 'single_choice',
   '{"options": [
     {"value": "weekly", "label": "Weekly", "phase_scores": {"stabilize": 5}},
     {"value": "monthly", "label": "Monthly", "phase_scores": {"stabilize": 4}},
     {"value": "quarterly", "label": "Quarterly", "phase_scores": {"stabilize": 2}},
     {"value": "annually", "label": "Annually or less", "phase_scores": {"stabilize": 0}},
     {"value": "never", "label": "I don''t review them", "phase_scores": {"stabilize": 0}}
   ]}',
   true, 10, NOW(), NOW()),

  -- Bookkeeping status
  ('STAB-002', 'What is the current status of your bookkeeping?', 'single_choice',
   '{"options": [
     {"value": "current_professional", "label": "Current and managed by a professional", "phase_scores": {"stabilize": 5}},
     {"value": "current_self", "label": "Current and I do it myself", "phase_scores": {"stabilize": 4}},
     {"value": "behind_1_3_months", "label": "1-3 months behind", "phase_scores": {"stabilize": 2}},
     {"value": "behind_3_6_months", "label": "3-6 months behind", "phase_scores": {"stabilize": 1}},
     {"value": "behind_over_6_months", "label": "More than 6 months behind", "phase_scores": {"stabilize": 0}}
   ]}',
   true, 11, NOW(), NOW()),

  -- Bank reconciliation
  ('STAB-003', 'How often do you reconcile your bank accounts?', 'single_choice',
   '{"options": [
     {"value": "monthly", "label": "Monthly", "phase_scores": {"stabilize": 5}},
     {"value": "quarterly", "label": "Quarterly", "phase_scores": {"stabilize": 3}},
     {"value": "annually", "label": "Annually", "phase_scores": {"stabilize": 1}},
     {"value": "never", "label": "I don''t reconcile", "phase_scores": {"stabilize": 0}}
   ]}',
   true, 12, NOW(), NOW()),

  -- Tax filing status
  ('STAB-004', 'Are your business tax returns filed on time and current?', 'single_choice',
   '{"options": [
     {"value": "yes_all_current", "label": "Yes, all returns are current", "phase_scores": {"stabilize": 5}},
     {"value": "mostly_current", "label": "Mostly current, minor delays", "phase_scores": {"stabilize": 3}},
     {"value": "some_late", "label": "Some returns are late or on extension", "phase_scores": {"stabilize": 1}},
     {"value": "significantly_behind", "label": "Significantly behind on filings", "phase_scores": {"stabilize": 0}}
   ]}',
   true, 13, NOW(), NOW()),

  -- Accounts receivable tracking
  ('STAB-005', 'Do you track accounts receivable (money owed to you)?', 'single_choice',
   '{"options": [
     {"value": "yes_system", "label": "Yes, using an automated system", "phase_scores": {"stabilize": 5}},
     {"value": "yes_manual", "label": "Yes, manually tracking", "phase_scores": {"stabilize": 3}},
     {"value": "sometimes", "label": "Sometimes, not consistently", "phase_scores": {"stabilize": 1}},
     {"value": "no", "label": "No, I don''t track AR", "phase_scores": {"stabilize": 0}},
     {"value": "not_applicable", "label": "Not applicable (cash business)", "phase_scores": {"stabilize": 5}}
   ]}',
   true, 14, NOW(), NOW()),

  -- Accounts payable tracking
  ('STAB-006', 'Do you track accounts payable (money you owe)?', 'single_choice',
   '{"options": [
     {"value": "yes_system", "label": "Yes, using an automated system", "phase_scores": {"stabilize": 5}},
     {"value": "yes_manual", "label": "Yes, manually tracking", "phase_scores": {"stabilize": 3}},
     {"value": "sometimes", "label": "Sometimes, not consistently", "phase_scores": {"stabilize": 1}},
     {"value": "no", "label": "No, I don''t track AP", "phase_scores": {"stabilize": 0}}
   ]}',
   true, 15, NOW(), NOW()),

  -- Business debt
  ('STAB-007', 'Do you have a clear understanding of all your business debts and payment schedules?', 'single_choice',
   '{"options": [
     {"value": "yes_documented", "label": "Yes, fully documented and managed", "phase_scores": {"stabilize": 5}},
     {"value": "yes_informal", "label": "Yes, but not formally documented", "phase_scores": {"stabilize": 3}},
     {"value": "partial", "label": "Partial understanding", "phase_scores": {"stabilize": 1}},
     {"value": "no", "label": "No clear understanding", "phase_scores": {"stabilize": 0}},
     {"value": "no_debt", "label": "We have no business debt", "phase_scores": {"stabilize": 5}}
   ]}',
   true, 16, NOW(), NOW()),

  -- Personal vs business finances
  ('STAB-008', 'Are your personal and business finances completely separated?', 'single_choice',
   '{"options": [
     {"value": "yes_fully", "label": "Yes, completely separated", "phase_scores": {"stabilize": 5}},
     {"value": "mostly", "label": "Mostly separated, occasional mixing", "phase_scores": {"stabilize": 3}},
     {"value": "partially", "label": "Partially separated", "phase_scores": {"stabilize": 1}},
     {"value": "no", "label": "No, they are mixed together", "phase_scores": {"stabilize": 0}}
   ]}',
   true, 17, NOW(), NOW()),

  -- Payroll compliance
  ('STAB-009', 'If you have employees, how do you manage payroll?', 'single_choice',
   '{"options": [
     {"value": "payroll_service", "label": "Professional payroll service", "phase_scores": {"stabilize": 5}},
     {"value": "accounting_software", "label": "Accounting software (QuickBooks, etc.)", "phase_scores": {"stabilize": 4}},
     {"value": "manual", "label": "Manual calculations", "phase_scores": {"stabilize": 1}},
     {"value": "no_employees", "label": "No employees", "phase_scores": {"stabilize": 5}}
   ]}',
   true, 18, NOW(), NOW()),

  -- Sales tax compliance
  ('STAB-010', 'Do you collect and remit sales tax (if applicable)?', 'single_choice',
   '{"options": [
     {"value": "yes_automated", "label": "Yes, using automated system", "phase_scores": {"stabilize": 5}},
     {"value": "yes_manual", "label": "Yes, tracking manually", "phase_scores": {"stabilize": 3}},
     {"value": "inconsistent", "label": "Inconsistently", "phase_scores": {"stabilize": 1}},
     {"value": "no", "label": "No, but I should be", "phase_scores": {"stabilize": 0}},
     {"value": "not_applicable", "label": "Not applicable to my business", "phase_scores": {"stabilize": 5}}
   ]}',
   true, 19, NOW(), NOW()),

  -- Financial records organization
  ('STAB-011', 'How organized are your financial records and receipts?', 'rating',
   '{"min": 1, "max": 5, "min_label": "Completely disorganized", "max_label": "Highly organized", "phase_scoring": {"stabilize": "linear"}}',
   true, 20, NOW(), NOW()),

  -- Emergency fund
  ('STAB-012', 'Does your business have an emergency fund or cash reserves?', 'single_choice',
   '{"options": [
     {"value": "3_months_plus", "label": "Yes, 3+ months of expenses", "phase_scores": {"stabilize": 5, "grow": 3}},
     {"value": "1_3_months", "label": "Yes, 1-3 months of expenses", "phase_scores": {"stabilize": 4, "grow": 2}},
     {"value": "under_1_month", "label": "Less than 1 month", "phase_scores": {"stabilize": 2, "grow": 1}},
     {"value": "no", "label": "No emergency fund", "phase_scores": {"stabilize": 0, "grow": 0}}
   ]}',
   true, 21, NOW(), NOW())

ON CONFLICT (question_key) DO NOTHING;

-- =============================================================================
-- ORGANIZE PHASE - Foundational Setup & Systems (10 questions)
-- =============================================================================

INSERT INTO questions (question_key, question_text, question_type, options, required, display_order, created_at, updated_at)
VALUES
  -- Business entity type (with S-Corp conditional)
  ('ORG-001', 'What is your business entity type?', 'single_choice',
   '{"options": [
     {"value": "sole_proprietor", "label": "Sole Proprietor", "phase_scores": {"organize": 1}},
     {"value": "llc", "label": "LLC (Single or Multi-Member)", "phase_scores": {"organize": 3}},
     {"value": "s_corp", "label": "S-Corporation", "phase_scores": {"organize": 5}, "conditional_question": "ORG-002"},
     {"value": "c_corp", "label": "C-Corporation", "phase_scores": {"organize": 5}},
     {"value": "partnership", "label": "Partnership", "phase_scores": {"organize": 3}},
     {"value": "not_sure", "label": "Not sure", "phase_scores": {"organize": 0}}
   ]}',
   true, 30, NOW(), NOW()),

  -- S-Corp payroll conditional
  ('ORG-002', 'As an S-Corp owner, are you on payroll with a reasonable salary?', 'single_choice',
   '{"options": [
     {"value": "yes", "label": "Yes, I take a regular salary", "phase_scores": {"organize": 5}},
     {"value": "no", "label": "No, I''m not on payroll", "phase_scores": {"organize": 0}, "flag_compliance_risk": true},
     {"value": "distributions_only", "label": "I only take distributions", "phase_scores": {"organize": 0}, "flag_compliance_risk": true}
   ]}',
   false, 31, NOW(), NOW()),

  -- Chart of Accounts
  ('ORG-003', 'Do you have a well-organized Chart of Accounts?', 'single_choice',
   '{"options": [
     {"value": "yes_customized", "label": "Yes, customized for my business", "phase_scores": {"organize": 5}},
     {"value": "yes_default", "label": "Yes, using default/template", "phase_scores": {"organize": 3}},
     {"value": "basic", "label": "Basic setup, not optimized", "phase_scores": {"organize": 2}},
     {"value": "no", "label": "No formal Chart of Accounts", "phase_scores": {"organize": 0}}
   ]}',
   true, 32, NOW(), NOW()),

  -- Accounting software
  ('ORG-004', 'What accounting software do you use?', 'single_choice',
   '{"options": [
     {"value": "quickbooks", "label": "QuickBooks (Desktop or Online)", "phase_scores": {"organize": 5}},
     {"value": "xero", "label": "Xero", "phase_scores": {"organize": 5}},
     {"value": "freshbooks", "label": "FreshBooks", "phase_scores": {"organize": 4}},
     {"value": "wave", "label": "Wave", "phase_scores": {"organize": 4}},
     {"value": "spreadsheet", "label": "Excel/Google Sheets", "phase_scores": {"organize": 2}},
     {"value": "other", "label": "Other software", "phase_scores": {"organize": 3}},
     {"value": "none", "label": "No software, manual tracking", "phase_scores": {"organize": 0}}
   ]}',
   true, 33, NOW(), NOW()),

  -- System integration
  ('ORG-005', 'Are your business systems integrated (e.g., POS, inventory, accounting)?', 'single_choice',
   '{"options": [
     {"value": "fully_integrated", "label": "Fully integrated and automated", "phase_scores": {"organize": 5, "build": 3}},
     {"value": "partially_integrated", "label": "Partially integrated", "phase_scores": {"organize": 3, "build": 2}},
     {"value": "manual_entry", "label": "Manual data entry between systems", "phase_scores": {"organize": 1, "build": 1}},
     {"value": "no_integration", "label": "No integration", "phase_scores": {"organize": 0, "build": 0}},
     {"value": "not_applicable", "label": "Not applicable (simple business)", "phase_scores": {"organize": 5}}
   ]}',
   true, 34, NOW(), NOW()),

  -- Inventory management
  ('ORG-006', 'If you have inventory, how do you track it?', 'single_choice',
   '{"options": [
     {"value": "system_integrated", "label": "Inventory management system (integrated)", "phase_scores": {"organize": 5}},
     {"value": "system_separate", "label": "Inventory system (not integrated)", "phase_scores": {"organize": 3}},
     {"value": "spreadsheet", "label": "Spreadsheet tracking", "phase_scores": {"organize": 2}},
     {"value": "no_tracking", "label": "No formal tracking", "phase_scores": {"organize": 0}},
     {"value": "no_inventory", "label": "No physical inventory", "phase_scores": {"organize": 5}}
   ]}',
   true, 35, NOW(), NOW()),

  -- Payment processing
  ('ORG-007', 'How do you process customer payments?', 'multiple_choice',
   '{"options": [
     {"value": "credit_cards", "label": "Credit/debit cards"},
     {"value": "ach_bank_transfer", "label": "ACH/bank transfers"},
     {"value": "checks", "label": "Checks"},
     {"value": "cash", "label": "Cash"},
     {"value": "digital_wallet", "label": "Digital wallets (PayPal, Venmo, etc.)"},
     {"value": "invoicing_software", "label": "Invoicing software"}
   ]}',
   true, 36, NOW(), NOW()),

  -- Document storage
  ('ORG-008', 'How do you store important financial documents?', 'single_choice',
   '{"options": [
     {"value": "cloud_organized", "label": "Cloud storage, well organized", "phase_scores": {"organize": 5}},
     {"value": "cloud_messy", "label": "Cloud storage, somewhat disorganized", "phase_scores": {"organize": 3}},
     {"value": "physical_organized", "label": "Physical files, well organized", "phase_scores": {"organize": 3}},
     {"value": "physical_messy", "label": "Physical files, disorganized", "phase_scores": {"organize": 1}},
     {"value": "mixed", "label": "Mix of physical and digital, no clear system", "phase_scores": {"organize": 1}}
   ]}',
   true, 37, NOW(), NOW()),

  -- Vendor management
  ('ORG-009', 'Do you have a system for managing vendor relationships and contracts?', 'single_choice',
   '{"options": [
     {"value": "yes_formal", "label": "Yes, formal vendor management system", "phase_scores": {"organize": 5}},
     {"value": "spreadsheet", "label": "Yes, tracking in spreadsheet", "phase_scores": {"organize": 3}},
     {"value": "informal", "label": "Informal tracking", "phase_scores": {"organize": 1}},
     {"value": "no", "label": "No vendor tracking", "phase_scores": {"organize": 0}}
   ]}',
   true, 38, NOW(), NOW()),

  -- Financial workflow clarity
  ('ORG-010', 'How clear are your financial workflows and processes?', 'rating',
   '{"min": 1, "max": 5, "min_label": "No clear processes", "max_label": "Fully documented processes", "phase_scoring": {"organize": "linear"}}',
   true, 39, NOW(), NOW())

ON CONFLICT (question_key) DO NOTHING;

-- =============================================================================
-- BUILD PHASE - Operational Systems & SOPs (10 questions)
-- =============================================================================

INSERT INTO questions (question_key, question_text, question_type, options, required, display_order, created_at, updated_at)
VALUES
  -- Financial SOPs
  ('BUILD-001', 'Do you have documented Standard Operating Procedures (SOPs) for financial tasks?', 'single_choice',
   '{"options": [
     {"value": "comprehensive", "label": "Yes, comprehensive SOPs for all major tasks", "phase_scores": {"build": 5}},
     {"value": "some", "label": "Yes, for some tasks", "phase_scores": {"build": 3}},
     {"value": "informal", "label": "Informal/undocumented processes", "phase_scores": {"build": 1}},
     {"value": "no", "label": "No SOPs", "phase_scores": {"build": 0}}
   ]}',
   true, 50, NOW(), NOW()),

  -- Budgeting
  ('BUILD-002', 'Do you operate with a formal budget?', 'single_choice',
   '{"options": [
     {"value": "yes_detailed", "label": "Yes, detailed annual budget with monthly tracking", "phase_scores": {"build": 5, "grow": 2}},
     {"value": "yes_basic", "label": "Yes, basic budget", "phase_scores": {"build": 3, "grow": 1}},
     {"value": "informal", "label": "Informal spending guidelines", "phase_scores": {"build": 1}},
     {"value": "no", "label": "No budget", "phase_scores": {"build": 0}}
   ]}',
   true, 51, NOW(), NOW()),

  -- Budget variance analysis
  ('BUILD-003', 'How often do you review actual vs. budgeted performance?', 'single_choice',
   '{"options": [
     {"value": "monthly", "label": "Monthly", "phase_scores": {"build": 5, "grow": 3}},
     {"value": "quarterly", "label": "Quarterly", "phase_scores": {"build": 3, "grow": 2}},
     {"value": "annually", "label": "Annually", "phase_scores": {"build": 1, "grow": 1}},
     {"value": "never", "label": "Never/No budget to compare", "phase_scores": {"build": 0, "grow": 0}}
   ]}',
   true, 52, NOW(), NOW()),

  -- Approval processes
  ('BUILD-004', 'Do you have formal approval processes for major expenses?', 'single_choice',
   '{"options": [
     {"value": "yes_documented", "label": "Yes, documented approval workflows", "phase_scores": {"build": 5}},
     {"value": "yes_informal", "label": "Yes, informal approval required", "phase_scores": {"build": 3}},
     {"value": "threshold_only", "label": "Only for expenses above certain threshold", "phase_scores": {"build": 2}},
     {"value": "no", "label": "No formal approval process", "phase_scores": {"build": 0}}
   ]}',
   true, 53, NOW(), NOW()),

  -- Financial reporting cadence
  ('BUILD-005', 'How often do you generate financial reports for decision-making?', 'single_choice',
   '{"options": [
     {"value": "weekly", "label": "Weekly", "phase_scores": {"build": 5, "systemic": 3}},
     {"value": "monthly", "label": "Monthly", "phase_scores": {"build": 4, "systemic": 2}},
     {"value": "quarterly", "label": "Quarterly", "phase_scores": {"build": 2, "systemic": 1}},
     {"value": "annually", "label": "Annually or less", "phase_scores": {"build": 1, "systemic": 0}},
     {"value": "never", "label": "Rarely/Never", "phase_scores": {"build": 0, "systemic": 0}}
   ]}',
   true, 54, NOW(), NOW()),

  -- Team financial training
  ('BUILD-006', 'Have you provided financial training to relevant team members?', 'single_choice',
   '{"options": [
     {"value": "ongoing", "label": "Yes, ongoing training program", "phase_scores": {"build": 5}},
     {"value": "initial", "label": "Yes, initial training only", "phase_scores": {"build": 3}},
     {"value": "informal", "label": "Informal on-the-job training", "phase_scores": {"build": 2}},
     {"value": "no", "label": "No formal training", "phase_scores": {"build": 0}},
     {"value": "no_team", "label": "No team members handling finances", "phase_scores": {"build": 5}}
   ]}',
   true, 55, NOW(), NOW()),

  -- Financial controls
  ('BUILD-007', 'Do you have internal controls to prevent fraud or errors?', 'single_choice',
   '{"options": [
     {"value": "comprehensive", "label": "Yes, comprehensive controls in place", "phase_scores": {"build": 5}},
     {"value": "basic", "label": "Yes, basic controls", "phase_scores": {"build": 3}},
     {"value": "minimal", "label": "Minimal controls", "phase_scores": {"build": 1}},
     {"value": "no", "label": "No formal controls", "phase_scores": {"build": 0}}
   ]}',
   true, 56, NOW(), NOW()),

  -- Expense categorization
  ('BUILD-008', 'How consistent is your expense categorization?', 'rating',
   '{"min": 1, "max": 5, "min_label": "Inconsistent/random", "max_label": "Highly consistent", "phase_scoring": {"build": "linear"}}',
   true, 57, NOW(), NOW()),

  -- Financial dashboard
  ('BUILD-009', 'Do you use a financial dashboard to monitor key metrics?', 'single_choice',
   '{"options": [
     {"value": "yes_automated", "label": "Yes, automated real-time dashboard", "phase_scores": {"build": 5, "systemic": 3}},
     {"value": "yes_manual", "label": "Yes, manually updated dashboard", "phase_scores": {"build": 3, "systemic": 2}},
     {"value": "spreadsheet", "label": "Track metrics in spreadsheet", "phase_scores": {"build": 2, "systemic": 1}},
     {"value": "no", "label": "No dashboard or metrics tracking", "phase_scores": {"build": 0, "systemic": 0}}
   ]}',
   true, 58, NOW(), NOW()),

  -- Process automation
  ('BUILD-010', 'Have you automated any financial processes?', 'multiple_choice',
   '{"options": [
     {"value": "bill_pay", "label": "Bill payment", "phase_scores": {"build": 1}},
     {"value": "invoicing", "label": "Invoicing", "phase_scores": {"build": 1}},
     {"value": "expense_tracking", "label": "Expense tracking", "phase_scores": {"build": 1}},
     {"value": "payroll", "label": "Payroll", "phase_scores": {"build": 1}},
     {"value": "reconciliation", "label": "Bank reconciliation", "phase_scores": {"build": 1}},
     {"value": "reporting", "label": "Financial reporting", "phase_scores": {"build": 1}},
     {"value": "none", "label": "None - all manual processes", "phase_scores": {"build": 0}}
   ]}',
   true, 59, NOW(), NOW())

ON CONFLICT (question_key) DO NOTHING;

-- =============================================================================
-- GROW PHASE - Strategic Planning & Forecasting (10 questions)
-- =============================================================================

INSERT INTO questions (question_key, question_text, question_type, options, required, display_order, created_at, updated_at)
VALUES
  -- Cash flow forecasting
  ('GROW-001', 'Do you regularly forecast your cash flow?', 'single_choice',
   '{"options": [
     {"value": "yes_rolling", "label": "Yes, rolling 13-week or longer forecast", "phase_scores": {"grow": 5}},
     {"value": "yes_monthly", "label": "Yes, monthly forecasting", "phase_scores": {"grow": 4}},
     {"value": "quarterly", "label": "Quarterly forecasting", "phase_scores": {"grow": 2}},
     {"value": "no", "label": "No regular cash flow forecasting", "phase_scores": {"grow": 0}}
   ]}',
   true, 70, NOW(), NOW()),

  -- Revenue projections
  ('GROW-002', 'How do you approach revenue projections?', 'single_choice',
   '{"options": [
     {"value": "data_driven", "label": "Data-driven models with multiple scenarios", "phase_scores": {"grow": 5}},
     {"value": "historical", "label": "Based on historical trends", "phase_scores": {"grow": 3}},
     {"value": "gut_feeling", "label": "Educated guesses", "phase_scores": {"grow": 1}},
     {"value": "no_projections", "label": "Don''t create revenue projections", "phase_scores": {"grow": 0}}
   ]}',
   true, 71, NOW(), NOW()),

  -- Scenario planning
  ('GROW-003', 'Do you create different scenarios for business planning (best case, worst case, etc.)?', 'single_choice',
   '{"options": [
     {"value": "yes_detailed", "label": "Yes, detailed scenario planning", "phase_scores": {"grow": 5}},
     {"value": "yes_basic", "label": "Yes, basic scenarios", "phase_scores": {"grow": 3}},
     {"value": "occasionally", "label": "Occasionally", "phase_scores": {"grow": 1}},
     {"value": "no", "label": "No scenario planning", "phase_scores": {"grow": 0}}
   ]}',
   true, 72, NOW(), NOW()),

  -- Capital planning
  ('GROW-004', 'Do you have a plan for major capital expenditures?', 'single_choice',
   '{"options": [
     {"value": "yes_multi_year", "label": "Yes, multi-year capital plan", "phase_scores": {"grow": 5}},
     {"value": "yes_annual", "label": "Yes, annual capital budget", "phase_scores": {"grow": 3}},
     {"value": "ad_hoc", "label": "Ad hoc decisions as needs arise", "phase_scores": {"grow": 1}},
     {"value": "no", "label": "No capital planning", "phase_scores": {"grow": 0}}
   ]}',
   true, 73, NOW(), NOW()),

  -- Growth strategy
  ('GROW-005', 'Do you have a documented growth strategy with financial targets?', 'single_choice',
   '{"options": [
     {"value": "yes_detailed", "label": "Yes, detailed strategy with milestones", "phase_scores": {"grow": 5}},
     {"value": "yes_basic", "label": "Yes, basic goals outlined", "phase_scores": {"grow": 3}},
     {"value": "informal", "label": "Informal growth plans", "phase_scores": {"grow": 1}},
     {"value": "no", "label": "No formal growth strategy", "phase_scores": {"grow": 0}}
   ]}',
   true, 74, NOW(), NOW()),

  -- Profitability analysis
  ('GROW-006', 'Do you analyze profitability by product/service line?', 'single_choice',
   '{"options": [
     {"value": "yes_regular", "label": "Yes, regular detailed analysis", "phase_scores": {"grow": 5, "systemic": 2}},
     {"value": "yes_occasional", "label": "Yes, occasionally", "phase_scores": {"grow": 3, "systemic": 1}},
     {"value": "high_level", "label": "Only high-level profit analysis", "phase_scores": {"grow": 1}},
     {"value": "no", "label": "No profitability analysis by segment", "phase_scores": {"grow": 0}}
   ]}',
   true, 75, NOW(), NOW()),

  -- Customer acquisition cost
  ('GROW-007', 'Do you track customer acquisition cost (CAC) and lifetime value (LTV)?', 'single_choice',
   '{"options": [
     {"value": "yes_both", "label": "Yes, track both CAC and LTV", "phase_scores": {"grow": 5}},
     {"value": "yes_one", "label": "Yes, track one of them", "phase_scores": {"grow": 3}},
     {"value": "informal", "label": "Have rough estimates", "phase_scores": {"grow": 1}},
     {"value": "no", "label": "Don''t track these metrics", "phase_scores": {"grow": 0}}
   ]}',
   true, 76, NOW(), NOW()),

  -- Funding strategy
  ('GROW-008', 'Do you have a strategy for funding growth (loans, investors, bootstrapping)?', 'single_choice',
   '{"options": [
     {"value": "yes_documented", "label": "Yes, documented funding strategy", "phase_scores": {"grow": 5}},
     {"value": "yes_informal", "label": "Yes, informal plan", "phase_scores": {"grow": 3}},
     {"value": "exploring", "label": "Currently exploring options", "phase_scores": {"grow": 2}},
     {"value": "no", "label": "No funding strategy", "phase_scores": {"grow": 0}}
   ]}',
   true, 77, NOW(), NOW()),

  -- Financial modeling
  ('GROW-009', 'Do you use financial models to test business decisions?', 'single_choice',
   '{"options": [
     {"value": "yes_sophisticated", "label": "Yes, sophisticated financial models", "phase_scores": {"grow": 5}},
     {"value": "yes_basic", "label": "Yes, basic financial models", "phase_scores": {"grow": 3}},
     {"value": "spreadsheet", "label": "Simple spreadsheet calculations", "phase_scores": {"grow": 1}},
     {"value": "no", "label": "No financial modeling", "phase_scores": {"grow": 0}}
   ]}',
   true, 78, NOW(), NOW()),

  -- Strategic financial advisor
  ('GROW-010', 'Do you work with a financial advisor or CFO for strategic planning?', 'single_choice',
   '{"options": [
     {"value": "fractional_cfo", "label": "Yes, fractional CFO or advisor", "phase_scores": {"grow": 5}},
     {"value": "consultant", "label": "Yes, occasional consultant", "phase_scores": {"grow": 3}},
     {"value": "accountant", "label": "My accountant provides some guidance", "phase_scores": {"grow": 2}},
     {"value": "no", "label": "No external financial guidance", "phase_scores": {"grow": 0}}
   ]}',
   true, 79, NOW(), NOW())

ON CONFLICT (question_key) DO NOTHING;

-- =============================================================================
-- SYSTEMIC PHASE - Financial Literacy & Reporting (8 questions)
-- =============================================================================

INSERT INTO questions (question_key, question_text, question_type, options, required, display_order, created_at, updated_at)
VALUES
  -- Reading financial statements
  ('SYS-001', 'How comfortable are you reading and interpreting financial statements?', 'rating',
   '{"min": 1, "max": 5, "min_label": "Very uncomfortable", "max_label": "Very comfortable", "phase_scoring": {"systemic": "linear"}}',
   true, 90, NOW(), NOW()),

  -- Financial decision-making
  ('SYS-002', 'How often do you use financial data to make business decisions?', 'single_choice',
   '{"options": [
     {"value": "always", "label": "Always - data drives all major decisions", "phase_scores": {"systemic": 5}},
     {"value": "often", "label": "Often - for most important decisions", "phase_scores": {"systemic": 4}},
     {"value": "sometimes", "label": "Sometimes - when I remember to check", "phase_scores": {"systemic": 2}},
     {"value": "rarely", "label": "Rarely - mostly rely on intuition", "phase_scores": {"systemic": 1}},
     {"value": "never", "label": "Never - don''t use financial data", "phase_scores": {"systemic": 0}}
   ]}',
   true, 91, NOW(), NOW()),

  -- KPI tracking
  ('SYS-003', 'Do you regularly monitor Key Performance Indicators (KPIs)?', 'single_choice',
   '{"options": [
     {"value": "yes_multiple", "label": "Yes, track multiple KPIs weekly", "phase_scores": {"systemic": 5}},
     {"value": "yes_monthly", "label": "Yes, track KPIs monthly", "phase_scores": {"systemic": 4}},
     {"value": "yes_occasional", "label": "Yes, check occasionally", "phase_scores": {"systemic": 2}},
     {"value": "no", "label": "No regular KPI tracking", "phase_scores": {"systemic": 0}}
   ]}',
   true, 92, NOW(), NOW()),

  -- Understanding metrics
  ('SYS-004', 'Do you understand what metrics are most important for your business?', 'single_choice',
   '{"options": [
     {"value": "yes_clear", "label": "Yes, very clear on key metrics", "phase_scores": {"systemic": 5}},
     {"value": "yes_mostly", "label": "Yes, mostly understand", "phase_scores": {"systemic": 3}},
     {"value": "somewhat", "label": "Somewhat understand", "phase_scores": {"systemic": 1}},
     {"value": "no", "label": "Not sure what metrics matter", "phase_scores": {"systemic": 0}}
   ]}',
   true, 93, NOW(), NOW()),

  -- Teaching financial literacy
  ('SYS-005', 'Do you teach financial literacy to your team members?', 'single_choice',
   '{"options": [
     {"value": "yes_program", "label": "Yes, formal training program", "phase_scores": {"systemic": 5}},
     {"value": "yes_informal", "label": "Yes, informal teaching", "phase_scores": {"systemic": 3}},
     {"value": "occasionally", "label": "Occasionally share insights", "phase_scores": {"systemic": 1}},
     {"value": "no", "label": "No financial literacy training for team", "phase_scores": {"systemic": 0}},
     {"value": "no_team", "label": "No team members", "phase_scores": {"systemic": 5}}
   ]}',
   true, 94, NOW(), NOW()),

  -- Financial education
  ('SYS-006', 'How do you stay educated on financial management?', 'multiple_choice',
   '{"options": [
     {"value": "courses", "label": "Take courses/workshops"},
     {"value": "books", "label": "Read books/articles"},
     {"value": "advisor", "label": "Work with advisor/mentor"},
     {"value": "peer_groups", "label": "Peer groups/masterminds"},
     {"value": "podcasts", "label": "Podcasts/webinars"},
     {"value": "conferences", "label": "Attend conferences"},
     {"value": "none", "label": "Don''t actively seek financial education"}
   ]}',
   true, 95, NOW(), NOW()),

  -- Financial goal setting
  ('SYS-007', 'Do you set and track financial goals?', 'single_choice',
   '{"options": [
     {"value": "yes_detailed", "label": "Yes, detailed goals with regular tracking", "phase_scores": {"systemic": 5, "grow": 2}},
     {"value": "yes_basic", "label": "Yes, basic goals", "phase_scores": {"systemic": 3, "grow": 1}},
     {"value": "informal", "label": "Informal goals in mind", "phase_scores": {"systemic": 1}},
     {"value": "no", "label": "No specific financial goals", "phase_scores": {"systemic": 0}}
   ]}',
   true, 96, NOW(), NOW()),

  -- Financial awareness
  ('SYS-008', 'How would you rate your overall financial awareness of your business?', 'rating',
   '{"min": 1, "max": 5, "min_label": "Very low awareness", "max_label": "Excellent awareness", "phase_scoring": {"systemic": "linear"}}',
   true, 97, NOW(), NOW())

ON CONFLICT (question_key) DO NOTHING;

-- =============================================================================
-- DISC PROFILING QUESTIONS (12 questions - hidden personality assessment)
-- =============================================================================

INSERT INTO questions (question_key, question_text, question_type, options, required, display_order, created_at, updated_at)
VALUES
  -- Communication style
  ('DISC-001', 'When communicating about business challenges, I prefer:', 'single_choice',
   '{"options": [
     {"value": "direct_brief", "label": "Direct and brief - get to the point quickly", "disc_scores": {"D": 2}},
     {"value": "collaborative", "label": "Collaborative discussion with the team", "disc_scores": {"I": 2}},
     {"value": "thoughtful_steady", "label": "Thoughtful, step-by-step explanation", "disc_scores": {"S": 2}},
     {"value": "detailed_data", "label": "Detailed with supporting data and analysis", "disc_scores": {"C": 2}}
   ]}',
   true, 100, NOW(), NOW()),

  -- Decision-making speed
  ('DISC-002', 'When making important business decisions, I tend to:', 'single_choice',
   '{"options": [
     {"value": "decide_quickly", "label": "Decide quickly and move forward", "disc_scores": {"D": 2}},
     {"value": "discuss_options", "label": "Discuss options with others first", "disc_scores": {"I": 2}},
     {"value": "consider_impact", "label": "Carefully consider impact on everyone", "disc_scores": {"S": 2}},
     {"value": "analyze_thoroughly", "label": "Analyze all data thoroughly before deciding", "disc_scores": {"C": 2}}
   ]}',
   true, 101, NOW(), NOW()),

  -- Work pace
  ('DISC-003', 'My preferred work pace is:', 'single_choice',
   '{"options": [
     {"value": "fast_results", "label": "Fast-paced, focused on results", "disc_scores": {"D": 2}},
     {"value": "energetic_varied", "label": "Energetic with variety", "disc_scores": {"I": 2}},
     {"value": "steady_consistent", "label": "Steady and consistent", "disc_scores": {"S": 2}},
     {"value": "methodical_precise", "label": "Methodical and precise", "disc_scores": {"C": 2}}
   ]}',
   true, 102, NOW(), NOW()),

  -- Risk tolerance
  ('DISC-004', 'When it comes to business risks, I:', 'single_choice',
   '{"options": [
     {"value": "embrace_challenge", "label": "Embrace challenges and take calculated risks", "disc_scores": {"D": 2}},
     {"value": "optimistic", "label": "Stay optimistic about new opportunities", "disc_scores": {"I": 2}},
     {"value": "cautious_secure", "label": "Prefer security and proven approaches", "disc_scores": {"S": 2}},
     {"value": "analyze_risks", "label": "Carefully analyze all potential risks", "disc_scores": {"C": 2}}
   ]}',
   true, 103, NOW(), NOW()),

  -- Team interaction
  ('DISC-005', 'In team settings, I am most likely to:', 'single_choice',
   '{"options": [
     {"value": "take_charge", "label": "Take charge and drive results", "disc_scores": {"D": 2}},
     {"value": "energize_team", "label": "Energize the team and build enthusiasm", "disc_scores": {"I": 2}},
     {"value": "support_harmony", "label": "Support others and maintain harmony", "disc_scores": {"S": 2}},
     {"value": "ensure_quality", "label": "Ensure quality and accuracy", "disc_scores": {"C": 2}}
   ]}',
   true, 104, NOW(), NOW()),

  -- Problem-solving approach
  ('DISC-006', 'When facing a business problem, I:', 'single_choice',
   '{"options": [
     {"value": "solve_quickly", "label": "Want to solve it quickly and efficiently", "disc_scores": {"D": 2}},
     {"value": "brainstorm", "label": "Like to brainstorm creative solutions with others", "disc_scores": {"I": 2}},
     {"value": "consider_people", "label": "Consider how it affects people involved", "disc_scores": {"S": 2}},
     {"value": "research_analyze", "label": "Research and analyze all possible solutions", "disc_scores": {"C": 2}}
   ]}',
   true, 105, NOW(), NOW()),

  -- Priority focus
  ('DISC-007', 'What matters most to me in business is:', 'single_choice',
   '{"options": [
     {"value": "achievement", "label": "Achievement and results", "disc_scores": {"D": 2}},
     {"value": "relationships", "label": "Relationships and collaboration", "disc_scores": {"I": 2}},
     {"value": "stability", "label": "Stability and consistency", "disc_scores": {"S": 2}},
     {"value": "accuracy", "label": "Accuracy and quality", "disc_scores": {"C": 2}}
   ]}',
   true, 106, NOW(), NOW()),

  -- Detail orientation
  ('DISC-008', 'When reviewing financial information, I prefer:', 'single_choice',
   '{"options": [
     {"value": "summary", "label": "Summary of key numbers and action items", "disc_scores": {"D": 2}},
     {"value": "visual_overview", "label": "Visual overview with highlights", "disc_scores": {"I": 2}},
     {"value": "clear_explanation", "label": "Clear step-by-step explanation", "disc_scores": {"S": 2}},
     {"value": "comprehensive_detail", "label": "Comprehensive detail and documentation", "disc_scores": {"C": 2}}
   ]}',
   true, 107, NOW(), NOW()),

  -- Change response
  ('DISC-009', 'When business changes are needed, I:', 'single_choice',
   '{"options": [
     {"value": "drive_change", "label": "Drive change decisively", "disc_scores": {"D": 2}},
     {"value": "inspire_enthusiasm", "label": "Inspire enthusiasm for the change", "disc_scores": {"I": 2}},
     {"value": "need_time", "label": "Need time to adapt and prefer gradual shifts", "disc_scores": {"S": 2}},
     {"value": "evaluate_thoroughly", "label": "Want to evaluate the change thoroughly first", "disc_scores": {"C": 2}}
   ]}',
   true, 108, NOW(), NOW()),

  -- Feedback preference
  ('DISC-010', 'I prefer feedback that is:', 'single_choice',
   '{"options": [
     {"value": "direct_concise", "label": "Direct and concise", "disc_scores": {"D": 2}},
     {"value": "positive_encouraging", "label": "Positive and encouraging", "disc_scores": {"I": 2}},
     {"value": "supportive_patient", "label": "Supportive and patient", "disc_scores": {"S": 2}},
     {"value": "specific_detailed", "label": "Specific and detailed", "disc_scores": {"C": 2}}
   ]}',
   true, 109, NOW(), NOW()),

  -- Planning style
  ('DISC-011', 'My approach to planning is:', 'single_choice',
   '{"options": [
     {"value": "quick_action", "label": "Quick planning, focus on action", "disc_scores": {"D": 2}},
     {"value": "big_picture", "label": "Big picture vision with flexibility", "disc_scores": {"I": 2}},
     {"value": "careful_thorough", "label": "Careful and thorough", "disc_scores": {"S": 2}},
     {"value": "detailed_systematic", "label": "Detailed and systematic", "disc_scores": {"C": 2}}
   ]}',
   true, 110, NOW(), NOW()),

  -- Success definition
  ('DISC-012', 'Success in business means:', 'single_choice',
   '{"options": [
     {"value": "winning_achieving", "label": "Winning and achieving ambitious goals", "disc_scores": {"D": 2}},
     {"value": "recognition_impact", "label": "Recognition and making a positive impact", "disc_scores": {"I": 2}},
     {"value": "security_loyalty", "label": "Security and loyal relationships", "disc_scores": {"S": 2}},
     {"value": "excellence_mastery", "label": "Excellence and mastery", "disc_scores": {"C": 2}}
   ]}',
   true, 111, NOW(), NOW())

ON CONFLICT (question_key) DO NOTHING;

-- Final count
SELECT
  'Questions seeded successfully!' as message,
  COUNT(*) as total_questions,
  COUNT(*) FILTER (WHERE question_key LIKE 'META-%') as metadata_questions,
  COUNT(*) FILTER (WHERE question_key LIKE 'STAB-%') as stabilize_questions,
  COUNT(*) FILTER (WHERE question_key LIKE 'ORG-%') as organize_questions,
  COUNT(*) FILTER (WHERE question_key LIKE 'BUILD-%') as build_questions,
  COUNT(*) FILTER (WHERE question_key LIKE 'GROW-%') as grow_questions,
  COUNT(*) FILTER (WHERE question_key LIKE 'SYS-%') as systemic_questions,
  COUNT(*) FILTER (WHERE question_key LIKE 'DISC-%') as disc_questions
FROM questions;
