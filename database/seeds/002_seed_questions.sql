-- Seed Sample Assessment Questions
-- This is a starter set - full question bank should be developed with SME input

-- Metadata Questions
INSERT INTO questions (
    question_text,
    question_type,
    section,
    order_index,
    is_required,
    is_conditional,
    disc_trait_mapping,
    phase_weight_mapping,
    answer_options
) VALUES
(
    'How confident do you feel about where you are with your business finances right now?',
    'rating',
    'metadata',
    1,
    true,
    false,
    NULL,
    NULL,
    NULL
),
(
    'What is your business entity type?',
    'single_choice',
    'metadata',
    2,
    true,
    false,
    NULL,
    NULL,
    '[
        {"value": "sole_proprietor", "label": "Sole Proprietor"},
        {"value": "llc", "label": "LLC"},
        {"value": "s_corp", "label": "S-Corporation"},
        {"value": "c_corp", "label": "C-Corporation"},
        {"value": "partnership", "label": "Partnership"},
        {"value": "other", "label": "Other"}
    ]'::jsonb
);

-- Conditional S-Corp Payroll Question
INSERT INTO questions (
    question_text,
    question_type,
    section,
    order_index,
    is_required,
    is_conditional,
    conditional_parent_id,
    conditional_trigger_value,
    disc_trait_mapping,
    phase_weight_mapping,
    answer_options
) VALUES
(
    'Are you currently on payroll?',
    'single_choice',
    'organize',
    3,
    true,
    true,
    (SELECT id FROM questions WHERE question_text LIKE '%business entity type%'),
    's_corp',
    NULL,
    '{"option_yes": {"organize": 3}, "option_no": {"stabilize": 5, "organize": 0}}'::jsonb,
    '[
        {"value": "option_yes", "label": "Yes, I am on payroll"},
        {"value": "option_no", "label": "No, I am not on payroll"}
    ]'::jsonb
);

-- Stabilize Phase Questions
INSERT INTO questions (
    question_text,
    question_type,
    section,
    order_index,
    is_required,
    is_conditional,
    disc_trait_mapping,
    phase_weight_mapping,
    answer_options,
    help_text
) VALUES
(
    'Are your books currently up to date?',
    'single_choice',
    'stabilize',
    10,
    true,
    false,
    NULL,
    '{
        "option_current": {"stabilize": 0, "organize": 2},
        "option_1month": {"stabilize": 2, "organize": 1},
        "option_3months": {"stabilize": 4, "organize": 0},
        "option_6months": {"stabilize": 5, "organize": 0}
    }'::jsonb,
    '[
        {"value": "option_current", "label": "Yes, current within the last week"},
        {"value": "option_1month", "label": "Within the last month"},
        {"value": "option_3months", "label": "1-3 months behind"},
        {"value": "option_6months", "label": "More than 3 months behind"}
    ]'::jsonb,
    'Up-to-date books are essential for accurate financial decision-making'
),
(
    'Do you have outstanding tax obligations or unfiled returns?',
    'single_choice',
    'stabilize',
    11,
    true,
    false,
    NULL,
    '{
        "option_current": {"stabilize": 0},
        "option_minor": {"stabilize": 2},
        "option_significant": {"stabilize": 5}
    }'::jsonb,
    '[
        {"value": "option_current", "label": "No, all taxes are current and filed"},
        {"value": "option_minor", "label": "Minor outstanding obligations (less than $5,000)"},
        {"value": "option_significant", "label": "Significant obligations or unfiled returns"}
    ]'::jsonb,
    'Tax compliance is critical for business stability'
);

-- Organize Phase Questions
INSERT INTO questions (
    question_text,
    question_type,
    section,
    order_index,
    is_required,
    is_conditional,
    disc_trait_mapping,
    phase_weight_mapping,
    answer_options,
    help_text
) VALUES
(
    'Do you have a proper Chart of Accounts set up for your business?',
    'single_choice',
    'organize',
    20,
    true,
    false,
    NULL,
    '{
        "option_yes": {"organize": 0, "build": 1},
        "option_basic": {"organize": 2},
        "option_no": {"organize": 5, "stabilize": 1}
    }'::jsonb,
    '[
        {"value": "option_yes", "label": "Yes, properly structured for my industry"},
        {"value": "option_basic", "label": "Basic setup, but not optimized"},
        {"value": "option_no", "label": "No, or using default chart"}
    ]'::jsonb,
    'A proper Chart of Accounts is the foundation of accurate financial reporting'
),
(
    'How well integrated are your financial systems (accounting software, payment processors, etc.)?',
    'single_choice',
    'organize',
    21,
    true,
    false,
    NULL,
    '{
        "option_integrated": {"organize": 0, "build": 2},
        "option_partial": {"organize": 3},
        "option_manual": {"organize": 5}
    }'::jsonb,
    '[
        {"value": "option_integrated", "label": "Fully integrated and automated"},
        {"value": "option_partial", "label": "Some integration, but manual processes remain"},
        {"value": "option_manual", "label": "Mostly manual data entry"}
    ]'::jsonb,
    'Integration reduces errors and saves time'
);

-- DISC Profile Questions (hidden from client)
INSERT INTO questions (
    question_text,
    question_type,
    section,
    order_index,
    is_required,
    is_conditional,
    disc_trait_mapping,
    phase_weight_mapping,
    answer_options,
    help_text
) VALUES
(
    'When reviewing financial reports, what matters most to you?',
    'single_choice',
    'disc',
    30,
    true,
    false,
    '{
        "option_bottom_line": {"D": 5, "I": 0, "S": 0, "C": 1},
        "option_trends": {"D": 2, "I": 3, "S": 1, "C": 2},
        "option_understanding": {"D": 0, "I": 1, "S": 5, "C": 2},
        "option_accuracy": {"D": 0, "I": 0, "S": 1, "C": 5}
    }'::jsonb,
    NULL,
    '[
        {"value": "option_bottom_line", "label": "The bottom line - profit or loss"},
        {"value": "option_trends", "label": "Trends and opportunities"},
        {"value": "option_understanding", "label": "Understanding what each number means"},
        {"value": "option_accuracy", "label": "Accuracy and detail of every line item"}
    ]'::jsonb,
    NULL
),
(
    'When making financial decisions for your business, you tend to:',
    'single_choice',
    'disc',
    31,
    true,
    false,
    '{
        "option_decide_fast": {"D": 5, "I": 2, "S": 0, "C": 0},
        "option_discuss": {"D": 1, "I": 5, "S": 2, "C": 0},
        "option_consider": {"D": 0, "I": 1, "S": 5, "C": 2},
        "option_analyze": {"D": 0, "I": 0, "S": 1, "C": 5}
    }'::jsonb,
    NULL,
    '[
        {"value": "option_decide_fast", "label": "Make quick decisions based on gut feel"},
        {"value": "option_discuss", "label": "Discuss with others and decide together"},
        {"value": "option_consider", "label": "Take time to consider all implications"},
        {"value": "option_analyze", "label": "Thoroughly analyze all data before deciding"}
    ]'::jsonb,
    NULL
);

-- Build Phase Question
INSERT INTO questions (
    question_text,
    question_type,
    section,
    order_index,
    is_required,
    is_conditional,
    disc_trait_mapping,
    phase_weight_mapping,
    answer_options,
    help_text
) VALUES
(
    'Do you have documented Standard Operating Procedures (SOPs) for your financial processes?',
    'single_choice',
    'build',
    40,
    true,
    false,
    NULL,
    '{
        "option_comprehensive": {"build": 0, "grow": 2},
        "option_partial": {"build": 3},
        "option_none": {"build": 5, "organize": 2}
    }'::jsonb,
    '[
        {"value": "option_comprehensive", "label": "Yes, comprehensive and followed"},
        {"value": "option_partial", "label": "Some processes documented"},
        {"value": "option_none", "label": "No, mostly undocumented"}
    ]'::jsonb,
    'SOPs ensure consistency and enable delegation'
);

-- Grow Phase Question
INSERT INTO questions (
    question_text,
    question_type,
    section,
    order_index,
    is_required,
    is_conditional,
    disc_trait_mapping,
    phase_weight_mapping,
    answer_options,
    help_text
) VALUES
(
    'Do you have a rolling 12-month cash flow forecast?',
    'single_choice',
    'grow',
    50,
    true,
    false,
    NULL,
    '{
        "option_yes_updated": {"grow": 0},
        "option_yes_old": {"grow": 2},
        "option_no": {"grow": 5, "build": 2}
    }'::jsonb,
    '[
        {"value": "option_yes_updated", "label": "Yes, updated regularly"},
        {"value": "option_yes_old", "label": "Yes, but not kept current"},
        {"value": "option_no", "label": "No"}
    ]'::jsonb,
    'Cash flow forecasting enables proactive decision-making'
);

-- Systemic Phase Question
INSERT INTO questions (
    question_text,
    question_type,
    section,
    order_index,
    is_required,
    is_conditional,
    disc_trait_mapping,
    phase_weight_mapping,
    answer_options,
    help_text
) VALUES
(
    'How comfortable are you reading and interpreting financial reports?',
    'rating',
    'systemic',
    60,
    true,
    false,
    NULL,
    '{
        "1": {"systemic": 5},
        "2": {"systemic": 4},
        "3": {"systemic": 3},
        "4": {"systemic": 2},
        "5": {"systemic": 0}
    }'::jsonb,
    NULL,
    'Financial literacy enables better decision-making'
);

-- Final Confidence Question
INSERT INTO questions (
    question_text,
    question_type,
    section,
    order_index,
    is_required,
    is_conditional,
    disc_trait_mapping,
    phase_weight_mapping,
    answer_options
) VALUES
(
    'After completing this assessment, how confident do you feel about your understanding of where you are with your business finances?',
    'rating',
    'metadata',
    999,
    true,
    false,
    NULL,
    NULL,
    NULL
);
