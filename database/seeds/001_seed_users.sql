-- Seed Users for Development
-- Password for all users: "SecurePass123!"
-- bcrypt hash with work factor 12

-- Insert Admin User
INSERT INTO users (
    id,
    email,
    password_hash,
    role,
    first_name,
    last_name,
    is_active,
    created_at,
    updated_at
) VALUES (
    '00000000-0000-0000-0000-000000000001',
    'admin@financialrise.com',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYWK6lF7pVW',
    'admin',
    'System',
    'Administrator',
    true,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);

-- Insert Sample Consultants
INSERT INTO users (
    id,
    email,
    password_hash,
    role,
    first_name,
    last_name,
    is_active,
    created_at,
    updated_at
) VALUES
(
    '00000000-0000-0000-0000-000000000002',
    'john.smith@consultants.com',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYWK6lF7pVW',
    'consultant',
    'John',
    'Smith',
    true,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
),
(
    '00000000-0000-0000-0000-000000000003',
    'sarah.johnson@consultants.com',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYWK6lF7pVW',
    'consultant',
    'Sarah',
    'Johnson',
    true,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
),
(
    '00000000-0000-0000-0000-000000000004',
    'michael.chen@consultants.com',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYWK6lF7pVW',
    'consultant',
    'Michael',
    'Chen',
    true,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);

-- Insert Consultant Settings for Sample Consultants
INSERT INTO consultant_settings (
    consultant_id,
    company_name,
    brand_color,
    email_signature,
    created_at,
    updated_at
) VALUES
(
    '00000000-0000-0000-0000-000000000002',
    'Smith Financial Consulting',
    '#4B006E',
    'Best regards,\nJohn Smith\nCertified Financial Consultant',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
),
(
    '00000000-0000-0000-0000-000000000003',
    'Johnson & Associates',
    '#2E5090',
    'Warm regards,\nSarah Johnson, CPA\nFinancial Advisory Services',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
),
(
    '00000000-0000-0000-0000-000000000004',
    'Chen CFO Services',
    '#1A472A',
    'Sincerely,\nMichael Chen\nFractional CFO',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);
