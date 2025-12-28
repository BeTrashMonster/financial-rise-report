import { LogSanitizer } from './log-sanitizer';

describe('LogSanitizer', () => {
  describe('sanitizeEmail', () => {
    it('should redact email address showing only domain', () => {
      const result = LogSanitizer.sanitizeEmail('john.doe@example.com');
      expect(result).toBe('***@example.com');
    });

    it('should handle emails with subdomains', () => {
      const result = LogSanitizer.sanitizeEmail('user@mail.company.co.uk');
      expect(result).toBe('***@mail.company.co.uk');
    });

    it('should handle invalid email formats gracefully', () => {
      const result = LogSanitizer.sanitizeEmail('not-an-email');
      expect(result).toBe('[REDACTED]');
    });

    it('should handle null or undefined', () => {
      expect(LogSanitizer.sanitizeEmail(null as any)).toBe('[REDACTED]');
      expect(LogSanitizer.sanitizeEmail(undefined as any)).toBe('[REDACTED]');
    });

    it('should handle empty string', () => {
      expect(LogSanitizer.sanitizeEmail('')).toBe('[REDACTED]');
    });
  });

  describe('sanitizeToken', () => {
    it('should completely redact tokens', () => {
      const token = 'abc123def456ghi789jkl012mno345pqr678';
      const result = LogSanitizer.sanitizeToken(token);
      expect(result).toBe('[REDACTED - TOKEN]');
    });

    it('should not reveal token length', () => {
      const shortToken = 'abc';
      const longToken = 'a'.repeat(100);
      expect(LogSanitizer.sanitizeToken(shortToken)).toBe('[REDACTED - TOKEN]');
      expect(LogSanitizer.sanitizeToken(longToken)).toBe('[REDACTED - TOKEN]');
    });

    it('should handle null or undefined tokens', () => {
      expect(LogSanitizer.sanitizeToken(null as any)).toBe('[REDACTED - TOKEN]');
      expect(LogSanitizer.sanitizeToken(undefined as any)).toBe('[REDACTED - TOKEN]');
    });
  });

  describe('sanitizeDISCScores', () => {
    it('should completely redact DISC scores in production', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      const scores = { D: 75, I: 60, S: 45, C: 80 };
      const result = LogSanitizer.sanitizeDISCScores(scores);

      expect(result).toBe('[REDACTED - PII]');
      expect(result).not.toContain('75');
      expect(result).not.toContain('60');
      expect(result).not.toContain('45');
      expect(result).not.toContain('80');

      process.env.NODE_ENV = originalEnv;
    });

    it('should return hash in development for debugging', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';

      const scores = { D: 75, I: 60, S: 45, C: 80 };
      const result = LogSanitizer.sanitizeDISCScores(scores);

      expect(result).toMatch(/^[a-f0-9]{8}$/); // 8 character hex hash
      expect(result).not.toContain('75');
      expect(result).not.toContain('60');

      process.env.NODE_ENV = originalEnv;
    });

    it('should produce different hashes for different scores', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';

      const scores1 = { D: 75, I: 60, S: 45, C: 80 };
      const scores2 = { D: 80, I: 45, S: 60, C: 75 };

      const hash1 = LogSanitizer.sanitizeDISCScores(scores1);
      const hash2 = LogSanitizer.sanitizeDISCScores(scores2);

      expect(hash1).not.toBe(hash2);

      process.env.NODE_ENV = originalEnv;
    });

    it('should produce same hash for identical scores', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';

      const scores1 = { D: 75, I: 60, S: 45, C: 80 };
      const scores2 = { D: 75, I: 60, S: 45, C: 80 };

      const hash1 = LogSanitizer.sanitizeDISCScores(scores1);
      const hash2 = LogSanitizer.sanitizeDISCScores(scores2);

      expect(hash1).toBe(hash2);

      process.env.NODE_ENV = originalEnv;
    });
  });

  describe('sanitizePassword', () => {
    it('should completely redact passwords', () => {
      const result = LogSanitizer.sanitizePassword('SecureP@ssw0rd123!');
      expect(result).toBe('[REDACTED - PASSWORD]');
    });

    it('should not reveal password length', () => {
      expect(LogSanitizer.sanitizePassword('short')).toBe('[REDACTED - PASSWORD]');
      expect(LogSanitizer.sanitizePassword('a'.repeat(50))).toBe('[REDACTED - PASSWORD]');
    });
  });

  describe('sanitizeName', () => {
    it('should show first letter and mask the rest', () => {
      expect(LogSanitizer.sanitizeName('John Doe')).toBe('J***');
    });

    it('should handle single character names', () => {
      expect(LogSanitizer.sanitizeName('A')).toBe('A');
    });

    it('should handle empty strings', () => {
      expect(LogSanitizer.sanitizeName('')).toBe('[REDACTED]');
    });

    it('should handle null or undefined', () => {
      expect(LogSanitizer.sanitizeName(null as any)).toBe('[REDACTED]');
      expect(LogSanitizer.sanitizeName(undefined as any)).toBe('[REDACTED]');
    });

    it('should handle names with special characters', () => {
      expect(LogSanitizer.sanitizeName("O'Brien")).toBe('O***');
    });
  });

  describe('sanitizeFinancialData', () => {
    it('should mask numeric values', () => {
      const result = LogSanitizer.sanitizeFinancialData(123456.78);
      expect(result).toBe('[REDACTED - FINANCIAL]');
    });

    it('should mask currency strings', () => {
      const result = LogSanitizer.sanitizeFinancialData('$123,456.78');
      expect(result).toBe('[REDACTED - FINANCIAL]');
    });

    it('should handle null values', () => {
      expect(LogSanitizer.sanitizeFinancialData(null)).toBe('[REDACTED - FINANCIAL]');
    });
  });

  describe('sanitizeObject', () => {
    it('should sanitize sensitive fields in objects', () => {
      const data = {
        id: '123',
        email: 'user@example.com',
        password: 'SecureP@ss123',
        resetToken: 'abc123def456',
        name: 'John Doe',
        revenue: 500000,
      };

      const result = LogSanitizer.sanitizeObject(data);

      expect(result.id).toBe('123');
      expect(result.email).toBe('***@example.com');
      expect(result.password).toBe('[REDACTED - PASSWORD]');
      expect(result.resetToken).toBe('[REDACTED - TOKEN]');
      expect(result.name).toBe('J***');
      expect(result.revenue).toBe('[REDACTED - FINANCIAL]');
    });

    it('should handle nested objects', () => {
      const data = {
        user: {
          email: 'test@example.com',
          profile: {
            name: 'Jane Smith',
          },
        },
        auth: {
          password: 'secret123',
        },
      };

      const result = LogSanitizer.sanitizeObject(data);

      expect(result.user.email).toBe('***@example.com');
      expect(result.user.profile.name).toBe('J***');
      expect(result.auth.password).toBe('[REDACTED - PASSWORD]');
    });

    it('should handle arrays in objects', () => {
      const data = {
        users: [
          { email: 'user1@test.com', name: 'Alice' },
          { email: 'user2@test.com', name: 'Bob' },
        ],
      };

      const result = LogSanitizer.sanitizeObject(data);

      expect(result.users[0].email).toBe('***@test.com');
      expect(result.users[0].name).toBe('A***');
      expect(result.users[1].email).toBe('***@test.com');
      expect(result.users[1].name).toBe('B***');
    });

    it('should preserve non-sensitive fields', () => {
      const data = {
        id: 'user-123',
        status: 'active',
        createdAt: '2025-01-01',
        email: 'test@example.com',
      };

      const result = LogSanitizer.sanitizeObject(data);

      expect(result.id).toBe('user-123');
      expect(result.status).toBe('active');
      expect(result.createdAt).toBe('2025-01-01');
      expect(result.email).toBe('***@example.com');
    });

    it('should handle DISC score fields', () => {
      const data = {
        assessmentId: 'assess-123',
        d_score: 75,
        i_score: 60,
        s_score: 45,
        c_score: 80,
      };

      const result = LogSanitizer.sanitizeObject(data);

      expect(result.assessmentId).toBe('assess-123');
      expect(result.d_score).toBe('[REDACTED - PII]');
      expect(result.i_score).toBe('[REDACTED - PII]');
      expect(result.s_score).toBe('[REDACTED - PII]');
      expect(result.c_score).toBe('[REDACTED - PII]');
    });

    it('should handle null and undefined', () => {
      expect(LogSanitizer.sanitizeObject(null as any)).toBeNull();
      expect(LogSanitizer.sanitizeObject(undefined as any)).toBeUndefined();
    });

    it('should handle primitive values', () => {
      expect(LogSanitizer.sanitizeObject('string' as any)).toBe('string');
      expect(LogSanitizer.sanitizeObject(123 as any)).toBe(123);
      expect(LogSanitizer.sanitizeObject(true as any)).toBe(true);
    });
  });

  describe('sanitizeUrl', () => {
    it('should preserve URL structure but redact query params with sensitive data', () => {
      const url = 'https://api.example.com/reset-password?token=abc123&email=user@test.com';
      const result = LogSanitizer.sanitizeUrl(url);

      expect(result).toContain('https://api.example.com/reset-password');
      expect(result).not.toContain('abc123');
      expect(result).not.toContain('user@test.com');
    });

    it('should redact token query parameters', () => {
      const url = 'https://api.example.com/verify?token=secret123';
      const result = LogSanitizer.sanitizeUrl(url);

      // URL encoding converts [REDACTED] to %5BREDACTED%5D - both are acceptable
      expect(result).toMatch(/token=(%5B)?REDACTED(%5D)?/);
      expect(result).not.toContain('secret123');
    });

    it('should preserve safe query parameters', () => {
      const url = 'https://api.example.com/users?page=1&limit=10';
      const result = LogSanitizer.sanitizeUrl(url);

      expect(result).toBe(url);
    });

    it('should handle URLs without query params', () => {
      const url = 'https://api.example.com/users/123';
      const result = LogSanitizer.sanitizeUrl(url);

      expect(result).toBe(url);
    });
  });

  describe('detectAndRedactPII', () => {
    it('should detect and redact email addresses in strings', () => {
      const text = 'User john.doe@example.com requested password reset';
      const result = LogSanitizer.detectAndRedactPII(text);

      expect(result).toBe('User ***@example.com requested password reset');
    });

    it('should detect and redact multiple emails', () => {
      const text = 'Emails: user1@test.com, admin@company.org';
      const result = LogSanitizer.detectAndRedactPII(text);

      expect(result).toContain('***@test.com');
      expect(result).toContain('***@company.org');
    });

    it('should detect and redact JWT-like tokens', () => {
      const text = 'Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
      const result = LogSanitizer.detectAndRedactPII(text);

      expect(result).toContain('[REDACTED - TOKEN]');
      expect(result).not.toContain('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
    });

    it('should detect and redact hex tokens (32+ chars)', () => {
      const text = 'Reset token: abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567';
      const result = LogSanitizer.detectAndRedactPII(text);

      expect(result).toContain('[REDACTED - TOKEN]');
      expect(result).not.toContain('abc123def456');
    });

    it('should preserve non-sensitive content', () => {
      const text = 'User ID: 12345 requested action at 2025-12-28T10:00:00Z';
      const result = LogSanitizer.detectAndRedactPII(text);

      expect(result).toBe(text);
    });

    it('should handle empty strings', () => {
      expect(LogSanitizer.detectAndRedactPII('')).toBe('');
    });

    it('should handle null and undefined', () => {
      expect(LogSanitizer.detectAndRedactPII(null as any)).toBe('');
      expect(LogSanitizer.detectAndRedactPII(undefined as any)).toBe('');
    });
  });

  describe('sanitizePhoneNumber', () => {
    it('should mask phone numbers showing only last 4 digits', () => {
      expect(LogSanitizer.sanitizePhoneNumber('555-123-4567')).toBe('***-***-4567');
    });

    it('should handle phone numbers in different formats', () => {
      expect(LogSanitizer.sanitizePhoneNumber('(555) 123-4567')).toBe('***-***-4567');
      expect(LogSanitizer.sanitizePhoneNumber('5551234567')).toBe('***-***-4567');
      expect(LogSanitizer.sanitizePhoneNumber('+1 555 123 4567')).toBe('***-***-4567');
    });

    it('should handle international phone numbers', () => {
      expect(LogSanitizer.sanitizePhoneNumber('+44 20 1234 5678')).toBe('***-***-5678');
    });

    it('should handle null or undefined', () => {
      expect(LogSanitizer.sanitizePhoneNumber(null as any)).toBe('[REDACTED]');
      expect(LogSanitizer.sanitizePhoneNumber(undefined as any)).toBe('[REDACTED]');
    });

    it('should handle invalid phone numbers', () => {
      expect(LogSanitizer.sanitizePhoneNumber('123')).toBe('[REDACTED]');
      expect(LogSanitizer.sanitizePhoneNumber('not-a-phone')).toBe('[REDACTED]');
    });
  });

  describe('sanitizeSSN', () => {
    it('should completely redact SSN', () => {
      expect(LogSanitizer.sanitizeSSN('123-45-6789')).toBe('[REDACTED - SSN]');
    });

    it('should handle SSN without dashes', () => {
      expect(LogSanitizer.sanitizeSSN('123456789')).toBe('[REDACTED - SSN]');
    });

    it('should handle null or undefined', () => {
      expect(LogSanitizer.sanitizeSSN(null as any)).toBe('[REDACTED - SSN]');
      expect(LogSanitizer.sanitizeSSN(undefined as any)).toBe('[REDACTED - SSN]');
    });
  });

  describe('sanitizeCreditCard', () => {
    it('should show only last 4 digits of credit card', () => {
      expect(LogSanitizer.sanitizeCreditCard('4532-1234-5678-9010')).toBe('****-****-****-9010');
    });

    it('should handle credit cards without dashes', () => {
      expect(LogSanitizer.sanitizeCreditCard('4532123456789010')).toBe('****-****-****-9010');
    });

    it('should handle Amex format (15 digits)', () => {
      expect(LogSanitizer.sanitizeCreditCard('371449635398431')).toBe('****-****-***-8431');
    });

    it('should handle null or undefined', () => {
      expect(LogSanitizer.sanitizeCreditCard(null as any)).toBe('[REDACTED]');
      expect(LogSanitizer.sanitizeCreditCard(undefined as any)).toBe('[REDACTED]');
    });
  });

  describe('sanitizeIPAddress', () => {
    it('should mask IPv4 addresses showing only first octet', () => {
      expect(LogSanitizer.sanitizeIPAddress('192.168.1.100')).toBe('192.*.*.*');
    });

    it('should handle localhost', () => {
      expect(LogSanitizer.sanitizeIPAddress('127.0.0.1')).toBe('127.*.*.*');
    });

    it('should mask IPv6 addresses', () => {
      expect(LogSanitizer.sanitizeIPAddress('2001:0db8:85a3:0000:0000:8a2e:0370:7334')).toBe('[REDACTED - IPv6]');
    });

    it('should handle null or undefined', () => {
      expect(LogSanitizer.sanitizeIPAddress(null as any)).toBe('[REDACTED]');
      expect(LogSanitizer.sanitizeIPAddress(undefined as any)).toBe('[REDACTED]');
    });
  });

  describe('sanitizeAddress', () => {
    it('should completely redact physical addresses', () => {
      expect(LogSanitizer.sanitizeAddress('123 Main St, Portland, OR 97201')).toBe('[REDACTED - ADDRESS]');
    });

    it('should handle multi-line addresses', () => {
      const address = '123 Main St\nApt 4B\nPortland, OR 97201';
      expect(LogSanitizer.sanitizeAddress(address)).toBe('[REDACTED - ADDRESS]');
    });

    it('should handle null or undefined', () => {
      expect(LogSanitizer.sanitizeAddress(null as any)).toBe('[REDACTED - ADDRESS]');
      expect(LogSanitizer.sanitizeAddress(undefined as any)).toBe('[REDACTED - ADDRESS]');
    });
  });

  describe('detectAndRedactPII - Enhanced', () => {
    it('should detect and redact phone numbers in text', () => {
      const text = 'Please call me at 555-123-4567 or (555) 987-6543';
      const result = LogSanitizer.detectAndRedactPII(text);

      expect(result).toContain('***-***-4567');
      expect(result).toContain('***-***-6543');
      expect(result).not.toContain('555-123-4567');
    });

    it('should detect and redact SSN in text', () => {
      const text = 'SSN: 123-45-6789 on file';
      const result = LogSanitizer.detectAndRedactPII(text);

      expect(result).toContain('[REDACTED - SSN]');
      expect(result).not.toContain('123-45-6789');
    });

    it('should detect and redact credit card numbers', () => {
      const text = 'Payment made with card 4532-1234-5678-9010';
      const result = LogSanitizer.detectAndRedactPII(text);

      expect(result).toContain('****-****-****-9010');
      expect(result).not.toContain('4532-1234-5678-9010');
    });

    it('should detect and redact IP addresses', () => {
      const text = 'Request from IP 192.168.1.100';
      const result = LogSanitizer.detectAndRedactPII(text);

      expect(result).toContain('192.*.*.*');
      expect(result).not.toContain('192.168.1.100');
    });

    it('should handle multiple PII types in one string', () => {
      const text = 'User john@example.com called from 555-123-4567, IP: 192.168.1.50, Card: 4532123456789010';
      const result = LogSanitizer.detectAndRedactPII(text);

      expect(result).toContain('***@example.com');
      expect(result).toContain('***-***-4567');
      expect(result).toContain('192.*.*.*');
      expect(result).toContain('****-****-****-9010');
    });
  });

  describe('sanitizeObject - Enhanced PII Fields', () => {
    it('should sanitize phone number fields', () => {
      const data = {
        id: '123',
        phone: '555-123-4567',
        mobile: '(555) 987-6543',
        contactNumber: '5559998888',
      };

      const result = LogSanitizer.sanitizeObject(data);

      expect(result.id).toBe('123');
      expect(result.phone).toBe('***-***-4567');
      expect(result.mobile).toBe('***-***-6543');
      expect(result.contactNumber).toBe('***-***-8888');
    });

    it('should sanitize SSN fields', () => {
      const data = {
        id: '123',
        ssn: '123-45-6789',
        socialSecurityNumber: '987654321',
      };

      const result = LogSanitizer.sanitizeObject(data);

      expect(result.id).toBe('123');
      expect(result.ssn).toBe('[REDACTED - SSN]');
      expect(result.socialSecurityNumber).toBe('[REDACTED - SSN]');
    });

    it('should sanitize credit card fields', () => {
      const data = {
        id: '123',
        creditCard: '4532-1234-5678-9010',
        cardNumber: '4532123456789010',
      };

      const result = LogSanitizer.sanitizeObject(data);

      expect(result.id).toBe('123');
      expect(result.creditCard).toBe('****-****-****-9010');
      expect(result.cardNumber).toBe('****-****-****-9010');
    });

    it('should sanitize IP address fields', () => {
      const data = {
        id: '123',
        ipAddress: '192.168.1.100',
        ip: '10.0.0.5',
        clientIp: '172.16.0.1',
      };

      const result = LogSanitizer.sanitizeObject(data);

      expect(result.id).toBe('123');
      expect(result.ipAddress).toBe('192.*.*.*');
      expect(result.ip).toBe('10.*.*.*');
      expect(result.clientIp).toBe('172.*.*.*');
    });

    it('should sanitize address fields', () => {
      const data = {
        id: '123',
        address: '123 Main St, Portland, OR',
        street: '456 Oak Ave',
        mailingAddress: 'PO Box 789',
      };

      const result = LogSanitizer.sanitizeObject(data);

      expect(result.id).toBe('123');
      expect(result.address).toBe('[REDACTED - ADDRESS]');
      expect(result.street).toBe('[REDACTED - ADDRESS]');
      expect(result.mailingAddress).toBe('[REDACTED - ADDRESS]');
    });

    it('should handle complex nested objects with multiple PII types', () => {
      const data = {
        user: {
          name: 'John Doe',
          email: 'john@example.com',
          phone: '555-123-4567',
          address: '123 Main St',
        },
        payment: {
          cardNumber: '4532123456789010',
          amount: 1500,
        },
        metadata: {
          ipAddress: '192.168.1.100',
          ssn: '123-45-6789',
        },
      };

      const result = LogSanitizer.sanitizeObject(data);

      expect(result.user.name).toBe('J***');
      expect(result.user.email).toBe('***@example.com');
      expect(result.user.phone).toBe('***-***-4567');
      expect(result.user.address).toBe('[REDACTED - ADDRESS]');
      expect(result.payment.cardNumber).toBe('****-****-****-9010');
      expect(result.payment.amount).toBe('[REDACTED - FINANCIAL]');
      expect(result.metadata.ipAddress).toBe('192.*.*.*');
      expect(result.metadata.ssn).toBe('[REDACTED - SSN]');
    });
  });

  describe('integration scenarios', () => {
    it('should sanitize complete authentication log entry', () => {
      const logData = {
        event: 'password_reset_requested',
        email: 'user@example.com',
        resetToken: 'abc123def456ghi789',
        timestamp: '2025-12-28T10:00:00Z',
      };

      const sanitized = LogSanitizer.sanitizeObject(logData);

      expect(sanitized.event).toBe('password_reset_requested');
      expect(sanitized.email).toBe('***@example.com');
      expect(sanitized.resetToken).toBe('[REDACTED - TOKEN]');
      expect(sanitized.timestamp).toBe('2025-12-28T10:00:00Z');
    });

    it('should sanitize DISC calculation log entry', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      const logData = {
        assessmentId: 'assess-123',
        scores: { D: 75, I: 60, S: 45, C: 80 },
        calculatedAt: '2025-12-28T10:00:00Z',
      };

      const sanitized = LogSanitizer.sanitizeObject(logData);

      expect(sanitized.assessmentId).toBe('assess-123');
      expect(sanitized.scores).toBe('[REDACTED - PII]');
      expect(sanitized.calculatedAt).toBe('2025-12-28T10:00:00Z');

      process.env.NODE_ENV = originalEnv;
    });

    it('should sanitize financial assessment data', () => {
      const logData = {
        clientName: 'John Smith',
        email: 'john@business.com',
        revenue: 500000,
        expenses: 350000,
        assessmentType: 'quarterly',
      };

      const sanitized = LogSanitizer.sanitizeObject(logData);

      expect(sanitized.clientName).toBe('J***');
      expect(sanitized.email).toBe('***@business.com');
      expect(sanitized.revenue).toBe('[REDACTED - FINANCIAL]');
      expect(sanitized.expenses).toBe('[REDACTED - FINANCIAL]');
      expect(sanitized.assessmentType).toBe('quarterly');
    });
  });
});
