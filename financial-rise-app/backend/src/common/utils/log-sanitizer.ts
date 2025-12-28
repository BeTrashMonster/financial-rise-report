import * as crypto from 'crypto';

/**
 * LogSanitizer - Utility class for redacting PII from logs
 *
 * SECURITY: Implements CRIT-002 remediation - prevents sensitive data exposure in logs
 * COMPLIANCE: GDPR/CCPA requirement - no PII in application logs
 *
 * Usage:
 *   LogSanitizer.sanitizeEmail('user@example.com') => '***@example.com'
 *   LogSanitizer.sanitizeObject({ email: 'test@test.com' }) => { email: '***@test.com' }
 */
export class LogSanitizer {
  // Sensitive field names that should always be redacted
  private static readonly SENSITIVE_FIELDS = new Set([
    'password',
    'password_hash',
    'resetToken',
    'reset_token',
    'reset_password_token',
    'accessToken',
    'access_token',
    'refreshToken',
    'refresh_token',
    'token',
    'secret',
    'apiKey',
    'api_key',
    'privateKey',
    'private_key',
  ]);

  // Financial field names
  private static readonly FINANCIAL_FIELDS = new Set([
    'revenue',
    'expenses',
    'profit',
    'loss',
    'salary',
    'wage',
    'income',
    'debt',
    'cash',
    'balance',
    'amount',
    'price',
    'cost',
  ]);

  // DISC score field names
  private static readonly DISC_FIELDS = new Set([
    'd_score',
    'i_score',
    's_score',
    'c_score',
    'disc_d_score',
    'disc_i_score',
    'disc_s_score',
    'disc_c_score',
    'scores', // For objects containing DISC scores
  ]);

  // PII field names
  private static readonly PII_FIELDS = new Set([
    'name',
    'firstName',
    'first_name',
    'lastName',
    'last_name',
    'fullName',
    'full_name',
    'clientName',
    'client_name',
  ]);

  /**
   * Sanitize email address - show domain only
   * @param email - Email address to sanitize
   * @returns Sanitized email showing only domain
   */
  static sanitizeEmail(email: string | null | undefined): string {
    if (!email || typeof email !== 'string') {
      return '[REDACTED]';
    }

    if (!email.includes('@')) {
      return '[REDACTED]';
    }

    const [, domain] = email.split('@');
    if (!domain) {
      return '[REDACTED]';
    }

    return `***@${domain}`;
  }

  /**
   * Sanitize token/secret - complete redaction
   * @param token - Token or secret to redact
   * @returns Redacted placeholder
   */
  static sanitizeToken(token: string | null | undefined): string {
    return '[REDACTED - TOKEN]';
  }

  /**
   * Sanitize password - complete redaction
   * @param password - Password to redact
   * @returns Redacted placeholder
   */
  static sanitizePassword(password: string | null | undefined): string {
    return '[REDACTED - PASSWORD]';
  }

  /**
   * Sanitize DISC scores - complete redaction in production, hash in development
   * @param scores - DISC scores object or value
   * @returns Redacted or hashed representation
   */
  static sanitizeDISCScores(scores: any): string {
    if (process.env.NODE_ENV === 'production') {
      return '[REDACTED - PII]';
    }

    // In development, return a hash for debugging correlation
    const hash = crypto
      .createHash('sha256')
      .update(JSON.stringify(scores))
      .digest('hex')
      .substring(0, 8);

    return hash;
  }

  /**
   * Sanitize name - show first letter only
   * @param name - Name to sanitize
   * @returns First letter + ***
   */
  static sanitizeName(name: string | null | undefined): string {
    if (!name || typeof name !== 'string' || name.length === 0) {
      return '[REDACTED]';
    }

    if (name.length === 1) {
      return name;
    }

    return `${name.charAt(0)}***`;
  }

  /**
   * Sanitize financial data - complete redaction
   * @param value - Financial value to redact
   * @returns Redacted placeholder
   */
  static sanitizeFinancialData(value: any): string {
    return '[REDACTED - FINANCIAL]';
  }

  /**
   * Sanitize URL - redact sensitive query parameters
   * @param url - URL to sanitize
   * @returns Sanitized URL with redacted params
   */
  static sanitizeUrl(url: string): string {
    try {
      const urlObj = new URL(url);
      const sensitiveParams = ['token', 'password', 'secret', 'key', 'apiKey'];

      sensitiveParams.forEach((param) => {
        if (urlObj.searchParams.has(param)) {
          urlObj.searchParams.set(param, '[REDACTED]');
        }
      });

      // Also redact email if present
      if (urlObj.searchParams.has('email')) {
        const email = urlObj.searchParams.get('email');
        if (email) {
          urlObj.searchParams.set('email', this.sanitizeEmail(email));
        }
      }

      return urlObj.toString();
    } catch {
      // If URL parsing fails, return as-is (might not be a URL)
      return url;
    }
  }

  /**
   * Detect and redact PII patterns in strings
   * @param text - Text to scan for PII
   * @returns Text with PII redacted
   */
  static detectAndRedactPII(text: string | null | undefined): string {
    if (!text || typeof text !== 'string') {
      return '';
    }

    let sanitized = text;

    // Redact email addresses
    const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
    sanitized = sanitized.replace(emailRegex, (email) => this.sanitizeEmail(email));

    // Redact JWT tokens (three base64 segments separated by dots)
    const jwtRegex = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;
    sanitized = sanitized.replace(jwtRegex, '[REDACTED - TOKEN]');

    // Redact long alphanumeric strings (likely tokens - 32+ characters)
    const hexTokenRegex = /\b[a-fA-F0-9]{32,}\b/g;
    sanitized = sanitized.replace(hexTokenRegex, '[REDACTED - TOKEN]');

    // Redact long mixed alphanumeric strings (also likely tokens)
    const alphaNumTokenRegex = /\b[a-zA-Z0-9]{32,}\b/g;
    sanitized = sanitized.replace(alphaNumTokenRegex, '[REDACTED - TOKEN]');

    return sanitized;
  }

  /**
   * Sanitize an entire object recursively
   * @param obj - Object to sanitize
   * @returns Sanitized copy of object
   */
  static sanitizeObject(obj: any): any {
    if (obj === null || obj === undefined) {
      return obj;
    }

    // Handle primitive types
    if (typeof obj !== 'object') {
      return obj;
    }

    // Handle arrays
    if (Array.isArray(obj)) {
      return obj.map((item) => this.sanitizeObject(item));
    }

    // Handle Date objects
    if (obj instanceof Date) {
      return obj;
    }

    // Handle regular objects
    const sanitized: any = {};

    for (const [key, value] of Object.entries(obj)) {
      const lowerKey = key.toLowerCase();

      // Check if field is password specifically
      if (lowerKey.includes('password')) {
        sanitized[key] = this.sanitizePassword(value as string);
        continue;
      }

      // Check if field is sensitive token
      if (this.SENSITIVE_FIELDS.has(key) || lowerKey.includes('token')) {
        sanitized[key] = this.sanitizeToken(value as string);
        continue;
      }

      // Check if field is email
      if (key === 'email' || lowerKey === 'email') {
        sanitized[key] = this.sanitizeEmail(value as string);
        continue;
      }

      // Check if field is a name
      if (this.PII_FIELDS.has(key) || lowerKey.includes('name')) {
        sanitized[key] = this.sanitizeName(value as string);
        continue;
      }

      // Check if field is financial data
      if (this.FINANCIAL_FIELDS.has(key) || lowerKey.includes('revenue') || lowerKey.includes('expense')) {
        sanitized[key] = this.sanitizeFinancialData(value);
        continue;
      }

      // Check if field is DISC score
      if (this.DISC_FIELDS.has(key)) {
        sanitized[key] = '[REDACTED - PII]';
        continue;
      }

      // Recursively sanitize nested objects
      if (value && typeof value === 'object') {
        sanitized[key] = this.sanitizeObject(value);
      } else {
        sanitized[key] = value;
      }
    }

    return sanitized;
  }
}
