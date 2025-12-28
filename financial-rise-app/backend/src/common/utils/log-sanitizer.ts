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

  // Phone number field names
  private static readonly PHONE_FIELDS = new Set([
    'phone',
    'phoneNumber',
    'phone_number',
    'mobile',
    'mobileNumber',
    'mobile_number',
    'contactNumber',
    'contact_number',
    'telephone',
  ]);

  // SSN field names
  private static readonly SSN_FIELDS = new Set([
    'ssn',
    'socialSecurityNumber',
    'social_security_number',
    'taxId',
    'tax_id',
  ]);

  // Credit card field names
  private static readonly CREDIT_CARD_FIELDS = new Set([
    'creditCard',
    'credit_card',
    'cardNumber',
    'card_number',
    'paymentCard',
    'payment_card',
  ]);

  // IP address field names
  private static readonly IP_FIELDS = new Set([
    'ip',
    'ipAddress',
    'ip_address',
    'clientIp',
    'client_ip',
    'remoteAddress',
    'remote_address',
  ]);

  // Address field names
  private static readonly ADDRESS_FIELDS = new Set([
    'address',
    'street',
    'streetAddress',
    'street_address',
    'mailingAddress',
    'mailing_address',
    'billingAddress',
    'billing_address',
    'shippingAddress',
    'shipping_address',
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
   * Sanitize phone number - show only last 4 digits
   * @param phone - Phone number to sanitize
   * @returns Sanitized phone number
   */
  static sanitizePhoneNumber(phone: string | null | undefined): string {
    if (!phone || typeof phone !== 'string') {
      return '[REDACTED]';
    }

    // Extract only digits
    const digits = phone.replace(/\D/g, '');

    // Validate phone number length (should be at least 7 digits)
    if (digits.length < 7) {
      return '[REDACTED]';
    }

    // Show only last 4 digits
    const lastFour = digits.slice(-4);
    return `***-***-${lastFour}`;
  }

  /**
   * Sanitize SSN - complete redaction
   * @param ssn - Social Security Number to redact
   * @returns Redacted placeholder
   */
  static sanitizeSSN(ssn: string | null | undefined): string {
    return '[REDACTED - SSN]';
  }

  /**
   * Sanitize credit card number - show only last 4 digits
   * @param cardNumber - Credit card number to sanitize
   * @returns Sanitized credit card number
   */
  static sanitizeCreditCard(cardNumber: string | null | undefined): string {
    if (!cardNumber || typeof cardNumber !== 'string') {
      return '[REDACTED]';
    }

    // Extract only digits
    const digits = cardNumber.replace(/\D/g, '');

    // Validate credit card length (typically 15-16 digits)
    if (digits.length < 13 || digits.length > 19) {
      return '[REDACTED]';
    }

    // Show only last 4 digits
    const lastFour = digits.slice(-4);

    // Format based on card length
    if (digits.length === 15) {
      // American Express format
      return `****-****-***-${lastFour}`;
    } else {
      // Visa, Mastercard, Discover format
      return `****-****-****-${lastFour}`;
    }
  }

  /**
   * Sanitize IP address - mask last 3 octets for IPv4, redact IPv6
   * @param ip - IP address to sanitize
   * @returns Sanitized IP address
   */
  static sanitizeIPAddress(ip: string | null | undefined): string {
    if (!ip || typeof ip !== 'string') {
      return '[REDACTED]';
    }

    // Check if IPv6
    if (ip.includes(':')) {
      return '[REDACTED - IPv6]';
    }

    // Check if IPv4
    const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
    const match = ip.match(ipv4Regex);

    if (match) {
      // Show only first octet
      return `${match[1]}.*.*.*`;
    }

    return '[REDACTED]';
  }

  /**
   * Sanitize physical address - complete redaction
   * @param address - Physical address to redact
   * @returns Redacted placeholder
   */
  static sanitizeAddress(address: string | null | undefined): string {
    return '[REDACTED - ADDRESS]';
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

    // Redact SSN patterns (XXX-XX-XXXX)
    const ssnRegex = /\b\d{3}-\d{2}-\d{4}\b/g;
    sanitized = sanitized.replace(ssnRegex, '[REDACTED - SSN]');

    // Redact SSN without dashes (9 consecutive digits)
    const ssnNoHyphenRegex = /\b\d{9}\b/g;
    sanitized = sanitized.replace(ssnNoHyphenRegex, '[REDACTED - SSN]');

    // Redact credit card numbers (13-19 digits with optional dashes/spaces)
    const creditCardRegex = /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g;
    sanitized = sanitized.replace(creditCardRegex, (card) => this.sanitizeCreditCard(card));

    // Redact Amex format (15 digits)
    const amexRegex = /\b\d{4}[\s-]?\d{6}[\s-]?\d{5}\b/g;
    sanitized = sanitized.replace(amexRegex, (card) => this.sanitizeCreditCard(card));

    // Redact phone numbers (various formats)
    const phoneRegex = /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g;
    sanitized = sanitized.replace(phoneRegex, (phone) => this.sanitizePhoneNumber(phone));

    // Redact IPv4 addresses
    const ipv4Regex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;
    sanitized = sanitized.replace(ipv4Regex, (ip) => this.sanitizeIPAddress(ip));

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

      // Check if field is a phone number
      if (this.PHONE_FIELDS.has(key) || lowerKey.includes('phone') || lowerKey.includes('mobile') || lowerKey.includes('telephone')) {
        sanitized[key] = this.sanitizePhoneNumber(value as string);
        continue;
      }

      // Check if field is SSN
      if (this.SSN_FIELDS.has(key) || lowerKey.includes('ssn') || lowerKey.includes('social')) {
        sanitized[key] = this.sanitizeSSN(value as string);
        continue;
      }

      // Check if field is credit card
      if (this.CREDIT_CARD_FIELDS.has(key) || lowerKey.includes('card')) {
        sanitized[key] = this.sanitizeCreditCard(value as string);
        continue;
      }

      // Check if field is IP address
      if (this.IP_FIELDS.has(key) || lowerKey.includes('ip')) {
        sanitized[key] = this.sanitizeIPAddress(value as string);
        continue;
      }

      // Check if field is an address
      if (this.ADDRESS_FIELDS.has(key) || lowerKey.includes('address') || lowerKey.includes('street')) {
        sanitized[key] = this.sanitizeAddress(value as string);
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
