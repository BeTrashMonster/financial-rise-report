import { PIISafeLogger } from './pii-safe-logger';
import { LogSanitizer } from './log-sanitizer';

describe('PIISafeLogger', () => {
  let logger: PIISafeLogger;

  beforeEach(() => {
    logger = new PIISafeLogger('TestContext');
    // Spy on console methods to verify sanitization
    jest.spyOn(console, 'log').mockImplementation();
    jest.spyOn(console, 'error').mockImplementation();
    jest.spyOn(console, 'warn').mockImplementation();
    jest.spyOn(console, 'debug').mockImplementation();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('log', () => {
    it('should sanitize PII in string messages', () => {
      const message = 'User john@example.com logged in';
      logger.log(message);

      // Verify console.log was called with sanitized message
      expect(console.log).toHaveBeenCalled();
      const callArgs = (console.log as jest.Mock).mock.calls[0];
      const loggedMessage = callArgs.join(' ');

      expect(loggedMessage).toContain('***@example.com');
      expect(loggedMessage).not.toContain('john@example.com');
    });

    it('should sanitize PII in object messages', () => {
      const data = {
        email: 'user@example.com',
        password: 'SecureP@ss123',
        phone: '555-123-4567',
      };

      logger.log('User data:', data);

      expect(console.log).toHaveBeenCalled();
      const callArgs = (console.log as jest.Mock).mock.calls[0];

      // Check that the logged data is sanitized
      const loggedData = callArgs[1];
      expect(loggedData.email).toBe('***@example.com');
      expect(loggedData.password).toBe('[REDACTED - PASSWORD]');
      expect(loggedData.phone).toBe('***-***-4567');
    });

    it('should handle multiple arguments with mixed types', () => {
      logger.log('User', { email: 'test@example.com' }, 'called from', '192.168.1.100');

      expect(console.log).toHaveBeenCalled();
      const callArgs = (console.log as jest.Mock).mock.calls[0];

      expect(callArgs[1].email).toBe('***@example.com');
      expect(callArgs[3]).toBe('192.*.*.*');
    });
  });

  describe('error', () => {
    it('should sanitize PII in error messages', () => {
      const error = new Error('Failed to process user john@example.com');
      logger.error(error.message);

      expect(console.error).toHaveBeenCalled();
      const callArgs = (console.error as jest.Mock).mock.calls[0];
      const loggedMessage = callArgs.join(' ');

      expect(loggedMessage).toContain('***@example.com');
      expect(loggedMessage).not.toContain('john@example.com');
    });

    it('should sanitize Error objects', () => {
      const error = new Error('Database error');
      const context = {
        email: 'admin@company.com',
        query: 'SELECT * FROM users WHERE email = "admin@company.com"',
      };

      logger.error(error.message, context);

      expect(console.error).toHaveBeenCalled();
      const callArgs = (console.error as jest.Mock).mock.calls[0];

      expect(callArgs[1].email).toBe('***@company.com');
    });

    it('should handle stack traces without exposing PII', () => {
      const error = new Error('Auth failed for user@example.com');
      logger.error(error.stack || error.message);

      expect(console.error).toHaveBeenCalled();
      const callArgs = (console.error as jest.Mock).mock.calls[0];
      const loggedMessage = callArgs.join(' ');

      expect(loggedMessage).not.toContain('user@example.com');
      expect(loggedMessage).toContain('***@example.com');
    });
  });

  describe('warn', () => {
    it('should sanitize PII in warning messages', () => {
      logger.warn('Account locked for phone 555-123-4567');

      expect(console.warn).toHaveBeenCalled();
      const callArgs = (console.warn as jest.Mock).mock.calls[0];
      const loggedMessage = callArgs.join(' ');

      expect(loggedMessage).toContain('***-***-4567');
      expect(loggedMessage).not.toContain('555-123-4567');
    });

    it('should sanitize PII in warning context objects', () => {
      const context = {
        userId: '123',
        ssn: '123-45-6789',
        reason: 'invalid_credentials',
      };

      logger.warn('Security alert', context);

      expect(console.warn).toHaveBeenCalled();
      const callArgs = (console.warn as jest.Mock).mock.calls[0];

      expect(callArgs[1].userId).toBe('123');
      expect(callArgs[1].ssn).toBe('[REDACTED - SSN]');
    });
  });

  describe('debug', () => {
    it('should sanitize PII in debug messages', () => {
      logger.debug('Credit card processed: 4532-1234-5678-9010');

      expect(console.debug).toHaveBeenCalled();
      const callArgs = (console.debug as jest.Mock).mock.calls[0];
      const loggedMessage = callArgs.join(' ');

      expect(loggedMessage).toContain('****-****-****-9010');
      expect(loggedMessage).not.toContain('4532-1234-5678-9010');
    });

    it('should sanitize financial data in debug context', () => {
      const context = {
        clientName: 'John Doe',
        revenue: 500000,
        ipAddress: '192.168.1.50',
      };

      logger.debug('Processing assessment', context);

      expect(console.debug).toHaveBeenCalled();
      const callArgs = (console.debug as jest.Mock).mock.calls[0];

      expect(callArgs[1].clientName).toBe('J***');
      expect(callArgs[1].revenue).toBe('[REDACTED - FINANCIAL]');
      expect(callArgs[1].ipAddress).toBe('192.*.*.*');
    });
  });

  describe('verbose', () => {
    it('should sanitize PII in verbose messages', () => {
      logger.verbose('Request details: IP 10.0.0.5, User: alice@example.com');

      // verbose uses console.log internally
      expect(console.log).toHaveBeenCalled();
      const callArgs = (console.log as jest.Mock).mock.calls[0];
      const loggedMessage = callArgs.join(' ');

      expect(loggedMessage).toContain('10.*.*.*');
      expect(loggedMessage).toContain('***@example.com');
    });
  });

  describe('integration scenarios', () => {
    it('should sanitize authentication flow logs', () => {
      const loginData = {
        email: 'user@company.com',
        password: 'P@ssw0rd!',
        ipAddress: '192.168.1.100',
        timestamp: '2025-12-28T10:00:00Z',
      };

      logger.log('Login attempt', loginData);

      expect(console.log).toHaveBeenCalled();
      const callArgs = (console.log as jest.Mock).mock.calls[0];
      const sanitized = callArgs[1];

      expect(sanitized.email).toBe('***@company.com');
      expect(sanitized.password).toBe('[REDACTED - PASSWORD]');
      expect(sanitized.ipAddress).toBe('192.*.*.*');
      expect(sanitized.timestamp).toBe('2025-12-28T10:00:00Z'); // Timestamps should not be sanitized
    });

    it('should sanitize DISC calculation logs', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      const discData = {
        assessmentId: 'assess-123',
        scores: { D: 75, I: 60, S: 45, C: 80 },
        calculatedAt: '2025-12-28T10:00:00Z',
      };

      logger.debug('DISC calculation complete', discData);

      expect(console.debug).toHaveBeenCalled();
      const callArgs = (console.debug as jest.Mock).mock.calls[0];
      const sanitized = callArgs[1];

      expect(sanitized.assessmentId).toBe('assess-123');
      expect(sanitized.scores).toBe('[REDACTED - PII]');

      process.env.NODE_ENV = originalEnv;
    });

    it('should sanitize payment processing logs', () => {
      const paymentData = {
        orderId: 'order-456',
        cardNumber: '4532123456789010',
        amount: 1500,
        customerEmail: 'customer@shop.com',
      };

      logger.log('Processing payment', paymentData);

      expect(console.log).toHaveBeenCalled();
      const callArgs = (console.log as jest.Mock).mock.calls[0];
      const sanitized = callArgs[1];

      expect(sanitized.orderId).toBe('order-456');
      expect(sanitized.cardNumber).toBe('****-****-****-9010');
      expect(sanitized.amount).toBe('[REDACTED - FINANCIAL]');
      expect(sanitized.customerEmail).toBe('***@shop.com');
    });

    it('should handle complex nested objects with multiple PII types', () => {
      const complexData = {
        user: {
          name: 'Jane Smith',
          email: 'jane@company.com',
          phone: '(555) 987-6543',
        },
        billing: {
          address: '123 Main St, Portland, OR',
          cardNumber: '371449635398431', // Amex
        },
        metadata: {
          ipAddress: '10.0.0.1',
          ssn: '987-65-4321',
        },
      };

      logger.log('User profile update', complexData);

      expect(console.log).toHaveBeenCalled();
      const callArgs = (console.log as jest.Mock).mock.calls[0];
      const sanitized = callArgs[1];

      expect(sanitized.user.name).toBe('J***');
      expect(sanitized.user.email).toBe('***@company.com');
      expect(sanitized.user.phone).toBe('***-***-6543');
      expect(sanitized.billing.address).toBe('[REDACTED - ADDRESS]');
      expect(sanitized.billing.cardNumber).toBe('****-****-***-8431');
      expect(sanitized.metadata.ipAddress).toBe('10.*.*.*');
      expect(sanitized.metadata.ssn).toBe('[REDACTED - SSN]');
    });
  });

  describe('setContext', () => {
    it('should update logger context', () => {
      logger.setContext('NewContext');
      logger.log('Test message');

      expect(console.log).toHaveBeenCalled();
      const callArgs = (console.log as jest.Mock).mock.calls[0];

      // Context should be included in the log output
      expect(callArgs[0]).toContain('NewContext');
    });
  });

  describe('edge cases', () => {
    it('should handle null and undefined arguments', () => {
      logger.log('Test', null, undefined);

      expect(console.log).toHaveBeenCalled();
      // Should not throw errors
    });

    it('should handle empty objects', () => {
      logger.log('Empty object', {});

      expect(console.log).toHaveBeenCalled();
      const callArgs = (console.log as jest.Mock).mock.calls[0];
      expect(callArgs[1]).toEqual({});
    });

    it('should handle circular references gracefully', () => {
      const circular: any = { id: '123' };
      circular.self = circular;

      // Should not throw on circular references
      expect(() => logger.log('Circular', circular)).not.toThrow();
    });

    it('should preserve non-PII data integrity', () => {
      const data = {
        id: '12345',
        status: 'active',
        count: 42,
        enabled: true,
        items: ['item1', 'item2'],
        timestamp: new Date('2025-12-28T10:00:00Z'),
      };

      logger.log('Non-PII data', data);

      expect(console.log).toHaveBeenCalled();
      const callArgs = (console.log as jest.Mock).mock.calls[0];
      const logged = callArgs[1];

      expect(logged.id).toBe('12345');
      expect(logged.status).toBe('active');
      expect(logged.count).toBe(42);
      expect(logged.enabled).toBe(true);
      expect(logged.items).toEqual(['item1', 'item2']);
    });
  });
});
