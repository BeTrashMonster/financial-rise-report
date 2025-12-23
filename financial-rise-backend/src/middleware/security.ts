import { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';

/**
 * Security Middleware
 * Implements comprehensive security headers and protections
 */

/**
 * Content Security Policy (CSP) configuration
 * Prevents XSS, clickjacking, and other code injection attacks
 */
export const cspMiddleware = helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: [
      "'self'",
      // Allow inline scripts with nonce (should be generated per request in production)
      "'unsafe-inline'", // TODO: Replace with nonce-based approach in production
      // Allow scripts from trusted CDNs
      'https://cdn.jsdelivr.net',
      'https://unpkg.com',
    ],
    styleSrc: [
      "'self'",
      "'unsafe-inline'", // Material-UI requires inline styles
      'https://fonts.googleapis.com',
    ],
    fontSrc: [
      "'self'",
      'https://fonts.gstatic.com',
      'data:',
    ],
    imgSrc: [
      "'self'",
      'data:',
      'https:', // Allow images from HTTPS sources
      'blob:', // Allow blob URLs for generated images
    ],
    connectSrc: [
      "'self'",
      // Allow API connections
      process.env.API_URL || 'http://localhost:3000',
    ],
    frameSrc: ["'none'"], // Prevent clickjacking
    objectSrc: ["'none'"], // Prevent plugin execution
    baseUri: ["'self'"],
    formAction: ["'self'"],
    frameAncestors: ["'none'"], // X-Frame-Options alternative
    upgradeInsecureRequests: [], // Upgrade HTTP to HTTPS
  },
});

/**
 * Security headers middleware
 * Combines multiple security headers for comprehensive protection
 */
export const securityHeaders = [
  // Content Security Policy
  cspMiddleware,

  // Strict Transport Security (HSTS)
  helmet.hsts({
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true,
  }),

  // X-Frame-Options (prevent clickjacking)
  helmet.frameguard({
    action: 'deny',
  }),

  // X-Content-Type-Options (prevent MIME sniffing)
  helmet.noSniff(),

  // X-XSS-Protection (legacy XSS protection)
  helmet.xssFilter(),

  // Referrer-Policy
  helmet.referrerPolicy({
    policy: 'strict-origin-when-cross-origin',
  }),

  // Remove X-Powered-By header
  helmet.hidePoweredBy(),

  // DNS Prefetch Control
  helmet.dnsPrefetchControl({
    allow: false,
  }),

  // Expect-CT (Certificate Transparency)
  helmet.expectCt({
    enforce: true,
    maxAge: 30,
  }),

  // Permissions-Policy (formerly Feature-Policy)
  helmet.permittedCrossDomainPolicies({
    permittedPolicies: 'none',
  }),
];

/**
 * CSRF protection middleware
 * Validates CSRF tokens for state-changing requests
 */
export const csrfProtection = (req: Request, res: Response, next: NextFunction) => {
  // Skip CSRF check for safe methods
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }

  // Skip CSRF for API requests with valid JWT
  if (req.headers.authorization?.startsWith('Bearer ')) {
    return next();
  }

  // Check CSRF token
  const csrfToken = req.headers['x-csrf-token'] || req.body?._csrf;
  const sessionToken = req.session?.csrfToken;

  if (!csrfToken || csrfToken !== sessionToken) {
    return res.status(403).json({
      error: {
        code: 'CSRF_TOKEN_INVALID',
        message: 'Invalid CSRF token',
      },
    });
  }

  next();
};

/**
 * SQL Injection protection middleware
 * Validates and sanitizes input data
 */
export const sqlInjectionProtection = (req: Request, res: Response, next: NextFunction) => {
  const dangerousPatterns = [
    /(\bSELECT\b|\bUNION\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b|\bCREATE\b)/i,
    /(-{2}|\/\*|\*\/)/,
    /(;|\||&)/,
  ];

  const checkValue = (value: any): boolean => {
    if (typeof value === 'string') {
      return dangerousPatterns.some(pattern => pattern.test(value));
    }
    if (typeof value === 'object' && value !== null) {
      return Object.values(value).some(checkValue);
    }
    return false;
  };

  // Check request body
  if (req.body && checkValue(req.body)) {
    return res.status(400).json({
      error: {
        code: 'INVALID_INPUT',
        message: 'Invalid characters detected in request',
      },
    });
  }

  // Check query parameters
  if (req.query && checkValue(req.query)) {
    return res.status(400).json({
      error: {
        code: 'INVALID_INPUT',
        message: 'Invalid characters detected in query parameters',
      },
    });
  }

  next();
};

/**
 * XSS protection middleware
 * Sanitizes user input to prevent cross-site scripting
 */
export const xssProtection = (req: Request, res: Response, next: NextFunction) => {
  const sanitizeValue = (value: any): any => {
    if (typeof value === 'string') {
      return value
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;');
    }
    if (typeof value === 'object' && value !== null) {
      const sanitized: any = Array.isArray(value) ? [] : {};
      for (const key in value) {
        sanitized[key] = sanitizeValue(value[key]);
      }
      return sanitized;
    }
    return value;
  };

  // Sanitize request body (only for specific content types)
  if (req.body && req.is('application/json')) {
    req.body = sanitizeValue(req.body);
  }

  next();
};

/**
 * Request size limiter
 * Prevents DoS attacks via large payloads
 */
export const requestSizeLimiter = (maxSize: string = '10mb') => {
  return (req: Request, res: Response, next: NextFunction) => {
    const contentLength = parseInt(req.headers['content-length'] || '0');
    const maxBytes = parseSize(maxSize);

    if (contentLength > maxBytes) {
      return res.status(413).json({
        error: {
          code: 'PAYLOAD_TOO_LARGE',
          message: `Request payload too large. Maximum size: ${maxSize}`,
        },
      });
    }

    next();
  };
};

/**
 * Helper: Parse size string to bytes
 */
function parseSize(size: string): number {
  const units: { [key: string]: number } = {
    b: 1,
    kb: 1024,
    mb: 1024 * 1024,
    gb: 1024 * 1024 * 1024,
  };

  const match = size.toLowerCase().match(/^(\d+(?:\.\d+)?)\s*([kmg]?b)$/);
  if (!match) return 10 * 1024 * 1024; // Default 10MB

  const value = parseFloat(match[1]);
  const unit = match[2];

  return value * units[unit];
}
