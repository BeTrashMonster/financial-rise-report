/**
 * Security Headers Configuration (Work Stream 58 - HIGH-009)
 *
 * Comprehensive security headers to protect against:
 * - XSS attacks (Content Security Policy)
 * - Clickjacking (X-Frame-Options)
 * - MITM attacks (HSTS)
 * - Information leakage (Referrer-Policy)
 * - Unauthorized browser features (Permissions-Policy)
 *
 * Target: securityheaders.com grade A+
 *
 * Security Requirements:
 * - OWASP: A05:2021 - Security Misconfiguration
 * - CWE: CWE-16 - Configuration
 *
 * Reference: SECURITY-AUDIT-REPORT.md Lines 1189-1252
 */

import { INestApplication } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';

/**
 * Configure comprehensive security headers using Helmet
 *
 * This function configures Helmet with enhanced security settings
 * to achieve A+ grade on securityheaders.com
 *
 * @param app - NestJS application instance
 */
export function configureSecurityHeaders(app: INestApplication): void {
  // Apply Helmet with custom configuration
  app.use(
    helmet({
      // Content Security Policy - Prevents XSS attacks
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"], // No unsafe-inline, no unsafe-eval
          styleSrc: ["'self'", "'unsafe-inline'"], // unsafe-inline required for Material-UI
          imgSrc: ["'self'", 'data:', 'https:'],
          connectSrc: ["'self'"], // API calls
          fontSrc: ["'self'"],
          objectSrc: ["'none'"], // Block Flash, Java applets
          mediaSrc: ["'self'"],
          frameSrc: ["'none'"], // Block all iframes
          baseUri: ["'self'"], // Prevent base tag injection
          formAction: ["'self'"], // Prevent form hijacking
          upgradeInsecureRequests: [], // Upgrade HTTP to HTTPS
        },
      },

      // HTTP Strict Transport Security - Forces HTTPS
      hsts: {
        maxAge: 31536000, // 1 year in seconds
        includeSubDomains: true,
        preload: true, // Enable HSTS preload
      },

      // X-Frame-Options - Prevents clickjacking
      frameguard: {
        action: 'deny', // Stricter than SAMEORIGIN
      },

      // X-Content-Type-Options - Prevents MIME sniffing
      noSniff: true,

      // Referrer-Policy - Privacy protection
      referrerPolicy: {
        policy: 'strict-origin-when-cross-origin',
      },

      // X-XSS-Protection - Disable legacy XSS filter (CSP is better)
      xssFilter: false, // This will set X-XSS-Protection: 0

      // Cross-Origin-Embedder-Policy
      crossOriginEmbedderPolicy: true,

      // Cross-Origin-Opener-Policy
      crossOriginOpenerPolicy: { policy: 'same-origin' },

      // Cross-Origin-Resource-Policy
      crossOriginResourcePolicy: { policy: 'same-origin' },
    }),
  );

  // Add additional security headers not covered by Helmet defaults
  app.use((req: Request, res: Response, next: NextFunction) => {
    // Permissions-Policy (replaces Feature-Policy)
    res.setHeader(
      'Permissions-Policy',
      'geolocation=(), microphone=(), camera=(), payment=(), usb=()',
    );

    // Explicitly set X-XSS-Protection to 0 (disabled)
    // Modern best practice: disable XSS filter in favor of CSP
    // See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection
    res.setHeader('X-XSS-Protection', '0');

    next();
  });
}

/**
 * Security Headers Documentation
 *
 * 1. Content-Security-Policy (CSP)
 *    - Prevents XSS by restricting resource sources
 *    - default-src 'self': Only load resources from same origin
 *    - script-src 'self': No inline scripts, no eval()
 *    - style-src 'self' 'unsafe-inline': Allow inline styles for Material-UI
 *    - object-src 'none': Block Flash, Java applets
 *    - frame-src 'none': Prevent iframe embedding
 *
 * 2. HTTP Strict Transport Security (HSTS)
 *    - Forces HTTPS connections
 *    - max-age=31536000: 1 year validity
 *    - includeSubDomains: Apply to all subdomains
 *    - preload: Enable HSTS preload list
 *
 * 3. X-Frame-Options
 *    - Prevents clickjacking attacks
 *    - DENY: Cannot be embedded in any iframe
 *
 * 4. X-Content-Type-Options
 *    - Prevents MIME type sniffing
 *    - nosniff: Browser must respect declared Content-Type
 *
 * 5. Referrer-Policy
 *    - Controls referrer information sent
 *    - strict-origin-when-cross-origin: Send origin on cross-origin, full URL on same-origin
 *
 * 6. Permissions-Policy
 *    - Restricts browser features
 *    - Disables: geolocation, microphone, camera, payment, USB
 *
 * 7. X-XSS-Protection
 *    - Set to 0 (disabled)
 *    - Modern security: CSP is the proper XSS defense
 *    - Legacy XSS filter can create vulnerabilities
 *
 * Security Grade Target: A+ on securityheaders.com
 *
 * Testing:
 * - All security headers are tested in security-headers.spec.ts
 * - Tests verify header presence, values, and configuration
 * - E2E tests ensure headers don't break application functionality
 */
