/**
 * Request Size Limits Configuration
 * Work Stream 64: Request Size Limits & DoS Prevention (MED-003)
 *
 * Configures payload size limits to prevent DoS attacks through large requests.
 * Implements per-endpoint limits for different use cases.
 *
 * Security: OWASP A04:2021, CWE-400 (Uncontrolled Resource Consumption)
 */

import { INestApplication } from '@nestjs/common';
import { json, urlencoded, Request, Response, NextFunction } from 'express';

/**
 * Request size limit configuration per endpoint pattern
 */
export interface RequestSizeLimitConfig {
  /** Endpoint pattern (regex or string) */
  pattern: string | RegExp;
  /** Size limit (e.g., '1mb', '5mb', '10mb') */
  limit: string;
  /** Description for monitoring/logging */
  description: string;
}

/**
 * Predefined endpoint size limits
 * Authentication endpoints have stricter limits
 * Assessment/report endpoints may need larger payloads
 */
export const ENDPOINT_SIZE_LIMITS: RequestSizeLimitConfig[] = [
  {
    pattern: /^\/api\/v1\/auth\/(register|login|forgot-password|reset-password)/,
    limit: '1mb',
    description: 'Authentication endpoints (strict limit for security)',
  },
  {
    pattern: /^\/api\/v1\/assessments\/[^/]+\/responses/,
    limit: '5mb',
    description: 'Assessment response submissions (larger payloads allowed)',
  },
  {
    pattern: /^\/api\/v1\/reports\//,
    limit: '5mb',
    description: 'Report generation endpoints',
  },
];

/**
 * Default size limits for all endpoints
 */
export const DEFAULT_SIZE_LIMITS = {
  json: '10mb',
  urlencoded: '10mb',
} as const;

/**
 * Get size limit for a specific request path
 *
 * @param path - Request path to check
 * @returns Size limit string (e.g., '1mb', '10mb')
 */
export function getSizeLimitForPath(path: string): string {
  for (const config of ENDPOINT_SIZE_LIMITS) {
    const pattern = typeof config.pattern === 'string'
      ? new RegExp(config.pattern)
      : config.pattern;

    if (pattern.test(path)) {
      return config.limit;
    }
  }

  return DEFAULT_SIZE_LIMITS.json;
}

/**
 * Request size monitoring middleware
 * Logs request sizes for analysis and DoS detection
 *
 * @param req - Express request
 * @param res - Express response
 * @param next - Next middleware
 */
export function requestSizeMonitoring(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const contentLength = req.get('content-length');

  if (contentLength) {
    const sizeInBytes = parseInt(contentLength, 10);
    const sizeInMB = (sizeInBytes / (1024 * 1024)).toFixed(2);

    // Log large requests (>5MB) for monitoring
    if (sizeInBytes > 5 * 1024 * 1024) {
      console.warn(
        `[Request Size Monitor] Large request detected: ${req.method} ${req.path} - ${sizeInMB}MB`,
      );
    }

    // Attach size metadata to request for later analysis
    (req as any).requestSizeBytes = sizeInBytes;
    (req as any).requestSizeMB = parseFloat(sizeInMB);
  }

  next();
}

/**
 * Create per-endpoint size limit middleware
 * Dynamically adjusts body parser limits based on endpoint
 *
 * @param config - Endpoint size limit configuration
 * @returns Express middleware
 */
export function createEndpointSizeLimitMiddleware(
  config: RequestSizeLimitConfig,
) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const pattern = typeof config.pattern === 'string'
      ? new RegExp(config.pattern)
      : config.pattern;

    if (pattern.test(req.path)) {
      // Apply custom size limits for this endpoint
      json({ limit: config.limit })(req, res, (err) => {
        if (err) {
          return next(err);
        }

        urlencoded({ extended: true, limit: config.limit })(req, res, next);
      });
    } else {
      next();
    }
  };
}

/**
 * Configure request size limits for the NestJS application
 *
 * Features:
 * - Default 10MB limit for all endpoints
 * - Per-endpoint custom limits (1MB for auth, 5MB for assessments)
 * - Request size monitoring and logging
 * - DoS attack prevention
 *
 * @param app - NestJS application instance
 */
export function configureRequestSizeLimits(app: INestApplication): void {
  // Apply default size limits first
  // These are overridden by per-endpoint limits if configured
  app.use(json({ limit: DEFAULT_SIZE_LIMITS.json }));
  app.use(urlencoded({ extended: true, limit: DEFAULT_SIZE_LIMITS.urlencoded }));

  // Apply per-endpoint size limit middlewares
  for (const config of ENDPOINT_SIZE_LIMITS) {
    app.use(createEndpointSizeLimitMiddleware(config));
  }

  // Add request size monitoring
  app.use(requestSizeMonitoring);

  console.log('🛡️  Request Size Limits: CONFIGURED');
  console.log(`   - Default JSON limit: ${DEFAULT_SIZE_LIMITS.json}`);
  console.log(`   - Default URL-encoded limit: ${DEFAULT_SIZE_LIMITS.urlencoded}`);
  console.log(`   - Custom endpoint limits: ${ENDPOINT_SIZE_LIMITS.length} configured`);

  for (const config of ENDPOINT_SIZE_LIMITS) {
    console.log(`     • ${config.description}: ${config.limit}`);
  }
}

/**
 * Error handler for payload too large errors
 * Provides consistent error responses for oversized payloads
 *
 * @param err - Error object
 * @param req - Express request
 * @param res - Express response
 * @param next - Next middleware
 */
export function payloadTooLargeErrorHandler(
  err: any,
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  if (err.type === 'entity.too.large' || err.status === 413) {
    const limit = getSizeLimitForPath(req.path);

    res.status(413).json({
      statusCode: 413,
      error: 'Payload Too Large',
      message: `Request entity too large. Maximum allowed size is ${limit}.`,
      path: req.path,
      timestamp: new Date().toISOString(),
    });

    // Log the attempt for security monitoring
    console.warn(
      `[DoS Prevention] Rejected oversized request: ${req.method} ${req.path} - exceeds ${limit}`,
    );
  } else {
    next(err);
  }
}
