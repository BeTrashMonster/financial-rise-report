/**
 * Validation Middleware
 * Higher-order function to validate request data using Zod schemas
 */

import { Request, Response, NextFunction } from 'express';
import { z, ZodError } from 'zod';
import { AppError } from './errorHandler';
import { ERROR_CODES } from '../constants';

/**
 * Type of data to validate
 */
export type ValidationSource = 'body' | 'query' | 'params';

/**
 * Create validation middleware for a Zod schema
 */
export function validate<T extends z.ZodTypeAny>(schema: T, source: ValidationSource = 'body') {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      // Get data from specified source
      const data = req[source];

      // Validate and parse data
      const validated = await schema.parseAsync(data);

      // Replace request data with validated data
      (req as any)[source] = validated;

      next();
    } catch (error) {
      if (error instanceof ZodError) {
        // Transform Zod errors to our error format
        const details = error.errors.map((err) => ({
          field: err.path.join('.'),
          message: err.message,
        }));

        return next(
          new AppError(
            'Validation failed',
            400,
            ERROR_CODES.VALIDATION_ERROR,
            details
          )
        );
      }

      // Unexpected error
      next(error);
    }
  };
}

/**
 * Convenience functions for common validation sources
 */
export const validateBody = <T extends z.ZodTypeAny>(schema: T) => validate(schema, 'body');
export const validateQuery = <T extends z.ZodTypeAny>(schema: T) => validate(schema, 'query');
export const validateParams = <T extends z.ZodTypeAny>(schema: T) => validate(schema, 'params');
