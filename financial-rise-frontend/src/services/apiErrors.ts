import { AxiosError } from 'axios';

/**
 * API Error Handling
 * Standardized error handling for Financial RISE API
 * Implements error format from API-CONTRACT.md Section 8
 */

/**
 * API Error interface matching backend error format
 */
export interface ApiError {
  statusCode: number;
  message: string;
  error: string;
  details?: Array<{
    field: string;
    message: string;
    value?: any;
    constraint?: string;
  }>;
}

/**
 * Custom error class for API errors
 */
export class ApiException extends Error {
  public statusCode: number;
  public error: string;
  public details?: Array<{
    field: string;
    message: string;
    value?: any;
    constraint?: string;
  }>;

  constructor(statusCode: number, message: string, error: string, details?: any[]) {
    super(message);
    this.name = 'ApiException';
    this.statusCode = statusCode;
    this.error = error;
    this.details = details;

    // Maintains proper stack trace for where error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, ApiException);
    }
  }

  /**
   * Get user-friendly error message
   */
  getUserMessage(): string {
    // For validation errors with details, return first field error
    if (this.details && this.details.length > 0) {
      return this.details[0].message;
    }
    return this.message;
  }

  /**
   * Get all validation errors
   */
  getValidationErrors(): Record<string, string> {
    if (!this.details) return {};

    return this.details.reduce(
      (acc, detail) => {
        acc[detail.field] = detail.message;
        return acc;
      },
      {} as Record<string, string>
    );
  }

  /**
   * Check if error is a specific type
   */
  is(statusCode: number): boolean {
    return this.statusCode === statusCode;
  }

  /**
   * Check if error is a validation error
   */
  isValidationError(): boolean {
    return this.statusCode === 400 && this.details && this.details.length > 0;
  }

  /**
   * Check if error is an authentication error
   */
  isAuthError(): boolean {
    return this.statusCode === 401 || this.statusCode === 403;
  }

  /**
   * Check if error is a not found error
   */
  isNotFound(): boolean {
    return this.statusCode === 404;
  }

  /**
   * Check if error is a conflict error
   */
  isConflict(): boolean {
    return this.statusCode === 409;
  }

  /**
   * Check if error is a rate limit error
   */
  isRateLimited(): boolean {
    return this.statusCode === 429;
  }

  /**
   * Check if error is a server error
   */
  isServerError(): boolean {
    return this.statusCode >= 500;
  }
}

/**
 * Handle Axios errors and convert to ApiException
 */
export function handleApiError(error: unknown): ApiException {
  // Handle Axios errors
  if (error && typeof error === 'object' && 'isAxiosError' in error) {
    const axiosError = error as AxiosError<ApiError>;

    if (axiosError.response) {
      // Server responded with error status
      const data = axiosError.response.data;

      return new ApiException(
        data.statusCode || axiosError.response.status,
        data.message || 'An error occurred',
        data.error || axiosError.response.statusText,
        data.details
      );
    } else if (axiosError.request) {
      // Request was made but no response received
      return new ApiException(
        503,
        'Unable to reach the server. Please check your internet connection.',
        'Network Error'
      );
    } else {
      // Error setting up the request
      return new ApiException(500, axiosError.message || 'Request setup failed', 'Request Error');
    }
  }

  // Handle other errors
  if (error instanceof Error) {
    return new ApiException(500, error.message, 'Unknown Error');
  }

  // Fallback for unknown error types
  return new ApiException(500, 'An unexpected error occurred', 'Unknown Error');
}

/**
 * Error message helpers for common scenarios
 */
export const ErrorMessages = {
  // Authentication
  INVALID_CREDENTIALS: 'Invalid email or password',
  ACCOUNT_LOCKED: 'Account locked due to too many failed login attempts',
  SESSION_EXPIRED: 'Your session has expired. Please log in again.',
  UNAUTHORIZED: 'You are not authorized to perform this action',

  // Validation
  REQUIRED_FIELD: 'This field is required',
  INVALID_EMAIL: 'Please enter a valid email address',
  PASSWORD_TOO_WEAK: 'Password does not meet security requirements',
  INVALID_FORMAT: 'Invalid format',

  // Resources
  NOT_FOUND: 'The requested resource was not found',
  ALREADY_EXISTS: 'A resource with this information already exists',

  // Network
  NETWORK_ERROR: 'Unable to connect to the server',
  TIMEOUT: 'Request timed out. Please try again.',
  SERVER_ERROR: 'A server error occurred. Please try again later.',

  // Rate limiting
  RATE_LIMITED: 'Too many requests. Please wait a moment and try again.',

  // Generic
  UNKNOWN_ERROR: 'An unexpected error occurred',
};

/**
 * Get user-friendly error message based on status code
 */
export function getErrorMessage(error: ApiException): string {
  // Use specific message if available
  if (error.message && error.message !== 'An error occurred') {
    return error.message;
  }

  // Fallback to status code-based messages
  switch (error.statusCode) {
    case 400:
      return 'Invalid request. Please check your input.';
    case 401:
      return ErrorMessages.SESSION_EXPIRED;
    case 403:
      return ErrorMessages.UNAUTHORIZED;
    case 404:
      return ErrorMessages.NOT_FOUND;
    case 409:
      return ErrorMessages.ALREADY_EXISTS;
    case 423:
      return ErrorMessages.ACCOUNT_LOCKED;
    case 429:
      return ErrorMessages.RATE_LIMITED;
    case 500:
    case 502:
    case 503:
    case 504:
      return ErrorMessages.SERVER_ERROR;
    default:
      return ErrorMessages.UNKNOWN_ERROR;
  }
}

/**
 * Log error to console (can be extended to send to error tracking service)
 */
export function logError(error: ApiException, context?: string) {
  const errorInfo = {
    context,
    statusCode: error.statusCode,
    error: error.error,
    message: error.message,
    details: error.details,
    timestamp: new Date().toISOString(),
  };

  // In development, log full error
  if (import.meta.env.DEV) {
    console.error('[API Error]', errorInfo);
  }

  // In production, you might want to send to an error tracking service
  // like Sentry, LogRocket, etc.
  // Example:
  // if (import.meta.env.PROD) {
  //   Sentry.captureException(error, { extra: errorInfo });
  // }
}

/**
 * Create a toast-friendly error message
 */
export function getToastError(error: ApiException): {
  title: string;
  message: string;
  variant: 'error' | 'warning';
} {
  // For validation errors, show first validation message
  if (error.isValidationError()) {
    return {
      title: 'Validation Error',
      message: error.getUserMessage(),
      variant: 'error',
    };
  }

  // For authentication errors
  if (error.isAuthError()) {
    return {
      title: 'Authentication Error',
      message: getErrorMessage(error),
      variant: 'error',
    };
  }

  // For not found errors
  if (error.isNotFound()) {
    return {
      title: 'Not Found',
      message: error.message,
      variant: 'warning',
    };
  }

  // For server errors
  if (error.isServerError()) {
    return {
      title: 'Server Error',
      message: ErrorMessages.SERVER_ERROR,
      variant: 'error',
    };
  }

  // For rate limiting
  if (error.isRateLimited()) {
    return {
      title: 'Too Many Requests',
      message: ErrorMessages.RATE_LIMITED,
      variant: 'warning',
    };
  }

  // Default error
  return {
    title: 'Error',
    message: getErrorMessage(error),
    variant: 'error',
  };
}

export default {
  ApiException,
  handleApiError,
  getErrorMessage,
  logError,
  getToastError,
  ErrorMessages,
};
