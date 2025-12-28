/**
 * Environment Configuration
 * Validates and exports all required environment variables
 * Fails fast on startup if required variables are missing
 */

import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

/**
 * Required environment variables
 */
const REQUIRED_ENV_VARS = [
  'JWT_SECRET',
  'DATABASE_URL',
] as const;

/**
 * Optional environment variables with defaults
 */
const OPTIONAL_ENV_VARS = {
  NODE_ENV: 'development',
  PORT: '3000',
  API_VERSION: 'v1',
  CORS_ORIGIN: 'http://localhost:3001',
  RATE_LIMIT_WINDOW_MS: '60000',
  RATE_LIMIT_MAX_REQUESTS: '100',
  LOG_LEVEL: 'info',
  BCRYPT_ROUNDS: '12',
  DATABASE_POOL_MIN: '5',
  DATABASE_POOL_MAX: '20',
} as const;

/**
 * Validate required environment variables
 */
function validateEnv(): void {
  const missing: string[] = [];

  for (const envVar of REQUIRED_ENV_VARS) {
    if (!process.env[envVar]) {
      missing.push(envVar);
    }
  }

  if (missing.length > 0) {
    console.error('❌ FATAL: Missing required environment variables:');
    missing.forEach(envVar => {
      console.error(`   - ${envVar}`);
    });
    console.error('\nPlease set these variables in your .env file or environment.');
    console.error('See .env.example for reference.\n');
    process.exit(1);
  }
}

/**
 * Get environment variable with default fallback
 */
function getEnvVar<K extends keyof typeof OPTIONAL_ENV_VARS>(
  key: K,
  defaultValue: typeof OPTIONAL_ENV_VARS[K]
): string {
  return process.env[key] || defaultValue;
}

// Validate on module load (skip in test environment)
if (process.env.NODE_ENV !== 'test') {
  validateEnv();
}

/**
 * Validated and typed configuration object
 */
export const config = {
  // Environment
  nodeEnv: getEnvVar('NODE_ENV', 'development'),
  port: parseInt(getEnvVar('PORT', '3000'), 10),
  apiVersion: getEnvVar('API_VERSION', 'v1'),

  // Security (guaranteed to exist after validation)
  jwtSecret: process.env.JWT_SECRET!,
  bcryptRounds: parseInt(getEnvVar('BCRYPT_ROUNDS', '12'), 10),

  // Database (guaranteed to exist after validation)
  databaseUrl: process.env.DATABASE_URL!,
  databasePoolMin: parseInt(getEnvVar('DATABASE_POOL_MIN', '5'), 10),
  databasePoolMax: parseInt(getEnvVar('DATABASE_POOL_MAX', '20'), 10),

  // CORS
  corsOrigin: getEnvVar('CORS_ORIGIN', 'http://localhost:3001'),

  // Rate Limiting
  rateLimitWindowMs: parseInt(getEnvVar('RATE_LIMIT_WINDOW_MS', '60000'), 10),
  rateLimitMaxRequests: parseInt(getEnvVar('RATE_LIMIT_MAX_REQUESTS', '100'), 10),

  // Logging
  logLevel: getEnvVar('LOG_LEVEL', 'info'),

  // Helpers
  isDevelopment: getEnvVar('NODE_ENV', 'development') === 'development',
  isProduction: getEnvVar('NODE_ENV', 'development') === 'production',
  isTest: getEnvVar('NODE_ENV', 'development') === 'test',
} as const;

// Log configuration (sanitized)
if (config.isDevelopment) {
  console.log('✅ Environment configuration loaded:');
  console.log(`   NODE_ENV: ${config.nodeEnv}`);
  console.log(`   PORT: ${config.port}`);
  console.log(`   API_VERSION: ${config.apiVersion}`);
  console.log(`   CORS_ORIGIN: ${config.corsOrigin}`);
  console.log(`   DATABASE_URL: ${config.databaseUrl.replace(/\/\/.*@/, '//***:***@')}`); // Hide credentials
  console.log(`   JWT_SECRET: ${config.jwtSecret ? '[SET]' : '[NOT SET]'}`);
  console.log('');
}
