// Test Setup File
// Loads environment variables before tests run

import * as dotenv from 'dotenv';
import * as path from 'path';

// Load test environment variables
dotenv.config({ path: path.join(__dirname, '../../.env.test') });

// Mock console.error to reduce noise in test output
global.console = {
  ...console,
  error: jest.fn(), // Mock console.error
};

// Mock Puppeteer to avoid browser launch issues in tests
jest.mock('puppeteer', () => ({
  launch: jest.fn().mockResolvedValue({
    newPage: jest.fn().mockResolvedValue({
      setContent: jest.fn().mockResolvedValue(undefined),
      pdf: jest.fn().mockResolvedValue(Buffer.from('mock-pdf-data')),
      close: jest.fn().mockResolvedValue(undefined),
    }),
    close: jest.fn().mockResolvedValue(undefined),
  }),
}));

// Mock AWS S3 Client
jest.mock('@aws-sdk/client-s3', () => ({
  S3Client: jest.fn().mockImplementation(() => ({
    send: jest.fn().mockResolvedValue({}),
  })),
  PutObjectCommand: jest.fn(),
}));

jest.mock('@aws-sdk/s3-request-presigner', () => ({
  getSignedUrl: jest.fn().mockResolvedValue('https://s3.example.com/mock-signed-url'),
}));

// Global test setup
beforeAll(() => {
  // Suppress environment validation during tests
  process.env.NODE_ENV = 'test';
});

afterAll(() => {
  // Cleanup
});
