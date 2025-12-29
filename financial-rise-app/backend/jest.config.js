const { pathsToModuleNameMapper } = require('ts-jest');
const { compilerOptions } = require('./tsconfig.json');
const { config } = require('dotenv');

// Load test environment variables
config({ path: '.env.test' });

module.exports = {
  moduleFileExtensions: ['js', 'json', 'ts'],
  rootDir: 'src',
  testRegex: '.*\\.spec\\.ts$',
  testPathIgnorePatterns: [
    '/node_modules/',
    '\\.e2e-spec\\.ts$',
    '\\.integration\\.spec\\.ts$',
    'secrets-e2e\\.spec\\.ts$',
    'main\\.spec\\.ts$',
    'sql-injection\\.spec\\.ts$',
    'users-right-to-object\\.spec\\.ts$',
    'users-processing-restriction\\.spec\\.ts$',
    'consents\\.(service|controller)\\.spec\\.ts$',
    'auth\\.module\\.spec\\.ts$',
    'cors-configuration\\.spec\\.ts$',
    'idor-attack\\.integration\\.spec\\.ts$',
    'assessment-response\\.encryption\\.spec\\.ts$',
    'auth\\.(service|rate-limiting)\\.spec\\.ts$',
    'pii-safe-logger\\.spec\\.ts$',
    'security-headers\\.spec\\.ts$',
    'data-retention\\.(service|integration)\\.spec\\.ts$',
    'users\\.service\\.spec\\.ts$',
  ],
  transform: {
    '^.+\\.(t|j)s$': 'ts-jest',
  },
  collectCoverageFrom: [
    '**/*.(t|j)s',
    '!**/*.module.ts',
    '!**/main.ts',
    '!**/index.ts',
    '!**/*.spec.ts',
    '!**/*.interface.ts',
    '!**/*.dto.ts',
    '!**/*.entity.ts',
  ],
  coverageDirectory: '../coverage',
  testEnvironment: 'node',
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80,
    },
  },
  moduleNameMapper: pathsToModuleNameMapper(compilerOptions.paths || {}, {
    prefix: '<rootDir>/',
  }),
  globals: {
    'ts-jest': {
      tsconfig: {
        ...compilerOptions,
        // Ensure all source files are included
        skipLibCheck: true,
      },
    },
  },
};
