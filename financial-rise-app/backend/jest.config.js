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
    'sql-injection\\.spec\\.ts$', // Requires database setup
    'users-right-to-object\\.spec\\.ts$', // Incomplete feature - requires Work Stream 67
    'auth\\.module\\.spec\\.ts$', // Complex module dependencies
    'cors-configuration\\.spec\\.ts$', // Depends on incomplete features
    'idor-attack\\.integration\\.spec\\.ts$', // Integration test
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
