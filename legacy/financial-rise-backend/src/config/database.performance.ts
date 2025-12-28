/**
 * Database Performance Optimization Configuration
 * Indexes, query optimization, and connection pooling
 */

export const DATABASE_INDEXES = {
  // Users table indexes
  users: [
    { fields: ['email'], unique: true },
    { fields: ['role'] },
    { fields: ['createdAt'] },
  ],

  // Assessments table indexes
  assessments: [
    { fields: ['userId'] },
    { fields: ['status'] },
    { fields: ['createdAt'] },
    { fields: ['userId', 'status'] }, // Composite index for common queries
    { fields: ['userId', 'createdAt'] }, // For sorting user's assessments
  ],

  // AssessmentResponses table indexes
  assessmentResponses: [
    { fields: ['assessmentId'] },
    { fields: ['questionId'] },
    { fields: ['assessmentId', 'questionId'], unique: true },
  ],

  // Reports table indexes (if applicable)
  reports: [
    { fields: ['assessmentId'], unique: true },
    { fields: ['userId'] },
    { fields: ['createdAt'] },
  ],
};

export const CONNECTION_POOL_CONFIG = {
  // Connection pool settings
  pool: {
    max: 20, // Maximum number of connections
    min: 5, // Minimum number of connections
    acquire: 30000, // Maximum time (ms) to acquire connection
    idle: 10000, // Maximum time (ms) connection can be idle
  },

  // Query performance
  logging: process.env.NODE_ENV === 'development' ? console.log : false,
  benchmark: process.env.NODE_ENV === 'development',

  // Connection retry
  retry: {
    max: 3,
    timeout: 3000,
  },
};

export const QUERY_OPTIMIZATIONS = {
  // Limit default query results
  DEFAULT_LIMIT: 50,
  MAX_LIMIT: 100,

  // Eager loading strategies
  assessmentIncludes: ['user', 'responses'],
  userIncludes: ['assessments'],

  // Pagination defaults
  DEFAULT_PAGE: 1,
  DEFAULT_PAGE_SIZE: 20,
};
