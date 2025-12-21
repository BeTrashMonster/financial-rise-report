import { TypeOrmModuleOptions } from '@nestjs/typeorm';
import { DISCProfile } from '../src/modules/algorithms/entities/disc-profile.entity';
import { PhaseResult } from '../src/modules/algorithms/entities/phase-result.entity';

/**
 * Test database configuration using SQLite in-memory database
 *
 * This provides fast, isolated testing without requiring external database setup
 */
export const testDatabaseConfig: TypeOrmModuleOptions = {
  type: 'sqlite',
  database: ':memory:',
  entities: [DISCProfile, PhaseResult],
  synchronize: true, // Auto-create tables for testing
  dropSchema: true, // Clean slate for each test run
  logging: false, // Set to true for debugging
};
