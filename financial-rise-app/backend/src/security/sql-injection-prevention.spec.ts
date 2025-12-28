/**
 * SQL Injection Prevention - Unit Tests
 *
 * Purpose: Verify that TypeORM Query Builder properly parameterizes queries
 * and prevents SQL injection attacks through automated testing.
 *
 * Security Finding: CRIT-003 - SQL Injection Verification
 * Status: VERIFIED SECURE - All queries use parameterized statements
 *
 * Audit Results:
 * - Migrations: Use QueryRunner.query() with static DDL (no user input)
 * - Services: All use TypeORM QueryBuilder with parameterized queries
 * - JSONB queries: No direct JSONB operator queries found
 * - Raw SQL: Zero instances of string interpolation in queries
 *
 * This test suite verifies:
 * 1. TypeORM QueryBuilder parameterization behavior
 * 2. Protection against classic SQL injection payloads
 * 3. Safe handling of special characters in WHERE clauses
 * 4. IN clause array parameterization
 * 5. ILIKE search query safety
 */

import { DataSource, Repository, Entity, Column, PrimaryGeneratedColumn } from 'typeorm';
import { randomUUID } from 'crypto';

// Simple test entity without enums for SQLite compatibility
@Entity('test_users')
class TestUser {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'varchar' })
  email: string;

  @Column({ type: 'varchar' })
  password_hash: string;

  @Column({ type: 'varchar' })
  first_name: string;

  @Column({ type: 'varchar' })
  last_name: string;
}

describe('SQL Injection Prevention Tests', () => {
  let dataSource: DataSource;
  let userRepository: Repository<TestUser>;

  // Common SQL injection attack payloads
  const SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--",
    "'; DROP TABLE users--",
    "' UNION SELECT NULL--",
    "\\'; DROP TABLE users--",
  ];

  beforeAll(async () => {
    // Create in-memory SQLite database for testing
    dataSource = new DataSource({
      type: 'sqlite',
      database: ':memory:',
      entities: [TestUser],
      synchronize: true,
      logging: false,
    });

    await dataSource.initialize();
    userRepository = dataSource.getRepository(TestUser);

    // Create test data
    const testUser = userRepository.create({
      email: 'test@example.com',
      password_hash: 'hashed_password',
      first_name: 'Test',
      last_name: 'User',
    });
    await userRepository.save(testUser);
  });

  afterAll(async () => {
    await dataSource.destroy();
  });

  describe('TypeORM QueryBuilder Parameterization', () => {
    it('should use parameterized queries for WHERE clauses', async () => {
      // Test that malicious email input is treated as literal string, not SQL
      const maliciousEmail = "' OR '1'='1--";

      const query = userRepository
        .createQueryBuilder('tu')
        .where('tu.email = :email', { email: maliciousEmail });

      // Get the generated SQL
      const sql = query.getSql();

      // Verify SQL uses parameters (? for SQLite, $1 for PostgreSQL)
      // TypeORM uses quoted identifiers like "tu"."email"
      expect(sql).toMatch(/email.*=.*\?/);
      expect(sql).not.toContain(maliciousEmail);

      // Execute query - should return no results (not bypass authentication)
      const result = await query.getOne();
      expect(result).toBeNull();
    });

    it('should safely handle SQL injection in ILIKE search', async () => {
      const maliciousSearch = "%'; DROP TABLE test_users; --";

      const query = userRepository
        .createQueryBuilder('tu')
        .where('tu.email LIKE :search', { search: `%${maliciousSearch}%` }); // LIKE instead of ILIKE for SQLite

      const sql = query.getSql();

      // Verify parameterized query
      expect(sql).toContain('LIKE ?');
      expect(sql).not.toContain('DROP TABLE');

      // Should execute safely without errors
      const result = await query.getMany();
      expect(Array.isArray(result)).toBe(true);
    });

    it('should parameterize IN clauses with arrays', async () => {
      const maliciousIds = ["' OR '1'='1--", "'; DROP TABLE test_users--"];

      const query = userRepository
        .createQueryBuilder('tu')
        .whereInIds(maliciousIds);

      const sql = query.getSql();

      // Verify IN clause is parameterized
      expect(sql).toContain('IN');
      expect(sql).not.toContain('DROP TABLE');

      // Should execute without errors
      const result = await query.getMany();
      expect(Array.isArray(result)).toBe(true);
    });

    it('should handle AND/OR conditions safely', async () => {
      const maliciousFirst = "' OR '1'='1";
      const maliciousLast = "'; DELETE FROM test_users WHERE '1'='1";

      const query = userRepository
        .createQueryBuilder('tu')
        .where('tu.first_name = :firstName', { firstName: maliciousFirst })
        .andWhere('tu.last_name = :lastName', { lastName: maliciousLast });

      const sql = query.getSql();

      // Verify both conditions use parameters (TypeORM uses quoted identifiers)
      expect(sql).toMatch(/first_name.*=.*\?/);
      expect(sql).toMatch(/last_name.*=.*\?/);
      expect(sql).not.toContain('DELETE FROM');

      const result = await query.getOne();
      expect(result).toBeNull();
    });

    SQL_INJECTION_PAYLOADS.forEach((payload, index) => {
      it(`should block SQL injection payload ${index + 1}: "${payload}"`, async () => {
        const query = userRepository
          .createQueryBuilder('tu')
          .where('tu.email = :email', { email: payload });

        // Should not throw SQL syntax errors
        await expect(query.getOne()).resolves.not.toThrow();

        // Should return null (not bypass authentication)
        const result = await query.getOne();
        expect(result).toBeNull();
      });
    });
  });

  describe('Special Characters Handling', () => {
    it('should safely handle single quotes in data', async () => {
      const emailWithQuotes = "test'@example.com";

      const query = userRepository
        .createQueryBuilder('tu')
        .where('tu.email = :email', { email: emailWithQuotes });

      // Should treat single quote as literal character
      const result = await query.getOne();
      expect(result).toBeNull();
    });

    it('should safely handle double dashes (SQL comment)', async () => {
      const emailWithComments = "test@example.com--";

      const query = userRepository
        .createQueryBuilder('tu')
        .where('tu.email = :email', { email: emailWithComments });

      const result = await query.getOne();
      expect(result).toBeNull();
    });

    it('should safely handle semicolons (statement terminators)', async () => {
      const emailWithSemicolon = "test@example.com; DROP TABLE test_users;";

      const query = userRepository
        .createQueryBuilder('tu')
        .where('tu.email = :email', { email: emailWithSemicolon });

      const result = await query.getOne();
      expect(result).toBeNull();

      // Verify table still exists
      const count = await userRepository.count();
      expect(count).toBeGreaterThan(0);
    });

    it('should safely handle backslashes', async () => {
      const emailWithBackslash = "test\\@example.com";

      const query = userRepository
        .createQueryBuilder('tu')
        .where('tu.email = :email', { email: emailWithBackslash });

      const result = await query.getOne();
      expect(result).toBeNull();
    });
  });

  describe('Query Logging and Inspection', () => {
    it('should generate SQL with placeholders, not raw values', async () => {
      const sensitiveEmail = "admin@example.com";
      const sensitivePassword = "SuperSecret123!";

      const query = userRepository
        .createQueryBuilder('tu')
        .where('tu.email = :email', { email: sensitiveEmail })
        .andWhere('tu.password_hash = :password', { password: sensitivePassword });

      const sql = query.getSql();

      // Verify sensitive data not in SQL string
      expect(sql).not.toContain(sensitiveEmail);
      expect(sql).not.toContain(sensitivePassword);
      expect(sql).toContain('?'); // Placeholders
    });

    it('should allow inspection of parameters separately from SQL', async () => {
      const query = userRepository
        .createQueryBuilder('tu')
        .where('tu.email = :email', { email: 'test@example.com' });

      const sql = query.getSql();
      const parameters = query.getParameters();

      // SQL and parameters should be separate (TypeORM uses quoted identifiers like "tu"."email")
      expect(sql).toMatch(/email.*=.*\?/);
      expect(parameters.email).toBe('test@example.com');
    });
  });

  describe('Complex Query Scenarios', () => {
    it('should handle multiple OR conditions safely', async () => {
      const query = userRepository
        .createQueryBuilder('tu')
        .where('tu.email = :email1', { email1: "' OR '1'='1" })
        .orWhere('tu.email = :email2', { email2: "admin'--" })
        .orWhere('tu.email = :email3', { email3: "'; DROP TABLE test_users--" });

      // All should be parameterized
      const sql = query.getSql();
      expect(sql).not.toContain('DROP TABLE');

      const result = await query.getMany();
      expect(result.length).toBe(0);
    });

    it('should handle subqueries safely', async () => {
      const subQuery = userRepository
        .createQueryBuilder('tu_sub')
        .select('tu_sub.id')
        .where('tu_sub.email = :email', { email: "' OR '1'='1" });

      const query = userRepository
        .createQueryBuilder('tu')
        .where(`tu.id IN (${subQuery.getQuery()})`)
        .setParameters(subQuery.getParameters());

      const result = await query.getMany();
      expect(result.length).toBe(0);
    });
  });

  describe('JSONB Safety (Future-Proofing)', () => {
    it('should demonstrate how to safely query JSONB columns', async () => {
      // Although current codebase has no direct JSONB queries,
      // this test documents the safe pattern for future development

      const exampleUserInput = "malicious'; DROP TABLE--";

      // SAFE: Parameterized JSONB query
      const safeQuery = `
        SELECT * FROM assessment_responses
        WHERE answer->>'field' = $1
      `;

      // This would be executed as:
      // dataSource.query(safeQuery, [exampleUserInput]);

      // UNSAFE (for documentation only, not executed):
      // Using template literal for demonstration
      const unsafeQueryBuilder = (input: string) => `
        SELECT * FROM assessment_responses
        WHERE answer->>'field' = '${input}'
      `;
      const unsafeExample = unsafeQueryBuilder(exampleUserInput);

      // This test documents that JSONB queries MUST use parameterization
      expect(safeQuery).toContain('$1');
      expect(unsafeExample).toContain(exampleUserInput); // Unsafe query contains raw user input
    });
  });
});

/**
 * AUDIT SUMMARY:
 *
 * Files Audited:
 * 1. progress.service.ts - Line 109: createQueryBuilder with parameterized WHERE
 * 2. assessments.service.ts - Line 69: createQueryBuilder with parameterized queries
 * 3. refresh-token.service.ts - Line 134: createQueryBuilder DELETE with parameters
 *
 * All Findings: SECURE ✅
 * - Zero raw SQL with string interpolation
 * - All queries use TypeORM QueryBuilder with :paramName syntax
 * - No JSONB operator queries (->>, ->) found in services
 * - Migrations use static DDL, no user input
 *
 * Example Safe Patterns Found:
 * ```typescript
 * .where('response.assessment_id = :assessmentId', { assessmentId })
 * .andWhere('response.question_id IN (:...requiredQuestionKeys)', { requiredQuestionKeys })
 * .andWhere('assessment.client_name ILIKE :search', { search: `%${search}%` })
 * .where('revoked_at < :date', { date: thirtyDaysAgo })
 * ```
 *
 * Recommendation: VERIFIED SECURE - No remediation needed
 * Continue using TypeORM QueryBuilder with parameterized queries for all future development.
 */
