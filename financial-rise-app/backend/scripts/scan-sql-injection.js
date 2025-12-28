#!/usr/bin/env node
/**
 * SQL Injection Vulnerability Scanner
 *
 * Automated static analysis tool to detect potential SQL injection
 * vulnerabilities in the codebase.
 *
 * Usage:
 *   node scripts/scan-sql-injection.js
 *
 * Exit Codes:
 *   0 - No vulnerabilities found
 *   1 - Vulnerabilities detected
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// ANSI color codes
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
};

class SQLInjectionScanner {
  constructor() {
    this.vulnerabilities = [];
    this.warnings = [];
    this.srcDir = path.join(__dirname, '../src');
  }

  /**
   * Run all vulnerability scans
   */
  async scan() {
    console.log(`${colors.cyan}🔍 SQL Injection Vulnerability Scanner${colors.reset}\n`);

    // Scan patterns
    this.scanTemplateStringsInQueries();
    this.scanStringConcatenation();
    this.scanUnsafeJSONBQueries();
    this.scanDynamicTableNames();
    this.checkForParameterizedQueries();

    // Print results
    this.printResults();

    // Return exit code
    return this.vulnerabilities.length > 0 ? 1 : 0;
  }

  /**
   * Scan for template literals in query() calls
   * Pattern: query(`...${...}...`)
   */
  scanTemplateStringsInQueries() {
    console.log(`${colors.blue}📋 Scanning for template literals in query() calls...${colors.reset}`);

    try {
      // Use git grep if available (faster), fallback to grep
      const grepCmd = 'git -C ' + this.srcDir + ' grep -n "query(\`.*\${" || grep -rn "query(\`.*\${" ' + this.srcDir;
      const result = execSync(grepCmd, { encoding: 'utf8', stdio: 'pipe' });

      if (result.trim()) {
        const matches = result.trim().split('\n');
        matches.forEach((match) => {
          this.addVulnerability('CRITICAL', 'Template literal in query()', match, 'Use parameterized queries instead');
        });
      }
    } catch (error) {
      // No matches found (exit code 1 from grep)
      if (!error.message.includes('Command failed')) {
        console.error(`${colors.red}Error scanning:${colors.reset}`, error.message);
      }
    }
  }

  /**
   * Scan for string concatenation in SQL
   * Pattern: query("..." + var)
   */
  scanStringConcatenation() {
    console.log(`${colors.blue}📋 Scanning for string concatenation in queries...${colors.reset}`);

    const patterns = [
      'query\\(".*\\+',
      "query\\('.*\\+",
    ];

    patterns.forEach((pattern) => {
      try {
        const result = execSync(`grep -rn "${pattern}" ${this.srcDir}`, { encoding: 'utf8', stdio: 'pipe' });

        if (result.trim()) {
          const matches = result.trim().split('\n');
          matches.forEach((match) => {
            this.addVulnerability('CRITICAL', 'String concatenation in query()', match, 'Use parameterized queries');
          });
        }
      } catch (error) {
        // No matches (expected)
      }
    });
  }

  /**
   * Scan for unsafe JSONB queries
   * Pattern: answer->>'${...}'
   */
  scanUnsafeJSONBQueries() {
    console.log(`${colors.blue}📋 Scanning for unsafe JSONB queries...${colors.reset}`);

    try {
      const result = execSync(`grep -rn "->>'.*\${" ${this.srcDir}`, { encoding: 'utf8', stdio: 'pipe' });

      if (result.trim()) {
        const matches = result.trim().split('\n');
        matches.forEach((match) => {
          this.addVulnerability('HIGH', 'Unsafe JSONB query with interpolation', match, 'Use parameterized JSONB queries');
        });
      }
    } catch (error) {
      // No matches (expected)
    }
  }

  /**
   * Scan for dynamic table/column names
   * Pattern: orderBy(`entity.${...}`)
   */
  scanDynamicTableNames() {
    console.log(`${colors.blue}📋 Scanning for dynamic table/column names...${colors.reset}`);

    try {
      const result = execSync(`grep -rn "orderBy(\`.*\${" ${this.srcDir}`, { encoding: 'utf8', stdio: 'pipe' });

      if (result.trim()) {
        const matches = result.trim().split('\n');
        matches.forEach((match) => {
          this.addWarning('MEDIUM', 'Dynamic column name in orderBy()', match, 'Validate against whitelist');
        });
      }
    } catch (error) {
      // No matches
    }
  }

  /**
   * Check that all createQueryBuilder calls use parameterized queries
   */
  checkForParameterizedQueries() {
    console.log(`${colors.blue}📋 Verifying parameterized queries...${colors.reset}`);

    try {
      // Find all files with createQueryBuilder
      const filesWithQB = execSync(`grep -rl "createQueryBuilder" ${this.srcDir} --include="*.ts" --exclude="*.spec.ts"`, {
        encoding: 'utf8',
        stdio: 'pipe',
      }).trim().split('\n');

      filesWithQB.forEach((file) => {
        if (!file) return;

        const content = fs.readFileSync(file, 'utf8');
        const lines = content.split('\n');

        lines.forEach((line, index) => {
          // Check if line has .where() or .andWhere() or .orWhere()
          if (line.match(/\.(where|andWhere|orWhere)\(/)) {
            // Check if it uses parameterized syntax (:paramName)
            if (!line.includes(':') && line.includes('=')) {
              this.addWarning(
                'MEDIUM',
                'Potential non-parameterized WHERE clause',
                `${file}:${index + 1}: ${line.trim()}`,
                'Verify this uses parameterized queries'
              );
            }
          }
        });
      });
    } catch (error) {
      // No files found
    }
  }

  /**
   * Add a vulnerability finding
   */
  addVulnerability(severity, type, location, recommendation) {
    this.vulnerabilities.push({
      severity,
      type,
      location,
      recommendation,
    });
  }

  /**
   * Add a warning finding
   */
  addWarning(severity, type, location, recommendation) {
    this.warnings.push({
      severity,
      type,
      location,
      recommendation,
    });
  }

  /**
   * Print scan results
   */
  printResults() {
    console.log('\n' + '='.repeat(70));

    if (this.vulnerabilities.length === 0 && this.warnings.length === 0) {
      console.log(`${colors.green}✅ No SQL injection vulnerabilities detected!${colors.reset}`);
      console.log('\n📊 Scan Summary:');
      console.log(`   - Files scanned: ${this.getScanStats()}`);
      console.log(`   - Vulnerabilities: 0`);
      console.log(`   - Warnings: 0`);
    } else {
      if (this.vulnerabilities.length > 0) {
        console.log(`${colors.red}❌ ${this.vulnerabilities.length} VULNERABILITIES DETECTED${colors.reset}\n`);

        this.vulnerabilities.forEach((vuln, index) => {
          console.log(`${colors.red}[${vuln.severity}]${colors.reset} ${vuln.type}`);
          console.log(`   Location: ${vuln.location}`);
          console.log(`   Fix: ${vuln.recommendation}\n`);
        });
      }

      if (this.warnings.length > 0) {
        console.log(`${colors.yellow}⚠️  ${this.warnings.length} WARNINGS${colors.reset}\n`);

        this.warnings.forEach((warning, index) => {
          console.log(`${colors.yellow}[${warning.severity}]${colors.reset} ${warning.type}`);
          console.log(`   Location: ${warning.location}`);
          console.log(`   Recommendation: ${warning.recommendation}\n`);
        });
      }
    }

    console.log('='.repeat(70));
  }

  /**
   * Get scan statistics
   */
  getScanStats() {
    try {
      const result = execSync(`find ${this.srcDir} -name "*.ts" -not -path "*/node_modules/*" | wc -l`, {
        encoding: 'utf8',
      });
      return result.trim();
    } catch (error) {
      return 'unknown';
    }
  }
}

// Run scanner
const scanner = new SQLInjectionScanner();
scanner.scan().then((exitCode) => {
  process.exit(exitCode);
}).catch((error) => {
  console.error(`${colors.red}Scanner error:${colors.reset}`, error);
  process.exit(2);
});
