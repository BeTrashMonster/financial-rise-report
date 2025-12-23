/**
 * Template Validation Script
 * Validates HTML structure and CSS syntax for report templates
 */

const fs = require('fs');
const path = require('path');

// ANSI color codes for terminal output
const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m'
};

function validateHTML(filePath) {
  console.log(`\n${colors.blue}Validating: ${filePath}${colors.reset}`);

  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const issues = [];

    // Check for basic HTML structure
    if (!content.includes('<!DOCTYPE html>')) {
      issues.push('Missing <!DOCTYPE html> declaration');
    }

    if (!content.includes('<html')) {
      issues.push('Missing <html> tag');
    }

    if (!content.includes('<head>')) {
      issues.push('Missing <head> section');
    }

    if (!content.includes('<body>')) {
      issues.push('Missing <body> section');
    }

    if (!content.includes('</html>')) {
      issues.push('Missing closing </html> tag');
    }

    // Check for unclosed tags (basic check)
    const openTags = content.match(/<(?!\/)[a-z][a-z0-9]*[^>]*>/gi) || [];
    const closeTags = content.match(/<\/[a-z][a-z0-9]*>/gi) || [];
    const selfClosingTags = ['meta', 'link', 'img', 'br', 'hr', 'input'];

    const openTagNames = openTags.map(tag => {
      const match = tag.match(/<([a-z][a-z0-9]*)/i);
      return match ? match[1].toLowerCase() : null;
    }).filter(tag => tag && !selfClosingTags.includes(tag) && !tag.endsWith('/>'));

    const closeTagNames = closeTags.map(tag => {
      const match = tag.match(/<\/([a-z][a-z0-9]*)/i);
      return match ? match[1].toLowerCase() : null;
    });

    // Check for charset declaration
    if (!content.includes('charset')) {
      issues.push('Missing charset declaration');
    }

    // Check for title tag
    if (!content.includes('<title>')) {
      issues.push('Missing <title> tag');
    }

    // Check for viewport meta tag
    if (!content.includes('viewport')) {
      issues.push('Missing viewport meta tag (recommended for responsive design)');
    }

    // Check for unclosed style tags
    const styleOpenCount = (content.match(/<style[^>]*>/gi) || []).length;
    const styleCloseCount = (content.match(/<\/style>/gi) || []).length;
    if (styleOpenCount !== styleCloseCount) {
      issues.push(`Unclosed <style> tags (${styleOpenCount} open, ${styleCloseCount} close)`);
    }

    // Check for template variables format
    const variables = content.match(/\{\{[^}]+\}\}/g) || [];
    console.log(`  Found ${variables.length} template variables`);

    // Check CSS syntax within style tags
    const styleMatches = content.match(/<style[^>]*>([\s\S]*?)<\/style>/gi);
    if (styleMatches) {
      styleMatches.forEach((styleBlock, index) => {
        const css = styleBlock.replace(/<\/?style[^>]*>/gi, '');

        // Check for unclosed CSS blocks
        const openBraces = (css.match(/\{/g) || []).length;
        const closeBraces = (css.match(/\}/g) || []).length;
        if (openBraces !== closeBraces) {
          issues.push(`CSS block ${index + 1}: Unclosed braces (${openBraces} open, ${closeBraces} close)`);
        }

        // Check for missing semicolons (basic check)
        const cssRules = css.split('}').filter(rule => rule.trim());
        cssRules.forEach((rule, ruleIndex) => {
          if (rule.includes(':') && !rule.trim().endsWith(';') && !rule.includes('@')) {
            const preview = rule.trim().substring(0, 50);
            issues.push(`CSS block ${index + 1}, rule ${ruleIndex + 1}: Possible missing semicolon near "${preview}..."`);
          }
        });
      });
    }

    if (issues.length === 0) {
      console.log(`${colors.green}✓ Valid HTML structure${colors.reset}`);
      return true;
    } else {
      console.log(`${colors.red}✗ Found ${issues.length} issue(s):${colors.reset}`);
      issues.forEach(issue => {
        console.log(`  ${colors.yellow}⚠${colors.reset} ${issue}`);
      });
      return false;
    }

  } catch (error) {
    console.log(`${colors.red}✗ Error reading file: ${error.message}${colors.reset}`);
    return false;
  }
}

function validateSVG(filePath) {
  console.log(`\n${colors.blue}Validating SVG: ${filePath}${colors.reset}`);

  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const issues = [];

    // Check for SVG root element
    if (!content.includes('<svg')) {
      issues.push('Missing <svg> root element');
    }

    // Check for xmlns namespace
    if (!content.includes('xmlns="http://www.w3.org/2000/svg"')) {
      issues.push('Missing xmlns namespace declaration');
    }

    // Check for viewBox (recommended)
    if (!content.includes('viewBox')) {
      issues.push('Missing viewBox attribute (recommended for scaling)');
    }

    // Check for unclosed tags
    const openBrackets = (content.match(/</g) || []).length;
    const closeBrackets = (content.match(/>/g) || []).length;
    if (openBrackets !== closeBrackets) {
      issues.push(`Unclosed tags (${openBrackets} <, ${closeBrackets} >)`);
    }

    if (issues.length === 0) {
      console.log(`${colors.green}✓ Valid SVG structure${colors.reset}`);
      return true;
    } else {
      console.log(`${colors.red}✗ Found ${issues.length} issue(s):${colors.reset}`);
      issues.forEach(issue => {
        console.log(`  ${colors.yellow}⚠${colors.reset} ${issue}`);
      });
      return false;
    }

  } catch (error) {
    console.log(`${colors.red}✗ Error reading file: ${error.message}${colors.reset}`);
    return false;
  }
}

// Main validation
console.log(`${colors.blue}${'='.repeat(60)}`);
console.log('Financial RISE Report - Template Validation');
console.log(`${'='.repeat(60)}${colors.reset}\n`);

const templatesDir = path.join(__dirname);
const assetsDir = path.join(__dirname, 'assets');

const results = {
  passed: 0,
  failed: 0
};

// Validate HTML templates
const htmlFiles = [
  path.join(templatesDir, 'consultant-report.html'),
  path.join(templatesDir, 'client-report.html')
];

htmlFiles.forEach(file => {
  if (fs.existsSync(file)) {
    if (validateHTML(file)) {
      results.passed++;
    } else {
      results.failed++;
    }
  } else {
    console.log(`${colors.red}✗ File not found: ${file}${colors.reset}`);
    results.failed++;
  }
});

// Validate SVG assets
if (fs.existsSync(assetsDir)) {
  const svgFiles = fs.readdirSync(assetsDir).filter(f => f.endsWith('.svg'));

  svgFiles.forEach(file => {
    const filePath = path.join(assetsDir, file);
    if (validateSVG(filePath)) {
      results.passed++;
    } else {
      results.failed++;
    }
  });
}

// Validate JSON
const jsonFile = path.join(templatesDir, 'disc-content.json');
if (fs.existsSync(jsonFile)) {
  console.log(`\n${colors.blue}Validating JSON: ${jsonFile}${colors.reset}`);
  try {
    const content = fs.readFileSync(jsonFile, 'utf8');
    JSON.parse(content);
    console.log(`${colors.green}✓ Valid JSON structure${colors.reset}`);
    results.passed++;
  } catch (error) {
    console.log(`${colors.red}✗ Invalid JSON: ${error.message}${colors.reset}`);
    results.failed++;
  }
}

// Summary
console.log(`\n${colors.blue}${'='.repeat(60)}`);
console.log('Validation Summary');
console.log(`${'='.repeat(60)}${colors.reset}`);
console.log(`${colors.green}✓ Passed: ${results.passed}${colors.reset}`);
console.log(`${colors.red}✗ Failed: ${results.failed}${colors.reset}`);

if (results.failed === 0) {
  console.log(`\n${colors.green}All templates are valid!${colors.reset}\n`);
  process.exit(0);
} else {
  console.log(`\n${colors.yellow}Some templates have issues. Please review above.${colors.reset}\n`);
  process.exit(1);
}
