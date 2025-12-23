const { execSync } = require('child_process');
const { readdirSync, statSync } = require('fs');
const { join } = require('path');

// Find all test files recursively
function findTestFiles(dir, fileList = []) {
  const files = readdirSync(dir);

  files.forEach(file => {
    const filePath = join(dir, file);
    if (statSync(filePath).isDirectory()) {
      if (!file.includes('node_modules') && !file.includes('dist') && !file.includes('coverage')) {
        findTestFiles(filePath, fileList);
      }
    } else if (file.match(/\.test\.(ts|tsx|js|jsx)$/)) {
      fileList.push(filePath);
    }
  });

  return fileList;
}

const testFiles = findTestFiles('./src');
console.log(`Found ${testFiles.length} test files\n`);

let totalPassed = 0;
let totalFailed = 0;
const failedFiles = [];

testFiles.forEach((file, index) => {
  console.log(`[${index + 1}/${testFiles.length}] Running: ${file}`);

  try {
    const output = execSync(
      `node_modules\\.bin\\vitest run "${file}" --no-coverage --reporter=basic`,
      {
        encoding: 'utf-8',
        stdio: ['pipe', 'pipe', 'pipe'],
        timeout: 30000
      }
    );

    const passedMatch = output.match(/(\d+) passed/);
    const failedMatch = output.match(/(\d+) failed/);

    if (passedMatch) totalPassed += parseInt(passedMatch[1]);
    if (failedMatch) {
      totalFailed += parseInt(failedMatch[1]);
      failedFiles.push(file);
    }

    console.log(output.split('\n').filter(line =>
      line.includes('✓') || line.includes('×') || line.includes('Test Files') || line.includes('Tests')
    ).join('\n'));

  } catch (error) {
    console.error(`  FAILED: ${error.message}`);
    failedFiles.push(file);
  }

  console.log('');
});

console.log('\n===================');
console.log('SUMMARY');
console.log('===================');
console.log(`Total Passed: ${totalPassed}`);
console.log(`Total Failed: ${totalFailed}`);

if (failedFiles.length > 0) {
  console.log('\nFiles with failures:');
  failedFiles.forEach(file => console.log(`  - ${file}`));
  process.exit(1);
} else {
  console.log('\n✅ All tests passed!');
  process.exit(0);
}
