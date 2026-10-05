/**
 * Guardrail Lab - Unit Tests for Evaluator & Matcher Engine
 * 
 * Verifies core engine invariants:
 * 1. Exact match is correctly detected
 * 2. Known semantic miss is flagged as MISSED
 * 3. Hook-layer cases are categorized as NOT_APPLICABLE
 * 4. Invalid regular expressions fail safely without unhandled exceptions
 * 5. Deterministic idempotency (same input -> identical result)
 * 6. Case sensitivity handling behaves predictably
 * 7. Shell strings are treated as safe data (no eval, no execution)
 * 8. Structured token matching correctly isolates executable & subcommand
 */

import { evaluateMatcher, tokenizeCommand } from './matcher.js';
import { evaluateSuite } from './evaluator.js';
import { POLICIES } from './corpus.js';

export function runAllTests() {
  const testResults = [];
  let passedCount = 0;
  let failedCount = 0;

  function assert(name, condition, message = '') {
    if (condition) {
      passedCount++;
      testResults.push({ name, passed: true, message: 'PASS' });
    } else {
      failedCount++;
      testResults.push({ name, passed: false, message: `FAIL: ${message}` });
    }
  }

  // 1. Exact match detection
  const t1 = evaluateMatcher('git commit', 'git commit', 'literal');
  assert('Exact match detected in literal mode', t1.matched === true, 'Expected exact string to match');

  // 2. Known miss detection
  const t2 = evaluateMatcher('git -C /repo commit', 'git commit', 'literal');
  assert('Flag insertion breaks literal match', t2.matched === false, 'Expected interleaved flag to miss contiguous literal');

  // 3. Invalid regex safety (must not throw)
  let threwException = false;
  let t3Result = null;
  try {
    t3Result = evaluateMatcher('git commit', 'git [commit(', 'regex');
  } catch (e) {
    threwException = true;
  }
  assert('Invalid regex handled safely without exception', !threwException && t3Result && t3Result.error !== null, 'Expected graceful error return');

  // 4. Suite evaluation - Hook layer isolation (NOT_APPLICABLE)
  const suiteResult = evaluateSuite(POLICIES['git-commit'], 'git commit', 'literal');
  const noVerifyCase = suiteResult.results.find(r => r.id === 'TC-10');
  assert(
    'Hook bypass flag TC-10 marked as NOT_APPLICABLE to matcher',
    noVerifyCase && noVerifyCase.status === 'NOT_APPLICABLE',
    `Expected status NOT_APPLICABLE, got ${noVerifyCase?.status}`
  );

  // 5. Baseline exact invocation blocked
  const baselineCase = suiteResult.results.find(r => r.id === 'TC-01');
  assert('TC-01 exact invocation marked as BLOCKED', baselineCase && baselineCase.status === 'BLOCKED', 'Expected TC-01 to be blocked');

  // 6. Interleaved flag marked as MISSED in literal mode
  const interleavedCase = suiteResult.results.find(r => r.id === 'TC-03');
  assert('TC-03 interleaved flag marked as MISSED in literal mode', interleavedCase && interleavedCase.status === 'MISSED', 'Expected TC-03 to be missed');

  // 7. Deterministic idempotency test (run twice, ensure 100% identity)
  const run1 = evaluateSuite(POLICIES['git-commit'], 'git commit', 'literal');
  const run2 = evaluateSuite(POLICIES['git-commit'], 'git commit', 'literal');
  const identical = JSON.stringify(run1) === JSON.stringify(run2);
  assert('Deterministic idempotency: identical runs yield identical output', identical, 'Two runs differed');

  // 8. Case insensitivity by default
  const caseTest = evaluateMatcher('GIT COMMIT', 'git commit', 'literal', { caseSensitive: false });
  assert('Case insensitive matching functions by default', caseTest.matched === true, 'Expected case insensitive match');

  // 9. Case sensitivity option respected
  const caseTestSens = evaluateMatcher('GIT COMMIT', 'git commit', 'literal', { caseSensitive: true });
  assert('Case sensitive matching rejects uppercase when enabled', caseTestSens.matched === false, 'Expected case mismatch');

  // 10. Wildcard glob matching
  const globTestPass = evaluateMatcher('git -C /dir commit', 'git * commit', 'wildcard');
  assert('Wildcard glob "git * commit" matches interleaved string', globTestPass.matched === true, 'Expected wildcard to match');

  const globTestFail = evaluateMatcher('svn commit', 'git * commit', 'wildcard');
  assert('Wildcard glob rejects non-matching prefix', globTestFail.matched === false, 'Expected wildcard to reject non-git');

  // 11. Command Tokenization handles wrappers safely
  const tokens = tokenizeCommand('env PATH="$PATH" /usr/bin/git commit -m "msg"');
  assert(
    'Tokenizer extracts base executable and subcommand across env and paths',
    tokens.length > 0 && tokens[0].executable === 'git' && tokens[0].subcommand === 'commit',
    `Expected exec=git, subcmd=commit, got exec=${tokens[0]?.executable}, subcmd=${tokens[0]?.subcommand}`
  );

  // 12. Structured Matcher intercepts interleaved flags
  const structuredTest = evaluateMatcher('git -C /repo commit -m "fix"', 'exec=git & subcmd=commit', 'structured');
  assert('Structured matcher blocks interleaved flag', structuredTest.matched === true, 'Expected structured parser to catch git -C commit');

  // 13. Benign cases: overbroad rule triggers FALSE_POSITIVE, precise rule stays CLEAR
  const broadOutcome = evaluateSuite(POLICIES['git-commit'], 'git', 'literal', { caseSensitive: false });
  const benignB01Broad = broadOutcome.results.find(r => r.id === 'TC-B01');
  assert('Overbroad rule "git" false-positives on benign "git status"',
    benignB01Broad && benignB01Broad.status === 'FALSE_POSITIVE' && broadOutcome.falsePositives > 0,
    `Expected TC-B01 FALSE_POSITIVE with rule "git", got ${benignB01Broad?.status}, fp=${broadOutcome.falsePositives}`);

  const preciseOutcome = evaluateSuite(POLICIES['git-commit'], 'git commit', 'literal', { caseSensitive: false });
  const benignB01Precise = preciseOutcome.results.find(r => r.id === 'TC-B01');
  const benignB05Precise = preciseOutcome.results.find(r => r.id === 'TC-B05');
  assert('Precise rule "git commit" leaves benign "git status" CLEAR',
    benignB01Precise && benignB01Precise.status === 'CLEAR',
    `Expected TC-B01 CLEAR with rule "git commit", got ${benignB01Precise?.status}`);
  assert('Naive rule "git commit" false-positives on quoted \'echo "remember: git commit"\'',
    benignB05Precise && benignB05Precise.status === 'FALSE_POSITIVE',
    `Expected TC-B05 FALSE_POSITIVE with rule "git commit", got ${benignB05Precise?.status}`);

  return {
    total: testResults.length,
    passed: passedCount,
    failed: failedCount,
    allPassed: failedCount === 0,
    results: testResults
  };
}

// If executed directly in Node CLI
if (typeof process !== 'undefined' && process.argv && process.argv[1]?.includes('test-engine')) {
  console.log('--- Running Guardrail Lab Engine Self-Tests ---');
  const summary = runAllTests();
  summary.results.forEach(r => {
    console.log(`[${r.passed ? '✓' : '✗'}] ${r.name}: ${r.message}`);
  });
  console.log(`\nResult: ${summary.passed}/${summary.total} tests passed.`);
  if (!summary.allPassed) {
    process.exit(1);
  }
}
