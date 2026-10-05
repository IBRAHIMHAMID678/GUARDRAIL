/**
 * Guardrail Lab - Evaluation Engine
 * 
 * Runs deterministic adversarial tests against the selected policy corpus.
 * Categorizes verdicts into BLOCKED, MISSED, and NOT APPLICABLE (Different Control Layer).
 */

import { evaluateMatcher } from './matcher.js';

export function evaluateSuite(policy, rule, mode, options = { caseSensitive: false }) {
  if (!policy || !policy.corpus) {
    return { error: 'Invalid policy specified', results: [] };
  }

  const results = [];
  let applicableTotal = 0;
  let applicableBlocked = 0;
  let applicableMissed = 0;
  let differentLayerCount = 0;
  let falsePositives = 0;
  let benignTotal = 0;
  let syntaxError = null;

  for (const testCase of policy.corpus) {
    const matchOutcome = evaluateMatcher(testCase.command, rule, mode, options);

    if (matchOutcome.error && !syntaxError) {
      syntaxError = matchOutcome.error;
    }

    let verdictStatus = 'MISSED'; // BLOCKED | MISSED | NOT_APPLICABLE | FALSE_POSITIVE | CLEAR
    let explanation = '';
    let layerClassification = testCase.targetLayer;

    if (testCase.isBenign) {
      // Precision check: innocent commands the rule must NOT block
      benignTotal++;
      if (matchOutcome.matched) {
        falsePositives++;
        verdictStatus = 'FALSE_POSITIVE';
        explanation = `False alarm: your rule blocked an innocent command. Tightening the rule to catch more attacks also catches harmless work like this — precision matters as much as coverage.`;
      } else {
        verdictStatus = 'CLEAR';
        explanation = `Correctly ignored. Your rule left this harmless command alone. Keep it that way as you tighten the rule.`;
      }
    } else if (!testCase.applicableToMatcher) {
      // This test is about a different check level (e.g. git hooks, not text rules)
      differentLayerCount++;
      verdictStatus = 'NOT_APPLICABLE';
      explanation = matchOutcome.matched
        ? `The text matches your rule, BUT this test is about ${testCase.layerNote || 'a different check level'}. If your real defense is a git hook, this still slips past it.`
        : `Does not match your rule, AND this tests ${testCase.layerNote || 'a different check level'}.`;
    } else {
      applicableTotal++;
      if (matchOutcome.matched) {
        applicableBlocked++;
        verdictStatus = 'BLOCKED';
        explanation = `Caught it. Your rule matched: ${matchOutcome.details}`;
      } else {
        applicableMissed++;
        verdictStatus = 'MISSED';
        explanation = deriveFailureReason(testCase, rule, mode);
      }
    }

    results.push({
      id: testCase.id,
      title: testCase.title,
      command: testCase.command,
      targetLayer: testCase.targetLayer,
      category: testCase.category,
      intent: testCase.intent,
      whyItMatters: testCase.whyItMatters,
      applicableToMatcher: testCase.applicableToMatcher,
      status: verdictStatus,
      matched: matchOutcome.matched,
      matcherDetails: matchOutcome.details,
      explanation
    });
  }

  const coveragePercent = applicableTotal > 0
    ? Math.round((applicableBlocked / applicableTotal) * 100)
    : 0;

  let verdictHeadline = 'Weak protection';
  let verdictClass = 'verdict-weak';
  let hardeningAdvice = '';

  if (syntaxError) {
    verdictHeadline = 'Your rule has an error';
    verdictClass = 'verdict-error';
    hardeningAdvice = `Fix the error in your rule: ${syntaxError}`;
  } else if (coveragePercent === 100) {
    if (falsePositives > 0) {
      verdictHeadline = 'Catches all — but overblocks';
      verdictClass = 'verdict-warning';
      hardeningAdvice = `100% attack coverage, but your rule also blocks ${falsePositives} innocent command${falsePositives === 1 ? '' : 's'}. A precise rule catches attacks without punishing normal work — narrow it until the false alarms disappear.`;
    } else {
      verdictHeadline = 'Strong on these tests';
      verdictClass = 'verdict-robust';
      hardeningAdvice = 'All 12 test cases caught. Note: git nicknames or shell tricks may still need checks beyond text matching.';
    }
  } else if (coveragePercent >= 75) {
    verdictHeadline = 'Mostly covered';
    verdictClass = 'verdict-moderate';
    hardeningAdvice = 'High coverage — but a few edge cases (like chained commands or full paths) still slip through.';
  } else if (coveragePercent >= 40) {
    verdictHeadline = 'Needs work';
    verdictClass = 'verdict-warning';
    hardeningAdvice = 'Your rule misses several common variations, like flags in between or wrapper commands.';
  } else {
    verdictHeadline = 'Weak protection';
    verdictClass = 'verdict-weak';
    hardeningAdvice = 'Your rule only catches the exact text. The same action written differently slips past easily.';
  }

  return {
    policyId: policy.id,
    policyName: policy.name,
    policyIntent: policy.intent,
    rule,
    mode,
    syntaxError,
    applicableTotal,
    applicableBlocked,
    applicableMissed,
    differentLayerCount,
    falsePositives,
    benignTotal,
    totalCases: policy.corpus.length,
    coveragePercent,
    verdictHeadline,
    verdictClass,
    hardeningAdvice,
    results
  };
}

/**
 * Explains WHY a particular command slipped past the rule
 */
function deriveFailureReason(testCase, rule, mode) {
  switch (testCase.category) {
    case 'Interleaved Flag':
      return `Your rule looks for "${rule}" as one piece, but flags like "-C" sit between the command and the action. The shell still runs it — the text is just split up.`;

    case 'Shell Chaining':
      return `The commit is joined to other commands with "&&" or ";". Rules that expect the command at the start of the line miss it because something else comes first.`;

    case 'Path Variation':
      return `Git is run with its full path ("/usr/bin/git"). A rule looking for plain "${rule}" misses it unless it strips the path first.`;

    case 'Dynamic Resolution':
      return `"$(which git)" is figured out by the shell right before running. A text rule cannot predict what it becomes.`;

    case 'Process Wrapper':
      return `The command is wrapped in something like "env". The first word is "env", while the real action hides behind it.`;

    case 'Syntactic Normalization':
      return `Extra spaces or tabs separate the words. An exact-text rule fails on unnormalized spacing.`;

    case 'Configuration Alias':
      return `Uses a short git nickname (like "ci"). The action is git commit, but the text only contains "ci" — the rule has no way to know.`;

    case 'Shell Escaping':
      return `A backslash ("\\git") is put in front to dodge nicknames. Rules expecting a plain "git" at the start miss it.`;

    case 'De-piping (Two-stage)':
      return `The download and the run are split into two separate commands via a temp file, so there is no "|" to match.`;

    case 'Process Substitution':
      return `Uses "<(...)" instead of a pipe, so rules looking for a pipe symbol miss it.`;

    default:
      return `Your rule checks the text ("${rule}"), but this command does the same thing written differently.`;
  }
}
