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
  let syntaxError = null;

  for (const testCase of policy.corpus) {
    const matchOutcome = evaluateMatcher(testCase.command, rule, mode, options);

    if (matchOutcome.error && !syntaxError) {
      syntaxError = matchOutcome.error;
    }

    let verdictStatus = 'MISSED'; // BLOCKED | MISSED | NOT_APPLICABLE
    let explanation = '';
    let layerClassification = testCase.targetLayer;

    if (!testCase.applicableToMatcher) {
      // Test specifically targets a different layer (e.g. Git pre-commit hooks, not command pattern filters)
      differentLayerCount++;
      verdictStatus = 'NOT_APPLICABLE';
      explanation = matchOutcome.matched
        ? `Command string matches your pattern, BUT this test targets the ${testCase.layerNote || 'different control layer'}. If your security boundary is a Git hook, this bypasses it regardless of pattern matching.`
        : `Does not match pattern, AND targets ${testCase.layerNote || 'different control layer'}.`;
    } else {
      applicableTotal++;
      if (matchOutcome.matched) {
        applicableBlocked++;
        verdictStatus = 'BLOCKED';
        explanation = `Correctly intercepted. Pattern successfully matched: ${matchOutcome.details}`;
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

  let verdictHeadline = 'WEAK ENFORCEMENT';
  let verdictClass = 'verdict-weak';
  let hardeningAdvice = '';

  if (syntaxError) {
    verdictHeadline = 'SYNTAX ERROR IN RULE';
    verdictClass = 'verdict-error';
    hardeningAdvice = `Fix the syntax error in your pattern: ${syntaxError}`;
  } else if (coveragePercent === 100) {
    verdictHeadline = 'ROBUST AGAINST THIS CORPUS';
    verdictClass = 'verdict-robust';
    hardeningAdvice = 'All 12 applicable corpus vectors blocked. Note: Repository aliases or dynamic subshells may still require runtime AST parsing or OS-level sandboxing.';
  } else if (coveragePercent >= 75) {
    verdictHeadline = 'MOSTLY COVERED (CORPUS-BOUND)';
    verdictClass = 'verdict-moderate';
    hardeningAdvice = 'High coverage, but edge cases (e.g. shell chaining or path indirection) still slip through.';
  } else if (coveragePercent >= 40) {
    verdictHeadline = 'NEEDS HARDENING';
    verdictClass = 'verdict-warning';
    hardeningAdvice = 'Literal/naive pattern misses multiple common operational variants like interleaved flags or wrappers.';
  } else {
    verdictHeadline = 'WEAK ENFORCEMENT';
    verdictClass = 'verdict-weak';
    hardeningAdvice = 'Rule only covers the exact trivial string representation. The underlying operation easily escapes.';
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
    totalCases: policy.corpus.length,
    coveragePercent,
    verdictHeadline,
    verdictClass,
    hardeningAdvice,
    results
  };
}

/**
 * Explains WHY a particular representation bypassed the matcher
 */
function deriveFailureReason(testCase, rule, mode) {
  switch (testCase.category) {
    case 'Interleaved Flag':
      return `The matcher searches for contiguous "${rule}", but flags like "-C" or "--git-dir" are placed between the command and subcommand. The shell executes git commit, but the string is fragmented.`;
    
    case 'Shell Chaining':
      return `The command is executed as part of a compound shell expression ("&&", ";", or "|"). Anchored patterns (e.g. "^${rule}") fail because the token is preceded by other commands.`;
    
    case 'Path Variation':
      return `The binary is invoked with an absolute path ("/usr/bin/git"). Simple string or prefix filters looking for bare "${rule}" fail without filesystem path resolution.`;
    
    case 'Dynamic Resolution':
      return `Dynamic subshell expression "$(which git)" evaluates at runtime in POSIX shells. Static string matchers cannot predict subshell resolution without shell AST execution.`;
    
    case 'Process Wrapper':
      return `Invoked through process wrappers like "env PATH=...". The leading command token is "env", while the executed payload is the restricted operation.`;
    
    case 'Syntactic Normalization':
      return `Whitespace, tabs, or non-breaking spaces separate command tokens. A literal substring fails to match unnormalized whitespace.`;
    
    case 'Configuration Alias':
      return `Uses a short git alias (e.g. "git ci"). The operation is git commit, but the CLI string contains only "ci". The matcher lacks Git configuration context.`;
    
    case 'Shell Escaping':
      return `Prefixed with a backslash ("\\git") to bypass shell aliases. Matches expecting unescaped binary tokens are evaded.`;
    
    case 'De-piping (Two-stage)':
      return `Splits download and execution into two separate commands via intermediate file, completely avoiding pipeline tokens ("|").`;
    
    case 'Process Substitution':
      return `Uses bash process substitution "<(...)" instead of a standard pipe, evading pipe-symbol matchers.`;

    default:
      return `The matcher evaluates syntax representation ("${rule}"), but this command expresses the identical operation using an alternative syntax representation.`;
  }
}
