/**
 * Guardrail Lab - Matcher Engine
 * 
 * Implements deterministic matching models without external dependencies:
 * - Literal Substring
 * - Safe Regular Expression (with syntax validation)
 * - Wildcard Glob Pattern (* and ?)
 * - Structured Command Tokenizer (AST-based parser hardening)
 */

import { parseShellCommand } from './ast-parser.js';

/**
 * Validates and tests an input command string against a user-defined rule and mode.
 * Returns { matched: boolean, error: string|null, details: string, ast: object }
 */
export function evaluateMatcher(command, rule, mode, options = { caseSensitive: false }) {
  if (!rule || rule.trim() === '') {
    return { matched: false, error: 'Empty guardrail rule provided', details: 'No rule pattern to evaluate', ast: null };
  }

  const ast = parseShellCommand(command);
  const cleanCommand = options.caseSensitive ? command : command.toLowerCase();
  const cleanRule = options.caseSensitive ? rule : rule.toLowerCase();

  switch (mode) {
    case 'literal': {
      const isMatched = cleanCommand.includes(cleanRule);
      return {
        matched: isMatched,
        error: null,
        details: isMatched
          ? `Contains exact literal substring "${cleanRule}"`
          : `Contiguous substring "${cleanRule}" was not found in string`,
        ast
      };
    }

    case 'regex': {
      try {
        const flags = options.caseSensitive ? '' : 'i';
        const rx = new RegExp(rule, flags);
        const isMatched = rx.test(command);
        return {
          matched: isMatched,
          error: null,
          details: isMatched
            ? `Matches regular expression /${rule}/${flags}`
            : `Failed regex pattern /${rule}/${flags}`,
          ast
        };
      } catch (err) {
        return {
          matched: false,
          error: `Invalid Regular Expression: ${err.message}`,
          details: 'Evaluation halted due to regex syntax error',
          ast
        };
      }
    }

    case 'wildcard': {
      try {
        const escaped = cleanRule.replace(/[.+^${}()|[\]\\]/g, '\\$&');
        const globRegexStr = escaped.replace(/\*/g, '.*').replace(/\?/g, '.');
        const rx = new RegExp(globRegexStr, options.caseSensitive ? '' : 'i');
        const isMatched = rx.test(command);
        return {
          matched: isMatched,
          error: null,
          details: isMatched
            ? `Matches wildcard glob "${rule}" (expanded to /${globRegexStr}/)`
            : `Failed wildcard glob "${rule}"`,
          ast
        };
      } catch (err) {
        return {
          matched: false,
          error: `Wildcard translation error: ${err.message}`,
          details: 'Could not construct wildcard matcher',
          ast
        };
      }
    }

    case 'structured': {
      return evaluateStructuredRuleWithAst(command, rule, ast);
    }

    default:
      return {
        matched: false,
        error: `Unknown matcher mode: ${mode}`,
        details: 'Mode unsupported',
        ast
      };
  }
}

/**
 * Evaluates a structured rule against the parsed AST nodes.
 * Supports conditions connected by '&', where condition values can use '|' (OR).
 * Examples:
 * - "exec=git & subcmd=commit"
 * - "exec=rm & flag=-r & flag=-f"
 * - "exec=curl|wget & pipe=bash|sh"
 * - "exec=curl|wget|nc & arg=.env|.ssh"
 */
function evaluateStructuredRuleWithAst(command, rule, ast) {
  const conditions = rule.split('&').map(c => c.trim().toLowerCase());
  const segments = ast.segments || [];

  // Check if ANY pipeline/compound segment satisfies the rule conditions
  for (let sIdx = 0; sIdx < segments.length; sIdx++) {
    const seg = segments[sIdx];
    let segmentMatchesAll = true;
    const matchReasons = [];

    for (const cond of conditions) {
      const [key, rawVal] = cond.split('=').map(s => s?.trim());
      if (!key || !rawVal) continue;

      const allowedValues = rawVal.split('|').map(v => v.trim().toLowerCase());

      if (key === 'exec' || key === 'executable') {
        const segExec = seg.executable.toLowerCase();
        if (!allowedValues.includes(segExec)) {
          segmentMatchesAll = false;
          break;
        }
        matchReasons.push(`exec=${seg.executable}`);
      } else if (key === 'subcmd' || key === 'subcommand') {
        const segSubcmd = (seg.subcommand || '').toLowerCase();
        if (!allowedValues.includes(segSubcmd)) {
          segmentMatchesAll = false;
          break;
        }
        matchReasons.push(`subcmd=${seg.subcommand}`);
      } else if (key === 'flag') {
        // Check if any flag matches the value
        const hasFlag = seg.flags.some(f => {
          const cleanF = f.toLowerCase();
          return allowedValues.some(val => {
            // Check combined flags e.g. -rf contains -r and -f
            if (val.startsWith('-') && !val.startsWith('--') && cleanF.startsWith('-') && !cleanF.startsWith('--')) {
              const charNeeded = val.replace('-', '');
              return cleanF.includes(charNeeded);
            }
            return cleanF === val;
          });
        });
        if (!hasFlag) {
          segmentMatchesAll = false;
          break;
        }
        matchReasons.push(`flag satisfies ${rawVal}`);
      } else if (key === 'arg') {
        // Check if any positional or raw arg contains the pattern
        const hasArg = seg.args.some(a => allowedValues.some(val => a.toLowerCase().includes(val))) ||
                       seg.flags.some(f => allowedValues.some(val => f.toLowerCase().includes(val))) ||
                       allowedValues.some(val => seg.raw.toLowerCase().includes(val));
        if (!hasArg) {
          segmentMatchesAll = false;
          break;
        }
        matchReasons.push(`arg satisfies ${rawVal}`);
      } else if (key === 'pipe') {
        // Checks if this command or the next piped segment matches allowed pipeline target
        const nextSeg = segments[sIdx + 1];
        const nextIsPipe = nextSeg && nextSeg.hasPipe;
        const matchesTarget = nextIsPipe && allowedValues.includes(nextSeg.executable.toLowerCase());
        if (!matchesTarget) {
          segmentMatchesAll = false;
          break;
        }
        matchReasons.push(`pipe=${nextSeg.executable}`);
      }
    }

    if (segmentMatchesAll) {
      return {
        matched: true,
        error: null,
        details: `Structured AST parser matched executable="${seg.executable}" [${matchReasons.join(', ')}]`,
        ast
      };
    }
  }

  return {
    matched: false,
    error: null,
    details: `Parsed ${segments.length} AST segments; none satisfied all structured conditions: ${rule}`,
    ast
  };
}

/**
 * Tokenizes a shell command safely without execution.
 * Backwards compatibility helper for existing callers and test runner.
 */
export function tokenizeCommand(command) {
  const ast = parseShellCommand(command);
  return ast.segments.map(seg => ({
    raw: seg.raw,
    executable: seg.executable,
    subcommand: seg.subcommand,
    flags: seg.flags,
    tokens: [seg.rawExecutable, ...seg.flags, ...seg.args]
  }));
}
