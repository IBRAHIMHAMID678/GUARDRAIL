/**
 * Guardrail Lab - Matcher Engine
 * 
 * Implements deterministic matching models without external dependencies:
 * - Literal Substring
 * - Safe Regular Expression (with syntax validation)
 * - Wildcard Glob Pattern (* and ?)
 * - Structured Command Tokenizer (Demonstrates parser-based hardening)
 */

/**
 * Validates and tests an input command string against a user-defined rule and mode.
 * Returns { matched: boolean, error: string|null, details: string }
 */
export function evaluateMatcher(command, rule, mode, options = { caseSensitive: false }) {
  if (!rule || rule.trim() === '') {
    return { matched: false, error: 'Empty guardrail rule provided', details: 'No rule pattern to evaluate' };
  }

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
          : `Contiguous substring "${cleanRule}" was not found in string`
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
            : `Failed regex pattern /${rule}/${flags}`
        };
      } catch (err) {
        return {
          matched: false,
          error: `Invalid Regular Expression: ${err.message}`,
          details: 'Evaluation halted due to regex syntax error'
        };
      }
    }

    case 'wildcard': {
      try {
        // Convert wildcard glob (* -> .*, ? -> .) safely
        // Escape special regex chars except * and ?
        const escaped = cleanRule.replace(/[.+^${}()|[\]\\]/g, '\\$&');
        const globRegexStr = escaped.replace(/\*/g, '.*').replace(/\?/g, '.');
        const rx = new RegExp(globRegexStr, options.caseSensitive ? '' : 'i');
        const isMatched = rx.test(command);
        return {
          matched: isMatched,
          error: null,
          details: isMatched
            ? `Matches wildcard glob "${rule}" (expanded to /${globRegexStr}/)`
            : `Failed wildcard glob "${rule}"`
        };
      } catch (err) {
        return {
          matched: false,
          error: `Wildcard translation error: ${err.message}`,
          details: 'Could not construct wildcard matcher'
        };
      }
    }

    case 'structured': {
      // Structured command token model:
      // Accepts key-value tokens, e.g.: "exec=git & subcmd=commit"
      // Or auto-tokenizes standard CLI commands and verifies executable & subcommand
      return evaluateStructuredRule(command, rule);
    }

    default:
      return {
        matched: false,
        error: `Unknown matcher mode: ${mode}`,
        details: 'Mode unsupported'
      };
  }
}

/**
 * Tokenizes a shell command safely without execution.
 * Splits into pipeline stages or command segments, then strips global wrappers/env.
 */
export function tokenizeCommand(command) {
  // Simple deterministic tokenization aware of common wrappers
  // Handles: /usr/bin/git, env VAR=val git, \git, $(which git)
  const segments = command.split(/&&|\|\||;|\|/).map(s => s.trim()).filter(Boolean);
  
  const analyzedSegments = segments.map(seg => {
    // Normalization: clean leading backslash, handle env prefixes
    let tokens = seg.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g) || [];
    tokens = tokens.map(t => t.replace(/^["']|["']$/g, ''));

    // Strip leading env vars or 'env' command
    let idx = 0;
    while (idx < tokens.length) {
      const tok = tokens[idx];
      if (tok === 'env' || tok.includes('=')) {
        idx++;
      } else {
        break;
      }
    }
    const filteredTokens = tokens.slice(idx);
    
    // Extract base executable
    let rawExec = filteredTokens[0] || '';
    // Strip leading backslash or absolute path
    let execName = rawExec.replace(/^\\/, '').split('/').pop().split('\\').pop();
    if (execName.startsWith('$(') && execName.includes('which ')) {
      execName = execName.replace(/\$\(which\s+([^)]+)\)/, '$1').trim();
    }

    // Extract potential subcommands and options
    const args = filteredTokens.slice(1);
    let subcmd = null;
    const flags = [];

    for (let i = 0; i < args.length; i++) {
      const arg = args[i];
      if (arg.startsWith('-')) {
        flags.push(arg);
        // If flag takes an inline param (-C /path or --git-dir=path), skip next if separated
        if ((arg === '-C' || arg === '--git-dir' || arg === '-u') && i + 1 < args.length && !args[i + 1].startsWith('-')) {
          flags.push(args[++i]);
        }
      } else if (!subcmd) {
        subcmd = arg;
      }
    }

    return {
      raw: seg,
      executable: execName,
      subcommand: subcmd,
      flags,
      tokens: filteredTokens
    };
  });

  return analyzedSegments;
}

/**
 * Evaluates a structured rule against tokenized segments.
 * Rule syntax: "exec=git & subcmd=commit"
 */
function evaluateStructuredRule(command, rule) {
  const segments = tokenizeCommand(command);
  const conditions = rule.split('&').map(c => c.trim().toLowerCase());

  // Check if ANY pipeline/compound segment matches all structured conditions
  for (const seg of segments) {
    let segmentMatchesAll = true;

    for (const cond of conditions) {
      const [key, val] = cond.split('=').map(s => s?.trim());
      if (!key || !val) continue;

      if (key === 'exec' || key === 'executable') {
        if (seg.executable.toLowerCase() !== val.toLowerCase()) {
          segmentMatchesAll = false;
          break;
        }
      } else if (key === 'subcmd' || key === 'subcommand') {
        if (!seg.subcommand || seg.subcommand.toLowerCase() !== val.toLowerCase()) {
          segmentMatchesAll = false;
          break;
        }
      } else if (key === 'flag') {
        const hasFlag = seg.flags.some(f => f.toLowerCase() === val.toLowerCase());
        if (!hasFlag) {
          segmentMatchesAll = false;
          break;
        }
      }
    }

    if (segmentMatchesAll) {
      return {
        matched: true,
        error: null,
        details: `Structured parser identified executable="${seg.executable}" and subcommand="${seg.subcommand}" matching rule conditions`
      };
    }
  }

  return {
    matched: false,
    error: null,
    details: `Parsed command tokens did not satisfy structured condition: ${rule}`
  };
}
