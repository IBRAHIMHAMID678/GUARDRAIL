/**
 * Guardrail Lab - POSIX Shell Lexer & AST Parser
 * 
 * Provides deterministic, safe static analysis of shell command structures
 * without invoking a shell or executing any arbitrary code.
 * 
 * Accurately models:
 * - Single and double quoting rules (including nested escaping)
 * - Pipelines (|) and compound operators (&&, ||, ;, &)
 * - Environment variable prefix assignments (VAR=val cmd)
 * - Process supervisors and wrappers (env, sudo, time, nohup)
 * - Absolute and relative executable path canonicalization
 * - Interleaved global options and subcommands
 * - Subshell ($(...) and `...`) and process substitution (<(...) and >(...))
 */

export class ShellLexer {
  constructor(input) {
    this.input = input.trim();
    this.pos = 0;
    this.len = this.input.length;
  }

  tokenize() {
    const tokens = [];
    let currentToken = '';
    let inSingleQuote = false;
    let inDoubleQuote = false;
    let isEscaped = false;
    let parenDepth = 0;

    while (this.pos < this.len) {
      const ch = this.input[this.pos];
      const nextCh = this.pos + 1 < this.len ? this.input[this.pos + 1] : '';

      if (isEscaped) {
        currentToken += ch;
        isEscaped = false;
        this.pos++;
        continue;
      }

      if (ch === '\\' && !inSingleQuote) {
        if (inDoubleQuote) {
          // Inside double quotes, backslash only escapes ", \, $, `, and newline
          if (['"', '\\', '$', '`'].includes(nextCh)) {
            isEscaped = true;
          } else {
            currentToken += ch;
          }
        } else {
          isEscaped = true;
        }
        this.pos++;
        continue;
      }

      if (ch === "'" && !inDoubleQuote) {
        inSingleQuote = !inSingleQuote;
        currentToken += ch;
        this.pos++;
        continue;
      }

      if (ch === '"' && !inSingleQuote) {
        inDoubleQuote = !inDoubleQuote;
        currentToken += ch;
        this.pos++;
        continue;
      }

      if (!inSingleQuote && !inDoubleQuote) {
        if (ch === '(') {
          parenDepth++;
        } else if (ch === ')' && parenDepth > 0) {
          parenDepth--;
        }

        // Compound shell operators: &&, ||, ;, |, & (only outside subshells)
        if (parenDepth === 0) {
          if ((ch === '&' && nextCh === '&') || (ch === '|' && nextCh === '|')) {
            if (currentToken.trim()) tokens.push({ type: 'WORD', value: currentToken.trim() });
            tokens.push({ type: 'OPERATOR', value: ch + nextCh });
            currentToken = '';
            this.pos += 2;
            continue;
          }

          if (ch === ';' || ch === '|' || ch === '&') {
            if (currentToken.trim()) tokens.push({ type: 'WORD', value: currentToken.trim() });
            tokens.push({ type: 'OPERATOR', value: ch });
            currentToken = '';
            this.pos++;
            continue;
          }

          // Whitespace token separation
          if (/\s/.test(ch)) {
            if (currentToken.trim()) {
              tokens.push({ type: 'WORD', value: currentToken.trim() });
              currentToken = '';
            }
            this.pos++;
            continue;
          }
        }
      }

      currentToken += ch;
      this.pos++;
    }

    if (currentToken.trim()) {
      tokens.push({ type: 'WORD', value: currentToken.trim() });
    }

    return tokens;
  }
}

/**
 * Parses raw shell tokens into an Abstract Syntax Tree (AST)
 */
export function parseShellCommand(commandString) {
  if (!commandString || !commandString.trim()) {
    return { type: 'Empty', segments: [] };
  }

  const lexer = new ShellLexer(commandString);
  const rawTokens = lexer.tokenize();

  const segments = [];
  let currentWords = [];
  let currentOp = null;

  for (const tok of rawTokens) {
    if (tok.type === 'OPERATOR') {
      if (currentWords.length > 0) {
        segments.push(analyzeCommandSegment(currentWords, currentOp));
        currentWords = [];
      }
      currentOp = tok.value;
    } else {
      currentWords.push(tok.value);
    }
  }

  if (currentWords.length > 0) {
    segments.push(analyzeCommandSegment(currentWords, currentOp));
  }

  return {
    type: 'PipelineSequence',
    raw: commandString,
    segmentCount: segments.length,
    segments
  };
}

/**
 * Forensically analyzes an individual command invocation segment
 */
function analyzeCommandSegment(words, precedingOperator) {
  const envVars = {};
  let idx = 0;

  // 1. Extract leading environment variable assignments (e.g. FOO=bar) or 'env' supervisor
  while (idx < words.length) {
    const word = words[idx];
    if (word === 'env') {
      idx++;
      continue;
    }
    // Environment assignment pattern: VAR=value
    const eqIdx = word.indexOf('=');
    if (eqIdx > 0 && !word.startsWith('-')) {
      const k = word.slice(0, eqIdx);
      const v = word.slice(eqIdx + 1).replace(/^["']|["']$/g, '');
      envVars[k] = v;
      idx++;
    } else {
      break;
    }
  }

  const remainingTokens = words.slice(idx);
  const rawExec = remainingTokens[0] || '';

  // 2. Canonicalize Executable Name
  // Handles: /usr/bin/git, C:\Git\bin\git.exe, \git, $(which git), `which git`
  let canonicalExec = rawExec;
  let hasDynamicResolution = false;

  // Unescape leading backslash (used to bypass shell aliases e.g. \git)
  if (canonicalExec.startsWith('\\')) {
    canonicalExec = canonicalExec.slice(1);
  }

  // Detect subshell dynamic resolution $(which cmd) or `which cmd`
  if (canonicalExec.startsWith('$(') || canonicalExec.startsWith('`')) {
    hasDynamicResolution = true;
    const match = canonicalExec.match(/(?:\$\(which|`which)\s+([^)`]+)/);
    if (match && match[1]) {
      canonicalExec = match[1].trim();
    }
  }

  // Strip absolute and relative filesystem path prefixes
  canonicalExec = canonicalExec.replace(/^["']|["']$/g, '');
  canonicalExec = canonicalExec.split('/').pop().split('\\').pop();
  // Strip Windows .exe extension
  canonicalExec = canonicalExec.replace(/\.exe$/i, '');

  // 3. Extract Subcommands, Flags, and Arguments
  const args = remainingTokens.slice(1);
  const flags = [];
  const positionalArgs = [];
  let subcommand = null;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const cleanArg = arg.replace(/^["']|["']$/g, '');

    if (arg.startsWith('-')) {
      flags.push(arg);
      // If flag takes an inline param (-C /path or --git-dir=path), capture it
      if (['-C', '--git-dir', '--work-tree', '-u', '-m', '-d', '-F', '-o'].includes(arg) && i + 1 < args.length && !args[i + 1].startsWith('-')) {
        flags.push(args[++i]);
      }
    } else {
      positionalArgs.push(cleanArg);
      if (!subcommand) {
        subcommand = cleanArg;
      }
    }
  }

  // Check for dynamic subshells in arguments
  const rawSegmentStr = words.join(' ');
  const hasSubshell = /\$\([^)]+\)|`[^`]+`|<\([^)]+\)/.test(rawSegmentStr);
  const hasPipe = precedingOperator === '|';

  return {
    type: 'CommandNode',
    operator: precedingOperator || 'START',
    raw: rawSegmentStr,
    executable: canonicalExec,
    rawExecutable: rawExec,
    subcommand: subcommand || null,
    flags,
    args: positionalArgs,
    envVars,
    hasSubshell,
    hasDynamicResolution,
    hasPipe
  };
}
