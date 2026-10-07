# GUARDRAIL / LAB
> **Adversarial AI Coding Agent Permission Firewall & 3D Defense Interceptor**

[![Invariants Passing](https://img.shields.io/badge/Engine%20Invariants-21%2F21%20Passing-10b981?style=flat-square)](file:///d:/GUARDRAIL%20LAB/test-engine.js)
[![Zero External Runtime Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Pure%20ES6)-4f46e5?style=flat-square)](file:///d:/GUARDRAIL%20LAB/package.json)
[![Evaluation Model](https://img.shields.io/badge/Evaluation-100%25%20Deterministic%20AST-059669?style=flat-square)](file:///d:/GUARDRAIL%20LAB/ast-parser.js)
[![Theme](https://img.shields.io/badge/Theme-Modern%20Light%20Studio-0ea5e9?style=flat-square)](file:///d:/GUARDRAIL%20LAB/style.css)

![Guardrail Lab 3D Studio](assets/guardrail_lab_3d_studio.png)

A deterministic, client-side adversarial test harness and interactive 3D WebGL simulator designed to expose and fix the critical flaw in AI coding agent guardrails: **confusing naive string/regex blocklists with POSIX shell execution semantics.**

---

## 1. The Core Problem

When engineers deploy autonomous AI coding agents (**Claude Code**, **Cursor**, **Copilot**, **Aider**), they configure shell permissions using simple string or regex blocklists:
- **Developer Intent:** *"Prevent the agent from committing code or wiping directories directly."*
- **Implemented Guardrail:** `git commit` or `rm -rf`

The engineer assumes: **"The guardrail blocks git commits."**  
The mathematical reality: **"The guardrail only blocks this specific contiguous 10-byte ASCII sequence."**

In POSIX shell environments, an identical operation can be expressed in dozens of valid syntactic representations:

```bash
git -C /repo commit -m "fix"               # Interleaved global flags (breaks literal sequence)
echo ok && git commit                      # Compound shell pipeline chaining
/usr/bin/git commit                        # Absolute filesystem path
env PATH="$PATH" git commit                # Environment / process wrapper
$(which git) commit                        # Runtime subshell command substitution
"git" commit                               # Quote character evasion
eval $(echo git) commit                    # Dynamic eval indirection
```

A standard regex or substring matcher fails against **over 70%** of realistic evasion vectors. **Guardrail Lab allows you to simulate, visualize, and harden these defenses before an agent breaches your system.**

---

## 2. Interactive 3D Physical Defense Air-Gap

![Guardrail Lab Attack Matrix](assets/guardrail_lab_attack_matrix.png)

Guardrail Lab visualizes command execution as a **physical 3D WebGL security pipeline**:

```
[ 🤖 AI AGENT TERMINAL ] ===(Command Projectile)===> [ 🛡️ QUANTUM DEFENSE SHIELD ] ===(If Bypassed)===> [ 🔒 PROTECTED SERVER ]
     (Left Node)                                            (Center Forcefield)                                (Right Node)
```

- **Interactive Firing Simulation**: Enter any shell command or click a quick-attack chip (`⚡ Flag Insertion`, `⚡ Chained &&`, `⚡ Subshell`, `⚡ Env Wrapper`, `⚡ Quote Evasion`).
- **Real-Time Physics**:
  - **Hardened AST Mode (Blocked)**: The 3D projectile slams into the crystalline quantum shield, ricochets backward, and detonates into an emerald spark shower with an expanding circular shockwave (`[🛡️ INTERCEPTED]`).
  - **Naive Regex Mode (Bypassed)**: The projectile slips through the porous forcefield and crashes directly into the Protected Server Core, triggering a flashing crimson alert wave (`[⚠️ BREACH]`).
- **Light Studio Aesthetics**: Built with Three.js WebGL studio lighting (`HemisphereLight` + directional key lights, soft studio floor grid, transparent canvas, crystal refractive materials).

---

## 3. The 6 Security Policies & 49 Curated Vectors

Guardrail Lab includes 6 OWASP-mapped agent threat domains with 49 rigorously curated adversarial test vectors:

| Policy | Intent | Industry Naive Matcher | Hardened POSIX AST Rule | Corpus Vectors |
| :--- | :--- | :--- | :--- | :--- |
| **📦 Git Commit** | Prevent unreviewed commits | `git commit` | `exec=git & subcmd=commit` | 14 vectors |
| **⚡ Remote Scripts** | Block curl-piped shell execution | `curl.*\|.*bash` | `exec=curl & pipe=bash \| sh` | 7 vectors |
| **🗑️ Filesystem Wipe** | Prevent destructive file wipes | `rm -rf` | `exec=rm & flag=-r & flag=-f` | 8 vectors |
| **🔑 Exfiltration** | Block credential leaks via network | `curl.*\.env` | `exec=curl \| wget & arg=*.env` | 7 vectors |
| **🐚 Reverse Shell** | Prevent socket hijacks | `bash -i.*tcp` | `exec=bash & flag=-i & arg=*/dev/tcp*` | 7 vectors |
| **🔒 Sudo Escalation**| Block unauthorized root escalation | `sudo su` | `exec=sudo & subcmd=su \| -i` | 6 vectors |

---

## 4. Architectural Mitigation: Deterministic POSIX AST Engine

Rather than relying on non-deterministic LLM judges, Guardrail Lab uses an auditable, client-side **POSIX Shell AST Tokenizer** (`ast-parser.js`):
1. **Lexical Splitting with Quote Preservation**: Correctly handles single quotes (`'...'`), double quotes (`"..."`), and escape sequences (`\ `).
2. **Subshell Nesting Tracking**: Tracks parenthesis depth (`parenDepth`) so subshell substitutions like `$(which git)` remain intact for isolated sub-evaluation.
3. **Pipeline & Compound Decomposition**: Recursively splits commands across `&&`, `||`, `;`, and `|`.
4. **Binary & Flag Normalization**: Strips wrapper prefixes (`env`, `sudo`, `time`), extracts the canonical base executable name, normalizes combined flags (`-rf` -> `-r`, `-f`), and extracts subcommands (`commit`, `clone`, `checkout`).

---

## 5. One-Click Production Exporters

Once your guardrail is verified, click **`Export Guardrail`** to copy ready-to-deploy configuration for your agent environment:

- **Claude Code**: Terminal command hook (`config.json`)
- **Cursor IDE**: System prompt constraint (`.cursorrules`)
- **AgentSH**: Zero-trust bash agent filter (`agentsh.yaml`)
- **POSIX Bash Hook**: Drop-in `.bashrc` / `preexec` deterministic wrapper script
- **Docker / Seccomp**: Container syscall and capability restrictions

---

## 6. Verified Invariant Self-Tests

Guardrail Lab includes an automated self-test suite (`test-engine.js`) verifying 21 core engine invariants:
- Exact match detection
- Flag insertion breaking naive matchers
- Graceful handling of invalid regex syntax (no exceptions)
- Hook-layer isolation (marking `--no-verify` as `NOT_APPLICABLE` to matchers)
- Deterministic idempotency across repeated executions
- Case normalization and case-sensitive overrides
- Wildcard glob expansion (`*` and `?`)
- AST executable and subcommand extraction
- Quoted string preservation across pipeline operators
- Piping detection (`curl | bash`)
- Combined flag normalization (`-fr` matching `flag=-r & flag=-f`)
- Full evaluation across all 6 policies

Run the test suite locally via Node:
```bash
node test-engine.js
```
Output:
```
--- Running Guardrail Lab Engine Self-Tests ---
[✓] Exact match detected in literal mode: PASS
[✓] Flag insertion breaks literal match: PASS
[✓] Invalid regex handled safely without exception: PASS
[✓] Hook bypass flag TC-10 marked as NOT_APPLICABLE to matcher: PASS
...
Result: 21/21 tests passed.
```

---

## 7. Running Locally

Serve the repository with any local static HTTP server:

```bash
# Python 3
python -m http.server 8080

# Or Node.js
npx serve .
```

Open your browser to:
```
http://localhost:8080/
```

Zero external build steps. Pure standards-compliant ES6 JavaScript modules, HTML5, and CSS3.
