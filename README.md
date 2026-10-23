# GUARDRAIL LAB
> **Agent Permission Firewall Test Bench & 3D Defense Interceptor**

[![Invariants Passing](https://img.shields.io/badge/Engine%20Invariants-21%2F21%20Passing-10b981?style=flat-square)](file:///d:/GUARDRAIL%20LAB/test-engine.js)
[![Zero External Runtime Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Pure%20ES6)-4f46e5?style=flat-square)](file:///d:/GUARDRAIL%20LAB/package.json)
[![Evaluation Model](https://img.shields.io/badge/Evaluation-100%25%20Deterministic%20AST-059669?style=flat-square)](file:///d:/GUARDRAIL%20LAB/ast-parser.js)
[![Design](https://img.shields.io/badge/Design-Editorial%20Light%20Studio-111827?style=flat-square)](file:///d:/GUARDRAIL%20LAB/style.css)

![Guardrail Lab Hero Interface](screenshots/guardrail_lab_hero_ui.png)

---

## About Guardrail Lab

**Guardrail Lab** is a client-side adversarial test bench and 3D WebGL physical simulator designed to expose and fix the critical flaw in AI coding agent guardrails: **confusing naive string/regex blocklists with POSIX shell execution semantics.**

When engineering teams configure permission rules for autonomous coding agents (**Claude Code**, **Cursor**, **Copilot**, **Aider**, **Devin**), they often set basic string filters like `git commit` or `rm -rf`. 

While the developer intends to *"prevent unreviewed git commits"*, a naive filter only blocks that exact contiguous ASCII byte sequence. In real-world POSIX environments, an agent running a shell can bypass these naive blocklists with ease:

```bash
git -C /repo commit -m "bypass"             # Interleaved flags (-C breaks string continuity)
echo ok && git commit                      # Compound shell pipeline chaining
/usr/bin/git commit                        # Absolute path execution
env PATH="$PATH" git commit                # Process wrapper
$(which git) commit                        # Runtime subshell command substitution
"git" commit                               # Quote evasion
```

Guardrail Lab enables developers and security engineers to test, visualize, and auto-harden their AI permission boundaries against real POSIX syntax using a deterministic in-memory AST parser.

---

## Screenshots of the Interface

### 1. Test Bench & Policy Selector
The clean editorial dashboard showing real-time metrics across 32 adversarial vectors and 6 OWASP-mapped threat policies:
![Hero UI](screenshots/guardrail_lab_hero_ui.png)

### 2. 3D Defense Interceptor & Attack Matrix
Real-time 3D WebGL forcefield simulation showing projectile deflections vs breach explosions alongside the live WAF event stream and forensic case dossier:
![3D Defense & Matrix](screenshots/guardrail_lab_3d_matrix.png)

### 3. One-Click Production Exporter
Export hardened guardrails ready for deployment to Claude Code, Cursor, agentsh, Bash wrappers, and Docker/Seccomp:
![Export Modal](screenshots/guardrail_lab_export_modal.png)

---

## Core Capabilities

- **Deterministic In-Memory POSIX AST Engine**: Recursively parses command strings into discrete execution units, normalizing paths, flags, wrappers, subshells, and pipelines.
- **Physical 3D WebGL Interceptor Theater**: Visualizes AI agent command execution as real-time kinetic projectiles fired into a crystalline quantum defense shield.
- **Side-by-Side Dual Engine Workbench**: Test any payload simultaneously against a naive substring matcher and a hardened POSIX AST tokenizer.
- **Autonomous Red-Team Adversary Duel**: Launch an escalating 5-stage automated assault with live streaming terminal thoughts and procedural Web Audio FX.
- **WAF Security Event Matrix & Forensic Dossier**: In-depth breakdown explaining why each syntactic transformation evades naive filters and how AST parsing mitigates it.
- **Zero Runtime Dependencies**: Written entirely in pure, standards-compliant ES6 JavaScript, HTML5, CSS3, and Three.js.

---

## The 6 Security Policies & Benchmark Vectors

| Policy | Intent | Industry Naive Matcher | Hardened POSIX AST Rule | Evasion Vectors |
| :--- | :--- | :--- | :--- | :--- |
| **📦 Git commit** | Prevent unreviewed commits | `git commit` | `exec=git & subcmd=commit` | 8 vectors |
| **⚡ Remote scripts** | Block curl piped to bash/sh | `curl.*\|.*bash` | `exec=curl & pipe=bash \| sh` | 5 vectors |
| **🗑️ Filesystem wipes** | Prevent destructive file wipes | `rm -rf` | `exec=rm & flag=-r & flag=-f` | 6 vectors |
| **🔑 Exfiltration** | Block credential leaks via network | `curl.*\.env` | `exec=curl \| wget & arg=*.env` | 5 vectors |
| **🐚 Reverse shell** | Prevent socket hijacks | `bash -i.*tcp` | `exec=bash & flag=-i & arg=*/dev/tcp*` | 4 vectors |
| **🔒 Privilege escalation**| Block root escalation | `sudo su` | `exec=sudo & subcmd=su \| -i` | 4 vectors |

---

## Production Exporters

Once verified, click **`Export`** to generate production-ready configuration profiles:

- **Claude Code**: Pre-tool execution deny policy (`config.json`)
- **Cursor IDE**: System prompt operational constraint (`.cursorrules`)
- **AgentSH**: Zero-trust bash agent filter (`agentsh.yaml`)
- **POSIX Bash Hook**: Drop-in `.bashrc` / `preexec` deterministic wrapper script
- **Docker / Seccomp**: Container syscall and capability restrictions

---

## 21 Invariant Self-Tests

Guardrail Lab includes an automated deterministic test suite verifying 21 engine invariants:

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
[✓] TC-01 exact invocation marked as BLOCKED: PASS
[✓] TC-03 interleaved flag marked as MISSED in literal mode: PASS
[✓] Deterministic idempotency: identical runs yield identical output: PASS
[✓] Case insensitive matching functions by default: PASS
[✓] Case sensitive matching rejects uppercase when enabled: PASS
[✓] Wildcard glob "git * commit" matches interleaved string: PASS
[✓] Wildcard glob rejects non-matching prefix: PASS
[✓] Tokenizer extracts base executable and subcommand across env and paths: PASS
[✓] Structured matcher blocks interleaved flag: PASS
[✓] Quoted string containing && is preserved as single command segment: PASS
[✓] Structured matcher detects curl piped to bash: PASS
[✓] Combined flags -fr matches discrete flag=-r and flag=-f conditions: PASS
[✓] rm-rf policy evaluates 8 test cases correctly: PASS
[✓] curl-bash policy evaluates 7 test cases correctly: PASS
[✓] Dynamic resolution $(which git) flagged in AST node: PASS
[✓] secret-exfil policy evaluates 7 test cases correctly: PASS
[✓] reverse-shell policy evaluates 7 test cases correctly: PASS

Result: 21/21 tests passed.
```

---

## Running Locally

Serve the repository with any local static HTTP server:

```bash
# Using Node.js
npx serve .

# Or Python 3
python -m http.server 8080
```

Open your browser to:
```
http://localhost:8080/
```

Zero build steps required. Pure native web technologies.
