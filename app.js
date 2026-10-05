/**
 * GUARDRAIL / LAB — Instrument Controller
 * 
 * Orchestrates deterministic suite execution, rapid diagnostic progress ticker,
 * forensic evidence inspection, Before/After hardening tracking, and invariant verification.
 */

import { POLICIES } from './corpus.js';
import { evaluateSuite } from './evaluator.js';
import { runAllTests } from './test-engine.js';

// Application State
const state = {
  policyId: 'git-commit',
  mode: 'literal',
  rule: 'git commit',
  activeFilter: 'all',
  activeCaseId: 'TC-03', // Default to TC-03 so evidence is immediately visible on first load
  history: [],
  lastRunResult: null,
  isExecuting: false
};

// DOM References
const elements = {
  // Navigation & Pipeline
  navAttack: document.getElementById('nav-attack'),
  navEvidence: document.getElementById('nav-evidence'),
  navHarden: document.getElementById('nav-harden'),
  btnSelfTests: document.getElementById('btn-self-tests'),
  btnThemeToggle: document.getElementById('btn-theme-toggle'),

  // Form Controls
  policySelect: document.getElementById('policy-select'),
  policyDesc: document.getElementById('policy-desc'),
  modeSelect: document.getElementById('mode-select'),
  modeMeta: document.getElementById('mode-meta'),
  modeDesc: document.getElementById('mode-desc'),
  ruleInput: document.getElementById('rule-input'),
  ruleTypeIndicator: document.getElementById('rule-type-indicator'),
  ruleError: document.getElementById('rule-error'),
  controlStatus: document.getElementById('control-status'),

  // Presets & Actions
  presetNaive: document.getElementById('preset-naive'),
  presetRegex: document.getElementById('preset-regex'),
  presetHardened: document.getElementById('preset-hardened'),
  btnRun: document.getElementById('btn-run'),
  btnRunText: document.getElementById('btn-run-text'),
  diagnosticTicker: document.getElementById('diagnostic-ticker'),
  tickerStageText: document.getElementById('ticker-stage-text'),
  tickerProgressFill: document.getElementById('ticker-progress-fill'),

  // Telemetry Readout
  scorePct: document.getElementById('score-pct'),
  scoreFraction: document.getElementById('score-fraction'),
  verdictBanner: document.getElementById('verdict-banner'),
  meterMatcher: document.getElementById('meter-matcher'),
  meterShell: document.getElementById('meter-shell'),
  meterHook: document.getElementById('meter-hook'),

  // Filter Pills & Badges
  pillTabs: document.querySelectorAll('.pill-tab'),
  badgeMissed: document.getElementById('badge-missed'),
  badgeBlocked: document.getElementById('badge-blocked'),
  badgeNa: document.getElementById('badge-na'),

  // Test Runner List
  runnerList: document.getElementById('test-runner-list'),

  // Forensic Dossier
  dossierCaseId: document.getElementById('dossier-case-id'),
  dossierTitle: document.getElementById('dossier-title'),
  dossierBadge: document.getElementById('dossier-badge'),
  dossierCode: document.getElementById('dossier-code'),
  dossierMarker: document.getElementById('dossier-marker'),
  dossierPointerText: document.getElementById('dossier-pointer-text'),
  dossierIntent: document.getElementById('dossier-intent'),
  dossierLayer: document.getElementById('dossier-layer'),
  dossierMatters: document.getElementById('dossier-matters'),
  dossierExplanation: document.getElementById('dossier-explanation'),
  dossierHardening: document.getElementById('dossier-hardening'),

  // Hardening Timeline
  timelineBody: document.getElementById('timeline-body'),
  btnClearHistory: document.getElementById('btn-clear-history'),

  // Methodology Tabs
  methTabs: document.querySelectorAll('.meth-tab'),
  methPanes: document.querySelectorAll('.meth-pane'),

  // Invariant Modal
  modalSelfTests: document.getElementById('modal-self-tests'),
  btnCloseModal: document.getElementById('btn-close-modal'),
  btnDismissModal: document.getElementById('btn-dismiss-modal'),
  modalTestOutput: document.getElementById('modal-test-output'),
  modalTestSummary: document.getElementById('modal-test-summary')
};

/**
 * Initialize on DOM Ready
 */
function init() {
  bindEvents();
  loadPolicy(state.policyId);
  // Execute initial suite immediately so first viewport is populated
  executeSuiteImmediate();
}

/**
 * Event Bindings
 */
function bindEvents() {
  // Policy Select
  elements.policySelect.addEventListener('change', (e) => {
    loadPolicy(e.target.value);
    runSuiteWithTicker();
  });

  // Mode Select
  elements.modeSelect.addEventListener('change', (e) => {
    state.mode = e.target.value;
    updateModeUI();
    clearActivePreset();
  });

  // Rule Input
  elements.ruleInput.addEventListener('input', (e) => {
    state.rule = e.target.value;
    elements.ruleError.classList.add('hidden');
    clearActivePreset();
  });

  // Presets
  elements.presetNaive.addEventListener('click', () => {
    setActivePreset(elements.presetNaive);
    elements.modeSelect.value = 'literal';
    state.mode = 'literal';
    elements.ruleInput.value = state.policyId === 'git-commit' ? 'git commit' : 'curl | bash';
    state.rule = elements.ruleInput.value;
    updateModeUI();
    runSuiteWithTicker();
  });

  elements.presetRegex.addEventListener('click', () => {
    setActivePreset(elements.presetRegex);
    elements.modeSelect.value = 'regex';
    state.mode = 'regex';
    elements.ruleInput.value = state.policyId === 'git-commit' ? '^git\\s+commit' : 'curl\\b.*\\|\\s*(ba)?sh';
    state.rule = elements.ruleInput.value;
    updateModeUI();
    runSuiteWithTicker();
  });

  elements.presetHardened.addEventListener('click', () => {
    setActivePreset(elements.presetHardened);
    elements.modeSelect.value = 'structured';
    state.mode = 'structured';
    elements.ruleInput.value = state.policyId === 'git-commit' ? 'exec=git & subcmd=commit' : 'exec=curl & pipe=sh';
    state.rule = elements.ruleInput.value;
    updateModeUI();
    runSuiteWithTicker();
  });

  // Form submit / Run button
  document.getElementById('guardrail-form').addEventListener('submit', (e) => {
    e.preventDefault();
    state.rule = elements.ruleInput.value;
    runSuiteWithTicker();
  });

  // Filter Pills
  elements.pillTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      elements.pillTabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      state.activeFilter = tab.dataset.filter;
      renderRunnerRows();
    });
  });

  // Clear Timeline History
  elements.btnClearHistory.addEventListener('click', () => {
    state.history = [];
    renderHistoryTimeline();
  });

  // Methodology Tabs
  elements.methTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      elements.methTabs.forEach(t => t.classList.remove('active'));
      elements.methPanes.forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      const pane = document.getElementById(tab.dataset.pane);
      if (pane) pane.classList.add('active');
    });
  });

  // Self Tests Modal
  elements.btnSelfTests.addEventListener('click', openSelfTestsModal);
  elements.btnCloseModal.addEventListener('click', closeSelfTestsModal);
  elements.btnDismissModal.addEventListener('click', closeSelfTestsModal);
  elements.modalSelfTests.addEventListener('click', (e) => {
    if (e.target === elements.modalSelfTests) closeSelfTestsModal();
  });

  // Theme Toggle (Defaults to light theme)
  if (elements.btnThemeToggle) {
    elements.btnThemeToggle.addEventListener('click', () => {
      const current = document.documentElement.getAttribute('data-theme') || 'light';
      const next = current === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      localStorage.setItem('guardrail_theme', next);
      elements.btnThemeToggle.textContent = next === 'dark' ? '☼ LIGHT' : '◐ DARK';
    });

    const savedTheme = localStorage.getItem('guardrail_theme') || 'light';
    document.documentElement.setAttribute('data-theme', savedTheme);
    elements.btnThemeToggle.textContent = savedTheme === 'dark' ? '☼ LIGHT' : '◐ DARK';
  }
}

function setActivePreset(button) {
  document.querySelectorAll('.btn-preset').forEach(b => b.classList.remove('active'));
  if (button) button.classList.add('active');
}

function clearActivePreset() {
  document.querySelectorAll('.btn-preset').forEach(b => b.classList.remove('active'));
}

/**
 * Loads policy metadata into controls
 */
function loadPolicy(policyId) {
  state.policyId = policyId;
  const policy = POLICIES[policyId];
  if (!policy) return;

  elements.policyDesc.textContent = `Policy intent: ${policy.intent}`;
  elements.modeSelect.value = policy.defaultMode;
  state.mode = policy.defaultMode;
  elements.ruleInput.value = policy.defaultRule;
  state.rule = policy.defaultRule;

  if (policyId === 'git-commit') {
    elements.presetNaive.innerHTML = '<span class="chip-dot"></span> Naive Substring';
    elements.presetRegex.innerHTML = '<span class="chip-dot"></span> Anchored Regex';
    elements.presetHardened.innerHTML = '<span class="chip-dot"></span> Structured Token';
  } else {
    elements.presetNaive.innerHTML = '<span class="chip-dot"></span> Naive Pipe';
    elements.presetRegex.innerHTML = '<span class="chip-dot"></span> Regex Pipe';
    elements.presetHardened.innerHTML = '<span class="chip-dot"></span> Structured Pipe';
  }

  setActivePreset(elements.presetNaive);
  updateModeUI();
}

/**
 * Updates UI labels when mode changes
 */
function updateModeUI() {
  switch (state.mode) {
    case 'literal':
      elements.modeMeta.textContent = 'SUBSTRING';
      elements.ruleTypeIndicator.textContent = 'RAW BYTES';
      elements.modeDesc.textContent = 'Inspects command string for contiguous literal occurrence.';
      break;
    case 'regex':
      elements.modeMeta.textContent = 'ECMA REGEX';
      elements.ruleTypeIndicator.textContent = 'PATTERN';
      elements.modeDesc.textContent = 'Evaluates compiled regular expression against full command string.';
      break;
    case 'wildcard':
      elements.modeMeta.textContent = 'GLOB EXPANSION';
      elements.ruleTypeIndicator.textContent = 'GLOB PATTERN';
      elements.modeDesc.textContent = 'Translates wildcard glob (*, ?) into equivalent token filter.';
      break;
    case 'structured':
      elements.modeMeta.textContent = 'STRUCTURED PARSER';
      elements.ruleTypeIndicator.textContent = 'TOKEN QUERY';
      elements.modeDesc.textContent = 'Extracts executable and subcommand tokens (e.g. exec=git & subcmd=commit).';
      break;
  }
}

/**
 * Runs suite with a rapid diagnostic sequence ticker (giving genuine instrument feedback)
 */
function runSuiteWithTicker() {
  if (state.isExecuting) return;
  state.isExecuting = true;

  elements.controlStatus.textContent = 'TESTING...';
  elements.btnRun.disabled = true;
  elements.btnRunText.textContent = 'ANALYZING...';
  elements.diagnosticTicker.classList.remove('hidden');

  // Activate Stage 02 in Nav
  elements.navAttack.classList.add('active');

  const stages = [
    { text: '01/05 Checking exact syntax representation...', pct: '20%' },
    { text: '02/05 Checking flag reordering & parameter insertion...', pct: '45%' },
    { text: '03/05 Testing shell chaining & compound operators (&&, ;)...', pct: '70%' },
    { text: '04/05 Simulating executable resolution & wrappers (env, paths)...', pct: '90%' },
    { text: '05/05 Isolating Git hook layer boundaries...', pct: '100%' }
  ];

  let currentStage = 0;
  const interval = setInterval(() => {
    if (currentStage < stages.length) {
      elements.tickerStageText.textContent = stages[currentStage].text;
      elements.tickerProgressFill.style.width = stages[currentStage].pct;
      currentStage++;
    } else {
      clearInterval(interval);
      setTimeout(() => {
        executeSuiteImmediate();
        elements.diagnosticTicker.classList.add('hidden');
        elements.btnRun.disabled = false;
        elements.btnRunText.textContent = 'RUN ATTACK SUITE';
        elements.controlStatus.textContent = 'VERIFIED';
        state.isExecuting = false;
        // Activate Evidence Nav
        elements.navEvidence.classList.add('active');
        elements.navHarden.classList.add('active');
      }, 70);
    }
  }, 55);
}

/**
 * Executes evaluation suite synchronously
 */
function executeSuiteImmediate() {
  const policy = POLICIES[state.policyId];
  if (!policy) return;

  const outcome = evaluateSuite(policy, state.rule, state.mode);

  if (outcome.syntaxError) {
    elements.ruleError.textContent = `[SYNTAX FAULT] ${outcome.syntaxError}`;
    elements.ruleError.classList.remove('hidden');
  } else {
    elements.ruleError.classList.add('hidden');
  }

  recordHistorySnapshot(outcome);
  state.lastRunResult = outcome;

  renderTelemetry(outcome);
  renderRunnerRows();
  renderHistoryTimeline();

  // If activeCaseId exists, render its dossier
  if (state.activeCaseId) {
    const activeCase = outcome.results.find(r => r.id === state.activeCaseId) || outcome.results[0];
    if (activeCase) inspectDossier(activeCase);
  }
}

/**
 * Renders Top Telemetry Block
 */
function renderTelemetry(outcome) {
  elements.scorePct.textContent = `${outcome.coveragePercent}%`;
  elements.scoreFraction.textContent = `${outcome.applicableBlocked} / ${outcome.applicableTotal} APPLICABLE`;

  elements.verdictBanner.textContent = outcome.verdictHeadline;
  elements.verdictBanner.className = `verdict-tag ${outcome.verdictClass}`;

  // Layer Meters
  const matcherCases = outcome.results.filter(r => r.targetLayer === 'matcher');
  const matcherBlocked = matcherCases.filter(r => r.status === 'BLOCKED').length;
  elements.meterMatcher.textContent = `${matcherBlocked}/${matcherCases.length} BLOCKED`;

  const shellCases = outcome.results.filter(r => r.targetLayer === 'shell');
  const shellBlocked = shellCases.filter(r => r.status === 'BLOCKED').length;
  elements.meterShell.textContent = `${shellBlocked}/${shellCases.length} BLOCKED`;

  const hookCases = outcome.results.filter(r => r.targetLayer === 'hook');
  elements.meterHook.textContent = `${hookCases.length} NON-APPLICABLE`;

  // Badge Counts
  const missedCount = outcome.results.filter(r => r.status === 'MISSED').length;
  const blockedCount = outcome.results.filter(r => r.status === 'BLOCKED').length;
  const naCount = outcome.results.filter(r => r.status === 'NOT_APPLICABLE').length;

  elements.badgeMissed.textContent = missedCount;
  elements.badgeBlocked.textContent = blockedCount;
  elements.badgeNa.textContent = naCount;
}

/**
 * Renders the Runner Terminal Rows
 */
function renderRunnerRows() {
  elements.runnerList.innerHTML = '';
  if (!state.lastRunResult || !state.lastRunResult.results) return;

  const filtered = state.lastRunResult.results.filter(c => {
    if (state.activeFilter === 'all') return true;
    if (state.activeFilter === 'missed') return c.status === 'MISSED';
    if (state.activeFilter === 'blocked') return c.status === 'BLOCKED';
    if (state.activeFilter === 'not-applicable') return c.status === 'NOT_APPLICABLE';
    return true;
  });

  if (filtered.length === 0) {
    const emptyRow = document.createElement('div');
    emptyRow.style.padding = '14px';
    emptyRow.style.color = 'var(--text-muted)';
    emptyRow.style.fontFamily = 'var(--font-mono)';
    emptyRow.style.fontSize = '11px';
    emptyRow.textContent = `[EMPTY] No cases match active filter: ${state.activeFilter.toUpperCase()}`;
    elements.runnerList.appendChild(emptyRow);
    return;
  }

  filtered.forEach(tc => {
    const row = document.createElement('div');
    row.className = `runner-row ${tc.id === state.activeCaseId ? 'active-row' : ''}`;
    row.dataset.id = tc.id;

    // State Badge
    const stateEl = document.createElement('span');
    stateEl.className = `row-state ${getRowStateClass(tc.status)}`;
    stateEl.textContent = getRowStateLabel(tc.status);
    row.appendChild(stateEl);

    // ID
    const idEl = document.createElement('span');
    idEl.className = 'row-id';
    idEl.textContent = tc.id;
    row.appendChild(idEl);

    // Command
    const cmdEl = document.createElement('span');
    cmdEl.className = 'row-cmd';
    cmdEl.textContent = tc.command;
    row.appendChild(cmdEl);

    // Category
    const catEl = document.createElement('span');
    catEl.className = 'row-cat';
    catEl.textContent = tc.category;
    row.appendChild(catEl);

    // Layer
    const layerEl = document.createElement('span');
    layerEl.className = 'row-layer';
    layerEl.textContent = formatLayerUpper(tc.targetLayer);
    row.appendChild(layerEl);

    row.addEventListener('click', () => {
      document.querySelectorAll('.runner-row').forEach(r => r.classList.remove('active-row'));
      row.classList.add('active-row');
      inspectDossier(tc);
    });

    elements.runnerList.appendChild(row);
  });
}

/**
 * Populates Forensic Dossier (Evidence)
 */
function inspectDossier(tc) {
  state.activeCaseId = tc.id;

  elements.dossierCaseId.textContent = tc.id;
  elements.dossierTitle.textContent = tc.title;
  elements.dossierCode.textContent = tc.command;

  // Verdict Tag
  elements.dossierBadge.textContent = tc.status === 'NOT_APPLICABLE' ? 'HOOK LAYER (N/A)' : tc.status;
  elements.dossierBadge.className = `case-verdict-tag ${tc.status === 'BLOCKED' ? 'blocked' : tc.status === 'MISSED' ? 'missed' : 'na'}`;

  // Evidence Pointer & Marker
  setDossierPointer(tc);

  elements.dossierIntent.textContent = tc.intent;
  elements.dossierLayer.textContent = `${formatLayerUpper(tc.targetLayer)} (Control Level)`;
  elements.dossierMatters.textContent = tc.whyItMatters;
  elements.dossierExplanation.textContent = tc.explanation;

  // Hardening Guidance
  if (tc.status === 'BLOCKED') {
    elements.dossierHardening.textContent = 'This vector is intercepted by the current rule. Ensure subsequent rule hardening does not cause a regression on this baseline.';
  } else if (tc.status === 'NOT_APPLICABLE') {
    elements.dossierHardening.textContent = 'Control Layer Mismatch: A pre-commit hook bypass (--no-verify) cannot be solved by command pattern matching. This requires server-side repository branch protections and mandatory CI checks that agents cannot bypass.';
  } else {
    elements.dossierHardening.textContent = getDossierHardening(tc);
  }
}

/**
 * Configures the visual token pointer for the command
 */
function setDossierPointer(tc) {
  switch (tc.category) {
    case 'Interleaved Flag':
      elements.dossierPointerText.textContent = 'Parameter insertion (-C /repo) breaks contiguous string matching while remaining valid command invocation.';
      break;
    case 'Shell Chaining':
      elements.dossierPointerText.textContent = 'Compound operator (&& or ;) sequences previous commands, defeating start-of-line (^) anchors.';
      break;
    case 'Path Variation':
      elements.dossierPointerText.textContent = 'Absolute executable path (/usr/bin/git) alters binary token representation.';
      break;
    case 'Dynamic Resolution':
      elements.dossierPointerText.textContent = 'Subshell $(which git) evaluates at runtime in POSIX shell before process spawn.';
      break;
    case 'Process Wrapper':
      elements.dossierPointerText.textContent = 'Wrapper command (env) becomes the primary command token in the string.';
      break;
    case 'Syntactic Normalization':
      elements.dossierPointerText.textContent = 'Unnormalized whitespace/tabs split tokens without breaking shell argv.';
      break;
    case 'Configuration Alias':
      elements.dossierPointerText.textContent = 'Command relies on .gitconfig alias (ci -> commit). Matcher lacks Git internal config context.';
      break;
    default:
      elements.dossierPointerText.textContent = 'Syntactic representation differs from the pattern expected by the matcher.';
  }
}

function getDossierHardening(tc) {
  switch (tc.category) {
    case 'Interleaved Flag':
      return 'Harden from literal contiguous matching to Structured Token Parsing (exec=git & subcmd=commit), or allow interleaved flags in regex: ^git(\\s+--?[\\w-]+)*\\s+commit.';
    case 'Shell Chaining':
      return 'Decompose shell commands into individual pipeline stages before matching, rather than anchoring regex to the line start.';
    case 'Path Variation':
      return 'Normalize executable paths by extracting the basename (e.g. basename("/usr/bin/git") -> "git") prior to policy evaluation.';
    case 'Dynamic Resolution':
      return 'Subshells cannot be statically evaluated with certainty. Sandbox environments must disallow dynamic subshell substitution in automated tool arguments.';
    case 'Process Wrapper':
      return 'Strip known process supervisors (env, sudo, nohup) to isolate the target invocation payload.';
    case 'Syntactic Normalization':
      return 'Pre-process command strings by collapsing multiple whitespace/tab characters into a single space.';
    case 'Configuration Alias':
      return 'Defense cannot rely solely on command regexes. Enforce branch protection on GitHub/GitLab servers to disallow direct push/commit regardless of local alias.';
    default:
      return 'Adopt structured argument tokenization instead of single fragile regex strings.';
  }
}

function getRowStateClass(status) {
  switch (status) {
    case 'BLOCKED': return 'state-blocked';
    case 'MISSED': return 'state-missed';
    case 'NOT_APPLICABLE': return 'state-na';
    default: return '';
  }
}

function getRowStateLabel(status) {
  switch (status) {
    case 'BLOCKED': return '✓ BLOCKED';
    case 'MISSED': return '! MISSED';
    case 'NOT_APPLICABLE': return '— HOOK';
    default: return status;
  }
}

function formatLayerUpper(layer) {
  switch (layer) {
    case 'matcher': return 'MATCHER';
    case 'shell': return 'SHELL';
    case 'hook': return 'GIT HOOK';
    case 'git-config': return 'GIT ALIAS';
    default: return layer.toUpperCase();
  }
}

/**
 * Tracks Before vs After Timeline
 */
function recordHistorySnapshot(outcome) {
  const snapshot = {
    rule: outcome.rule,
    mode: outcome.mode,
    coverage: outcome.coveragePercent,
    blocked: outcome.applicableBlocked,
    total: outcome.applicableTotal
  };

  const last = state.history[state.history.length - 1];
  if (!last || last.rule !== snapshot.rule || last.mode !== snapshot.mode) {
    state.history.push(snapshot);
    if (state.history.length > 5) state.history.shift();
  }
}

/**
 * Renders the Before vs After Progression
 */
function renderHistoryTimeline() {
  if (state.history.length <= 1) {
    elements.timelineBody.innerHTML = `
      <div class="empty-timeline">
        Run test suite, modify rule to structured or regex, and retest to observe the empirical attack coverage delta.
      </div>
    `;
    return;
  }

  const before = state.history[0];
  const current = state.history[state.history.length - 1];
  const delta = current.coverage - before.coverage;
  const deltaSign = delta > 0 ? `+${delta}%` : `${delta}%`;
  const deltaColor = delta > 0 ? 'var(--c-blocked)' : delta < 0 ? 'var(--c-missed)' : 'var(--text-dim)';

  elements.timelineBody.innerHTML = `
    <div class="timeline-delta-block">
      <div class="timeline-col">
        <span class="delta-tag">BEFORE [${before.mode.toUpperCase()}]</span>
        <span class="delta-score">${before.coverage}% (${before.blocked}/${before.total})</span>
        <span class="delta-rule" title="${escapeHtml(before.rule)}">${escapeHtml(before.rule)}</span>
      </div>
      <div class="timeline-col highlight-current">
        <span class="delta-tag">CURRENT [${current.mode.toUpperCase()}]</span>
        <span class="delta-score" style="color: ${deltaColor};">${current.coverage}% [${deltaSign}]</span>
        <span class="delta-rule" title="${escapeHtml(current.rule)}">${escapeHtml(current.rule)}</span>
      </div>
    </div>
  `;
}

/**
 * Open Invariant Diagnostics Modal
 */
function openSelfTestsModal() {
  elements.modalSelfTests.classList.remove('hidden');
  elements.modalTestOutput.innerHTML = '';
  elements.modalTestSummary.textContent = 'RUNNING INVARIANTS...';

  const testReport = runAllTests();

  testReport.results.forEach(t => {
    const item = document.createElement('div');
    item.className = 'diag-item';
    item.innerHTML = `
      <span class="diag-icon ${t.passed ? 'pass' : 'fail'}">${t.passed ? '✓' : '✗'}</span>
      <span class="diag-name">${escapeHtml(t.name)}</span>
      <span class="diag-verdict ${t.passed ? 'pass' : 'fail'}">${t.message}</span>
    `;
    elements.modalTestOutput.appendChild(item);
  });

  elements.modalTestSummary.textContent = `${testReport.passed} / ${testReport.total} INVARIANTS VERIFIED (${testReport.allPassed ? '100% PASS' : 'FAILURES DETECTED'})`;
  elements.modalTestSummary.style.color = testReport.allPassed ? 'var(--c-blocked)' : 'var(--c-missed)';
}

function closeSelfTestsModal() {
  elements.modalSelfTests.classList.add('hidden');
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/[&<>'"]/g, 
    tag => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      "'": '&#39;',
      '"': '&quot;'
    }[tag] || tag)
  );
}

document.addEventListener('DOMContentLoaded', init);
