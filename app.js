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
  activeCaseId: 'TC-03', // Default to TC-03 so case details are immediately visible on first load
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
  fpFraction: document.getElementById('fp-fraction'),
  fpWarn: document.getElementById('fp-warn'),
  meterMatcher: document.getElementById('meter-matcher'),
  meterShell: document.getElementById('meter-shell'),
  meterHook: document.getElementById('meter-hook'),
  utcClock: document.getElementById('utc-clock'),

  // Filter Pills & Badges
  pillTabs: document.querySelectorAll('.pill-tab'),
  badgeMissed: document.getElementById('badge-missed'),
  badgeBlocked: document.getElementById('badge-blocked'),
  badgeNa: document.getElementById('badge-na'),
  badgeFp: document.getElementById('badge-fp'),

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
  tickClock();
  setInterval(tickClock, 1000);
  // Execute initial suite immediately so first viewport is populated
  executeSuiteImmediate();
}

/**
 * Live UTC readout for the status bar — mission-control style.
 */
function tickClock() {
  if (!elements.utcClock) return;
  const d = new Date();
  elements.utcClock.textContent = d.toISOString().slice(11, 19) + ' UTC';
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

  elements.policyDesc.textContent = policy.intent;
  elements.modeSelect.value = policy.defaultMode;
  state.mode = policy.defaultMode;
  elements.ruleInput.value = policy.defaultRule;
  state.rule = policy.defaultRule;

  if (policyId === 'git-commit') {
    elements.presetNaive.innerHTML = '<span class="chip-dot"></span> Simple text';
    elements.presetRegex.innerHTML = '<span class="chip-dot"></span> Pattern';
    elements.presetHardened.innerHTML = '<span class="chip-dot"></span> Smart tokens';
  } else {
    elements.presetNaive.innerHTML = '<span class="chip-dot"></span> Simple pipe';
    elements.presetRegex.innerHTML = '<span class="chip-dot"></span> Pipe pattern';
    elements.presetHardened.innerHTML = '<span class="chip-dot"></span> Smart pipe';
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
      elements.modeMeta.textContent = 'TEXT MATCH';
      elements.ruleTypeIndicator.textContent = 'TEXT';
      elements.modeDesc.textContent = 'Checks if your rule appears in the command exactly as written.';
      break;
    case 'regex':
      elements.modeMeta.textContent = 'PATTERN';
      elements.ruleTypeIndicator.textContent = 'PATTERN';
      elements.modeDesc.textContent = 'Uses a pattern (regex) to match the command.';
      break;
    case 'wildcard':
      elements.modeMeta.textContent = 'WILDCARD';
      elements.ruleTypeIndicator.textContent = 'WILDCARD';
      elements.modeDesc.textContent = 'Uses * and ? to match parts of the command.';
      break;
    case 'structured':
      elements.modeMeta.textContent = 'SMART TOKENS';
      elements.ruleTypeIndicator.textContent = 'TOKENS';
      elements.modeDesc.textContent = 'Finds the command name and action separately (e.g. exec=git & action=commit).';
      break;
  }
}

/**
 * Runs suite with a rapid diagnostic sequence ticker (giving genuine instrument feedback)
 */
function runSuiteWithTicker() {
  if (state.isExecuting) return;
  state.isExecuting = true;

  elements.controlStatus.textContent = 'Testing…';
  elements.btnRun.disabled = true;
  elements.btnRunText.textContent = 'Checking…';
  elements.diagnosticTicker.classList.remove('hidden');

  // Activate Stage 02 in Nav
  elements.navAttack.classList.add('active');

  const stages = [
    { text: '1/5 Checking the exact command…', pct: '20%' },
    { text: '2/5 Trying flags in between…', pct: '45%' },
    { text: '3/5 Trying command chains (&&, ;)…', pct: '70%' },
    { text: '4/5 Trying full paths and wrappers…', pct: '90%' },
    { text: '5/5 Checking the git hook cases…', pct: '100%' }
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
        elements.btnRunText.textContent = 'Run the test';
        elements.controlStatus.textContent = 'Done';
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
    elements.ruleError.textContent = `Rule error: ${outcome.syntaxError}`;
    elements.ruleError.classList.remove('hidden');
  } else {
    elements.ruleError.classList.add('hidden');
  }

  recordHistorySnapshot(outcome);
  state.lastRunResult = outcome;

  renderTelemetry(outcome);
  renderRunnerRows();
  renderResultStrip();
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
  animateScore(elements.scorePct, state.lastCoverage ?? 0, outcome.coveragePercent);
  state.lastCoverage = outcome.coveragePercent;
  elements.scoreFraction.textContent = `${outcome.applicableBlocked} / ${outcome.applicableTotal} blocked`;

  elements.verdictBanner.textContent = outcome.verdictHeadline;
  elements.verdictBanner.className = `verdict-tag ${outcome.verdictClass}`;

  // False alarms (precision): innocent commands the rule wrongly blocked
  if (elements.fpFraction) {
    elements.fpFraction.textContent = `${outcome.falsePositives} / ${outcome.benignTotal}`;
  }
  if (elements.fpWarn) {
    elements.fpWarn.classList.toggle('hidden', outcome.falsePositives === 0);
  }

  // Layer Meters (attack cases only — benign cases have their own readout)
  const attackResults = outcome.results.filter(r => r.category !== 'Benign');
  const matcherCases = attackResults.filter(r => r.targetLayer === 'matcher');
  const matcherBlocked = matcherCases.filter(r => r.status === 'BLOCKED').length;
  elements.meterMatcher.textContent = `${matcherBlocked}/${matcherCases.length} blocked`;

  const shellCases = outcome.results.filter(r => r.targetLayer === 'shell');
  const shellBlocked = shellCases.filter(r => r.status === 'BLOCKED').length;
  elements.meterShell.textContent = `${shellBlocked}/${shellCases.length} blocked`;

  const hookCases = outcome.results.filter(r => r.targetLayer === 'hook');
  elements.meterHook.textContent = `${hookCases.length} skipped`;

  // Badge Counts
  const missedCount = outcome.results.filter(r => r.status === 'MISSED').length;
  const blockedCount = outcome.results.filter(r => r.status === 'BLOCKED').length;
  const naCount = outcome.results.filter(r => r.status === 'NOT_APPLICABLE').length;
  const fpCount = outcome.results.filter(r => r.status === 'FALSE_POSITIVE').length;

  elements.badgeMissed.textContent = missedCount;
  elements.badgeBlocked.textContent = blockedCount;
  elements.badgeNa.textContent = naCount;
  if (elements.badgeFp) elements.badgeFp.textContent = fpCount;

  const allPill = document.querySelector('.pill-tab[data-filter="all"]');
  if (allPill) allPill.innerHTML = `All [${outcome.totalCases}]`;
  const corpusCount = document.getElementById('corpus-count');
  if (corpusCount) corpusCount.textContent = outcome.totalCases;
}

/**
 * Animates the coverage number counting up/down to its new value
 */
function animateScore(el, from, to) {
  if (from === to) {
    el.textContent = `${to}%`;
    return;
  }
  const start = performance.now();
  const dur = 650;
  function frame(t) {
    const p = Math.min(1, (t - start) / dur);
    const eased = 1 - Math.pow(1 - p, 3);
    el.textContent = `${Math.round(from + (to - from) * eased)}%`;
    if (p < 1) requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
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
    if (state.activeFilter === 'false-positive') return c.status === 'FALSE_POSITIVE';
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
  const badgeText = tc.status === 'NOT_APPLICABLE' ? 'GIT HOOK TEST'
    : tc.status === 'FALSE_POSITIVE' ? 'FALSE ALARM'
    : tc.status === 'CLEAR' ? 'CLEAR' : tc.status;
  elements.dossierBadge.textContent = badgeText;
  const badgeClass = tc.status === 'BLOCKED' ? 'blocked'
    : tc.status === 'MISSED' ? 'missed'
    : tc.status === 'FALSE_POSITIVE' ? 'false-alarm'
    : tc.status === 'CLEAR' ? 'clear' : 'na';
  elements.dossierBadge.className = `case-verdict-tag ${badgeClass}`;

  // Evidence Pointer & Marker
  setDossierPointer(tc);

  elements.dossierIntent.textContent = tc.intent;
  elements.dossierLayer.textContent = formatLayerUpper(tc.targetLayer);
  elements.dossierMatters.textContent = tc.whyItMatters;
  elements.dossierExplanation.textContent = tc.explanation;

  // Hardening Guidance
  if (tc.status === 'BLOCKED') {
    elements.dossierHardening.textContent = 'Your current rule catches this one. When you change your rule, make sure you do not break this case.';
  } else if (tc.status === 'NOT_APPLICABLE') {
    elements.dossierHardening.textContent = 'This is about git hooks, not text rules: --no-verify turns off git\'s own checks. A text rule cannot fix that — you need server-side rules (like branch protection on GitHub) that an agent cannot switch off.';
  } else if (tc.status === 'FALSE_POSITIVE') {
    elements.dossierHardening.textContent = 'Narrow the rule so it targets the dangerous action, not innocent lookalikes. Re-run after every tightening — these benign cases are your guardrail against overblocking.';
  } else if (tc.status === 'CLEAR') {
    elements.dossierHardening.textContent = 'Your rule correctly ignores this. Keep this case passing whenever you tighten the rule.';
  } else {
    elements.dossierHardening.textContent = getDossierHardening(tc);
  }

  renderResultStrip();
}

/**
 * Renders the signature case strip: one clickable block per test case,
 * colored by verdict. Clicking a block opens that case's details.
 */
function renderResultStrip() {
  const strip = document.getElementById('result-strip');
  if (!strip || !state.lastRunResult || !state.lastRunResult.results) return;

  strip.innerHTML = '';
  state.lastRunResult.results.forEach(tc => {
    const seg = document.createElement('button');
    const kind = tc.status === 'BLOCKED' ? 'blocked'
      : tc.status === 'MISSED' ? 'missed'
      : tc.status === 'FALSE_POSITIVE' ? 'fp'
      : tc.status === 'CLEAR' ? 'clear' : 'na';
    seg.className = `strip-seg seg-${kind}${tc.id === state.activeCaseId ? ' seg-active' : ''}`;
    const statusWord = tc.status === 'NOT_APPLICABLE' ? 'git-hook test'
      : tc.status === 'FALSE_POSITIVE' ? 'false alarm'
      : tc.status === 'CLEAR' ? 'correctly ignored' : tc.status.toLowerCase();
    seg.title = `${tc.id} — ${tc.title} (${statusWord})`;
    seg.setAttribute('aria-label', seg.title);
    seg.addEventListener('click', () => {
      document.querySelectorAll('.runner-row').forEach(r => r.classList.toggle('active-row', r.dataset.id === tc.id));
      inspectDossier(tc);
      const dossier = document.getElementById('forensic-dossier');
      if (dossier) dossier.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    });
    strip.appendChild(seg);
  });
}

/**
 * Configures the visual token pointer for the command
 */
function setDossierPointer(tc) {
  switch (tc.category) {
    case 'Benign':
      elements.dossierPointerText.textContent = 'Nothing dangerous here — the question is whether your rule can tell the difference.';
      break;
    case 'Interleaved Flag':
      elements.dossierPointerText.textContent = 'A flag (-C /repo) sits between "git" and "commit", so the exact text does not match — but it still commits.';
      break;
    case 'Shell Chaining':
      elements.dossierPointerText.textContent = 'The commit is joined to another command with && or ; — rules that expect "git" at the start miss it.';
      break;
    case 'Path Variation':
      elements.dossierPointerText.textContent = 'Git is run with its full path (/usr/bin/git), so the line does not start with plain "git".';
      break;
    case 'Dynamic Resolution':
      elements.dossierPointerText.textContent = 'The shell figures out where git is with $(which git) right before running it.';
      break;
    case 'Process Wrapper':
      elements.dossierPointerText.textContent = 'The first word is "env", not "git" — simple rules check the wrong word.';
      break;
    case 'Syntactic Normalization':
      elements.dossierPointerText.textContent = 'Extra spaces or tabs between the words — the shell ignores them, exact-text rules do not.';
      break;
    case 'Configuration Alias':
      elements.dossierPointerText.textContent = 'The command uses a git nickname (ci = commit). The rule has no idea the nickname exists.';
      break;
    default:
      elements.dossierPointerText.textContent = 'This command is written differently from what your rule expects.';
  }
}

function getDossierHardening(tc) {
  switch (tc.category) {
    case 'Interleaved Flag':
      return 'Switch from exact-text matching to smart tokens (exec=git & action=commit), or allow flags in a pattern like ^git(\\s+--[\\w-]+)*\\s+commit.';
    case 'Shell Chaining':
      return 'Split chained commands into separate parts before checking, instead of only checking the start of the line.';
    case 'Path Variation':
      return 'Take just the file name from the path (e.g. /usr/bin/git → git) before checking.';
    case 'Dynamic Resolution':
      return 'You cannot reliably predict $(...) by reading text. In locked-down setups, do not allow $(...) in agent commands.';
    case 'Process Wrapper':
      return 'Strip known wrappers (env, sudo, nohup) first, then check what is left.';
    case 'Syntactic Normalization':
      return 'Squash multiple spaces and tabs into one space before checking.';
    case 'Configuration Alias':
      return 'Text rules alone cannot handle nicknames. Add branch protection on GitHub/GitLab so direct commits are rejected no matter how they are spelled.';
    default:
      return 'Check the command name and action as separate tokens instead of one fragile text match.';
  }
}

function getRowStateClass(status) {
  switch (status) {
    case 'BLOCKED': return 'state-blocked';
    case 'MISSED': return 'state-missed';
    case 'NOT_APPLICABLE': return 'state-na';
    case 'FALSE_POSITIVE': return 'state-fp';
    case 'CLEAR': return 'state-clear';
    default: return '';
  }
}

function getRowStateLabel(status) {
  switch (status) {
    case 'BLOCKED': return '✓ BLOCKED';
    case 'MISSED': return '! MISSED';
    case 'NOT_APPLICABLE': return '— HOOK';
    case 'FALSE_POSITIVE': return '✕ FALSE ALARM';
    case 'CLEAR': return '○ CLEAR';
    default: return status;
  }
}

function formatLayerUpper(layer) {
  switch (layer) {
    case 'matcher': return 'Text check';
    case 'shell': return 'Shell tricks';
    case 'hook': return 'Git hooks';
    case 'git-config': return 'Git nickname';
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
        Run a test, then change your rule and run again — you'll see your score change here.
      </div>
    `;
    return;
  }

  const before = state.history[0];
  const current = state.history[state.history.length - 1];
  const delta = current.coverage - before.coverage;
  const deltaSign = delta > 0 ? `+${delta}%` : `${delta}%`;
  const deltaColor = delta > 0 ? 'var(--green)' : delta < 0 ? 'var(--red)' : 'var(--text-3)';

  elements.timelineBody.innerHTML = `
    <div class="timeline-delta-block">
      <div class="timeline-col">
        <span class="delta-tag">BEFORE [${before.mode.toUpperCase()}]</span>
        <span class="delta-score">${before.coverage}% (${before.blocked}/${before.total})</span>
        <span class="delta-rule" title="${escapeHtml(before.rule)}">${escapeHtml(before.rule)}</span>
      </div>
      <div class="timeline-col highlight-current">
        <span class="delta-tag">NOW [${current.mode.toUpperCase()}]</span>
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

  elements.modalTestSummary.textContent = `${testReport.passed} / ${testReport.total} checks passed`;
  elements.modalTestSummary.style.color = testReport.allPassed ? 'var(--green)' : 'var(--red)';
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
