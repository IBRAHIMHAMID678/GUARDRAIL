/**
 * GUARDRAIL / LAB — Studio Instrument Controller
 * 
 * Orchestrates:
 * - Deterministic adversarial suite execution
 * - Studio 3D Quantum Defensive Interceptor WebGL visualization
 * - Real-time POSIX AST Tree inspection
 * - 1-Click Auto-Harden Rule Workflow
 * - Live Red-Team Attack Sandbox with quick bypass chips
 * - Production Guardrail Exporters (Claude Code, Cursor, agentsh, Bash, Seccomp)
 * - URL Permalink State Sharing
 * - Invariant self-testing verification
 */

import { POLICIES } from './corpus.js';
import { evaluateSuite } from './evaluator.js';
import { evaluateMatcher } from './matcher.js';
import { parseShellCommand } from './ast-parser.js';
import { runAllTests } from './test-engine.js';
import { QuantumInterceptor3D } from './interceptor-3d.js';
import { generateExports } from './exporters.js';

// Application State
const state = {
  policyId: 'git-commit',
  mode: 'literal',
  rule: 'git commit',
  activeFilter: 'all',
  activeCaseId: 'TC-03',
  history: [],
  lastRunResult: null,
  isExecuting: false,
  viewMode: '3d', // '3d' | 'ast'
  exportTarget: 'claudeCode'
};

// 3D Interceptor Instance
let interceptor3d = null;

// DOM References
const elements = {
  // Navigation & Header
  btnExport: document.getElementById('btn-export'),
  btnShare: document.getElementById('btn-share'),
  btnSelfTests: document.getElementById('btn-self-tests'),
  btnThemeToggle: document.getElementById('btn-theme-toggle'),

  // Policy Switcher Pills
  policyPills: document.querySelectorAll('.policy-pill-btn'),
  policySelect: document.getElementById('policy-select'),
  policyDesc: document.getElementById('policy-desc'),
  policyCategoryTag: document.getElementById('policy-category-tag'),

  // Operational Specs
  specCorpusCount: document.getElementById('spec-corpus-count'),

  // Form Controls
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
  btnRunCount: document.getElementById('btn-run-count'),
  btnAutoHarden: document.getElementById('btn-auto-harden'),
  hardenCallout: document.getElementById('harden-callout'),
  diagnosticTicker: document.getElementById('diagnostic-ticker'),
  tickerStageText: document.getElementById('ticker-stage-text'),
  tickerProgressFill: document.getElementById('ticker-progress-fill'),

  // Live Attack Sandbox
  sandboxCmdInput: document.getElementById('sandbox-cmd-input'),
  btnSandboxFire: document.getElementById('btn-sandbox-fire'),
  sandboxFeedback: document.getElementById('sandbox-feedback'),
  quickAtkChips: document.querySelectorAll('.quick-atk-chip'),

  // 3D Viewport & AST Tree
  tabView3d: document.getElementById('tab-view-3d'),
  tabViewAst: document.getElementById('tab-view-ast'),
  cameraControls: document.getElementById('camera-controls'),
  interceptorCanvasContainer: document.getElementById('interceptor-canvas-container'),
  astVisualizerPane: document.getElementById('ast-visualizer-pane'),
  astTargetCmd: document.getElementById('ast-target-cmd'),
  astNodesContainer: document.getElementById('ast-nodes-container'),

  // Telemetry Readout
  scorePct: document.getElementById('score-pct'),
  scoreFraction: document.getElementById('score-fraction'),
  verdictBanner: document.getElementById('verdict-banner'),
  meterMatcher: document.getElementById('meter-matcher'),
  meterShell: document.getElementById('meter-shell'),
  meterHook: document.getElementById('meter-hook'),
  telemetryAdviceText: document.getElementById('telemetry-advice-text'),

  // Filter Pills & Badges
  filterPills: document.querySelectorAll('.filter-tab-pill, .filter-pill, .pill-tab'),
  badgeAll: document.getElementById('badge-all'),
  badgeMissed: document.getElementById('badge-missed'),
  badgeBlocked: document.getElementById('badge-blocked'),
  badgeNa: document.getElementById('badge-na'),

  // Threat Cards List
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

  // Exporters Modal
  modalExports: document.getElementById('modal-exports'),
  btnCloseExportModal: document.getElementById('btn-close-export-modal'),
  exportNavTabs: document.querySelectorAll('.export-nav-tab'),
  exportTargetDesc: document.getElementById('export-target-desc'),
  exportCodeText: document.getElementById('export-code-text'),
  btnCopyExport: document.getElementById('btn-copy-export'),
  btnDownloadExport: document.getElementById('btn-download-export'),

  // Invariant Modal
  modalSelfTests: document.getElementById('modal-self-tests'),
  btnCloseModal: document.getElementById('btn-close-modal'),
  btnDismissModal: document.getElementById('btn-dismiss-modal'),
  modalTestOutput: document.getElementById('modal-test-output'),
  modalTestSummary: document.getElementById('modal-test-summary'),

  // Toast
  toastNotify: document.getElementById('toast-notify')
};

/**
 * Initialize Instrument
 */
function init() {
  restoreStateFromUrl();
  bindEvents();
  init3DInterceptor();
  loadPolicy(state.policyId);
  executeSuiteImmediate();
  updateTotalCorpusSpec();
}

/**
 * Initialize Three.js Quantum Interceptor
 */
function init3DInterceptor() {
  if (window.THREE) {
    interceptor3d = new QuantumInterceptor3D('interceptor-canvas', (layerId) => {
      if (layerId === 'hook') {
        setFilter('not-applicable');
      } else {
        setFilter('all');
        showToast(`Filtered threats for ${layerId.toUpperCase()} in 3D Interceptor`);
      }
    });
  }
}

/**
 * Bind All Event Handlers
 */
function bindEvents() {
  // Topbar Policy Pills
  elements.policyPills.forEach(pill => {
    pill.addEventListener('click', () => {
      const policyId = pill.dataset.policy;
      loadPolicy(policyId);
      runSuiteWithTicker();
      updateUrlHash();
    });
  });

  // Hidden Policy Select fallback
  if (elements.policySelect) {
    elements.policySelect.addEventListener('change', (e) => {
      loadPolicy(e.target.value);
      runSuiteWithTicker();
      updateUrlHash();
    });
  }

  // Mode Selection
  elements.modeSelect.addEventListener('change', (e) => {
    setMode(e.target.value);
    updateUrlHash();
  });

  // Rule Input Change & Live Validation
  elements.ruleInput.addEventListener('input', (e) => {
    state.rule = e.target.value;
    validateRuleLive();
    updateUrlHash();
  });

  // Presets
  elements.presetNaive.addEventListener('click', () => applyPreset('naive'));
  elements.presetRegex.addEventListener('click', () => applyPreset('regex'));
  elements.presetHardened.addEventListener('click', () => applyPreset('hardened'));

  // 1-Click Auto Harden CTA
  const handleAutoHarden = () => {
    applyPreset('hardened');
    showToast('🛡️ Upgraded rule to Hardened POSIX AST evaluation!');
  };
  if (elements.btnAutoHarden) elements.btnAutoHarden.addEventListener('click', handleAutoHarden);
  const btnQuickHarden = document.getElementById('btn-quick-harden');
  if (btnQuickHarden) btnQuickHarden.addEventListener('click', handleAutoHarden);

  // Run Suite Button
  if (elements.btnRun) {
    elements.btnRun.addEventListener('click', () => runSuiteWithTicker());
  }

  // Form Submit (if present)
  const guardrailForm = document.getElementById('guardrail-form');
  if (guardrailForm) {
    guardrailForm.addEventListener('submit', (e) => {
      e.preventDefault();
      runSuiteWithTicker();
    });
  }

  // View Mode Switcher (3D vs AST Tree)
  elements.tabView3d.addEventListener('click', () => setViewMode('3d'));
  elements.tabViewAst.addEventListener('click', () => setViewMode('ast'));

  // Camera Controls
  document.querySelectorAll('.cam-btn, .cam-pill, .btn-cam').forEach(btn => {
    btn.addEventListener('click', () => {
      const cam = btn.dataset.cam;
      if (interceptor3d) interceptor3d.setCameraView(cam);
    });
  });

  // HUD layer chip clicks
  document.querySelectorAll('.hud-chip, .meter-bar-item, .layer-chip').forEach(item => {
    item.addEventListener('click', () => {
      const layer = item.dataset.layer;
      if (layer === 'hook') {
        setFilter('not-applicable');
      } else {
        setFilter('all');
      }
    });
  });

  // Live Attack Sandbox Fire
  elements.btnSandboxFire.addEventListener('click', fireLiveSandboxVector);
  elements.sandboxCmdInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      fireLiveSandboxVector();
    }
  });

  // Quick Attack Shortcut Chips
  elements.quickAtkChips.forEach(chip => {
    chip.addEventListener('click', () => {
      elements.sandboxCmdInput.value = chip.dataset.cmd;
      fireLiveSandboxVector();
    });
  });

  // Filter Pills
  elements.filterPills.forEach(tab => {
    tab.addEventListener('click', () => setFilter(tab.dataset.filter));
  });

  // Clear Timeline
  elements.btnClearHistory.addEventListener('click', clearHistory);

  // Exporters Modal
  elements.btnExport.addEventListener('click', openExportModal);
  elements.btnCloseExportModal.addEventListener('click', closeExportModal);
  elements.exportNavTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      elements.exportNavTabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      state.exportTarget = tab.dataset.target;
      renderExportCode();
    });
  });
  elements.btnCopyExport.addEventListener('click', copyExportCode);
  elements.btnDownloadExport.addEventListener('click', downloadExportCode);

  // Share Permalink
  elements.btnShare.addEventListener('click', copyPermalink);

  // Invariant Self-Test Modal
  elements.btnSelfTests.addEventListener('click', openSelfTestsModal);
  elements.btnCloseModal.addEventListener('click', closeSelfTestsModal);
  elements.btnDismissModal.addEventListener('click', closeSelfTestsModal);

  // Theme Toggle
  elements.btnThemeToggle.addEventListener('click', toggleTheme);
}

/**
 * Updates the total vectors count
 */
function updateTotalCorpusSpec() {
  let count = 0;
  Object.values(POLICIES).forEach(p => count += p.corpus.length);
  elements.specCorpusCount.textContent = `${count} VECTORS IN CORPUS`;
}

/**
 * Load Policy Definition
 */
function loadPolicy(policyId) {
  const policy = POLICIES[policyId] || POLICIES['git-commit'];
  state.policyId = policy.id;
  state.mode = policy.defaultMode;
  state.rule = policy.defaultRule;

  // Update Topbar Pills active class
  elements.policyPills.forEach(pill => {
    pill.classList.toggle('active', pill.dataset.policy === policy.id);
  });

  if (elements.policySelect) elements.policySelect.value = policy.id;
  elements.policyDesc.textContent = policy.intent;
  if (elements.policyCategoryTag) {
    elements.policyCategoryTag.textContent = policy.category ? policy.category.toUpperCase() : 'SECURITY CONTROL';
  }

  elements.modeSelect.value = policy.defaultMode;
  elements.ruleInput.value = policy.defaultRule;
  elements.btnRunCount.textContent = `(${policy.corpus.length} Attacks)`;

  if (policy.corpus[0]) {
    state.activeCaseId = policy.corpus[0].id;
  }

  updateModeMetadata(policy.defaultMode);
  updatePresetButtons(policy.defaultMode);
}

/**
 * Mode Switching
 */
function setMode(mode) {
  state.mode = mode;
  elements.modeSelect.value = mode;
  updateModeMetadata(mode);
  updatePresetButtons(mode);

  const policy = POLICIES[state.policyId];
  if (mode === 'literal') {
    state.rule = policy.defaultRule;
    elements.ruleInput.value = policy.defaultRule;
  } else if (mode === 'regex') {
    state.rule = policy.alternativeRegex || policy.defaultRule;
    elements.ruleInput.value = state.rule;
  } else if (mode === 'structured') {
    state.rule = policy.hardenedRule;
    elements.ruleInput.value = policy.hardenedRule;
  }

  if (interceptor3d) {
    interceptor3d.setShieldMode(mode === 'structured' ? 'hardened' : 'porous');
  }

  validateRuleLive();
}

/**
 * Updates Mode UI Descriptions
 */
function updateModeMetadata(mode) {
  switch (mode) {
    case 'literal':
      elements.modeMeta.textContent = 'SUBSTRING';
      elements.modeDesc.textContent = 'Searches for contiguous literal bytes. Bypassed by flags (-C), subshells, and chaining.';
      elements.ruleTypeIndicator.textContent = 'RAW BYTES';
      break;
    case 'regex':
      elements.modeMeta.textContent = 'SYNTAX PATTERN';
      elements.modeDesc.textContent = 'Evaluates against regular expression pattern. Anchor misses compound commands (&&, ;).';
      elements.ruleTypeIndicator.textContent = 'REGULAR EXPR';
      break;
    case 'wildcard':
      elements.modeMeta.textContent = 'GLOB PATTERN';
      elements.modeDesc.textContent = 'Expands glob symbols (* matches any string, ? matches character).';
      elements.ruleTypeIndicator.textContent = 'GLOB STRING';
      break;
    case 'structured':
      elements.modeMeta.textContent = 'POSIX AST PARSER';
      elements.modeDesc.textContent = 'Inspects tokenized AST segments. Evaluates executable and subcommand boundaries.';
      elements.ruleTypeIndicator.textContent = 'AST CONDITION';
      break;
  }
}

/**
 * Apply Test Presets
 */
function applyPreset(presetType) {
  const policy = POLICIES[state.policyId];
  if (presetType === 'naive') {
    setMode('literal');
    state.rule = policy.defaultRule;
    elements.ruleInput.value = policy.defaultRule;
  } else if (presetType === 'regex') {
    setMode('regex');
    state.rule = policy.alternativeRegex;
    elements.ruleInput.value = policy.alternativeRegex;
  } else if (presetType === 'hardened') {
    setMode('structured');
    state.rule = policy.hardenedRule;
    elements.ruleInput.value = policy.hardenedRule;
  }
  runSuiteWithTicker();
  updateUrlHash();
}

function updatePresetButtons(activeMode) {
  elements.presetNaive.classList.toggle('active', activeMode === 'literal');
  elements.presetRegex.classList.toggle('active', activeMode === 'regex');
  elements.presetHardened.classList.toggle('active', activeMode === 'structured');
}

/**
 * View Mode Switcher (3D vs AST)
 */
function setViewMode(mode) {
  state.viewMode = mode;
  elements.tabView3d.classList.toggle('active', mode === '3d');
  elements.tabViewAst.classList.toggle('active', mode === 'ast');

  if (mode === '3d') {
    elements.interceptorCanvasContainer.classList.remove('hidden');
    elements.astVisualizerPane.classList.add('hidden');
    elements.cameraControls.classList.remove('hidden');
    if (interceptor3d) interceptor3d.handleResize();
  } else {
    elements.interceptorCanvasContainer.classList.add('hidden');
    elements.astVisualizerPane.classList.remove('hidden');
    elements.cameraControls.classList.add('hidden');
    renderAstTreeView(elements.sandboxCmdInput.value.trim() || state.rule);
  }
}

/**
 * Live Rule Validation
 */
function validateRuleLive() {
  if (state.mode === 'regex') {
    try {
      new RegExp(state.rule);
      elements.ruleError.classList.add('hidden');
      elements.ruleError.textContent = '';
      elements.controlStatus.textContent = 'READY';
      elements.controlStatus.className = 'status-pill status-ready';
    } catch (e) {
      elements.ruleError.classList.remove('hidden');
      elements.ruleError.textContent = `Regex Error: ${e.message}`;
      elements.controlStatus.textContent = 'SYNTAX ERROR';
      elements.controlStatus.className = 'status-pill status-error';
    }
  } else {
    elements.ruleError.classList.add('hidden');
    elements.ruleError.textContent = '';
    elements.controlStatus.textContent = 'READY';
    elements.controlStatus.className = 'status-pill status-ready';
  }
}

/**
 * Immediate Execution
 */
function executeSuiteImmediate() {
  const policy = POLICIES[state.policyId];
  const suiteResult = evaluateSuite(policy, state.rule, state.mode);
  renderResults(suiteResult);
  recordHistory(suiteResult);
}

/**
 * Run Suite with Diagnostic Ticker and 3D Particle Launch
 */
function runSuiteWithTicker() {
  if (state.isExecuting) return;
  state.isExecuting = true;

  elements.btnRun.disabled = true;
  elements.btnRunText.textContent = 'ANALYZING...';
  elements.diagnosticTicker.classList.remove('hidden');

  const policy = POLICIES[state.policyId];
  const stages = [
    '01/04 Tokenizing POSIX shell syntax...',
    '02/04 Evaluating AST control layer boundaries...',
    '03/04 Measuring adversarial bypass vectors...',
    '04/04 Firing 3D Interceptor simulations...'
  ];

  let currentStage = 0;
  const interval = setInterval(() => {
    currentStage++;
    if (currentStage < stages.length) {
      elements.tickerStageText.textContent = stages[currentStage];
      elements.tickerProgressFill.style.width = `${(currentStage / stages.length) * 100}%`;
    } else {
      clearInterval(interval);
      elements.diagnosticTicker.classList.add('hidden');
      elements.tickerProgressFill.style.width = '0%';
      elements.btnRun.disabled = false;
      elements.btnRunText.textContent = 'TEST GUARDRAIL DEFENSE';
      state.isExecuting = false;

      const suiteResult = evaluateSuite(policy, state.rule, state.mode);
      renderResults(suiteResult);
      recordHistory(suiteResult);

      if (interceptor3d && state.viewMode === '3d') {
        interceptor3d.fireSuite(suiteResult.results);
      }
    }
  }, 90);
}

/**
 * Render Suite Verdicts & Forensic Dossier
 */
function renderResults(suiteResult) {
  state.lastRunResult = suiteResult;

  // 1. Telemetry Readouts
  elements.scorePct.textContent = `${suiteResult.coveragePercent}%`;
  elements.scoreFraction.textContent = `${suiteResult.applicableBlocked} / ${suiteResult.applicableTotal} BLOCKED`;

  elements.verdictBanner.textContent = suiteResult.verdictHeadline;
  elements.verdictBanner.className = `verdict-status-tag ${suiteResult.coveragePercent === 100 ? 'secure' : 'vulnerable'}`;

  const scoreDialWrap = document.getElementById('score-dial-wrap');
  if (scoreDialWrap) {
    scoreDialWrap.className = `dial-circle-wrap ${suiteResult.coveragePercent === 100 ? 'secure' : 'vulnerable'}`;
  }

  // Layer Meters
  const layerMatcherBlocked = suiteResult.results.filter(r => r.targetLayer === 'matcher' && r.status === 'BLOCKED').length;
  const layerMatcherTotal = suiteResult.results.filter(r => r.targetLayer === 'matcher').length;
  elements.meterMatcher.textContent = `${layerMatcherBlocked}/${layerMatcherTotal}`;

  const layerShellBlocked = suiteResult.results.filter(r => r.targetLayer === 'shell' && r.status === 'BLOCKED').length;
  const layerShellTotal = suiteResult.results.filter(r => r.targetLayer === 'shell').length;
  elements.meterShell.textContent = `${layerShellBlocked}/${layerShellTotal}`;

  elements.meterHook.textContent = `${suiteResult.differentLayerCount} NON-APPLICABLE`;

  if (elements.telemetryAdviceText) {
    elements.telemetryAdviceText.textContent = suiteResult.hardeningAdvice || 'Evaluated against adversarial corpus.';
  }

  // Auto-harden prompt visibility
  if (elements.hardenCallout) {
    if (suiteResult.coveragePercent === 100) {
      elements.hardenCallout.classList.add('hidden');
    } else {
      elements.hardenCallout.classList.remove('hidden');
    }
  }

  // Badges
  if (elements.badgeAll) elements.badgeAll.textContent = suiteResult.totalCases;
  elements.badgeMissed.textContent = suiteResult.applicableMissed;
  elements.badgeBlocked.textContent = suiteResult.applicableBlocked;
  elements.badgeNa.textContent = suiteResult.differentLayerCount;

  // 2. Render Matrix Threat Cards
  renderRunnerList(suiteResult.results);

  // 3. Render Selected Forensic Case Dossier
  let activeCase = suiteResult.results.find(r => r.id === state.activeCaseId);
  if (!activeCase && suiteResult.results.length > 0) {
    activeCase = suiteResult.results.find(r => r.status === 'MISSED') || suiteResult.results[0];
    state.activeCaseId = activeCase.id;
  }

  if (activeCase) {
    renderDossier(activeCase);
  }
}

/**
 * Render Threat Cards
 */
function renderRunnerList(results) {
  elements.runnerList.innerHTML = '';

  const filtered = results.filter(r => {
    if (state.activeFilter === 'all') return true;
    if (state.activeFilter === 'missed') return r.status === 'MISSED';
    if (state.activeFilter === 'blocked') return r.status === 'BLOCKED';
    if (state.activeFilter === 'not-applicable') return r.status === 'NOT_APPLICABLE';
    return true;
  });

  if (filtered.length === 0) {
    const emptyRow = document.createElement('div');
    emptyRow.className = 'empty-state';
    emptyRow.textContent = `No test cases matching filter "${state.activeFilter}".`;
    elements.runnerList.appendChild(emptyRow);
    return;
  }

  filtered.forEach(tc => {
    const card = document.createElement('div');
    card.className = `threat-card ${tc.id === state.activeCaseId ? 'active' : ''}`;
    card.dataset.id = tc.id;

    let badgeClass = 'missed';
    let badgeText = 'BYPASSED';
    if (tc.status === 'BLOCKED') {
      badgeClass = 'blocked';
      badgeText = 'BLOCKED';
    } else if (tc.status === 'NOT_APPLICABLE') {
      badgeClass = 'na';
      badgeText = 'HOOK LAYER';
    }

    card.innerHTML = `
      <span class="threat-id">${tc.id}</span>
      <span class="threat-cat">${escapeHtml(tc.category)}</span>
      <span class="threat-cmd-cell"><code class="threat-code">${escapeHtml(tc.command)}</code></span>
      <span class="threat-badge ${badgeClass}">${badgeText}</span>
      <button type="button" class="btn-test-row" title="Simulate this vector in 3D Interceptor">▶ Test in 3D</button>
    `;

    const testBtn = card.querySelector('.btn-test-row');
    if (testBtn) {
      testBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        elements.sandboxCmdInput.value = tc.command;
        fireLiveSandboxVector();
      });
    }

    card.addEventListener('click', () => {
      state.activeCaseId = tc.id;
      document.querySelectorAll('.threat-card').forEach(c => c.classList.remove('active'));
      card.classList.add('active');
      renderDossier(tc);
      if (state.viewMode === 'ast') {
        renderAstTreeView(tc.command);
      }
    });

    elements.runnerList.appendChild(card);
  });
}

/**
 * Render Forensic Evidence Dossier
 */
function renderDossier(testCase) {
  elements.dossierCaseId.textContent = testCase.id;
  elements.dossierTitle.textContent = testCase.title;
  elements.dossierCode.textContent = testCase.command;
  elements.dossierIntent.textContent = testCase.intent;
  elements.dossierLayer.textContent = `${testCase.targetLayer.toUpperCase()} LAYER`;
  elements.dossierMatters.textContent = testCase.whyItMatters;
  elements.dossierExplanation.textContent = testCase.explanation;

  let badgeClass = 'missed';
  let badgeText = 'BYPASSED';
  if (testCase.status === 'BLOCKED') {
    badgeClass = 'blocked';
    badgeText = 'INTERCEPTED';
  } else if (testCase.status === 'NOT_APPLICABLE') {
    badgeClass = 'na';
    badgeText = 'HOOK BOUNDARY';
  }

  elements.dossierBadge.className = `verdict-badge ${badgeClass}`;
  elements.dossierBadge.textContent = badgeText;

  // Engineering hardening advice
  if (testCase.status === 'BLOCKED') {
    elements.dossierHardening.textContent = 'Rule successfully intercepted this vector representation.';
  } else if (testCase.status === 'NOT_APPLICABLE') {
    elements.dossierHardening.textContent = 'Command-filtering layer cannot enforce Git hooks. Requires remote branch protection (Layer D) and server-side pre-receive verification.';
  } else {
    elements.dossierHardening.textContent = 'Upgrade from naive string matching to POSIX AST structured evaluation (e.g. tokenizing executable basename and inspecting arguments).';
  }

  // Pointer breakdown
  if (testCase.category === 'Interleaved Flag') {
    elements.dossierPointerText.textContent = 'Interleaved option placed before subcommand fragments literal string.';
  } else if (testCase.category === 'Shell Chaining') {
    elements.dossierPointerText.textContent = 'Executed as compound shell chain (&& or ;); anchored matchers miss non-zero offset.';
  } else if (testCase.category === 'Path Variation') {
    elements.dossierPointerText.textContent = 'Absolute binary path prefix (/usr/bin/) bypasses bare word check.';
  } else if (testCase.category === 'Dynamic Resolution') {
    elements.dossierPointerText.textContent = 'Subshell $(...) expands in shell runtime; static string matcher sees raw token.';
  } else {
    elements.dossierPointerText.textContent = 'Syntactic transformation bypasses naive matcher.';
  }

  if (state.viewMode === 'ast') {
    renderAstTreeView(testCase.command);
  }
}

/**
 * Render AST Tree Breakdown
 */
function renderAstTreeView(cmdString) {
  elements.astTargetCmd.textContent = cmdString;
  elements.astNodesContainer.innerHTML = '';

  const ast = parseShellCommand(cmdString);
  if (!ast.segments || ast.segments.length === 0) {
    elements.astNodesContainer.innerHTML = '<div class="empty-state">Empty command string.</div>';
    return;
  }

  ast.segments.forEach((seg, sIdx) => {
    const card = document.createElement('div');
    card.className = 'ast-segment-card';

    let badgesHtml = '';
    badgesHtml += `<span class="ast-badge exec">EXEC: ${escapeHtml(seg.executable || 'none')}</span>`;
    if (seg.subcommand) {
      badgesHtml += `<span class="ast-badge subcmd">SUBCMD: ${escapeHtml(seg.subcommand)}</span>`;
    }
    seg.flags.forEach(f => {
      badgesHtml += `<span class="ast-badge flag">FLAG: ${escapeHtml(f)}</span>`;
    });
    seg.args.forEach(a => {
      badgesHtml += `<span class="ast-badge arg">ARG: ${escapeHtml(a)}</span>`;
    });
    if (seg.hasSubshell) {
      badgesHtml += `<span class="ast-badge subshell">⚠ SUBSHELL DETECTED</span>`;
    }
    if (seg.hasDynamicResolution) {
      badgesHtml += `<span class="ast-badge subshell">⚠ DYNAMIC RESOLUTION $(...)</span>`;
    }

    card.innerHTML = `
      <div class="ast-seg-header">
        <span class="ast-operator-tag">STAGE ${sIdx + 1} // ${seg.operator}</span>
        <code class="threat-code">${escapeHtml(seg.raw)}</code>
      </div>
      <div class="ast-node-badges">
        ${badgesHtml}
      </div>
    `;

    elements.astNodesContainer.appendChild(card);
  });
}

/**
 * Live Attack Sandbox Vector Fire
 */
function fireLiveSandboxVector() {
  const customCmd = elements.sandboxCmdInput.value.trim();
  if (!customCmd) return;

  const matchOutcome = evaluateMatcher(customCmd, state.rule, state.mode);
  const status = matchOutcome.matched ? 'BLOCKED' : 'MISSED';

  elements.sandboxFeedback.classList.remove('hidden');
  elements.sandboxFeedback.className = `sandbox-feedback-banner ${matchOutcome.matched ? 'blocked' : 'bypassed'}`;

  elements.sandboxFeedback.innerHTML = `
    <span><strong>${matchOutcome.matched ? '🛡️ INTERCEPTED' : '⚠️ BYPASSED'}</strong> — ${escapeHtml(matchOutcome.details)}</span>
    <span class="verdict-badge ${matchOutcome.matched ? 'blocked' : 'missed'}">${status}</span>
  `;

  if (state.viewMode === 'ast') {
    renderAstTreeView(customCmd);
  }

  if (interceptor3d) {
    interceptor3d.fireProjectile({
      status,
      command: customCmd,
      targetLayer: 'matcher'
    });
  }

  showToast(`Fired "${customCmd}" into 3D Interceptor: ${status}`);
}

/**
 * Filter Matrix Rows
 */
function setFilter(filter) {
  state.activeFilter = filter;
  elements.filterPills.forEach(tab => {
    tab.classList.toggle('active', tab.dataset.filter === filter);
  });
  if (state.lastRunResult) {
    renderRunnerList(state.lastRunResult.results);
  }
}

/**
 * Record Before/After History
 */
function recordHistory(suiteResult) {
  state.history.unshift({
    timestamp: new Date().toLocaleTimeString(),
    policy: suiteResult.policyName,
    rule: suiteResult.rule,
    mode: suiteResult.mode,
    coverage: suiteResult.coveragePercent,
    blocked: suiteResult.applicableBlocked,
    total: suiteResult.applicableTotal
  });

  if (state.history.length > 5) {
    state.history.pop();
  }

  renderHistory();
}

function renderHistory() {
  elements.timelineBody.innerHTML = '';
  if (state.history.length === 0) {
    elements.timelineBody.innerHTML = `
      <div class="empty-state">
        Run test suite, modify rule to structured or regex, and retest to observe the empirical attack coverage delta.
      </div>
    `;
    return;
  }

  state.history.forEach((h, idx) => {
    const item = document.createElement('div');
    item.className = 'timeline-item';
    item.innerHTML = `
      <div class="delta-header">
        <span class="delta-tag">RUN #${state.history.length - idx} [${h.mode.toUpperCase()}]</span>
        <span class="delta-score">${h.coverage}%</span>
      </div>
      <div class="delta-rule"><code>${escapeHtml(h.rule)}</code> (${h.blocked}/${h.total} intercepted)</div>
    `;
    elements.timelineBody.appendChild(item);
  });
}

function clearHistory() {
  state.history = [];
  renderHistory();
}

/**
 * Exporter Modal Management
 */
function openExportModal() {
  elements.modalExports.classList.remove('hidden');
  renderExportCode();
}

function closeExportModal() {
  elements.modalExports.classList.add('hidden');
}

function renderExportCode() {
  const policy = POLICIES[state.policyId];
  const exportsData = generateExports(policy, state.rule, state.mode);

  const target = state.exportTarget;
  elements.exportCodeText.textContent = exportsData[target] || '';

  const descriptions = {
    claudeCode: 'Claude Code config.json pre-tool permission deny policy',
    cursorRules: 'Cursor .cursorrules tool operational constraint prompt',
    agentsh: 'agentsh YAML execution-layer kernel syscall policy',
    shellWrapper: 'POSIX Bash pre-execution security wrapper hook',
    seccomp: 'Docker / Linux Seccomp syscall filtering profile'
  };
  elements.exportTargetDesc.textContent = descriptions[target] || 'Configuration file';
}

function copyExportCode() {
  const code = elements.exportCodeText.textContent;
  navigator.clipboard.writeText(code).then(() => {
    showToast('Hardened rule copied to clipboard!');
  });
}

function downloadExportCode() {
  const code = elements.exportCodeText.textContent;
  const policy = POLICIES[state.policyId];
  const extensions = {
    claudeCode: 'json',
    cursorRules: 'md',
    agentsh: 'yaml',
    shellWrapper: 'sh',
    seccomp: 'json'
  };
  const ext = extensions[state.exportTarget] || 'txt';
  const filename = `guardrail-${policy.id}.${ext}`;

  const blob = new Blob([code], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
  showToast(`Downloaded ${filename}`);
}

/**
 * Share Permalink State in URL Hash
 */
function updateUrlHash() {
  const hash = `policy=${encodeURIComponent(state.policyId)}&mode=${encodeURIComponent(state.mode)}&rule=${encodeURIComponent(state.rule)}`;
  window.history.replaceState(null, '', `#${hash}`);
}

function restoreStateFromUrl() {
  if (window.location.hash) {
    const params = new URLSearchParams(window.location.hash.slice(1));
    if (params.has('policy')) state.policyId = params.get('policy');
    if (params.has('mode')) state.mode = params.get('mode');
    if (params.has('rule')) state.rule = params.get('rule');
  }
}

function copyPermalink() {
  updateUrlHash();
  navigator.clipboard.writeText(window.location.href).then(() => {
    showToast('Permalink copied to clipboard!');
  });
}

/**
 * Self-Test Diagnostics Modal
 */
function openSelfTestsModal() {
  elements.modalSelfTests.classList.remove('hidden');
  const testSuite = runAllTests();

  elements.modalTestOutput.innerHTML = '';
  testSuite.results.forEach(r => {
    const item = document.createElement('div');
    item.className = 'diag-item';
    item.innerHTML = `
      <span class="diag-icon ${r.passed ? 'pass' : 'fail'}">${r.passed ? '✓' : '✗'}</span>
      <span class="diag-name">${escapeHtml(r.name)}</span>
      <span class="diag-verdict ${r.passed ? 'pass' : 'fail'}">${r.message}</span>
    `;
    elements.modalTestOutput.appendChild(item);
  });

  elements.modalTestSummary.textContent = `${testSuite.passed} / ${testSuite.total} TESTS PASSED`;
  elements.modalTestSummary.className = testSuite.allPassed ? 'summary-badge-green' : 'summary-badge-green fail';
}

function closeSelfTestsModal() {
  elements.modalSelfTests.classList.add('hidden');
}

/**
 * Toast Notification
 */
function showToast(msg) {
  elements.toastNotify.textContent = msg;
  elements.toastNotify.classList.remove('hidden');
  setTimeout(() => {
    elements.toastNotify.classList.add('hidden');
  }, 2400);
}

/**
 * Theme Toggle
 */
function toggleTheme() {
  const isDark = document.body.classList.toggle('dark-theme');
  document.body.classList.toggle('light-theme', !isDark);
  elements.btnThemeToggle.textContent = isDark ? '☼' : '◐';
  showToast(isDark ? 'Switched to Dark Mode' : 'Switched to Studio Light Mode');
}

/**
 * Safe HTML Escaping
 */
function escapeHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Launch on DOM ready
document.addEventListener('DOMContentLoaded', init);
