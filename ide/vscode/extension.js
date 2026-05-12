let vscode;
try {
  vscode = require('vscode');
} catch {
  vscode = null;
}
const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const tierRank = { informational: 0, low: 1, medium: 2, high: 3, urgent: 4 };

let collection;
let output;
let lastDiagnostics = [];
let statusBar;

function activate(context) {
  if (!vscode) {
    return;
  }
  collection = vscode.languages.createDiagnosticCollection('Reachability Advisor');
  output = vscode.window.createOutputChannel('Reachability Advisor');
  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBar.command = 'reachabilityAdvisor.scanWorkspace';
  statusBar.text = 'RA: idle';
  statusBar.tooltip = 'Reachability Advisor scan status';
  statusBar.show();
  context.subscriptions.push(collection, output, statusBar);
  context.subscriptions.push(vscode.commands.registerCommand('reachabilityAdvisor.scanWorkspace', scanWorkspace));
  context.subscriptions.push(vscode.commands.registerCommand('reachabilityAdvisor.explainFinding', explainFinding));
  context.subscriptions.push(vscode.commands.registerCommand('reachabilityAdvisor.generateSbomPlan', () => generatePlan('sbom')));
  context.subscriptions.push(vscode.commands.registerCommand('reachabilityAdvisor.generateSourceEvidencePlan', () => generatePlan('source-evidence')));
  context.subscriptions.push(vscode.commands.registerCommand('reachabilityAdvisor.validateProfile', validateCurrentProfile));
}

function deactivate() {
  if (collection) {
    collection.dispose();
  }
  if (output) {
    output.dispose();
  }
  if (statusBar) {
    statusBar.dispose();
  }
}

async function scanWorkspace() {
  const workspace = vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders[0];
  if (!workspace) {
    vscode.window.showWarningMessage('Reachability Advisor requires an open workspace.');
    return;
  }
  const root = workspace.uri.fsPath;
  const cfg = vscode.workspace.getConfiguration('reachabilityAdvisor');
  const executable = cfg.get('executable') || 'reachability-advisor';
  const profile = profileState(cfg);
  setStatus(`RA: ${profile.label}`);
  const validation = profileValidation(cfg, root);
  writeProfileValidation(validation);
  if (validation.status === 'blocked') {
    setStatus(`RA: ${profile.label} blocked`);
    vscode.window.showWarningMessage(`Reachability Advisor ${profile.label} profile is blocked: ${validation.blockers.map((item) => item.message).join('; ')}`);
    return;
  }
  const sbom = discoverPath(root, cfg.get('sbom'), ['app.cdx.json', 'bom.json', 'sbom.json', 'reachability/app.cdx.json', 'reachability/sbom.cdx.json', '.reachability/app.cdx.json']);
  const vulns = discoverPath(root, cfg.get('vulns'), ['vulnerabilities.json', 'grype.json', 'reachability/vulnerabilities.json', 'reachability/grype.json', '.reachability/grype.json']);

  const diagnosticsPath = path.join(os.tmpdir(), `reachability-advisor-diagnostics-${Date.now()}.json`);
  const findingsPath = path.join(os.tmpdir(), `reachability-advisor-findings-${Date.now()}.json`);
  const sourceCoveragePath = path.join(os.tmpdir(), `reachability-advisor-source-${Date.now()}.json`);
  const args = [
    'scan',
    '--sbom', sbom,
    '--vulns', vulns,
    '--source-root', `${cfg.get('sourceRootArtifact') || 'app'}=${root}`,
    '--analysis-profile', profile.analysisProfile,
    '--diagnostics-out', diagnosticsPath,
    '--source-coverage-out', sourceCoveragePath,
    '--out', findingsPath,
    '--no-table',
  ];

  pushOptional(args, '--context', resolvePath(root, cfg.get('context')));
  pushOptional(args, '--policy', resolvePath(root, cfg.get('policy')));
  pushOptional(args, '--terraform-plan', resolvePath(root, cfg.get('terraformPlan')));
  pushOptional(args, '--terraform-source', resolvePath(root, cfg.get('terraformSource')));
  pushRepeated(args, '--kubernetes-manifest', cfg.get('kubernetesManifest'), root);
  pushRepeated(args, '--source-evidence-in', cfg.get('sourceEvidence'), root);
  pushRepeated(args, '--artifact-manifest', cfg.get('artifactManifest'), root);
  if (profile.analysisProfile === 'production') {
    args.push('--require-strong-source-for-critical');
  }

  await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: 'Reachability Advisor scanning' }, async () => {
    try {
      output.clear();
      output.appendLine(`$ ${executable} ${args.join(' ')}`);
      const result = await execFile(executable, args, root);
      if (result.stderr) {
        output.appendLine(result.stderr);
      }
      if (result.code !== 0 && result.code !== 10) {
        vscode.window.showErrorMessage(`Reachability Advisor failed with exit code ${result.code}. See Output: Reachability Advisor.`);
        return;
      }
      const parsed = JSON.parse(fs.readFileSync(diagnosticsPath, 'utf8'));
      let diagnostics = parsed.diagnostics || [];
      diagnostics = filterByTier(diagnostics, cfg.get('diagnosticMinimumTier') || 'low');
      const baselinePath = resolvePath(root, cfg.get('baseline'));
      diagnostics = await filterByBaseline(diagnostics, executable, root, findingsPath, baselinePath);
      lastDiagnostics = diagnostics;
      publishDiagnostics(diagnostics, root);
      const baselineLabel = baselinePath && fs.existsSync(baselinePath) ? 'baseline filtered' : 'no baseline';
      setStatus(`RA: ${profile.label}, ${diagnostics.length} findings`);
      vscode.window.showInformationMessage(`Reachability Advisor reported ${diagnostics.length} diagnostics (${profile.label}, ${baselineLabel}).`);
    } catch (err) {
      setStatus('RA: failed');
      vscode.window.showErrorMessage(`Reachability Advisor failed: ${err.message}`);
      output.appendLine(err.stack || err.message);
    }
  });
}

async function filterByBaseline(diagnostics, executable, root, findingsPath, baselinePath) {
  if (!baselinePath || !fs.existsSync(baselinePath)) {
    return diagnostics;
  }
  const deltaPath = path.join(os.tmpdir(), `reachability-advisor-delta-${Date.now()}.json`);
  const args = ['compare', '--baseline', baselinePath, '--head-findings', findingsPath, '--only-new-or-worsened', '--out', deltaPath];
  const result = await execFile(executable, args, root);
  if (result.code !== 0) {
    output.appendLine(`Baseline compare failed with exit code ${result.code}; showing all diagnostics.`);
    return diagnostics;
  }
  const delta = JSON.parse(fs.readFileSync(deltaPath, 'utf8'));
  const keys = new Set();
  for (const finding of delta.new || []) {
    if (finding.key) keys.add(finding.key);
  }
  for (const item of delta.worsened || []) {
    if (item.after && item.after.key) keys.add(item.after.key);
  }
  output.appendLine(`Baseline filter kept ${keys.size} new or worsened findings.`);
  return diagnostics.filter((item) => keys.has(item.finding_key));
}

function publishDiagnostics(items, root) {
  collection.clear();
  const byFile = new Map();
  for (const item of items) {
    if (!item.uri || item.uri.startsWith('sbom://')) {
      continue;
    }
    const uri = vscode.Uri.file(path.isAbsolute(item.uri) ? item.uri : path.join(root, item.uri));
    const start = item.range && item.range.start ? item.range.start : { line: 0, character: 0 };
    const end = item.range && item.range.end ? item.range.end : { line: start.line, character: start.character + 1 };
    const diagnostic = new vscode.Diagnostic(
      new vscode.Range(start.line, start.character, end.line, end.character),
      item.message || 'Reachability Advisor finding',
      severity(item.severity)
    );
    diagnostic.source = item.source || 'Reachability Advisor';
    diagnostic.code = {
      value: item.code,
      target: vscode.Uri.parse('command:reachabilityAdvisor.explainFinding'),
    };
    diagnostic.relatedInformation = relatedInformation(item, root);
    if (!byFile.has(uri.toString())) {
      byFile.set(uri.toString(), { uri, diagnostics: [] });
    }
    byFile.get(uri.toString()).diagnostics.push(diagnostic);
  }
  for (const entry of byFile.values()) {
    collection.set(entry.uri, entry.diagnostics);
  }
}

function setStatus(text) {
  if (statusBar) {
    statusBar.text = text;
  }
}

function relatedInformation(item, root) {
  const result = [];
  const locations = (((item.evidence || {}).source_locations) || []).slice(1, 8);
  for (const location of locations) {
    if (!location.path) continue;
    const uri = vscode.Uri.file(path.isAbsolute(location.path) ? location.path : path.join(root, location.path));
    const line = Math.max(0, (location.line || 1) - 1);
    const column = Math.max(0, (location.column || 1) - 1);
    result.push(new vscode.DiagnosticRelatedInformation(new vscode.Location(uri, new vscode.Position(line, column)), location.snippet || 'Source evidence'));
  }
  for (const pathEvidence of (((item.evidence || {}).network_paths) || []).slice(0, 3)) {
    result.push(new vscode.DiagnosticRelatedInformation(new vscode.Location(vscode.Uri.file(root), new vscode.Position(0, 0)), `Network: ${pathEvidence.exposure || 'unknown'} via ${(pathEvidence.steps || []).join(' -> ')}`));
  }
  return result;
}

async function explainFinding() {
  if (!lastDiagnostics.length) {
    vscode.window.showInformationMessage('No Reachability Advisor diagnostics are loaded.');
    return;
  }
  const pick = await vscode.window.showQuickPick(lastDiagnostics.map((item) => ({
    label: `${item.tier} ${item.code}`,
    description: `${item.artifact}/${item.component} score ${item.score}`,
    item,
  })));
  if (!pick) {
    return;
  }
  const item = pick.item;
  const doc = await vscode.workspace.openTextDocument({
    content: JSON.stringify({
      finding_key: item.finding_key,
      tier: item.tier,
      score: item.score,
      confidence: item.confidence,
      source_reachability: item.source_reachability,
      source_evidence: item.source_evidence,
      context: item.context,
      explanation: item.explanation,
      evidence: item.evidence,
    }, null, 2),
    language: 'json',
  });
  vscode.window.showTextDocument(doc, { preview: true });
}

async function validateCurrentProfile() {
  const workspace = vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders[0];
  if (!workspace) {
    vscode.window.showWarningMessage('Reachability Advisor requires an open workspace.');
    return;
  }
  const validation = profileValidation(vscode.workspace.getConfiguration('reachabilityAdvisor'), workspace.uri.fsPath);
  writeProfileValidation(validation);
  const message = validation.status === 'ready'
    ? 'Reachability Advisor profile is ready.'
    : `Reachability Advisor profile is ${validation.status}: ${validation.blockers.concat(validation.warnings).map((item) => item.message).join('; ')}`;
  if (validation.status === 'blocked') {
    vscode.window.showWarningMessage(message);
  } else {
    vscode.window.showInformationMessage(message);
  }
}

async function generatePlan(kind) {
  const workspace = vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders[0];
  if (!workspace) {
    vscode.window.showWarningMessage('Reachability Advisor requires an open workspace.');
    return;
  }
  const root = workspace.uri.fsPath;
  const cfg = vscode.workspace.getConfiguration('reachabilityAdvisor');
  const executable = cfg.get('executable') || 'reachability-advisor';
  const plan = planCommandArgs(kind, cfg, root);
  fs.mkdirSync(plan.outputDir, { recursive: true });
  output.appendLine(`$ ${executable} ${plan.args.join(' ')}`);
  const result = await execFile(executable, plan.args, root);
  if (result.stderr) {
    output.appendLine(result.stderr);
  }
  if (result.code !== 0) {
    vscode.window.showErrorMessage(`Reachability Advisor plan generation failed with exit code ${result.code}. See Output: Reachability Advisor.`);
    return;
  }
  const doc = await vscode.workspace.openTextDocument(plan.markdownPath);
  vscode.window.showTextDocument(doc, { preview: true });
}

function filterByTier(items, minimumTier) {
  const minimum = tierRank[minimumTier] === undefined ? tierRank.low : tierRank[minimumTier];
  return items.filter((item) => (tierRank[item.tier] || 0) >= minimum);
}

function severity(value) {
  if (value === 0) return vscode.DiagnosticSeverity.Error;
  if (value === 1) return vscode.DiagnosticSeverity.Warning;
  if (value === 2) return vscode.DiagnosticSeverity.Information;
  return vscode.DiagnosticSeverity.Hint;
}

function execFile(executable, args, cwd) {
  return new Promise((resolve) => {
    childProcess.execFile(executable, args, { cwd, maxBuffer: 8 * 1024 * 1024 }, (error, stdout, stderr) => {
      const code = error ? (typeof error.code === 'number' ? error.code : 1) : 0;
      resolve({ code, stdout: stdout || '', stderr: stderr || '' });
    });
  });
}

function discoverPath(root, configured, candidates) {
  const explicit = resolvePath(root, configured);
  if (explicit && fs.existsSync(explicit)) {
    return explicit;
  }
  for (const candidate of candidates) {
    const resolved = path.join(root, candidate);
    if (fs.existsSync(resolved)) {
      return resolved;
    }
  }
  return explicit;
}

function resolvePath(root, value) {
  if (!value || typeof value !== 'string' || !value.trim()) {
    return '';
  }
  const trimmed = value.trim();
  return path.isAbsolute(trimmed) ? trimmed : path.join(root, trimmed);
}

function pushOptional(args, flag, value) {
  if (value) {
    args.push(flag, value);
  }
}

function pushRepeated(args, flag, value, root) {
  const values = Array.isArray(value) ? value : String(value || '').split(/\r?\n/);
  for (const item of values) {
    const resolved = resolvePath(root, item);
    if (resolved) {
      args.push(flag, resolved);
    }
  }
}

function configuredPaths(value, root) {
  const paths = [];
  const values = Array.isArray(value) ? value : String(value || '').split(/\r?\n/);
  for (const item of values) {
    const resolved = resolvePath(root, item);
    if (resolved) {
      paths.push(resolved);
    }
  }
  return paths;
}

function profileState(cfg) {
  const preset = cfg.get('profilePreset') || '';
  if (preset === 'release-gate') {
    return { label: 'release gate', analysisProfile: 'production' };
  }
  if (preset === 'advisory') {
    return { label: 'advisory', analysisProfile: 'advisory' };
  }
  const analysisProfile = cfg.get('analysisProfile') || 'advisory';
  return { label: analysisProfile === 'production' ? 'release gate' : 'advisory', analysisProfile };
}

function profileValidation(cfg, root) {
  const profile = profileState(cfg);
  const blockers = [];
  const warnings = [];
  const sbom = discoverPath(root, cfg.get('sbom'), ['app.cdx.json', 'bom.json', 'sbom.json', 'reachability/app.cdx.json', 'reachability/sbom.cdx.json', '.reachability/app.cdx.json']);
  const vulns = discoverPath(root, cfg.get('vulns'), ['vulnerabilities.json', 'grype.json', 'reachability/vulnerabilities.json', 'reachability/grype.json', '.reachability/grype.json']);
  const sourceEvidence = configuredPaths(cfg.get('sourceEvidence'), root).filter((item) => fs.existsSync(item));
  const terraformPlan = resolvePath(root, cfg.get('terraformPlan'));
  const terraformSource = resolvePath(root, cfg.get('terraformSource'));
  const kubernetesManifests = configuredPaths(cfg.get('kubernetesManifest'), root).filter((item) => fs.existsSync(item));
  const artifactManifests = configuredPaths(cfg.get('artifactManifest'), root).filter((item) => fs.existsSync(item));

  if (!sbom || !fs.existsSync(sbom)) {
    blockers.push({ kind: 'missing_sbom', message: 'missing SBOM; run Reachability Advisor: Generate SBOM Plan or configure reachabilityAdvisor.sbom' });
  }
  if (!vulns || !fs.existsSync(vulns)) {
    blockers.push({ kind: 'missing_vulnerabilities', message: 'missing vulnerability JSON; configure reachabilityAdvisor.vulns' });
  }
  if (profile.analysisProfile === 'production') {
    if (!sourceEvidence.length) {
      blockers.push({ kind: 'missing_external_source_evidence', message: 'release gate requires Semgrep, CodeQL, govulncheck, or native source evidence' });
    }
    if ((!terraformPlan || !fs.existsSync(terraformPlan)) && !kubernetesManifests.length) {
      blockers.push({ kind: 'missing_rendered_deployment_evidence', message: 'release gate requires terraform show -json plan or rendered Kubernetes manifests' });
    }
    if (terraformSource && fs.existsSync(terraformSource) && (!terraformPlan || !fs.existsSync(terraformPlan))) {
      blockers.push({ kind: 'terraform_source_only', message: 'Terraform source mode is advisory; release gate needs a rendered Terraform plan' });
    }
    if (!artifactManifests.length) {
      warnings.push({ kind: 'missing_artifact_manifest', message: 'no CI artifact manifest configured; image digest matching may depend on SBOM metadata only' });
    }
  }
  return {
    status: blockers.length ? 'blocked' : warnings.length ? 'warning' : 'ready',
    profile: profile.label,
    analysisProfile: profile.analysisProfile,
    blockers,
    warnings,
  };
}

function writeProfileValidation(validation) {
  if (!output) {
    return;
  }
  output.appendLine(`Profile: ${validation.profile} (${validation.status})`);
  for (const item of validation.blockers) {
    output.appendLine(`  blocker: ${item.message}`);
  }
  for (const item of validation.warnings) {
    output.appendLine(`  warning: ${item.message}`);
  }
}

function planCommandArgs(kind, cfg, root) {
  const outputDir = path.join(root, '.reachability');
  if (kind === 'sbom') {
    const artifact = cfg.get('sourceRootArtifact') || 'app';
    return {
      outputDir,
      markdownPath: path.join(outputDir, 'sbom-plan.md'),
      args: [
        'sbom-plan',
        '--artifact', artifact,
        '--source-root', root,
        '--output-dir', '.reachability',
        '--out-md', path.join(outputDir, 'sbom-plan.md'),
        '--out-json', path.join(outputDir, 'sbom-plan.json'),
      ],
    };
  }
  return {
    outputDir,
    markdownPath: path.join(outputDir, 'source-evidence-plan.md'),
    args: [
      'source-evidence-plan',
      '--source-root', root,
      '--output-dir', '.reachability',
      '--out-md', path.join(outputDir, 'source-evidence-plan.md'),
      '--out-json', path.join(outputDir, 'source-evidence-plan.json'),
    ],
  };
}

module.exports = {
  activate,
  deactivate,
  configuredPaths,
  discoverPath,
  filterByTier,
  planCommandArgs,
  profileValidation,
  profileState,
  pushRepeated,
  resolvePath,
};
