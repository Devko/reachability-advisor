const vscode = require('vscode');
const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const tierRank = { informational: 0, low: 1, medium: 2, high: 3, urgent: 4 };

let collection;
let output;
let lastDiagnostics = [];

function activate(context) {
  collection = vscode.languages.createDiagnosticCollection('Reachability Advisor');
  output = vscode.window.createOutputChannel('Reachability Advisor');
  context.subscriptions.push(collection, output);
  context.subscriptions.push(vscode.commands.registerCommand('reachabilityAdvisor.scanWorkspace', scanWorkspace));
  context.subscriptions.push(vscode.commands.registerCommand('reachabilityAdvisor.explainFinding', explainFinding));
}

function deactivate() {
  if (collection) {
    collection.dispose();
  }
  if (output) {
    output.dispose();
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
  const sbom = discoverPath(root, cfg.get('sbom'), ['app.cdx.json', 'bom.json', 'sbom.json', 'reachability/app.cdx.json']);
  const vulns = discoverPath(root, cfg.get('vulns'), ['vulnerabilities.json', 'grype.json', 'reachability/vulnerabilities.json']);
  if (!sbom || !vulns) {
    vscode.window.showWarningMessage('Reachability Advisor needs an SBOM and vulnerability JSON. Configure reachabilityAdvisor.sbom and reachabilityAdvisor.vulns.');
    return;
  }

  const diagnosticsPath = path.join(os.tmpdir(), `reachability-advisor-diagnostics-${Date.now()}.json`);
  const findingsPath = path.join(os.tmpdir(), `reachability-advisor-findings-${Date.now()}.json`);
  const sourceCoveragePath = path.join(os.tmpdir(), `reachability-advisor-source-${Date.now()}.json`);
  const args = [
    'scan',
    '--sbom', sbom,
    '--vulns', vulns,
    '--source-root', `${cfg.get('sourceRootArtifact') || 'app'}=${root}`,
    '--analysis-profile', cfg.get('analysisProfile') || 'advisory',
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
      diagnostics = await filterByBaseline(diagnostics, executable, root, findingsPath, resolvePath(root, cfg.get('baseline')));
      lastDiagnostics = diagnostics;
      publishDiagnostics(diagnostics, root);
      vscode.window.showInformationMessage(`Reachability Advisor reported ${diagnostics.length} diagnostics.`);
    } catch (err) {
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
    diagnostic.code = item.code;
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

module.exports = { activate, deactivate };
