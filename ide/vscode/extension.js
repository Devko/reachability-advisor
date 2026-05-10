const vscode = require('vscode');
const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

let collection;

function activate(context) {
  collection = vscode.languages.createDiagnosticCollection('Reachability Advisor');
  context.subscriptions.push(collection);
  context.subscriptions.push(vscode.commands.registerCommand('reachabilityAdvisor.scanWorkspace', scanWorkspace));
}

function deactivate() {
  if (collection) {
    collection.dispose();
  }
}

function scanWorkspace() {
  const workspace = vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders[0];
  if (!workspace) {
    vscode.window.showWarningMessage('Reachability Advisor requires an open workspace.');
    return;
  }
  const root = workspace.uri.fsPath;
  const cfg = vscode.workspace.getConfiguration('reachabilityAdvisor');
  const executable = cfg.get('executable') || 'reachability-advisor';
  const sbom = path.join(root, cfg.get('sbom') || 'app.cdx.json');
  const vulns = path.join(root, cfg.get('vulns') || 'vulnerabilities.json');
  const contextPath = cfg.get('context') ? path.join(root, cfg.get('context')) : '';
  const artifact = cfg.get('sourceRootArtifact') || 'app';
  const diagnosticsPath = path.join(os.tmpdir(), `reachability-advisor-${Date.now()}.json`);
  const args = ['scan', '--sbom', sbom, '--vulns', vulns, '--source-root', `${artifact}=${root}`, '--diagnostics-out', diagnosticsPath, '--no-table'];
  if (contextPath) {
    args.push('--context', contextPath);
  }
  vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: 'Reachability Advisor scanning' }, () => {
    return new Promise((resolve) => {
      childProcess.execFile(executable, args, { cwd: root, maxBuffer: 1024 * 1024 }, (error, stdout, stderr) => {
        if (error) {
          vscode.window.showErrorMessage(`Reachability Advisor failed: ${stderr || error.message}`);
          resolve();
          return;
        }
        try {
          const parsed = JSON.parse(fs.readFileSync(diagnosticsPath, 'utf8'));
          publishDiagnostics(parsed.diagnostics || []);
          vscode.window.showInformationMessage(`Reachability Advisor reported ${(parsed.diagnostics || []).length} diagnostics.`);
        } catch (err) {
          vscode.window.showErrorMessage(`Reachability Advisor diagnostics parse failed: ${err.message}`);
        }
        resolve();
      });
    });
  });
}

function publishDiagnostics(items) {
  collection.clear();
  const byFile = new Map();
  for (const item of items) {
    if (!item.uri || item.uri.startsWith('sbom://')) {
      continue;
    }
    const uri = vscode.Uri.file(item.uri);
    const start = item.range && item.range.start ? item.range.start : { line: 0, character: 0 };
    const end = item.range && item.range.end ? item.range.end : { line: start.line, character: start.character + 1 };
    const diagnostic = new vscode.Diagnostic(
      new vscode.Range(start.line, start.character, end.line, end.character),
      item.message || 'Reachability Advisor finding',
      severity(item.severity)
    );
    diagnostic.source = item.source || 'Reachability Advisor';
    diagnostic.code = item.code;
    if (!byFile.has(uri.toString())) {
      byFile.set(uri.toString(), { uri, diagnostics: [] });
    }
    byFile.get(uri.toString()).diagnostics.push(diagnostic);
  }
  for (const entry of byFile.values()) {
    collection.set(entry.uri, entry.diagnostics);
  }
}

function severity(value) {
  if (value === 0) return vscode.DiagnosticSeverity.Error;
  if (value === 1) return vscode.DiagnosticSeverity.Warning;
  if (value === 2) return vscode.DiagnosticSeverity.Information;
  return vscode.DiagnosticSeverity.Hint;
}

module.exports = { activate, deactivate };
