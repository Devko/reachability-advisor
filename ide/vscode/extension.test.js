const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const extension = require('./extension');

function cfg(values) {
  return {
    get: (key) => values[key],
  };
}

const release = extension.profileState(cfg({ profilePreset: 'release-gate', analysisProfile: 'advisory' }));
assert.deepStrictEqual(release, { label: 'release gate', analysisProfile: 'production' });

const advisory = extension.profileState(cfg({ profilePreset: 'advisory', analysisProfile: 'production' }));
assert.deepStrictEqual(advisory, { label: 'advisory', analysisProfile: 'advisory' });

const configuredProduction = extension.profileState(cfg({ profilePreset: '', analysisProfile: 'production' }));
assert.deepStrictEqual(configuredProduction, { label: 'release gate', analysisProfile: 'production' });

const filtered = extension.filterByTier([
  { tier: 'low' },
  { tier: 'medium' },
  { tier: 'high' },
], 'medium');
assert.deepStrictEqual(filtered.map((item) => item.tier), ['medium', 'high']);

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ra-vscode-'));
fs.mkdirSync(path.join(root, 'reachability'));
fs.writeFileSync(path.join(root, 'reachability', 'sbom.cdx.json'), '{}');
assert.strictEqual(extension.discoverPath(root, '', ['reachability/sbom.cdx.json']), path.join(root, 'reachability', 'sbom.cdx.json'));
assert.strictEqual(extension.resolvePath(root, 'reachability/grype.json'), path.join(root, 'reachability', 'grype.json'));

const args = [];
extension.pushRepeated(args, '--source-evidence-in', ['reachability/semgrep.json', ''], root);
assert.deepStrictEqual(args, ['--source-evidence-in', path.join(root, 'reachability', 'semgrep.json')]);

const blocked = extension.profileValidation(cfg({ profilePreset: 'release-gate', sbom: '', vulns: '', sourceEvidence: [], terraformPlan: '', terraformSource: '', kubernetesManifest: [], artifactManifest: [] }), root);
assert.strictEqual(blocked.status, 'blocked');
assert.ok(blocked.blockers.some((item) => item.kind === 'missing_vulnerabilities'));
assert.ok(blocked.blockers.some((item) => item.kind === 'missing_external_source_evidence'));
assert.ok(blocked.blockers.some((item) => item.kind === 'missing_rendered_deployment_evidence'));

fs.writeFileSync(path.join(root, 'vulnerabilities.json'), '{}');
fs.writeFileSync(path.join(root, 'semgrep.json'), '{}');
fs.writeFileSync(path.join(root, 'tfplan.json'), '{}');
fs.writeFileSync(path.join(root, 'artifact-manifest.json'), '{}');
const ready = extension.profileValidation(cfg({
  profilePreset: 'release-gate',
  sbom: 'reachability/sbom.cdx.json',
  vulns: 'vulnerabilities.json',
  sourceEvidence: ['semgrep.json'],
  terraformPlan: 'tfplan.json',
  terraformSource: '',
  kubernetesManifest: [],
  artifactManifest: ['artifact-manifest.json'],
}), root);
assert.strictEqual(ready.status, 'ready');

const sbomPlan = extension.planCommandArgs('sbom', cfg({ sourceRootArtifact: 'checkout' }), root);
assert.deepStrictEqual(sbomPlan.args.slice(0, 3), ['sbom-plan', '--artifact', 'checkout']);
assert.strictEqual(sbomPlan.markdownPath, path.join(root, '.reachability', 'sbom-plan.md'));

const sourcePlan = extension.planCommandArgs('source-evidence', cfg({}), root);
assert.strictEqual(sourcePlan.args[0], 'source-evidence-plan');
assert.strictEqual(sourcePlan.markdownPath, path.join(root, '.reachability', 'source-evidence-plan.md'));

console.log('VS Code extension helper tests passed');
