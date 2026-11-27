import semver from 'semver';
import { getDownloads, getManifest, getPackument, pool } from './net.js';
import { queryOsv } from './osv.js';
import { installEntryFiles, scanFiles, scanInstallScript } from './scan.js';
import { readTarball } from './tarball.js';
import { typosquatOf } from './typosquat.js';
import { verifyRegistrySignature } from './verify.js';
import { verifyAgainstSource } from './source.js';
import type { AnalyzeOptions, DepInput, Finding, PackageReport, ProjectReport, Verdict } from './types.js';

interface Work extends PackageReport {
  manifest?: any;
  packument?: any;
}

const SEV_ORDER = { danger: 0, review: 1, info: 2, good: 3 } as const;
const HOUR = 3600_000;
const DAY = 24 * HOUR;

const INSTALL_KEYS = ['preinstall', 'install', 'postinstall'];
const hasInstall = (m: any) => !!m && (INSTALL_KEYS.some((k) => m.scripts?.[k]) || !!m.gypfile);

function ago(ms: number): string {
  if (ms < HOUR) return `${Math.max(1, Math.round(ms / 60000))} min`;
  if (ms < 2 * DAY) return `${Math.round(ms / HOUR)} h`;
  return `${Math.round(ms / DAY)} days`;
}

function repoUrl(m: any): string | undefined {
  const r = typeof m?.repository === 'string' ? m.repository : m?.repository?.url;
  if (!r) return undefined;
  return String(r)
    .replace(/^git\+/, '')
    .replace(/^git:\/\//, 'https://')
    .replace(/^github:/, 'https://github.com/')
    .replace(/^ssh:\/\/git@/, 'https://')
    .replace(/^git@github\.com:/, 'https://github.com/')
    .replace(/\.git$/, '');
}

function splitAlias(name: string, spec: string): { name: string; spec: string; alias: boolean } {
  if (!spec.startsWith('npm:')) return { name, spec, alias: false };
  const s = spec.slice(4);
  const at = s.lastIndexOf('@');
  if (at > 0) return { name: s.slice(0, at), spec: s.slice(at + 1), alias: true };
  return { name: s, spec: 'latest', alias: true };
}

async function resolveOne(d: DepInput, now: number): Promise<Work> {
  const a = splitAlias(d.name, d.spec.trim());
  const r: Work = { name: a.name, spec: d.spec, direct: d.direct, dev: !!d.dev, verdict: 'unknown', findings: [], meta: {}, scanned: false };
  if (a.alias) {
    r.findings.push({
      code: 'alias',
      severity: 'info',
      title: `Installed under another name`,
      detail: `Your code imports "${d.name}", but npm installs "${a.name}".`,
    });
  }
  const spec = a.spec;
  if (/^(workspace:|link:|file:|portal:|\.{0,2}\/)/.test(spec)) {
    r.findings.push({ code: 'local', severity: 'info', title: 'Local package', detail: 'Comes from your own repo, not the npm registry.' });
    return r;
  }
  if (/^(git(\+\w+)?:|github:|gitlab:|bitbucket:|https?:)/.test(spec) || /^[\w-]+\/[\w.-]+(#.*)?$/.test(spec)) {
    r.findings.push({
      code: 'non-registry',
      severity: 'review',
      title: 'Installed from a URL or git, not npm',
      detail: 'Nothing pins what is at that address. Whoever controls it can change the code you install.',
      evidence: [spec],
    });
    return r;
  }

  const exact = semver.valid(spec);
  let manifest: any = null;
  let packument: any = null;
  if (exact && !d.direct) manifest = await getManifest(a.name, exact);
  if (!manifest) packument = await getPackument(a.name);

  if (!manifest && !packument) {
    r.findings.push({
      code: 'not-on-npm',
      severity: 'danger',
      title: 'This name does not exist on npm',
      detail:
        'Anyone can register it and publish code that your next `npm install` will run. This is how dependency-confusion attacks work. If it is a private package, use a scope (@your-org/name) that you own.',
    });
    return r;
  }

  if (packument && !manifest) {
    const versions = Object.keys(packument.versions || {});
    const tags = packument['dist-tags'] || {};
    let version: string | null = null;
    if (exact) version = exact;
    else if (!spec || spec === '*' || spec === 'latest') version = tags.latest ?? null;
    else if (tags[spec]) version = tags[spec];
    else if (semver.validRange(spec)) {
      version = tags.latest && semver.satisfies(tags.latest, spec) ? tags.latest : semver.maxSatisfying(versions, spec);
    }
    const latestDoc = tags.latest ? packument.versions?.[tags.latest] : null;
    if (latestDoc && (/-security$/.test(latestDoc.version) || latestDoc.description === 'security holding package')) {
      r.version = exact ?? latestDoc.version;
      r.packument = packument;
      r.findings.push({
        code: 'security-holding',
        severity: 'danger',
        title: 'npm took this package down as malicious',
        detail: 'The name now points to an empty "security holding" placeholder. The original package was malware. Remove it and check the machines that installed it.',
        link: `https://www.npmjs.com/package/${a.name}`,
      });
      return r;
    }
    if (!versions.length) {
      r.version = exact ?? undefined;
      r.findings.push({
        code: 'unpublished',
        severity: 'danger',
        title: 'Removed from npm',
        detail: 'Every version of this package has been unpublished. npm usually does this after malware reports.',
      });
      r.packument = packument;
      return r;
    }
    if (!version || !packument.versions[version]) {
      r.version = exact ?? undefined;
      r.findings.push({
        code: 'version-missing',
        severity: 'review',
        title: exact ? `Version ${exact} is no longer on npm` : `No version matches "${spec}"`,
        detail: exact
          ? 'It was unpublished. npm pulls versions mostly when they were malicious or broken. Upgrade to a current release.'
          : 'npm install will fail, or pick something unexpected.',
      });
      r.packument = packument;
      return r;
    }
    manifest = packument.versions[version];
  }

  r.version = manifest.version;
  r.manifest = manifest;
  r.packument = packument ?? undefined;
  r.meta = {
    description: manifest.description,
    publisher: manifest._npmUser?.name,
    repository: repoUrl(manifest),
    license: typeof manifest.license === 'string' ? manifest.license : manifest.license?.type,
    unpackedSize: manifest.dist?.unpackedSize,
    hasInstallScript: hasInstall(manifest),
    provenance: !!manifest.dist?.attestations?.provenance,
    publishedAt: packument?.time?.[manifest.version],
  };

  if (manifest.description === 'security holding package' || /-security$/.test(manifest.version) || /npm\/security-holder/.test(r.meta.repository || '')) {
    r.findings.push({
      code: 'security-holding',
      severity: 'danger',
      title: 'npm took this package down as malicious',
      detail: 'The name now points to an empty "security holding" placeholder. The original package was malware. Remove it and check the machines that installed it.',
      link: `https://www.npmjs.com/package/${a.name}`,
    });
    return r;
  }

  const sig = await verifyRegistrySignature(manifest.name || a.name, manifest.version, manifest.dist).catch(() => 'unknown-key' as const);
  r.meta.signature = sig;
  if (sig === 'invalid') {
    r.findings.push({
      code: 'signature-invalid',
      severity: 'danger',
      title: 'npm registry signature does not match',
      detail: 'The registry signs every version (name, version and tarball hash). This one fails verification, so what you would install is not what npm published.',
      evidence: [`${a.name}@${manifest.version}:${manifest.dist?.integrity}`],
    });
  } else if (sig === 'missing') {
    r.findings.push({
      code: 'signature-missing',
      severity: 'review',
      title: 'No npm registry signature',
      detail: 'npm signs every version it serves. A missing signature usually means a mirror or proxy rewrote the metadata.',
    });
  }
  r.findings.push(...scanInstallScript(manifest.scripts));
  if (manifest.gypfile && !INSTALL_KEYS.some((k) => manifest.scripts?.[k])) {
    r.findings.push({ code: 'install-script-native', severity: 'info', title: 'Compiles native code on install', detail: 'Has a binding.gyp, so npm runs node-gyp during install.' });
  }
  if (manifest.deprecated) {
    r.findings.push({ code: 'deprecated', severity: 'review', title: 'Deprecated by its author', detail: String(manifest.deprecated).slice(0, 300) });
  }
  if (r.meta.provenance) {
    r.findings.push({ code: 'provenance', severity: 'good', title: 'Built and signed by CI', detail: 'Published with npm provenance: you can trace this tarball to the source commit and build that made it.' });
  }

  // Release history: the signals that caught chalk/debug (Sept 2025) and the Shai-Hulud worm.
  if (packument?.time && packument.versions) {
    const t = packument.time;
    const published = t[manifest.version] ? Date.parse(t[manifest.version]) : NaN;
    if (!Number.isNaN(published)) {
      const age = now - published;
      if (age < 3 * DAY) {
        r.findings.push({
          code: 'fresh',
          severity: 'review',
          title: `Published ${ago(age)} ago`,
          detail: 'Most malicious releases are caught and pulled within days. Waiting 3 days before adopting new versions blocks the bulk of attacks.',
        });
      }
    }
    const isPre = !!semver.prerelease(manifest.version);
    const history = Object.keys(packument.versions)
      .filter((v) => t[v] && Date.parse(t[v]) < (Number.isNaN(published) ? Infinity : published))
      .filter((v) => isPre || !semver.prerelease(v))
      .sort((x, y) => Date.parse(t[y]) - Date.parse(t[x]));
    const prev = history.length ? packument.versions[history[0]] : null;
    const prevPublishers = new Set(history.slice(0, 10).map((v) => packument.versions[v]?._npmUser?.name).filter(Boolean));
    const signals: string[] = [];
    const trusted = r.meta.publisher === 'GitHub Actions' && r.meta.provenance;
    if (trusted && prevPublishers.size && !prevPublishers.has(r.meta.publisher!)) {
      r.findings.push({ code: 'trusted-publishing', severity: 'good', title: 'Now released from CI', detail: 'Recently moved to npm trusted publishing, so no long-lived token can publish it.' });
    } else if (r.meta.publisher && prevPublishers.size && !prevPublishers.has(r.meta.publisher)) {
      signals.push(`first release by ${r.meta.publisher}`);
      r.findings.push({
        code: 'new-publisher',
        severity: 'info',
        title: `First release by ${r.meta.publisher}`,
        detail: `None of the previous ${Math.min(10, history.length)} versions were published by this account. Stolen npm tokens look exactly like this.`,
        evidence: [`earlier publishers: ${[...prevPublishers].join(', ')}`],
      });
    }
    if (prev && hasInstall(manifest) && !hasInstall(prev)) {
      signals.push('install script added');
      r.findings.push({
        code: 'install-added',
        severity: 'review',
        title: `Install script added in ${manifest.version}`,
        detail: `${prev.version} ran nothing on install. This version does. Worms like Shai-Hulud spread by adding a postinstall.`,
      });
    }
    if (prev?.dist?.attestations?.provenance && !r.meta.provenance) {
      signals.push('provenance dropped');
      r.findings.push({
        code: 'provenance-dropped',
        severity: 'review',
        title: 'Published by hand, not from CI',
        detail: `${prev.version} was built and signed by CI. This version was not, which is what a release made with a stolen token looks like.`,
      });
    }
    const curSize = manifest.dist?.unpackedSize;
    const prevSize = prev?.dist?.unpackedSize;
    if (curSize && prevSize && curSize > 2 * prevSize && curSize - prevSize > 200_000) {
      signals.push('size jump');
      r.findings.push({
        code: 'size-jump',
        severity: 'review',
        title: `Grew ${(curSize / prevSize).toFixed(1)}x since ${prev.version}`,
        detail: `${Math.round(prevSize / 1024)} kB → ${Math.round(curSize / 1024)} kB. Injected payloads often show up as a sudden size jump.`,
      });
    }
    const fresh = r.findings.some((f) => f.code === 'fresh');
    if (signals.length >= 2 || (signals.length >= 1 && fresh && signals[0] !== 'size jump')) {
      r.findings.push({
        code: 'hijack-pattern',
        severity: 'danger',
        title: 'Looks like a hijacked release',
        detail: 'Several takeover signals at once. Pin the previous version until the maintainers confirm this release.',
        evidence: [...signals, ...(fresh ? ['published in the last 3 days'] : [])],
      });
    }
  }
  return r;
}

function needsScan(r: Work): boolean {
  if (!r.manifest?.dist?.tarball) return false;
  return r.meta.hasInstallScript || r.findings.some((f) => f.severity === 'danger' || f.severity === 'review');
}

export function verdictOf(findings: Finding[]): Verdict {
  if (findings.some((f) => f.severity === 'danger')) return 'danger';
  if (findings.some((f) => f.severity === 'review')) return 'review';
  return 'safe';
}

export async function scanPackageCode(r: PackageReport & { manifest?: any }): Promise<void> {
  const m = (r as Work).manifest;
  if (!m?.dist?.tarball || r.scanned) return;
  try {
    const files = await readTarball(m.dist.tarball, m.dist.integrity);
    if (files.integrityOk === false) {
      r.meta.integrity = 'mismatch';
      r.findings.push({
        code: 'integrity-mismatch',
        severity: 'danger',
        title: 'Tarball does not match its published hash',
        detail: 'The file served for download differs from the sha512 npm recorded at publish time. Something between you and the publisher changed it.',
        evidence: [m.dist.integrity],
      });
    } else if (files.integrityOk) r.meta.integrity = 'verified';
    const installFiles = installEntryFiles(m.scripts);
    const res = scanFiles(files, installFiles);
    r.findings.push(...res.findings);
    try {
      const src = await verifyAgainstSource(m, files, installFiles);
      r.findings.push(...src.findings);
      const c = src.check;
      r.meta.source = { status: c.status, repo: c.repo, commit: c.commit, compared: c.compared, matched: c.matched, modified: c.modified.length, notInGit: c.notInGit.length };
    } catch (e) {
      r.findings.push({ code: 'source-failed', severity: 'info', title: 'Could not compare with the source repo', detail: String((e as Error).message || e) });
    }
    r.findings.push({
      code: 'scanned',
      severity: res.findings.length ? 'info' : 'good',
      title: res.findings.length ? `Scanned ${res.filesScanned} files` : `Code scan clean (${res.filesScanned} files)`,
      detail: 'Checked the published tarball (hash verified) for the patterns used by real npm attacks: install-time downloads, hidden eval, token theft, wallet hijacking, obfuscation.',
    });
    r.scanned = true;
  } catch (e) {
    r.findings.push({ code: 'scan-failed', severity: 'info', title: 'Could not scan the code', detail: String((e as Error).message || e) });
  }
  finalize(r);
}

function finalize(r: PackageReport) {
  r.findings.sort((x, y) => SEV_ORDER[x.severity] - SEV_ORDER[y.severity]);
  r.verdict = r.error ? 'unknown' : verdictOf(r.findings);
}

export function scoreOf(packages: PackageReport[]): { score: number; counts: Record<Verdict, number> } {
  const counts: Record<Verdict, number> = { danger: 0, review: 0, safe: 0, unknown: 0 };
  for (const p of packages) counts[p.verdict]++;
  const score = Math.max(0, Math.round(100 - Math.min(100, counts.danger * 25 + counts.review * 3)));
  return { score, counts };
}

export function sortReports(packages: PackageReport[]): PackageReport[] {
  const order = { danger: 0, review: 1, unknown: 2, safe: 3 };
  return packages.sort((a, b) => order[a.verdict] - order[b.verdict] || Number(b.direct) - Number(a.direct) || a.name.localeCompare(b.name));
}

export async function analyzeProject(source: string, deps: DepInput[], opts: AnalyzeOptions = {}): Promise<ProjectReport> {
  const now = opts.now ?? Date.now();
  const startedAt = new Date().toISOString();
  const max = opts.maxPackages ?? 300;
  const progress = opts.onProgress ?? (() => {});

  const uniq = new Map<string, DepInput>();
  for (const d of deps) {
    const k = `${d.name}@${d.spec}`;
    const e = uniq.get(k);
    if (!e) uniq.set(k, { ...d });
    else {
      e.direct ||= d.direct;
      e.dev = !!e.dev && !!d.dev;
    }
  }
  let list = [...uniq.values()].sort((a, b) => Number(b.direct) - Number(a.direct));
  const skipped = Math.max(0, list.length - max);
  list = list.slice(0, max);

  let done = 0;
  progress({ stage: 'Reading the npm registry', done, total: list.length });
  const downloadsP = getDownloads(list.map((d) => splitAlias(d.name, d.spec).name));
  const reports: Work[] = await pool(list, 10, async (d) => {
    let r: Work;
    try {
      r = await resolveOne(d, now);
    } catch (e) {
      r = { name: d.name, spec: d.spec, direct: d.direct, dev: !!d.dev, verdict: 'unknown', findings: [], meta: {}, scanned: false, error: String((e as Error).message || e) };
    }
    progress({ stage: 'Reading the npm registry', done: ++done, total: list.length });
    return r;
  });

  progress({ stage: 'Checking download counts and look-alike names', done: 0, total: 1 });
  const downloads = await downloadsP;
  for (const r of reports) {
    const dl = downloads.get(r.name);
    r.meta.weeklyDownloads = dl ?? null;
    const squat = r.name.startsWith('@types/') ? null : typosquatOf(r.name);
    const holding = r.findings.some((f) => f.code === 'security-holding' || f.code === 'not-on-npm');
    if (squat && !holding && (dl == null || dl < 50_000)) {
      r.findings.push({
        code: 'typosquat',
        severity: dl == null || dl < 5_000 ? 'danger' : 'review',
        title: `Name imitates "${squat}"`,
        detail: `One typo away from a hugely popular package, with ${dl == null ? 'almost no' : dl.toLocaleString('en-US')} downloads a week. Typosquats steal installs from people who mistype.`,
        link: `https://www.npmjs.com/package/${squat}`,
      });
    } else if (squat && holding) {
      r.findings.push({ code: 'typosquat', severity: 'info', title: `Name imitates "${squat}"`, detail: 'A classic typosquat.' });
    }
    if (r.version && dl != null && dl < 50 && r.direct && !holding) {
      r.findings.push({
        code: 'unpopular',
        severity: 'review',
        title: `Almost nobody uses it (${dl} downloads/week)`,
        detail: 'Few eyes on the code means problems go unnoticed. Make sure you meant this package.',
      });
    }
  }

  progress({ stage: 'Checking OSV for known malware and vulnerabilities', done: 0, total: 1 });
  const osv = await queryOsv(reports.filter((r) => r.version).map((r) => ({ name: r.name, version: r.version! })));
  for (const r of reports) {
    if (!r.version) continue;
    const advisories = osv.get(`${r.name}@${r.version}`) || [];
    const bad = advisories.filter((x) => x.malicious);
    if (bad.length) {
      r.findings.push({
        code: 'osv-malicious',
        severity: 'danger',
        title: 'Known malicious version',
        detail: bad[0].summary,
        link: bad[0].url,
        evidence: bad.map((a) => `${a.id}  ${a.summary}`),
      });
    }
    const vulns = advisories.filter((x) => !x.malicious);
    if (vulns.length) {
      const serious = vulns.filter((v) => v.severity === 'high' || v.severity === 'critical');
      r.findings.push({
        code: 'osv-vuln',
        severity: serious.length ? 'review' : 'info',
        title: `${vulns.length} known vulnerabilit${vulns.length === 1 ? 'y' : 'ies'}${serious.length ? ` (${serious.length} high or critical)` : ''}`,
        detail: 'Security bugs fixed in later versions. Not an attack, but worth upgrading.',
        evidence: vulns.slice(0, 6).map((v) => `${v.id}${v.severity ? ` [${v.severity}]` : ''}  ${v.summary}`),
        link: vulns[0].url,
      });
    }
  }

  const toScan = reports.filter((r) => (opts.deep ? !!r.manifest?.dist?.tarball : needsScan(r))).slice(0, opts.deep ? 80 : 30);
  let scanned = 0;
  progress({ stage: 'Scanning package code', done: 0, total: toScan.length });
  await pool(toScan, 4, async (r) => {
    await scanPackageCode(r);
    progress({ stage: 'Scanning package code', done: ++scanned, total: toScan.length });
  });

  for (const r of reports) {
    // Binary installers like esbuild or sharp legitimately download during install.
    if ((r.meta.weeklyDownloads ?? 0) > 1_000_000) {
      for (const f of r.findings) if (['code-install-exec-net', 'install-script', 'source-install-not-in-git'].includes(f.code)) f.severity = 'info';
    }
    finalize(r);
  }
  const packages = sortReports(reports.map(({ manifest, packument, ...rest }) => Object.defineProperty(rest, 'manifest', { value: manifest, enumerable: false }) as PackageReport));
  const { score, counts } = scoreOf(packages);
  return { source, packages, score, counts, startedAt, finishedAt: new Date().toISOString(), skipped };
}
