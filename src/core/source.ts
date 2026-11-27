import { pool } from './net.js';
import { scanFiles } from './scan.js';
import type { PkgFile } from './tarball.js';
import type { Finding } from './types.js';

export interface SourceCheck {
  status: 'verified' | 'differs' | 'built' | 'commit-missing' | 'not-located' | 'no-commit' | 'not-github';
  repo?: string;
  commit?: string;
  dir?: string;
  compared: number;
  matched: number;
  modified: { path: string; added: string[] }[];
  notInGit: string[];
}

const RAW = 'https://raw.githubusercontent.com';
const CODE = /\.(c?js|mjs|cts|mts|ts|jsx|tsx|sh|ps1|py)$/;
const SKIP = /(^|\/)(package\.json|readme[^/]*|changelog[^/]*|license[^/]*|.*\.d\.[cm]?ts|.*\.map)$/i;
const MAX_FILES = 30;

export function githubRepo(manifest: any): { owner: string; repo: string; dir: string } | null {
  const raw = typeof manifest?.repository === 'string' ? manifest.repository : manifest?.repository?.url;
  if (!raw) return null;
  const m = /github(?:\.com[:/]|:)([\w.-]+)\/([\w.-]+?)(?:\.git)?(?:[#/].*)?$/i.exec(String(raw)) || /^([\w.-]+)\/([\w.-]+)$/.exec(String(raw));
  if (!m) return null;
  return { owner: m[1], repo: m[2], dir: (manifest?.repository?.directory || '').replace(/^\.?\/|\/$/g, '') };
}

async function rawText(url: string): Promise<string | null> {
  try {
    const r = await fetch(url);
    if (r.status === 404) return null;
    if (!r.ok) throw new Error(`GitHub ${r.status}`);
    return await r.text();
  } catch (e) {
    throw e;
  }
}

const norm = (s: string) => s.replace(/\r\n/g, '\n').split('\n').map((l) => l.trimEnd()).join('\n').trim();

/** Lines present in the published file but absent from the git version. */
function addedLines(published: string, git: string): string[] {
  const have = new Map<string, number>();
  for (const l of git.split('\n')) {
    const k = l.trim();
    if (k) have.set(k, (have.get(k) || 0) + 1);
  }
  const out: string[] = [];
  for (const l of published.split('\n')) {
    const k = l.trim();
    if (!k) continue;
    const n = have.get(k) || 0;
    if (n > 0) have.set(k, n - 1);
    else out.push(l);
  }
  return out;
}

/** Locate the package inside the repo at the given commit (handles monorepos). */
async function locate(base: string, name: string, hint: string): Promise<{ dir: string } | 'commit-missing' | null> {
  const bare = name.replace(/^@[^/]+\//, '');
  const candidates = [...new Set([hint, '', `packages/${bare}`, `npm/${name}`, `npm/${bare}`, `packages/${name.replace('@', '').replace('/', '-')}`, bare])];
  let anyCommit = false;
  for (const dir of candidates) {
    const txt = await rawText(`${base}/${dir ? dir + '/' : ''}package.json`).catch(() => null);
    if (txt == null) continue;
    anyCommit = true;
    try {
      if (JSON.parse(txt).name === name) return { dir };
    } catch {
      /* not JSON */
    }
  }
  if (!anyCommit) {
    // Is it the commit that is missing, or just package.json at that path?
    const readme = await rawText(`${base}/README.md`).catch(() => null);
    if (readme == null) return 'commit-missing';
  }
  return null;
}

/**
 * Compare the published tarball with the GitHub repo at the commit npm recorded (gitHead).
 * This is the check that would have caught the xz backdoor and hand-published hijacks:
 * code that ships to users but does not exist in the project's source.
 */
export async function verifyAgainstSource(manifest: any, files: PkgFile[], installFiles: string[] = []): Promise<{ check: SourceCheck; findings: Finding[] }> {
  const gh = githubRepo(manifest);
  const empty = { compared: 0, matched: 0, modified: [], notInGit: [] };
  if (!gh) return { check: { status: 'not-github', ...empty }, findings: [] };
  const repo = `${gh.owner}/${gh.repo}`;
  const commit: string | undefined = manifest.gitHead;
  if (!commit) {
    return {
      check: { status: 'no-commit', repo, ...empty },
      findings: [
        {
          code: 'source-no-commit',
          severity: 'info',
          title: 'Release does not record its source commit',
          detail: 'npm stores the git commit a release was published from. This one has none, so it cannot be compared with the repo.',
        },
      ],
    };
  }
  const base = `${RAW}/${gh.owner}/${gh.repo}/${commit}`;
  const where = await locate(base, manifest.name, gh.dir);
  const short = commit.slice(0, 7);
  if (where === 'commit-missing') {
    return {
      check: { status: 'commit-missing', repo, commit, ...empty },
      findings: [
        {
          code: 'source-commit-missing',
          severity: 'review',
          title: `Source commit ${short} is not in ${repo}`,
          detail: 'The release says it was built from a commit that the public repo does not contain. It may have been force-pushed away, or the release was built from code that was never pushed.',
          link: `https://github.com/${repo}/commit/${commit}`,
        },
      ],
    };
  }
  if (!where) {
    return {
      check: { status: 'not-located', repo, commit, ...empty },
      findings: [{ code: 'source-not-located', severity: 'info', title: 'Could not find the package in its repo', detail: `${repo} at ${short} has no package.json named ${manifest.name}.` }],
    };
  }

  const prefix = where.dir ? where.dir + '/' : '';
  const install = new Set(installFiles);
  const main = String(manifest.main || 'index.js').replace(/^\.\//, '');
  const code = files
    .filter((f) => f.text != null && CODE.test(f.path) && !SKIP.test(f.path))
    .sort((a, b) => Number(install.has(b.path)) - Number(install.has(a.path)) || Number(b.path === main) - Number(a.path === main) || a.size - b.size)
    .slice(0, MAX_FILES);

  const check: SourceCheck = { status: 'verified', repo, commit, dir: where.dir, compared: 0, matched: 0, modified: [], notInGit: [] };
  await pool(code, 6, async (f) => {
    const git = await rawText(`${base}/${prefix}${f.path}`).catch(() => undefined);
    if (git === undefined) return;
    if (git === null) {
      check.notInGit.push(f.path);
      return;
    }
    check.compared++;
    if (norm(git) === norm(f.text!)) {
      check.matched++;
      return;
    }
    const added = addedLines(norm(f.text!), norm(git));
    if (!added.length) check.matched++;
    else check.modified.push({ path: f.path, added });
  });

  const findings: Finding[] = [];
  const link = `https://github.com/${repo}/tree/${commit}${where.dir ? '/' + where.dir : ''}`;
  if (check.modified.length) {
    check.status = 'differs';
    // Run the attack patterns over just the injected lines.
    const injected = scanFiles(check.modified.map((m) => ({ path: m.path, size: 0, text: m.added.join('\n') })), installFiles);
    const bad = injected.findings.some((x) => x.severity === 'danger');
    const total = check.modified.reduce((n, m) => n + m.added.length, 0);
    const tiny = !bad && total <= 2;
    findings.push({
      code: 'source-differs',
      severity: bad ? 'danger' : tiny ? 'info' : 'review',
      title: bad
        ? 'Code that is not in the source repo, and it looks like an attack'
        : `${check.modified.length} published file${check.modified.length > 1 ? 's differ' : ' differs'} from source commit ${short}`,
      detail: bad
        ? `These lines ship to everyone who installs it but do not exist in ${repo} at ${short}: ${injected.findings.filter((x) => x.severity === 'danger').map((x) => x.title.toLowerCase()).join(', ')}.`
        : tiny
          ? 'Tiny publish-time edits (often a version string). Shown for completeness.'
          : `${total} line${total > 1 ? 's' : ''} in the package do not exist in the repo at the commit it claims to come from. Review them before trusting this release.`,
      evidence: check.modified.slice(0, 4).flatMap((m) => [`${m.path}  (+${m.added.length} lines not in git)`, ...m.added.slice(0, 6).map((l) => '  + ' + l.trim().slice(0, 160))]),
      link,
    });
  }
  const installNotInGit = check.notInGit.filter((p) => install.has(p));
  if (installNotInGit.length) {
    findings.push({
      code: 'source-install-not-in-git',
      severity: 'review',
      title: 'Install script is not in the source repo',
      detail: 'The file npm runs during install was added at publish time and cannot be reviewed on GitHub.',
      evidence: installNotInGit,
      link,
    });
  }
  if (!check.compared) {
    check.status = 'built';
    findings.push({
      code: 'source-built',
      severity: 'info',
      title: 'Built during publish',
      detail: `All ${check.notInGit.length} code files are build output that is not committed to ${repo}, so they cannot be compared line by line.`,
      link,
    });
  } else if (!check.modified.length) {
    findings.push({
      code: 'source-verified',
      severity: 'good',
      title: `Matches source commit ${short}`,
      detail: `${check.matched} of ${check.compared} code files are identical to ${repo} at the commit this release was published from.${check.notInGit.length ? ` ${check.notInGit.length} more are build output not kept in git.` : ''}`,
      link,
    });
  }
  return { check, findings };
}
