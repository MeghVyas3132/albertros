import type { DepInput } from './types.js';

export interface ParsedInput {
  kind: 'package.json' | 'package-lock.json' | 'pnpm-lock.yaml' | 'yarn.lock' | 'list';
  name?: string;
  deps: DepInput[];
}

function nameFromLockKey(key: string): string {
  const i = key.lastIndexOf('node_modules/');
  return i === -1 ? key : key.slice(i + 'node_modules/'.length);
}

/** Parse a package.json, a package-lock.json (v1-v3), or a plain list like "lodash@4.17.21 express". */
export function parseInput(text: string, opts: { includeDev?: boolean } = {}): ParsedInput {
  const trimmed = text.trim();
  if (!trimmed) throw new Error('Nothing to check: paste a package.json, a package-lock.json, or package names.');
  if (trimmed.startsWith('{')) {
    let j: any;
    try {
      j = JSON.parse(trimmed);
    } catch (e) {
      throw new Error(`That looks like JSON but does not parse: ${(e as Error).message}`);
    }
    if (j.lockfileVersion) return parseLock(j, opts);
    return parseManifest(j, opts);
  }
  if (/^lockfileVersion:/m.test(trimmed) && /^(importers|packages|dependencies):/m.test(trimmed)) return parsePnpmLock(trimmed, opts);
  if (/^# yarn lockfile v1|^__metadata:/m.test(trimmed)) return parseYarnLock(trimmed);
  return { kind: 'list', deps: parseList(trimmed) };
}

const unquote = (s: string) => s.trim().replace(/^['"]|['"]$/g, '');

function splitNameVersion(key: string): { name: string; version: string } | null {
  let k = unquote(key).replace(/^\//, '');
  k = k.replace(/\(.*$/, ''); // pnpm v9 peer suffix: foo@1.0.0(react@18.0.0)
  const at = k.lastIndexOf('@');
  if (at > 0) {
    const name = k.slice(0, at);
    const version = k.slice(at + 1).replace(/_.*$/, ''); // pnpm v6 peer suffix: foo@1.0.0_react@18
    return { name, version };
  }
  // pnpm v5: /name/1.2.3
  const m = /^(@[^/]+\/[^/]+|[^/]+)\/(\d[^/]*)$/.exec(k);
  return m ? { name: m[1], version: m[2] } : null;
}

/** pnpm-lock.yaml v5-v9: every resolved package, with direct ones taken from importers. */
export function parsePnpmLock(text: string, opts: { includeDev?: boolean } = {}): ParsedInput {
  const lines = text.split('\n');
  const direct = new Map<string, boolean>(); // name -> dev
  let section = '';
  let group = '';
  let current = '';
  const pkgs: { name: string; version: string }[] = [];
  for (const line of lines) {
    if (/^\S/.test(line)) {
      section = line.replace(/:.*$/, '').trim();
      continue;
    }
    if (section === 'importers' || section === 'dependencies' || section === 'devDependencies' || section === 'optionalDependencies') {
      // v9/v6 importers: 4-space group, 6-space name. v5 root-level dependencies: 2-space name.
      const g = /^ {4}(dependencies|devDependencies|optionalDependencies):/.exec(line);
      if (g) {
        group = g[1];
        continue;
      }
      const nameLine = section === 'importers' ? /^ {6}(['"]?[^'"\s:][^:]*?['"]?):/.exec(line) : /^ {2}(['"]?[^'"\s:][^:]*?['"]?):/.exec(line);
      if (nameLine) {
        current = unquote(nameLine[1]);
        const dev = (section === 'importers' ? group : section) === 'devDependencies';
        if (!direct.has(current) || !dev) direct.set(current, dev);
      }
      const ver = /^ +version: *(.+)$/.exec(line);
      if (ver && /^link:/.test(unquote(ver[1])) && current) direct.delete(current);
      continue;
    }
    if (section === 'packages') {
      const m = /^ {2}(['"]?[^\s].*?['"]?):\s*$/.exec(line);
      if (m) {
        const nv = splitNameVersion(m[1]);
        if (nv && /^\d/.test(nv.version)) pkgs.push(nv);
      }
    }
  }
  const seen = new Set<string>();
  const deps: DepInput[] = [];
  for (const p of pkgs) {
    const key = `${p.name}@${p.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const isDirect = direct.has(p.name);
    const dev = isDirect ? direct.get(p.name)! : false;
    if (dev && opts.includeDev === false) continue;
    deps.push({ name: p.name, spec: p.version, direct: isDirect, dev });
  }
  if (!deps.length) throw new Error('This pnpm lockfile lists no packages.');
  return { kind: 'pnpm-lock.yaml', deps };
}

/** yarn.lock, classic (v1) and Berry. Direct dependencies are marked from directNames when given. */
export function parseYarnLock(text: string, directNames: Set<string> = new Set()): ParsedInput {
  const deps: DepInput[] = [];
  const seen = new Set<string>();
  let name: string | null = null;
  for (const line of text.split('\n')) {
    if (/^\S/.test(line) && line.trim().endsWith(':') && !line.startsWith('#') && !line.startsWith('__metadata')) {
      const first = unquote(line.slice(0, -1).split(',')[0]);
      if (/@(workspace|patch|link|file|portal|exec):/.test(first)) {
        name = null;
        continue;
      }
      const at = first.indexOf('@', 1);
      name = at > 0 ? first.slice(0, at) : first;
      // Aliases: "eslint-v7@npm:eslint@^7.0.0" installs the real package "eslint".
      const rest = at > 0 ? first.slice(at + 1) : '';
      if (rest.startsWith('npm:')) {
        const real = rest.slice(4);
        const ra = real.indexOf('@', 1);
        if (ra > 0) name = real.slice(0, ra);
        else if (!/^[\^~<>=*\d]/.test(real)) name = real;
      }
      continue;
    }
    const v = /^ {2}version:? +"?([^"\s]+)"?/.exec(line);
    if (v && name) {
      const key = `${name}@${v[1]}`;
      if (!seen.has(key)) {
        seen.add(key);
        deps.push({ name, spec: v[1], direct: directNames.has(name) });
      }
      name = null;
    }
  }
  if (!deps.length) throw new Error('This yarn.lock lists no packages.');
  return { kind: 'yarn.lock', deps };
}

export function parseManifest(j: any, opts: { includeDev?: boolean } = {}): ParsedInput {
  const deps: DepInput[] = [];
  const add = (obj: any, dev: boolean) => {
    for (const [name, spec] of Object.entries(obj || {})) deps.push({ name, spec: String(spec), direct: true, dev });
  };
  add(j.dependencies, false);
  add(j.optionalDependencies, false);
  if (opts.includeDev !== false) add(j.devDependencies, true);
  if (!deps.length) throw new Error('This package.json has no dependencies to check.');
  return { kind: 'package.json', name: j.name, deps };
}

export function parseLock(j: any, opts: { includeDev?: boolean } = {}): ParsedInput {
  const deps: DepInput[] = [];
  if (j.packages) {
    const root = j.packages[''] || {};
    const directNames = new Set([
      ...Object.keys(root.dependencies || {}),
      ...Object.keys(root.devDependencies || {}),
      ...Object.keys(root.optionalDependencies || {}),
    ]);
    for (const [key, v] of Object.entries<any>(j.packages)) {
      if (!key || v.link || !v.version || !key.includes('node_modules/')) continue;
      if (v.dev && opts.includeDev === false) continue;
      const name = v.name || nameFromLockKey(key);
      const nested = key.slice(key.indexOf('node_modules/') + 13).includes('node_modules/');
      const spec = /^(https?:|git)/.test(v.resolved || '') && !String(v.resolved).includes('registry.npmjs.org') ? v.resolved : v.version;
      deps.push({ name, spec, direct: !nested && directNames.has(name), dev: !!v.dev });
    }
  } else if (j.dependencies) {
    const walk = (obj: any, depth: number) => {
      for (const [name, v] of Object.entries<any>(obj || {})) {
        if (v.dev && opts.includeDev === false) continue;
        if (v.version) deps.push({ name, spec: v.version, direct: depth === 0, dev: !!v.dev });
        walk(v.dependencies, depth + 1);
      }
    };
    walk(j.dependencies, 0);
  }
  if (!deps.length) throw new Error('This lockfile lists no packages.');
  return { kind: 'package-lock.json', name: j.name, deps };
}

export function parseList(text: string): DepInput[] {
  return text
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => {
      const at = s.lastIndexOf('@');
      if (at > 0) return { name: s.slice(0, at), spec: s.slice(at + 1) || 'latest', direct: true };
      return { name: s, spec: 'latest', direct: true };
    });
}

/** "github.com/owner/repo", "owner/repo", or a full URL with /tree/branch/sub/dir */
export function parseGithub(input: string): { owner: string; repo: string; ref: string; dir: string } | null {
  const s = input.trim().replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\.git$/, '').replace(/\/$/, '');
  const m = /^(?:github\.com\/)?([\w.-]+)\/([\w.-]+)(?:\/tree\/([^/]+)(\/.*)?)?$/.exec(s);
  if (!m) return null;
  return { owner: m[1], repo: m[2], ref: m[3] || 'HEAD', dir: (m[4] || '').replace(/^\//, '') };
}

export interface ProjectFile {
  path: string;
  text: string;
}

const PROJECT_FILES = ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'package.json'];
const SKIP_DIR = /(^|\/)(node_modules|\.git|dist|build|out|coverage|vendor|fixtures?|__tests__|test|tests|examples?|\.next|\.turbo)(\/|$)/;

/**
 * Merge every project in a repo: each folder contributes its lockfile (exact versions) if it has one,
 * otherwise its package.json. Covers monorepos and "frontend/ + backend/" layouts.
 */
export function collectProject(files: ProjectFile[], opts: { includeDev?: boolean } = {}): { deps: DepInput[]; kinds: string[]; folders: string[] } {
  const byDir = new Map<string, Map<string, string>>();
  for (const f of files) {
    const i = f.path.lastIndexOf('/');
    const dir = i === -1 ? '' : f.path.slice(0, i);
    const base = i === -1 ? f.path : f.path.slice(i + 1);
    if (SKIP_DIR.test(dir)) continue;
    if (!byDir.has(dir)) byDir.set(dir, new Map());
    byDir.get(dir)!.set(base, f.text);
  }
  // A root pnpm/npm lockfile already covers every workspace below it.
  const root = byDir.get('');
  const rootLock = root && (root.get('pnpm-lock.yaml') || root.get('package-lock.json'));
  const deps: DepInput[] = [];
  const kinds = new Set<string>();
  const folders: string[] = [];
  const localNames = new Set<string>();
  for (const m of byDir.values()) {
    try {
      const n = m.get('package.json') && JSON.parse(m.get('package.json')!).name;
      if (n) localNames.add(n);
    } catch {
      /* ignore */
    }
  }
  for (const [dir, m] of [...byDir.entries()].sort((a, b) => a[0].length - b[0].length)) {
    if (rootLock && dir !== '' && !m.has('package-lock.json') && !m.has('pnpm-lock.yaml') && !m.has('yarn.lock')) continue;
    let parsed: ParsedInput | null = null;
    let pkg: any = null;
    try {
      pkg = m.get('package.json') ? JSON.parse(m.get('package.json')!) : null;
    } catch {
      /* broken package.json */
    }
    const directNames = new Set(pkg ? [...Object.keys(pkg.dependencies || {}), ...Object.keys(pkg.devDependencies || {}), ...Object.keys(pkg.optionalDependencies || {})] : []);
    try {
      if (m.get('package-lock.json')) parsed = parseLock(JSON.parse(m.get('package-lock.json')!), opts);
      else if (m.get('pnpm-lock.yaml')) parsed = parsePnpmLock(m.get('pnpm-lock.yaml')!, opts);
      else if (m.get('yarn.lock')) parsed = parseYarnLock(m.get('yarn.lock')!, directNames);
      else if (pkg) parsed = parseManifest(pkg, opts);
    } catch {
      parsed = null;
    }
    if (!parsed) continue;
    kinds.add(parsed.kind);
    folders.push(dir || '.');
    deps.push(...parsed.deps.filter((d) => !localNames.has(d.name) && !/^(workspace|link|file):/.test(d.spec)));
  }
  return { deps, kinds: [...kinds], folders };
}

async function rawFile(g: { owner: string; repo: string; ref: string }, path: string): Promise<string | null> {
  try {
    const r = await fetch(`https://raw.githubusercontent.com/${g.owner}/${g.repo}/${g.ref}/${path}`);
    return r.ok ? await r.text() : null;
  } catch {
    return null;
  }
}

const COMMON_DIRS = ['', 'frontend', 'backend', 'client', 'server', 'web', 'app', 'api', 'cli', 'ui', 'site', 'landing', 'website', 'dashboard', 'admin', 'apps/web', 'apps/api', 'apps/frontend', 'apps/backend', 'packages/core', 'packages/web', 'src'];

/** Fetch every lockfile and package.json in a public GitHub repo, including nested folders. */
export async function fetchGithub(input: string, opts: { includeDev?: boolean } = {}): Promise<ParsedInput & { source: string }> {
  const g = parseGithub(input);
  if (!g) throw new Error('Use a GitHub repo like "expressjs/express" or https://github.com/owner/repo');
  const prefix = g.dir ? g.dir + '/' : '';
  const source = `github.com/${g.owner}/${g.repo}${g.dir ? '/' + g.dir : ''}`;

  // 1. Every project file in the repo, from one tree listing.
  let paths: string[] | null = null;
  try {
    const res = await fetch(`https://api.github.com/repos/${g.owner}/${g.repo}/git/trees/${g.ref}?recursive=1`);
    if (res.ok) {
      const tree = await res.json();
      paths = (tree.tree || [])
        .map((t: any) => t.path as string)
        .filter((p: string) => p.startsWith(prefix) && PROJECT_FILES.some((f) => p === prefix + f || p.endsWith('/' + f)))
        .filter((p: string) => !SKIP_DIR.test(p.slice(0, p.lastIndexOf('/') + 1)))
        .slice(0, 80);
    }
  } catch {
    /* rate limited or offline */
  }
  // 2. GitHub API unavailable (60 requests/hour without a token): probe the usual folder names directly.
  if (!paths) paths = COMMON_DIRS.flatMap((d) => PROJECT_FILES.map((f) => prefix + (d ? d + '/' : '') + f));

  const files = (await Promise.all(paths.map(async (p) => ({ path: p.slice(prefix.length), text: await rawFile(g, p) })))).filter((f): f is ProjectFile => f.text != null);
  if (!files.length) throw new Error(`No package.json or lockfile found anywhere in ${g.owner}/${g.repo}${g.dir ? '/' + g.dir : ''}. Is it a public JavaScript project?`);
  const { deps, kinds, folders } = collectProject(files, opts);
  if (!deps.length) throw new Error(`${g.owner}/${g.repo} has no npm dependencies to check.`);
  let rootName: string | undefined;
  try {
    rootName = JSON.parse(files.find((f) => f.path === 'package.json')?.text || '{}').name;
  } catch {
    /* ignore */
  }
  const where = folders.length === 1 ? (folders[0] === '.' ? kinds[0] : `${folders[0]}/ ${kinds[0]}`) : `${folders.length} folders: ${folders.slice(0, 4).join(', ')}${folders.length > 4 ? '…' : ''}`;
  return { kind: (kinds[0] as ParsedInput['kind']) || 'package.json', name: rootName, deps, source: `${source} (${where})` };
}
