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

/** Fetch a repo's lockfile (npm, pnpm or yarn) or its package.json files, including monorepo workspaces. */
export async function fetchGithub(input: string, opts: { includeDev?: boolean } = {}): Promise<ParsedInput & { source: string }> {
  const g = parseGithub(input);
  if (!g) throw new Error('Use a GitHub repo like "expressjs/express" or https://github.com/owner/repo');
  const base = `https://raw.githubusercontent.com/${g.owner}/${g.repo}/${g.ref}/${g.dir ? g.dir + '/' : ''}`;
  const get = async (f: string) => {
    const r = await fetch(base + f);
    return r.ok ? r.text() : null;
  };
  const source = `github.com/${g.owner}/${g.repo}${g.dir ? '/' + g.dir : ''}`;
  const [pkg, lock, pnpm, yarn] = await Promise.all([get('package.json'), get('package-lock.json'), get('pnpm-lock.yaml'), get('yarn.lock')]);
  if (!pkg && !lock && !pnpm && !yarn) throw new Error(`No package.json found in ${g.owner}/${g.repo}${g.dir ? '/' + g.dir : ''}. Is the repo public?`);

  let root: any = {};
  try {
    root = pkg ? JSON.parse(pkg) : {};
  } catch {
    /* ignore */
  }
  if (lock) {
    try {
      return { ...parseLock(JSON.parse(lock), opts), source: `${source} (package-lock.json)` };
    } catch {
      /* fall through */
    }
  }
  if (pnpm) {
    try {
      return { ...parsePnpmLock(pnpm, opts), source: `${source} (pnpm-lock.yaml)` };
    } catch {
      /* fall through */
    }
  }
  const manifests = await workspaceManifests(g, root);
  const directNames = new Set(manifests.flatMap((m) => [...Object.keys(m.dependencies || {}), ...Object.keys(m.devDependencies || {}), ...Object.keys(m.optionalDependencies || {})]));
  if (yarn) {
    try {
      return { ...parseYarnLock(yarn, directNames), source: `${source} (yarn.lock)` };
    } catch {
      /* fall through */
    }
  }
  const deps: DepInput[] = [];
  const local = new Set(manifests.map((m) => m.name).filter(Boolean));
  for (const m of manifests) {
    try {
      deps.push(...parseManifest(m, opts).deps.filter((d) => !local.has(d.name) && !/^workspace:/.test(d.spec)));
    } catch {
      /* no deps in this one */
    }
  }
  if (!deps.length) throw new Error(`${g.owner}/${g.repo} has no npm dependencies to check.`);
  return { kind: 'package.json', name: root.name, deps, source: `${source} (${manifests.length > 1 ? `${manifests.length} package.json files` : 'package.json'})` };
}

/** Root package.json plus every workspace package.json (found with one GitHub tree call). */
async function workspaceManifests(g: { owner: string; repo: string; ref: string; dir: string }, root: any): Promise<any[]> {
  const out = [root];
  const hasDeps = (m: any) => Object.keys({ ...m.dependencies, ...m.devDependencies, ...m.optionalDependencies }).length > 0;
  const isMono = !!root.workspaces || !hasDeps(root);
  if (!isMono) return out;
  try {
    const res = await fetch(`https://api.github.com/repos/${g.owner}/${g.repo}/git/trees/${g.ref}?recursive=1`);
    if (!res.ok) return out;
    const tree = await res.json();
    const prefix = g.dir ? g.dir + '/' : '';
    const paths: string[] = (tree.tree || [])
      .map((t: any) => t.path as string)
      .filter((p: string) => p.startsWith(prefix) && p.endsWith('/package.json') && !/(^|\/)(node_modules|test|tests|fixtures|examples?|__tests__)\//.test(p))
      .slice(0, 40);
    const raws = await Promise.all(
      paths.map((p) =>
        fetch(`https://raw.githubusercontent.com/${g.owner}/${g.repo}/${g.ref}/${p}`)
          .then((r) => (r.ok ? r.json() : null))
          .catch(() => null),
      ),
    );
    out.push(...raws.filter(Boolean));
  } catch {
    /* rate limited: root only */
  }
  return out;
}
