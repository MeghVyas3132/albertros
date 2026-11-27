import type { DepInput } from './types.js';

export interface ParsedInput {
  kind: 'package.json' | 'package-lock.json' | 'list';
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
  return { kind: 'list', deps: parseList(trimmed) };
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

/** Fetch a repo's lockfile (preferred) or package.json from GitHub. */
export async function fetchGithub(input: string, opts: { includeDev?: boolean } = {}): Promise<ParsedInput & { source: string }> {
  const g = parseGithub(input);
  if (!g) throw new Error('Use a GitHub repo like "expressjs/express" or https://github.com/owner/repo');
  const base = `https://raw.githubusercontent.com/${g.owner}/${g.repo}/${g.ref}/${g.dir ? g.dir + '/' : ''}`;
  const get = async (f: string) => {
    const r = await fetch(base + f);
    return r.ok ? r.text() : null;
  };
  const [lock, pkg] = await Promise.all([get('package-lock.json'), get('package.json')]);
  if (!pkg && !lock) throw new Error(`No package.json found in ${g.owner}/${g.repo}${g.dir ? '/' + g.dir : ''}. Is the repo public?`);
  const source = `github.com/${g.owner}/${g.repo}${g.dir ? '/' + g.dir : ''}`;
  if (lock) {
    try {
      const parsed = parseLock(JSON.parse(lock), opts);
      return { ...parsed, source: `${source} (package-lock.json)` };
    } catch {
      /* fall through to package.json */
    }
  }
  return { ...parseManifest(JSON.parse(pkg!), opts), source: `${source} (package.json)` };
}
