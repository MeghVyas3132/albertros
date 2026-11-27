import type { PackageReport } from './types.js';

export interface Account {
  name: string;
  /** Packages in your tree this account can publish. */
  packages: string[];
  /** Your direct dependencies that would deliver code from this account if it were phished. */
  directReach: string[];
  /** Every package that would run or pull in the attacker's code. */
  affected: string[];
}

export interface TrustReport {
  /** Distinct npm accounts that can publish code into this install. */
  people: number;
  packages: number;
  direct: number;
  /** Packages whose code runs automatically during npm install. */
  runOnInstall: string[];
  /** Packages with exactly one maintainer: one stolen password, no second pair of eyes. */
  solo: number;
  /** Packages not released in over 3 years. */
  stale: number;
  /** Accounts sorted by how much of your app one phished password reaches. */
  accounts: Account[];
  /** Graph edges parent -> child by package name (root is ""). */
  edges: [string, string][];
}

/**
 * Who can push code into this install, and how far one stolen account reaches.
 * Reach is computed on the dependency graph: if an account publishes a poisoned version of a package,
 * every package that depends on it (up to your direct dependencies) delivers that code to you.
 */
export function computeTrust(packages: PackageReport[], now = Date.now()): TrustReport {
  const byName = new Map<string, PackageReport>();
  for (const p of packages) if (!byName.has(p.name)) byName.set(p.name, p);
  const names = [...byName.keys()];
  const direct = packages.filter((p) => p.direct).map((p) => p.name);

  const edges: [string, string][] = [];
  const parents = new Map<string, Set<string>>();
  const link = (from: string, to: string) => {
    if (!byName.has(to) || from === to) return;
    edges.push([from, to]);
    if (!parents.has(to)) parents.set(to, new Set());
    parents.get(to)!.add(from);
  };
  for (const d of new Set(direct)) link('', d);
  for (const p of byName.values()) for (const d of p.meta.deps || []) link(p.name, d);

  const owned = new Map<string, Set<string>>();
  for (const p of byName.values()) {
    for (const m of p.meta.maintainers || []) {
      if (!owned.has(m)) owned.set(m, new Set());
      owned.get(m)!.add(p.name);
    }
  }

  const ancestorsCache = new Map<string, Set<string>>();
  const ancestors = (n: string): Set<string> => {
    const hit = ancestorsCache.get(n);
    if (hit) return hit;
    const out = new Set<string>();
    const stack = [n];
    while (stack.length) {
      const x = stack.pop()!;
      for (const par of parents.get(x) || []) {
        if (par && !out.has(par)) {
          out.add(par);
          stack.push(par);
        }
      }
    }
    ancestorsCache.set(n, out);
    return out;
  };

  const directSet = new Set(direct);
  const accounts: Account[] = [...owned.entries()].map(([name, pk]) => {
    const affected = new Set<string>(pk);
    for (const p of pk) for (const a of ancestors(p)) affected.add(a);
    return {
      name,
      packages: [...pk].sort(),
      directReach: [...affected].filter((x) => directSet.has(x)).sort(),
      affected: [...affected].sort(),
    };
  });
  accounts.sort((a, b) => b.directReach.length - a.directReach.length || b.affected.length - a.affected.length || b.packages.length - a.packages.length);

  const runOnInstall = names.filter((n) => byName.get(n)!.meta.hasInstallScript);
  const solo = names.filter((n) => (byName.get(n)!.meta.maintainers || []).length === 1).length;
  const stale = names.filter((n) => {
    const t = byName.get(n)!.meta.publishedAt;
    return t && now - Date.parse(t) > 3 * 365 * 864e5;
  }).length;

  return { people: owned.size, packages: names.length, direct: directSet.size, runOnInstall, solo, stale, accounts, edges };
}
