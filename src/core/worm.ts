import type { PackageReport } from './types.js';

/**
 * Worm simulator: how a Shai-Hulud style worm would spread through *your* dependency tree.
 *
 * Model (matches how CanisterWorm, Shai-Hulud and Miasma spread in 2025-2026):
 *  1. Patient zero: one maintainer account's npm token is stolen.
 *  2. The worm republishes every package that account can publish (up to `cap`).
 *  3. Anyone who maintains a package that depends on a poisoned package runs the poisoned code while
 *     developing or in CI. With probability `p` their token is on that machine, so they are infected
 *     and the next generation begins.
 *  4. Repeat until no new account is infected.
 *
 * Only the packages and maintainers in your tree are modelled, so the result is a lower bound on
 * the worm's real reach and an exact answer to "how much of what I install would be poisoned".
 */
export interface WormGeneration {
  gen: number;
  accounts: string[];
  packages: string[];
}

export interface WormRun {
  patientZero: string;
  generations: WormGeneration[];
  poisoned: number;
  poisonedShare: number;
  accountsInfected: number;
  directPoisoned: number;
}

export interface WormModel {
  accounts: string[];
  run(patientZero: string, p?: number, cap?: number, rng?: () => number): WormRun;
  /** Average reach over many random runs at infection chance p. */
  expected(patientZero: string, p: number, runs?: number): { poisonedShare: number; generations: number };
  /** Accounts ranked by worst-case outbreak size. */
  superSpreaders(limit?: number): { account: string; poisonedShare: number; generations: number; accountsInfected: number }[];
}

export function buildWorm(packages: PackageReport[]): WormModel {
  const byName = new Map<string, PackageReport>();
  for (const p of packages) if (!byName.has(p.name)) byName.set(p.name, p);
  const total = byName.size;
  const direct = new Set(packages.filter((p) => p.direct).map((p) => p.name));

  const owns = new Map<string, string[]>(); // account -> packages it can publish
  for (const p of byName.values()) {
    for (const m of p.meta.maintainers || []) {
      if (!owns.has(m)) owns.set(m, []);
      owns.get(m)!.push(p.name);
    }
  }
  // dependents: package -> packages that depend on it (in this tree)
  const dependents = new Map<string, string[]>();
  for (const p of byName.values()) {
    for (const d of p.meta.deps || []) {
      if (!byName.has(d)) continue;
      if (!dependents.has(d)) dependents.set(d, []);
      dependents.get(d)!.push(p.name);
    }
  }
  const accounts = [...owns.keys()];

  function run(patientZero: string, p = 1, cap = 100, rng: () => number = Math.random): WormRun {
    const infected = new Set<string>([patientZero]);
    const poisoned = new Set<string>();
    const generations: WormGeneration[] = [];
    let wave = [patientZero];
    let gen = 0;
    while (wave.length && gen < 50) {
      const newPkgs: string[] = [];
      for (const acct of wave) {
        for (const pkg of (owns.get(acct) || []).slice(0, cap)) {
          if (!poisoned.has(pkg)) {
            poisoned.add(pkg);
            newPkgs.push(pkg);
          }
        }
      }
      generations.push({ gen, accounts: wave, packages: newPkgs });
      const next: string[] = [];
      for (const pkg of newPkgs) {
        for (const dep of dependents.get(pkg) || []) {
          for (const m of byName.get(dep)!.meta.maintainers || []) {
            if (!infected.has(m) && rng() < p) {
              infected.add(m);
              next.push(m);
            }
          }
        }
      }
      wave = next;
      gen++;
    }
    return {
      patientZero,
      generations,
      poisoned: poisoned.size,
      poisonedShare: total ? poisoned.size / total : 0,
      accountsInfected: infected.size,
      directPoisoned: [...poisoned].filter((x) => direct.has(x)).length,
    };
  }

  function expected(patientZero: string, p: number, runs = 200) {
    let share = 0;
    let gens = 0;
    for (let i = 0; i < runs; i++) {
      const r = run(patientZero, p);
      share += r.poisonedShare;
      gens += r.generations.length;
    }
    return { poisonedShare: share / runs, generations: gens / runs };
  }

  function superSpreaders(limit = 10) {
    return accounts
      .map((a) => {
        const r = run(a, 1);
        return { account: a, poisonedShare: r.poisonedShare, generations: r.generations.length, accountsInfected: r.accountsInfected };
      })
      .sort((x, y) => y.poisonedShare - x.poisonedShare || x.generations - y.generations)
      .slice(0, limit);
  }

  return { accounts, run, expected, superSpreaders };
}
