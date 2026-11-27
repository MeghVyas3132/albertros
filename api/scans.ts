import { list, put } from '@vercel/blob';
import type { VercelRequest, VercelResponse } from '@vercel/node';

/**
 * Public scan history. Only public GitHub repos are recorded (never pasted files or package lists),
 * and only summary numbers: no findings, no maintainer names.
 */
interface Entry {
  repo: string;
  scannedAt: string;
  packages: number;
  score: number;
  danger: number;
  review: number;
  people: number;
  topPct: number;
  wormPct: number;
}
interface Index {
  updatedAt: string;
  totals: { scans: number; packages: number; dangers: number };
  entries: Entry[];
}

const PREFIX = 'history/scans/';
const REPO_RE = /^[A-Za-z0-9_.-]{1,39}\/[A-Za-z0-9_.-]{1,100}$/;
const recent = new Map<string, number>();

const n = (v: unknown, max: number) => Math.max(0, Math.min(max, Math.round(Number(v) || 0)));

/** One blob per scan (no read-modify-write races); the newest scan of each repo wins. */
async function load(): Promise<Index> {
  const blobs: { url: string; pathname: string; uploadedAt: Date }[] = [];
  let cursor: string | undefined;
  do {
    const page = await list({ prefix: PREFIX, limit: 1000, cursor });
    blobs.push(...page.blobs);
    cursor = page.hasMore ? page.cursor : undefined;
  } while (cursor && blobs.length < 5000);
  blobs.sort((a, b) => +new Date(b.uploadedAt) - +new Date(a.uploadedAt));
  const latest = blobs.slice(0, 120);
  const entries = (await Promise.all(latest.map((b) => fetch(b.url).then((r) => (r.ok ? (r.json() as Promise<Entry>) : null)).catch(() => null)))).filter(Boolean) as Entry[];
  const seen = new Set<string>();
  const unique = entries.filter((e) => {
    const k = e.repo.toLowerCase();
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  return {
    updatedAt: latest[0] ? new Date(latest[0].uploadedAt).toISOString() : new Date().toISOString(),
    totals: { scans: blobs.length, packages: entries.reduce((a, e) => a + e.packages, 0), dangers: entries.reduce((a, e) => a + e.danger, 0) },
    entries: unique.slice(0, 60),
  };
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (!process.env.BLOB_READ_WRITE_TOKEN) {
    return res.status(503).json({ error: 'history storage not configured', entries: [], totals: { scans: 0, packages: 0, dangers: 0 } });
  }
  if (req.method === 'GET') {
    res.setHeader('cache-control', 'public, s-maxage=20, stale-while-revalidate=120');
    return res.status(200).json(await load());
  }
  if (req.method !== 'POST') return res.status(405).end();

  const ip = String(req.headers['x-forwarded-for'] || '').split(',')[0] || 'unknown';
  const last = recent.get(ip) || 0;
  if (Date.now() - last < 5000) return res.status(429).json({ error: 'slow down' });
  recent.set(ip, Date.now());

  const b = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : req.body || {};
  const repo = String(b.repo || '').replace(/^https?:\/\/(www\.)?github\.com\//, '').replace(/\.git$|\/$/g, '');
  if (!REPO_RE.test(repo)) return res.status(400).json({ error: 'repo must be owner/name' });

  // Only list repositories that are actually public JavaScript projects.
  const files = ['package.json', 'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock'];
  const found = await Promise.all(files.map((f) => fetch(`https://raw.githubusercontent.com/${repo}/HEAD/${f}`, { method: 'HEAD' }).then((r) => r.ok).catch(() => false)));
  const tree = found.some(Boolean)
    ? true
    : await fetch(`https://api.github.com/repos/${repo}`).then((r) => r.ok).catch(() => false);
  if (!tree) return res.status(404).json({ error: 'not a public GitHub repo' });

  const entry: Entry = {
    repo,
    scannedAt: new Date().toISOString(),
    packages: n(b.packages, 100000),
    score: n(b.score, 100),
    danger: n(b.danger, 100000),
    review: n(b.review, 100000),
    people: n(b.people, 100000),
    topPct: n(b.topPct, 100),
    wormPct: n(b.wormPct, 100),
  };
  const key = `${PREFIX}${Date.now().toString(36)}-${repo.replace(/[^A-Za-z0-9_.-]/g, '_')}.json`;
  await put(key, JSON.stringify(entry), { access: 'public', addRandomSuffix: true, contentType: 'application/json' });
  return res.status(200).json({ ok: true });
}
