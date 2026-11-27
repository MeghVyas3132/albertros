import type { VercelRequest, VercelResponse } from '@vercel/node';

/**
 * Cached proxy for npm weekly download counts. Browsers hit api.npmjs.org's rate limit quickly, and its
 * 429 responses carry no CORS header, which the browser reports as a CORS error.
 * GET /api/downloads?names=a,b,@scope/c  ->  { "a": 123, "b": null, ... }
 */
const NAME = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/i;

async function getJson(url: string): Promise<any> {
  for (let i = 0; i < 3; i++) {
    const r = await fetch(url);
    if (r.ok) return r.json();
    if (r.status === 404) return null;
    await new Promise((s) => setTimeout(s, 400 * (i + 1)));
  }
  return null;
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  const names = String(req.query.names || '')
    .split(',')
    .map((s) => s.trim())
    .filter((s) => NAME.test(s))
    .slice(0, 128);
  const out: Record<string, number | null> = {};
  const unscoped = names.filter((n) => !n.startsWith('@'));
  const scoped = names.filter((n) => n.startsWith('@'));
  if (unscoped.length) {
    const j = await getJson(`https://api.npmjs.org/downloads/point/last-week/${unscoped.map(encodeURIComponent).join(',')}`).catch(() => null);
    for (const n of unscoped) out[n] = unscoped.length === 1 ? (j?.downloads ?? null) : (j?.[n]?.downloads ?? null);
  }
  await Promise.all(
    scoped.map(async (n) => {
      const j = await getJson(`https://api.npmjs.org/downloads/point/last-week/@${encodeURIComponent(n.slice(1))}`).catch(() => null);
      out[n] = j?.downloads ?? null;
    }),
  );
  res.setHeader('cache-control', 'public, s-maxage=86400, stale-while-revalidate=604800');
  res.setHeader('access-control-allow-origin', '*');
  return res.status(200).json(out);
}
