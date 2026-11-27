export const REGISTRY = 'https://registry.npmjs.org';
export const DOWNLOADS = 'https://api.npmjs.org/downloads/point/last-week';
export const OSV = 'https://api.osv.dev/v1';

export function encName(name: string): string {
  return name.startsWith('@') ? '@' + encodeURIComponent(name.slice(1)) : encodeURIComponent(name);
}

export async function getJson<T = any>(url: string, init?: RequestInit, retries = 2): Promise<T | null> {
  for (let attempt = 0; ; attempt++) {
    try {
      const res = await fetch(url, init);
      if (res.status === 404) return null;
      if (res.status === 429 || res.status >= 500) throw new Error(`HTTP ${res.status}`);
      if (!res.ok) return null;
      return (await res.json()) as T;
    } catch (e) {
      if (attempt >= retries) throw e;
      await new Promise((r) => setTimeout(r, 400 * (attempt + 1)));
    }
  }
}

export async function pool<T, R>(items: T[], limit: number, fn: (item: T, i: number) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i], i);
    }
  });
  await Promise.all(workers);
  return out;
}

const packuments = new Map<string, Promise<any | null>>();
export function getPackument(name: string): Promise<any | null> {
  let p = packuments.get(name);
  if (!p) {
    p = getJson(`${REGISTRY}/${encName(name)}`);
    packuments.set(name, p);
  }
  return p;
}

const manifests = new Map<string, Promise<any | null>>();
export function getManifest(name: string, version: string): Promise<any | null> {
  const key = `${name}@${version}`;
  let p = manifests.get(key);
  if (!p) {
    p = getJson(`${REGISTRY}/${encName(name)}/${encodeURIComponent(version)}`).then((j) =>
      j && typeof j === 'object' && j.version ? j : null,
    );
    manifests.set(key, p);
  }
  return p;
}

let downloadsProxy: string | null = null;
/** Route download counts through a cached proxy (the web app uses its own /api/downloads). */
export function setDownloadsProxy(url: string | null) {
  downloadsProxy = url;
}

/** Weekly downloads. Bulk endpoint for unscoped names (128 per call), one call each for scoped. */
export async function getDownloads(names: string[]): Promise<Map<string, number | null>> {
  if (downloadsProxy) {
    const out = new Map<string, number | null>();
    const uniq = [...new Set(names)];
    const chunks: string[][] = [];
    for (let i = 0; i < uniq.length; i += 100) chunks.push(uniq.slice(i, i + 100));
    await pool(chunks, 4, async (chunk) => {
      const j = await getJson<Record<string, number | null>>(`${downloadsProxy}?names=${chunk.map(encodeURIComponent).join(',')}`).catch(() => null);
      for (const n of chunk) out.set(n, j?.[n] ?? null);
    });
    return out;
  }
  const out = new Map<string, number | null>();
  const unscoped = [...new Set(names.filter((n) => !n.startsWith('@')))];
  const scoped = [...new Set(names.filter((n) => n.startsWith('@')))];
  const chunks: string[][] = [];
  for (let i = 0; i < unscoped.length; i += 128) chunks.push(unscoped.slice(i, i + 128));
  await pool(chunks, 3, async (chunk) => {
    try {
      const j = await getJson<any>(`${DOWNLOADS}/${chunk.map(encodeURIComponent).join(',')}`);
      if (!j) return chunk.forEach((n) => out.set(n, null));
      if (chunk.length === 1) out.set(chunk[0], typeof j.downloads === 'number' ? j.downloads : null);
      else for (const n of chunk) out.set(n, j[n] && typeof j[n].downloads === 'number' ? j[n].downloads : null);
    } catch {
      chunk.forEach((n) => out.set(n, null));
    }
  });
  await pool(scoped, 6, async (n) => {
    try {
      const j = await getJson<any>(`${DOWNLOADS}/${encName(n)}`);
      out.set(n, j && typeof j.downloads === 'number' ? j.downloads : null);
    } catch {
      out.set(n, null);
    }
  });
  return out;
}

const abbrevs = new Map<string, Promise<any | null>>();
/** Abbreviated packument (versions + dependencies only): much smaller, used to resolve ranges. */
export function getAbbrev(name: string): Promise<any | null> {
  let p = abbrevs.get(name);
  if (!p) {
    p = getJson(`${REGISTRY}/${encName(name)}`, { headers: { accept: 'application/vnd.npm.install-v1+json' } });
    abbrevs.set(name, p);
  }
  return p;
}
