import { OSV, getJson, pool } from './net.js';

export interface Advisory {
  id: string;
  summary: string;
  malicious: boolean;
  severity?: string;
  url: string;
}

const MALICIOUS_RE = /malicious|malware|embedded (malicious )?code|compromised|protestware|backdoor|hijack|wipe|sabotage|infinite loop.*(colors|faker)/i;

const details = new Map<string, Promise<Advisory>>();
function getAdvisory(id: string): Promise<Advisory> {
  let p = details.get(id);
  if (!p) {
    p = getJson<any>(`${OSV}/vulns/${encodeURIComponent(id)}`)
      .catch(() => null)
      .then((v) => {
        const summary: string = (v?.summary || v?.details || id).toString().split('\n')[0].slice(0, 200);
        const text = `${v?.summary || ''} ${String(v?.details || '').slice(0, 600)}`;
        const malicious = id.startsWith('MAL-') || MALICIOUS_RE.test(text) || (v?.aliases || []).some((a: string) => a.startsWith('MAL-'));
        const severity: string | undefined = v?.database_specific?.severity;
        return {
          id,
          summary,
          malicious,
          severity: severity ? String(severity).toLowerCase() : undefined,
          url: `https://osv.dev/vulnerability/${id}`,
        };
      });
    details.set(id, p);
  }
  return p;
}

/** Query OSV for every name@version. Returns advisories per key "name@version". */
export async function queryOsv(items: { name: string; version: string }[]): Promise<Map<string, Advisory[]>> {
  const out = new Map<string, Advisory[]>();
  if (!items.length) return out;
  const ids = new Map<string, string[]>();
  for (let i = 0; i < items.length; i += 500) {
    const batch = items.slice(i, i + 500);
    const res = await getJson<any>(`${OSV}/querybatch`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ queries: batch.map((x) => ({ package: { name: x.name, ecosystem: 'npm' }, version: x.version })) }),
    }).catch(() => null);
    if (!res?.results) continue;
    res.results.forEach((r: any, j: number) => {
      const key = `${batch[j].name}@${batch[j].version}`;
      ids.set(key, (r?.vulns || []).map((v: any) => v.id));
    });
  }
  const unique = [...new Set([...ids.values()].flat())].slice(0, 400);
  await pool(unique, 8, (id) => getAdvisory(id));
  for (const [key, list] of ids) {
    out.set(key, await Promise.all(list.filter((id) => details.has(id)).map((id) => details.get(id)!)));
  }
  return out;
}
