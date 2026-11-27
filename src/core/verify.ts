import { REGISTRY } from './net.js';

/**
 * npm registry signing keys (public), as served by https://registry.npmjs.org/-/npm/v1/keys.
 * Bundled because that endpoint does not allow browser (CORS) requests. Node refreshes them live.
 */
const BUNDLED_KEYS: NpmKey[] = [
  {
    keyid: 'SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA',
    expires: '2025-01-29T00:00:00.000Z',
    key: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1Olb3zMAFFxXKHiIkQO5cJ3Yhl5i6UPp+IhuteBJbuHcA5UogKo0EWtlWwW6KSaKoTNEYL7JlCQiVnkhBktUgg==',
  },
  {
    keyid: 'SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U',
    expires: null,
    key: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEY6Ya7W++7aUPzvMTrezH6Ycx3c+HOKYCcNGybJZSCJq/fd7Qa8uuAKtdIkUQtQiEKERhAmE5lMMJhP8OkDOa2g==',
  },
];

interface NpmKey {
  keyid: string;
  expires: string | null;
  key: string;
}

export type SignatureStatus = 'valid' | 'invalid' | 'missing' | 'unknown-key';

const b64 = (s: string): Uint8Array<ArrayBuffer> => {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};

let keysP: Promise<Map<string, NpmKey>> | null = null;
function getKeys(): Promise<Map<string, NpmKey>> {
  if (!keysP) {
    keysP = (async () => {
      const map = new Map(BUNDLED_KEYS.map((k) => [k.keyid, k]));
      if (typeof window === 'undefined') {
        try {
          const res = await fetch(`${REGISTRY}/-/npm/v1/keys`);
          if (res.ok) for (const k of (await res.json()).keys || []) map.set(k.keyid, k);
        } catch {
          /* offline: bundled keys */
        }
      }
      return map;
    })();
  }
  return keysP;
}

const imported = new Map<string, Promise<CryptoKey>>();
function importKey(k: NpmKey): Promise<CryptoKey> {
  let p = imported.get(k.keyid);
  if (!p) {
    p = crypto.subtle.importKey('spki', b64(k.key), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    imported.set(k.keyid, p);
  }
  return p;
}

/** DER ECDSA signature -> raw r||s (64 bytes) as WebCrypto expects. */
function derToRaw(der: Uint8Array): Uint8Array<ArrayBuffer> {
  let i = 2;
  if (der[1] & 0x80) i = 2 + (der[1] & 0x7f);
  const read = () => {
    if (der[i++] !== 0x02) throw new Error('bad DER');
    const len = der[i++];
    let v = der.subarray(i, i + len);
    i += len;
    while (v.length > 32 && v[0] === 0) v = v.subarray(1);
    const out = new Uint8Array(32);
    out.set(v, 32 - v.length);
    return out;
  };
  const r = read();
  const s = read();
  const raw = new Uint8Array(64);
  raw.set(r, 0);
  raw.set(s, 32);
  return raw;
}

/** Verify the registry's ECDSA signature over "name@version:integrity" (same check as `npm audit signatures`). */
export async function verifyRegistrySignature(name: string, version: string, dist: any): Promise<SignatureStatus> {
  const sigs: { keyid: string; sig: string }[] = dist?.signatures || [];
  if (!sigs.length || !dist?.integrity) return 'missing';
  const keys = await getKeys();
  const msg = new TextEncoder().encode(`${name}@${version}:${dist.integrity}`);
  let sawKnown = false;
  for (const s of sigs) {
    const k = keys.get(s.keyid);
    if (!k) continue;
    sawKnown = true;
    try {
      const key = await importKey(k);
      const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, derToRaw(b64(s.sig)), msg);
      if (ok) return 'valid';
    } catch {
      /* try next signature */
    }
  }
  return sawKnown ? 'invalid' : 'unknown-key';
}

/** Check downloaded tarball bytes against the "sha512-..." integrity npm published. */
export async function checkIntegrity(buf: ArrayBuffer, integrity: string | undefined): Promise<boolean | null> {
  const m = /sha512-([A-Za-z0-9+/=]+)/.exec(integrity || '');
  if (!m) return null;
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-512', buf));
  let bin = '';
  for (const b of digest) bin += String.fromCharCode(b);
  return btoa(bin) === m[1];
}
