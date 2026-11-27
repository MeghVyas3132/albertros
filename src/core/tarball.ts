export interface PkgFile {
  path: string;
  size: number;
  text?: string;
}

const TEXT_EXT = /\.(c?js|mjs|ts|cts|mts|json|sh|bash|ps1|py|bat|cmd|node-gyp|gyp)$|(^|\/)[^.\/]+$/i;
const MAX_TGZ = 12 * 1024 * 1024;
const MAX_TEXT_FILE = 2 * 1024 * 1024;

function cstr(b: Uint8Array, start: number, len: number): string {
  let end = start;
  while (end < start + len && b[end] !== 0) end++;
  return new TextDecoder().decode(b.subarray(start, end));
}

async function gunzip(data: ArrayBuffer): Promise<Uint8Array> {
  const stream = new Blob([data]).stream().pipeThrough(new DecompressionStream('gzip'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/** Download an npm tarball and return its files (text for code files). Runs in browsers and Node 18+. */
export async function readTarball(url: string): Promise<PkgFile[]> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`tarball HTTP ${res.status}`);
  const buf = await res.arrayBuffer();
  if (buf.byteLength > MAX_TGZ) throw new Error('tarball too large to scan');
  const tar = await gunzip(buf);
  const files: PkgFile[] = [];
  const dec = new TextDecoder('utf-8', { fatal: false });
  let off = 0;
  let longName: string | null = null;
  while (off + 512 <= tar.length) {
    const name = cstr(tar, off, 100);
    if (!name) break;
    const size = parseInt(cstr(tar, off + 124, 12).trim() || '0', 8) || 0;
    const type = String.fromCharCode(tar[off + 156] || 48);
    const prefix = cstr(tar, off + 345, 155);
    const dataStart = off + 512;
    let path = longName ?? (prefix ? `${prefix}/${name}` : name);
    longName = null;
    if (type === 'x' || type === 'L') {
      const body = dec.decode(tar.subarray(dataStart, dataStart + size));
      const m = type === 'L' ? body.replace(/\0+$/, '') : /\d+ path=([^\n]+)\n/.exec(body)?.[1];
      if (m) longName = m;
    } else if (type === '0' || type === '\0') {
      path = path.replace(/^[^/]+\//, '');
      const f: PkgFile = { path, size };
      if (size <= MAX_TEXT_FILE && TEXT_EXT.test(path)) f.text = dec.decode(tar.subarray(dataStart, dataStart + size));
      files.push(f);
    }
    off = dataStart + Math.ceil(size / 512) * 512;
  }
  return files;
}
