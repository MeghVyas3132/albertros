import type { Finding } from './types.js';
import type { PkgFile } from './tarball.js';

interface Rule {
  id: string;
  title: string;
  why: string;
  re: RegExp;
  kind: 'strong' | 'secret' | 'net' | 'exec';
}

const PRIVATE_IP = /^(127\.|10\.|0\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|255\.)/;

const RULES: Rule[] = [
  {
    id: 'drop-service',
    title: 'Sends data to a drop service',
    why: 'Code contacts a service attackers use to collect stolen data (webhooks, paste sites, tunnels).',
    re: /(webhook\.site|discord(?:app)?\.com\/api\/webhooks|api\.telegram\.org\/bot|pastebin\.com\/raw|transfer\.sh|[a-z0-9-]+\.ngrok(?:-free)?\.(?:io|app)|pipedream\.net|requestbin|burpcollaborator\.net|\.oast\.(?:fun|me|pro|live|site|online)|interact\.sh|canarytokens)/i,
    kind: 'strong',
  },
  {
    id: 'pipe-shell',
    title: 'Downloads and runs a script',
    why: 'Fetches a script from the internet and executes it, so what runs can change at any time.',
    re: /(?:curl|wget)\s[^\n|;]{0,200}\|\s*(?:ba|z)?sh\b|powershell[^\n]{0,60}\s-(?:e|enc|encodedcommand)\s|iex\s*\(\s*(?:new-object|iwr|invoke-webrequest)/i,
    kind: 'strong',
  },
  {
    id: 'hidden-eval',
    title: 'Runs hidden code',
    why: 'Decodes a string and executes it. Legit packages almost never need this.',
    re: /\beval\s*\(\s*(?:atob|Buffer\.from|unescape|decodeURIComponent|String\.fromCharCode)\s*\(|new\s+Function\s*\(\s*(?:atob|Buffer\.from)\s*\(|\beval\s*\(\s*['"`]\\x[0-9a-f]{2}/i,
    kind: 'strong',
  },
  {
    id: 'wallet-hook',
    title: 'Hijacks wallet or network calls',
    why: 'Replaces window.ethereum, fetch or XMLHttpRequest, the trick used to swap crypto addresses (chalk/debug attack, Sept 2025).',
    re: /window\.ethereum\s*\.\s*(?:request|send|sendAsync)\s*=|XMLHttpRequest\.prototype\.(?:open|send)\s*=|(?:window|globalThis|self)\.fetch\s*=\s*(?:async\s*)?(?:function|\()/,
    kind: 'strong',
  },
  {
    id: 'secrets',
    title: 'Reads tokens or credentials',
    why: 'Touches files or variables that hold secrets: npm/GitHub/cloud tokens, SSH keys, browser or wallet data.',
    re: /(?:['"`\/]\.npmrc\b|\.ssh\/id_(?:rsa|ed25519)|NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|AWS_SECRET_ACCESS_KEY|\.aws\/credentials|trufflehog|\.git-credentials|Login Data|Local Extension Settings|wallet\.dat|\.config\/solana\/id\.json|Exodus\/exodus\.wallet)/,
    kind: 'secret',
  },
  {
    id: 'env-dump',
    title: 'Collects all environment variables',
    why: 'Serialises the whole environment, which usually contains CI tokens and API keys.',
    re: /JSON\.stringify\(\s*process\.env\s*[,)]|Buffer\.from\(\s*JSON\.stringify\(\s*process\.env|(?:body|data|payload)\s*[:=]\s*process\.env\b/,
    kind: 'secret',
  },
  {
    id: 'raw-ip',
    title: 'Contacts a raw IP address',
    why: 'Hard-coded IP endpoints are a common way to hide a command-and-control server.',
    re: /https?:\/\/((?:\d{1,3}\.){3}\d{1,3})(?::\d+)?\//,
    kind: 'net',
  },
];

const NET_RE = /\bhttps?\.(?:request|get)\(|\bfetch\(|require\(['"]axios['"]\)|\bnet\.connect\(|\bdns\.(?:resolve|lookup)|new\s+WebSocket\(|\bXMLHttpRequest\b/;
const EXEC_RE = /require\(\s*['"](?:node:)?child_process['"]\s*\)|from\s+['"](?:node:)?child_process['"]/;

function obfuscationScore(text: string): number {
  const hexNames = (text.match(/_0x[0-9a-f]{4,6}/g) || []).length;
  const hexEsc = (text.match(/\\x[0-9a-f]{2}/gi) || []).length;
  const longB64 = /['"`][A-Za-z0-9+/=]{4000,}['"`]/.test(text) ? 1 : 0;
  return (hexNames >= 40 ? 2 : 0) + (hexEsc >= 400 ? 1 : 0) + longB64;
}

function lineOf(text: string, idx: number): { line: number; snippet: string } {
  const before = text.lastIndexOf('\n', idx) + 1;
  const after = text.indexOf('\n', idx);
  const line = text.slice(0, idx).split('\n').length;
  const raw = text.slice(before, after === -1 ? undefined : after);
  const col = idx - before;
  const start = Math.max(0, col - 50);
  const snippet = (start > 0 ? '…' : '') + raw.slice(start, start + 140).trim() + (raw.length > start + 140 ? '…' : '');
  return { line, snippet };
}

export interface ScanResult {
  findings: Finding[];
  filesScanned: number;
}

/**
 * Look through a package's files for the patterns used by real npm attacks.
 * installFiles are the files run by install scripts: anything found there is worse.
 */
export function scanFiles(files: PkgFile[], installFiles: string[] = []): ScanResult {
  const hits = new Map<string, { rule: Rule; evidence: string[]; inInstall: boolean }>();
  let net = false;
  let netInInstall = false;
  let execInInstall: string | null = null;
  let obf: { path: string; score: number } | null = null;
  let scanned = 0;
  const install = new Set(installFiles.map((f) => f.replace(/^\.\//, '')));

  for (const f of files) {
    if (!f.text) continue;
    if (/\.(d\.ts|map)$/.test(f.path) || /(^|\/)(test|tests|__tests__|docs?|examples?)\//.test(f.path)) continue;
    scanned++;
    const t = f.text;
    const inInstall = install.has(f.path);
    if (NET_RE.test(t)) {
      net = true;
      if (inInstall) netInInstall = true;
    }
    if (inInstall && EXEC_RE.test(t)) execInInstall = f.path;
    if (/\.(c?js|mjs)$/.test(f.path)) {
      const s = obfuscationScore(t);
      if (s >= 2 && (!obf || s > obf.score)) obf = { path: f.path, score: s };
    }
    for (const rule of RULES) {
      const g = new RegExp(rule.re.source, rule.re.flags.includes('g') ? rule.re.flags : rule.re.flags + 'g');
      let m: RegExpExecArray | null;
      let n = 0;
      while ((m = g.exec(t)) && n < 3) {
        if (rule.id === 'raw-ip' && PRIVATE_IP.test(m[1])) continue;
        n++;
        const { line, snippet } = lineOf(t, m.index);
        const h = hits.get(rule.id) || { rule, evidence: [], inInstall: false };
        if (h.evidence.length < 4) h.evidence.push(`${f.path}:${line}  ${snippet}`);
        h.inInstall ||= inInstall;
        hits.set(rule.id, h);
        if (m.index === g.lastIndex) g.lastIndex++;
      }
    }
  }

  const findings: Finding[] = [];
  const has = (id: string) => hits.has(id);
  const secretish = has('secrets') || has('env-dump');
  const netish = net || has('raw-ip') || has('drop-service');

  for (const { rule, evidence, inInstall } of hits.values()) {
    let severity: Finding['severity'] = 'review';
    if (rule.kind === 'strong') severity = 'danger';
    if (rule.kind === 'secret' && (netish || inInstall)) severity = 'danger';
    if (rule.kind === 'net' && (secretish || inInstall)) severity = 'danger';
    findings.push({
      code: `code-${rule.id}`,
      severity,
      title: rule.title + (inInstall ? ' (during install)' : ''),
      detail: rule.why,
      evidence,
    });
  }
  if (obf) {
    findings.push({
      code: 'code-obfuscated',
      severity: netish || secretish || install.has(obf.path) ? 'danger' : 'review',
      title: 'Obfuscated code',
      detail: `${obf.path} is deliberately scrambled (hex-named variables, encoded strings). Real attacks hide payloads this way.`,
      evidence: [obf.path],
    });
  }
  if (execInInstall && netInInstall) {
    findings.push({
      code: 'code-install-exec-net',
      severity: secretish ? 'danger' : 'review',
      title: 'Install script runs commands and uses the network',
      detail: `${execInInstall} runs system commands and makes network calls while npm installs the package.`,
      evidence: [execInInstall],
    });
  }
  return { findings, filesScanned: scanned };
}

/** Files an install script runs, e.g. "node scripts/postinstall.js" -> scripts/postinstall.js */
export function installEntryFiles(scripts: Record<string, string> = {}): string[] {
  const out: string[] = [];
  for (const k of ['preinstall', 'install', 'postinstall']) {
    const s = scripts[k];
    if (!s) continue;
    for (const m of s.matchAll(/(?:node|bun|sh|bash)\s+(?:-[a-z-]+\s+)*([\w./-]+\.(?:c?js|mjs|sh))/g)) out.push(m[1].replace(/^\.\//, ''));
  }
  return out;
}

export function scanInstallScript(scripts: Record<string, string> = {}): Finding[] {
  const findings: Finding[] = [];
  const entries = ['preinstall', 'install', 'postinstall'].filter((k) => scripts[k]);
  if (!entries.length) return findings;
  const cmds = entries.map((k) => `${k}: ${scripts[k]}`);
  const joined = entries.map((k) => scripts[k]).join(' && ');
  const native = /^(node-gyp(-build)? rebuild|node-gyp-build|prebuild-install( \|\| node-gyp rebuild)?.*|node install\.js|node-pre-gyp install.*)$/;
  if (/(curl|wget)\s|https?:\/\/|powershell|\beval\b|base64\s+(-d|--decode)|node\s+-e\s/.test(joined)) {
    findings.push({
      code: 'install-script-network',
      severity: 'danger',
      title: 'Install script reaches the internet or runs inline code',
      detail: 'This command runs automatically on `npm install`, before you ever import the package.',
      evidence: cmds,
    });
  } else if (entries.every((k) => native.test(scripts[k].trim()))) {
    findings.push({
      code: 'install-script-native',
      severity: 'info',
      title: 'Builds or downloads a native binary on install',
      detail: 'Common for packages with native code. It still runs code on your machine during install.',
      evidence: cmds,
    });
  } else {
    findings.push({
      code: 'install-script',
      severity: 'review',
      title: 'Runs a script on install',
      detail: 'Code runs automatically on `npm install`. This is how most npm attacks start (e.g. the Shai-Hulud worm).',
      evidence: cmds,
    });
  }
  return findings;
}
