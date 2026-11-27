import { analyzeProject, computeTrust, fetchGithub, parseInput, parseList, replayAttack, scanPackageCode, scoreOf, sortReports } from '../src/core/index.js';
import type { Finding, PackageReport, ProjectReport, ReplayResult, TrustReport, Verdict } from '../src/core/index.js';
import { TrustGraph } from './graph.js';

const $ = <T extends HTMLElement = HTMLElement>(s: string) => document.querySelector(s) as T;
const esc = (s: unknown) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

const RISKY = JSON.stringify(
  {
    name: 'checkout-service',
    version: '1.0.0',
    dependencies: {
      express: '^4.21.2',
      lodahs: '*',
      crossenv: '^6.1.1',
      'event-stream': '3.3.6',
      'acme-internal-auth': '^1.2.0',
      'node-ipc': '10.1.1',
      jsonwebtoken: '8.5.1',
      zod: '^3.23.8',
    },
    devDependencies: { esbuild: '^0.25.0', electorn: '*' },
  },
  null,
  2,
);

let tab: 'repo' | 'paste' | 'list' = 'repo';
let report: ProjectReport | null = null;
let filter: 'all' | Verdict = 'all';
let shareQuery = '';
let replay: ReplayResult | null = null;
let trust: TrustReport | null = null;
let graph: TrustGraph | null = null;
const LABEL: Record<Verdict, string> = { danger: 'Danger', review: 'Review', safe: 'Safe', unknown: 'Error' };
const SEV_ICON: Record<Finding['severity'], string> = { danger: '!', review: '?', info: 'i', good: '✓' };

function setTab(t: typeof tab) {
  tab = t;
  document.querySelectorAll<HTMLButtonElement>('.tabs button').forEach((b) => b.setAttribute('aria-selected', String(b.dataset.tab === t)));
  document.querySelectorAll<HTMLElement>('.pane').forEach((p) => (p.hidden = p.dataset.pane !== t));
}

function toast(msg: string) {
  const el = document.createElement('div');
  el.className = 'toast';
  el.textContent = msg;
  document.body.append(el);
  setTimeout(() => el.remove(), 1800);
}

function fmtNum(n: number | null | undefined) {
  if (n == null) return '–';
  if (n >= 1e6) return (n / 1e6).toFixed(n >= 1e7 ? 0 : 1) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(n >= 1e4 ? 0 : 1) + 'k';
  return String(n);
}

function fmtAge(iso?: string) {
  if (!iso) return '';
  const d = (Date.now() - Date.parse(iso)) / 864e5;
  if (d < 1 / 24) return `${Math.max(1, Math.round(d * 1440))} min ago`;
  if (d < 1) return `${Math.max(1, Math.round(d * 24))}h ago`;
  if (d < 60) return `${Math.round(d)}d ago`;
  if (d < 730) return `${Math.round(d / 30)}mo ago`;
  return `${Math.round(d / 365)}y ago`;
}

function progress(stage: string, done: number, total: number, weight: [number, number]) {
  $('#progress').hidden = false;
  $('#stage').textContent = total > 1 ? `${stage} · ${done}/${total}` : stage;
  const frac = total ? done / total : 0;
  ($('#progress .bar i') as HTMLElement).style.width = `${Math.round((weight[0] + frac * (weight[1] - weight[0])) * 100)}%`;
}

const STAGE_WEIGHT: Record<string, [number, number]> = {
  'Reading the npm registry': [0.04, 0.55],
  'Checking download counts and look-alike names': [0.55, 0.6],
  'Checking OSV for known malware and vulnerabilities': [0.6, 0.72],
  'Scanning package code': [0.72, 0.98],
};

async function runReplay(id: string) {
  $('#error').hidden = true;
  $('#results').hidden = true;
  const btns = document.querySelectorAll<HTMLButtonElement>('[data-replay]');
  btns.forEach((b) => (b.disabled = true));
  let step = 0;
  try {
    replay = await replayAttack(id, (stage) => progress(stage, 0, 1, [step * 0.33, ++step * 0.33]));
    report = {
      source: `Attack replay · ${replay.scenario.title}`,
      packages: [replay.hijacked, replay.genuine],
      score: 0,
      counts: { danger: 0, review: 0, safe: 0, unknown: 0 },
      startedAt: new Date().toISOString(),
      finishedAt: new Date().toISOString(),
      skipped: 0,
    };
    shareQuery = `replay=${id}`;
    history.replaceState(null, '', `#${shareQuery}`);
    filter = 'all';
    render();
    document.querySelectorAll('#list-out .item').forEach((li) => li.classList.add('open'));
  } catch (e) {
    $('#error').textContent = (e as Error).message || String(e);
    $('#error').hidden = false;
  } finally {
    $('#progress').hidden = true;
    btns.forEach((b) => (b.disabled = false));
  }
}

function renderReplay() {
  const el = $('#replay');
  if (!replay) {
    el.hidden = true;
    return;
  }
  const { scenario: sc, genuine, hijacked } = replay;
  const src = genuine.meta.source;
  el.hidden = false;
  el.innerHTML = `
    <div class="replay-story">
      <time>${esc(sc.when)}</time>
      <h3>The ${esc(sc.title)}, replayed</h3>
      <p>${esc(sc.story)}</p>
      <p class="fine">We took the real <b>${esc(sc.name)}@${esc(sc.genuine)}</b> tarball from npm, made the same kind of change the attackers made (an inert stand-in, never executed), and ran the normal checks. No malware database was used: OSV only listed the real attack after it was reported.</p>
    </div>
    <div class="versus">
      <div class="vs vs-${hijacked.verdict}"><span class="pill p-${hijacked.verdict}">${LABEL[hijacked.verdict]}</span><b>${esc(sc.name)}@${esc(hijacked.version)}</b><small>hijacked release, ${hijacked.findings.filter((f) => f.severity === 'danger').length} danger signals</small></div>
      <div class="vs vs-${genuine.verdict}"><span class="pill p-${genuine.verdict}">${LABEL[genuine.verdict]}</span><b>${esc(sc.name)}@${esc(genuine.version)}</b><small>${src?.status === 'verified' ? `matches git commit ${esc((src.commit || '').slice(0, 7))}` : 'genuine release'}</small></div>
    </div>`;
}

function renderTrust() {
  const el = $('#trust');
  if (!report || replay || report.packages.length < 3) {
    el.hidden = true;
    return;
  }
  trust = computeTrust(report.packages);
  const t = trust;
  el.hidden = false;
  $('#trust-title').innerHTML = `<b>${t.people}</b> strangers can push code into this app`;
  $('#trust-sub').textContent = `That's how many npm accounts can publish one of its ${t.packages} packages${report.expanded ? ' (full tree resolved from package.json)' : ''}. Any one of them, phished, ships code straight to your machine and your users.`;
  $('#trust-stats').innerHTML = [
    [t.runOnInstall.length, 'run code the moment you install'],
    [t.solo, 'have a single maintainer'],
    [t.packages, 'packages in the tree'],
  ]
    .map(([n, l]) => `<div><b>${n}</b><span>${l}</span></div>`)
    .join('');
  const top = t.accounts.slice(0, 7);
  $('#accounts').innerHTML = top
    .map((a, i) => {
      const pct = Math.round((100 * a.directReach.length) / Math.max(1, t.direct));
      return `<li><button data-acct="${i}"><span class="who">${esc(a.name)}</span><span class="bar"><i style="width:${pct}%"></i></span><span class="pct">${pct}%</span><small>${a.packages.length} package${a.packages.length > 1 ? 's' : ''} · reaches ${a.directReach.length}/${t.direct} direct deps</small></button></li>`;
    })
    .join('');
  $('#phish-msg').textContent = '';
  if (!graph) {
    graph = new TrustGraph($<HTMLCanvasElement>('#graph'), $('#tip'));
    graph.onPick = (name) => {
      const i = visible.findIndex((p) => p.name === name);
      const li = document.querySelector<HTMLElement>(`#list-out li[data-i="${i}"]`);
      if (li) {
        li.classList.add('open');
        li.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    };
  }
  graph.load(report.packages, t);
}

function phish(i: number) {
  if (!trust || !graph) return;
  const a = trust.accounts[i];
  document.querySelectorAll('#accounts button').forEach((b, j) => b.classList.toggle('active', j === i));
  graph.phish(a.packages);
  const pct = Math.round((100 * a.directReach.length) / Math.max(1, trust.direct));
  graph.onTick = (n) => {
    $('#phish-msg').innerHTML = `If <b>${esc(a.name)}</b> is phished, <b class="t-danger">${n} of ${trust!.direct}</b> direct dependencies ship the attacker's code${n >= a.directReach.length ? ` (${pct}%)` : '…'}<br><span>Through: ${esc(a.packages.slice(0, 8).join(', '))}${a.packages.length > 8 ? '…' : ''}</span>`;
  };
}

async function run() {
  const go = $<HTMLButtonElement>('#go');
  const includeDev = $<HTMLInputElement>('#dev').checked;
  const deep = $<HTMLInputElement>('#deep').checked;
  $('#error').hidden = true;
  $('#results').hidden = true;
  replay = null;
  go.disabled = true;
  go.textContent = 'Checking…';
  try {
    let source = '';
    let deps;
    if (tab === 'repo') {
      const v = $<HTMLInputElement>('#repo').value.trim();
      if (!v) throw new Error('Enter a GitHub repo, like expressjs/express.');
      progress('Fetching package files from GitHub', 0, 1, [0, 0.04]);
      const g = await fetchGithub(v, { includeDev });
      source = g.source;
      deps = g.deps;
      shareQuery = `repo=${encodeURIComponent(v)}`;
    } else if (tab === 'paste') {
      const p = parseInput($<HTMLTextAreaElement>('#paste').value, { includeDev });
      source = p.name ? `${p.name} (${p.kind})` : p.kind;
      deps = p.deps;
      const direct = deps.filter((d) => d.direct);
      shareQuery = direct.length <= 60 ? `pkgs=${encodeURIComponent(direct.map((d) => `${d.name}@${d.spec}`).join(' '))}` : '';
    } else {
      const v = $<HTMLInputElement>('#list').value.trim();
      if (!v) throw new Error('Enter one or more packages, like chalk@5.6.1 lodash.');
      deps = parseList(v);
      source = v;
      shareQuery = `pkgs=${encodeURIComponent(v)}`;
    }
    report = await analyzeProject(source, deps, {
      deep,
      maxPackages: 300,
      onProgress: (p) => progress(p.stage, p.done, p.total, STAGE_WEIGHT[p.stage] || [0, 1]),
    });
    if (shareQuery) history.replaceState(null, '', `#${shareQuery}`);
    filter = 'all';
    render();
  } catch (e) {
    $('#error').textContent = (e as Error).message || String(e);
    $('#error').hidden = false;
  } finally {
    $('#progress').hidden = true;
    go.disabled = false;
    go.textContent = 'Check';
  }
}

function headline(r: ProjectReport) {
  const { danger, review } = r.counts;
  if (replay) return replay.hijacked.verdict === 'danger' ? 'Caught. The hijacked release is flagged from its code alone, minutes after publish.' : 'Not caught.';
  if (danger) return `${danger} ${danger === 1 ? 'dependency is' : 'dependencies are'} dangerous. Don't install this as is.`;
  if (review) return `No known attacks. ${review} ${review === 1 ? 'package needs' : 'packages need'} a quick look.`;
  return 'Nothing suspicious. Every dependency checks out.';
}

function scoreRing(score: number) {
  const r = 46;
  const c = 2 * Math.PI * r;
  const color = score >= 80 ? 'var(--safe)' : score >= 50 ? 'var(--review)' : 'var(--danger)';
  return `<svg viewBox="0 0 104 104" aria-hidden="true"><circle class="track" cx="52" cy="52" r="${r}"/><circle class="val" cx="52" cy="52" r="${r}" stroke="${color}" stroke-dasharray="${c}" stroke-dashoffset="${c}" data-target="${c * (1 - score / 100)}"/></svg><b style="color:${color}">${score}</b>`;
}

function render() {
  if (!report) return;
  const r = report;
  const { score, counts } = scoreOf(r.packages);
  r.score = score;
  r.counts = counts;
  $('#results').hidden = false;
  $('#score').innerHTML = scoreRing(score);
  $('#score').hidden = !!replay;
  $('#score').setAttribute('aria-label', `Score ${score} out of 100`);
  requestAnimationFrame(() =>
    requestAnimationFrame(() => {
      const v = document.querySelector<SVGCircleElement>('#score .val');
      if (v) v.style.strokeDashoffset = v.dataset.target!;
    }),
  );
  $('#source').textContent = `${r.source} · ${r.packages.length} packages · ${((Date.parse(r.finishedAt) - Date.parse(r.startedAt)) / 1000).toFixed(1)}s`;
  $('#headline').textContent = headline(r);
  $('#counts').innerHTML = (['danger', 'review', 'safe', 'unknown'] as Verdict[])
    .filter((v) => v !== 'unknown' || counts.unknown)
    .map((v) => `<span class="pill p-${v}">${counts[v]} ${LABEL[v]}</span>`)
    .join('');
  $('#share').hidden = !shareQuery;
  renderReplay();
  renderTrust();
  $('#filters').innerHTML = (['all', 'danger', 'review', 'safe'] as const)
    .map((f) => `<button data-filter="${f}" aria-pressed="${filter === f}">${f === 'all' ? `All ${r.packages.length}` : `${LABEL[f]} ${counts[f]}`}</button>`)
    .join('');
  renderList();
  $('#results').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function topReason(p: PackageReport) {
  const f = p.findings.find((x) => x.severity === 'danger') || p.findings.find((x) => x.severity === 'review');
  if (f) return f.title;
  if (p.error) return p.error;
  const good = p.findings.find((x) => x.severity === 'good');
  return good ? good.title : p.meta.description || 'No issues found';
}

function renderFinding(f: Finding) {
  return `<div class="finding"><span class="dot s-${f.severity}">${SEV_ICON[f.severity]}</span><div>
    <h4>${esc(f.title)}</h4><p>${esc(f.detail)}</p>
    ${f.evidence?.length ? `<pre>${f.evidence.map((l) => (l.startsWith('  + ') ? `<span class="add">${esc(l)}</span>` : esc(l))).join('\n')}</pre>` : ''}
    ${f.link ? `<a href="${esc(f.link)}" target="_blank" rel="noopener">Source ↗</a>` : ''}
  </div></div>`;
}

function renderItem(p: PackageReport, i: number) {
  const tags = [p.direct ? '' : 'transitive', p.dev ? 'dev' : ''].filter(Boolean).map((t) => `<span class="tag">${t}</span>`).join('');
  const meta = [
    p.meta.weeklyDownloads != null ? `${fmtNum(p.meta.weeklyDownloads)} downloads/week` : '',
    p.meta.publishedAt ? `published ${fmtAge(p.meta.publishedAt)}` : '',
    p.meta.publisher ? `by ${p.meta.publisher}` : '',
    p.meta.unpackedSize ? `${Math.round(p.meta.unpackedSize / 1024)} kB` : '',
    p.meta.license || '',
  ].filter(Boolean);
  const badges = [
    p.meta.signature === 'valid' ? 'Signed by npm' : '',
    p.meta.integrity === 'verified' ? 'Tarball hash verified' : '',
    p.meta.source?.status === 'verified' ? `Matches git ${String(p.meta.source.commit || '').slice(0, 7)}` : '',
    p.meta.provenance ? 'Built by CI' : '',
  ].filter(Boolean);
  const npm = `https://www.npmjs.com/package/${p.name}${p.version ? `/v/${p.version}` : ''}`;
  const canScan = !p.scanned && !!(p as any).manifest?.dist?.tarball;
  return `<li class="item" data-i="${i}">
    <button aria-expanded="false">
      <span class="pill p-${p.verdict}">${LABEL[p.verdict]}</span>
      <span class="pkg"><b>${esc(p.name)}</b> <span class="ver">${esc(p.version ? '@' + p.version : p.spec)}</span>${tags ? `<span class="tags">${tags}</span>` : ''}</span>
      <span class="reason">${esc(topReason(p))}</span>
      <span class="dl">${p.meta.weeklyDownloads != null ? fmtNum(p.meta.weeklyDownloads) + '/wk' : ''}</span>
      <svg class="chev" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 3l5 5-5 5"/></svg>
    </button>
    <div class="detail">
      ${meta.length ? `<div class="meta">${meta.map((m) => `<span>${esc(m)}</span>`).join('')}</div>` : ''}
      ${badges.length ? `<div class="badges">${badges.map((b) => `<span>✓ ${esc(b)}</span>`).join('')}</div>` : ''}
      ${p.meta.description ? `<p class="desc">${esc(p.meta.description)}</p>` : ''}
      ${p.findings.map(renderFinding).join('') || '<p class="desc">No findings.</p>'}
      <div class="links">
        <a href="${esc(npm)}" target="_blank" rel="noopener">npm ↗</a>
        ${p.meta.repository && /^https:\/\//.test(p.meta.repository) ? `<a href="${esc(p.meta.repository)}" target="_blank" rel="noopener">Source repo ↗</a>` : ''}
        ${p.version ? `<a href="https://osv.dev/list?ecosystem=npm&q=${encodeURIComponent(p.name)}" target="_blank" rel="noopener">OSV ↗</a>` : ''}
        ${canScan ? `<button data-scan="${i}">Scan this package's code</button>` : ''}
      </div>
    </div>
  </li>`;
}

let visible: PackageReport[] = [];
function renderList() {
  if (!report) return;
  const q = $<HTMLInputElement>('#search').value.trim().toLowerCase();
  visible = report.packages.filter((p) => (filter === 'all' || p.verdict === filter) && (!q || p.name.toLowerCase().includes(q)));
  const shown = visible.slice(0, 200);
  $('#list-out').innerHTML = shown.length
    ? shown.map(renderItem).join('') + (visible.length > shown.length ? `<li class="more">${visible.length - shown.length} more. Narrow the filter to see them.</li>` : '')
    : `<li class="empty">No packages match.</li>`;
  if (report.skipped) $('#list-out').insertAdjacentHTML('beforeend', `<li class="more">${report.skipped} more packages were not checked. Use the CLI with --max for very large lockfiles.</li>`);
}

document.querySelectorAll<HTMLButtonElement>('.tabs button').forEach((b) => b.addEventListener('click', () => setTab(b.dataset.tab as typeof tab)));
$('#form').addEventListener('submit', (e) => {
  e.preventDefault();
  run();
});

document.querySelector('.examples')!.addEventListener('click', (e) => {
  const b = (e.target as HTMLElement).closest<HTMLButtonElement>('button[data-example]');
  if (!b) return;
  const ex = b.dataset.example;
  if (ex === 'risky') {
    setTab('paste');
    $<HTMLTextAreaElement>('#paste').value = RISKY;
  } else if (ex === 'hijack') {
    setTab('list');
    $<HTMLInputElement>('#list').value = 'chalk@5.6.1 debug@4.4.2 ansi-styles@6.2.2 @ctrl/tinycolor@4.1.1 chalk@5.6.2';
  } else {
    setTab('repo');
    $<HTMLInputElement>('#repo').value = 'expressjs/express';
  }
  run();
});

document.querySelectorAll<HTMLButtonElement>('[data-replay]').forEach((b) => b.addEventListener('click', () => runReplay(b.dataset.replay!)));
$('#accounts').addEventListener('click', (e) => {
  const b = (e.target as HTMLElement).closest<HTMLButtonElement>('button[data-acct]');
  if (b) phish(Number(b.dataset.acct));
});

$('#filters').addEventListener('click', (e) => {
  const b = (e.target as HTMLElement).closest<HTMLButtonElement>('button[data-filter]');
  if (!b) return;
  filter = b.dataset.filter as typeof filter;
  document.querySelectorAll('#filters button').forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
  renderList();
});
$('#search').addEventListener('input', renderList);

$('#list-out').addEventListener('click', async (e) => {
  const t = e.target as HTMLElement;
  const scanBtn = t.closest<HTMLButtonElement>('button[data-scan]');
  if (scanBtn) {
    const p = visible[Number(scanBtn.dataset.scan)];
    scanBtn.disabled = true;
    scanBtn.textContent = 'Scanning…';
    await scanPackageCode(p);
    sortReports(report!.packages);
    const li = scanBtn.closest('li')!;
    const idx = Number(li.dataset.i);
    li.outerHTML = renderItem(p, idx);
    const fresh = document.querySelector<HTMLElement>(`#list-out li[data-i="${idx}"]`);
    fresh?.classList.add('open');
    const { score, counts } = scoreOf(report!.packages);
    report!.score = score;
    report!.counts = counts;
    return;
  }
  const head = t.closest<HTMLButtonElement>('.item > button');
  if (head) {
    const li = head.parentElement!;
    li.classList.toggle('open');
    head.setAttribute('aria-expanded', String(li.classList.contains('open')));
  }
});

$('#share').addEventListener('click', async () => {
  await navigator.clipboard.writeText(location.href);
  toast('Link copied');
});
$('#download').addEventListener('click', () => {
  if (!report) return;
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'albertros-report.json';
  a.click();
  URL.revokeObjectURL(a.href);
});
document.querySelectorAll<HTMLButtonElement>('[data-copy]').forEach((b) =>
  b.addEventListener('click', async () => {
    await navigator.clipboard.writeText($(`#${b.dataset.copy}`).textContent || '');
    toast('Copied');
  }),
);

// Shared links: #repo=owner/repo or #pkgs=a@1 b@2
const params = new URLSearchParams(location.hash.slice(1));
if (params.get('replay')) {
  runReplay(params.get('replay')!);
} else if (params.get('repo')) {
  setTab('repo');
  $<HTMLInputElement>('#repo').value = params.get('repo')!;
  run();
} else if (params.get('pkgs')) {
  setTab('list');
  $<HTMLInputElement>('#list').value = params.get('pkgs')!;
  run();
}
