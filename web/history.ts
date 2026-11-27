const $ = (s: string) => document.querySelector(s) as HTMLElement;
const esc = (s: unknown) => String(s ?? '').replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

function ago(iso: string) {
  const m = (Date.now() - Date.parse(iso)) / 60000;
  if (m < 1) return 'just now';
  if (m < 60) return `${Math.round(m)} min ago`;
  if (m < 1440) return `${Math.round(m / 60)} h ago`;
  return `${Math.round(m / 1440)} d ago`;
}

async function cft() {
  const r = await fetch('./codefestthon.json').then((x) => (x.ok ? x.json() : null)).catch(() => null);
  if (!r) return;
  $('#cft').hidden = false;
  $('#cft-title').innerHTML = `We checked every CODEFESTTHON project with a public repo. The median one trusts <b>${r.strangersMedian}</b> strangers.`;
  $('#cft-sub').textContent = `${r.submissions} submissions, ${r.withRepo} with a public GitHub repo, ${r.javascript} of them JavaScript. ${r.packages.toLocaleString('en-US')} npm packages in total. No project is named here.`;
  const stats: [string, string][] = [
    [`${r.strangersTotal.toLocaleString('en-US')}`, 'npm accounts, summed across projects, that can push code into them'],
    [`${r.topReachMedian}%`, 'of a typical project’s direct dependencies reached by one phished account'],
    [`${r.wormMedian}%`, 'of a typical project poisoned by one Shai-Hulud style worm, worst case'],
    [`${r.projectsWithInstallScripts}/${r.javascript}`, 'projects that run strangers’ code the moment you npm install'],
    [`${r.projectsWithKnownVulns}/${r.javascript}`, 'projects shipping a package with a known vulnerability'],
    [`${r.projectsWithDanger}`, 'projects with a known-malicious or hijacked dependency'],
  ];
  $('#cft-stats').innerHTML = stats.map(([n, l]) => `<div><b>${esc(n)}</b><span>${esc(l)}</span></div>`).join('');
  const max = Math.max(...r.distribution.map((d: any) => d.people));
  $('#cft-bars').innerHTML = r.distribution
    .map((d: any) => `<div class="b" title="${d.people} accounts · ${d.packages} packages · one account reaches ${d.topPct}% · worm ${d.worm}%"><i style="height:${Math.max(3, (100 * d.people) / max)}%"></i><span>${d.people}</span></div>`)
    .join('');
}

async function loadHistory() {
  const r = await fetch('./api/scans').then((x) => x.json()).catch(() => null);
  const rows = $('#rows');
  if (!r || !r.entries) {
    rows.innerHTML = `<tr><td colspan="7" class="empty">History is not available right now.</td></tr>`;
    return;
  }
  const t = r.totals || { scans: 0, packages: 0, dangers: 0 };
  $('#totals').innerHTML = [
    [t.scans, 'repo checks'],
    [t.packages, 'packages checked'],
    [t.dangers, 'dangerous dependencies found'],
  ]
    .map(([n, l]) => `<div><b>${Number(n).toLocaleString('en-US')}</b><span>${l}</span></div>`)
    .join('');
  if (!r.entries.length) {
    rows.innerHTML = `<tr><td colspan="7" class="empty">${r.error ? 'History storage is being set up.' : 'No public repos checked yet.'} <a href="./">Check one</a>.</td></tr>`;
    return;
  }
  rows.innerHTML = r.entries
    .map((e: any) => {
      const tone = e.danger ? 'danger' : e.review ? 'review' : 'safe';
      return `<tr>
        <td><a class="repo" href="./#repo=${encodeURIComponent(e.repo)}">${esc(e.repo)}</a> <a class="gh" href="https://github.com/${esc(e.repo)}" target="_blank" rel="noopener" aria-label="Open on GitHub">↗</a></td>
        <td><span class="pill p-${tone}">${e.score}</span></td>
        <td class="num">${e.people}</td>
        <td class="num">${e.topPct}%</td>
        <td class="num">${e.wormPct}%</td>
        <td>${e.danger ? `<span class="t-danger">${e.danger} danger</span>` : ''}${e.danger && e.review ? ' · ' : ''}${e.review ? `<span class="t-review">${e.review} review</span>` : ''}${!e.danger && !e.review ? '<span class="t-safe">clean</span>' : ''}</td>
        <td class="when">${ago(e.scannedAt)}</td>
      </tr>`;
    })
    .join('');
}

cft();
loadHistory();
export {};
