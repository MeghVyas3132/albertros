#!/usr/bin/env node
import { appendFileSync, existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { analyzeProject, applyConfig, computeTrust, fetchGithub, parseInput, parseGithub, parseList, toMarkdown, toSarif } from './core/index.js';
import type { AlbertrosConfig, PackageReport, ProjectReport, Verdict } from './core/index.js';

const VERSION = '0.1.0';
const tty = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code: string) => (s: string | number) => (tty ? `\x1b[${code}m${s}\x1b[0m` : String(s));
const red = c('31'), yellow = c('33'), green = c('32'), dim = c('2'), bold = c('1'), cyan = c('36');

const HELP = `
${bold('albertros')} ${dim(VERSION)}: know which npm dependency will hurt you, before npm install does.

${bold('Usage')}
  albertros check [path]              Check package-lock.json or package.json in path (default: .)
  albertros check owner/repo          Check a public GitHub repo
  albertros check lodash@4.17.21 ...  Check specific packages

${bold('Options')}
  --deep           Scan the code of every package, not only suspicious ones
  --prod           Skip devDependencies
  --json           Print the full report as JSON
  --fail-on <lvl>  Exit 1 on "danger" (default), "review", or "never"
  --max <n>        Check at most n packages (default 300)
  --sarif <file>   Also write SARIF for GitHub code scanning
  --markdown <file>  Also write a Markdown summary (use $GITHUB_STEP_SUMMARY in Actions)
  --config <file>  Config file (default: .albertrosrc.json next to package.json)
  --verbose        Show every finding with details
  -h, --help       Show this help

${bold('In CI')}
  npx albertros check --fail-on danger
`;

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i > -1 ? process.argv[i + 1] : undefined;
}

const icon: Record<Verdict, string> = { danger: red('✖ DANGER'), review: yellow('▲ REVIEW'), safe: green('✔ SAFE  '), unknown: dim('? ERROR ') };

function line(p: PackageReport, verbose: boolean) {
  const top = p.findings.filter((f) => f.severity === 'danger' || f.severity === 'review');
  const id = `${p.name}${p.version ? dim('@' + p.version) : dim(' ' + p.spec)}`;
  const tag = p.direct ? '' : dim(' (transitive)');
  console.log(`  ${icon[p.verdict]}  ${id}${tag}`);
  if (p.verdict === 'safe' && !verbose) return;
  for (const f of top.slice(0, verbose ? 99 : 3)) {
    const col = f.severity === 'danger' ? red : yellow;
    console.log(`              ${col('•')} ${f.title}`);
    if (verbose) console.log(`                ${dim(f.detail)}`);
    for (const e of (f.evidence || []).slice(0, 2)) console.log(`                ${dim(e.length > 150 ? e.slice(0, 150) + '…' : e)}`);
  }
  if (p.error) console.log(`              ${dim(p.error)}`);
}

function print(report: ProjectReport) {
  const { counts, score } = report;
  console.log('');
  console.log(`${bold('albertros')} ${dim('·')} ${report.source}`);
  console.log('');
  const shown = report.packages.filter((p) => p.verdict !== 'safe');
  for (const p of shown) line(p, process.argv.includes('--verbose'));
  if (!shown.length) console.log(`  ${green('Nothing suspicious.')}`);
  const scoreCol = score >= 80 ? green : score >= 50 ? yellow : red;
  console.log('');
  console.log(
    `  ${bold('Score')} ${scoreCol(bold(score))}${dim('/100')}   ${red(counts.danger + ' danger')}  ${yellow(counts.review + ' review')}  ${green(counts.safe + ' safe')}${counts.unknown ? dim(`  ${counts.unknown} errors`) : ''}   ${dim(`${report.packages.length} packages`)}`,
  );
  if (report.skipped) console.log(dim(`  ${report.skipped} more packages not checked (raise --max)`));
  const t = computeTrust(report.packages);
  const top = t.accounts[0];
  console.log('');
  console.log(`  ${bold('Who can push code into this install')}`);
  console.log(`  ${bold(t.people)} npm accounts can publish one of your ${t.packages} packages. ${bold(t.runOnInstall.length)} run code the moment you install. ${t.solo} have a single maintainer.`);
  if (top && top.directReach.length) {
    const pct = Math.round((100 * top.directReach.length) / Math.max(1, t.direct));
    console.log(`  ${red('One phished account')} (${bold(top.name)}) reaches ${bold(pct + '%')} of your direct dependencies (${top.directReach.length}/${t.direct}) through ${top.packages.length} package${top.packages.length > 1 ? 's' : ''}: ${dim(top.packages.slice(0, 6).join(', ') + (top.packages.length > 6 ? '…' : ''))}`);
  }
  console.log('');
}

async function main() {
  const argv = process.argv.slice(2);
  if (!argv.length || argv.includes('-h') || argv.includes('--help')) return console.log(HELP);
  if (argv.includes('-v') || argv.includes('--version')) return console.log(VERSION);
  const cmd = argv[0] === 'check' ? argv.slice(1) : argv;
  const flagsWithValue = new Set(['--fail-on', '--max', '--sarif', '--markdown', '--config']);
  const targets: string[] = [];
  for (let i = 0; i < cmd.length; i++) {
    if (flagsWithValue.has(cmd[i])) i++;
    else if (!cmd[i].startsWith('-')) targets.push(cmd[i]);
  }
  const t = targets[0] ?? '.';
  const asPath = resolve(t);
  const local = targets.length <= 1 && existsSync(asPath);
  const baseDir = local ? (statSync(asPath).isDirectory() ? asPath : dirname(asPath)) : process.cwd();
  const cfgPath = arg('--config') ? resolve(arg('--config')!) : join(baseDir, '.albertrosrc.json');
  let cfg: AlbertrosConfig = {};
  if (existsSync(cfgPath)) {
    try {
      cfg = JSON.parse(readFileSync(cfgPath, 'utf8'));
    } catch (e) {
      throw new Error(`Could not read ${cfgPath}: ${(e as Error).message}`);
    }
  }
  const includeDev = argv.includes('--prod') ? false : cfg.includeDev ?? true;
  const json = argv.includes('--json');
  const failOn = (arg('--fail-on') || cfg.failOn || 'danger') as 'danger' | 'review' | 'never';
  const max = Number(arg('--max') || 300);

  let source: string;
  let deps;
  let file: string | undefined;
  let fileText: string | undefined;
  if (local) {
    file = asPath;
    if (statSync(asPath).isDirectory()) {
      const lock = join(asPath, 'package-lock.json');
      file = existsSync(lock) ? lock : join(asPath, 'package.json');
    }
    if (!existsSync(file)) throw new Error(`No package.json or package-lock.json in ${asPath}`);
    fileText = readFileSync(file, 'utf8');
    deps = parseInput(fileText, { includeDev }).deps;
    source = relative(process.cwd(), file) || file;
  } else if (targets.length === 1 && parseGithub(t) && !/^@/.test(t) && t.includes('/')) {
    const g = await fetchGithub(t, { includeDev });
    deps = g.deps;
    source = g.source;
  } else {
    deps = parseList(targets.join(' '));
    source = targets.join(' ');
  }

  let last = '';
  const report = await analyzeProject(source, deps, {
    deep: argv.includes('--deep') || !!cfg.deep,
    maxPackages: max,
    onProgress: (p) => {
      if (json || !process.stderr.isTTY) return;
      const msg = `  ${cyan('›')} ${p.stage}${p.total > 1 ? dim(` ${p.done}/${p.total}`) : ''}`;
      if (msg !== last) process.stderr.write(`\r\x1b[2K${msg}`);
      last = msg;
    },
  });
  if (!json && process.stderr.isTTY) process.stderr.write('\r\x1b[2K');
  applyConfig(report, cfg);
  const sarif = arg('--sarif');
  if (sarif) writeFileSync(sarif, JSON.stringify(toSarif(report, file ? relative(process.cwd(), file) : 'package.json', fileText), null, 2));
  const md = arg('--markdown');
  if (md) appendFileSync(md, toMarkdown(report));

  if (json) console.log(JSON.stringify(report, null, 2));
  else print(report);

  const fail = failOn === 'never' ? false : failOn === 'review' ? report.counts.danger + report.counts.review > 0 : report.counts.danger > 0;
  process.exitCode = fail ? 1 : 0;
}

main().catch((e) => {
  console.error(red(`albertros: ${e?.message || e}`));
  process.exitCode = 2;
});
