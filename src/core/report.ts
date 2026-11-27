import { scoreOf, sortReports, verdictOf } from './analyze.js';
import type { PackageReport, ProjectReport } from './types.js';

export interface AlbertrosConfig {
  /** Packages to trust anyway: "name" or "name@version". */
  allow?: string[];
  /** Finding codes to ignore everywhere, e.g. "osv-vuln". */
  ignoreFindings?: string[];
  failOn?: 'danger' | 'review' | 'never';
  deep?: boolean;
  includeDev?: boolean;
}

/** Downgrade allowed packages and ignored finding codes to info, then recompute verdicts. */
export function applyConfig(report: ProjectReport, cfg: AlbertrosConfig): ProjectReport {
  const allow = new Set(cfg.allow || []);
  const ignore = new Set(cfg.ignoreFindings || []);
  for (const p of report.packages) {
    const allowed = allow.has(p.name) || (p.version && allow.has(`${p.name}@${p.version}`));
    for (const f of p.findings) {
      if ((allowed || ignore.has(f.code)) && (f.severity === 'danger' || f.severity === 'review')) {
        f.severity = 'info';
        f.title += allowed ? ' (allowed in config)' : ' (ignored in config)';
      }
    }
    if (p.verdict !== 'unknown') p.verdict = verdictOf(p.findings);
  }
  sortReports(report.packages);
  const { score, counts } = scoreOf(report.packages);
  report.score = score;
  report.counts = counts;
  return report;
}

function locate(manifestText: string | undefined, name: string): number {
  if (!manifestText) return 1;
  const lines = manifestText.split('\n');
  const needles = [`"node_modules/${name}"`, `"${name}":`];
  for (const n of needles) {
    const i = lines.findIndex((l) => l.includes(n));
    if (i !== -1) return i + 1;
  }
  return 1;
}

const RULE_HELP: Record<string, string> = {
  'security-holding': 'npm replaced this package with a security placeholder because it was malware.',
  'osv-malicious': 'OSV lists this exact version as malicious.',
  'not-on-npm': 'The dependency name is not registered on npm (dependency confusion).',
  typosquat: 'The name imitates a popular package.',
  'hijack-pattern': 'Several account-takeover signals in one release.',
};

/** SARIF 2.1.0 for GitHub code scanning. */
export function toSarif(report: ProjectReport, file: string, fileText?: string): object {
  const results: object[] = [];
  const rules = new Map<string, object>();
  for (const p of report.packages) {
    for (const f of p.findings) {
      if (f.severity !== 'danger' && f.severity !== 'review') continue;
      const ruleId = `albertros/${f.code}`;
      if (!rules.has(ruleId)) {
        rules.set(ruleId, {
          id: ruleId,
          name: f.code,
          shortDescription: { text: RULE_HELP[f.code] || f.title },
          helpUri: 'https://github.com/MeghVyas3132/albertros#how-it-decides',
          properties: { tags: ['security', 'supply-chain'], 'security-severity': f.severity === 'danger' ? '9.0' : '5.0' },
        });
      }
      results.push({
        ruleId,
        level: f.severity === 'danger' ? 'error' : 'warning',
        message: { text: `${p.name}${p.version ? '@' + p.version : ''}: ${f.title}. ${f.detail}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: file }, region: { startLine: locate(fileText, p.name) } } }],
        partialFingerprints: { package: `${p.name}@${p.version || p.spec}/${f.code}` },
      });
    }
  }
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{ tool: { driver: { name: 'Albertros', informationUri: 'https://github.com/MeghVyas3132/albertros', rules: [...rules.values()] } }, results }],
  };
}

/** Markdown summary for a GitHub job summary or PR comment. */
export function toMarkdown(report: ProjectReport): string {
  const { counts, score } = report;
  const icon = { danger: '🛑', review: '⚠️', safe: '✅', unknown: '❔' } as const;
  const rows = report.packages
    .filter((p) => p.verdict === 'danger' || p.verdict === 'review')
    .map((p: PackageReport) => {
      const why = p.findings.filter((f) => f.severity === 'danger' || f.severity === 'review').map((f) => f.title).join('; ');
      return `| ${icon[p.verdict]} ${p.verdict} | \`${p.name}${p.version ? '@' + p.version : ''}\` | ${why.replace(/\|/g, '\\|')} |`;
    });
  return [
    `## Albertros dependency check: ${score}/100`,
    '',
    `${counts.danger} danger · ${counts.review} review · ${counts.safe} safe · ${report.packages.length} packages checked in \`${report.source}\``,
    '',
    rows.length ? ['| Verdict | Package | Why |', '|---|---|---|', ...rows].join('\n') : 'Nothing suspicious.',
    '',
  ].join('\n');
}
