# Albertros

**Know which npm dependency will hurt you, before `npm install` does.**

In September 2025, `chalk` and `debug` (2.6 billion downloads a week between them) were published with a crypto-stealing payload from a phished maintainer account. A week later the Shai-Hulud worm used stolen npm tokens to republish hundreds of packages with a postinstall script that harvested secrets and spread itself. `npm audit` stayed quiet through both: it reports known vulnerabilities, not attacks in progress.

Albertros checks every dependency for the signs of an attack, and gives each one a verdict with the reason in plain language:

- **Danger**: don't install this.
- **Review**: probably fine, but look first.
- **Safe**: nothing found.

It runs in the browser (nothing is uploaded), in your terminal, and in CI.

| | |
|---|---|
| **Web app** | _deploy link_ |
| **CLI** | `npx github:MeghVyas3132/albertros check` |
| **GitHub Action** | `uses: MeghVyas3132/albertros@main` |

## Try it in 30 seconds

1. Open the web app and click **A risky project**. You get 6 dangerous dependencies, each with its reason: npm takedowns, known-malicious versions, a name that anyone could register.
2. Click **The Sept 2025 chalk/debug hijack** to see the real compromised versions flagged.
3. Paste your own `package.json` or `package-lock.json`, or enter any public GitHub repo.

## How it decides

Each package gets four independent checks. Any **danger** finding makes the package Danger; otherwise any **review** finding makes it Review.

### 1. Registry facts
| Finding | Verdict |
|---|---|
| npm replaced the package with a `security holding package` placeholder (it was malware) | Danger |
| The name does not exist on npm, so anyone can register it (dependency confusion) | Danger |
| The package or the pinned version was unpublished | Danger / Review |
| The name is one typo away from a top package and has fewer than 5,000 weekly downloads | Danger |
| Installed from git or a URL rather than the registry | Review |
| Deprecated by its author | Review |
| Published with npm provenance (built and signed by CI) | Good |

### 2. Known malware and vulnerabilities
Every exact version is checked against [OSV.dev](https://osv.dev), which aggregates the OpenSSF malicious-packages feed and GitHub Security Advisories.

| Finding | Verdict |
|---|---|
| Version listed as malicious (`MAL-*` or a malware advisory) | Danger |
| High or critical vulnerability | Review |
| Lower-severity vulnerability | Info |

### 3. Signs of a hijacked release
This compares the resolved version with the releases before it:

- first release by an account that never published the previous 10 versions
- an install script that the previous version did not have
- the previous version had CI provenance and this one doesn't (a hand-published release, typical of a stolen token)
- unpacked size more than doubled (+200 kB)
- published less than 3 days ago

Any one of these is a Review. **Two at once, or one on a release under 3 days old, is Danger ("looks like a hijacked release").** This is the pattern both the chalk/debug and Shai-Hulud releases showed.

### 4. The code itself
For anything with an install script or another finding (or every package with `--deep`), Albertros downloads the published tarball and scans it for what real attacks do:

| Pattern | Example |
|---|---|
| Sends data to a drop service | `webhook.site`, Discord webhooks, Telegram bots, ngrok, OAST domains |
| Downloads and runs a script | `curl … \| sh`, `powershell -enc` |
| Runs hidden code | `eval(Buffer.from(…, 'base64'))`, `new Function(atob(…))` |
| Hijacks wallet or network calls | reassigning `window.ethereum.request`, `fetch`, `XMLHttpRequest.prototype.send` |
| Reads tokens or credentials | `.npmrc`, `NPM_TOKEN`, `GITHUB_TOKEN`, SSH keys, cloud credentials, browser or wallet data, `trufflehog` |
| Collects all environment variables | `JSON.stringify(process.env)` |
| Contacts a raw public IP | `http://45.9.148.3/` |
| Obfuscated code | `_0x…` identifiers, thousands of hex escapes, huge base64 blobs |

Secret access or a raw IP becomes **Danger** when it is combined with network calls or happens during install. Install-time downloaders in very popular packages (esbuild, sharp) are reported as info, not review.

### Score
`100 − 25 × danger − 3 × review`, floored at 0.

## CLI

```bash
npx github:MeghVyas3132/albertros check                 # ./package-lock.json or ./package.json
npx github:MeghVyas3132/albertros check expressjs/express
npx github:MeghVyas3132/albertros check chalk@5.6.1 lodash
```

| Option | |
|---|---|
| `--deep` | Scan the code of every package |
| `--prod` | Skip devDependencies |
| `--json` | Full report as JSON |
| `--sarif <file>` | SARIF 2.1.0 for GitHub code scanning |
| `--markdown <file>` | Markdown summary (e.g. `$GITHUB_STEP_SUMMARY`) |
| `--fail-on danger\|review\|never` | Exit code policy (default `danger`) |
| `--max <n>` | Package limit (default 300) |
| `--config <file>` | Config file (default `.albertrosrc.json`) |

Exit codes: `0` clean, `1` policy failed, `2` error.

## GitHub Action

```yaml
name: dependency check
on: [pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  albertros:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: MeghVyas3132/albertros@main
        with:
          fail-on: danger
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: albertros.sarif
```

Findings appear in the job summary and in the repository's **Security → Code scanning** tab.

## Config

`.albertrosrc.json` next to your `package.json`:

```json
{
  "failOn": "danger",
  "allow": ["some-internal-tool", "legacy-lib@1.2.3"],
  "ignoreFindings": ["osv-vuln"]
}
```

`allow` trusts a package (or one exact version). `ignoreFindings` turns off a finding type everywhere. Allowed findings are still shown, marked as allowed.

## Library

```ts
import { analyzeProject, parseInput } from 'albertros';
const { deps } = parseInput(fs.readFileSync('package-lock.json', 'utf8'));
const report = await analyzeProject('my-app', deps);
if (report.counts.danger) process.exit(1);
```

The engine has no server and no API keys. It uses only public endpoints that allow browser access: the npm registry, the npm downloads API, and OSV.

## Run locally

```bash
npm install
npm test            # unit tests; LIVE=1 npm test adds live registry checks
npm run dev         # web app on http://localhost:5173
npx tsc && node dist/cli.js check .
```

## Limits

- Lockfiles are capped at 300 packages per run (direct dependencies first). Raise it with `--max`.
- Transitive packages from a lockfile get registry, OSV and code checks; release-history checks run on direct dependencies and on anything already flagged.
- The code scan is heuristic. A clean scan is evidence, not proof, and a determined attacker can evade pattern matching.
- Unauthenticated GitHub raw access is rate-limited.

## Roadmap

- [ ] Publish `albertros` to npm so `npx albertros` works without GitHub
- [ ] pnpm-lock.yaml and yarn.lock support
- [ ] Diff mode for PRs: only the dependencies a PR adds or changes
- [ ] Compare a release's tarball with its git tag (code shipped that is not in the repo)
- [ ] Watch mode: webhook or email alert when a dependency you use publishes a suspicious release
- [ ] VS Code extension that flags risky imports as you type

## License

MIT
