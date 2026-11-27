# Devfolio submission: Albertros

**Project name:** Albertros

**Tagline (short):** Know which npm package will hurt you, first.

**Links**
- Live app: https://albertros-rouge.vercel.app
- GitHub: https://github.com/MeghVyas3132/albertros
- Try it: https://albertros-rouge.vercel.app/#replay=chalk and https://albertros-rouge.vercel.app/#repo=expressjs/express
- Recently scanned + CODEFESTTHON results: https://albertros-rouge.vercel.app/history

**Tracks / tags:** Open Innovation, Automation & Productivity (devtools), Security

**Tech:** TypeScript, Node.js, Vite, npm registry API, OSV.dev API, GitHub Actions, SARIF, Vercel

---

## The problem it solves

Every JavaScript project installs hundreds of packages written by strangers, and `npm install` runs their code on your machine and in your CI with full access to your tokens.

That trust keeps getting abused:
- **Sept 2025:** a phished maintainer account pushed crypto-stealing code into `chalk` and `debug`, about 2.6 billion downloads a week.
- **Weeks later:** the **Shai-Hulud** worm used stolen npm tokens to republish hundreds of packages with a postinstall script that stole secrets and spread itself.
- **Every day:** typosquats like `lodahs` and `electorn` catch people who mistype.

`npm audit` didn't catch any of these. It only knows about vulnerabilities after someone files an advisory, not attacks in progress.

**Albertros** does three things no other checker shows you:

- **Who can push code into your app.** It resolves your whole dependency tree and counts every npm account that can publish into it. Express: **259 strangers**. Then it finds the single account whose stolen password reaches the most of your app (one account reaches 75% of Express's direct dependencies) and animates the attack spreading through your dependency graph.
- **Proof the package is its source code.** It downloads the published tarball, fetches the same files from GitHub at the exact commit npm says the release came from, and shows **the lines that ship to users but don't exist in git**. The xz backdoor and the chalk hijack both lived only in published artifacts.
- **Worm outbreak simulator.** The 2025-2026 attacks (Shai-Hulud, CanisterWorm, Miasma) were worms: steal one token, republish everything that account can publish, infect whoever runs it next. Albertros runs that worm generation by generation on your real dependency and maintainer graph. Express: one stolen token, 5 generations, **222 of 297 packages (75%) poisoned, 95 accounts compromised**. A slider sets how likely each infected maintainer is to have a token exposed. We found no other tool that simulates worm spread through your own tree.
- **Attack replays.** One click re-creates the Sept 2025 chalk hijack and the Shai-Hulud worm on the real tarballs (inert stand-in code, never executed) and catches them live, from the code alone, minutes after publish, without any malware database.

On top of that, it checks every dependency for the signs of an attack and gives each one a verdict, **Danger**, **Review** or **Safe**, with the reason in plain language:

1. **Registry facts.** Packages npm took down as malware, names that don't exist on npm (anyone could register them: dependency confusion), unpublished versions, typosquats of popular packages.
2. **Known malware.** Every exact version is checked against OSV.dev, which includes the OpenSSF malicious-packages feed.
3. **Signs of a hijacked release.** A first release by a new account, an install script that wasn't there before, CI provenance that suddenly stops, a sudden size jump, a release only hours old. Two at once means Danger: the exact pattern chalk/debug and Shai-Hulud showed.
4. **The code itself.** It downloads the published tarball and looks for what real attacks do: install scripts that reach the internet, hidden `eval`, reading `.npmrc`/SSH keys/tokens, hooking `window.ethereum`, obfuscation.

It also verifies every version's npm registry signature (ECDSA P-256, the same check as `npm audit signatures`) and every tarball's sha512, in the browser with WebCrypto.

**We checked every CODEFESTTHON 2026 project with a public repo** (13 JavaScript projects, 2,729 packages; no project named): the median project trusts **166 strangers**, one phished account reaches a median **33%** of its direct dependencies, and a single worm would poison a median **44%** of its packages. Results and a live list of every public repo checked with Albertros: https://albertros-rouge.vercel.app/history

**Three ways to use it:**
- **Web app:** paste a package.json or lockfile, or enter a GitHub repo. It runs entirely in your browser and uploads nothing.
- **CLI:** `npx albertros check`
- **GitHub Action:** fails the PR on danger, writes a job summary, and uploads SARIF so findings appear in GitHub's Security tab. Albertros already runs this on its own repo.

Production details: a config file to allow-list packages, `--fail-on` policy, JSON/SARIF/Markdown output, retries on registry errors, 17 tests including a live test against the real chalk@5.6.1 hijack, and CI on every push plus nightly.

## Challenges we ran into

- **No backend, no keys.** We wanted it to run in the browser so nobody has to upload their dependency list. We checked that the npm registry, the npm downloads API, OSV and GitHub raw files all allow cross-origin requests. Then we wrote a small tar reader on the browser's built-in `DecompressionStream`, so the same engine scans real npm tarballs in Chrome and in Node.
- **Huge metadata.** The full registry document for `typescript` is 16 MB. Transitive packages in a lockfile only fetch the small per-version manifest. Full history is pulled only for direct dependencies and anything already suspicious.
- **False positives.** Our first run flagged Express because its newest release was published by "GitHub Actions" instead of a person. That's actually a security upgrade (trusted publishing), so it's now marked as a good sign. esbuild and sharp legitimately download binaries on install, so install-time downloaders in packages with over a million weekly downloads are reported as info, not warnings. A "new publisher" alone is weak evidence, so it only escalates in combination with other signals.
- **Real test data.** npm deletes malicious packages, so we built the demo around what remains: security-holding placeholders, unpublished versions and OSV records. The code scanner is tested on a real tarball that we build in the test with a token-stealing install script.

## What's next
Publish to npm, pnpm/yarn lockfiles, PR diff mode (only check what a PR changes), comparing tarballs with their git tag, and alerts when a dependency you use ships a suspicious release.
