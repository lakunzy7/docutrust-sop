# DocuTrust — SOP files

Source files for the DocuTrust walkthroughs (Chain A, Projects 1 to 3).

One directory per project, and inside each, one directory per phase — mirroring the
walkthroughs, which are read a phase at a time.

The walkthroughs teach SAST, secrets scanning and DAST by having you build the changes
yourself, step by step. Some of those steps produce a file too large to print in the guide
without burying the lesson — this repository holds those files, so each step can show a
single copy command instead of a page of YAML or JavaScript.

## How to use it

Clone this alongside the environment:

```bash
git clone https://github.com/lakunzy7/docutrust-sop.git
```

Then, whenever the walkthrough reaches a step that says a file is provided here, copy it into
place. The walkthrough always names the exact command. Nothing here needs to be typed by
hand.

## Project 1 — SAST, Secrets Scanning and Live Secret Verification

| File | Walkthrough section | What it is |
|---|---|---|
| `sop-files/project1/phase3-custom-rule/sql-built-by-interpolation.yaml` | 3.1 | The custom Semgrep rule. Matches the *construction* of a SQL statement by interpolation or concatenation, then constrains it to SQL with a keyword check scoped to the matched range. It never names `documents`, `search` or `pool.query`, which is what lets it generalise past the one seeded line. |
| `sop-files/project1/phase3-custom-rule/generalization-cases.js` | 3.3 | Nine functions: five SQL injections in shapes that appear nowhere in DocuTrust, and four safe forms that must not be reported. The rule's evaluation criterion is whether it catches all five and none of the four. |
| `sop-files/project1/phase3-custom-rule/source-dependency.js` | 3.4 | Two structurally identical injections differing only in where the value comes from. Run against `p/expressjs` it yields one finding; against the custom rule, two. This is the demonstration that the custom rule is not a duplicate of the registry rule. |
| `sop-files/project1/phase4-secrets-scan/.gitleaks.toml` | 4.2 | Gitleaks configuration. Extends the default ruleset rather than replacing it, and adds one rule for AWS key IDs ending in `EXAMPLE` — the shape Gitleaks' built-in `aws-access-token` rule allowlists, and which this repository deliberately contains. Without it a default scan of DocuTrust reports nothing at all. |
| `sop-files/project1/phase5-live-verification/verify-key.js` | 5.2 | The live verification. Makes a real, signed `sts:GetCallerIdentity` call with the scanned key and reports whether it is an active credential or an inert placeholder. Credentials are passed explicitly so the result is attributable to the key under test rather than to anything already present on the machine. |
| `sop-files/project1/phase6-remediation/escapeHtml.js` | 6.4 | The XSS fix. Escapes the five characters that carry structural meaning in HTML, so a document title containing a `<script>` tag is delivered as text rather than executed. Hand-written rather than pulled from npm: a package here would put a dependency into DocuTrust's tree that Project 1 introduced, and that tree is what Project 2 measures. |
| `sop-files/project1/phase6-remediation/documents.js` | 6.2 | The route file at the end of all three Phase 6 commits — routing reordered, query parameterized, output escaped. An escape hatch for anyone who would rather not hand-edit: copy it over `src/routes/documents.js`. The walkthrough gives the edits themselves, because the change is the lesson; this exists so no step is a transcription exercise. |
| `sop-files/project1/phase7-ci-gate/ci.yml` | 7.2 | The workflow with the `sast-and-secrets` job added, alongside the existing `build-and-test`. Semgrep from a pinned image, Gitleaks downloaded and checksum-verified, both exiting non-zero on a finding — which is what turns two scanners into a gate. |
| `sop-files/project1/phase7-ci-gate/.gitleaksignore` | 7.3 | The two findings the gate accepts, as fingerprints (`file:rule:line`). Not Gitleaks' JSON baseline, which carries a `Secret` field — committing that would write the credential into the repository to record that the credential is known. |
| `sop-files/project1/phase7-ci-gate/reports.js` | 7.7 | The seeded violation. A fresh SQL concatenation in a new file, written after the Phase 6 fix and never merged. Deliberately not wired into `src/index.js`, so nothing can reach it; the scanner reads files, not routes. |

## Project 2 — SCA, Dependency Confusion Defense and OpenSSF Scorecard

| File | Walkthrough section | What it is |
|---|---|---|
| `sop-files/project2/phase3-policy/DEPENDENCY-POLICY.md` | 3.5 | The written dependency policy. Two severity thresholds — production fails at **moderate**, the complete tree fails at **high** — each with its exact `npm audit` command. Also carries the exception register: seven required fields, a 30-day maximum, a named approver, and the rule that an expired entry is void whether or not anyone remembered to remove it. The thresholds are checkable; "use good judgment" is not a policy. |
| `sop-files/project2/phase3-policy/ci.yml` | 3.5 | The workflow with the `sca` job added. `npm ci` runs first and that ordering is load-bearing: `npm audit` exits 1 with `ENOLOCK` on a tree with no lockfile, the same exit code it uses for a finding, so without it a missing lockfile would be indistinguishable from an advisory. Both thresholds from the policy then run, which is what makes them thresholds rather than descriptions. |
| `sop-files/project2/phase4-supply-chain/.npmrc` | 4.4 | The dependency confusion defence, in one line: the org-owned `@docutrust` scope resolves from GitHub Packages and nowhere else. The value this file must never carry is `registry.npmjs.org` — pinning an org scope to the public registry would not be the control, it would be the vulnerability, because a public package taking an internal name is precisely the attack. |
| `sop-files/project2/phase4-supply-chain/demo.npmrc` | 4.5 | The same rule applied to a scope whose package, `@babel/core`, genuinely exists on the public registry — so that "npm did not fall back" is something you watch happen rather than something you take on trust. Without a package that really is publicly available, a refused install proves only that something went wrong. |
| `sop-files/project2/phase6-scorecard-policy/SCORECARD-POLICY.md` | 6.2 | The Scorecard-driven policy: a floor of **5.0** on the upstream project behind every declared dependency. The number was measured, not chosen — the five packages this repository already declares score between 5.4 and 8.3 — and §6 states plainly that DocuTrust's own score of 2.9 would fail it, and why that asymmetry is deliberate rather than an oversight. §3 records what Scorecard cannot see, including its SAST check's blindness to Semgrep. |
| `sop-files/project2/phase6-scorecard-policy/ci.yml` | 6.3 | The workflow with the `dependency-scorecard` job added, alongside the earlier `build-and-test`, `sast-and-secrets` and `sca` jobs. It reads the dependency list from `package.json` rather than naming packages in the job, which is what makes it a gate on *new* dependencies. Scorecard is downloaded and checksum-verified the way Gitleaks is, and the job needs a token — measured, because an unauthenticated run did not finish in four minutes. |

## Why these are separate from the repository

The DocuTrust repository is the **environment** — the application, the workflow that scans
it, the fixes. It is the thing that gets forked, reviewed and pushed.

These files are the **walkthrough's** source material. Keeping them apart means the
walkthrough can be followed without editing the guide by hand, and the repository stays
readable as an application rather than accumulating fixtures for a document about it.

Projects 2 and 3 add their own directories here when their phases are written.
