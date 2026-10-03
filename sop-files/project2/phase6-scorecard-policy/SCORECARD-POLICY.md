# DocuTrust Scorecard policy

**Owner:** Owofola Olakunle, repository maintainer
**Applies to:** every package declared in `package.json` — production and development alike
**Enforced by:** the `dependency-scorecard` job in `.github/workflows/ci.yml`, on every pull request
**Status:** in force from the commit that added this file

`DEPENDENCY-POLICY.md` asks whether a package is **vulnerable**. This document asks a different
question: whether the project behind it is one worth depending on at all. A package with no
advisories is not thereby a package worth having, and the second question cannot be answered by
the first.

---

## 1. The threshold

| Applies to | Minimum | Measured by |
|---|---|---|
| Every declared dependency, production and development | **5.0** | `scorecard --npm=<package>` — the aggregate score of the upstream repository |

A declared dependency whose upstream project scores **below 5.0** fails the build.

The check runs against the **upstream repository**, resolved from the package name. `express`
is scored as `github.com/expressjs/express`, not as a tarball.

---

## 2. Where that number came from

It was not chosen. It was measured, on 2026-10-03, with Scorecard v5.5.0, against the five
packages this repository already declares:

| Dependency | Upstream repository | Score |
|---|---|---|
| `express` | github.com/expressjs/express | 8.3 |
| `lodash` | github.com/lodash/lodash | 6.2 |
| `@jazzer.js/core` | github.com/CodeIntelligenceTesting/jazzer.js | 5.8 |
| `pg` | github.com/brianc/node-postgres | 5.7 |
| `zod` | github.com/colinhacks/zod | 5.4 |

**The floor sits below the lowest incumbent.** That is deliberate, for two reasons.

**A policy that immediately fails the packages it was derived from is a policy nobody can comply
with.** Setting the floor at 6.0 would fail `pg`, `zod` and `@jazzer.js/core` on the day it was
written — three packages that were reviewed, chosen, and are working. A threshold that has to be
excepted three times before it has caught anything is a threshold that gets disabled in a week.

**The floor's job is to stop the next package, not to relitigate the last ones.** The evidence for
the packages already in the tree is that they are in the tree; they were accepted by review. What
this policy adds is a bar that has to be cleared *before* a new one gets there.

---

## 3. What Scorecard measures, and what it does not

Stated so that a passing score is not read as more than it is.

**It scores the repository, not the artefact.** Scorecard reads the upstream project — its
workflows, its review practice, its branch protection, its advisories. It cannot tell you whether
the tarball on the registry was built from that repository, or by whom, or from which commit. That
is what signing and provenance attestations are for, and they belong to a different project in
this track. A package that passes this policy is a package whose *upstream* looks healthy.

**Its SAST check recognises three tools, and Semgrep is not one of them.** Scorecard's
documentation says the check looks for *"known GitHub apps such as CodeQL (github-code-scanning)
or SonarCloud"*, and for *"the deprecated LGTM service"*, and concedes directly: *"A project that
fulfills this criterion with other tools may still receive a low score on this test."* A project
running Semgrep — as DocuTrust itself does, on every pull request — scores 0 on that check. The
score is a floor on health, not a measurement of it, and this is the clearest place where the two
differ.

**Some checks measure age and team shape rather than quality.** `Maintained` scores 0 for any
repository created within the last 90 days. `Contributors` scores 0 for a project with a single
contributing organisation. A young, single-maintainer project is not thereby a bad dependency, but
it does score as one.

**Some checks return `?` rather than a number, and are excluded from the aggregate.** So the
aggregate describes the checks that *could* be evaluated — which depends partly on what the token
running the scan is permitted to read. `Branch-Protection` is the check most likely to differ
between one token and another.

**Transitive dependencies are out of scope.** The policy covers what `package.json` declares.
The 189 packages underneath them are covered by `DEPENDENCY-POLICY.md` for advisories, but not
scored here — that would be 189 Scorecard runs per pull request, and the cost buys less than it
appears to.

---

## 4. Exceptions

An exception is a recorded decision to merge **despite** a dependency scoring below the floor. It
is not a lowering of the floor.

The register has the same shape as the one in `DEPENDENCY-POLICY.md` §4, and the same three rules:
an exception expires (30 days maximum, and an entry whose date has passed is void whether or not
anyone removed it), an exception is one package at one version, and an exception that is not
recorded does not exist.

| Package | Version | Score | Justification | Approved by | Expires |
|---|---|---|---|---|---|
| — | — | — | *No exceptions in force.* | — | — |

**A package scoring below 3.0 is not excepted.** At that level the finding is not about one check;
it is that the upstream project has no review practice, no protection, and no maintenance worth
the name. The decision there is whether the dependency can be replaced, not whether the floor can
be crossed.

---

## 5. Enforcement

The `dependency-scorecard` job in `.github/workflows/ci.yml`.

```yaml
      - name: Score every declared dependency
        env:
          GITHUB_AUTH_TOKEN: ${{ secrets.SCORECARD_TOKEN || secrets.GITHUB_TOKEN }}
        run: |
          FLOOR=5.0
          for pkg in $(jq -r '.dependencies + .devDependencies | keys[]' package.json); do
            echo "Scoring $pkg"
            scorecard --npm="$pkg" --format=json -o /tmp/scorecard-check.json
            jq -r '"\(.repo.name) -> \(.score)"' /tmp/scorecard-check.json
            if jq -e --argjson f "$FLOOR" '.score < $f' /tmp/scorecard-check.json > /dev/null; then
              echo "::error::$pkg falls below the $FLOOR floor in SCORECARD-POLICY.md"
              exit 1
            fi
          done
```

**The dependency list is read from `package.json`, not written into the job.** That is what makes
this a gate on *new* dependencies: a package added in a pull request is scored by this job without
anyone editing the job. A hardcoded list would silently stop covering the thing it exists to cover.

**A token is required, and the requirement is sharper than it first appears.** Two things were
measured, and the second one changed the job.

An unauthenticated run against a single dependency did not complete within four minutes.

Then, with the workflow's own `GITHUB_TOKEN`: `@jazzer.js/core` scored **5.8 — matching the
workstation exactly** — and the run then **aborted** on `express` with `some github tokens can't
read classic branch protection rules`. Reading branch protection on a repository we do not own is
an administrative request, and GitHub does not grant it to that token. Scorecard treats a check it
cannot read as fatal: it exits non-zero rather than computing a score over the checks it *could*
read.

**That refusal is the behaviour worth keeping.** If Scorecard had quietly scored `express` over
the readable checks, the gate would have produced a number derived from a different set of checks
in CI than the number this policy's floor was measured against. A threshold that means one thing
on a workstation and another in the pipeline is worse than one that declines to run.

So the job requires **`SCORECARD_TOKEN` — a classic personal access token with the `public_repo`
scope**. `public_repo` is the least privilege that works, and that was measured rather than
assumed: with the secret in place, all five dependencies scored in CI to the same decimal as on a
workstation, `express` included. The fallback to the workflow's own token is kept deliberately, so
that a repository which has not set the secret fails loudly here rather than quietly scoring
something weaker.

**The token expires, and that is part of the control rather than an inconvenience.** A secret with
an expiry date makes this a gate that decays: on that date it stops working whether or not anyone
remembered. This is the same shape as the exception register in `DEPENDENCY-POLICY.md` §3, and it
fails in the same safe direction. **An expired token cannot pass quietly, and the reason is the
behaviour measured in the paragraph above**: Scorecard treats a check it cannot read as fatal, and
an expired token makes every check unreadable. The result is a red build, which *is* the reminder.

The remedy is to issue a replacement and update the secret. Nothing else in this policy changes
when that happens, and no score needs re-measuring — the floor is a property of the dependencies,
not of the credential used to observe them.

**It fails closed.** If a declared package cannot be resolved to an upstream repository, Scorecard
exits non-zero and the job stops. A dependency the policy cannot evaluate is not a dependency the
policy passed.

---

## 6. DocuTrust would fail this policy

Stated deliberately, because a reader will notice it: **DocuTrust's own Scorecard score is 2.9.**
Under the threshold in §1, DocuTrust would not qualify as a dependency of itself.

That is not an oversight and it is not a reason to lower the number.

**The floor applies to code we cannot fix.** A dependency is somebody else's project. The only
decision available is whether to take it, and its score is most of what can be known about it
before that decision. DocuTrust is code we control and can change — and this policy is not the
instrument for that. The instrument for that is the eighteen checks, read one at a time, which is
what Project 2 §5.3 and §5.4 do.

**Three of DocuTrust's zeros measure something other than the code.** A repository younger than
90 days scores 0 on `Maintained`. A project with one contributing organisation scores 0 on
`Contributors`. A project running Semgrep scores 0 on `SAST`, because the check does not recognise
it. Those three are properties of a three-week-old fork of a demo application, not defects in it —
and none of them would apply to `express` or `lodash`, which is exactly why the same floor can be
the right bar for a dependency and the wrong bar for this repository.

---

## 7. Review

Like `DEPENDENCY-POLICY.md`, this policy is reviewed when it is exercised rather than on a
calendar.

A build that fails on the floor is the signal to re-read it. Either it caught something real, in
which case the exception process in §4 gets used, or it caught a project that is genuinely worth
depending on and scores low for reasons like the ones in §3 — in which case the floor is wrong and
this document gets changed deliberately, with the measurement that changed it recorded here.
