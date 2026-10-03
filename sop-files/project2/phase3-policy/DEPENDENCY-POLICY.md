# DocuTrust dependency policy

**Owner:** Owofola Olakunle, repository maintainer
**Applies to:** every package in `package.json` and everything those packages resolve to
**Enforced by:** the `sca` job in `.github/workflows/ci.yml`, on every pull request
**Status:** in force from the commit that added this file

This document states what DocuTrust accepts in its dependency tree, what refuses a change, and
who can override the refusal. It is written to be checkable: every rule below names either an
exact command or an exact recorded field, so whether a given build should have passed is a
question with one answer.

---

## 1. The threshold

Two thresholds, because production and development dependencies carry different risk.

| Tree | Fails the build at | Command |
|---|---|---|
| **Production** — what ships and runs | any advisory rated **moderate** or above | `npm audit --omit=dev --audit-level=moderate` |
| **Complete** — development dependencies included | any advisory rated **high** or above | `npm audit --audit-level=high` |

A build that reports any advisory at or above the threshold for its tree **fails**. There is no
warn-only mode and no "non-blocking" variant of either command. `low` and `info` advisories are
reported by both commands and block neither; they are recorded but they do not stop a merge.

**Both commands run on every pull request.** Passing one and failing the other is a failing
build.

### What "at or above the threshold" means, precisely

`npm audit --audit-level=X` exits non-zero if **any** advisory in the tree is rated X or higher,
and exits zero otherwise. It does not filter the report — the full advisory list prints either
way. The flag decides only what is fatal.

This was verified rather than assumed, against the same tree:

| Tree contains | `--audit-level=critical` | `--audit-level=high` | `--audit-level=moderate` |
|---|---|---|---|
| one **high** advisory | exit 0 | exit 1 | exit 1 |
| one **moderate** advisory | exit 0 | exit 0 | exit 1 |

The identical report appears in every cell. The exit code is the only thing that changes.

---

## 2. Why two thresholds rather than one

**Production dependencies get the tighter bar because they are what runs.** An advisory in the
production tree is reachable by anyone who can reach the application. `qs` parses the query
string on every search request DocuTrust serves, so a fault in `qs` is a fault in a code path an
unauthenticated caller drives directly. Moderate is the right place to stop that.

**Development dependencies are not exempt, and they get a bar of their own.** They never ship —
but they execute on the build runner, and the build runner holds the credentials that deploy.
A compromised development dependency does not need to reach production to be worth stopping; it
only needs to run once, in the right place. The `eslint-scope` and `event-stream` incidents were
both exactly this shape.

**High rather than moderate, because the tree is deeper and the exposure is narrower.** The
development tree resolves 189 packages against 5 declared, and most of that depth exists to
build a test harness. Holding it to the production bar would mean a moderate advisory in a
transitive dev dependency blocks every merge, which trades real friction for a risk that the
same advisory does not carry in the shipping artefact. High is where that trade stops being
worth making.

This is a policy choice, and it is recorded here as one. A project with a different deployment
shape — a published library, or a build runner with no credentials — should set it differently
and say so.

---

## 3. Exceptions

An exception is a recorded decision to merge **despite** a failing advisory. It is not a
waiver of the threshold.

### Who signs off

**The repository maintainer.** One approver, named in the register. An advisory cannot be
excepted by the person who introduced it without that person being the maintainer.

### What an exception must contain

An exception is valid only when all seven fields below are recorded in the register in §4:

| Field | What it means |
|---|---|
| **Advisory** | The GHSA identifier, so the entry is checkable against the public database |
| **Package** | The package and installed version the advisory applies to |
| **Severity** | The rating, as reported by `npm audit` |
| **Tree** | `production` or `development` — which threshold it is being excepted from |
| **Justification** | Why the advisory is not exploitable in DocuTrust, stated specifically |
| **Approved by** | The maintainer who signed it |
| **Expires** | A date, **no more than 30 days** after approval |

### The three rules

1. **An exception expires.** Thirty days maximum, and the date is recorded when it is granted.
   An entry whose expiry date has passed is **void**, and the next build fails — regardless of
   whether anyone remembered to remove it.
2. **An exception is one advisory against one package.** It does not cover a second advisory,
   a different package, or a later version of the same package.
3. **An exception is recorded or it does not exist.** An agreement in a chat thread, a code
   review comment, or a maintainer's memory is not an exception. If it is not in the register,
   the build is correctly failing.

### When an exception cannot be granted

**Critical advisories are not excepted.** If a critical advisory is present in the production
tree, the fix is to remove or upgrade the dependency. If neither is possible, the decision is
about whether the dependency can stay at all — and that is a change to this policy, not an
exception to it.

---

## 4. The exception register

Every exception currently in force. Empty means the threshold is being enforced without
exception — which is the intended state.

| Advisory | Package | Severity | Tree | Justification | Approved by | Expires |
|---|---|---|---|---|---|---|
| — | — | — | — | *No exceptions in force.* | — | — |

**Reviewing this register.** Every entry carries an expiry date. On that date the entry is void
whether or not it has been removed, so the register cannot accumulate stale acceptances that
look current. The `sca` job fails on the underlying advisory from that day forward, which is
what makes the expiry real rather than aspirational.

---

## 5. What this policy does not cover

Stated so the boundary is explicit rather than implied.

**Advisories that no database has published yet.** `npm audit` asks the GitHub Advisory
Database. A dependency can be compromised, or vulnerable, before anything is filed, and this
policy will not see it. The controls against that are the dependency confusion defence and the
Scorecard threshold — different problems, different mechanisms.

**Where a package came from.** This policy asks whether a package is *vulnerable*, not whether
it is *the package the project meant to install*. A typosquatted name, or an internal-sounding
name resolved from the public registry, passes every check in this document. That is deliberately
out of scope here and covered separately.

**Whether the package should be a dependency at all.** A dependency with no advisories is not
thereby a dependency worth having. This policy sets the bar a package has to clear; it does not
argue for the package's existence.

---

## 6. Enforcement

The policy is enforced by the `sca` job added to `.github/workflows/ci.yml`:

```yaml
  sca:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node
        uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Install dependencies
        run: npm ci

      - name: SCA - production dependencies (moderate and above)
        run: npm audit --omit=dev --audit-level=moderate

      - name: SCA - complete tree (high and above)
        run: npm audit --audit-level=high
```

**`npm ci` runs first, and that ordering is load-bearing.** `npm audit` requires a lockfile and
exits non-zero with `ENOLOCK` when there is none — the same exit code as a found vulnerability.
Running `npm ci` first guarantees the lockfile is present and the tree is the one the lockfile
describes, so a failure downstream means an advisory. Without it, a missing-lockfile error would
be indistinguishable from a security finding at the level of the exit code.

**Two things this job deliberately does not do.** It does not read `package.json` to decide
whether the tree is acceptable — the lockfile and the installed tree are the source of truth,
because that is what actually runs. And it does not download a scanner: `npm audit` ships with
npm, so the check adds no dependency to the very tree it is judging.

---

## 7. Review

**This policy is reviewed when the threshold is exercised, not on a calendar.** A build that
fails on the threshold is the signal that the thresholds are worth re-reading — either they
caught something real, in which case the exception process gets used, or they caught something
that did not warrant stopping a merge, in which case the bar is wrong and this document gets
changed deliberately.

An exception entry in §4 is evidence for that review. A register that stays empty while builds
fail is evidence too: it means the threshold is being enforced, and nobody has needed to argue
with it.
