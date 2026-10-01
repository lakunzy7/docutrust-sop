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

## Why these are separate from the repository

The DocuTrust repository is the **environment** — the application, the workflow that scans
it, the fixes. It is the thing that gets forked, reviewed and pushed.

These files are the **walkthrough's** source material. Keeping them apart means the
walkthrough can be followed without editing the guide by hand, and the repository stays
readable as an application rather than accumulating fixtures for a document about it.

Projects 2 and 3 add their own directories here when their phases are written.
