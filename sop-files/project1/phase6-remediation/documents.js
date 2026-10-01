const express = require("express");
const _ = require("lodash");
const { pool } = require("../db");
const { createDocumentSchema, createCommentSchema } = require("../validation");
const { parseSearchQuery } = require("../lib/searchQuery");
const { escapeHtml } = require("../lib/escapeHtml");

const router = express.Router();

router.post("/", async (req, res) => {
  const parsed = createDocumentSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "Invalid document data" });
  }

  try {
    const result = await pool.query(
      "INSERT INTO documents (title, body) VALUES ($1, $2) RETURNING id, title, body, created_at",
      [parsed.data.title, parsed.data.body]
    );
    // lodash used here for a real, if minor, purpose: a deep clone
    // before returning, so callers can't accidentally mutate a cached
    // reference. This is the app's one real use of the intentionally
    // outdated lodash@4.17.15 pin, see package.json and Project 2's
    // brief. `npm audit` confirms multiple real, disclosed advisories
    // against this exact pinned version (prototype pollution, command
    // injection, ReDoS), a genuine, live SCA finding, not a dependency
    // added purely for show.
    const doc = _.cloneDeep(result.rows[0]);
    res.status(201).json(doc);
  } catch (err) {
    res.status(503).json({ error: "Database unavailable" });
  }
});

/**
 * SEEDED FINDING for Project 1 (SAST) and Project 3 (DAST): the query
 * below is built with raw string concatenation instead of a
 * parameterized query, a textbook SQL injection, deliberately left
 * exactly this way so a SAST rule and a real DAST payload both have a
 * genuine, findable target here, not a synthetic example bolted on
 * separately. Compare against the parameterized queries above and in
 * comments.js below, that contrast is the point.
 *
 * FIXED in Project 1, Phase 6. The statement below now passes the search
 * term as a bound parameter, so it is treated as data rather than parsed
 * as SQL. The vulnerable form is preserved at the commit preceding that
 * fix, which is where Project 3 runs its external tests from.
 *
 * This same endpoint also calls the intentionally naive
 * parseSearchQuery() from lib/searchQuery.js, Project 7's fuzz target,
 * documented there. One endpoint, three different testing
 * methodologies (SAST, DAST, fuzzing), three different real findings.
 *
 * Registered BEFORE "/:id", and that ordering is load-bearing. Express
 * matches in registration order, and "/:id" matches any single path
 * segment -- so with "/search" defined after it, a request to
 * /documents/search was captured by the ":id" handler, handed to
 * Postgres as a document id, and rejected as an invalid integer. The
 * route was unreachable and no request ever reached the code below.
 */
router.get("/search", async (req, res) => {
  const q = req.query.q || "";

  let tokens;
  try {
    tokens = parseSearchQuery(String(q));
  } catch (err) {
    return res.status(400).json({ error: "Invalid query" });
  }

  const searchTerm = tokens.map((t) => t.value).join(" ");

  try {
    // The search term is a bound parameter, not part of the statement
    // text. The wildcards belong to the value, so the driver escapes them
    // along with everything else the user supplied -- there is no path by
    // which a search term becomes SQL.
    const result = await pool.query(
      "SELECT id, title FROM documents WHERE title ILIKE $1",
      [`%${searchTerm}%`]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(503).json({ error: "Database unavailable" });
  }
});

router.get("/:id", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM documents WHERE id = $1", [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Not found" });
    }
    res.json(result.rows[0]);
  } catch (err) {
    res.status(503).json({ error: "Database unavailable" });
  }
});

/**
 * SEEDED FINDING for Project 1 (SAST) and Project 3 (DAST/IAST): the
 * document title was written into the HTML response without escaping.
 * A title containing a script tag round-tripped straight into the
 * response, a textbook reflected/stored XSS, deliberately left that
 * way for the same reason as the search endpoint above.
 *
 * FIXED in Project 1, Phase 6. Both values now pass through
 * lib/escapeHtml.js before reaching the response. The vulnerable form
 * is preserved at the commit preceding that fix, which is where
 * Project 3 runs its external tests from.
 */
router.get("/:id/render", async (req, res) => {
  try {
    const result = await pool.query("SELECT title, body FROM documents WHERE id = $1", [
      req.params.id,
    ]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Not found" });
    }
    const { title, body } = result.rows[0];

    // Both values are escaped before they reach the response. The data is
    // unchanged -- the browser is told to treat it as text rather than as
    // markup, so a title containing a <script> tag renders as those
    // characters instead of executing.
    res.set("Content-Type", "text/html");
    // The two findings Semgrep reports on the next line are false positives, and
    // the suppression below is a recorded judgement rather than a silenced alert.
    //
    // Both values pass through escapeHtml() before reaching the response, which is
    // the correct treatment for HTML element content. Semgrep's taint engine does
    // not recognise a hand-written sanitizer -- it knows a fixed list, DOMPurify
    // and similar -- so it reports an injection on code that no longer has one.
    //
    // The second rule, direct-response-write-with-header, is a structural warning
    // about constructing HTML by hand at all. Satisfying it would mean adopting a
    // template engine and adding a dependency that Project 1 has no business
    // putting into the application's tree.
    //
    // This is precisely the gap Project 3's IAST tracer exists to close: it follows
    // the value through the sanitizer we actually wrote, which is the thing a taint
    // engine with a hard-coded sanitizer list structurally cannot do.
    // nosemgrep: javascript.express.security.injection.raw-html-format.raw-html-format, javascript.express.direct-response-write-with-header.direct-response-write-with-header
    res.send(`<html><body><h1>${escapeHtml(title)}</h1><p>${escapeHtml(body)}</p></body></html>`);
  } catch (err) {
    res.status(503).json({ error: "Database unavailable" });
  }
});

router.post("/:id/comments", async (req, res) => {
  const parsed = createCommentSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "Invalid comment data" });
  }

  try {
    const result = await pool.query(
      "INSERT INTO comments (document_id, body) VALUES ($1, $2) RETURNING id, body, created_at",
      [req.params.id, parsed.data.body]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(503).json({ error: "Database unavailable" });
  }
});

module.exports = router;
