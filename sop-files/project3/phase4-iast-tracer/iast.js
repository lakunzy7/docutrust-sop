/**
 * Author: Owofola Olakunle
 *
 * A working IAST-style taint tracer for DocuTrust.
 *
 * WHAT THIS IS
 * ------------
 * An interactive application security testing tracer. It follows a value from
 * the moment it enters the process as HTTP input, through the code that
 * handles it, to the moment it is written into a SQL statement or an HTML
 * response — and reports when a value that came from outside reaches one of
 * those sinks without having been neutralised on the way.
 *
 * WHY IT IS BUILT THIS WAY
 * ------------------------
 * Commercial IAST products instrument bytecode and keep *shadow memory*: a
 * parallel map from object identity to taint state. That works in Java or
 * .NET because a string there is an object with an identity that can be
 * referenced. JavaScript strings are primitives — `"abc"` has no identity and
 * nowhere to hang a tag, and any `String(x)`, template literal or `.join()`
 * would drop such a tag even if one could be attached. Node exposes no
 * bytecode hook and no shadow memory.
 *
 * So the technique is re-derived for the platform. Rather than tagging the
 * value, this tracer records the exact strings that entered, and looks for
 * them at the sinks. A taint then travels *inside* the query string or the
 * HTML body, where no operation can strip it off:
 *
 *     source  --record-->  registry  --lookup-->  sink
 *
 * THE HONEST LIMIT OF THIS APPROACH
 * ---------------------------------
 * Two identical strings are indistinguishable. A tainted "hello" cannot be
 * told apart from an untainted one, which is why MIN_TRACKED_LENGTH exists and
 * why this tracer is looking for distinctive input — payloads, not prose. A
 * shadow-memory engine does not have this problem, and anyone reading this
 * file should know that this is a re-derivation of the technique under a real
 * platform constraint, not a complete implementation of it.
 *
 * HOW THE SANITISER IS HANDLED
 * ----------------------------
 * It falls out of the design rather than being special-cased. Escaping changes
 * the value, so `&lt;script&gt;` does not contain `<script>` and the raw taint
 * stops matching at the sink. escapeHtml() is wrapped only so the tracer can
 * *report* that a sanitizer ran — the silence at the sink needs no rule.
 */

"use strict";

const { Pool } = require("pg");

// Required here, and this file must be required before routes/documents.js.
// That file does `const { escapeHtml } = require("../lib/escapeHtml")`, which
// destructures at load time — so if the router loads first it keeps a
// reference to the original function and the wrapper below never runs. This
// is the same ordering rule every instrumentation agent lives by; Java's
// -javaagent exists for exactly this reason.
const escapeHtmlModule = require("./escapeHtml");

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// Values shorter than this are not tracked. A three-character string appears
// in unrelated places constantly, and tracking it would produce noise rather
// than findings — see "the honest limit" above. Six is a compromise: long
// enough to be distinctive, short enough to catch real payload fragments.
const MIN_TRACKED_LENGTH = 6;

// Ceiling on the registry, so a long-running process or a fuzzing scan cannot
// grow it without bound. Oldest entries are dropped first.
const MAX_TRACKED = 2000;

// ---------------------------------------------------------------------------
// The registry
// ---------------------------------------------------------------------------

/**
 * Tainted values, keyed by their normalised form.
 *
 * Deliberately NOT cleared between requests. A value that entered in one
 * request can surface in a later one — that is what a stored cross-site
 * scripting vulnerability is — and keeping the origin here is what lets the
 * tracer report the request the payload *entered* on, not merely the one it
 * was found in.
 */
const tainted = new Map();

/** Values that have been through a recognised sanitiser. */
const sanitised = new Set();

/**
 * Collapses runs of whitespace and trims.
 *
 * Needed because the search parser tokenises on spaces and re-joins, so the
 * value reaching the sink is not always a literal substring of the value that
 * arrived. Normalising both sides makes the comparison survive that.
 */
function normalise(value) {
  return String(value).replace(/\s+/g, " ").trim();
}

function remember(value, param, where) {
  const key = normalise(value);
  if (key.length < MIN_TRACKED_LENGTH) return;
  if (tainted.has(key)) return;

  tainted.set(key, { param, where, at: new Date().toISOString() });

  if (tainted.size > MAX_TRACKED) {
    tainted.delete(tainted.keys().next().value);
  }
}

/**
 * Returns the first tracked value contained in `text`, or null.
 *
 * `skipSanitised` is set by the HTML sink, and it exists because the neat part
 * of this design turned out to have a hole. The assumption was that escaping
 * changes a value, so an escaped taint stops matching — which is true for
 * `<script>` and false for `hello`. A value with nothing to escape passes
 * through escapeHtml() unchanged, still matches, and gets reported as though
 * the sanitiser had never run.
 *
 * So the HTML sink also consults the sanitiser record. The SQL sink does not:
 * escaping is an HTML treatment and does nothing for a SQL statement, so a
 * value that has been through escapeHtml() is still tainted as far as the
 * database is concerned. Knowing *which* sanitiser applies to *which* sink is
 * the real skill, and applying one blanket rule here would be wrong in one
 * direction or the other.
 */
function findTaint(text, skipSanitised) {
  const haystack = normalise(text);
  for (const [value, origin] of tainted) {
    if (skipSanitised && sanitised.has(value)) continue;
    if (haystack.includes(value)) return { value, origin };
  }
  return null;
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

let findings = 0;

/** The application frame that called the sink — the "which line" answer. */
function callSite() {
  const lines = new Error().stack.split("\n").slice(2);
  for (const line of lines) {
    const match = line.match(/([^\s()]+\.js:\d+:\d+)\)?\s*$/);
    if (!match) continue;
    const file = match[1].replace(`${process.cwd()}/`, "");
    if (file.startsWith("src/") && !file.startsWith("src/lib/iast.js")) return file;
  }
  return "unknown";
}

function report({ kind, value, origin, sink, detail }) {
  findings += 1;
  const line = "-".repeat(72);

  console.log(`\n${line}`);
  console.log(`[IAST] tainted input reached a ${kind} sink`);
  console.log(line);
  console.log(`  source      ${origin.param}  from ${origin.where}`);
  console.log(`  value       ${value}`);
  console.log(`  sink        ${sink}  at ${callSite()}`);
  if (detail) console.log(`  ${detail}`);
  console.log(`  sanitizer   none applied`);
  console.log(line);
}

// ---------------------------------------------------------------------------
// Source — HTTP input
// ---------------------------------------------------------------------------

function collect(value, param, where) {
  if (typeof value === "string") {
    remember(value, param, where);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, i) => collect(item, `${param}[${i}]`, where));
    return;
  }
  if (value && typeof value === "object") {
    for (const key of Object.keys(value)) {
      collect(value[key], param ? `${param}.${key}` : key, where);
    }
  }
}

/**
 * Express middleware. Mount it after the body parser so req.body is
 * populated, and before the router so every handler is covered.
 */
function iastMiddleware(req, res, next) {
  const where = `${req.method} ${req.originalUrl || req.url}`;

  collect(req.query, "req.query", where);
  collect(req.params, "req.params", where);
  collect(req.body, "req.body", where);

  // Wrap this response's send. Wrapping per request rather than on a prototype
  // because res is created by Express per request; res.json() delegates to
  // res.send(), so one wrapper covers both.
  const originalSend = res.send.bind(res);
  res.send = function (body) {
    // Output context decides whether a value is dangerous at all, so the check
    // is scoped to HTML responses. The same <script> text is executable in a
    // text/html body and completely inert inside application/json — and this
    // application returns both. Without this guard the POST's own JSON echo of
    // a title would be reported as an HTML finding, which it is not.
    //
    // Known limit: a handler that sends a string without setting the header
    // would be missed, because Express applies the default type inside send()
    // rather than before it.
    const contentType = res.get("Content-Type") || "";
    if (contentType.includes("text/html")) {
      const text = typeof body === "string" ? body : JSON.stringify(body);
      const hit = findTaint(text, true);
      if (hit) {
        report({
          kind: "HTML output",
          value: hit.value,
          origin: hit.origin,
          sink: "res.send",
          detail: `route       ${where}`,
        });
      }
    }
    return originalSend(body);
  };

  next();
}

// ---------------------------------------------------------------------------
// Sink — SQL
// ---------------------------------------------------------------------------

/**
 * Inspects the statement text, and only the statement text.
 *
 * This is the important decision in the file. A value in the bound-parameter
 * array is *not* a finding — it is the fix. `ILIKE $1` with the term in the
 * array sends the statement and the value to the database by different routes,
 * so the value can never be parsed as SQL, and reporting it would flag the
 * secure form as loudly as the vulnerable one. What matters is whether a
 * tainted value has become part of the statement itself, so that is what this
 * checks.
 */
function inspectStatement(sql) {
  const hit = findTaint(sql);
  if (!hit) return;
  report({
    kind: "SQL",
    value: hit.value,
    origin: hit.origin,
    sink: "Pool.query",
    detail: `statement   ${sql}`,
  });
}

const originalQuery = Pool.prototype.query;
Pool.prototype.query = function (...args) {
  const [sql] = args;
  if (typeof sql === "string") inspectStatement(sql);
  return originalQuery.apply(this, args);
};

// ---------------------------------------------------------------------------
// Sanitiser
// ---------------------------------------------------------------------------

const originalEscapeHtml = escapeHtmlModule.escapeHtml;

escapeHtmlModule.escapeHtml = function (value) {
  const result = originalEscapeHtml(value);
  const key = normalise(value);

  if (tainted.has(key) && !sanitised.has(key)) {
    sanitised.add(key);
    const origin = tainted.get(key);
    const line = "-".repeat(72);

    console.log(`\n${line}`);
    console.log("[IAST] tainted input passed through a recognised sanitizer");
    console.log(line);
    console.log(`  source      ${origin.param}  from ${origin.where}`);
    console.log(`  value       ${value}`);
    console.log(`  sanitizer   escapeHtml -> ${result}`);
    console.log(`  verdict     neutralised, this value will not be reported at a sink`);
    console.log(line);
  }

  return result;
};

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  iastMiddleware,
  // Exposed for the walkthrough's own inspection, not used by the application.
  stats: () => ({ tracked: tainted.size, sanitised: sanitised.size, findings }),
  reset: () => {
    tainted.clear();
    sanitised.clear();
    findings = 0;
  },
};
