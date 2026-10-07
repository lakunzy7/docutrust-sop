/**
 * Author: Owofola Olakunle
 *
 * A working RASP-style blocking middleware for DocuTrust.
 *
 * WHAT THIS IS
 * ------------
 * Runtime Application Self-Protection: middleware that inspects an incoming
 * request and refuses it before it reaches a route handler, if the request
 * carries something that matches one of the two seeded attacks. It runs as
 * close to the wire as it can while still seeing a parsed body, so a blocked
 * request is refused before any other code in the application sees it.
 *
 * WHERE IT BLOCKS EACH ATTACK — AND WHY THAT IS NOT THE SAME PLACE
 * ----------------------------------------------------------------
 * The SQL injection arrives in the request that exploits it. `GET
 * /documents/search?q=` carries the payload and hands it to the query, so the
 * block happens on that request.
 *
 * The cross-site scripting does not. Its payload is written by `POST
 * /documents` and appears later, when `GET /documents/:id/render` reads it
 * back out of the database. The render request carries no payload at all — it
 * is an entirely ordinary GET with an id in the path. **So RASP blocks the XSS
 * at the write, not at the render.**
 *
 * That is the right place for it regardless. Stop the payload being stored and
 * there is nothing left to render. But it is worth being explicit about,
 * because it means this middleware's protection for stored XSS is at the point
 * of entry, and the evidence for it is a *later* request that comes back
 * clean.
 *
 * WHAT THIS IS NOT
 * ----------------
 * This is illustrative infrastructure. It is deliberately not production-grade,
 * and the following are stated here rather than discovered later:
 *
 *   - It is PATTERN MATCHING ON A REQUEST, not analysis of what the request
 *     does. It cannot know whether a value ever reaches a dangerous sink. It
 *     guesses, from the shape of the input, and guessing is a compromise with
 *     no safe setting: rules loose enough to catch `admin'--` will block a
 *     report titled "Q3 -- draft", and rules tight enough to pass that will
 *     miss something else.
 *
 *   - It has FALSE NEGATIVES BY CONSTRUCTION. It catches the two patterns it
 *     was written for. It is not a web application firewall and not a security
 *     boundary.
 *
 *   - It is TRIVIAL TO BYPASS. URL-encoding, case variants, comment insertion,
 *     obfuscation of any kind would slip past these rules. Anyone who reads
 *     this file knows how to defeat it.
 *
 *   - THE RIGHT FIX IS IN THE APPLICATION, not in front of it. RASP earns its
 *     place as defence in depth, for code you cannot change quickly. DocuTrust's
 *     code is right there, and parameterizing the query and escaping the output
 *     — which Project 1 does — is the actual remedy. This middleware is the
 *     thing you reach for when you cannot do that yet.
 *
 * DISABLING IT
 * ------------
 * Set RASP_ENABLED=false in the environment before starting the application:
 *
 *     RASP_ENABLED=false npm start
 *
 * Anything other than the exact string "false" leaves it enabled — an unset
 * variable, an empty one, a typo. That is deliberate: a RASP silently switched
 * off by a misspelling is worse than no RASP at all, because the application
 * still looks protected. The startup line below reports which state it is in.
 */

"use strict";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const ENABLED = process.env.RASP_ENABLED !== "false";

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------
//
// Every rule below requires SQL or HTML SYNTAX, never a suspicious character on
// its own. An apostrophe is not an attack; an apostrophe followed by a boolean
// operator is. That distinction is what keeps a name like O'Brien out of the
// block log, and it is the only reason these rules are usable at all.

const SQLI_RULES = [
  {
    id: "SQLI-001",
    description: "quote followed by a boolean operator",
    pattern: /['"]\s*(or|and)\s/i,
  },
  {
    id: "SQLI-002",
    description: "quote followed by a comment marker",
    pattern: /['"]\s*--/,
  },
  {
    id: "SQLI-003",
    description: "UNION SELECT",
    pattern: /\bunion\b[\s\S]*\bselect\b/i,
  },
  {
    id: "SQLI-004",
    description: "statement terminator followed by a statement",
    pattern: /;\s*(drop|delete|update|insert|select)\b/i,
  },
];

const XSS_RULES = [
  {
    id: "XSS-001",
    description: "script tag",
    pattern: /<script/i,
  },
  {
    id: "XSS-002",
    description: "javascript: URI",
    pattern: /javascript:/i,
  },
  {
    id: "XSS-003",
    description: "inline event handler",
    pattern: /\bon(load|error|click|mouse\w+|focus|blur)\s*=/i,
  },
];

const RULES = [...SQLI_RULES, ...XSS_RULES];

// ---------------------------------------------------------------------------
// Inspection
// ---------------------------------------------------------------------------

/** Returns the first rule the value matches, or null. */
function inspectValue(value) {
  for (const rule of RULES) {
    if (rule.pattern.test(value)) return rule;
  }
  return null;
}

/**
 * Walks the request's inputs and returns the first match found, with the
 * parameter it came from. Nested objects and arrays are covered because
 * `POST /documents` takes a JSON body and the payload can be in any field.
 */
function inspectInputs(value, param) {
  if (typeof value === "string") {
    const rule = inspectValue(value);
    return rule ? { rule, param, value } : null;
  }

  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i += 1) {
      const hit = inspectInputs(value[i], `${param}[${i}]`);
      if (hit) return hit;
    }
    return null;
  }

  if (value && typeof value === "object") {
    for (const key of Object.keys(value)) {
      const hit = inspectInputs(value[key], param ? `${param}.${key}` : key);
      if (hit) return hit;
    }
  }

  return null;
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

function reportBlocked({ rule, param, value, route, query }) {
  const line = "-".repeat(72);

  console.log(`\n${line}`);
  console.log("[RASP] request blocked");
  console.log(line);
  console.log(`  rule        ${rule.id}  ${rule.description}`);
  console.log(`  parameter   ${param}`);
  console.log(`  value       ${value}`);
  console.log(`  route       ${route}`);
  if (query) console.log(`  query       ${query}`);
  console.log(`  response    403 - request not forwarded to the route`);
  console.log(line);
}

// ---------------------------------------------------------------------------
// The middleware
// ---------------------------------------------------------------------------

function raspMiddleware(req, res, next) {
  if (!ENABLED) return next();

  const route = `${req.method} ${req.originalUrl || req.url}`;

  const hit =
    inspectInputs(req.query, "req.query") ||
    inspectInputs(req.params, "req.params") ||
    inspectInputs(req.body, "req.body");

  if (!hit) return next();

  // Returning the rule and the matched value is instructive here and would be
  // wrong in production: telling an attacker which rule caught them, and what
  // it matched, is a gift. A production RASP returns a generic error and logs
  // the detail where the attacker cannot read it. This one is teaching.
  reportBlocked({ ...hit, route });

  res.status(403).json({
    error: "Request blocked",
    rule: hit.rule.id,
    description: hit.rule.description,
  });
}

// ---------------------------------------------------------------------------
// Startup state
// ---------------------------------------------------------------------------

console.log(
  ENABLED
    ? "[RASP] enabled - inspecting query, path and body for SQL injection and XSS patterns"
    : "[RASP] DISABLED by RASP_ENABLED=false - requests pass through uninspected"
);

module.exports = {
  raspMiddleware,
  // Exposed for testing the rules directly, not used by the application.
  rules: RULES,
  enabled: () => ENABLED,
  inspectValue,
};
