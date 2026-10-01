// Two structurally identical SQL injections. The only difference is where the
// value comes from -- and that difference decides whether the registry rule
// sees them.
//
// Run against p/expressjs:     one finding, the first function only.
// Run against the custom rule: two findings, both functions.
//
// tainted-sql-string follows taint from a source it recognises (req.query,
// req.body and similar) to a query sink. Function 1 has such a source, so the
// chain completes and the rule fires. Function 2's value arrives as an
// ordinary parameter -- the chain never starts, and the rule stays silent even
// though the vulnerability is identical.
//
// The custom rule does not care where the value came from. It flags the
// construction, which is why it catches the class rather than the instance.

// A: value derived from req.query -- a source Semgrep recognises
async function fromRequest(req, pool) {
  const term = req.query.q;
  const query = `SELECT id FROM documents WHERE title = '${term}'`;
  return pool.query(query);
}

// B: identical construction, value arrives as a function parameter
async function fromParameter(term, pool) {
  const query = `SELECT id FROM documents WHERE title = '${term}'`;
  return pool.query(query);
}
