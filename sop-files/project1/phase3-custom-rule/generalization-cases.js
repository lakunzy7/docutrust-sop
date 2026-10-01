// Generalisation test bed for the custom rule.
//
// The first five functions build a SQL statement by interpolation or
// concatenation, in five different shapes. None of them appears anywhere in
// DocuTrust -- they exist to answer one question: does the rule catch the
// class, or did it just learn the one seeded line?
//
// The last four are safe, and must NOT be reported. A rule that flags a
// parameterized query is worse than no rule, because it teaches people to
// ignore it.

// --- must be reported ---------------------------------------------------

// 1. DocuTrust's exact shape: built into a local, then handed to query()
function docutrustShape(searchTerm, pool) {
  const query = `SELECT id, title FROM documents WHERE title ILIKE '%${searchTerm}%'`;
  return pool.query(query);
}

// 2. Interpolated directly at the call site, different names throughout
async function directInterp(db, name) {
  return db.query(`SELECT * FROM users WHERE name = '${name}'`);
}

// 3. Concatenation rather than a template literal
async function concatForm(pool, userId) {
  const q = "SELECT * FROM users WHERE id = " + userId;
  return pool.query(q);
}

// 4. A different statement type, and a different name for the client
async function deleteForm(client, token) {
  const sql = `DELETE FROM sessions WHERE token = '${token}'`;
  return client.query(sql);
}

// 5. A multi-line template with two interpolations
async function multiLine(pool, status, owner) {
  const stmt = `SELECT id
                FROM orders
                WHERE status = '${status}'
                AND owner = '${owner}'`;
  return pool.query(stmt);
}

// --- must NOT be reported -----------------------------------------------

// 6. Parameterized query -- the correct form
async function parameterized(pool, id) {
  return pool.query("SELECT * FROM documents WHERE id = $1", [id]);
}

// 7. A template literal with no interpolation at all
async function staticTemplate(pool) {
  return pool.query(`SELECT id, title FROM documents ORDER BY created_at DESC`);
}

// 8. An interpolated template that is not SQL
function notSql(name) {
  const greeting = `Hello ${name}, welcome back`;
  return greeting;
}

// 9. A concatenation with no interpolation
async function staticConcat(pool) {
  const q = "SELECT count(*) FROM documents";
  return pool.query(q);
}
